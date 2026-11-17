"""End-to-end and adversarial tests for `#76` (`wythe-plugin-apple-ipc`).

Benchmarked against pinned open-source fixtures distilled from:
- `apple/container@16e8d488ee1d9ede35ab9cf21b9973ffdc9361b3`
- `apple/containerization@706cb512ccfc50fe27b575084c17a2964526be8e`
"""

from __future__ import annotations

import importlib.metadata
import time
from pathlib import Path

import pytest

from app.adapters.autodetect import detect_repository_stack
from app.db.session import get_session_factory
from app.main import initialize_database
from app.models import TargetProject
from app.services.companion_export_service import build_openlineage_static_bundle
from app.services.llm_context_service import build_lineage_cone_slice, build_llms_txt_brief
from app.services.scanner_service import run_target_scan
from wythe_plugin_apple_ipc import (
    APPLE_IPC_PLUGIN,
    MAX_NESTING_DEPTH,
    MAX_SOURCE_FILE_BYTES,
    extract_swift_systems_repo,
    parse_package_manifest,
    parse_package_manifest_text,
    parse_safe_plist_bytes,
    resolve_safe_source_path,
)
from wythe_plugin_apple_ipc.package_manifest import sanitize_swift_source


def _write(base: Path, rel: str, text: str) -> Path:
    fp = base / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(text, encoding="utf-8")
    return fp


def _build_apple_container_fixture(repo: Path) -> Path:
    """Distilled multi-file `apple/container@16e8d488ee1d9ede35ab9cf21b9973ffdc9361b3` slice."""
    _write(
        repo,
        "Package.swift",
        """// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "container",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "container", targets: ["CLI"]),
    ],
    targets: [
        .executableTarget(
            name: "CLI",
            dependencies: [
                "ContainerCommands",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .target(
            name: "ContainerCommands",
            dependencies: [
                "ContainerXPC",
                "ContainerAPIService",
                "ContainerImagesService",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .target(name: "ContainerXPC", dependencies: []),
        .target(name: "CAuditToken", publicHeadersPath: "include"),
        .target(name: "ContainerPersistence", dependencies: []),
        .target(name: "ContainerPlugin", dependencies: []),
        .target(
            name: "ContainerBuild",
            dependencies: [.product(name: "GRPCCore", package: "grpc-swift")]
        ),
        .target(
            name: "ContainerAPIService",
            dependencies: [
                "ContainerXPC",
                "ContainerPersistence",
                "ContainerPlugin",
                "CAuditToken",
            ],
            path: "Sources/Services/ContainerAPIService"
        ),
        .target(
            name: "ContainerImagesService",
            dependencies: ["ContainerXPC"],
            path: "Sources/Services/ContainerImagesService"
        ),
        .testTarget(
            name: "ContainerTests",
            dependencies: ["ContainerCommands", "ContainerAPIService"]
        ),
    ]
)
""",
    )
    _write(
        repo,
        "Sources/CLI/ContainerCLI.swift",
        """import ArgumentParser
import ContainerCommands

@main
public struct ContainerCLI: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "container",
        abstract: "Manage Linux containers on macOS",
        subcommands: [ContainerRun.self, ImagePull.self]
    )
    public init() {}
}
""",
    )
    _write(
        repo,
        "Sources/ContainerCommands/Container/ContainerRun.swift",
        """import ArgumentParser
import ContainerXPC
import ContainerAPIService

public struct ContainerRun: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(commandName: "run")
    public init() {}

    public func run() async throws {
        let client = XPCClient(serviceName: "com.apple.container.apiserver")
        _ = try await client.send(XPCMessage(route: ContainersXPCRoutes.containerCreate.rawValue))
    }
}
""",
    )
    _write(
        repo,
        "Sources/ContainerCommands/Image/ImagePull.swift",
        """import ArgumentParser
import ContainerXPC
import ContainerImagesService

public struct ImagePull: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(commandName: "pull")
    public init() {}

    public func run() async throws {
        let client = XPCClient(serviceName: "com.apple.container.images")
        _ = try await client.send(XPCMessage(route: ImageServiceXPCRoutes.imagePull.rawValue))
    }
}
""",
    )
    _write(
        repo,
        "Sources/ContainerXPC/XPCClient.swift",
        """import Foundation

public struct XPCMessage: Sendable {
    public let route: String
    public init(route: String) { self.route = route }
}

public final class XPCClient: Sendable {
    public let serviceName: String
    public init(serviceName: String) { self.serviceName = serviceName }
    public func send(_ message: XPCMessage) async throws -> Data { Data() }
}
""",
    )
    _write(
        repo,
        "Sources/ContainerXPC/XPCServer.swift",
        """import Foundation

public actor XPCServer {
    private var routes: [String: @Sendable (Data) async throws -> Data] = [:]
    public init() {}
    public func register(_ route: String, handler: @escaping @Sendable (Data) async throws -> Data) {
        routes[route] = handler
    }
}
""",
    )
    _write(
        repo,
        "Sources/CAuditToken/include/AuditToken.h",
        """#ifndef CAUDIT_TOKEN_H
#define CAUDIT_TOKEN_H
#include <stdint.h>
uint32_t container_audit_token_euid(const void *token_ptr);
#endif
""",
    )
    _write(
        repo,
        "Sources/CAuditToken/AuditToken.c",
        """#include "include/AuditToken.h"

uint32_t container_audit_token_euid(const void *token_ptr) {
    (void)token_ptr;
    return 501;
}
""",
    )
    return repo


def _populate_apple_container_services_and_stores(repo: Path) -> None:
    _write(
        repo,
        "Sources/ContainerPersistence/EntityStore.swift",
        """import Foundation

public actor EntityStore<Record: Codable & Sendable> {
    public let rootDirectory: URL
    private let encoder = JSONEncoder()

    public init(rootDirectory: URL) { self.rootDirectory = rootDirectory }
    public func create(_ record: Record, id: String) throws { _ = (record, id, encoder) }
    public func load(id: String) throws -> Record? { _ = id; return nil }
}
""",
    )
    _write(
        repo,
        "Sources/ContainerPlugin/LaunchPlist.swift",
        """import Foundation

public struct LaunchPlist: Codable, Sendable {
    public let label: String
    public let machServices: [String: Bool]
    public let programArguments: [String]
    public static let defaultService = "com.apple.container.apiserver"
}
""",
    )
    _write(
        repo,
        "Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift",
        """import Foundation
import CAuditToken
import ContainerPersistence
import ContainerPlugin
import ContainerXPC

public enum ContainersXPCRoutes: String, Sendable {
    case containerCreate = "com.apple.container.apiserver/containers/create"
    case containerList = "com.apple.container.apiserver/containers/list"
}

public actor ContainersService {
    private let store: EntityStore<String>
    private let runtimeBinary = "container-runtime-linux"

    public init(store: EntityStore<String>) { self.store = store }

    public func bind(to server: XPCServer, peerToken: UnsafeRawPointer) async {
        _ = container_audit_token_euid(peerToken)
        _ = LaunchPlist.defaultService
        await server.register(ContainersXPCRoutes.containerCreate.rawValue) { _ in
            try await self.store.create("alpine", id: "c-1")
            return Data()
        }
        await server.register(ContainersXPCRoutes.containerList.rawValue) { _ in
            _ = try await self.store.load(id: "c-1")
            return Data()
        }
    }
}
""",
    )
    _write(
        repo,
        "Sources/Services/ContainerImagesService/Client/ImageServiceXPCRoutes.swift",
        """import Foundation

public enum ImageServiceXPCRoutes: String, Sendable {
    case imagePull = "com.apple.container.images/pull"
    case imageList = "com.apple.container.images/list"
    case unusedLegacyRoute = "com.apple.container.images/legacy_unused"
}
""",
    )
    _write(
        repo,
        "Sources/Services/ContainerImagesService/Server/SnapshotStore.swift",
        """import Foundation

public actor SnapshotStore {
    public let mountRoot: URL
    public init(mountRoot: URL) { self.mountRoot = mountRoot }
    public func unpack(digest: String) throws { _ = digest }
}
""",
    )
    _write(
        repo,
        "Sources/Services/ContainerImagesService/Server/ContentStoreService.swift",
        """import Foundation
import ContainerXPC

public actor ContentStoreService {
    public let blobsRoot: URL
    private let snapshotStore: SnapshotStore

    public init(blobsRoot: URL, snapshotStore: SnapshotStore) {
        self.blobsRoot = blobsRoot
        self.snapshotStore = snapshotStore
    }

    public func putBlob(digest: String) async throws {
        try await snapshotStore.unpack(digest: digest)
    }

    public func installRoutes(on server: XPCServer) async {
        await server.register(ImageServiceXPCRoutes.imagePull.rawValue) { _ in
            try await self.putBlob(digest: "sha256:deadbeef")
            return Data()
        }
    }
}
""",
    )
    _write(
        repo,
        "Sources/ContainerBuild/Builder.grpc.swift",
        """import Foundation

public enum BuilderClientMetadata {
    public static let serviceName = "com.apple.container.build.v1.Builder"
}

public protocol BuilderAsyncClientProtocol: Sendable {
    func performBuild() async throws
}
""",
    )
    _write(
        repo,
        "signing/container-runtime-linux.entitlements",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.virtualization</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
</dict>
</plist>
""",
    )
    # Test target containing undeclared imports & fake routes that MUST be ignored!
    _write(
        repo,
        "Tests/ContainerTests/ContainerTests.swift",
        """import ContainerPersistence
import ContainerImagesService

struct TestOnlyCommand: ParsableCommand {
    func run() throws {
        let client = XPCClient(serviceName: "com.apple.container.apiserver")
        _ = client
        let msg = XPCMessage(route: "com.apple.container.apiserver/test_only_missing")
        _ = msg
    }
}
""",
    )


def _build_apple_containerization_fixture(repo: Path) -> Path:
    """Distilled `apple/containerization@706cb512ccfc50fe27b575084c17a2964526be8e` slice."""
    _write(
        repo,
        "Package.swift",
        """// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "containerization",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "cctl", targets: ["cctl"]),
        .library(name: "Containerization", targets: ["Containerization"]),
    ],
    targets: [
        .executableTarget(
            name: "cctl",
            dependencies: [
                "Containerization",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .target(
            name: "Containerization",
            dependencies: [.product(name: "GRPCCore", package: "grpc-swift")]
        ),
    ]
)
""",
    )
    _write(
        repo,
        "Sources/cctl/cctl.swift",
        """import ArgumentParser
import Containerization

@main
struct cctl: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cctl",
        subcommands: [Run.self]
    )

    struct Run: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "run")

        func run() async throws {
            let store = ImageStore(path: "/var/lib/containerization")
            _ = try await store.load(reference: "ghcr.io/linux/alpine:latest")
            let client = SandboxContextAsyncClient(vsockPort: 2048)
            try await client.mount(source: "rootfs")
        }
    }
}
""",
    )
    _write(
        repo,
        "Sources/Containerization/SandboxContext/SandboxContext.proto",
        """syntax = "proto3";
package com.apple.containerization.sandbox.v1;

// Guest-agent vsock RPC interface
service SandboxContext {
  rpc Mount(MountRequest) returns (MountResponse);
  rpc ExecProcess(ExecRequest) returns (ExecResponse);
}
""",
    )
    _write(
        repo,
        "Sources/Containerization/SandboxContext/SandboxContext.grpc.swift",
        """import Foundation

// Transports over AF_VSOCK / VZVirtioSocketConnection
public struct SandboxContextAsyncClient: Sendable {
    public let vsockPort: UInt32
    public init(vsockPort: UInt32) { self.vsockPort = vsockPort }
    public func mount(source: String) async throws { _ = source }
    public func execProcess(command: String) async throws { _ = command }
}
""",
    )
    _write(
        repo,
        "Sources/Containerization/Image/ImageStore/ImageStore.swift",
        """import Foundation

public actor ImageStore {
    public let rootPath: String
    public init(path: String) { self.rootPath = path }
    public func load(reference: String) throws -> String { reference }
    public func save(reference: String) throws { _ = reference }
}
""",
    )
    return repo


def _scan_with_apple_ipc(repo: Path, slug: str):
    initialize_database()
    factory = get_session_factory()
    with factory() as session:
        det = detect_repository_stack(
            session,
            str(repo),
            allow_local_plugins=True,
            local_plugin_modules=["wythe_plugin_apple_ipc"],
        )
        target = TargetProject(
            slug=slug,
            name=slug,
            repo_path=str(repo),
            backend_subdir=det.backend_subdir,
            frontend_subdir=det.frontend_subdir,
            stack_profile_slug=det.recommended_profile_slug,
        )
        report = run_target_scan(
            session,
            target,
            strict_gate=True,
            persist_snapshot=False,
            allow_local_plugins=True,
            local_plugin_modules=["wythe_plugin_apple_ipc"],
        )
        return det, report


def test_plugin_metadata_and_apple_container_both_3tier_chains(tmp_path: Path) -> None:
    meta = APPLE_IPC_PLUGIN.to_metadata()
    assert "IPC-001" in meta["rules"]

    repo = _build_apple_container_fixture(tmp_path / "apple_container")
    _populate_apple_container_services_and_stores(repo)

    manifest = parse_package_manifest(repo)
    assert manifest.package_name == "container"
    assert manifest.targets["CAuditToken"].is_c_target is True
    assert manifest.targets["ContainerTests"].is_test_target is True
    assert manifest.targets["ContainerAPIService"].rel_path == "Sources/Services/ContainerAPIService"

    det, report = _scan_with_apple_ipc(repo, "apple-container-fixture")
    assert det.recommended_profile_slug == "swift-systems-ipc"
    assert det.truth_adapter == "swift-stores-truth"
    assert det.manipulator_adapter == "swift-ipc-manipulator"
    assert det.display_adapter == "swift-cli-display"
    assert det.coverage_complete is True
    assert det.confidence == "high"

    # Native 3-wythe representation: zero fake HTTP routes or paths
    assert all(n.http_methods == [] and n.http_paths == [] for n in report.nodes)
    assert report.gate.verdict == "PASS"
    assert report.findings == []

    # Test targets (`Tests/*`) and unused XPC enum cases produce zero runtime nodes or findings
    assert not any(n.source_file.startswith("Tests/") for n in report.nodes)

    nodes_by_label = {n.label: n for n in report.nodes}
    assert nodes_by_label["ContainerCLI"].subkind == "cli"
    assert nodes_by_label["ContainerRun"].subkind == "cli"
    assert nodes_by_label["ImagePull"].subkind == "cli"
    assert nodes_by_label["XPCClient"].subkind == "ipc_handler"
    assert nodes_by_label["XPCServer"].subkind == "ipc_handler"
    assert nodes_by_label["ImageServiceXPCRoutes"].subkind == "ipc_handler"
    assert nodes_by_label["Builder"].subkind == "ipc_handler"
    assert nodes_by_label["ContainersService"].subkind == "service"
    assert nodes_by_label["CAuditToken"].subkind == "ffi_shim"
    assert nodes_by_label["EntityStore"].subkind == "entity_store"
    assert nodes_by_label["ContentStoreService"].subkind == "entity_store"
    assert nodes_by_label["SnapshotStore"].subkind == "entity_store"
    assert nodes_by_label["LaunchPlist"].subkind == "entitlement_spec"
    ent_node = nodes_by_label["container-runtime-linux.entitlements"]
    assert ent_node.subkind == "entitlement_spec"
    assert "com.apple.security.virtualization" in ent_node.columns

    # Chain 1: ContainerRun -> XPCClient/ContainersXPCRoutes -> ContainersService (+ CAuditToken) -> EntityStore + .entitlements
    run_chains = [c for c in report.chains if c.display_label == "ContainerRun"]
    assert run_chains, f"Expected ContainerRun chain, got {[c.display_label for c in report.chains]}"
    rc = run_chains[0]
    assert rc.http_method == "IPC"
    assert "m:svc:ContainersService" in rc.manipulator_node_ids
    assert "m:ffi:CAuditToken" in rc.manipulator_node_ids
    assert "EntityStore" in rc.truth_table_labels
    assert "container-runtime-linux.entitlements" in rc.truth_table_labels
    assert "LaunchPlist" in rc.truth_table_labels

    # Chain 2: ImagePull -> ImageServiceXPCRoutes -> ContentStoreService / SnapshotStore
    pull_chains = [c for c in report.chains if c.display_label == "ImagePull"]
    assert pull_chains, f"Expected ImagePull chain, got {[c.display_label for c in report.chains]}"
    pc = pull_chains[0]
    assert pc.route_label == "ImageServiceXPCRoutes"
    assert "ContentStoreService" in pc.truth_table_labels
    assert "SnapshotStore" in pc.truth_table_labels
    assert "EntityStore" not in pc.truth_table_labels

    # Verify llms.txt brief, lineage cone, and OpenLineage export render native subkinds cleanly
    brief = build_llms_txt_brief(report)
    assert "EntityStore" in brief.markdown
    cone = build_lineage_cone_slice(report, "ContainerRun")
    assert any(p.label == "EntityStore" for p in cone.downstream_truth_nodes)
    ol_bundle = build_openlineage_static_bundle(report)
    ds_names = {d["name"] for d in ol_bundle["datasets"]}
    assert "EntityStore" in ds_names
    assert "ContentStoreService" in ds_names


def test_apple_containerization_cctl_vsock_grpc_chain(tmp_path: Path) -> None:
    repo = _build_apple_containerization_fixture(tmp_path / "apple_containerization")
    _, report = _scan_with_apple_ipc(repo, "apple-containerization-fixture")

    assert report.gate.verdict == "PASS"
    assert all(n.http_methods == [] and n.http_paths == [] for n in report.nodes)

    cctl_chains = [c for c in report.chains if c.display_label in ("cctl", "cctl.Run")]
    assert any(
        c.display_label == "cctl"
        and c.route_label == "SandboxContext"
        and "ImageStore" in c.truth_table_labels
        for c in cctl_chains
    )


def test_ipc001_mismatched_route_manip006_undeclared_import_and_negative_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _build_apple_container_fixture(tmp_path / "swift_defects")
    _populate_apple_container_services_and_stores(repo)

    # Inject: (1) undeclared sibling target import `ContainerPersistence` in `ContainerCommands`,
    # (2) static unmatched in-repo XPC route (`IPC-001`),
    # (3) external OS Mach service (`com.apple.system.logger`) & dynamic XPC route (both unverified, 0 IPC-001)
    _write(
        repo,
        "Sources/ContainerCommands/Container/ContainerInspect.swift",
        """import ArgumentParser
import ContainerXPC
import ContainerPersistence

public struct ContainerInspect: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(commandName: "inspect")

    public func run() async throws {
        let sysLogger = XPCClient(serviceName: "com.apple.system.logger")
        _ = sysLogger
        let dynAction = "stats"
        let client = XPCClient(serviceName: "com.apple.container.apiserver")
        _ = try await client.send(XPCMessage(route: "com.apple.container.apiserver/\\(dynAction)"))
        _ = try await client.send(XPCMessage(route: "com.apple.container.apiserver/containers/missing_route"))
    }
}
""",
    )

    _, report = _scan_with_apple_ipc(repo, "swift-defects")
    assert report.gate.verdict == "FAIL"

    ipc_findings = [f for f in report.findings if f.rule_code == "IPC-001"]
    assert len(ipc_findings) == 1
    assert ipc_findings[0].blocks_gate is True
    assert "missing_route" in ipc_findings[0].detail
    assert any(e.verification == "broken" for e in report.edges)

    m006_findings = [f for f in report.findings if f.rule_code == "MANIP-006"]
    assert len(m006_findings) == 1
    assert "ContainerPersistence" in m006_findings[0].detail

    # External `com.apple.system.logger` & dynamic route produce `unverified` edges + `unresolved` notes, NOT IPC-001
    assert any("com.apple.system.logger" in nt and "Unresolved" in nt for nt in report.scan_notes)
    assert any("Unresolved dynamic XPC endpoint" in nt for nt in report.scan_notes)
    assert any(e.verification == "unverified" for e in report.edges)

    # Uninstalled-plugin autodetect fallback on `Package.swift` repo: never coerced to typescript-react!
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: ())
    initialize_database()
    with get_session_factory()() as session:
        det_uninstalled = detect_repository_stack(session, str(repo))
    assert det_uninstalled.truth_adapter == "no-truth"
    assert det_uninstalled.manipulator_adapter == "no-manipulator"
    assert det_uninstalled.display_adapter == "no-display"
    assert det_uninstalled.coverage_complete is False
    assert det_uninstalled.confidence == "fallback"
    assert any("wythe-plugin-apple-ipc" in s for s in det_uninstalled.detected_signals)


def test_adversarial_symlink_xxe_nesting_size_and_redos_resilience(tmp_path: Path) -> None:
    repo = _build_apple_container_fixture(tmp_path / "adv_swift")
    _populate_apple_container_services_and_stores(repo)

    # 1. Symlinked file & symlinked directory inside repo are skipped without escaping
    outside_dir = tmp_path / "outside_secret"
    outside_dir.mkdir()
    secret_swift = _write(outside_dir, "SecretStore.swift", "public actor SecretLeakStore {}\n")
    (repo / "Sources" / "ContainerXPC" / "SymFile.swift").symlink_to(secret_swift)
    (repo / "Sources" / "SymTarget").symlink_to(outside_dir)

    ext = extract_swift_systems_repo(repo)
    assert ext.excluded_symlinks >= 2
    assert not any(n.label == "SecretLeakStore" for n in ext.truth_nodes)

    # 2. Direct path & symlinked parent directory rejection (including /var vs /private/var)
    sym_repo_alias = tmp_path / "sym_repo_parent"
    sym_repo_alias.symlink_to(repo)
    with pytest.raises(ValueError, match="(?i)symlink"):
        extract_swift_systems_repo(sym_repo_alias)
    with pytest.raises(ValueError, match="(?i)symlink"):
        parse_package_manifest(sym_repo_alias / "Package.swift")

    cand_repos = [repo]
    if str(repo).startswith("/private/var/"):
        var_alias = Path(str(repo).replace("/private/var/", "/var/", 1))
        if var_alias.exists():
            cand_repos.append(var_alias)
    for cand_r in cand_repos:
        for root_arg in (repo, repo.resolve()):
            with pytest.raises(ValueError, match="(?i)symlink"):
                resolve_safe_source_path(
                    cand_r / "Sources" / "ContainerXPC" / "SymFile.swift",
                    repo_root=root_arg,
                )

    # 3. XML <!ENTITY XXE rejection & >64 nesting depth rejection on plists and Swift sources
    xxe_plist = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<plist><dict><key>a</key><string>&xxe;</string></dict></plist>"
    )
    with pytest.raises(ValueError, match="ENTITY"):
        parse_safe_plist_bytes(xxe_plist, source_label="evil.entitlements")

    deep_plist = (
        b'<?xml version="1.0"?><plist>'
        + b"<dict><key>k</key>" * (MAX_NESTING_DEPTH + 4)
        + b"<true/>"
        + b"</dict>" * (MAX_NESTING_DEPTH + 4)
        + b"</plist>"
    )
    with pytest.raises(ValueError, match="nesting depth"):
        parse_safe_plist_bytes(deep_plist, source_label="deep.entitlements")

    with pytest.raises(ValueError, match="nesting depth"):
        sanitize_swift_source("struct S { " + "(" * (MAX_NESTING_DEPTH + 5) + ")" * (MAX_NESTING_DEPTH + 5) + " }")

    with pytest.raises(ValueError, match="nesting depth"):
        parse_package_manifest_text("/*" * (MAX_NESTING_DEPTH + 3) + "*/" * (MAX_NESTING_DEPTH + 3))

    # 4. > 8 MiB file ceiling enforced
    oversized = tmp_path / "huge.swift"
    oversized.write_bytes(b" " * (MAX_SOURCE_FILE_BYTES + 16))
    with pytest.raises(ValueError, match="exceeds"):
        resolve_safe_source_path(oversized)

    # 5. ReDoS linear-time verification on unterminated backslash strings & 16 KB lines
    slashes = "\\" * 128
    hostile_swift = (
        f'let a = "{slashes}unterminated\n'
        f'let b = XPCMessage(route: "{slashes}unterminated\n'
        + "public struct WideLine { " + ("let x = 1; " * 1500) + "}\n"
    )
    t0 = time.perf_counter()
    clean_s, skel_s = sanitize_swift_source(hostile_swift)
    assert len(clean_s) == len(skel_s) == len(hostile_swift)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.25, f"Expected linear O(N) scan <0.25s, got {elapsed:.3f}s"


def test_entry_point_discovery_zero_subprocess_and_db_row_invariance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from sqlalchemy import func, select

    from app.adapters.plugin_registry import discover_plugins
    from app.models import RulePolicy, StackProfile

    ep = importlib.metadata.EntryPoint(
        name="apple_ipc",
        value="wythe_plugin_apple_ipc.plugin:APPLE_IPC_PLUGIN",
        group="wythe.plugins",
    )
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (ep,) if kw.get("group") == "wythe.plugins" else (),
    )

    specs = discover_plugins()
    apple_specs = [s for s in specs if s.name == "apple_ipc"]
    assert len(apple_specs) == 1
    meta = apple_specs[0].to_metadata()
    assert meta["origin"] == "entry_point"
    assert meta["kind"] == "stack_adapter"
    assert meta["stack_profiles"] == ["swift-systems-ipc"]
    assert set(meta["tier_adapters"]) == {
        "swift-stores-truth",
        "swift-ipc-manipulator",
        "swift-cli-display",
    }

    repo = _build_apple_containerization_fixture(tmp_path / "ep_containerization")

    def _forbid_subprocess(*_a, **_kw):
        raise AssertionError("wythe-plugin-apple-ipc must never spawn external subprocesses!")

    monkeypatch.setattr(subprocess, "Popen", _forbid_subprocess)
    monkeypatch.setattr(subprocess, "run", _forbid_subprocess)
    ext = extract_swift_systems_repo(repo)
    assert any(n.label == "ImageStore" for n in ext.truth_nodes)
    assert any(n.label == "SandboxContext" for n in ext.manip_nodes)
    assert any(n.label == "cctl" for n in ext.disp_nodes)
    monkeypatch.undo()

    # Re-apply entry_points mock and verify DB StackProfile & RulePolicy counts stay untouched
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (ep,) if kw.get("group") == "wythe.plugins" else (),
    )
    initialize_database()
    with get_session_factory()() as session:
        rules_before = session.scalar(select(func.count()).select_from(RulePolicy))
        profs_before = session.scalar(select(func.count()).select_from(StackProfile))
        det = detect_repository_stack(session, str(repo))
        assert det.recommended_profile_slug == "swift-systems-ipc"
        target = TargetProject(
            slug="ep-swift-scan",
            name="ep-swift-scan",
            repo_path=str(repo),
            backend_subdir=det.backend_subdir,
            frontend_subdir=det.frontend_subdir,
            stack_profile_slug=det.recommended_profile_slug,
        )
        rep = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)
        assert rep.gate.verdict == "PASS"
        assert session.scalar(select(func.count()).select_from(RulePolicy)) == rules_before == 19
        assert session.scalar(select(func.count()).select_from(StackProfile)) == profs_before
