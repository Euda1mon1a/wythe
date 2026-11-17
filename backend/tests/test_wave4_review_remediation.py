"""Regression tests for Wave 4 adversarial review findings (`W4-01`..`W4-05`)."""

from __future__ import annotations

import dataclasses
import json
import plistlib
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
for _plugin_src in sorted((REPO_ROOT / "plugins").glob("*/src")):
    if str(_plugin_src) not in sys.path:
        sys.path.insert(0, str(_plugin_src))

from test_wave4_apple_ipc_plugin import _scan_with_apple_ipc
from test_wave4_binary_plugin import _align8, _build_synthetic_macho64, _scan_repo
from test_wave4_compiler_ir_plugin import _scan_python_metal_repo

from app.cli import main as cli_main
from app.schemas.atlas import AtlasNode, validate_semantic_atlas_id
from wythe_plugin_apple_ipc import extract_swift_systems_repo
from wythe_plugin_binary import (
    MachoBinaryCapabilities,
    SourceEntitlementSpec,
    binary_inspection_scope,
    correlate_binary_companions,
    evaluate_entitlement_drift,
    parse_macho_bytes,
    parse_recorded_fixture,
)
from wythe_plugin_compiler_ir.ir_parsers import CompilerIrBundle
from wythe_plugin_compiler_ir.metal_air import MetalSeamAnalysis, verify_metal_compute_seams
from wythe_plugin_compiler_ir.plugin import _expand_node_zoom2, upgrade_edges_with_compiler_ir
from wythe_plugin_compiler_ir.usr_index import parse_usr_index_text
from wythe_plugin_solver_internals.singleton_graph import (
    build_singleton_zoom2_subgraph,
    extract_singleton_dependency_graph,
)
from wythe_plugin_solver_internals.stage_matrix import load_cpp_usr_index


def _write(base: Path, rel: str, content: str) -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _pack_fat_macho(slices_with_cpu: list[tuple[int, int, bytes]]) -> bytes:
    header_sz = 8 + 20 * len(slices_with_cpu)
    cur_off = ((header_sz + 63) // 64) * 64
    entries: list[bytes] = [struct.pack(">II", 0xCAFEBABE, len(slices_with_cpu))]
    payloads: list[bytes] = []
    for cputype, cpusubtype, raw_slice in slices_with_cpu:
        aligned = _align8(raw_slice)
        entries.append(struct.pack(">iiIII", cputype, cpusubtype, cur_off, len(aligned), 3))
        payloads.append(aligned)
        cur_off += len(aligned)
    hdr = b"".join(entries)
    return hdr.ljust(64 if header_sz <= 64 else ((header_sz + 63) // 64) * 64, b"\x00") + b"".join(payloads)


def test_w4_01_universal_macho_per_slice_entitlement_drift_and_order_invariance(
    tmp_path: Path,
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    sb_key = "com.apple.security.app-sandbox"
    grp_key = "com.apple.security.application-groups"
    jit_key = "com.apple.security.cs.allow-jit"

    arm_unsandboxed = _build_synthetic_macho64(
        cputype=0x0100000C,
        entitlements_xml=plistlib.dumps({sb_key: False}).decode("utf-8"),
    )
    x86_sandboxed = _build_synthetic_macho64(
        cputype=0x01000007,
        entitlements_xml=plistlib.dumps({sb_key: True}).decode("utf-8"),
    )
    fat_arm_first = _pack_fat_macho([(0x0100000C, 0, arm_unsandboxed), (0x01000007, 3, x86_sandboxed)])
    fat_x86_first = _pack_fat_macho([(0x01000007, 3, x86_sandboxed), (0x0100000C, 0, arm_unsandboxed)])

    specs = [SourceEntitlementSpec("App.entitlements", "App", {sb_key: True})]

    cap_arm = parse_macho_bytes(arm_unsandboxed, source_name="App")
    cap_x86 = parse_macho_bytes(x86_sandboxed, source_name="App")
    cap_fat1 = parse_macho_bytes(fat_arm_first, source_name="App")
    cap_fat2 = parse_macho_bytes(fat_x86_first, source_name="App")
    assert isinstance(cap_fat1, MachoBinaryCapabilities)
    assert cap_fat1.slice_entitlements == {
        "arm64": {sb_key: False},
        "x86_64": {sb_key: True},
    }
    assert cap_fat2.slice_entitlements == cap_fat1.slice_entitlements
    assert cap_fat1.entitlements == cap_fat2.entitlements

    d_arm = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_arm.entitlements,
        linux_capabilities=(),
        source_specs=specs,
        slice_entitlements=cap_arm.slice_entitlements,
        slice_has_entitlements_blob=cap_arm.slice_has_entitlements_blob,
    )
    d_x86 = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_x86.entitlements,
        linux_capabilities=(),
        source_specs=specs,
        slice_entitlements=cap_x86.slice_entitlements,
        slice_has_entitlements_blob=cap_x86.slice_has_entitlements_blob,
    )
    d_fat1 = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_fat1.entitlements,
        linux_capabilities=(),
        source_specs=specs,
        slice_entitlements=cap_fat1.slice_entitlements,
        slice_has_entitlements_blob=cap_fat1.slice_has_entitlements_blob,
    )
    d_fat2 = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_fat2.entitlements,
        linux_capabilities=(),
        source_specs=specs,
        slice_entitlements=cap_fat2.slice_entitlements,
        slice_has_entitlements_blob=cap_fat2.slice_has_entitlements_blob,
    )
    # Also verify legacy caller omitting `slice_entitlements` still sees conservative drift
    d_legacy = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_fat1.entitlements,
        linux_capabilities=(),
        source_specs=specs,
    )

    assert d_arm.drift_status == "exceeded"
    assert d_x86.drift_status == "clean"
    assert d_fat1.drift_status == "exceeded"
    assert dataclasses.asdict(d_fat1) == dataclasses.asdict(d_fat2)
    assert d_legacy.drift_status == "exceeded"
    assert d_fat1.slice_drift["arm64"] == d_arm.slice_drift["arm64"]
    assert d_fat1.slice_drift["x86_64"] == d_x86.slice_drift["x86_64"]
    assert "arm64: com.apple.security.app-sandbox=disabled" in d_fat1.undeclared_privileges

    # Conflicting privilege arrays + boolean grants across slices (invariant to order)
    arm_arr = _build_synthetic_macho64(
        cputype=0x0100000C,
        entitlements_xml=plistlib.dumps({grp_key: ["group.shared", "group.extra"], jit_key: True}).decode("utf-8"),
    )
    x86_arr = _build_synthetic_macho64(
        cputype=0x01000007,
        entitlements_xml=plistlib.dumps({grp_key: ["group.shared"], jit_key: False}).decode("utf-8"),
    )
    arr_spec = [SourceEntitlementSpec("App.entitlements", "App", {grp_key: ["group.shared"]})]
    for fat_arr in (
        _pack_fat_macho([(0x0100000C, 0, arm_arr), (0x01000007, 3, x86_arr)]),
        _pack_fat_macho([(0x01000007, 3, x86_arr), (0x0100000C, 0, arm_arr)]),
    ):
        c_arr = parse_macho_bytes(fat_arr, source_name="App")
        d_arr = evaluate_entitlement_drift(
            artifact_name="App",
            signed_entitlements=c_arr.entitlements,
            linux_capabilities=(),
            source_specs=arr_spec,
            slice_entitlements=c_arr.slice_entitlements,
            slice_has_entitlements_blob=c_arr.slice_has_entitlements_blob,
        )
        assert d_arr.drift_status == "exceeded"
        assert f"arm64: {grp_key}=group.extra" in d_arr.undeclared_privileges
        assert f"arm64: {jit_key}" in d_arr.undeclared_privileges

    # Universal binary with NO entitlements blob on one slice + sandboxed slice -> FAIL BIN-ENT-001
    arm_no_ent = _build_synthetic_macho64(cputype=0x0100000C, entitlements_xml=None)
    fat_missing_ent_1 = _pack_fat_macho([(0x0100000C, 0, arm_no_ent), (0x01000007, 3, x86_sandboxed)])
    fat_missing_ent_2 = _pack_fat_macho([(0x01000007, 3, x86_sandboxed), (0x0100000C, 0, arm_no_ent)])

    bin_repo = tmp_path / "binary_repo"
    _write(bin_repo, "backend/schema.sql", "CREATE TABLE items (id INTEGER PRIMARY KEY);\n")
    _write(bin_repo, "App.entitlements", plistlib.dumps({sb_key: True}).decode("utf-8"))
    bin_path = bin_repo / "App"

    for slug, payload, expected_verdict in (
        ("w401-arm", arm_unsandboxed, "FAIL"),
        ("w401-x86", x86_sandboxed, "PASS"),
        ("w401-fat1", fat_arm_first, "FAIL"),
        ("w401-fat2", fat_x86_first, "FAIL"),
        ("w401-noent1", fat_missing_ent_1, "FAIL"),
        ("w401-noent2", fat_missing_ent_2, "FAIL"),
    ):
        bin_path.write_bytes(payload)
        with binary_inspection_scope(bin_path):
            rep = _scan_repo(bin_repo, slug=slug, include_binary_plugin=True)
        assert rep.gate.verdict == expected_verdict, f"{slug} gate={rep.gate.verdict}"
        bin_f = [f for f in rep.findings if f.rule_code == "BIN-ENT-001"]
        assert (len(bin_f) == 1) if expected_verdict == "FAIL" else (len(bin_f) == 0)

    comp_noent = correlate_binary_companions(bin_repo, rep, binary_paths=[bin_path])
    assert comp_noent["artifacts"][0]["slice_has_entitlements_blob"] == {
        "arm64": False,
        "x86_64": True,
    }
    assert (
        cli_main(
            [
                "gate",
                "--strict",
                str(bin_repo),
                "--allow-local-plugins",
                "--plugin",
                "wythe_plugin_binary.plugin",
                "--binary",
                str(bin_path),
            ]
        )
        == 1
    )


def test_w4_04_indexstoredb_role_bits_numeric_named_parity_and_unverified_fallback() -> None:
    # Full fixture exercising intervening local variables/fields/params, nested decls,
    # inheritance (`baseOf=1024`), overrides (`overrideOf=2048`), containment (`childOf=512`,
    # `containedBy=65536`), calls (`calledBy=8192`), and remaining CIndexStoreDB.h bits.
    symbols = [
        {"usr": "c:@S@Base", "name": "Base", "kind": "class", "file": "main.cc", "line": 1},
        {"usr": "c:@S@Base@F@run#", "name": "Base::run", "kind": "method", "file": "main.cc", "line": 2},
        {"usr": "c:@S@Derived", "name": "Derived", "kind": "class", "file": "main.cc", "line": 5},
        {"usr": "c:@S@Derived@S@Nested", "name": "Derived::Nested", "kind": "struct", "file": "main.cc", "line": 6},
        {"usr": "c:@S@Derived@F@run#", "name": "Derived::run", "kind": "method", "file": "main.cc", "line": 8},
        {"usr": "c:@F@f", "name": "f", "kind": "function", "file": "main.cc", "line": 12},
        {"usr": "c:main.cc@param_x", "name": "param_x", "kind": "parameter", "file": "main.cc", "line": 12},
        {"usr": "c:main.cc@local", "name": "local", "kind": "variable", "file": "main.cc", "line": 14},
        {"usr": "c:@S@Derived@FI@field_", "name": "field_", "kind": "field", "file": "main.cc", "line": 15},
        {"usr": "c:@F@g", "name": "g", "kind": "function", "file": "other.cc", "line": 1},
    ]
    numeric_doc = {
        "symbols": symbols,
        "occurrences": [
            {
                "usr": "c:@S@Base",
                "file": "main.cc",
                "line": 5,
                "roles": 4,
                "relations": [{"usr": "c:@S@Derived", "roles": 1024}],
            },
            {
                "usr": "c:@S@Derived@S@Nested",
                "file": "main.cc",
                "line": 6,
                "roles": 2,
                "relations": [{"usr": "c:@S@Derived", "roles": 512}],
            },
            {
                "usr": "c:@S@Derived@F@run#",
                "file": "main.cc",
                "line": 8,
                "roles": 2,
                "relations": [
                    {"usr": "c:@S@Derived", "roles": 512},
                    {"usr": "c:@S@Base@F@run#", "roles": 2048},
                ],
            },
            {
                "usr": "c:main.cc@local",
                "file": "main.cc",
                "line": 14,
                "roles": 2,
                "relations": [{"usr": "c:@F@f", "roles": 65536}],
            },
            {
                "usr": "c:@F@g",
                "file": "main.cc",
                "line": 16,
                "roles": 36,
                "relations": [
                    {"usr": "c:@S@Derived", "roles": 65536},
                    {"usr": "c:@F@f", "roles": 8192},
                ],
            },
        ],
    }
    named_doc = {
        "symbols": symbols,
        "occurrences": [
            {
                "usr": "c:@S@Base",
                "file": "main.cc",
                "line": 5,
                "roles": ["reference"],
                "relations": [{"usr": "c:@S@Derived", "roles": ["baseOf"]}],
            },
            {
                "usr": "c:@S@Derived@S@Nested",
                "file": "main.cc",
                "line": 6,
                "roles": ["definition"],
                "relations": [{"usr": "c:@S@Derived", "roles": ["childOf"]}],
            },
            {
                "usr": "c:@S@Derived@F@run#",
                "file": "main.cc",
                "line": 8,
                "roles": ["definition"],
                "relations": [
                    {"usr": "c:@S@Derived", "roles": ["childOf"]},
                    {"usr": "c:@S@Base@F@run#", "roles": ["overrideOf"]},
                ],
            },
            {
                "usr": "c:main.cc@local",
                "file": "main.cc",
                "line": 14,
                "roles": ["definition"],
                "relations": [{"usr": "c:@F@f", "roles": ["containedBy"]}],
            },
            {
                "usr": "c:@F@g",
                "file": "main.cc",
                "line": 16,
                "roles": ["reference", "call"],
                "relations": [
                    {"usr": "c:@S@Derived", "roles": ["containedBy"]},
                    {"usr": "c:@F@f", "roles": ["calledBy"]},
                ],
            },
        ],
    }

    numeric_bundle = parse_usr_index_text(json.dumps(numeric_doc))
    named_bundle = parse_usr_index_text(json.dumps(named_doc))
    assert numeric_bundle.dialect == "indexstoredb"
    assert [dataclasses.asdict(x) for x in numeric_bundle.cross_refs] == [
        dataclasses.asdict(x) for x in named_bundle.cross_refs
    ]
    call_edges = [x for x in numeric_bundle.cross_refs if x.kind == "calls_usr"]
    assert len(call_edges) == 1
    assert call_edges[0].caller_usr == "c:@F@f"
    assert call_edges[0].caller_name == "f"
    assert call_edges[0].callee_name == "g"
    assert call_edges[0].verification == "verified"
    assert any(x.kind == "inherits_usr" and x.caller_name == "Derived" and x.callee_name == "Base" for x in numeric_bundle.cross_refs)
    assert any(x.kind == "witness_dispatch" and x.caller_name == "Derived::run" and x.callee_name == "Base::run" for x in numeric_bundle.cross_refs)
    assert any(x.kind == "contains_usr" and x.caller_name == "Derived" and x.callee_name == "Derived::Nested" for x in numeric_bundle.cross_refs)

    parent = AtlasNode(
        id="m:test", tier="manipulate", subkind="service", label="main", source_file="main.cc", summary="Probe"
    )
    drill_num = _expand_node_zoom2(parent, CompilerIrBundle(usr_index=numeric_bundle), MetalSeamAnalysis())
    drill_nam = _expand_node_zoom2(parent, CompilerIrBundle(usr_index=named_bundle), MetalSeamAnalysis())
    assert [e.model_dump() for e in drill_num.edges] == [e.model_dump() for e in drill_nam.edges]

    # Unknown higher role bit (`1 << 20`) and missing `calledBy` must NEVER map to `calledBy` or `verified`!
    unverified_doc = {
        "symbols": symbols,
        "occurrences": [
            {
                "usr": "c:@F@g",
                "file": "main.cc",
                "line": 16,
                "roles": (1 << 5) | (1 << 2) | (1 << 12) | (1 << 14) | (1 << 15) | (1 << 17) | (1 << 18) | (1 << 20),
                "relations": [{"usr": "c:main.cc@local", "roles": 1 << 20}],
            }
        ],
    }
    unv_bundle = parse_usr_index_text(json.dumps(unverified_doc))
    occ0 = unv_bundle.occurrences[0]
    assert "unknown_role_0x100000" in occ0.roles
    assert {"receivedBy", "extendedBy", "accessorOf", "ibTypeOf", "specializationOf"} <= set(occ0.roles)
    assert occ0.relations[0].roles == ("unknown_role_0x100000",)
    assert "calledBy" not in occ0.relations[0].roles
    # Heuristic skips `local`/`field_`/`param_x`, selects callable `f`, and keeps it strictly `unverified`
    assert len(unv_bundle.cross_refs) == 1
    assert unv_bundle.cross_refs[0].caller_name == "f"
    assert unv_bundle.cross_refs[0].verification == "unverified"
    assert any("unverified" in nt for nt in unv_bundle.notes)
    drill_unv = _expand_node_zoom2(parent, CompilerIrBundle(usr_index=unv_bundle), MetalSeamAnalysis())
    assert all(e.verification != "verified" for e in drill_unv.edges)
    assert upgrade_edges_with_compiler_ir([], [parent], CompilerIrBundle(usr_index=unv_bundle)) == 0

    # Optional explicit `dialect="clang"` (`RelationCalledBy = 1 << 14` = 16384 in upstream Clang)
    clang_doc = {
        "dialect": "clang",
        "symbols": symbols,
        "occurrences": [
            {
                "usr": "c:@F@g",
                "file": "main.cc",
                "line": 16,
                "roles": 36,
                "relations": [{"usr": "c:@F@f", "roles": 1 << 14}],
            }
        ],
    }
    clang_bundle = parse_usr_index_text(json.dumps(clang_doc))
    assert clang_bundle.dialect == "clang"
    assert clang_bundle.cross_refs[0].caller_name == "f"
    assert clang_bundle.cross_refs[0].verification == "verified"


def test_w4_03_xpc_send_site_requires_transport_invocation_vs_mentions_and_dynamic(
    tmp_path: Path,
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    ipc = tmp_path / "ipc_sample"
    _write(
        ipc,
        "Package.swift",
        """// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "Sample",
    targets: [
        .executableTarget(name: "CLI", dependencies: ["Transport"]),
        .target(name: "Transport"),
    ]
)
""",
    )
    _write(
        ipc,
        "Sources/Transport/XPCClient.swift",
        """import Foundation
public struct XPCMessage: Sendable {
    public let route: String
    public init(route: String) { self.route = route }
}
public final class XPCClient: Sendable {
    public init(serviceName: String) {}
    public func send(_ message: XPCMessage) async throws {}
    public func send(_ route: DemoXPCRoutes) async throws {}
}
public actor XPCServer {
    public func register(_ route: String, handler: @Sendable () -> Void) {}
}
public enum DemoXPCRoutes: String, Sendable {
    case unused = "demo/unused"
    case unhandled = "demo/unhandled"
    case handled = "demo/handled"
}
""",
    )
    # 1. Negative controls: print, array/dict table storage, `==` comparison, unsent XPCMessage construction
    _write(
        ipc,
        "Sources/CLI/Main.swift",
        """import ArgumentParser
import Transport
struct Main: AsyncParsableCommand {
    func run() async throws {
        print(DemoXPCRoutes.unused.rawValue)
        let routeList = [DemoXPCRoutes.unused, DemoXPCRoutes.unhandled]
        let routeMap = ["k": DemoXPCRoutes.unused]
        let probe = DemoXPCRoutes.unused
        if probe == DemoXPCRoutes.unused { _ = (routeList, routeMap) }
        let unsentMsg = XPCMessage(route: DemoXPCRoutes.unhandled.rawValue)
        _ = unsentMsg
        let dynKey = String(describing: routeList.count)
        let client = XPCClient(serviceName: "com.example.demo")
        try await client.send(XPCMessage(route: dynKey))
    }
}
""",
    )
    out_clean = extract_swift_systems_repo(ipc)
    assert [f for f in out_clean.findings if f.rule_code == "IPC-001"] == []
    _, rep_clean = _scan_with_apple_ipc(ipc, "ipc-clean-controls")
    assert rep_clean.gate.verdict == "PASS"
    assert any(e.verification == "unverified" for e in rep_clean.edges)

    # 2. Real unhandled transport send (`client.send(DemoXPCRoutes.unhandled)` & local binding) -> FAIL IPC-001
    _write(
        ipc,
        "Sources/CLI/Main.swift",
        """import ArgumentParser
import Transport
struct Main: AsyncParsableCommand {
    func run() async throws {
        let client = XPCClient(serviceName: "com.example.demo")
        let targetRoute = DemoXPCRoutes.unhandled
        try await client.send(targetRoute)
    }
}
""",
    )
    _, rep_fail = _scan_with_apple_ipc(ipc, "ipc-unhandled-send")
    assert rep_fail.gate.verdict == "FAIL"
    ipc_f = [f for f in rep_fail.findings if f.rule_code == "IPC-001"]
    assert len(ipc_f) == 1
    assert "DemoXPCRoutes.unhandled" in ipc_f[0].title

    # 3. Registering the server handler clears `IPC-001` -> PASS
    _write(
        ipc,
        "Sources/Transport/DemoServer.swift",
        """public struct DemoServer {
    public func install(on server: XPCServer) async {
        await server.register(DemoXPCRoutes.unhandled.rawValue) {}
    }
}
""",
    )
    _, rep_fixed = _scan_with_apple_ipc(ipc, "ipc-handled-send")
    assert rep_fixed.gate.verdict == "PASS"
    assert [f for f in rep_fixed.findings if f.rule_code == "IPC-001"] == []


def test_w4_02_stateful_per_encoder_metal_bindings_and_conditional_uncertainty(
    tmp_path: Path,
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    metal_repo = tmp_path / "metal_repo"
    _write(metal_repo, "backend/schema.sql", "CREATE TABLE items (id INTEGER PRIMARY KEY);\n")
    _write(metal_repo, "backend/app/services/gpu.py", "def run():\n    return 1\n")
    _write(
        metal_repo,
        "scale.metal",
        """#include <metal_stdlib>
using namespace metal;
kernel void scale(device float *a [[buffer(0)]], device float *b [[buffer(1)]],
                  uint tid [[thread_position_in_grid]]) { b[tid] = 2 * a[tid]; }
""",
    )

    # 1. Retained slot 0 across two dispatches + legal slot replacement before dispatch -> PASS (`0` METAL-002)
    _write(
        metal_repo,
        "backend/app/services/valid_host.swift",
        """import Metal
func runRetainedAndRebound(lib: MTLLibrary, dev: MTLDevice, enc: MTLComputeCommandEncoder,
                           a: MTLBuffer, b: MTLBuffer, c: MTLBuffer) throws {
    let fn = lib.makeFunction(name: "scale")!
    let pipeline = try dev.makeComputePipelineState(function: fn)
    enc.setComputePipelineState(pipeline)
    enc.setBuffer(a, offset: 0, index: 0)
    enc.setBuffer(b, offset: 0, index: 1)
    enc.setBuffer(c, offset: 0, index: 1)
    enc.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
    enc.setBuffer(b, offset: 0, index: 1)
    enc.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
}
""",
    )
    seam_valid = verify_metal_compute_seams(metal_repo)
    assert [f for f in seam_valid.findings if f["rule_code"] == "METAL-002"] == []
    rep_valid = _scan_python_metal_repo(metal_repo, slug="w402-valid")
    assert rep_valid.gate.verdict == "PASS"
    assert [f for f in rep_valid.findings if f.rule_code == "METAL-002"] == []

    # 2. Conditional `if`-only slot binding + helper-passed encoder -> unverified, NOT blocking confirmed METAL-002
    _write(
        metal_repo,
        "backend/app/services/conditional_host.swift",
        """import Metal
func bindViaBranch(lib: MTLLibrary, dev: MTLDevice, enc: MTLComputeCommandEncoder,
                   a: MTLBuffer, b: MTLBuffer, cond: Bool) throws {
    let fn = lib.makeFunction(name: "scale")!
    let pipeline = try dev.makeComputePipelineState(function: fn)
    enc.setComputePipelineState(pipeline)
    if cond {
        enc.setBuffer(a, offset: 0, index: 0)
    }
    enc.setBuffer(b, offset: 0, index: 1)
    enc.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
}
func bindViaHelper(lib: MTLLibrary, dev: MTLDevice, enc: MTLComputeCommandEncoder) throws {
    let fn = lib.makeFunction(name: "scale")!
    let pso = try dev.makeComputePipelineState(function: fn)
    enc.setComputePipelineState(pso)
    configureSlots(enc)
    enc.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
}
""",
    )
    seam_cond = verify_metal_compute_seams(metal_repo)
    assert [f for f in seam_cond.findings if f["rule_code"] == "METAL-002"] == []
    cond_disps = [d for d in seam_cond.host_dispatches if "conditional_host.swift" in d.source_file]
    assert len(cond_disps) == 2
    assert all(d.binding_verification == "unverified" for d in cond_disps)
    assert any("unverified" in nt for nt in seam_cond.notes)
    rep_cond = _scan_python_metal_repo(metal_repo, slug="w402-cond")
    assert rep_cond.gate.verdict == "PASS"

    # 3. Two independent encoders `enc1` & `enc2` in one function: `enc1` binds 0 & 1, `enc2` omits 0 -> FAIL METAL-002!
    _write(
        metal_repo,
        "backend/app/services/two_encoders.swift",
        """import Metal
func runTwoEncoders(lib: MTLLibrary, dev: MTLDevice,
                    enc1: MTLComputeCommandEncoder, enc2: MTLComputeCommandEncoder,
                    a: MTLBuffer, b: MTLBuffer) throws {
    let fn = lib.makeFunction(name: "scale")!
    let pipeline = try dev.makeComputePipelineState(function: fn)
    enc1.setComputePipelineState(pipeline)
    enc1.setBuffer(a, offset: 0, index: 0)
    enc1.setBuffer(b, offset: 0, index: 1)
    enc1.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))

    enc2.setComputePipelineState(pipeline)
    enc2.setBuffer(b, offset: 0, index: 1)
    enc2.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
}
""",
    )
    rep_two = _scan_python_metal_repo(metal_repo, slug="w402-two-enc")
    assert rep_two.gate.verdict == "FAIL"
    m002 = [f for f in rep_two.findings if f.rule_code == "METAL-002"]
    assert len(m002) == 1
    assert "[[buffer(0)]]" in m002[0].title
    assert "enc2" in m002[0].detail


def test_w4_05_qualified_cpp_namespace_usr_singleton_vertices_and_ambiguous_using(
    tmp_path: Path,
) -> None:
    # 1. Acyclic 4-type `left::A -> right::B` & `left::B -> right::A` + USR index with same short names -> 0 cycles
    acyclic_cpp = tmp_path / "cpp_acyclic"
    _write(
        acyclic_cpp,
        "engine.cc",
        """struct Model { template<class T> T* GetOrCreate() { return nullptr; } };
namespace right { class A {}; class B {}; }
namespace left {
class A {
public:
    explicit A(Model* model) {
        model->GetOrCreate<right::B>();
    }
};
class B {
public:
    explicit B(Model* model) {
        model->GetOrCreate<right::A>();
    }
};
}
""",
    )
    usr_file = tmp_path / "same_short_usr.json"
    usr_file.write_text(
        json.dumps(
            {
                "symbols": [
                    {"usr": "c:@N@left@S@A", "name": "A", "kind": "class", "file": "engine.cc", "line": 4},
                    {"usr": "c:@N@right@S@A", "name": "A", "kind": "class", "file": "engine.cc", "line": 2},
                    {"usr": "c:@N@left@S@B", "name": "B", "kind": "class", "file": "engine.cc", "line": 10},
                    {"usr": "c:@N@right@S@B", "name": "B", "kind": "class", "file": "engine.cc", "line": 2},
                ]
            }
        ),
        encoding="utf-8",
    )
    usr_idx = load_cpp_usr_index([usr_file], repo_root=acyclic_cpp)
    sg_acyclic = extract_singleton_dependency_graph(acyclic_cpp, usr_index=usr_idx)
    assert sg_acyclic.cycles == ()
    assert sg_acyclic.findings == ()
    assert set(sg_acyclic.singletons) == {"left::A", "left::B", "right::A", "right::B"}
    assert sg_acyclic.singletons["left::A"].usr == "c:@N@left@S@A"
    assert sg_acyclic.singletons["right::A"].usr == "c:@N@right@S@A"

    z2_nodes, z2_edges = build_singleton_zoom2_subgraph("m:solver:engine", sg_acyclic, usr_index=usr_idx)
    assert {n.label for n in z2_nodes if n.kind == "cpp_singleton"} == {
        "left::A",
        "left::B",
        "right::A",
        "right::B",
    }
    for zn in z2_nodes:
        assert validate_semantic_atlas_id(zn.id) == zn.id
    for ze in z2_edges:
        assert validate_semantic_atlas_id(ze.id) == ze.id

    # 2. Genuine 3-hop qualified cycle `ns1::A -> ns2::B -> ns3::sub::C -> ns1::A` + self-cycle `ns1::Self -> ns1::Self`
    cyclic_cpp = tmp_path / "cpp_cyclic"
    _write(
        cyclic_cpp,
        "qualified_cycles.cc",
        """namespace ns3::sub { class C; }
namespace ns2 { class B; }
namespace ns1 {
using TargetB = ns2::B;
class A {
public:
    explicit A(Model* model) { model->GetOrCreate<TargetB>(); }
};
class Self {
public:
    explicit Self(Model* model) { model->GetOrCreate<Self>(); }
};
}
namespace ns2 {
class B {
public:
    explicit B(Model* model) { model->GetOrCreate<ns3::sub::C>(); }
};
}
namespace ns3::sub {
class C {
public:
    explicit C(Model* model) { model->GetOrCreate<::ns1::A>(); }
};
}
""",
    )
    sg_cyclic = extract_singleton_dependency_graph(cyclic_cpp)
    chains = {c.chain for c in sg_cyclic.cycles}
    assert ("ns1::A", "ns2::B", "ns3::sub::C", "ns1::A") in chains
    assert ("ns1::Self", "ns1::Self") in chains
    assert len([f for f in sg_cyclic.findings if f.rule_code == "SAT-INT-003"]) == 2

    # 3. Ambiguous `using namespace left; using namespace right;` suppresses definite confirmed SAT-INT-003
    ambig_cpp = tmp_path / "cpp_ambig"
    _write(
        ambig_cpp,
        "ambig.cc",
        """namespace left { class A {}; class B {}; }
namespace right { class A {}; class B {}; }
using namespace left;
using namespace right;
A::A(Model* model) { model->GetOrCreate<B>(); }
B::B(Model* model) { model->GetOrCreate<A>(); }
""",
    )
    sg_ambig = extract_singleton_dependency_graph(ambig_cpp)
    assert sg_ambig.cycles == ()
    assert sg_ambig.findings == ()
    assert all(d.is_ambiguous for d in sg_ambig.dependencies)
    assert all(e.verification == "unverified" for e in sg_ambig.atlas_edges)


def test_round2_verifier_edge_cases_arm64e_xpc_non_send_cpp17_brace_init_and_optional_metal(
    tmp_path: Path,
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    sb_key = "com.apple.security.app-sandbox"
    specs = [SourceEntitlementSpec("App.entitlements", "App", {sb_key: True})]

    # 1. W4-01a/b: `arm64` + `arm64e` + `x86_64h` subtype decoding & recorded JSON `slice_entitlements`
    arm64_unsb = bytearray(
        _build_synthetic_macho64(
            cputype=0x0100000C,
            entitlements_xml=plistlib.dumps({sb_key: False}).decode("utf-8"),
        )
    )
    arm64e_sb = bytearray(
        _build_synthetic_macho64(
            cputype=0x0100000C,
            entitlements_xml=plistlib.dumps({sb_key: True}).decode("utf-8"),
        )
    )
    struct.pack_into("<i", arm64e_sb, 8, 2)
    x86h_sb = bytearray(
        _build_synthetic_macho64(
            cputype=0x01000007,
            entitlements_xml=plistlib.dumps({sb_key: True}).decode("utf-8"),
        )
    )
    struct.pack_into("<i", x86h_sb, 8, 8)
    assert parse_macho_bytes(bytes(x86h_sb), source_name="App").architectures == ("x86_64h",)

    fat_arm_arm64e = _pack_fat_macho([(0x0100000C, 0, bytes(arm64_unsb)), (0x0100000C, 2, bytes(arm64e_sb))])
    fat_arm64e_arm = _pack_fat_macho([(0x0100000C, 2, bytes(arm64e_sb)), (0x0100000C, 0, bytes(arm64_unsb))])
    cap_ae_1 = parse_macho_bytes(fat_arm_arm64e, source_name="App")
    cap_ae_2 = parse_macho_bytes(fat_arm64e_arm, source_name="App")
    assert set(cap_ae_1.architectures) == {"arm64", "arm64e"}
    d_ae_1 = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_ae_1.entitlements,
        linux_capabilities=(),
        source_specs=specs,
        slice_entitlements=cap_ae_1.slice_entitlements,
        slice_has_entitlements_blob=cap_ae_1.slice_has_entitlements_blob,
    )
    d_ae_2 = evaluate_entitlement_drift(
        artifact_name="App",
        signed_entitlements=cap_ae_2.entitlements,
        linux_capabilities=(),
        source_specs=specs,
        slice_entitlements=cap_ae_2.slice_entitlements,
        slice_has_entitlements_blob=cap_ae_2.slice_has_entitlements_blob,
    )
    assert dataclasses.asdict(d_ae_1) == dataclasses.asdict(d_ae_2)
    assert d_ae_1.undeclared_privileges == ("arm64: com.apple.security.app-sandbox=disabled",)

    rec_json = json.dumps(
        {
            "name": "App",
            "format": "macho",
            "architectures": ["arm64", "x86_64"],
            "slice_entitlements": {
                "arm64": {sb_key: False, "com.apple.security.cs.allow-jit": True},
                "x86_64": {sb_key: True},
            },
        }
    ).encode("utf-8")
    rec_cap = parse_recorded_fixture(rec_json, source_name="App.json")
    assert rec_cap.entitlements == {
        sb_key: False,
        "com.apple.security.cs.allow-jit": True,
    }

    # 2. W4-03: Non-send methods on variables/enums containing `"xpc"` emit `0` `IPC-001`
    ipc_r2 = tmp_path / "ipc_r2"
    _write(
        ipc_r2,
        "Package.swift",
        """// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "Sample", targets: [.executableTarget(name: "CLI")])
""",
    )
    _write(
        ipc_r2,
        "Sources/CLI/Routes.swift",
        """enum DemoXPCRoutes: String {
    case unused = "demo/unused"
}
""",
    )
    _write(
        ipc_r2,
        "Sources/CLI/Main.swift",
        """import ArgumentParser
struct Main: ParsableCommand {
    func run() {
        let xpcRoutes = [DemoXPCRoutes.unused]
        _ = xpcRoutes.contains(DemoXPCRoutes.unused)
        _ = DemoXPCRoutes.unused.rawValue.hasPrefix("demo")
        _ = DemoXPCRoutes.init(rawValue: "demo/unused")
    }
}
""",
    )
    out_r2 = extract_swift_systems_repo(ipc_r2)
    assert [f for f in out_r2.findings if f.rule_code == "IPC-001"] == []

    # 3. W4-05: C++17 brace member-initializers in constructor initializer lists preserve SAT-INT-003
    cpp_brace = tmp_path / "cpp_brace_init"
    _write(
        cpp_brace,
        "brace_ctor.cc",
        """namespace ns2 { class B; }
namespace ns1 {
class A {
    int count_;
    ns2::B* b_;
public:
    explicit A(Model* model) : count_{0}, b_(model->GetOrCreate<ns2::B>()) {}
};
}
namespace ns2 {
class B {
    int count_;
    ns1::A* a_;
public:
    explicit B(Model* model) : a_{model->GetOrCreate<ns1::A>()}, count_{0} {}
};
}
""",
    )
    sg_brace = extract_singleton_dependency_graph(cpp_brace)
    assert any(c.chain == ("ns1::A", "ns2::B", "ns1::A") for c in sg_brace.cycles)
    assert len([f for f in sg_brace.findings if f.rule_code == "SAT-INT-003"]) == 1

    # 4. W4-02: Swift optional-chaining encoder calls (`enc?.dispatchThreads`) detect missing buffer 0
    metal_opt = tmp_path / "metal_opt"
    _write(metal_opt, "backend/schema.sql", "CREATE TABLE items (id INTEGER PRIMARY KEY);\n")
    _write(metal_opt, "backend/app/services/gpu.py", "def run():\n    return 1\n")
    _write(
        metal_opt,
        "scale.metal",
        """#include <metal_stdlib>
using namespace metal;
kernel void scale(device float *a [[buffer(0)]], device float *b [[buffer(1)]]) {}
""",
    )
    _write(
        metal_opt,
        "backend/app/services/opt_host.swift",
        """import Metal
func runOpt(lib: MTLLibrary, dev: MTLDevice, cmd: MTLCommandBuffer, b: MTLBuffer) throws {
    let fn = lib.makeFunction(name: "scale")!
    let pso = try dev.makeComputePipelineState(function: fn)
    let enc = cmd.makeComputeCommandEncoder()
    enc?.setComputePipelineState(pso)
    enc?.setBuffer(b, offset: 0, index: 1)
    enc?.dispatchThreads(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
    enc?.endEncoding()
}
""",
    )
    rep_opt = _scan_python_metal_repo(metal_opt, slug="w402-opt-chain")
    assert rep_opt.gate.verdict == "FAIL"
    m002_opt = [f for f in rep_opt.findings if f.rule_code == "METAL-002"]
    assert len(m002_opt) == 1
    assert "[[buffer(0)]]" in m002_opt[0].title
