"""Wythe stack-adapter plugin registration for `wythe-plugin-apple-ipc` (`#76`)."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from app.adapters import plugin_registry as _plugin_reg
from app.adapters.base import (
    DisplayExtractionResult,
    ManipulatorExtractionResult,
    TruthExtractionResult,
)
from wythe_plugin_apple_ipc.package_manifest import (
    iter_safe_repo_files,
    validate_safe_directory,
)
from wythe_plugin_apple_ipc.swift_extractor import (
    SwiftRepoExtraction,
    extract_swift_systems_repo,
)


@dataclass(frozen=True)
class _FallbackStackProfileSpec:
    slug: str
    name: str
    truth_adapter: str
    manipulator_adapter: str
    display_adapter: str
    maturity_status: Literal["implemented", "experimental"] = "implemented"
    description: str = ""


PluginStackProfileSpec = getattr(
    _plugin_reg, "PluginStackProfileSpec", _FallbackStackProfileSpec
)
PluginRuleSpec = _plugin_reg.PluginRuleSpec
WythePluginSpec = _plugin_reg.WythePluginSpec

_REPO_EXTRACTION_CACHE: OrderedDict[tuple[object, ...], SwiftRepoExtraction] = OrderedDict()
_REPO_CACHE_MAX = 8


def _repo_state_key(real_root: Path) -> tuple[object, ...]:
    pkg = real_root / "Package.swift"
    pkg_sig: tuple[object, ...] = ()
    if pkg.exists() and not pkg.is_symlink():
        st = pkg.lstat()
        pkg_sig = (st.st_mtime_ns, st.st_size)
    files, excl_links, _ = iter_safe_repo_files(
        real_root,
        {".swift", ".c", ".h", ".proto", ".entitlements", ".plist"},
        include_tests=False,
    )
    f_sigs = []
    for fp, rel_f in files:
        try:
            fst = fp.lstat()
            f_sigs.append((rel_f, fst.st_mtime_ns, fst.st_size))
        except OSError:
            continue
    return (str(real_root), pkg_sig, excl_links, tuple(f_sigs))


def _cached_swift_extraction(repo_root: Path) -> SwiftRepoExtraction:
    real_root = validate_safe_directory(repo_root)
    pkg = real_root / "Package.swift"
    if pkg.is_symlink():
        raise ValueError("Symlink component rejected in 'Package.swift'.")
    key = _repo_state_key(real_root)
    hit = _REPO_EXTRACTION_CACHE.get(key)
    if hit is not None:
        _REPO_EXTRACTION_CACHE.move_to_end(key)
        return hit
    extracted = extract_swift_systems_repo(repo_root)
    _REPO_EXTRACTION_CACHE[key] = extracted
    while len(_REPO_EXTRACTION_CACHE) > _REPO_CACHE_MAX:
        _REPO_EXTRACTION_CACHE.popitem(last=False)
    return extracted


class SwiftStoresTruthAdapter:
    """Tier-1 Truth adapter for Swift entity/OCI stores, launchd plists, and entitlements."""

    name = "swift-stores-truth"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        _ = (backend_subdir, pg_dsn)
        ext = _cached_swift_extraction(repo_root)
        return TruthExtractionResult(
            nodes=[n.model_copy(deep=True) for n in ext.truth_nodes],
            table_symbol_map=dict(ext.truth_symbol_map),
            function_symbol_map={},
            findings=[],
            observation_source="static_ast",
            notes=[],
            coverage_complete=True,
        )


class SwiftIpcManipulatorAdapter:
    """Tier-2 Manipulate adapter for Swift XPC, vsock/gRPC, C-FFI shims, and services."""

    name = "swift-ipc-manipulator"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        _ = (backend_subdir, truth)
        ext = _cached_swift_extraction(repo_root)
        flagged_nids = {
            f.node_id for f in ext.findings if f.node_id and f.rule_code in ("IPC-001", "MANIP-006")
        }
        nodes_copy = [
            n.model_copy(
                deep=True,
                update={"status": "gray_zone"} if n.id in flagged_nids and n.status == "clean" else {},
            )
            for n in ext.manip_nodes
        ]
        return ManipulatorExtractionResult(
            nodes=nodes_copy,
            edges=[e.model_copy(deep=True) for e in ext.manip_edges],
            routes=[],
            findings=list(ext.findings),
            notes=list(ext.notes),
            coverage_complete=True,
        )


class SwiftCliDisplayAdapter:
    """Tier-3 Display adapter for Swift `ArgumentParser` CLI command hierarchies."""

    name = "swift-cli-display"

    def extract(
        self,
        repo_root: Path,
        frontend_subdir: str,
    ) -> DisplayExtractionResult:
        _ = frontend_subdir
        ext = _cached_swift_extraction(repo_root)
        flagged_disp = {
            f.node_id for f in ext.findings if f.node_id and f.rule_code in ("IPC-001", "MANIP-006")
        }
        nodes_copy = [
            n.model_copy(
                deep=True,
                update={"status": "gray_zone"} if n.id in flagged_disp and n.status == "clean" else {},
            )
            for n in ext.disp_nodes
        ]
        return DisplayExtractionResult(
            nodes=nodes_copy,
            edges=[e.model_copy(deep=True) for e in ext.disp_edges],
            http_calls=[],
            findings=[],
            notes=[],
            coverage_complete=True,
        )


SWIFT_SYSTEMS_IPC_PROFILE = PluginStackProfileSpec(
    slug="swift-systems-ipc",
    name="Swift & Systems IPC (CLI / XPC / vsock / gRPC / Stores)",
    truth_adapter="swift-stores-truth",
    manipulator_adapter="swift-ipc-manipulator",
    display_adapter="swift-cli-display",
    maturity_status="implemented",
    description=(
        "Native Swift and C-FFI systems profile mapping ArgumentParser CLI commands, "
        "XPC/vsock/gRPC service handlers, persistent OCI/entity stores, launchd Mach "
        "service plists, and code-signing entitlements."
    ),
)

IPC_001_RULE = PluginRuleSpec(
    rule_code="IPC-001",
    tier="manipulate",
    title="Static in-repo XPC/IPC route key has no registered server handler in repository scope",
    severity="blocking",
    blocks_gate=True,
    enabled=True,
    confidence="confirmed",
    evidence_strength="structural_match",
)


def _build_apple_ipc_plugin_spec() -> WythePluginSpec:
    kwargs: dict[str, object] = {
        "name": "apple_ipc",
        "version": "0.1.0",
        "description": (
            "Pure-Python Swift & Systems IPC stack profile and boundary verifier "
            "(CLI / XPC / vsock / gRPC / C-FFI / Stores / Entitlements)."
        ),
        "enabled_by_default": True,
        "rules": (IPC_001_RULE,),
    }
    spec_fields = WythePluginSpec.__dataclass_fields__
    if "truth_adapters" in spec_fields:
        kwargs["kind"] = "stack_adapter"
        kwargs["origin"] = "entry_point"
        kwargs["truth_adapters"] = (SwiftStoresTruthAdapter(),)
        kwargs["manipulator_adapters"] = (SwiftIpcManipulatorAdapter(),)
        kwargs["display_adapters"] = (SwiftCliDisplayAdapter(),)
        kwargs["stack_profiles"] = (SWIFT_SYSTEMS_IPC_PROFILE,)
    else:
        kwargs["kind"] = "post_scan_check"
    return WythePluginSpec(**kwargs)  # type: ignore[arg-type]


APPLE_IPC_PLUGIN = _build_apple_ipc_plugin_spec()
WYTHE_PLUGIN = APPLE_IPC_PLUGIN


def register_wythe_plugin() -> WythePluginSpec:
    """Entry-point helper returning `APPLE_IPC_PLUGIN`."""
    return APPLE_IPC_PLUGIN
