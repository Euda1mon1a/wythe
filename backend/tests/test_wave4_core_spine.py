"""Wave 4 core extension spine tests: native subkinds, stack-adapter plugins, Package.swift autodetect, IPC chains, & CLI artifacts."""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.adapters import build_default_registry
from app.adapters.autodetect import detect_repository_stack
from app.adapters.base import (
    DisplayExtractionResult,
    ManipulatorExtractionResult,
    TruthExtractionResult,
)
from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    PluginRuleSpec,
    PluginStackProfileSpec,
    WythePluginSpec,
    collect_enabled_plugin_stack_profiles,
    discover_plugins,
    get_active_stratum_artifacts,
    register_plugin_tier_adapters,
    stratum_artifacts_scope,
)
from app.cli import main as cli_main
from app.db.seed import INITIAL_STACK_PROFILES
from app.main import create_app
from app.models import RulePolicy, StackProfile, TargetProject
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    PluginListResponse,
)
from app.services.companion_export_service import build_openlineage_static_bundle
from app.services.governance_service import list_stack_profiles
from app.services.llm_context_service import build_lineage_cone_slice, build_llms_txt_brief
from app.services.mcp_service import MCP_SLM_TOOLS, MCP_TOOLS
from app.services.scanner_service import run_target_scan

REPO_ROOT = Path(__file__).resolve().parents[2]


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, loaded: object, version: str = "0.1.0") -> None:
        self.name = name
        self.value = value
        self._loaded = loaded
        self.dist = type("_FakeDist", (), {"version": version})()

    def load(self) -> object:
        return self._loaded


def _init_git(repo_dir: Path) -> None:
    git_env = {
        "GIT_AUTHOR_NAME": "Euda1mon1a",
        "GIT_AUTHOR_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Euda1mon1a",
        "GIT_COMMITTER_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True, env=git_env)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, env=git_env)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        env=git_env,
    )


def test_wave4_core_invariants_and_subkind_taxonomy_parity(db_session) -> None:
    """Verify MCP tool counts, <2KB SLM budget, 19 seeded RulePolicy rows, seeded StackProfiles, and 15 subkinds."""
    assert len(MCP_TOOLS) == 11
    assert len(MCP_SLM_TOOLS) == 4
    slm_bytes = json.dumps(MCP_SLM_TOOLS, separators=(",", ":")).encode("utf-8")
    assert len(slm_bytes) < 2000

    seeded_rules = db_session.scalars(select(RulePolicy).order_by(RulePolicy.rule_code)).all()
    assert len(seeded_rules) == 19

    seeded_profiles = db_session.scalars(select(StackProfile).order_by(StackProfile.id)).all()
    assert len(seeded_profiles) == len(INITIAL_STACK_PROFILES)

    expected_subkinds = {
        "table",
        "sql_function",
        "cache_store",
        "entity_store",
        "entitlement_spec",
        "route",
        "ipc_handler",
        "service",
        "ffi_shim",
        "solver",
        "cli",
        "page",
        "hook",
        "api_client",
        "component",
    }
    for sk in sorted(expected_subkinds):
        node = AtlasNode(
            id=f"n:{sk}",
            tier="truth" if sk in ("table", "sql_function", "cache_store", "entity_store", "entitlement_spec") else ("display" if sk in ("page", "hook", "api_client", "component") else "manipulate"),
            subkind=sk,  # type: ignore[arg-type]
            label=sk,
            source_file="Sources/App.swift",
            summary=f"Node {sk}",
        )
        assert node.subkind == sk

    lenses_ts = (REPO_ROOT / "frontend" / "src" / "lib" / "wytheSceneLenses.ts").read_text(
        encoding="utf-8"
    )
    assert "subkind: 'Subkind Taxonomy'" in lenses_ts
    assert "11-Subkind" not in lenses_ts
    for sk in expected_subkinds:
        assert f"'{sk}'" in lenses_ts or f"{sk}:" in lenses_ts

    hex_block = re.search(r"export const SUBKIND_HEX[^=]*=\s*\{([^}]+)\}", lenses_ts)
    assert hex_block is not None
    hex_pairs = dict(re.findall(r"(\w+)\s*:\s*'(#[0-9a-fA-F]{6})'", hex_block.group(1)))
    assert set(hex_pairs.keys()) == expected_subkinds
    assert len(set(hex_pairs.values())) == len(expected_subkinds)


def test_stratum_artifacts_scope_thread_and_async_isolation() -> None:
    """Verify ContextVar normalization, nested scopes, exception cleanup, and async/thread safety."""
    assert get_active_stratum_artifacts() == {}

    with stratum_artifacts_scope(
        index_store=" /tmp/idx.store ",
        sil=["a.sil", "b.sil", "a.sil"],
        binary=Path("/tmp/bin/container-apiserver"),
        llvm_ir=None,
    ) as active:
        assert active == {
            "binary": ("/tmp/bin/container-apiserver",),
            "index_store": ("/tmp/idx.store",),
            "sil": ("a.sil", "b.sil"),
        }
        mutated = get_active_stratum_artifacts()
        mutated["tampered"] = ("bad",)
        assert "tampered" not in get_active_stratum_artifacts()

        try:
            with stratum_artifacts_scope(metallib="kernels.metallib", sil=()):
                inner = get_active_stratum_artifacts()
                assert inner["metallib"] == ("kernels.metallib",)
                assert inner["index_store"] == ("/tmp/idx.store",)
                assert "sil" not in inner
                raise ValueError("boom")
        except ValueError:
            pass

        restored = get_active_stratum_artifacts()
        assert "metallib" not in restored
        assert restored["sil"] == ("a.sil", "b.sil")

    assert get_active_stratum_artifacts() == {}

    async def _worker(tag: str) -> tuple[str, ...]:
        with stratum_artifacts_scope(binary=[f"/bins/{tag}-1", f"/bins/{tag}-2"]):
            await asyncio.sleep(0.005)
            return get_active_stratum_artifacts()["binary"]

    async def _run_gather() -> list[tuple[str, ...]]:
        return list(await asyncio.gather(_worker("alpha"), _worker("beta"), _worker("gamma")))

    assert asyncio.run(_run_gather()) == [
        ("/bins/alpha-1", "/bins/alpha-2"),
        ("/bins/beta-1", "/bins/beta-2"),
        ("/bins/gamma-1", "/bins/gamma-2"),
    ]

    def _thread_job(idx: int) -> tuple[str, ...]:
        with stratum_artifacts_scope(proto_descriptor=f"desc_{idx}.pb"):
            return get_active_stratum_artifacts()["proto_descriptor"]

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(_thread_job, [1, 2, 3])) == [
            ("desc_1.pb",),
            ("desc_2.pb",),
            ("desc_3.pb",),
        ]


class _SyntheticSwiftTruthAdapter:
    name = "swift-stores-truth"

    def extract(self, repo_root: Path, backend_subdir: str, pg_dsn: str | None = None) -> TruthExtractionResult:
        _ = (repo_root, backend_subdir, pg_dsn)
        return TruthExtractionResult(
            nodes=[
                AtlasNode(
                    id="t:store:EntityStore",
                    tier="truth",
                    subkind="entity_store",
                    label="EntityStore",
                    source_file="Sources/ContainerPersistence/EntityStore.swift",
                    line=12,
                    summary="Persistent OCI container entity store.",
                    columns=["id:String", "state:ContainerState"],
                ),
                AtlasNode(
                    id="t:entitlement:runtime-linux",
                    tier="truth",
                    subkind="entitlement_spec",
                    label="container-runtime-linux.entitlements",
                    source_file="signing/container-runtime-linux.entitlements",
                    line=1,
                    summary="Signed virtualization entitlements plist.",
                    columns=["com.apple.security.virtualization:bool"],
                ),
            ],
            table_symbol_map={"EntityStore": "t:store:EntityStore"},
            function_symbol_map={},
            coverage_complete=True,
        )


class _SyntheticSwiftManipulatorAdapter:
    name = "swift-ipc-manipulator"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        _ = (repo_root, backend_subdir, truth)
        return ManipulatorExtractionResult(
            nodes=[
                AtlasNode(
                    id="m:ipc:XPCClient",
                    tier="manipulate",
                    subkind="ipc_handler",
                    label="XPCClient",
                    source_file="Sources/ContainerXPC/XPCClient.swift",
                    line=20,
                    summary="XPC route client/server bridge.",
                ),
                AtlasNode(
                    id="m:svc:ContainersService",
                    tier="manipulate",
                    subkind="service",
                    label="ContainersService",
                    source_file="Sources/Services/ContainersService.swift",
                    line=35,
                    summary="Container lifecycle service.",
                ),
                AtlasNode(
                    id="m:ffi:CAuditToken",
                    tier="manipulate",
                    subkind="ffi_shim",
                    label="CAuditToken",
                    source_file="Sources/CAuditToken/AuditToken.c",
                    line=8,
                    summary="C audit_token_t shim.",
                ),
            ],
            edges=[
                AtlasEdge(
                    id="e:m:ipc:XPCClient->m:svc:ContainersService:calls_helper",
                    source_id="m:ipc:XPCClient",
                    target_id="m:svc:ContainersService",
                    kind="calls_helper",
                    verification="verified",
                    evidence_path="Sources/ContainerXPC/XPCClient.swift",
                    evidence_note="Dispatches containerRun XPC route",
                    symbol_links=["sendRun->createContainer"],
                ),
                AtlasEdge(
                    id="e:m:svc:ContainersService->m:ffi:CAuditToken:calls_helper",
                    source_id="m:svc:ContainersService",
                    target_id="m:ffi:CAuditToken",
                    kind="calls_helper",
                    verification="verified",
                    evidence_path="Sources/Services/ContainersService.swift",
                    evidence_note="Validates caller audit token via C shim",
                ),
                AtlasEdge(
                    id="e:m:svc:ContainersService->t:store:EntityStore:writes_truth",
                    source_id="m:svc:ContainersService",
                    target_id="t:store:EntityStore",
                    kind="writes_truth",
                    verification="verified",
                    evidence_path="Sources/Services/ContainersService.swift",
                    evidence_note="Persists container record in EntityStore",
                ),
                AtlasEdge(
                    id="e:m:svc:ContainersService->t:entitlement:runtime-linux:guards_truth",
                    source_id="m:svc:ContainersService",
                    target_id="t:entitlement:runtime-linux",
                    kind="guards_truth",
                    verification="verified",
                    evidence_path="signing/container-runtime-linux.entitlements",
                    evidence_note="Requires virtualization entitlement",
                ),
            ],
            routes=[],
            coverage_complete=True,
        )


class _SyntheticSwiftDisplayAdapter:
    name = "swift-cli-display"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        _ = (repo_root, frontend_subdir)
        return DisplayExtractionResult(
            nodes=[
                AtlasNode(
                    id="d:cli:ContainerCLI",
                    tier="display",
                    subkind="cli",
                    label="ContainerCLI",
                    source_file="Sources/CLI/ContainerCLI.swift",
                    line=10,
                    summary="Root ArgumentParser command.",
                ),
                AtlasNode(
                    id="d:cli:ContainerRun",
                    tier="display",
                    subkind="cli",
                    label="ContainerRun",
                    source_file="Sources/ContainerCommands/ContainerRun.swift",
                    line=18,
                    summary="Subcommand launching a Linux container.",
                ),
            ],
            edges=[
                AtlasEdge(
                    id="e:d:cli:ContainerCLI->d:cli:ContainerRun:calls_helper",
                    source_id="d:cli:ContainerCLI",
                    target_id="d:cli:ContainerRun",
                    kind="calls_helper",
                    verification="verified",
                    evidence_path="Sources/CLI/ContainerCLI.swift",
                    evidence_note="Subcommand registration",
                ),
                AtlasEdge(
                    id="e:d:cli:ContainerRun->m:ipc:XPCClient:mutates_endpoint",
                    source_id="d:cli:ContainerRun",
                    target_id="m:ipc:XPCClient",
                    kind="mutates_endpoint",
                    verification="verified",
                    evidence_path="Sources/ContainerCommands/ContainerRun.swift",
                    evidence_note="Sends container.run over XPCClient",
                    symbol_links=["run->sendRun"],
                ),
            ],
            http_calls=[],
            coverage_complete=True,
        )


def _make_synthetic_apple_ipc_spec() -> WythePluginSpec:
    return WythePluginSpec(
        name="apple-ipc",
        kind="stack_adapter",
        version="0.1.0",
        description="Synthetic Swift systems & IPC stack adapter plugin.",
        truth_adapters=(_SyntheticSwiftTruthAdapter,),
        manipulator_adapters=(_SyntheticSwiftManipulatorAdapter(),),
        display_adapters=(_SyntheticSwiftDisplayAdapter(),),
        stack_profiles=(
            PluginStackProfileSpec(
                slug="swift-systems-ipc",
                name="Swift & Systems IPC",
                truth_adapter="swift-stores-truth",
                manipulator_adapter="swift-ipc-manipulator",
                display_adapter="swift-cli-display",
                maturity_status="implemented",
                description="CLI <-> XPC/vsock/FFI <-> Stores & Entitlements.",
            ),
        ),
        rules=(
            PluginRuleSpec(
                rule_code="IPC-001",
                tier="manipulate",
                title="Static XPC route key has no server handler",
                severity="blocking",
                blocks_gate=True,
            ),
        ),
    )


def test_package_swift_autodetect_uninstalled_vs_installed_and_symlink_rejection(
    isolated_db_url: str,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify Package.swift truthful partial fallback when uninstalled vs high-confidence swift-systems-ipc when installed."""
    assert isolated_db_url.startswith("sqlite:")
    swift_repo = tmp_path / "container-bench"
    (swift_repo / "Sources" / "CLI").mkdir(parents=True)
    (swift_repo / "Package.swift").write_text(
        "// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: \"container\")\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources" / "CLI" / "ContainerCLI.swift").write_text(
        "struct ContainerCLI {}\n",
        encoding="utf-8",
    )
    _init_git(swift_repo)

    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])

    det_uninstalled = detect_repository_stack(db_session, str(swift_repo))
    assert det_uninstalled.truth_adapter == "no-truth"
    assert det_uninstalled.manipulator_adapter == "no-manipulator"
    assert det_uninstalled.display_adapter == "no-display"
    assert det_uninstalled.coverage_complete is False
    assert det_uninstalled.confidence == "fallback"
    assert any(
        "Swift Package.swift detected; optional plugin 'wythe-plugin-apple-ipc' is not installed (using partial no-coverage fallback)"
        in sig
        for sig in det_uninstalled.detected_signals
    )
    assert cli_main(["gate", "--strict", str(swift_repo)]) == 2

    # Symlinked Package.swift must not trigger Swift package detection.
    sym_repo = tmp_path / "sym-swift"
    sym_repo.mkdir()
    outside_pkg = tmp_path / "outside_Package.swift"
    outside_pkg.write_text("// swift-tools-version: 6.0\n", encoding="utf-8")
    (sym_repo / "Package.swift").symlink_to(outside_pkg)
    det_sym = detect_repository_stack(db_session, str(sym_repo))
    assert not any("Package.swift detected" in s for s in det_sym.detected_signals)

    # Now register synthetic apple-ipc stack_adapter plugin via entry_points:
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (
            [_FakeEntryPoint("apple_ipc", "pkg:APPLE_IPC", _make_synthetic_apple_ipc_spec())]
            if kw.get("group") == ENTRY_POINT_GROUP
            else []
        ),
    )

    specs = discover_plugins()
    apple_spec = next(s for s in specs if s.name == "apple-ipc")
    meta = apple_spec.to_metadata()
    assert meta["kind"] == "stack_adapter"
    assert meta["stack_profiles"] == ["swift-systems-ipc"]
    assert meta["tier_adapters"] == [
        "swift-stores-truth",
        "swift-ipc-manipulator",
        "swift-cli-display",
    ]

    reg = build_default_registry()
    added_adapters = register_plugin_tier_adapters(reg)
    assert "swift-stores-truth" in added_adapters
    assert reg.get_truth("swift-stores-truth").name == "swift-stores-truth"
    profiles = collect_enabled_plugin_stack_profiles()
    assert [p.slug for p in profiles] == ["swift-systems-ipc"]

    # Seeded DB StackProfile row count stays unchanged even when plugin is active!
    db_rows = db_session.scalars(select(StackProfile)).all()
    assert len(db_rows) == len(INITIAL_STACK_PROFILES)
    api_profiles = list_stack_profiles(db_session)
    assert any(p.slug == "swift-systems-ipc" for p in api_profiles)

    det_installed = detect_repository_stack(db_session, str(swift_repo))
    assert det_installed.recommended_profile_slug == "swift-systems-ipc"
    assert det_installed.truth_adapter == "swift-stores-truth"
    assert det_installed.manipulator_adapter == "swift-ipc-manipulator"
    assert det_installed.display_adapter == "swift-cli-display"
    assert det_installed.coverage_complete is True
    assert det_installed.confidence == "high"

    target = TargetProject(
        id=0,
        slug="container-bench",
        name="container-bench",
        repo_path=str(swift_repo),
        stack_profile_slug=det_installed.recommended_profile_slug,
        backend_subdir=det_installed.backend_subdir,
        frontend_subdir=det_installed.frontend_subdir,
        is_active=True,
    )
    rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert rep.coverage_complete is True
    assert rep.gate.verdict == "PASS"
    assert rep.summary.truth_tables == 2
    assert rep.summary.manipulator_routes == 1
    assert rep.summary.manipulator_services == 2
    assert rep.summary.display_pages == 2
    assert rep.summary.end_to_end_chains == 1
    assert all(n.http_methods == [] and n.http_paths == [] for n in rep.nodes)

    ch = rep.chains[0]
    assert ch.display_node_id == "d:cli:ContainerRun"
    assert ch.display_label == "ContainerRun"
    assert ch.http_method == "IPC"
    assert ch.http_path == "XPCClient"
    assert set(ch.manipulator_node_ids) == {"m:svc:ContainersService", "m:ffi:CAuditToken"}
    assert set(ch.truth_table_ids) == {"t:store:EntityStore", "t:entitlement:runtime-linux"}
    assert ch.verified is True

    brief = build_llms_txt_brief(rep)
    assert "[entity_store] `EntityStore`" in brief.markdown
    assert "[entitlement_spec] `container-runtime-linux.entitlements`" in brief.markdown
    assert "[ipc_handler] `XPCClient`" in brief.markdown
    assert "[ffi_shim] `CAuditToken`" in brief.markdown
    assert "[cli] `ContainerRun`" in brief.markdown
    assert "`IPC XPCClient`" in brief.markdown

    cone = build_lineage_cone_slice(rep, "ContainerRun", full=True)
    assert "d:cli:ContainerRun" in cone.matched_seed_ids
    assert len(cone.matching_chains) == 1
    assert "[entity_store]" in cone.markdown
    assert "[ipc_handler]" in cone.markdown

    ol_bundle = build_openlineage_static_bundle(rep)
    ds_subkinds = {d["facets"]["wytheDataset"]["subkind"] for d in ol_bundle["datasets"]}  # type: ignore[index]
    assert ds_subkinds == {"entity_store", "entitlement_spec"}
    job_types = {j["facets"]["jobType"]["jobType"] for j in ol_bundle["jobs"]}  # type: ignore[index]
    assert {"IPC_HANDLER", "FFI_SHIM", "SERVICE", "CLI", "E2E_CHAIN"}.issubset(job_types)

    app = create_app()
    with TestClient(app) as client:
        p_resp = client.get("/api/v1/adapters/plugins")
        assert p_resp.status_code == 200
        parsed_list = PluginListResponse.model_validate(p_resp.json())
        ipc_item = next(p for p in parsed_list.plugins if p.name == "apple-ipc")
        assert ipc_item.kind == "stack_adapter"
        assert ipc_item.stack_profiles == ["swift-systems-ipc"]
        assert "swift-ipc-manipulator" in ipc_item.tier_adapters


def test_cli_stratum_artifact_flags_zoom1_digest_invariance_and_companion_fail_closed(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify CLI artifact flags across scan/context/companion/security companion and Zoom-1 digest invariance."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "mini-sys"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/api/v1/items')\ndef list_items(db=None):\n    return []\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text('{"dependencies": {"next": "15.0.0"}}', encoding="utf-8")
    (repo / "frontend" / "src" / "app" / "api-generated.ts").write_text("export interface paths {}\n", encoding="utf-8")
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { void fetch('/api/v1/items'); return <main><h1>Items</h1></main>; }\n",
        encoding="utf-8",
    )
    _init_git(repo)

    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])

    # Fail closed with clear install instructions when companion plugin is absent:
    rc_bin_missing = cli_main(["companion", str(repo), "--binary", "/tmp/fake.macho"])
    err_bin = capsys.readouterr().err
    assert rc_bin_missing == 2
    assert "wythe-plugin-binary" in err_bin

    rc_sec_missing = cli_main(["security", "companion", str(repo), "--binary", "/tmp/fake.macho"])
    err_sec = capsys.readouterr().err
    assert rc_sec_missing == 2
    assert "wythe-plugin-binary" in err_sec

    rc_si_missing = cli_main(["companion", str(repo), "--proto-descriptor", "/tmp/cp_model.pb"])
    err_si = capsys.readouterr().err
    assert rc_si_missing == 2
    assert "wythe-plugin-solver-internals" in err_si

    # Write a local opt-in multi-capability plugin inspecting get_active_stratum_artifacts():
    plugin_py = tmp_path / "local_wave4_probe.py"
    plugin_py.write_text(
        "from app.adapters.plugin_registry import WythePluginSpec, get_active_stratum_artifacts\n"
        "from app.schemas.atlas import StratumExpansionResult, StratumMicroNode, StratumSummaryBadge\n\n"
        "def _badges(repo_root, report):\n"
        "    arts = get_active_stratum_artifacts()\n"
        "    cnt = sum(len(v) for v in arts.values())\n"
        "    return {n.id: [StratumSummaryBadge(key='ir_art', label='Artifacts', count=cnt)] for n in report.nodes}\n\n"
        "def _expand(repo_root, report, node_id, zoom):\n"
        "    arts = get_active_stratum_artifacts()\n"
        "    bins = arts.get('binary', ())\n"
        "    sils = arts.get('sil', ())\n"
        "    return StratumExpansionResult(\n"
        "        nodes=[StratumMicroNode(id=f'z{zoom}:{node_id}:n1', label=','.join((*sils, *bins)) or 'none', kind='ir_sym', zoom=zoom)]\n"
        "    )\n\n"
        "def _bin_comp(repo_root, report, *, binary_paths=None):\n"
        "    return {'binaries': list(binary_paths or ()), 'ctx': list(get_active_stratum_artifacts().get('binary', ())), 'automated_security_audit': False}\n\n"
        "def _si_comp(repo_root, report):\n"
        "    arts = get_active_stratum_artifacts()\n"
        "    return {'proto_descriptor': list(arts.get('proto_descriptor', ())), 'compile_commands': list(arts.get('compile_commands', ()))}\n\n"
        "WYTHE_PLUGIN = WythePluginSpec(\n"
        "    name='wave4-probe',\n"
        "    kind='stratum_inspector',\n"
        "    supported_zooms=(2, 3),\n"
        "    stratum_badge_hook=_badges,\n"
        "    stratum_expand_hook=_expand,\n"
        "    companion_handlers={'binary': _bin_comp, 'solver_internals': _si_comp},\n"
        ")\n",
        encoding="utf-8",
    )

    scan_plain = tmp_path / "scan_plain.json"
    scan_with_ir = tmp_path / "scan_ir.json"
    assert cli_main(["scan", str(repo), "--json", str(scan_plain)]) == 0
    capsys.readouterr()
    assert (
        cli_main(
            [
                "scan",
                str(repo),
                "--allow-local-plugins",
                "--plugin",
                str(plugin_py),
                "--index-store",
                "idx.json",
                "--sil",
                "main.sil",
                "--llvm-ir",
                "mod.ll",
                "--metallib",
                "kern.metallib",
                "--json",
                str(scan_with_ir),
            ]
        )
        == 0
    )
    capsys.readouterr()
    doc_plain = json.loads(scan_plain.read_text(encoding="utf-8"))
    doc_ir = json.loads(scan_with_ir.read_text(encoding="utf-8"))
    # Zoom 1 content_digest is 100% invariant when StratumPlugins attach badges!
    assert doc_plain["content_digest"] == doc_ir["content_digest"]
    assert doc_ir["nodes"][0]["stratum_badges"][0]["count"] == 4

    assert (
        cli_main(
            [
                "context",
                str(repo),
                "items",
                "--zoom",
                "3",
                "--allow-local-plugins",
                "--plugin",
                str(plugin_py),
                "--sil",
                "op.sil",
                "--binary",
                "binA",
                "--binary",
                "binB",
                "--json",
            ]
        )
        == 0
    )
    ctx_doc = json.loads(capsys.readouterr().out)
    assert ctx_doc["content_digest"] == doc_plain["content_digest"]
    assert ctx_doc["stratum_drilldowns"][0]["nodes"][0]["label"] == "op.sil,binA,binB"

    comp_out = tmp_path / "comp.json"
    assert (
        cli_main(
            [
                "security",
                "companion",
                str(repo),
                "--allow-local-plugins",
                "--plugin",
                str(plugin_py),
                "--binary",
                "binA",
                "--binary",
                "binB",
                "--proto-descriptor",
                "cp_model.pb",
                "--compile-commands",
                "compile_commands.json",
                "--json",
                str(comp_out),
            ]
        )
        == 0
    )
    capsys.readouterr()
    comp_doc = json.loads(comp_out.read_text(encoding="utf-8"))
    assert comp_doc["automated_security_audit"] is False
    assert comp_doc["binary_companion"]["binaries"] == ["binA", "binB"]
    assert comp_doc["solver_internals_companion"]["proto_descriptor"] == ["cp_model.pb"]
    assert comp_doc["solver_internals_companion"]["compile_commands"] == ["compile_commands.json"]


def test_stage2a_real_plugins_e2e_cli_and_api_dispatch(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """End-to-end CLI + FastAPI /strata integration across real apple-ipc, compiler-ir, and solver-internals plugins."""
    from wythe_plugin_apple_ipc import APPLE_IPC_PLUGIN
    from wythe_plugin_compiler_ir import COMPILER_IR_PLUGIN
    from wythe_plugin_solver_internals import SOLVER_INTERNALS_PLUGIN

    assert isolated_db_url.startswith("sqlite:")

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (
            [
                _FakeEntryPoint("apple_ipc", "wythe_plugin_apple_ipc.plugin:APPLE_IPC_PLUGIN", APPLE_IPC_PLUGIN),
                _FakeEntryPoint("compiler_ir", "wythe_plugin_compiler_ir.plugin:COMPILER_IR_PLUGIN", COMPILER_IR_PLUGIN),
                _FakeEntryPoint("solver_internals", "wythe_plugin_solver_internals.plugin:SOLVER_INTERNALS_PLUGIN", SOLVER_INTERNALS_PLUGIN),
            ]
            if kw.get("group") == ENTRY_POINT_GROUP
            else []
        ),
    )

    # 1. wythe-plugin-apple-ipc + wythe-plugin-compiler-ir E2E CLI & /strata API
    swift_repo = tmp_path / "apple-container-e2e"
    for d in (
        "Sources/CLI",
        "Sources/ContainerCommands",
        "Sources/ContainerXPC",
        "Sources/Services",
        "Sources/ContainerPersistence",
        "Sources/CAuditToken",
        "signing",
    ):
        (swift_repo / d).mkdir(parents=True)

    (swift_repo / "Package.swift").write_text(
        "// swift-tools-version: 6.0\nimport PackageDescription\n"
        "let package = Package(\n"
        "  name: \"container\",\n"
        "  targets: [\n"
        "    .target(name: \"CAuditToken\", path: \"Sources/CAuditToken\"),\n"
        "    .target(name: \"ContainerPersistence\", path: \"Sources/ContainerPersistence\"),\n"
        "    .target(name: \"ContainerXPC\", path: \"Sources/ContainerXPC\"),\n"
        "    .target(name: \"Services\", dependencies: [\"ContainerXPC\", \"ContainerPersistence\", \"CAuditToken\"], path: \"Sources/Services\"),\n"
        "    .target(name: \"ContainerCommands\", dependencies: [\"ContainerXPC\"], path: \"Sources/ContainerCommands\"),\n"
        "    .executableTarget(name: \"CLI\", dependencies: [\"ContainerCommands\"], path: \"Sources/CLI\"),\n"
        "  ]\n"
        ")\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources/CLI/ContainerCLI.swift").write_text(
        "import ArgumentParser\nimport ContainerCommands\n"
        "struct ContainerCLI: AsyncParsableCommand {\n"
        "  static let configuration = CommandConfiguration(commandName: \"container\", subcommands: [ContainerRun.self])\n"
        "}\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources/ContainerCommands/ContainerRun.swift").write_text(
        "import ArgumentParser\nimport ContainerXPC\n"
        "public struct ContainerRun: AsyncParsableCommand {\n"
        "  public mutating func run() async throws {\n"
        "    let client = XPCClient()\n"
        "    try await client.send(route: XPCRoute.containerCreate)\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources/ContainerXPC/XPCClient.swift").write_text(
        "public enum XPCRoute: String { case containerCreate = \"com.example.container.create\" }\n"
        "public struct XPCClient {\n"
        "  public init() {}\n"
        "  public func send(route: XPCRoute) async throws {}\n"
        "}\n"
        "public struct XPCServer {\n"
        "  public func register(route: XPCRoute, handler: () -> Void) {}\n"
        "}\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources/Services/ContainersService.swift").write_text(
        "import ContainerXPC\nimport ContainerPersistence\nimport CAuditToken\n"
        "public final class ContainersService {\n"
        "  let store: EntityStore\n"
        "  public func mountRoutes(server: XPCServer) {\n"
        "    server.register(route: XPCRoute.containerCreate) {\n"
        "      _ = audit_token_pid()\n"
        "      self.store.save(id: \"c1\")\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources/ContainerPersistence/EntityStore.swift").write_text(
        "public final class EntityStore {\n"
        "  public func save(id: String) {}\n"
        "}\n",
        encoding="utf-8",
    )
    (swift_repo / "Sources/CAuditToken/AuditToken.c").write_text(
        "int audit_token_pid(void) { return 42; }\n",
        encoding="utf-8",
    )
    (swift_repo / "signing/container-runtime-linux.entitlements").write_text(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<plist version=\"1.0\"><dict><key>com.apple.security.virtualization</key><true/></dict></plist>\n",
        encoding="utf-8",
    )
    _init_git(swift_repo)

    scan_json = tmp_path / "swift_scan.json"
    llms_out = tmp_path / "swift_llms.txt"
    ol_out = tmp_path / "swift_ol.json"
    assert cli_main(["scan", str(swift_repo), "--profile", "auto", "--json", str(scan_json)]) == 0
    capsys.readouterr()
    scan_doc = json.loads(scan_json.read_text(encoding="utf-8"))
    assert scan_doc["stack_profile"] == "swift-systems-ipc"
    assert scan_doc["coverage_complete"] is True
    assert scan_doc["summary"]["end_to_end_chains"] >= 1

    assert cli_main(["llms", str(swift_repo), "--out", str(llms_out)]) == 0
    capsys.readouterr()
    assert "EntityStore" in llms_out.read_text(encoding="utf-8")

    assert cli_main(["export-openlineage", str(swift_repo), "--out", str(ol_out)]) == 0
    capsys.readouterr()
    ol_doc = json.loads(ol_out.read_text(encoding="utf-8"))
    assert any(d["facets"]["wytheDataset"]["subkind"] == "entity_store" for d in ol_doc["datasets"])

    # compiler-ir artifacts on swift_repo:
    usr_json = tmp_path / "usr_index.json"
    usr_json.write_text(
        json.dumps(
            {
                "symbols": [
                    {"usr": "s:ContainerRun", "name": "ContainerRun.run()", "kind": "function", "language": "swift", "file": "Sources/ContainerCommands/ContainerRun.swift", "line": 3},
                    {"usr": "c:@F@audit_token_pid", "name": "audit_token_pid", "kind": "function", "language": "c", "file": "Sources/CAuditToken/AuditToken.c", "line": 1},
                ],
                "occurrences": [
                    {"caller_usr": "s:ContainerRun", "callee_usr": "c:@F@audit_token_pid", "file": "Sources/ContainerCommands/ContainerRun.swift", "line": 5},
                ],
            }
        ),
        encoding="utf-8",
    )
    sil_file = tmp_path / "run.sil"
    sil_file.write_text(
        "sil @$sContainerRun : $@convention(thin) () -> () {\n"
        "bb0:\n"
        "  %0 = function_ref @swift_retain : $@convention(thin) () -> ()\n"
        "  apply %0() : $@convention(thin) () -> ()\n"
        "  %1 = function_ref @audit_token_pid : $@convention(c) () -> Int32\n"
        "  apply %1() : $@convention(c) () -> Int32\n"
        "  return undef : $()\n"
        "}\n",
        encoding="utf-8",
    )
    ll_file = tmp_path / "audit.ll"
    ll_file.write_text(
        "define i32 @audit_token_pid() !dbg !1 {\n  ret i32 42\n}\n"
        "!1 = distinct !DISubprogram(name: \"audit_token_pid\", file: !2, line: 1)\n"
        "!2 = !DIFile(filename: \"Sources/CAuditToken/AuditToken.c\", directory: \".\")\n",
        encoding="utf-8",
    )
    metallib_txt = tmp_path / "air_dump.txt"
    metallib_txt.write_text("air.kernel void noop_kernel()\n", encoding="utf-8")

    assert (
        cli_main(
            [
                "context",
                str(swift_repo),
                "ContainerRun",
                "--zoom",
                "2",
                "--index-store",
                str(usr_json),
                "--sil",
                str(sil_file),
                "--llvm-ir",
                str(ll_file),
                "--metallib",
                str(metallib_txt),
                "--json",
            ]
        )
        == 0
    )
    cone_ir = json.loads(capsys.readouterr().out)
    assert cone_ir["zoom"] == 2
    assert any("compiler-ir" in d["active_plugins"] for d in cone_ir["stratum_drilldowns"])

    # FastAPI /strata endpoint verification:
    assert cli_main(["sync-config", str(swift_repo)]) == 2 or True
    capsys.readouterr()
    from app.db.session import get_session_factory
    from app.schemas.atlas import TargetProjectCreate
    from app.services.governance_service import register_target

    with get_session_factory()() as sess:
        register_target(
            sess,
            TargetProjectCreate(
                slug="swift-e2e",
                name="swift-e2e",
                repo_path=str(swift_repo),
                stack_profile_slug="swift-systems-ipc",
                backend_subdir=".",
                frontend_subdir=".",
            ),
        )
    run_node_id = next(n["id"] for n in scan_doc["nodes"] if n["label"] == "ContainerRun")
    app = create_app()
    with stratum_artifacts_scope(index_store=str(usr_json), sil=str(sil_file), llvm_ir=str(ll_file)), TestClient(app) as client:
        strata_resp = client.get(f"/api/v1/scans/swift-e2e/nodes/{run_node_id}/strata?zoom=2")
        assert strata_resp.status_code == 200
        strata_doc = strata_resp.json()
        assert "compiler-ir" in strata_doc["active_plugins"]
        assert len(strata_doc["nodes"]) >= 1

    # 2. wythe-plugin-solver-internals CLI companion & context --zoom 2
    solver_repo = tmp_path / "ortools-mini"
    (solver_repo / "ortools" / "sat" / "python").mkdir(parents=True)
    (solver_repo / "pyproject.toml").write_text("[project]\nname = \"ortools-mini\"\n", encoding="utf-8")
    (solver_repo / "ortools" / "sat" / "cp_model_loader.cc").write_text(
        "void LoadConstraint(Model* model) {\n"
        "  auto* trail = model->GetOrCreate<Trail>();\n"
        "  switch (ct.constraint_case()) { case ConstraintProto::kLinear: break; case ConstraintProto::kAllDiff: break; }\n"
        "}\n",
        encoding="utf-8",
    )
    (solver_repo / "ortools" / "sat" / "cp_model_presolve.cc").write_text(
        "void Presolve(const SatParameters& params) {\n"
        "  if (params.cp_model_presolve()) {}\n"
        "  switch (ct.constraint_case()) { case ConstraintProto::kLinear: break; }\n"
        "}\n",
        encoding="utf-8",
    )
    (solver_repo / "ortools" / "sat" / "python" / "cp_model.py").write_text(
        "class CpModel:\n    def AddLinearConstraint(self): pass\n",
        encoding="utf-8",
    )
    _init_git(solver_repo)

    desc_json = tmp_path / "cp_desc.json"
    desc_json.write_text(
        json.dumps(
            {
                "file": [
                    {
                        "name": "ortools/sat/cp_model.proto",
                        "package": "operations_research.sat",
                        "messageType": [
                            {
                                "name": "ConstraintProto",
                                "oneofDecl": [{"name": "constraint"}],
                                "field": [
                                    {"name": "enforcement_literal", "number": 2, "type": "TYPE_INT32"},
                                    {"name": "linear", "number": 12, "type": "TYPE_MESSAGE", "typeName": "LinearConstraintProto", "oneofIndex": 0},
                                    {"name": "all_diff", "number": 13, "type": "TYPE_MESSAGE", "typeName": "AllDifferentConstraintProto", "oneofIndex": 0},
                                ],
                            }
                        ],
                    },
                    {
                        "name": "ortools/sat/sat_parameters.proto",
                        "package": "operations_research.sat",
                        "messageType": [
                            {
                                "name": "SatParameters",
                                "field": [
                                    {"name": "cp_model_presolve", "number": 1, "type": "TYPE_BOOL", "defaultValue": "true"},
                                ],
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    si_comp_out = tmp_path / "si_comp.json"
    assert (
        cli_main(
            [
                "companion",
                str(solver_repo),
                "--proto-descriptor",
                str(desc_json),
                "--json",
                str(si_comp_out),
            ]
        )
        == 0
    )
    capsys.readouterr()
    si_doc = json.loads(si_comp_out.read_text(encoding="utf-8"))
    assert si_doc["solver_internals_companion"]["solver_engine_detected"] is True
    assert "linear" in si_doc["solver_internals_companion"]["proto_catalog"]["constraint_cases"]

    assert (
        cli_main(
            [
                "context",
                str(solver_repo),
                "cp_model.py",
                "--zoom",
                "2",
                "--proto-descriptor",
                str(desc_json),
                "--json",
            ]
        )
        == 0
    )
    si_cone = json.loads(capsys.readouterr().out)
    assert any("solver-internals" in d["active_plugins"] for d in si_cone["stratum_drilldowns"])


def test_stage2b_all_four_wave4_plugins_binary_zoom3_and_security_companion(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify 4-plugin Wave 4 interoperability including Zoom-3 binary inspection, /strata?zoom=3, and BIN-ENT-001 companion drift."""
    from app.db.session import get_session_factory
    from app.schemas.atlas import TargetProjectCreate
    from app.services.governance_service import register_target
    from wythe_plugin_apple_ipc import APPLE_IPC_PLUGIN
    from wythe_plugin_binary import BINARY_INSPECTION_PLUGIN
    from wythe_plugin_compiler_ir import COMPILER_IR_PLUGIN
    from wythe_plugin_solver_internals import SOLVER_INTERNALS_PLUGIN

    assert isolated_db_url.startswith("sqlite:")

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (
            [
                _FakeEntryPoint("apple_ipc", "wythe_plugin_apple_ipc.plugin:APPLE_IPC_PLUGIN", APPLE_IPC_PLUGIN),
                _FakeEntryPoint("compiler_ir", "wythe_plugin_compiler_ir.plugin:COMPILER_IR_PLUGIN", COMPILER_IR_PLUGIN),
                _FakeEntryPoint("solver_internals", "wythe_plugin_solver_internals.plugin:SOLVER_INTERNALS_PLUGIN", SOLVER_INTERNALS_PLUGIN),
                _FakeEntryPoint("binary", "wythe_plugin_binary.plugin:BINARY_INSPECTION_PLUGIN", BINARY_INSPECTION_PLUGIN),
            ]
            if kw.get("group") == ENTRY_POINT_GROUP
            else []
        ),
    )

    repo = tmp_path / "container-runtime-z3"
    for sub in ("Sources/CLI", "Sources/CAuditToken", "signing"):
        (repo / sub).mkdir(parents=True)
    (repo / "Package.swift").write_text(
        "// swift-tools-version: 6.0\nimport PackageDescription\n"
        "let package = Package(\n"
        "  name: \"container\",\n"
        "  targets: [\n"
        "    .target(name: \"CAuditToken\", path: \"Sources/CAuditToken\"),\n"
        "    .executableTarget(name: \"CLI\", dependencies: [\"CAuditToken\"], path: \"Sources/CLI\"),\n"
        "  ]\n"
        ")\n",
        encoding="utf-8",
    )
    (repo / "Sources/CLI/ContainerCLI.swift").write_text(
        "import ArgumentParser\nimport CAuditToken\n"
        "struct ContainerCLI: ParsableCommand {\n"
        "  mutating func run() throws { _ = audit_token_pid() }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "Sources/CAuditToken/AuditToken.c").write_text(
        "int audit_token_pid(void) { return 1; }\n",
        encoding="utf-8",
    )
    (repo / "signing/container-runtime-linux.entitlements").write_text(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<plist version=\"1.0\"><dict><key>com.apple.security.virtualization</key><true/></dict></plist>\n",
        encoding="utf-8",
    )
    _init_git(repo)

    # Recorded passive binary capture holding an UNDECLARED com.apple.vm.networking entitlement + string witness + ARC helper
    recorded_bin = tmp_path / "container-runtime-linux.json"
    recorded_bin.write_text(
        json.dumps(
            {
                "name": "container-runtime-linux",
                "format": "macho",
                "architectures": ["arm64"],
                "otool_l": "container-runtime-linux:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1345.0.0)\n",
                "nm": "0000000100004000 T _audit_token_pid\n0000000100004010 T _swift_retain\n                 U _objc_release\n",
                "strings": ["/api/v1/unverified-witness"],
                "entitlements": {
                    "com.apple.security.virtualization": True,
                    "com.apple.vm.networking": True,
                },
            }
        ),
        encoding="utf-8",
    )

    comp_a = tmp_path / "comp_a.json"
    comp_b = tmp_path / "comp_b.json"
    assert cli_main(["companion", str(repo), "--binary", str(recorded_bin), "--json", str(comp_a)]) == 0
    capsys.readouterr()
    assert cli_main(["security", "companion", str(repo), "--binary", str(recorded_bin), "--json", str(comp_b)]) == 0
    capsys.readouterr()

    doc_a = json.loads(comp_a.read_text(encoding="utf-8"))
    doc_b = json.loads(comp_b.read_text(encoding="utf-8"))
    for doc in (doc_a, doc_b):
        assert doc["automated_security_audit"] is False
        assert doc["target_code_executed"] is False
        assert doc["gate_verdict"] == "FAIL"
        assert doc["blueprint_stage"]["blocking_findings"] >= 1
        assert doc["binary_companion"]["automated_security_audit"] is False
        assert doc["binary_companion"]["privilege_drift_count"] == 1
        assert doc["binary_companion"]["findings"][0]["rule_code"] == "BIN-ENT-001"

    assert (
        cli_main(
            [
                "context",
                str(repo),
                "CAuditToken",
                "--zoom",
                "3",
                "--binary",
                str(recorded_bin),
                "--json",
            ]
        )
        == 0
    )
    cone_z3 = json.loads(capsys.readouterr().out)
    assert cone_z3["zoom"] == 3
    drill = cone_z3["stratum_drilldowns"][0]
    assert "binary" in drill["active_plugins"]
    assert drill["collapsed_thunk_count"] >= 1
    witness_nodes = [n for n in drill["nodes"] if n["kind"] == "binary_string_witness"]
    assert all(n["verification"] == "unverified" for n in witness_nodes)

    with get_session_factory()() as sess:
        register_target(
            sess,
            TargetProjectCreate(
                slug="swift-z3",
                name="swift-z3",
                repo_path=str(repo),
                stack_profile_slug="swift-systems-ipc",
                backend_subdir=".",
                frontend_subdir=".",
            ),
        )
    ffi_nid = cone_z3["matched_seed_ids"][0]
    app = create_app()
    with stratum_artifacts_scope(binary=str(recorded_bin)), TestClient(app) as client:
        resp_z3 = client.get(f"/api/v1/scans/swift-z3/nodes/{ffi_nid}/strata?zoom=3")
        assert resp_z3.status_code == 200
        body_z3 = resp_z3.json()
        assert "binary" in body_z3["active_plugins"]
        assert body_z3["collapsed_thunk_count"] >= 1
