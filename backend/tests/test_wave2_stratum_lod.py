"""Wave 2 (#80) tests: `StratumPlugin` contract, Zoom-1 invariance, & 10^4-node LOD compaction."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.parse
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    StratumPlugin,
    discover_plugins,
)
from app.adapters.python_ast_inspect import parse_python_module
from app.cli import main as cli_main
from app.main import create_app
from app.schemas.atlas import (
    LineageConeSlice,
    MicroStratumZoom,
    StratumDrilldownRead,
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TargetProjectCreate,
    TruthAtlasReport,
)
from app.services.governance_service import get_target_by_slug, register_target
from app.services.mcp_service import MCP_SLM_TOOLS, dispatch_mcp_request
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    attach_zoom1_stratum_badges,
    build_node_stratum_drilldown,
    compact_stratum_subgraph,
)


class _FakeDist:
    def __init__(self, version: str = "0.9.0") -> None:
        import sysconfig

        self.version = version
        self._path = Path(sysconfig.get_path("purelib")) / f"fake_stratum-{version}.dist-info"

    def locate_file(self, path: str) -> Path:
        return self._path.parent / path


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, obj: object, version: str = "0.9.0") -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist(version)
        self._obj = obj

    def load(self) -> object:
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


def _build_synthetic_repo(repo_dir: Path) -> Path:
    """Create a compact git-initialized 3-tier repo for deterministic scan & cone tests."""
    (repo_dir / "backend" / "app" / "api").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "services").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app" / "compute").mkdir(parents=True)

    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE compute_jobs (\n"
        "    id UUID PRIMARY KEY,\n"
        "    kernel_name TEXT NOT NULL,\n"
        "    status TEXT NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "services" / "metal_pipeline.py").write_text(
        "def dispatch_kernel(db, kernel_name: str):\n"
        '    return db.execute("SELECT id, kernel_name, status FROM compute_jobs")\n',
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "api" / "compute.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.metal_pipeline import dispatch_kernel\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/compute/jobs')\n"
        "def list_compute_jobs(db=None):\n"
        "    return dispatch_kernel(db, 'matmul_fp16')\n",
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "compute" / "page.tsx").write_text(
        "export default async function ComputePage() {\n"
        "  const res = await fetch('/api/v1/compute/jobs');\n"
        "  return <main>{String(res.ok)}</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Euda1mon1a"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "config", "user.email", "214782221+Euda1mon1a@users.noreply.github.com"],
        cwd=repo_dir,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init synthetic compute repo"], cwd=repo_dir, check=True)
    return repo_dir


_NOISE_TEMPLATES: tuple[str, ...] = (
    "swift_retain",
    "swift_release",
    "swift_bridgeObjectRetain",
    "objc_retainAutoreleasedReturnValue",
    "objc_release",
    "objc_autoreleaseReturnValue",
    "std::vector<float>::push_back",
    "core::ptr::drop_in_place",
    "Swift.Array._appendElementAssumeUniqueAndCapacity",
    "builtins.len",
    "protocol witness for ComputeBuffer.encode in conformance MetalBuf",
    "_$s7Compute8MetalBufCAA0A6BufferAAWP_TWo",
    "thunk for @escaping @callee_guaranteed () -> ()",
    "vtable thunk for KernelRunner::dispatch()",
)


class _TenKMockStratumPlugin:
    """Mock `StratumPlugin` emitting 10,000 Zoom-2/Zoom-3 nodes (>99% ARC/stdlib/thunk noise)."""

    name = "mock-metal-ir"
    version = "1.4.0"
    description = "Synthetic 10k-node IR/AIR & Mach-O microscope plugin"
    supported_zooms = (2, 3)

    def summarize_zoom1_badges(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
    ) -> dict[str, list[StratumSummaryBadge]]:
        _ = repo_root
        out: dict[str, list[StratumSummaryBadge]] = {}
        for node in report.nodes:
            if "metal_pipeline" in node.id or node.subkind == "route":
                out[node.id] = [
                    StratumSummaryBadge(key="metal_kernels", label="Metal AIR Kernels", count=4),
                    StratumSummaryBadge(key="retain_cycles", label="Retain Cycles", count=1),
                ]
        return out

    def expand_node_stratum(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
        node_id: str,
        zoom: MicroStratumZoom,
    ) -> StratumExpansionResult:
        _ = (repo_root, report)
        # Attempted mutation guard test: plugin must never flatten into Zoom-1 report.nodes!
        domain_nodes = [
            StratumMicroNode(
                id=f"z{zoom}:{node_id}:entry_dispatch",
                label="dispatch_kernel_entry",
                kind="sil_function" if zoom == 2 else "macho_symbol",
                zoom=zoom,
                source_file="backend/app/services/metal_pipeline.py",
                line=1,
                verification="verified",
                summary="Host-side compute kernel dispatcher.",
            ),
            StratumMicroNode(
                id=f"z{zoom}:{node_id}:air_matmul_fp16",
                label="air_kernel_matmul_fp16",
                kind="metal_air_kernel" if zoom == 2 else "metallib_section",
                zoom=zoom,
                source_file="shaders/matmul.metal",
                line=18,
                verification="verified",
                summary="FP16 tiled matrix multiply kernel.",
            ),
            StratumMicroNode(
                id=f"z{zoom}:{node_id}:buffer_bind_0",
                label="mtl_buffer_index_0",
                kind="air_buffer_binding",
                zoom=zoom,
                source_file="shaders/matmul.metal",
                line=22,
                verification="declared",
                summary="Buffer index 0 layout seam.",
            ),
            StratumMicroNode(
                id=f"z{zoom}:{node_id}:dyn_selector_lookup",
                label="objc_msgSend$dynamicPluginSelector",
                kind="dynamic_ir_call",
                zoom=zoom,
                source_file="backend/app/services/metal_pipeline.py",
                line=2,
                verification="unverified",
                summary="Opaque runtime selector target; static IR cannot resolve receiver.",
            ),
        ]
        # 1 witness trampoline bridging entry_dispatch -> air_matmul_fp16 + 9,995 leaf noise nodes = 9,996 noise + 4 domain = 10,000 total!
        trampoline_id = f"z{zoom}:noise:witness_bridge"
        noise_nodes: list[StratumMicroNode] = [
            StratumMicroNode(
                id=trampoline_id,
                label="protocol witness for KernelDispatch.invoke in conformance MetalPipe",
                kind="witness_thunk",
                zoom=zoom,
                verification="verified",
            )
        ]
        entry_id = domain_nodes[0].id
        edges: list[StratumMicroEdge] = [
            StratumMicroEdge(
                id=f"e:{entry_id}->trampoline",
                source_id=entry_id,
                target_id=trampoline_id,
                kind="calls_ir",
                verification="verified",
            ),
            StratumMicroEdge(
                id="e:trampoline->matmul",
                source_id=trampoline_id,
                target_id=domain_nodes[1].id,
                kind="calls_ir",
                verification="verified",
            ),
            StratumMicroEdge(
                id="e:matmul->buf0",
                source_id=domain_nodes[1].id,
                target_id=domain_nodes[2].id,
                kind="binds_buffer",
                verification="declared",
            ),
            StratumMicroEdge(
                id="e:entry->dyn_unverified",
                source_id=entry_id,
                target_id=domain_nodes[3].id,
                kind="dynamic_dispatch",
                verification="unverified",
                evidence_note="Indirect vtable/selector dispatch target unresolved statically",
            ),
        ]
        n_templates = len(_NOISE_TEMPLATES)
        for i in range(9995):
            sym = _NOISE_TEMPLATES[i % n_templates]
            nid = f"z{zoom}:noise:{i:04d}"
            noise_nodes.append(
                StratumMicroNode(
                    id=nid,
                    label=sym,
                    kind="ir_thunk",
                    zoom=zoom,
                    verification="verified",
                )
            )
            edges.append(
                StratumMicroEdge(
                    id=f"e:noise:{i:04d}",
                    source_id=node_id,
                    target_id=nid,
                    kind="calls_ir",
                    verification="verified",
                )
            )
        return StratumExpansionResult(
            summary_badges=[
                StratumSummaryBadge(key="metal_kernels", label="Metal AIR Kernels", count=4),
                StratumSummaryBadge(key="ir_symbols", label="Raw IR Symbols", count=10000),
            ],
            nodes=[*domain_nodes, *noise_nodes],
            edges=edges,
            notes=[f"Expanded Zoom-{zoom} IR subgraph for {node_id}"],
        )


def test_zero_plugin_baseline_and_10k_node_zoom1_invariance_and_compaction_perf(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify (a) Zoom-1 digest invariance, (b) <0.5s >95% compaction on 10,000 nodes, (d) zero-plugin clean op, and (e) unverified IR preservation."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _build_synthetic_repo(tmp_path / "compute-app")
    register_target(
        db_session,
        TargetProjectCreate(
            slug="compute-app",
            name="Compute App",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
            backend_subdir="backend",
            frontend_subdir="frontend",
        ),
    )
    target = get_target_by_slug(db_session, "compute-app")
    assert target is not None

    # (d) Zero-plugin baseline scan
    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: [])
    baseline_rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    baseline_digest = baseline_rep.content_digest
    baseline_node_ids = [n.id for n in baseline_rep.nodes]
    baseline_edge_ids = [e.id for e in baseline_rep.edges]
    assert all(n.stratum_badges == [] for n in baseline_rep.nodes)

    svc_node = next(n for n in baseline_rep.nodes if "metal_pipeline" in n.id)
    zero_drill = build_node_stratum_drilldown(repo_dir, baseline_rep, svc_node.id, zoom=2)
    assert zero_drill.active_plugins == []
    assert zero_drill.raw_node_count == 0
    assert zero_drill.nodes == []
    assert any("No active StratumPlugin" in nt for nt in zero_drill.notes)

    # (a) Activate 10,000-node StratumPlugin -> Zoom-1 digest & node/edge counts stay 100% identical!
    plugin_inst = _TenKMockStratumPlugin()
    assert isinstance(plugin_inst, StratumPlugin)
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda *, group: [_FakeEntryPoint("mock-metal-ir", "mock_pkg:plugin", plugin_inst, "1.4.0")],
    )
    plugin_rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert plugin_rep.content_digest == baseline_digest
    assert [n.id for n in plugin_rep.nodes] == baseline_node_ids
    assert [e.id for e in plugin_rep.edges] == baseline_edge_ids

    badged_svc = next(n for n in plugin_rep.nodes if n.id == svc_node.id)
    assert [b.key for b in badged_svc.stratum_badges] == ["metal_kernels", "retain_cycles"]

    # (b) 10,000-node Zoom-2 compaction must fold >95% boilerplate in <0.5s
    t0 = time.perf_counter()
    compacted: StratumDrilldownRead = build_node_stratum_drilldown(
        repo_dir,
        plugin_rep,
        svc_node.id,
        zoom=2,
        unfiltered_ir=False,
    )
    elapsed_s = time.perf_counter() - t0
    assert elapsed_s < 0.5, f"10k compaction took {elapsed_s:.3f}s (expected < 0.5s)"

    assert compacted.raw_node_count == 10000
    assert compacted.collapsed_thunk_count == 9996  # 99.96% > 95% folded!
    assert compacted.compacted_node_count == 4
    assert len(compacted.nodes) == 4
    assert compacted.active_plugins == ["mock-metal-ir"]

    parent_summary_edge = next(
        e for e in compacted.edges if e.id == f"s:collapsed:{svc_node.id}:thunks"
    )
    assert parent_summary_edge.collapsed_count == 9995
    assert parent_summary_edge.label == "+9995 runtime/stdlib thunks collapsed"
    assert "+9995 runtime/stdlib thunks collapsed" in parent_summary_edge.evidence_note
    assert len(parent_summary_edge.collapsed_samples) == 8

    # Witness trampoline between entry_dispatch -> air_matmul_fp16 is bridged cleanly
    assert any(
        e.id.startswith("s:bridged:") and e.target_id.endswith(":air_matmul_fp16")
        for e in compacted.edges
    )

    # (e) Unresolved dynamic IR call target (`verification="unverified"`) is preserved, never swallowed
    unverified_nodes = [n for n in compacted.nodes if n.verification == "unverified"]
    unverified_edges = [e for e in compacted.edges if e.verification == "unverified"]
    assert len(unverified_nodes) == 1
    assert "objc_msgSend" in unverified_nodes[0].label
    assert len(unverified_edges) == 1

    # `--unfiltered-ir` (`unfiltered_ir=True`) preserves all 10,000 raw micro-nodes
    unfiltered = build_node_stratum_drilldown(
        repo_dir,
        plugin_rep,
        svc_node.id,
        zoom=2,
        unfiltered_ir=True,
    )
    assert unfiltered.unfiltered_ir is True
    assert unfiltered.raw_node_count == 10000
    assert unfiltered.compacted_node_count == 10000
    assert unfiltered.collapsed_thunk_count == 0
    assert len(unfiltered.nodes) == 10000


def test_stratum_plugin_discovery_cli_api_mcp_and_fault_isolation(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify `StratumPlugin` discovery across CLI/HTTP/MCP plus crash & mutation isolation."""
    assert isolated_db_url.startswith("sqlite:")

    class _MutatingCrashPlugin:
        name = "rogue-crash-stratum"
        supported_zooms = (2,)

        def summarize_zoom1_badges(
            self, repo_root: Path, report: TruthAtlasReport
        ) -> dict[str, list[StratumSummaryBadge]]:
            report.nodes.clear()  # Must be rolled back by plugin_registry!
            raise RuntimeError("boom in badge hook")

        def expand_node_stratum(
            self, repo_root: Path, report: TruthAtlasReport, node_id: str, zoom: MicroStratumZoom
        ) -> StratumExpansionResult:
            report.nodes.clear()  # Must be rolled back!
            raise RuntimeError("boom in expand hook")

    eps = [
        _FakeEntryPoint("mock-metal-ir", "pkg_a:plugin", _TenKMockStratumPlugin(), "1.4.0"),
        _FakeEntryPoint("rogue-crash-stratum", "pkg_b:plugin", _MutatingCrashPlugin(), "0.1.0"),
    ]
    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: eps)

    specs = discover_plugins()
    stratum_specs = [s for s in specs if s.kind == "stratum_inspector"]
    assert [s.name for s in stratum_specs] == ["mock-metal-ir", "rogue-crash-stratum"]

    # CLI `wythe plugins` & `wythe plugins --json`
    assert cli_main(["plugins"]) == 0
    cli_txt = capsys.readouterr().out
    assert "mock-metal-ir" in cli_txt
    assert "stratum_inspector, StratumPlugin zooms=2,3" in cli_txt

    assert cli_main(["plugins", "--json"]) == 0
    cli_json = json.loads(capsys.readouterr().out)
    by_name = {p["name"]: p for p in cli_json["plugins"]}
    assert by_name["mock-metal-ir"]["kind"] == "stratum_inspector"
    assert by_name["mock-metal-ir"]["supported_zooms"] == [2, 3]

    # MCP `wythe_plugins`
    mcp_res = dispatch_mcp_request(
        db_session,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "wythe_plugins", "arguments": {}}},
    )
    assert mcp_res is not None and mcp_res["result"]["isError"] is False
    mcp_txt = mcp_res["result"]["content"][0]["text"]
    assert "mock-metal-ir" in mcp_txt and "stratum_inspector" in mcp_txt and "StratumPlugin" in mcp_txt

    # HTTP `GET /api/v1/adapters/plugins` + fault isolation during scan & drilldown
    repo_dir = _build_synthetic_repo(tmp_path / "iso-app")
    app = create_app()
    with TestClient(app) as client:
        plugins_http = client.get("/api/v1/adapters/plugins")
        assert plugins_http.status_code == 200
        p_names = {p["name"]: p for p in plugins_http.json()["plugins"]}
        assert p_names["mock-metal-ir"]["kind"] == "stratum_inspector"

        reg = client.post(
            "/api/v1/targets",
            json={
                "slug": "iso-app",
                "name": "Iso App",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        assert reg.status_code in (200, 201)
        scan_json = client.get("/api/v1/scans/iso-app").json()
        assert len(scan_json["nodes"]) >= 3  # Rogue `report.nodes.clear()` was rolled back!
        assert any("rogue-crash-stratum" in n and "isolated" in n for n in scan_json["scan_notes"])

        svc_id = next(n["id"] for n in scan_json["nodes"] if "metal_pipeline" in n["id"])
        strata_resp = client.get(f"/api/v1/scans/iso-app/nodes/{svc_id}/strata?zoom=2")
        assert strata_resp.status_code == 200
        strata_data = strata_resp.json()
        assert strata_data["active_plugins"] == ["mock-metal-ir"]
        assert strata_data["compacted_node_count"] == 4
        assert any("rogue-crash-stratum" in nt and "isolated" in nt for nt in strata_data["notes"])


def test_http_strata_routes_404_cli_context_and_mcp_cone_lod(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify (c) bounded CLI/HTTP/MCP zoom=2|3 cones & resource URIs, slash route IDs, and (e) 404 negative controls."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _build_synthetic_repo(tmp_path / "lod-routes-app")
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda *, group: [
            _FakeEntryPoint("mock-metal-ir", "mock_pkg:plugin", _TenKMockStratumPlugin(), "1.4.0")
        ],
    )

    app = create_app()
    with TestClient(app) as client:
        reg = client.post(
            "/api/v1/targets",
            json={
                "slug": "lod-routes-app",
                "name": "LOD Routes App",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        assert reg.status_code in (200, 201)

        scan_data = client.get("/api/v1/scans/lod-routes-app").json()
        route_node = next(n for n in scan_data["nodes"] if n["subkind"] == "route")
        svc_node = next(n for n in scan_data["nodes"] if "metal_pipeline" in n["id"])

        # Slash-bearing route node_id works both raw (`{node_id:path}`) and `encodeURIComponent`
        raw_route_strata = client.get(
            f"/api/v1/scans/lod-routes-app/nodes/{route_node['id']}/strata?zoom=3"
        )
        assert raw_route_strata.status_code == 200
        assert raw_route_strata.json()["zoom"] == 3
        assert raw_route_strata.json()["parent_node_id"] == route_node["id"]
        assert raw_route_strata.json()["compacted_node_count"] == 4

        encoded_id = urllib.parse.quote(route_node["id"], safe="")
        enc_route_strata = client.get(
            f"/api/v1/scans/lod-routes-app/nodes/{encoded_id}/strata?zoom=2"
        )
        assert enc_route_strata.status_code == 200
        assert enc_route_strata.json()["parent_node_id"] == route_node["id"]

        # (e) Negative controls: unknown node_id -> 404, unknown target -> 404
        missing_node = client.get(
            "/api/v1/scans/lod-routes-app/nodes/m:service:does_not_exist/strata?zoom=2"
        )
        assert missing_node.status_code == 404
        missing_target = client.get(
            "/api/v1/scans/unknown-target/nodes/m:service:any/strata?zoom=2"
        )
        assert missing_target.status_code == 404

        # `/context` and `/context/cone` default to zoom=1 (`stratum_drilldowns == []`)
        cone_z1 = client.get(f"/api/v1/scans/lod-routes-app/context?q={svc_node['id']}").json()
        assert cone_z1["zoom"] == 1
        assert cone_z1["stratum_drilldowns"] == []

        cone_z2 = client.get(
            f"/api/v1/scans/lod-routes-app/context/cone?q={svc_node['id']}&zoom=2"
        ).json()
        parsed_slice = LineageConeSlice.model_validate(cone_z2)
        assert parsed_slice.zoom == 2
        assert len(parsed_slice.stratum_drilldowns) >= 1
        assert parsed_slice.stratum_drilldowns[0].collapsed_thunk_count == 9996
        assert parsed_slice.completeness is not None
        assert parsed_slice.completeness.is_complete is True

        # Bounded cone with `unfiltered_ir=true` (without `full=true`) enforces #46 truncation cap!
        cone_unfiltered_bounded = client.get(
            f"/api/v1/scans/lod-routes-app/context/cone?q={svc_node['id']}&zoom=2&unfiltered_ir=true"
        ).json()
        comp_u = cone_unfiltered_bounded["completeness"]
        assert comp_u["is_complete"] is False
        assert comp_u["stratum_nodes"]["included"] == 40
        assert comp_u["stratum_nodes"]["eligible"] == 10000
        assert comp_u["stratum_nodes"]["omitted"] == 9960
        assert any(r.startswith("stratum_nodes_capped:") for r in comp_u["truncation_reasons"])

    # CLI `wythe context --zoom 2` (Markdown & JSON)
    capsys.readouterr()
    assert cli_main(["context", "lod-routes-app", svc_node["id"], "--zoom", "2"]) == 0
    cli_cone_md = capsys.readouterr().out
    assert "## Microscope Strata (Zoom 2 | compacted)" in cli_cone_md
    assert "+9995 runtime/stdlib thunks collapsed" in cli_cone_md
    assert "unverified=1" in cli_cone_md
    assert len(cli_cone_md) < 8000  # Strictly bounded!

    assert cli_main(["context", "lod-routes-app", svc_node["id"], "--zoom", "2", "--json"]) == 0
    cli_cone_json = json.loads(capsys.readouterr().out)
    assert cli_cone_json["zoom"] == 2
    assert cli_cone_json["stratum_drilldowns"][0]["compacted_node_count"] == 4

    # MCP `wythe_lineage_cone(zoom=2)` + `wythe://<slug>/cone/<node_id>?zoom=2`
    mcp_cone = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "wythe_lineage_cone",
                "arguments": {"target": "lod-routes-app", "query": svc_node["id"], "zoom": 2},
            },
        },
    )
    assert mcp_cone is not None and mcp_cone["result"]["isError"] is False
    mcp_cone_md = mcp_cone["result"]["content"][0]["text"]
    assert "Microscope Strata (Zoom 2 | compacted)" in mcp_cone_md
    assert "+9995 runtime/stdlib thunks collapsed" in mcp_cone_md
    assert len(mcp_cone_md) < 9000

    mcp_res_uri = f"wythe://lod-routes-app/cone/{urllib.parse.quote(svc_node['id'], safe='')}?zoom=2"
    mcp_res = dispatch_mcp_request(
        db_session,
        {"jsonrpc": "2.0", "id": 12, "method": "resources/read", "params": {"uri": mcp_res_uri}},
    )
    assert mcp_res is not None and "result" in mcp_res
    res_txt = mcp_res["result"]["contents"][0]["text"]
    assert "Microscope Strata (Zoom 2 | compacted)" in res_txt

    mcp_raw_route_uri = f"wythe://lod-routes-app/cone/{route_node['id']}?zoom=2"
    mcp_route_res = dispatch_mcp_request(
        db_session,
        {"jsonrpc": "2.0", "id": 14, "method": "resources/read", "params": {"uri": mcp_raw_route_uri}},
    )
    assert mcp_route_res is not None and "result" in mcp_route_res
    assert "Microscope Strata (Zoom 2 | compacted)" in mcp_route_res["result"]["contents"][0]["text"]

    # Reject invalid zoom values (`zoom=True`, `zoom=9`) cleanly
    bad_zoom = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "wythe_lineage_cone",
                "arguments": {"target": "lod-routes-app", "query": svc_node["id"], "zoom": True},
            },
        },
    )
    assert bad_zoom is not None and bad_zoom["result"]["isError"] is True


def test_wave2_stratum_modules_pass_wythe_self_dogfood_and_slm_budget() -> None:
    """Ensure all new/edited Wave 2 stratum modules obey MANIP-001/002 and SLM <2KB budget."""
    encoded_slm = json.dumps(MCP_SLM_TOOLS, separators=(",", ":")).encode("utf-8")
    assert len(encoded_slm) < 2000

    wt_root = Path(__file__).resolve().parents[2]
    checked = [
        ("backend/app/adapters/plugin_registry.py", "app.adapters.plugin_registry"),
        ("backend/app/services/stratum_service.py", "app.services.stratum_service"),
        ("backend/app/services/llm_context_service.py", "app.services.llm_context_service"),
        ("backend/app/services/scanner_service.py", "app.services.scanner_service"),
        ("backend/app/services/mcp_service.py", "app.services.mcp_service"),
        ("backend/app/api/routes/scans.py", "app.api.routes.scans"),
        ("backend/app/cli.py", "app.cli"),
    ]
    for rel_path, mod_name in checked:
        source_text = (wt_root / rel_path).read_text(encoding="utf-8")
        parsed = parse_python_module(source_text, rel_path, mod_name)
        assert parsed is not None
        if "/adapters/" not in rel_path:
            assert parsed.policy_literals == (), f"MANIP-001 triggered in {rel_path}: {parsed.policy_literals}"
        assert parsed.raw_clock_calls == (), f"MANIP-002 triggered in {rel_path}: {parsed.raw_clock_calls}"


def test_stratum_adversarial_diamond_memoization_epistemics_and_deep_isolation(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression suite for #82 items 1, 2, & 3: O(V+E) diamond DAG, #47 epistemics, multi-hop thunks, deep copy isolation, & plugin metadata."""
    assert isolated_db_url.startswith("sqlite:")

    # Item 1a: 30-level compiler-thunk diamond DAG (2^30 paths if unmemoized!) completes in <0.05s
    diamond_nodes: list[StratumMicroNode] = [
        StratumMicroNode(id="ir:src", label="entry_fn", kind="sil_fn", zoom=2, verification="verified"),
        StratumMicroNode(id="ir:dst", label="target_fn", kind="sil_fn", zoom=2, verification="verified"),
    ]
    diamond_edges: list[StratumMicroEdge] = []
    prev_pair = ["ir:src"]
    for lvl in range(30):
        left_id = f"ir:w:{lvl}:L"
        right_id = f"ir:w:{lvl}:R"
        diamond_nodes.append(
            StratumMicroNode(
                id=left_id,
                label=f"protocol witness for Level{lvl}Left",
                kind="witness",
                zoom=2,
                verification="verified",
            )
        )
        diamond_nodes.append(
            StratumMicroNode(
                id=right_id,
                label=f"thunk for Level{lvl}Right",
                kind="witness",
                zoom=2,
                verification="verified",
            )
        )
        for p in prev_pair:
            diamond_edges.append(
                StratumMicroEdge(id=f"e:{p}->{left_id}", source_id=p, target_id=left_id, kind="calls_ir", verification="verified")
            )
            diamond_edges.append(
                StratumMicroEdge(id=f"e:{p}->{right_id}", source_id=p, target_id=right_id, kind="calls_ir", verification="verified")
            )
        prev_pair = [left_id, right_id]
    for p in prev_pair:
        diamond_edges.append(
            StratumMicroEdge(id=f"e:{p}->ir:dst", source_id=p, target_id="ir:dst", kind="calls_ir", verification="verified")
        )

    t0 = time.perf_counter()
    c_nodes, c_edges, raw_n, comp_n, fold_n = compact_stratum_subgraph(
        "m:svc:diamond", diamond_nodes, diamond_edges
    )
    elapsed_diamond = time.perf_counter() - t0
    assert elapsed_diamond < 0.05, f"30-level diamond took {elapsed_diamond:.3f}s"
    assert (raw_n, comp_n, fold_n) == (62, 2, 60)
    assert len(c_nodes) == 2
    bridged = next(e for e in c_edges if e.id == "s:bridged:ir:src->ir:dst:calls_ir")
    assert bridged.collapsed_count == 60  # All 60 intermediate witness/thunk labels recorded!

    # Item 1b & 1c: #47 broken/unverified edge inside thunk chain + multi-hop W1->W2->B + external "swift_release"
    ep_nodes = [
        StratumMicroNode(id="ir:A", label="domain_caller", kind="sil_fn", zoom=2, verification="verified"),
        StratumMicroNode(id="ir:B", label="domain_callee", kind="sil_fn", zoom=2, verification="verified"),
        StratumMicroNode(id="ir:W1", label="thunk for hop1", kind="thunk", zoom=2, verification="verified"),
        StratumMicroNode(id="ir:W2", label="vtable thunk hop2", kind="thunk", zoom=2, verification="verified"),
        StratumMicroNode(id="ir:T_unv", label="_$s4Demo_TWo", kind="thunk", zoom=2, verification="verified"),
        StratumMicroNode(id="ir:orphan_thunk", label="objc_retain", kind="arc", zoom=2, verification="verified"),
    ]
    ep_edges = [
        StratumMicroEdge(id="e:1", source_id="ir:A", target_id="ir:W1", kind="calls_ir", verification="verified"),
        StratumMicroEdge(id="e:2", source_id="ir:W1", target_id="ir:W2", kind="calls_ir", verification="verified"),
        StratumMicroEdge(id="e:3", source_id="ir:W2", target_id="ir:B", kind="calls_ir", verification="verified"),
        # W1 -> external ARC symbol "swift_release" not in nodes_by_id must fold, NOT bridge!
        StratumMicroEdge(id="e:4", source_id="ir:W1", target_id="swift_release", kind="calls_ir", verification="verified"),
        # A --[verified]--> T_unv --[broken]--> swift_retain must mark s:collapsed:ir:A:thunks as "broken"!
        StratumMicroEdge(id="e:5", source_id="ir:A", target_id="ir:T_unv", kind="calls_ir", verification="verified"),
        StratumMicroEdge(id="e:6", source_id="ir:T_unv", target_id="swift_retain", kind="calls_ir", verification="broken"),
        # Unaccounted orphan thunk with internal "declared" edge to stdlib
        StratumMicroEdge(id="e:7", source_id="ir:orphan_thunk", target_id="std::terminate", kind="calls_ir", verification="declared"),
    ]
    _, ep_comp_edges, _, _, _ = compact_stratum_subgraph("m:svc:ep", ep_nodes, ep_edges)
    hop_bridge = next(e for e in ep_comp_edges if e.id == "s:bridged:ir:A->ir:B:calls_ir")
    assert hop_bridge.collapsed_count == 2
    assert set(hop_bridge.collapsed_samples) == {"thunk for hop1", "vtable thunk hop2"}
    assert not any("swift_release" in e.id and e.id.startswith("s:bridged:") for e in ep_comp_edges)

    a_collapsed = next(e for e in ep_comp_edges if e.id == "s:collapsed:ir:A:thunks")
    assert a_collapsed.verification == "broken"  # Never promoted to "verified"!
    assert "swift_release" in a_collapsed.collapsed_samples

    parent_collapsed = next(e for e in ep_comp_edges if e.id == "s:collapsed:m:svc:ep:thunks")
    assert parent_collapsed.verification == "declared"

    # Item 2 & 3: In-place mutation without raising + strict_plugins load failure + adapters/plugins source/zooms + query-first URI
    class _SilentTamperStratumPlugin:
        name = "silent-tamper-stratum"
        supported_zooms = (2,)

        def summarize_zoom1_badges(
            self, repo_root: Path, report: TruthAtlasReport
        ) -> dict[str, list[StratumSummaryBadge]]:
            if report.nodes:
                report.nodes[0].status = "orphaned"
            if report.edges:
                report.edges[0].verification = "broken"
            report.findings.clear()
            report.content_digest = "TAMPERED_DIGEST"
            return {report.nodes[0].id: [StratumSummaryBadge(key="ir_ops", label="IR Ops", count=2)]} if report.nodes else {}

        def expand_node_stratum(
            self, repo_root: Path, report: TruthAtlasReport, node_id: str, zoom: MicroStratumZoom
        ) -> StratumExpansionResult:
            if report.nodes:
                report.nodes[0].status = "orphaned"
            report.content_digest = "TAMPERED_DIGEST"
            return StratumExpansionResult()

    repo_dir = _build_synthetic_repo(tmp_path / "tamper-app")
    # Add a second route whose path includes `?limit=10` to test Item 3 query-first fallback
    (repo_dir / "backend" / "app" / "api" / "compute.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.metal_pipeline import dispatch_kernel\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/compute/jobs')\n"
        "def list_compute_jobs(db=None):\n"
        "    return dispatch_kernel(db, 'matmul_fp16')\n\n"
        "@router.get('/api/v1/compute/jobs?limit=10')\n"
        "def list_limited_jobs(db=None):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: [])
    register_target(
        db_session,
        TargetProjectCreate(
            slug="tamper-app",
            name="Tamper App",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
            backend_subdir="backend",
            frontend_subdir="frontend",
        ),
    )
    target = get_target_by_slug(db_session, "tamper-app")
    assert target is not None
    clean_rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    expected_digest = clean_rep.content_digest
    expected_statuses = [(n.id, n.status) for n in clean_rep.nodes]
    expected_verifs = [(e.id, e.verification) for e in clean_rep.edges]

    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda *, group: [_FakeEntryPoint("silent-tamper-stratum", "pkg:tamper", _SilentTamperStratumPlugin(), "0.2.0")],
    )
    persisted_rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=True)
    assert persisted_rep.content_digest == expected_digest
    assert [(n.id, n.status) for n in persisted_rep.nodes] == expected_statuses
    assert [(e.id, e.verification) for e in persisted_rep.edges] == expected_verifs
    assert persisted_rep.nodes[0].stratum_badges[0].key == "ir_ops"

    # Single broken stratum entry point honors strict_plugins=True AND records scan_notes on strict_plugins=False
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda *, group: [_FakeEntryPoint("sole-broken-stratum", "pkg:bad", ImportError("missing llvm"), "0.1.0")],
    )
    with pytest.raises(ImportError):
        attach_zoom1_stratum_badges(repo_dir, clean_rep.model_copy(deep=True), strict_plugins=True)
    note_rep = clean_rep.model_copy(deep=True)
    attach_zoom1_stratum_badges(repo_dir, note_rep, strict_plugins=False)
    assert any("sole-broken-stratum" in nt and "isolated" in nt for nt in note_rep.scan_notes)

    # Item 3: GET /api/v1/adapters/plugins exposes module source + supported_zooms, and wythe:// query-first matching
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda *, group: [_FakeEntryPoint("mock-metal-ir", "pkg:metal", _TenKMockStratumPlugin(), "1.4.0")],
    )
    app = create_app()
    with TestClient(app) as client:
        plug_json = client.get("/api/v1/adapters/plugins").json()
        metal_meta = next(p for p in plug_json["plugins"] if p["name"] == "mock-metal-ir")
        assert metal_meta["supported_zooms"] == [2, 3]
        assert "test_wave2_stratum_lod" in metal_meta["source"]

    uri_res = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "resources/read",
            "params": {"uri": "wythe://tamper-app/cone//api/v1/compute/jobs?limit=10"},
        },
    )
    assert uri_res is not None and "result" in uri_res
    assert "list_limited_jobs" in uri_res["result"]["contents"][0]["text"] or "limit=10" in uri_res["result"]["contents"][0]["text"]
