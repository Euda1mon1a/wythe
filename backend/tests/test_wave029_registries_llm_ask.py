"""Wave 0.2.9 regression tests for #97 (registries/launchd/systemd/freshness), #95 (Ask provenance/mlx_vlm), and #108 (version lockup)."""

from __future__ import annotations

import http.server
import json
import plistlib
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self

import pytest
from fastapi.testclient import TestClient

from app.adapters.container_launchers import augment_container_launchers
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.registry_sources import _is_excluded_registry_candidate
from app.adapters.service_sources import source_reference_with_mode
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.main import create_app
from app.schemas.atlas import (
    AtlasSummaryStats,
    GateEvaluation,
    LegacyBridgeSummary,
    TruthAtlasReport,
)
from app.services.llm_context_service import build_lineage_cone_slice, build_llms_txt_brief
from app.services.on_device_llm_service import (
    _looks_vision_capable,
    _sanitize_endpoint_origin,
    _select_safe_seat_model,
    probe_local_openai_engine,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def test_97_yaml_registry_safe_load_exclusions_and_accurate_format_labels(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "config/routing.yaml",
        "providers:\n"
        "  local:\n"
        "    enabled: true\n"
        "seats:\n"
        "  primary:\n"
        "    lane: fast\n"
        "    model: qwen\n"
        "routes:\n"
        "  default:\n"
        "    command: scripts/service_runner.py\n"
        "policies:\n"
        "  timeout_seconds: 15\n"
        "rules:\n"
        "  strict: true\n"
        "tokens:\n"
        "  max_tokens: 2048\n",
    )
    _write(
        tmp_path,
        "config/jobs.json",
        json.dumps({"jobs": [{"command": "scripts/service_runner.py", "enabled": True}]}),
    )
    _write(tmp_path, "config/unsafe.yaml", "seats:\n  bad: !!python/object/apply:os.system ['echo hi']\n")
    _write(tmp_path, "config/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\n")
    _write(tmp_path, "config/deno.lock", '{"version": "3"}\n')
    _write(tmp_path, "config/.github/workflows/ci.yml", "jobs:\n  test:\n    steps: []\n")
    _write(tmp_path, "config/.gitlab-ci.yml", "stages:\n  - test\nroutes:\n  - a\n")
    _write(tmp_path, "config/.circleci/config.yml", "version: 2.1\njobs:\n  build: {}\n")
    _write(tmp_path, "config/fixtures/seats.yaml", "seats:\n  demo:\n    enabled: true\n")
    _write(tmp_path, "config/testdata/routes.yaml", "routes:\n  demo:\n    enabled: true\n")
    _write(tmp_path, "config/seats.fixture.yaml", "seats:\n  demo:\n    enabled: true\n")
    _write(tmp_path, "config/__tests__/lanes.json", '{"lanes": {"demo": {"enabled": true}}}')
    _write(
        tmp_path,
        "config/meta_schema.json",
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {"seats": {"type": "object"}},
                "$defs": {"seat": {"type": "object"}},
            }
        ),
    )
    assert _is_excluded_registry_candidate("config/.gitlab-ci.yml", {"routes": ["a"]}) is True
    assert _is_excluded_registry_candidate("config/.circleci/config.yml", {"jobs": {}}) is True
    assert _is_excluded_registry_candidate("config/testdata/routes.yaml", {"routes": {}}) is True
    assert _is_excluded_registry_candidate("config/seats.fixture.yaml", {"seats": {}}) is True
    assert _is_excluded_registry_candidate("config/__tests__/lanes.json", {"lanes": {}}) is True

    _write(
        tmp_path,
        "scripts/service_runner.py",
        "from pathlib import Path\n"
        "import yaml\n"
        "def load_cfg():\n"
        "    cfg = yaml.safe_load(Path('config/routing.yaml').read_text())\n"
        "    return cfg['policies']['timeout_seconds']\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)

    reg_nodes = {n.id: n for n in truth.nodes if n.id.startswith("t:registry:")}
    assert set(reg_nodes) == {"t:registry:config/routing.yaml", "t:registry:config/jobs.json"}
    assert "Declarative YAML" in reg_nodes["t:registry:config/routing.yaml"].summary
    assert "Declarative JSON" in reg_nodes["t:registry:config/jobs.json"].summary

    m_nodes = {n.id: n for n in manip.nodes if n.id.startswith("m:registry:")}
    assert m_nodes["m:registry:config/routing.yaml"].summary.startswith("YAML command declarations")
    assert m_nodes["m:registry:config/jobs.json"].summary.startswith("JSON command declarations")

    read_edge = next(
        e for e in manip.edges if e.kind == "reads_truth" and e.target_id == "t:registry:config/routing.yaml"
    )
    assert "declarative YAML registry" in read_edge.evidence_note
    call_edge_yaml = next(
        e for e in manip.edges if e.source_id == "m:registry:config/routing.yaml"
    )
    assert call_edge_yaml.evidence_note.startswith("YAML command field")
    assert any("JSON/YAML (1 JSON, 1 YAML) command source coverage" in n for n in manip.notes)
    assert any("1 unreadable files" in n for n in manip.notes)
    assert manip.coverage_complete is False
    assert truth.coverage_complete is False


def test_97_launchd_and_systemd_suffix_paths_declared_with_host_install_path_unverified(
    tmp_path: Path,
) -> None:
    paths = {"scripts/pa/worker.py", "one/scripts/dup.py", "two/scripts/dup.py"}
    assert source_reference_with_mode("scripts/pa/worker.py", "launchagents/a.plist", paths) == (
        "scripts/pa/worker.py",
        "exact",
    )
    assert source_reference_with_mode("worker.py", "scripts/pa/caller.py", paths) == (
        "scripts/pa/worker.py",
        "sibling",
    )
    assert source_reference_with_mode(
        "/opt/host/app/scripts/pa/worker.py", "launchagents/a.plist", paths
    ) == ("scripts/pa/worker.py", "suffix")
    assert source_reference_with_mode(
        "/opt/host/app/scripts/dup.py", "launchagents/a.plist", paths
    ) is None

    _write(tmp_path, "scripts/pa/worker.py", "def run():\n    return 1\n")
    _write(tmp_path, "scripts/sub/helper.sh", "#!/bin/sh\necho ok\n")
    _write(tmp_path, "one/scripts/dup.py", "pass\n")
    _write(tmp_path, "two/scripts/dup.py", "pass\n")

    plist_path = tmp_path / "launchagents/com.example.worker.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.worker",
                "ProgramArguments": ["/usr/bin/python3", "/opt/host/app/scripts/pa/worker.py"],
            }
        )
    )
    plist_ambig = tmp_path / "launchagents/com.example.ambig.plist"
    plist_ambig.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.ambig",
                "ProgramArguments": ["/usr/bin/python3", "/opt/host/app/scripts/dup.py"],
            }
        )
    )
    _write(
        tmp_path,
        "deploy/helper.service",
        "[Unit]\nDescription=Helper\n[Service]\n"
        "ExecStart=/home/runner/installed/scripts/sub/helper.sh\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)
    augment_container_launchers(tmp_path, ".", manip)

    launchd_edges = [
        e for e in manip.edges if e.source_id == "m:launchd:launchagents/com.example.worker.plist"
    ]
    assert len(launchd_edges) == 1
    assert launchd_edges[0].target_id == "m:script:scripts/pa/worker.py"
    assert launchd_edges[0].verification == "declared"
    assert "host_install_path_unverified" in launchd_edges[0].evidence_note

    assert not any(
        e.source_id == "m:launchd:launchagents/com.example.ambig.plist" for e in manip.edges
    )

    sys_edges = [e for e in manip.edges if e.source_id == "m:systemd:deploy/helper.service"]
    assert len(sys_edges) == 1
    assert sys_edges[0].target_id == "m:script:scripts/sub/helper.sh"
    assert sys_edges[0].verification == "declared"
    assert "host_install_path_unverified" in sys_edges[0].evidence_note


def test_97_llm_brief_and_cone_freshness_headers_and_unobserved_tier_counts(tmp_path: Path) -> None:
    obs = datetime(2026, 11, 20, 9, 30, tzinfo=UTC)
    val = obs + timedelta(hours=4)
    rep = TruthAtlasReport(
        target_slug="no-cov",
        target_name="No Cov",
        repo_path=str(tmp_path),
        stack_profile="no-coverage-fallback",
        coverage_complete=False,
        source_commit="1234567890abcdef",
        worktree_dirty=False,
        dirty_path_count=0,
        observed_at=obs,
        valid_until=val,
        observation_source="filesystem_ast",
        content_digest="abcdef1234567890abcdef1234567890",
        scan_notes=[
            "Database/persistence schema coverage is absent or unsupported (no-truth adapter).",
            "Backend manipulation/route coverage is absent or unsupported (no-manipulator adapter).",
            "Display tier is unobserved (no-display).",
        ],
        summary=AtlasSummaryStats(
            truth_tables=0,
            sql_functions=0,
            manipulator_routes=0,
            manipulator_services=0,
            display_pages=0,
            display_hooks_and_clients=0,
            verified_edges=0,
            end_to_end_chains=0,
            clean_nodes=0,
            flagged_nodes=0,
            blocking_findings=0,
            warning_findings=0,
        ),
        nodes=[],
        edges=[],
        chains=[],
        findings=[],
        gate=GateEvaluation(verdict="INCOMPLETE", mode="strict", blocking_violations=0, evaluated_at=obs),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )

    brief = build_llms_txt_brief(rep)
    assert rep.observed_at == obs
    assert brief.source_observed_at == obs
    assert brief.observed_at == obs
    assert brief.valid_until == val
    assert brief.observation_source == "filesystem_ast"
    assert brief.coverage_complete is False
    assert set(brief.unobserved_tiers) == {"truth", "manipulate", "display"}
    assert f"source_observed_at=`{obs.isoformat()}`" in brief.markdown
    assert "unobserved (no-truth)" in brief.markdown
    assert "unobserved (no-manipulator)" in brief.markdown
    assert "unobserved (no-display)" in brief.markdown
    assert "0 SQL tables" not in brief.markdown
    assert "0 route modules" not in brief.markdown
    assert "0 pages" not in brief.markdown

    cone = build_lineage_cone_slice(rep, "missing_symbol")
    assert rep.observed_at == obs
    assert cone.source_observed_at == obs
    assert cone.observed_at == obs
    assert cone.valid_until == val
    assert cone.observation_source == "filesystem_ast"
    assert cone.coverage_complete is False
    assert set(cone.unobserved_tiers) == {"truth", "manipulate", "display"}
    assert f"source_observed_at=`{obs.isoformat()}`" in cone.markdown
    assert "unobserved (no-truth)" in cone.markdown
    assert "unobserved (no-manipulator)" in cone.markdown
    assert "unobserved (no-display)" in cone.markdown


def test_95_mlx_vlm_loaded_flags_coresident_ranking_and_vision_families(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for m in (
        "qwen3.5-27b",
        "qwen3.6-35b",
        "qwen2.5-vl-7b",
        "qwen2-vl-7b",
        "kimi-vl-a3b",
        "allenai/molmo-7b",
        "rhymes-ai/Aria",
        "pixtral-12b",
        "llava-1.6-7b",
        "gemma-3-12b-it",
        "internvl2_5-8b",
        "minicpm-v-2_6",
    ):
        assert _looks_vision_capable(m) is True, m
    assert _looks_vision_capable("invariant-text-8b") is False

    items = [
        {"id": "mlx-community/qwen3-0.5b-4bit", "loaded": True},
        {"id": "mlx-community/helper-0.6b", "loaded": True},
        {"id": "mlx-community/tiny-1b", "loaded": True},
        {"id": "mlx-community/speculative-draft-2b", "loaded": True},
        {"id": "mlx-community/policy-gate-2b", "loaded": True},
        {"id": "mlx-community/bge-embed-small", "loaded": True},
        {"id": "mlx-community/bge-rerank-base", "loaded": True},
        {"id": "mlx-community/whisper-small", "loaded": True},
        {"id": "mlx-community/kokoro-tts", "loaded": True},
        {"id": "mlx-community/custom-chat-omni", "loaded": True},
        {"id": "mlx-community/Qwen3.6-35B-A3B-4bit", "loaded": False},
    ]
    assert _select_safe_seat_model(
        items, None, server_header="mlx_vlm/0.6.17", prefer_vision=True
    ) == ("mlx-community/custom-chat-omni", "mlx-community/custom-chat-omni")
    assert _select_safe_seat_model(
        items, "mlx-community/Qwen3.6-35B-A3B-4bit", server_header="mlx_vlm/0.6.17"
    ) is None
    assert _select_safe_seat_model(
        [{"id": "mlx-community/Qwen3.6-35B-A3B-4bit", "loaded": False}],
        None,
        server_header="mlx_vlm/0.6.17",
    ) is None

    class _FakeResp:
        def __init__(self, payload: dict[str, object], server: str = "mlx_vlm/0.6.17") -> None:
            self.status = 200
            self._body = json.dumps(payload).encode("utf-8")
            self.headers = {"Server": server}

        def read(self) -> bytes:
            return self._body

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    from app.services import on_device_llm_service as llm_svc

    monkeypatch.setattr(
        llm_svc._no_proxy_opener,
        "open",
        lambda _req, timeout=4.5: _FakeResp({"data": items}, server="mlx_vlm/0.6.17"),
    )
    probed = probe_local_openai_engine("http://alice:secret@127.0.0.1:8084/v1?k=1#f", prefer_vision=True)
    assert probed.state == "ready"
    assert probed.model_id == "mlx-community/custom-chat-omni"
    assert probed.supports_vision is True
    assert probed.base_url == "http://127.0.0.1:8084/v1"
    assert _sanitize_endpoint_origin("http://alice:secret@127.0.0.1:8084/v1?k=1#f") == "http://127.0.0.1:8084"


def test_95_ask_captures_resolved_model_id_vision_fallback_and_sanitized_provenance(
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    seen_models: list[str] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        server_version = "mlx_vlm/0.6.17"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                body = json.dumps(
                    {
                        "object": "list",
                        "data": [
                            {"id": "mlx-community/Qwen3.5-27B-4bit", "loaded": True},
                            {"id": "mlx-community/Phi-4-mini-instruct-4bit", "loaded": False},
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            raw = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or "0")).decode("utf-8"))
            seen_models.append(str(raw.get("model") or ""))
            last_user = raw["messages"][-1]["content"]
            if isinstance(last_user, list):
                self.send_response(422)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"text only"}')
                return
            reply = {
                "model": "mlx-community/Qwen3.5-27B-4bit",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "Table `atlas_rule_policies` governs strict gate rules."},
                    }
                ],
            }
            out = json.dumps(reply).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        app = create_app()
        with TestClient(app) as client:
            fake_png = (
                "data:image/png;base64,"
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            )
            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain atlas_rule_policies.",
                    "engine": "local",
                    "target_slug": "wythe",
                    "selected_node_id": "t:atlas_rule_policies",
                    "local_base_url": f"http://alice:secret@127.0.0.1:{port}/v1?token=leak#frag",
                    "local_model_id": "default_model",
                    "snapshot_data_url": fake_png,
                    "include_vision_snapshot": True,
                },
            )
            assert res.status_code == 200, res.text
            ans = res.json()
            assert seen_models == ["default_model", "default_model"]
            assert ans["execution_origin"] == "wythe_server"
            assert ans["endpoint_origin"] == f"http://127.0.0.1:{port}"
            assert "alice" not in str(ans["endpoint_origin"])
            assert "secret" not in str(ans["endpoint_origin"])
            assert "token" not in str(ans["endpoint_origin"])
            assert ans["requested_model_id"] == "default_model"
            assert ans["resolved_model_id"] == "mlx-community/Qwen3.5-27B-4bit"
            assert ans["model_id"] == "mlx-community/Qwen3.5-27B-4bit"
            assert ans["used_vision_snapshot"] is False
            assert ans["fallback_from"] == "vision"
    finally:
        srv.shutdown()
        srv.server_close()


def test_108_healthz_version_hook_lockup_and_drawer_provenance_contracts(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        hz = client.get("/healthz")
        assert hz.status_code == 200
        assert hz.json()["status"] == "ok"
        assert hz.json()["version"] == "0.2.9"

    use_atlas = (REPO_ROOT / "frontend/src/hooks/useAtlas.ts").read_text(encoding="utf-8")
    wythe_mark = (REPO_ROOT / "frontend/src/components/WytheMark.tsx").read_text(encoding="utf-8")
    page_tsx = (REPO_ROOT / "frontend/src/app/page.tsx").read_text(encoding="utf-8")
    drawer_tsx = (REPO_ROOT / "frontend/src/components/AskWytheDrawer.tsx").read_text(encoding="utf-8")

    assert "useWytheVersion" in use_atlas and "getHealthz" in use_atlas and "'0.2.9'" in use_atlas
    assert "WytheBrandLockup" in wythe_mark and "tabIndex={0}" in wythe_mark
    assert "Escape" in wythe_mark and "text-slate-100" in wythe_mark and "bg-slate-900" in wythe_mark
    assert "border-slate-700" in wythe_mark
    assert "<WytheBrandLockup" in page_tsx and "healthz?.version" in page_tsx
    assert "Boolean(res.used_vision_snapshot)" in drawer_tsx
