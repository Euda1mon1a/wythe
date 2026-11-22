"""Regression tests for v0.2.6 UX dogfooding fixes (seat selection, F11, plain-English, MANIP-003 re-exports, scan cache)."""

from __future__ import annotations

import http.server
import json
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import create_app
from app.services import apple_fm_service, investigation_service, mcp_service, on_device_llm_service
from app.services.governance_service import get_target_by_slug, update_rule_policy
from app.services.investigation_service import clear_scan_reuse_cache, get_or_run_cached_scan
from app.services.llm_context_service import (
    build_lineage_cone_slice,
    build_section_budgeted_ask_prompt,
)
from app.services.on_device_llm_service import (
    _question_requests_mcp_or_camera,
    _question_requests_plain_english,
    _select_safe_seat_model,
    build_ask_instructions,
    probe_local_openai_engine,
)
from app.services.ui_focus_service import explain_ui_focus


def _start_models_server(
    models_data: list[dict[str, Any]],
    *,
    server_header: str = "mlx_vlm/0.6.17",
) -> tuple[http.server.ThreadingHTTPServer, str]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        server_version = server_header

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                raw = json.dumps({"object": "list", "data": models_data}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.end_headers()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1"


def _write_barrel_reexport_repo(repo_dir: Path) -> Path:
    repo_dir.mkdir(parents=True, exist_ok=True)
    app_dir = repo_dir / "backend" / "app"
    pkg_dir = app_dir / "pkg"
    fe_dir = repo_dir / "frontend" / "src" / "app"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    fe_dir.mkdir(parents=True, exist_ok=True)

    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (app_dir / "models.py").write_text(
        "from sqlalchemy import Column, Integer, String\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n\n"
        "class MetricWindow(Base):\n"
        "    __tablename__ = 'metric_windows'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    label = Column(String, nullable=False)\n",
        encoding="utf-8",
    )
    (app_dir / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/windows')\n"
        "def list_windows(db):\n"
        "    return db.query(MetricWindow).all()\n",
        encoding="utf-8",
    )
    # Line 4 passively re-exports `unused_calc.metrics_calc`; line 7 is TYPE_CHECKING-only.
    (pkg_dir / "__init__.py").write_text(
        '"""Metrics helper barrel package."""\n'
        "from typing import TYPE_CHECKING\n\n"
        "from .unused_calc import metrics_calc\n\n"
        "if TYPE_CHECKING:\n"
        "    from .type_only_calc import TypeOnlyHelper\n\n"
        "__all__ = ['metrics_calc']\n",
        encoding="utf-8",
    )
    (pkg_dir / "unused_calc.py").write_text(
        "def metrics_calc(values: list[float]) -> float:\n"
        "    return sum(values) / max(1, len(values))\n",
        encoding="utf-8",
    )
    (pkg_dir / "type_only_calc.py").write_text(
        "class TypeOnlyHelper:\n"
        "    def compute_score(self) -> int:\n"
        "        return 1\n",
        encoding="utf-8",
    )
    (fe_dir / "page.tsx").write_text(
        "export default function WindowsPage() {\n"
        "  fetch('/api/v1/windows');\n"
        "  return <main>Windows</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test Bot",
            "-c",
            "user.email=bot@example.com",
            "commit",
            "-m",
            "init synthetic barrel repo",
        ],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    return repo_dir


def test_loaded_true_multi_model_seat_selection_beats_2b_helper_and_default_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify 14-model `/v1/models` with `loaded: true` selects 35B VLM over 2B helper & `:8081` fallback."""
    fourteen_models = [
        {"id": "LiquidAI/d1-2B-MLX-8bit", "loaded": True, "created": 1780000001},
        {"id": "mlx-community/PaddleOCR-VL-1.5-8bit", "loaded": True, "created": 1780000002},
        {"id": "mlx-community/whisper-large-v3-turbo", "loaded": True, "created": 1780000003},
        {"id": "onnx-community/silero-vad", "loaded": False, "created": 1780000004},
        {"id": "BAAI/bge-reranker-v2-m3", "loaded": False, "created": 1780000005},
        {"id": "BAAI/bge-small-en-v1.5-embed", "loaded": False, "created": 1780000006},
        {"id": "mlx-community/Qwen2.5-VL-7B-Instruct-4bit", "loaded": False, "created": 1780000007},
        {"id": "mlx-community/Llama-3.2-3B-Instruct-4bit", "loaded": False, "created": 1780000008},
        {"id": "mlx-community/Mistral-Small-24B-Instruct-4bit", "loaded": False, "created": 1780000009},
        {"id": "mlx-community/Qwen3.6-35B-A3B-4bit", "loaded": True, "created": 1782796936},
        {"id": "mlx-community/gemma-4-26b-a4b-it-4bit", "loaded": False, "created": 1780000011},
        {"id": "mlx-community/Qwen3.5-14B-4bit", "loaded": False, "created": 1780000012},
        {"id": "mlx-community/Pixtral-12B-4bit", "loaded": False, "created": 1780000013},
        {"id": "LiquidAI/LFM2-1.2B-router-4bit", "loaded": False, "created": 1780000014},
    ]
    assert _select_safe_seat_model(
        fourteen_models, None, server_header="mlx_vlm/0.6.17", prefer_vision=True
    ) == ("mlx-community/Qwen3.6-35B-A3B-4bit", "mlx-community/Qwen3.6-35B-A3B-4bit")
    assert _select_safe_seat_model(
        fourteen_models, None, server_header="mlx_vlm/0.6.17", prefer_vision=False
    ) == ("mlx-community/Qwen3.6-35B-A3B-4bit", "mlx-community/Qwen3.6-35B-A3B-4bit")

    # If every chat model explicitly reports `loaded: False` while OCR/ASR are `loaded: True`, return None.
    only_ocr_loaded = [
        {"id": "mlx-community/PaddleOCR-VL-1.5-8bit", "loaded": True, "created": 1},
        {"id": "mlx-community/Qwen3.6-35B-A3B-4bit", "loaded": False, "created": 2},
    ]
    assert _select_safe_seat_model(only_ocr_loaded, None, server_header="mlx_vlm/0.6.17") is None

    unannotated_mlx_fallback = [
        {"id": "mlx-community/Phi-4-mini-instruct-4bit", "owned_by": "organization_owner"},
        {
            "id": "/Users/dev/.cache/huggingface/hub/models--mlx-community--Qwen3-8B-4bit/snapshots/abc123",
            "owned_by": "organization_owner",
        },
    ]
    srv_8080, url_8080 = _start_models_server(fourteen_models, server_header="mlx_vlm/0.6.17")
    srv_8081, url_8081 = _start_models_server(unannotated_mlx_fallback, server_header="Python/3.12")
    try:
        for ordered_seats in ((url_8080, url_8081), (url_8081, url_8080)):
            monkeypatch.setattr(on_device_llm_service, "_default_local_seats", ordered_seats)
            st = probe_local_openai_engine(prefer_vision=False)
            assert st.state == "ready"
            assert st.base_url == url_8080
            assert st.model_id == "mlx-community/Qwen3.6-35B-A3B-4bit"
            assert st.supports_vision is True
    finally:
        srv_8080.shutdown()
        srv_8080.server_close()
        srv_8081.shutdown()
        srv_8081.server_close()


def test_f11_toolless_http_400_retry_and_apple_instructions_are_honest(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify F11 (#114): tool-less retry and `apple` omit camera-control claims and report `fallback_reason`."""
    from test_ask_mcp_tool_loop import _start_mock_openai_server

    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "f11-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_barrel_reexport_repo(tmp_path / "f11-repo")

    def _no_tools_responder(_call_idx: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if "tools" in body:
            return 400, {"error": {"message": "tools unsupported on this runner"}}
        return 200, {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Text-only fallback answer."},
                }
            ]
        }

    apple_captured_instructions: list[str] = []

    def _fake_apple_status() -> on_device_llm_service.OnDeviceEngineStatus:
        return on_device_llm_service.OnDeviceEngineStatus(
            engine="apple",
            label="Apple Intelligence",
            state="ready",
            model_id="apple-foundation-models-on-device",
        )

    def _fake_apple_ask(
        instructions: str,
        _prompt: str,
        *,
        plain_english: bool = False,
    ) -> tuple[str, list[str]]:
        assert isinstance(plain_english, bool)
        apple_captured_instructions.append(instructions)
        return "Apple text-only response.", []

    monkeypatch.setattr(on_device_llm_service, "check_apple_engine_status", _fake_apple_status)
    monkeypatch.setattr(on_device_llm_service, "run_apple_engine_ask", _fake_apple_ask)

    srv, base_url, recorded = _start_mock_openai_server(_no_tools_responder)
    try:
        app = create_app()
        with TestClient(app) as client:
            client.post(
                "/api/v1/targets",
                json={"slug": "f11-lab", "name": "F11 Lab", "repo_path": str(repo_dir)},
            )
            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain this investigation and available camera tools.",
                    "engine": "local",
                    "target_slug": "f11-lab",
                    "session_id": "sess-f11",
                    "client_id": "cli-f11",
                    "local_base_url": base_url,
                    "include_vision_snapshot": False,
                },
            )
            assert res.status_code == 200, res.text
            payload = res.json()
            assert len(recorded) == 2
            assert "tools" in recorded[0]
            assert "Yes, you CAN directly control" in recorded[0]["messages"][0]["content"]
            assert "tools" not in recorded[1]
            retry_sys = recorded[1]["messages"][0]["content"]
            assert "Yes, you CAN directly control" not in retry_sys
            assert "wythe_backend_manipulate" in retry_sys
            assert "unavailable on this text-only completion path" in retry_sys
            assert payload["fallback_reason"] == (
                "Local endpoint rejected OpenAI tools payload; "
                "answered in text-only mode without live MCP tool execution."
            )
            saved_inv = client.get("/api/v1/investigations/sess-f11").json()
            assert saved_inv["turns"][-1]["fallback_reason"] == payload["fallback_reason"]

            res_apple = client.post(
                "/api/v1/ask",
                json={
                    "question": "Can you move the camera?",
                    "engine": "apple",
                    "target_slug": "f11-lab",
                    "include_vision_snapshot": False,
                },
            )
            assert res_apple.status_code == 200, res_apple.text
            assert len(apple_captured_instructions) == 1
            assert "Yes, you CAN directly control" not in apple_captured_instructions[0]
            assert "NOT available on this text-only completion path" in apple_captured_instructions[0]
    finally:
        srv.shutdown()
        srv.server_close()


def test_plain_english_mode_anti_third_person_and_barrel_reexport_warning(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify plain-English prompt adaptation, 2nd-person rule, and `__init__.py` MANIP-003 re-export trap."""
    assert isolated_db_url.startswith("sqlite:")
    for phrase in (
        "Explain this in plain english",
        "What happens in laymens terms?",
        "In layman's terms, what does this do?",
        "ELI5 why this node is highlighted",
        "Give a non-technical summary in short",
        "tldr",
    ):
        assert _question_requests_plain_english(phrase) is True
    assert _question_requests_plain_english("Audit SQL read edges for metric_windows") is False

    for tool_q in (
        "Show me what breaks if unused_calc.py was deleted",
        "Who calls this service or what is it used by?",
        "Check blast radius and affected routes if we remove this",
    ):
        assert _question_requests_mcp_or_camera(tool_q) is True

    for tools_flag in (True, False):
        for plain_flag in (False, True):
            sys_txt = build_ask_instructions(tools_enabled=tools_flag, plain_english=plain_flag)
            assert "second person ('you')" in sys_txt
            assert "The user is..." in sys_txt
            if plain_flag:
                assert "Why / Architectural Role:" not in sys_txt
                assert "Safe Next Step:" not in sys_txt

    # Verify Apple helper formatting omits rigid headers when `plain_english=True`
    monkeypatch.setattr(apple_fm_service, "_ensure_apple_helper_binary", lambda: (tmp_path / "mock-bin", ""))
    monkeypatch.setattr(
        apple_fm_service,
        "_invoke_apple_helper",
        lambda _b, req: {
            "ok": True,
            "summary": "This file calculates average window metrics.",
            "rootCauseOrRole": "It is re-exported by pkg/__init__.py.",
            "safeNextStep": "Remove the re-export line before deleting the file."
            if req.get("plainEnglish")
            else "Check imports.",
            "referencedNodes": [],
        },
    )
    plain_ans, _ = apple_fm_service.run_apple_engine_ask("inst", "prompt", plain_english=True)
    assert "Why / Architectural Role:" not in plain_ans
    assert "Safe Next Step:" not in plain_ans

    repo_dir = _write_barrel_reexport_repo(tmp_path / "barrel-repo")
    app = create_app()
    with TestClient(app) as client:
        reg = client.post(
            "/api/v1/targets",
            json={"slug": "barrel-lab", "name": "Barrel Lab", "repo_path": str(repo_dir)},
        )
        assert reg.status_code in (200, 201), reg.text

    target = get_target_by_slug(db_session, "barrel-lab")
    assert target is not None
    report = get_or_run_cached_scan(db_session, target, strict_gate=True)

    unused_finding = next(
        f for f in report.findings if f.rule_code == "MANIP-003" and "unused_calc" in f.source_file
    )
    assert "backend/app/pkg/__init__.py:4" in unused_finding.detail
    assert "ImportError" in unused_finding.detail and "ModuleNotFoundError" in unused_finding.detail
    assert "backend/app/pkg/__init__.py:4" in unused_finding.remediation

    # TYPE_CHECKING-only import in `__init__.py:7` must NOT emit a false runtime ImportError warning
    type_only_finding = next(
        f for f in report.findings if f.rule_code == "MANIP-003" and "type_only_calc" in f.source_file
    )
    assert "pkg/__init__.py" not in type_only_finding.detail

    unused_node = next(n for n in report.nodes if "unused_calc" in n.source_file)
    assert unused_node.verification_note is not None
    assert "backend/app/pkg/__init__.py:4" in unused_node.verification_note

    cone = build_lineage_cone_slice(report, unused_node.id)
    assert "backend/app/pkg/__init__.py:4" in cone.markdown

    focus = explain_ui_focus(db_session, target_override="barrel-lab")
    focus = focus.model_copy(update={"active_findings": [unused_finding]})
    local_p, apple_p, _ = build_section_budgeted_ask_prompt(
        question="What happens if unused_calc.py was deleted, in laymens terms?",
        focus=focus,
        report=report,
        cone=cone,
        evidence_identity=focus.evidence_identity,
    )
    for rendered_prompt in (local_p, apple_p):
        assert "[warning | confirmed | ast_exact]" not in rendered_prompt
        assert "backend/app/pkg/__init__.py:4" in rendered_prompt
        assert "Never write 'The user is...'" in rendered_prompt


def test_mcp_cached_scan_reuse_and_sqlite_snapshot_hydration_with_staleness_guard(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `mcp_service` reuses `get_or_run_cached_scan` and hydrates persisted SQLite `ScanSnapshot`s."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "cache-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_barrel_reexport_repo(tmp_path / "cache-repo")

    app = create_app()
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/targets",
            json={"slug": "cache-lab", "name": "Cache Lab", "repo_path": str(repo_dir)},
        ).status_code in (200, 201)
        # Persist `ScanSnapshot` into SQLite via `/api/v1/scans/{slug}`
        assert client.post("/api/v1/scans/cache-lab?strict=true").status_code == 200

    # Evict in-memory `_SCAN_REUSE_CACHE` so next read must hydrate from SQLite `ScanSnapshot`!
    clear_scan_reuse_cache()

    scan_calls: list[str] = []
    orig_scan = investigation_service.run_target_scan

    def _counted_scan(*args: Any, **kwargs: Any) -> Any:
        scan_calls.append("run_target_scan")
        return orig_scan(*args, **kwargs)

    monkeypatch.setattr(investigation_service, "run_target_scan", _counted_scan)
    monkeypatch.setattr(mcp_service, "run_target_scan", _counted_scan)

    for idx, rpc_msg in enumerate(
        (
            {
                "jsonrpc": "2.0",
                "id": idx_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": tool_args},
            }
            for idx_id, (tool_name, tool_args) in enumerate(
                (
                    ("wythe_lineage_cone", {"target": "cache-lab", "query": "unused_calc"}),
                    ("wythe_findings", {"target": "cache-lab"}),
                    ("wythe_overview", {"target": "cache-lab"}),
                ),
                start=1,
            )
        ),
        start=1,
    ):
        rpc_res = mcp_service.dispatch_mcp_request(db_session, rpc_msg, slice_mode="full")
        assert "error" not in rpc_res, f"call {idx} failed: {rpc_res}"
        assert not rpc_res["result"].get("isError")

    res_read = mcp_service.dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "resources/read",
            "params": {"uri": "wythe://cache-lab/findings"},
        },
    )
    assert "error" not in res_read
    assert len(scan_calls) == 0

    # Mutate a source file -> persisted snapshot is now stale and must trigger a fresh scan!
    (repo_dir / "backend" / "app" / "pkg" / "unused_calc.py").write_text(
        "def metrics_calc(values: list[float]) -> float:\n    return sum(values)\n",
        encoding="utf-8",
    )
    target = get_target_by_slug(db_session, "cache-lab")
    assert target is not None
    get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert len(scan_calls) == 1

    # Persist fresh snapshot, clear in-memory cache, then mutate governance -> must rescan!
    orig_scan(db_session, target, strict_gate=True, persist_snapshot=True)
    clear_scan_reuse_cache()
    from app.schemas.atlas import RulePolicyUpdate

    update_rule_policy(
        db_session,
        "MANIP-003",
        RulePolicyUpdate(blocks_gate=True, updated_by="test-operator"),
    )
    updated_rep = get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert len(scan_calls) == 2
    assert any(f.rule_code == "MANIP-003" and f.blocks_gate for f in updated_rep.findings)


def test_default_model_fallback_used_only_when_no_pinned_or_loaded_seat_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `default_model` fallback works when alone and `auto` cascade ranks pinned vs unpinned seats."""
    from app.schemas.atlas import OnDeviceEngineStatus
    from app.services.on_device_llm_service import resolve_auto_backend_cascade

    unannotated_mlx_items = [
        {"id": "mlx-community/Phi-4-mini-instruct-4bit", "owned_by": "organization_owner"},
        {
            "id": "/Users/dev/.cache/huggingface/hub/models--mlx-community--Qwen3-8B-4bit/snapshots/abc123",
            "owned_by": "organization_owner",
        },
    ]
    srv_fb, url_fb = _start_models_server(unannotated_mlx_items, server_header="Python/3.12")
    try:
        monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (url_fb,))
        st_fb = probe_local_openai_engine(prefer_vision=False)
        assert st_fb.state == "ready"
        assert st_fb.model_id == "default_model"
        assert "Qwen3-8B-4bit" in (st_fb.note or "")
    finally:
        srv_fb.shutdown()
        srv_fb.server_close()

    apple_ready = OnDeviceEngineStatus(
        engine="apple",
        label="Apple Intelligence",
        state="ready",
        model_id="apple-foundation-models-on-device",
    )
    pinned_vlm = OnDeviceEngineStatus(
        engine="local",
        label="Local /v1",
        state="ready",
        base_url="http://127.0.0.1:8080/v1",
        model_id="mlx-community/Qwen3.6-35B-A3B-4bit",
        supports_vision=True,
    )
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=pinned_vlm,
        question="What does this module do in plain english?",
    ) == ["local", "apple"]
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=st_fb,
        question="What does this module do in plain english?",
    ) == ["apple", "local"]
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=st_fb,
        question="Show me what breaks if this file was deleted.",
    ) == ["local", "apple"]


def test_pep562_lazy_barrel_reexport_and_unregistered_mcp_target_path_scan(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Verify PEP 562 lazy `__init__.py` re-exports warn in `MANIP-003` and ad-hoc paths still scan."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_barrel_reexport_repo(tmp_path / "adhoc-pep562")
    lazy_pkg = repo_dir / "backend" / "app" / "lazy_pkg"
    lazy_pkg.mkdir(parents=True, exist_ok=True)
    (lazy_pkg / "__init__.py").write_text(
        "_LAZY_EXPORTS = {\n"
        "    'fatigue_eval': ('app.lazy_pkg.fatigue_eval', 'fatigue_eval'),\n"
        "}\n\n"
        "def __getattr__(name: str):\n"
        "    raise AttributeError(name)\n",
        encoding="utf-8",
    )
    (lazy_pkg / "fatigue_eval.py").write_text(
        "def fatigue_eval(hours: float) -> float:\n"
        "    return max(0.0, hours - 8.0)\n",
        encoding="utf-8",
    )

    rpc_res = mcp_service.dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 77,
            "method": "tools/call",
            "params": {"name": "wythe_findings", "arguments": {"target": str(repo_dir)}},
        },
        slice_mode="full",
    )
    assert "error" not in rpc_res
    text = rpc_res["result"]["content"][0]["text"]
    assert "MANIP-003" in text
    assert "fatigue_eval" in text
