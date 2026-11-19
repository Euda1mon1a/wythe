"""CI Parity Gate & regression suite for Wythe's 4 Human-Agent Shared Investigation Standards."""

from __future__ import annotations

import http.server
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.db.session import get_session_factory
from app.main import create_app
from app.schemas.atlas import (
    TourKeyframe,
    UiFocusExplainRead,
    UiFocusStatePayload,
    ViewportCommand,
)
from app.services import on_device_llm_service
from app.services.mcp_service import (
    MCP_TOOLS,
    compute_smart_dense_salience_mode,
    dispatch_mcp_request,
)
from app.services.on_device_llm_service import build_ask_openai_tools
from app.services.viewport_service import get_viewport_state

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every interactive 3D viewport / filter / selection control in `frontend/src/app/page.tsx`
# mapped to `(ViewportCommand field, wythe_focus_camera arg, UiFocusStatePayload field | None)`.
GUI_VIEWPORT_PARITY_MAP: dict[str, tuple[str, str, str | None]] = {
    "activeSlug": ("target_slug", "target", "active_slug"),
    "activeTab": ("active_tab", "active_tab", "active_tab"),
    "selectedNodeId": ("selected_node_id", "selected_node_id", "selected_node_id"),
    "selectedFindingId": ("finding_id", "finding_id", "selected_finding_id"),
    "selectedEdgeId": ("selected_edge_id", "selected_edge_id", "selected_edge_id"),
    "tierFilter": ("tier_filter", "tier_filter", "tier_filter"),
    "subkindFilter": ("subkind_filter", "subkind_filter", "subkind_filter"),
    "edgeFilter": ("edge_filter", "edge_filter", "edge_filter"),
    "onlyFlagged": ("only_flagged", "only_flagged", "only_flagged"),
    "isolateCone": ("isolate_cone", "isolate_cone", "isolate_cone"),
    "connectedOnly": ("connected_only", "connected_only", "connected_only"),
    "neighborhoodHops": ("neighborhood_hops", "neighborhood_hops", "neighborhood_hops"),
    "searchQuery": ("search_query", "search_query", "search_query"),
    "sceneLens": ("lens", "lens", "lens"),
    "sceneLayout": ("layout_mode", "layout_mode", "layout_mode"),
    "blastMode": ("blast_mode", "blast_mode", "blast_mode"),
    "diffBaseRef": ("diff_base_ref", "diff_base_ref", "diff_base_ref"),
    "workingSetIds": ("focus_node_ids", "focus_node_ids", "working_set_only"),
    "workingSetActive": ("working_set_only", "working_set_only", "working_set_only"),
    "compactVisible": ("compact_visible", "compact_visible", "compact_visible"),
    "flatten2D": ("flatten_2d", "flatten_2d", "flatten_2d"),
    "groupBy": ("group_by", "group_by", "group_by"),
    "zWytheSlice": ("z_wythe_slice", "z_wythe_slice", "z_wythe_slice"),
    "requestedZoomStratum": ("zoom_stratum", "zoom_stratum", "zoom_stratum"),
    "askDrawerOpen": ("open_drawer", "open_drawer", None),
}

# Non-viewport transient UI modal/form/chrome states in `page.tsx`.
TRANSIENT_UI_CHROME_STATES: frozenset[str] = frozenset(
    {
        "showAddTarget",
        "newSlug",
        "newName",
        "newPath",
        "newProfileSlug",
        "newBackendSubdir",
        "newFrontendSubdir",
        "detectSummary",
        "copiedBriefLabel",
        "paletteOpen",
        "paletteInitialQuery",
        "isFullscreen3D",
        "stepRequest",
        "resetCameraRequest",
        "quickToast",
        "snapBaseId",
        "activeTraceChain",
        "whatsThisRequest",
        "whatsThisOpen",
        "whatsThisSnapshotUrl",
        "whatsThisExplanation",
        "whatsThisImageCopied",
        "collapsedGroups",
        "pinnedPositions",
        "visibleSceneNodeIds",
        "savedViews",
        "selectedSavedViewId",
        "savedViewNotice",
        "askPrefillQuestion",
        "liveViewportDigest",
        "hoverFocusMeta",
        "tabClientId",
        "sessionScope",
        "scopeEpoch",
        "agentCamState",
        "investigationSession",
        "priorSessions",
        "revisionComparison",
        "lastViewportReceipt",
        "agentCameraRequest",
        "coldPermalinkActive",
    }
)


def _write_synthetic_repo(repo_dir: Path) -> Path:
    repo_dir.mkdir(parents=True, exist_ok=True)
    backend_app = repo_dir / "backend" / "app"
    frontend_src = repo_dir / "frontend" / "src" / "app"
    backend_app.mkdir(parents=True, exist_ok=True)
    frontend_src.mkdir(parents=True, exist_ok=True)

    (backend_app / "models.py").write_text(
        "from sqlalchemy import Column, Integer, String\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n\n"
        "class BatchQuotaPolicy(Base):\n"
        "    __tablename__ = 'batch_quota_policies'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    max_parallel_jobs = Column(Integer, nullable=False)\n"
        "    scope_name = Column(String, nullable=False)\n",
        encoding="utf-8",
    )
    (backend_app / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/quotas')\n"
        "def list_quotas(db):\n"
        "    return db.query(BatchQuotaPolicy).all()\n",
        encoding="utf-8",
    )
    (frontend_src / "page.tsx").write_text(
        "export default function QuotaPage() {\n"
        "  fetch('/api/v1/quotas');\n"
        "  return <main>Batch Quotas</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Euda1mon1a",
            "-c",
            "user.email=214782221+Euda1mon1a@users.noreply.github.com",
            "commit",
            "-m",
            "Initialize synthetic parity test repo",
        ],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    return repo_dir


def test_standing_docs_codify_four_human_agent_standards() -> None:
    """Verify root AGENTS.md and CONTRIBUTING.md codify all 4 standing standards."""
    agents_md = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    contributing_md = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

    for doc_name, text in (("AGENTS.md", agents_md), ("CONTRIBUTING.md", contributing_md)):
        assert "Standard 1:" in text and "1:1 Human" in text, doc_name
        assert "Standard 2:" in text and ">120" in text, doc_name
        assert "Standard 3:" in text and "Confabulated" in text, doc_name
        assert "Standard 4:" in text and "wythe reply" in text and "record_turn" in text, doc_name
        assert "test_human_agent_parity_standard.py" in text, doc_name


def test_gui_viewport_controls_have_1_to_1_schema_tool_and_readback_parity() -> None:
    """CI Parity Gate: fail automatically if any GUI viewport control lacks 1:1 agent parity."""
    page_tsx = (REPO_ROOT / "frontend" / "src" / "app" / "page.tsx").read_text(encoding="utf-8")
    state_vars = set(
        re.findall(r"const\s+\[([a-zA-Z0-9_]+),\s*set[A-Z][a-zA-Z0-9_]*\]\s*=\s*\n?\s*useState", page_tsx)
    )
    assert state_vars, "Expected React useState declarations in frontend/src/app/page.tsx"

    unclassified = state_vars - set(GUI_VIEWPORT_PARITY_MAP) - TRANSIENT_UI_CHROME_STATES
    assert not unclassified, (
        f"Unclassified React state(s) in page.tsx: {sorted(unclassified)}. "
        "Every new 3D viewport filter/control MUST be wired 1:1 into ViewportCommand, "
        "wythe_focus_camera, and UiFocusStatePayload, then registered in GUI_VIEWPORT_PARITY_MAP."
    )

    mcp_focus = next(t for t in MCP_TOOLS if t["name"] == "wythe_focus_camera")
    mcp_props = set(mcp_focus["inputSchema"]["properties"])
    openai_focus = next(
        t for t in build_ask_openai_tools() if t["function"]["name"] == "wythe_focus_camera"
    )
    openai_props = set(openai_focus["function"]["parameters"]["properties"])
    assert mcp_props == openai_props

    for req_special in ("flagged_only", "reset_filters"):
        assert req_special in mcp_props, f"Missing {req_special} on wythe_focus_camera"
    assert "refresh_session_id" in ViewportCommand.model_fields
    assert "reset_filters" in ViewportCommand.model_fields
    assert "reset_filters" in TourKeyframe.model_fields

    for gui_state, (cmd_field, tool_arg, focus_field) in GUI_VIEWPORT_PARITY_MAP.items():
        assert gui_state in state_vars, f"Missing {gui_state} in page.tsx"
        assert cmd_field in ViewportCommand.model_fields, (
            f"GUI control {gui_state} missing ViewportCommand.{cmd_field}"
        )
        assert tool_arg in mcp_props, (
            f"GUI control {gui_state} missing wythe_focus_camera.{tool_arg}"
        )
        if focus_field is not None:
            assert focus_field in UiFocusStatePayload.model_fields, (
                f"GUI control {gui_state} missing UiFocusStatePayload.{focus_field}"
            )
            assert focus_field in UiFocusExplainRead.model_fields, (
                f"GUI control {gui_state} missing UiFocusExplainRead.{focus_field}"
            )

    # Target switch (`switchTargetCleanly`) must clear target-scoped filters so switching from a
    # `FlaggedOnly` or cone-isolated target never strands a clean target on a 0-node canvas.
    switch_match = re.search(
        r"const\s+switchTargetCleanly\s*=\s*useCallback\(([\s\S]*?)\n\s*\},\s*\n\s*\[bumpScopeEpoch\]",
        page_tsx,
    )
    assert switch_match is not None, "Expected switchTargetCleanly in page.tsx"
    switch_body = switch_match.group(1)
    for expected_reset in (
        "setOnlyFlagged(false)",
        "setIsolateCone(false)",
        "setWorkingSetActive(false)",
        "setCompactVisible(false)",
        "setConnectedOnly(false)",
        "setNeighborhoodHops(0)",
        "setTierFilter('all')",
        "setSubkindFilter('all')",
        "setEdgeFilter('all')",
        "setSearchQuery('')",
        "setBlastMode('off')",
    ):
        assert expected_reset in switch_body, f"switchTargetCleanly missing {expected_reset}"


def test_viewport_command_flagged_only_alias_preserves_extra_forbid_and_salience(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify flagged_only alias, extra='forbid', dense-graph salience, and 1:1 ui-focus readback."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "demo-lab")

    cmd_alias = ViewportCommand.model_validate({"target_slug": "demo-lab", "flagged_only": True})
    assert cmd_alias.only_flagged is True
    kf_alias = TourKeyframe.model_validate({"step_index": 0, "title": "Flagged", "flagged_only": True})
    assert kf_alias.only_flagged is True

    with pytest.raises(ValidationError):
        ViewportCommand.model_validate({"target_slug": "demo-lab", "bogus_unknown_filter": True})

    cmd_one = ViewportCommand(target_slug="wythe", focus_node_ids=["t:a"])
    cmd_many = ViewportCommand(target_slug="wythe", focus_node_ids=["t:a", "m:b", "d:c"])
    cmd_explicit = ViewportCommand(target_slug="wythe", focus_node_ids=["t:a"], only_flagged=True)
    cmd_reset = ViewportCommand(target_slug="wythe", reset_filters=True)
    assert compute_smart_dense_salience_mode(cmd_one, 450) == "auto_isolate_cone"
    assert compute_smart_dense_salience_mode(cmd_many, 450) == "auto_working_set_compact"
    assert compute_smart_dense_salience_mode(cmd_explicit, 450) == "explicit"
    assert compute_smart_dense_salience_mode(cmd_reset, 450) == "reset_to_overview"
    assert compute_smart_dense_salience_mode(cmd_one, 80) == "explicit"

    app = create_app()
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/targets",
            json={
                "slug": "demo-lab",
                "name": "Demo Lab",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
            },
        ).status_code in (200, 201)
        assert client.post("/api/v1/scans/demo-lab").status_code == 200

        sync_res = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "demo-lab",
                "session_id": "inv_parity_1",
                "client_id": "cli_parity_1",
                "actor": "human",
                "active_tab": "3d",
                "selected_node_id": "t:batch_quota_policies",
                "lens": "contention",
                "layout_mode": "subkind",
                "tier_filter": "truth",
                "subkind_filter": "db_table",
                "edge_filter": "reads_truth",
                "only_flagged": True,
                "isolate_cone": True,
                "connected_only": True,
                "neighborhood_hops": 2,
                "search_query": "quota",
                "working_set_only": True,
                "compact_visible": True,
                "flatten_2d": True,
                "group_by": "cluster",
                "z_wythe_slice": "z1_built",
                "zoom_stratum": 2,
                "visible_node_count": 3,
                "in_frustum_count": 2,
            },
        )
        assert sync_res.status_code == 200, sync_res.text

        read_res = client.get(
            "/api/v1/ui-focus",
            params={"target_slug": "demo-lab", "session_id": "inv_parity_1"},
        )
        assert read_res.status_code == 200, read_res.text
        body = read_res.json()
        assert body["lens"] == "contention"
        assert body["layout_mode"] == "subkind"
        assert body["tier_filter"] == "truth"
        assert body["subkind_filter"] == "db_table"
        assert body["edge_filter"] == "reads_truth"
        assert body["only_flagged"] is True
        assert body["isolate_cone"] is True
        assert body["connected_only"] is True
        assert body["neighborhood_hops"] == 2
        assert body["search_query"] == "quota"
        assert body["working_set_only"] is True
        assert body["compact_visible"] is True
        assert body["flatten_2d"] is True
        assert body["group_by"] == "cluster"
        assert body["z_wythe_slice"] == "z1_built"
        assert body["zoom_stratum"] == 2
        assert body["visible_node_count"] == 3
        assert body["in_frustum_count"] == 2


def _start_scripted_openai_server(
    responder: Callable[[int, dict[str, Any]], tuple[int, dict[str, Any]]],
) -> tuple[http.server.ThreadingHTTPServer, str, list[dict[str, Any]]]:
    recorded_bodies: list[dict[str, Any]] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                out = json.dumps(
                    {
                        "object": "list",
                        "data": [{"id": "mock-parity-model", "owned_by": "pinned"}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            idx = len(recorded_bodies)
            recorded_bodies.append(body)
            code, payload = responder(idx, body)
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1", recorded_bodies


def test_anti_confabulation_guard_corrective_round_and_truth_banner(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Standard 3: corrective VERIFICATION GATE retry + hard post-condition truth banner."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "demo-lab")

    # Scenario A: Round 0 confabulates without calling a tool -> Round 1 corrective gate executes tool
    def _recovering_responder(call_num: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if call_num == 0:
            return 200, {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": "I have just switched the camera to the contention lens and filtered for FlaggedOnly.",
                        },
                    }
                ]
            }
        if call_num == 1:
            gate_msg = body["messages"][-1]["content"]
            assert "VERIFICATION GATE:" in gate_msg
            return 200, {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_fix_1",
                                    "type": "function",
                                    "function": {
                                        "name": "wythe_focus_camera",
                                        "arguments": json.dumps(
                                            {
                                                "focus_node_ids": ["t:batch_quota_policies"],
                                                "lens": "contention",
                                                "flagged_only": True,
                                                "isolate_cone": True,
                                            }
                                        ),
                                    },
                                }
                            ],
                        },
                    }
                ]
            }
        return 200, {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Executed `wythe_focus_camera` on `t:batch_quota_policies` (`lens=contention`, `only_flagged=True`, `isolate_cone=True`).",
                    },
                }
            ]
        }

    # Scenario B: Model refuses tool execution on BOTH rounds while claiming viewport mutation
    def _stubborn_responder(call_num: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if call_num == 1:
            assert "VERIFICATION GATE:" in body["messages"][-1]["content"]
        return 200, {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "I have switched the camera to the contention lens and applied FlaggedOnly.",
                    },
                }
            ]
        }

    srv_a, url_a, calls_a = _start_scripted_openai_server(_recovering_responder)
    srv_b, url_b, calls_b = _start_scripted_openai_server(_stubborn_responder)
    try:
        app = create_app()
        with TestClient(app) as client:
            assert client.post(
                "/api/v1/targets",
                json={
                    "slug": "demo-lab",
                    "name": "Demo Lab",
                    "repo_path": str(repo_dir),
                    "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                },
            ).status_code in (200, 201)
            assert client.post("/api/v1/scans/demo-lab").status_code == 200

            monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (url_a,))
            res_a = client.post(
                "/api/v1/ask",
                json={
                    "question": "Switch the lens to contention, filter to FlaggedOnly=true, and isolate the cone on t:batch_quota_policies",
                    "engine": "local",
                    "target_slug": "demo-lab",
                    "session_id": "inv_guard_a",
                    "local_base_url": url_a,
                    "include_vision_snapshot": False,
                },
            )
            assert res_a.status_code == 200, res_a.text
            body_a = res_a.json()
            assert body_a["executed_tools"] == ["wythe_focus_camera"]
            assert "Viewport Notice:" not in body_a["answer_markdown"]
            assert len(calls_a) == 3

            vp_a = get_viewport_state("demo-lab", session_id="inv_guard_a")
            assert vp_a.latest is not None
            assert vp_a.latest.command.lens == "contention"
            assert vp_a.latest.command.only_flagged is True
            assert vp_a.latest.command.isolate_cone is True

            monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (url_b,))
            res_b = client.post(
                "/api/v1/ask",
                json={
                    "question": "Switch the lens to contention and filter to FlaggedOnly",
                    "engine": "local",
                    "target_slug": "demo-lab",
                    "session_id": "inv_guard_b",
                    "local_base_url": url_b,
                    "include_vision_snapshot": False,
                },
            )
            assert res_b.status_code == 200, res_b.text
            body_b = res_b.json()
            assert body_b["executed_tools"] == []
            assert len(calls_b) == 2
            assert body_b["answer_markdown"].startswith(
                "> **Viewport Notice:** No camera or filter command was executed on this turn; your 3D view remains unchanged.\n\n"
            )
    finally:
        srv_a.shutdown()
        srv_b.shutdown()


def test_mcp_record_turn_and_wythe_reply_cli_stdin_pipe(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Standard 4: wythe_investigation(action='record_turn') + `wythe reply` CLI stdin pipe."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "demo-lab")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])

    app = create_app()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    server_url = f"http://127.0.0.1:{port}"

    try:
        for _ in range(80):
            try:
                probe = httpx.get(f"{server_url}/api/v1/targets", timeout=0.5, trust_env=False)
                if probe.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)

        with httpx.Client(base_url=server_url, timeout=10.0, trust_env=False) as http_client:
            assert http_client.post(
                "/api/v1/targets",
                json={
                    "slug": "demo-lab",
                    "name": "Demo Lab",
                    "repo_path": str(repo_dir),
                    "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                },
            ).status_code in (200, 201)
            assert http_client.post("/api/v1/scans/demo-lab").status_code == 200

            # 1) MCP `wythe_investigation(action="record_turn")`
            with get_session_factory()() as db_session:
                rpc_res = dispatch_mcp_request(
                    db_session,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "wythe_investigation",
                            "arguments": {
                                "action": "record_turn",
                                "target": "demo-lab",
                                "session_id": "inv_mcp_pipe",
                                "question": "MCP Frontier Audit",
                                "answer_markdown": (
                                    "Verified `t:batch_quota_policies` at `backend/app/models.py:5`."
                                ),
                                "model_id": "frontier-mcp-agent",
                            },
                        },
                    },
                )
            assert rpc_res is not None
            mcp_result = rpc_res["result"]
            assert not mcp_result.get("isError"), mcp_result
            mcp_text = mcp_result["content"][0]["text"]
            json_match = re.search(r"```json\s*(\{.*?\})\s*```", mcp_text, re.DOTALL)
            assert json_match is not None, mcp_text
            mcp_payload = json.loads(json_match.group(1))
            assert mcp_payload["session_id"] == "inv_mcp_pipe"
            assert mcp_payload["validated_ref_count"] >= 1
            vp_mcp = get_viewport_state("demo-lab", session_id="inv_mcp_pipe")
            assert vp_mcp.latest is not None
            assert vp_mcp.latest.command.refresh_session_id == "inv_mcp_pipe"
            assert vp_mcp.latest.command.open_drawer is True

            # 2) Sync `/api/v1/ui-focus` so `wythe reply` auto-discovers `(demo-lab, inv_cli_pipe)`
            assert http_client.post(
                "/api/v1/ui-focus",
                json={
                    "active_slug": "demo-lab",
                    "session_id": "inv_cli_pipe",
                    "client_id": "cli_browser_1",
                    "actor": "human",
                    "active_tab": "3d",
                },
            ).status_code == 200

            env = {
                **os.environ,
                "PYTHONPATH": str(REPO_ROOT / "backend"),
                "WYTHE_STATE_DIR": str(state_dir),
            }
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "app.cli",
                    "reply",
                    "--server",
                    server_url,
                    "--question",
                    "Terminal Frontier Pipe",
                ],
                input="Frontier analysis of `t:batch_quota_policies` at `backend/app/models.py:5`.",
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
            receipt = json.loads(proc.stdout.strip())
            assert receipt["session_id"] == "inv_cli_pipe"
            assert receipt["turn_id"]
            assert receipt["validated_ref_count"] >= 1

            inv_read = http_client.get("/api/v1/investigations/inv_cli_pipe")
            assert inv_read.status_code == 200
            turns = inv_read.json()["turns"]
            assert len(turns) == 1
            assert turns[0]["actor"] == "agent"
            assert "t:batch_quota_policies" in turns[0]["answer_markdown"]

            vp_cli = http_client.get(
                "/api/v1/viewport/state",
                params={"target_slug": "demo-lab", "session_id": "inv_cli_pipe"},
            ).json()
            assert vp_cli["latest"]["command"]["refresh_session_id"] == "inv_cli_pipe"
            assert vp_cli["latest"]["command"]["open_drawer"] is True
            assert vp_cli["latest"]["command"]["focus_node_ids"] == []
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def test_wythe_reply_with_viewport_steering_flags(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `wythe reply` with `--focus`, `--lens`, `--only-flagged`, `--isolate-cone` steers the viewport."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "demo-lab")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])

    app = create_app()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    server_url = f"http://127.0.0.1:{port}"

    try:
        for _ in range(80):
            try:
                if httpx.get(f"{server_url}/api/v1/targets", timeout=0.5, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)

        with httpx.Client(base_url=server_url, timeout=10.0, trust_env=False) as http_client:
            assert http_client.post(
                "/api/v1/targets",
                json={
                    "slug": "demo-lab",
                    "name": "Demo Lab",
                    "repo_path": str(repo_dir),
                    "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                },
            ).status_code in (200, 201)
            assert http_client.post("/api/v1/scans/demo-lab").status_code == 200

            env = {
                **os.environ,
                "PYTHONPATH": str(REPO_ROOT / "backend"),
                "WYTHE_STATE_DIR": str(state_dir),
            }
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "app.cli",
                    "reply",
                    "--server",
                    server_url,
                    "--target",
                    "demo-lab",
                    "--session",
                    "inv_steered_1",
                    "--question",
                    "Steer and Reply",
                    "--focus",
                    "t:batch_quota_policies",
                    "--lens",
                    "contention",
                    "--only-flagged",
                    "--isolate-cone",
                ],
                input="Focused `t:batch_quota_policies`.",
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            vp = http_client.get(
                "/api/v1/viewport/state",
                params={"target_slug": "demo-lab", "session_id": "inv_steered_1"},
            ).json()
            latest_cmd = vp["latest"]["command"]
            assert latest_cmd["focus_node_ids"] == ["t:batch_quota_policies"]
            assert latest_cmd["lens"] == "contention"
            assert latest_cmd["only_flagged"] is True
            assert latest_cmd["isolate_cone"] is True
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def test_backend_permalink_omits_defaults_and_encodes_parity_filters() -> None:
    """Verify `build_viewport_permalink` leaves default hashes intact and appends parity filters."""
    from app.services.viewport_service import build_viewport_permalink

    default_link = build_viewport_permalink(ViewportCommand(target_slug="wythe"), base_origin="")
    assert default_link == "/#target=wythe&preset=iso_overview&zoom=1"

    parity_link = build_viewport_permalink(
        ViewportCommand(
            target_slug="wythe",
            focus_node_ids=["t:batch_quota_policies"],
            lens="contention",
            only_flagged=True,
            isolate_cone=True,
            working_set_only=True,
            compact_visible=True,
        ),
        base_origin="",
    )
    assert "only_flagged=1" in parity_link
    assert "isolate_cone=1" in parity_link
    assert "working_set=1" in parity_link
    assert "compact=1" in parity_link


def test_vlm_named_text_only_server_404_strips_image_before_tools(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify HTTP 404 on multimodal list content strips image first while preserving `tools`."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "demo-lab")
    tiny_webp = "data:image/webp;base64,UklGRhIAAABXRUJQVlA4TAYAAAAvAAAAAAfQ//73v/+BiOh/AAA="

    recorded_bodies: list[dict[str, Any]] = []

    class _MlxTextOnlyHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                out = json.dumps(
                    {
                        "object": "list",
                        "data": [
                            {
                                "id": "mlx-community/Qwen3.6-35B-A3B-4bit",
                                "owned_by": "pinned",
                            }
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            recorded_bodies.append(body)
            last_msg = body["messages"][-1]
            if isinstance(last_msg.get("content"), list):
                err = json.dumps({"error": "Only 'text' content type is supported."}).encode("utf-8")
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(err)
                return
            assert "tools" in body, "Expected `tools` preserved after stripping unsupported image_url"
            if last_msg.get("role") == "user":
                payload = {
                    "choices": [
                        {
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_mlx_1",
                                        "type": "function",
                                        "function": {
                                            "name": "wythe_focus_camera",
                                            "arguments": json.dumps(
                                                {
                                                    "focus_node_ids": ["t:batch_quota_policies"],
                                                    "lens": "contention",
                                                    "only_flagged": True,
                                                    "isolate_cone": True,
                                                }
                                            ),
                                        },
                                    }
                                ],
                            },
                        }
                    ]
                }
            else:
                payload = {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": "Applied `contention` lens, `only_flagged=True`, and `isolate_cone=True` on `t:batch_quota_policies`.",
                            },
                        }
                    ]
                }
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MlxTextOnlyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (base_url,))

    try:
        app = create_app()
        with TestClient(app) as client:
            assert client.post(
                "/api/v1/targets",
                json={
                    "slug": "demo-lab",
                    "name": "Demo Lab",
                    "repo_path": str(repo_dir),
                    "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                },
            ).status_code in (200, 201)
            assert client.post("/api/v1/scans/demo-lab").status_code == 200

            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Switch the lens to contention, filter to FlaggedOnly=true, and isolate the cone on `t:batch_quota_policies`",
                    "engine": "auto",
                    "target_slug": "demo-lab",
                    "session_id": "inv_mlx_vlm_404",
                    "local_base_url": base_url,
                    "include_vision_snapshot": True,
                    "snapshot_data_url": tiny_webp,
                },
            )
            assert res.status_code == 200, res.text
            ans = res.json()
            assert ans["engine_used"] == "local"
            assert ans["used_vision_snapshot"] is False
            assert ans["image_supplied"] is True
            assert ans["executed_tools"] == ["wythe_focus_camera"]
            assert len(recorded_bodies) == 3
            assert isinstance(recorded_bodies[0]["messages"][-1]["content"], list)
            assert isinstance(recorded_bodies[1]["messages"][-1]["content"], str)
            assert "tools" in recorded_bodies[1]

            vp = get_viewport_state("demo-lab", session_id="inv_mlx_vlm_404")
            assert vp.latest is not None
            assert vp.latest.command.lens == "contention"
            assert vp.latest.command.only_flagged is True
            assert vp.latest.command.isolate_cone is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_multi_session_target_switch_updates_active_slug_for_wythe_reply(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify target switching back to a >=2-session target updates active_slug for `wythe reply`."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_a = _write_synthetic_repo(tmp_path / "demo-lab")
    repo_b = _write_synthetic_repo(tmp_path / "second-lab")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])

    app = create_app()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    server_url = f"http://127.0.0.1:{port}"

    try:
        for _ in range(80):
            try:
                if httpx.get(f"{server_url}/api/v1/targets", timeout=0.5, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)

        with httpx.Client(base_url=server_url, timeout=10.0, trust_env=False) as http_client:
            for slug, rdir in (("demo-lab", repo_a), ("second-lab", repo_b)):
                assert http_client.post(
                    "/api/v1/targets",
                    json={
                        "slug": slug,
                        "name": slug,
                        "repo_path": str(rdir),
                        "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                    },
                ).status_code in (200, 201)
                assert http_client.post(f"/api/v1/scans/{slug}").status_code == 200

            # Create 2 sessions on `demo-lab`, switch to `second-lab`, then switch back to `demo-lab` (`inv_lab_b`)
            assert http_client.post(
                "/api/v1/ui-focus",
                json={"active_slug": "demo-lab", "session_id": "inv_lab_a", "selected_node_id": "t:batch_quota_policies"},
            ).status_code == 200
            time.sleep(0.02)
            assert http_client.post(
                "/api/v1/ui-focus",
                json={"active_slug": "second-lab", "session_id": "inv_second_1"},
            ).status_code == 200
            time.sleep(0.02)
            assert http_client.post(
                "/api/v1/ui-focus",
                json={"active_slug": "demo-lab", "session_id": "inv_lab_b"},
            ).status_code == 200

            unscoped = http_client.get("/api/v1/ui-focus").json()
            assert unscoped["active_slug"] == "demo-lab"
            assert set(unscoped["ambiguous_session_ids"]) == {"inv_lab_a", "inv_lab_b"}
            assert unscoped["focused_node"] is None

            env = {
                **os.environ,
                "PYTHONPATH": str(REPO_ROOT / "backend"),
                "WYTHE_STATE_DIR": str(state_dir),
            }
            proc = subprocess.run(
                [sys.executable, "-m", "app.cli", "reply", "--server", server_url, "--question", "Switch Back Pipe"],
                input="Piped back into `t:batch_quota_policies`.",
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            receipt = json.loads(proc.stdout.strip())
            assert receipt["target_slug"] == "demo-lab"
            assert receipt["session_id"] == "inv_lab_b"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
