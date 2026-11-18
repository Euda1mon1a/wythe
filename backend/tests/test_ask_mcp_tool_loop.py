"""Unit and integration tests for Wythe's in-app Ask MCP tool execution loop."""

from __future__ import annotations

import http.server
import json
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas.atlas import OnDeviceEngineStatus
from app.services import on_device_llm_service
from app.services.on_device_llm_service import (
    build_ask_openai_tools,
    resolve_auto_backend_cascade,
)
from app.services.viewport_service import get_viewport_state


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
            "user.name=Test Bot",
            "-c",
            "user.email=bot@example.com",
            "commit",
            "-m",
            "init synthetic repo",
        ],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    return repo_dir


def _start_mock_openai_server(
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
                        "data": [{"id": "mock-qwen-tool-model", "owned_by": "pinned"}],
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
            call_num = len(recorded_bodies)
            recorded_bodies.append(body)
            http_code, reply_obj = responder(call_num, body)
            encoded = json.dumps(reply_obj).encode("utf-8")
            self.send_response(http_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(encoded)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1", recorded_bodies


def test_openai_tool_schemas_and_auto_cascade_tool_awareness() -> None:
    """Verify all 9 core MCP tools map to OpenAI functions and `auto` prefers `local` for tool/camera prompts."""
    tools = build_ask_openai_tools()
    names = [item["function"]["name"] for item in tools]
    assert names == [
        "wythe_focus_camera",
        "wythe_camera_tour",
        "wythe_lineage_cone",
        "wythe_blast_radius",
        "wythe_findings",
        "wythe_what_is_this",
        "wythe_overview",
        "wythe_plugins",
        "wythe_investigation",
    ]
    for item in tools:
        assert item["type"] == "function"
        assert isinstance(item["function"]["description"], str) and item["function"]["description"]
        assert item["function"]["parameters"]["type"] == "object"

    apple_ready = OnDeviceEngineStatus(
        engine="apple",
        label="Apple Intelligence",
        state="ready",
        model_id="apple-foundation-models-on-device",
    )
    local_ready = OnDeviceEngineStatus(
        engine="local",
        label="Local /v1",
        state="ready",
        base_url="http://127.0.0.1:8084/v1",
        model_id="mock-qwen",
        supports_vision=False,
    )

    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=local_ready,
        question="Are you able to control the camera, and what MCP tools are exposed?",
    ) == ["local", "apple"]
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=local_ready,
        question="Use wythe_focus_camera to focus on t:batch_quota_policies with contention lens",
    ) == ["local", "apple"]
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=local_ready,
        question="Summarize the rule policy table.",
    ) == ["local", "apple"]

    local_default_unpinned = OnDeviceEngineStatus(
        engine="local",
        label="Local /v1",
        state="ready",
        base_url="http://127.0.0.1:8081/v1",
        model_id="default_model",
        supports_vision=False,
    )
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=local_default_unpinned,
        question="Summarize the rule policy table.",
    ) == ["apple", "local"]
    assert resolve_auto_backend_cascade(
        backend="auto",
        apple_status=apple_ready,
        local_status=local_default_unpinned,
        question="What happens if this module was deleted?",
    ) == ["local", "apple"]


def test_multiturn_focus_camera_publishes_scoped_viewport_command(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify multi-turn `wythe_focus_camera` publishes a `(target_slug, session_id)` ViewportCommand."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "demo-lab")

    def _responder(call_num: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if call_num == 0:
            assert "tools" in body
            return 200, {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "reasoning_content": None,
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_focus_1",
                                    "type": "function",
                                    "function": {
                                        "name": "wythe_focus_camera",
                                        "arguments": json.dumps(
                                            {
                                                "focus_node_ids": ["t:batch_quota_policies"],
                                                "lens": "contention",
                                            }
                                        ),
                                    },
                                }
                            ],
                        },
                    }
                ]
            }
        echoed_assistant = body["messages"][-2]
        tool_reply = body["messages"][-1]
        assert echoed_assistant["role"] == "assistant"
        assert echoed_assistant["content"] == ""
        assert "reasoning_content" not in echoed_assistant
        assert "index" not in echoed_assistant["tool_calls"][0]
        assert tool_reply["role"] == "tool"
        assert tool_reply["tool_call_id"] == "call_focus_1"
        assert len(tool_reply["content"]) <= 6000
        assert "t:batch_quota_policies" in tool_reply["content"]
        return 200, {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": (
                            "Focused the 3D camera on `t:batch_quota_policies` with the `contention` lens "
                            "(delivery_state=`accepted_by_service`)."
                        ),
                    },
                }
            ]
        }

    srv, base_url, recorded = _start_mock_openai_server(_responder)
    monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (base_url,))
    try:
        app = create_app()
        with TestClient(app) as client:
            reg = client.post(
                "/api/v1/targets",
                json={
                    "slug": "demo-lab",
                    "name": "Demo Lab",
                    "repo_path": str(repo_dir),
                    "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                },
            )
            assert reg.status_code in (200, 201), reg.text
            assert client.post("/api/v1/scans/demo-lab").status_code == 200

            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Use wythe_focus_camera to focus on t:batch_quota_policies with contention lens",
                    "engine": "local",
                    "target_slug": "demo-lab",
                    "session_id": "inv_tab_1",
                    "client_id": "cli_tab_1",
                    "local_base_url": base_url,
                    "include_vision_snapshot": False,
                },
            )
            assert res.status_code == 200, res.text
            payload = res.json()
            assert payload["executed_tools"] == ["wythe_focus_camera"]
            assert payload["session_id"] == "inv_tab_1"
            assert "t:batch_quota_policies" in payload["referenced_node_ids"]
            assert len(recorded) == 2

            vp = get_viewport_state("demo-lab", session_id="inv_tab_1")
            assert vp.latest is not None
            assert vp.latest.command.target_slug == "demo-lab"
            assert vp.latest.command.session_id == "inv_tab_1"
            assert vp.latest.command.focus_node_ids == ["t:batch_quota_policies"]
            assert vp.latest.command.lens == "contention"

            other_vp = get_viewport_state("demo-lab", session_id="inv_other_tab")
            assert other_vp.latest is None
    finally:
        srv.shutdown()
        srv.server_close()


def test_malformed_tool_arguments_and_unknown_tool_handled_gracefully(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify malformed JSON arguments and unknown tool names return structured errors without HTTP 500."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-err-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "err-lab")

    def _responder(call_num: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if call_num == 0:
            return 200, {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "call_bad_json",
                                    "type": "function",
                                    "function": {
                                        "name": "wythe_focus_camera",
                                        "arguments": "{unterminated_json",
                                    },
                                },
                                {
                                    "id": "call_unknown_fn",
                                    "type": "function",
                                    "function": {
                                        "name": "wythe_nonexistent_gadget",
                                        "arguments": "{}",
                                    },
                                },
                            ],
                        },
                    }
                ]
            }
        echoed_assistant = body["messages"][-3]
        bad_json_reply = json.loads(body["messages"][-2]["content"])
        unknown_reply = json.loads(body["messages"][-1]["content"])
        assert echoed_assistant["tool_calls"][0]["function"]["arguments"] == "{}"
        assert bad_json_reply["isError"] is True
        assert "Malformed JSON" in bad_json_reply["error"]
        assert unknown_reply["isError"] is True
        assert "Unknown Wythe MCP tool" in unknown_reply["error"]
        return 200, {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Recovered cleanly after structured tool validation errors.",
                    },
                }
            ]
        }

    srv, base_url, _ = _start_mock_openai_server(_responder)
    try:
        app = create_app()
        with TestClient(app) as client:
            client.post(
                "/api/v1/targets",
                json={"slug": "err-lab", "name": "Err Lab", "repo_path": str(repo_dir)},
            )
            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Test malformed tool arguments and unknown tool recovery.",
                    "engine": "local",
                    "target_slug": "err-lab",
                    "local_base_url": base_url,
                    "include_vision_snapshot": False,
                },
            )
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["executed_tools"] == []
            assert "Recovered cleanly" in body["answer_markdown"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_400_without_tool_support_and_max_rounds_synthesis_fallback(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify HTTP 400 fallback when server rejects `tools` and `max_rounds` synthesis fallback."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "wythe-fallback-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_repo(tmp_path / "fb-lab")

    def _no_tools_responder(_call_num: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if "tools" in body:
            return 400, {"error": {"message": "tools parameter is not supported by this server"}}
        return 200, {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Answered cleanly via plain messages fallback (`t:batch_quota_policies`).",
                    },
                }
            ]
        }

    def _looping_responder(_call_num: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if "tools" in body:
            return 200, {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": f"loop_{_call_num}",
                                    "type": "function",
                                    "function": {"name": "wythe_plugins", "arguments": "{}"},
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
                        "content": "Synthesized final summary after max_rounds tool budget.",
                    },
                }
            ]
        }

    srv_400, url_400, rec_400 = _start_mock_openai_server(_no_tools_responder)
    srv_loop, url_loop, rec_loop = _start_mock_openai_server(_looping_responder)
    try:
        app = create_app()
        with TestClient(app) as client:
            client.post(
                "/api/v1/targets",
                json={"slug": "fb-lab", "name": "FB Lab", "repo_path": str(repo_dir)},
            )
            res_400 = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain batch_quota_policies on a minimal server.",
                    "engine": "local",
                    "target_slug": "fb-lab",
                    "local_base_url": url_400,
                    "include_vision_snapshot": False,
                },
            )
            assert res_400.status_code == 200, res_400.text
            assert "plain messages fallback" in res_400.json()["answer_markdown"]
            assert len(rec_400) == 2
            assert "tools" in rec_400[0]
            assert "tools" not in rec_400[1]

            res_loop = client.post(
                "/api/v1/ask",
                json={
                    "question": "List plugins repeatedly until synthesis.",
                    "engine": "local",
                    "target_slug": "fb-lab",
                    "local_base_url": url_loop,
                    "include_vision_snapshot": False,
                },
            )
            assert res_loop.status_code == 200, res_loop.text
            loop_json = res_loop.json()
            assert loop_json["executed_tools"] == ["wythe_plugins"]
            assert "Synthesized final summary" in loop_json["answer_markdown"]
            assert len(rec_loop) == 4
            assert all("tools" in req for req in rec_loop[:3])
            assert "tools" not in rec_loop[3]
    finally:
        srv_400.shutdown()
        srv_400.server_close()
        srv_loop.shutdown()
        srv_loop.server_close()
