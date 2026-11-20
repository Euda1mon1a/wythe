"""Regression suite for P2 Ask MCP confinement/authorship (#112/#113) & viewport bounds (#106/#107)."""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services import on_device_llm_service
from app.services.viewport_service import get_viewport_state, list_viewport_receipts


def _write_synthetic_policy_repo(repo_dir: Path, *, marker: str = "alpha") -> Path:
    (repo_dir / "backend" / "app").mkdir(parents=True, exist_ok=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True, exist_ok=True)
    (repo_dir / "backend" / "schema.sql").write_text(
        f"CREATE TABLE quota_policies (\n"
        f"  id SERIAL PRIMARY KEY,\n"
        f"  scope_name TEXT NOT NULL DEFAULT '{marker}',\n"
        f"  max_hours_limit INTEGER NOT NULL\n"
        f");\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        '@app.get("/api/v1/quotas")\n'
        "def get_quotas(db=None):\n"
        '    return db.execute("SELECT id, scope_name, max_hours_limit FROM quota_policies").fetchall()\n',
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function QuotasPage() {\n"
        "  async function load() {\n"
        "    await fetch('/api/v1/quotas');\n"
        "  }\n"
        '  return <button type="button" onClick={load}>Load Quotas</button>;\n'
        "}\n",
        encoding="utf-8",
    )
    return repo_dir


def _register_target(client: TestClient, slug: str, repo_dir: Path) -> None:
    res = client.post(
        "/api/v1/targets",
        json={
            "slug": slug,
            "name": slug.replace("-", " ").title(),
            "repo_path": str(repo_dir),
            "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
            "backend_subdir": "backend",
            "frontend_subdir": "frontend",
        },
    )
    assert res.status_code in (200, 201), res.text


def _start_fixture_openai_server(
    responder: Callable[[int, dict[str, Any]], tuple[int, dict[str, Any]]],
) -> tuple[http.server.ThreadingHTTPServer, str, list[dict[str, Any]]]:
    recorded: list[dict[str, Any]] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                raw = json.dumps(
                    {
                        "object": "list",
                        "data": [{"id": "fixture-qwen-tool-model", "owned_by": "pinned"}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            idx = len(recorded)
            recorded.append(body)
            code, payload = responder(idx, body)
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1", recorded


def _tool_reply(name: str, args: dict[str, Any], call_id: str = "fixture-call") -> tuple[int, dict[str, Any]]:
    return (
        200,
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": name, "arguments": json.dumps(args)},
                            }
                        ],
                    },
                }
            ]
        },
    )


def _text_reply(text: str) -> tuple[int, dict[str, Any]]:
    return (200, {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": text}}]})


def test_f9_unoffered_tool_and_round_allowlist_rejected_before_dispatch(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#112 (F9): Reject unoffered MCP tools (`wythe_list_targets` & round-excluded tools) before dispatch."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "state-f9a"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))

    repo_a = _write_synthetic_policy_repo(tmp_path / "repo-a", marker="alpha")
    repo_b = _write_synthetic_policy_repo(tmp_path / "repo-b", marker="SECRET_BETA_MARKER")

    dispatched_names: list[str] = []
    real_dispatch = on_device_llm_service.dispatch_mcp_request

    def _spy_dispatch(db_session: Any, rpc_msg: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        dispatched_names.append(str((rpc_msg.get("params") or {}).get("name") or ""))
        return real_dispatch(db_session, rpc_msg, **kwargs)

    monkeypatch.setattr(on_device_llm_service, "dispatch_mcp_request", _spy_dispatch)

    srv, url, recorded = _start_fixture_openai_server(
        lambda n, _body: _tool_reply("wythe_list_targets", {}) if n == 0 else _text_reply("Final answer.")
    )
    try:
        app = create_app()
        with TestClient(app) as client:
            _register_target(client, "target-a", repo_a)
            _register_target(client, "target-b", repo_b)
            client.post(
                "/api/v1/investigations",
                json={"target_slug": "target-a", "session_id": "session-a", "client_id": "client-a"},
            )
            client.post(
                "/api/v1/investigations",
                json={"target_slug": "target-b", "session_id": "session-b", "client_id": "client-b"},
            )

            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain this investigation and available camera tools.",
                    "engine": "local",
                    "target_slug": "target-a",
                    "session_id": "session-a",
                    "client_id": "client-a",
                    "local_base_url": url,
                    "include_vision_snapshot": False,
                },
            )
            assert res.status_code == 200, res.text
            ans = res.json()
            assert ans["executed_tools"] == []
            assert dispatched_names == []
            assert len(recorded) == 2
            offered = [t["function"]["name"] for t in recorded[0]["tools"]]
            assert "wythe_list_targets" not in offered
            tool_msg = json.loads(recorded[1]["messages"][-1]["content"])
            assert tool_msg["ok"] is False
            assert tool_msg["isError"] is True
            assert tool_msg["tool"] == "wythe_list_targets"
            assert "target-b" not in recorded[1]["messages"][-1]["content"]
    finally:
        srv.shutdown()
        srv.server_close()

    # Custom per-round `openai_tools` offering only `wythe_plugins` must also block `wythe_overview`
    srv_narrow, url_narrow, rec_narrow = _start_fixture_openai_server(
        lambda n, _body: _tool_reply("wythe_overview", {"target": "target-a"})
        if n == 0
        else _text_reply("Narrow allowlist enforced.")
    )
    try:
        from app.db.session import get_session_factory

        only_plugins_tool = [
            t for t in on_device_llm_service.build_ask_openai_tools() if t["function"]["name"] == "wythe_plugins"
        ]
        executed_narrow: list[str] = []
        with get_session_factory()() as db_sess:
            out_tuple = on_device_llm_service._run_local_chat_completion(
                url_narrow,
                "fixture-qwen-tool-model",
                "Test narrow round allowlist.",
                "Summarize plugins.",
                None,
                db_session=db_sess,
                target_slug="target-a",
                session_id="session-a",
                openai_tools=only_plugins_tool,
                executed_tools_out=executed_narrow,
            )
        assert out_tuple[0] == "Narrow allowlist enforced."
        assert executed_narrow == []
        assert dispatched_names == []
        narrow_err = json.loads(rec_narrow[1]["messages"][-1]["content"])
        assert narrow_err["isError"] is True
        assert narrow_err["tool"] == "wythe_overview"
    finally:
        srv_narrow.shutdown()
        srv_narrow.server_close()


def test_f9_cross_target_and_cross_session_confinement_blocks_writes(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#112 (F9): Enforce `(target_slug, session_id)` confinement before `dispatch_mcp_request`."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "state-f9b"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))

    repo_a = _write_synthetic_policy_repo(tmp_path / "repo-a", marker="alpha")
    repo_b = _write_synthetic_policy_repo(tmp_path / "repo-b", marker="beta")

    dispatched_calls: list[tuple[str, dict[str, Any]]] = []
    real_dispatch = on_device_llm_service.dispatch_mcp_request

    def _spy_dispatch(db_session: Any, rpc_msg: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        params = rpc_msg.get("params") or {}
        dispatched_calls.append((str(params.get("name") or ""), dict(params.get("arguments") or {})))
        return real_dispatch(db_session, rpc_msg, **kwargs)

    monkeypatch.setattr(on_device_llm_service, "dispatch_mcp_request", _spy_dispatch)

    def _cross_responder(call_num: int, _body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if call_num == 0:
            return (
                200,
                {
                    "choices": [
                        {
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "cross-1",
                                        "type": "function",
                                        "function": {
                                            "name": "wythe_investigation",
                                            "arguments": json.dumps(
                                                {
                                                    "action": "record_correction",
                                                    "target": "target-b",
                                                    "session_id": "session-b",
                                                    "note": "SYNTHETIC_CROSS_SESSION_CORRECTION",
                                                }
                                            ),
                                        },
                                    },
                                    {
                                        "id": "cross-2",
                                        "type": "function",
                                        "function": {
                                            "name": "wythe_investigation",
                                            "arguments": json.dumps(
                                                {
                                                    "action": "record_correction",
                                                    "session_id": "session-a2",
                                                    "note": "SAME_TARGET_OTHER_SESSION",
                                                }
                                            ),
                                        },
                                    },
                                    {
                                        "id": "cross-3",
                                        "type": "function",
                                        "function": {
                                            "name": "wythe_overview",
                                            "arguments": json.dumps({"target_slug": "target-b"}),
                                        },
                                    },
                                ],
                            },
                        }
                    ]
                },
            )
        if call_num == 1:
            return _tool_reply(
                "wythe_investigation",
                {"action": "record_correction", "session_id": "default", "note": "Scoped to session-a"},
                call_id="ok-same-session",
            )
        return _text_reply("Confinement verified.")

    srv, url, recorded = _start_fixture_openai_server(_cross_responder)
    try:
        app = create_app()
        with TestClient(app) as client:
            _register_target(client, "target-a", repo_a)
            _register_target(client, "target-b", repo_b)
            for slug, sid in (("target-a", "session-a"), ("target-a", "session-a2"), ("target-b", "session-b")):
                client.post(
                    "/api/v1/investigations",
                    json={"target_slug": slug, "session_id": sid, "client_id": f"{sid}-cli"},
                )

            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "Check investigation confinement.",
                    "engine": "local",
                    "target_slug": "target-a",
                    "session_id": "session-a",
                    "client_id": "session-a-cli",
                    "local_base_url": url,
                    "include_vision_snapshot": False,
                },
            )
            assert res.status_code == 200, res.text
            assert res.json()["executed_tools"] == ["wythe_investigation"]
            assert len(dispatched_calls) == 1
            assert dispatched_calls[0][1]["target"] == "target-a"
            assert dispatched_calls[0][1]["session_id"] == "session-a"

            for msg_item in recorded[1]["messages"][-3:]:
                parsed_err = json.loads(msg_item["content"])
                assert parsed_err["isError"] is True

            assert client.get("/api/v1/investigations/session-b").json()["corrections"] == []
            assert client.get("/api/v1/investigations/session-a2").json()["corrections"] == []
            sess_a_corrs = client.get("/api/v1/investigations/session-a").json()["corrections"]
            assert [c["note"] for c in sess_a_corrs] == ["Scoped to session-a"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_f10_empty_synthesis_marks_scanner_brief_and_tuple_compat(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#113 (F10): Empty synthesis after tool calls emits system status notice with `authored_by='scanner_brief'`."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "state-f10"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_a = _write_synthetic_policy_repo(tmp_path / "repo-a")

    srv_ok, url_ok, _ = _start_fixture_openai_server(
        lambda n, _body: _tool_reply("wythe_plugins", {}) if n == 0 else _text_reply("")
    )
    srv_err, url_err, _ = _start_fixture_openai_server(
        lambda n, _body: _tool_reply("wythe_list_targets", {}) if n == 0 else _text_reply("")
    )
    try:
        app = create_app()
        with TestClient(app) as client:
            _register_target(client, "target-a", repo_a)
            client.post(
                "/api/v1/investigations",
                json={"target_slug": "target-a", "session_id": "session-a", "client_id": "client-a"},
            )

            res_ok = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain installed plugins and answer my architecture question.",
                    "engine": "local",
                    "target_slug": "target-a",
                    "session_id": "session-a",
                    "client_id": "client-a",
                    "local_base_url": url_ok,
                    "include_vision_snapshot": False,
                },
            )
            assert res_ok.status_code == 200, res_ok.text
            body_ok = res_ok.json()
            assert body_ok["authored_by"] == "scanner_brief"
            assert body_ok["fallback_reason"]
            assert body_ok["executed_tools"] == ["wythe_plugins"]
            assert "System / Tool Status Notice" in body_ok["answer_markdown"]
            assert "unanswered by the model" in body_ok["answer_markdown"]
            assert "Succeeded MCP tool call(s):** `wythe_plugins`" in body_ok["answer_markdown"]
            assert not body_ok["answer_markdown"].startswith("Executed Wythe MCP tool(s):")

            sess_data = client.get("/api/v1/investigations/session-a").json()
            saved_turn = next(t for t in sess_data["turns"] if t["turn_id"] == body_ok["turn_id"])
            assert saved_turn["authored_by"] == "scanner_brief"
            assert saved_turn["fallback_reason"] == body_ok["fallback_reason"]

            res_err = client.post(
                "/api/v1/ask",
                json={
                    "question": "Try unoffered tool then return empty synthesis.",
                    "engine": "local",
                    "target_slug": "target-a",
                    "session_id": "session-a",
                    "client_id": "client-a",
                    "local_base_url": url_err,
                    "include_vision_snapshot": False,
                },
            )
            assert res_err.status_code == 200, res_err.text
            body_err = res_err.json()
            assert body_err["authored_by"] == "scanner_brief"
            assert body_err["fallback_reason"]
            assert body_err["executed_tools"] == []
            assert "Failed / rejected MCP tool call(s):" in body_err["answer_markdown"]
            assert "`wythe_list_targets`" in body_err["answer_markdown"]
            assert "isError=true" in body_err["answer_markdown"]

            # Verify 2-tuple and 3-tuple monkeypatch compatibility on `_run_local_chat_completion`
            for fake_ret, exp_authored in (
                (("Two-tuple model reply.", False), "model"),
                (("Three-tuple reply.", False, "custom-note"), "model"),
            ):
                monkeypatch.setattr(
                    on_device_llm_service,
                    "_run_local_chat_completion",
                    lambda *_a, _ret=fake_ret, **_k: _ret,
                )
                compat = client.post(
                    "/api/v1/ask",
                    json={
                        "question": "Check tuple compatibility.",
                        "engine": "local",
                        "target_slug": "target-a",
                        "session_id": "session-a",
                        "local_base_url": url_ok,
                        "include_vision_snapshot": False,
                    },
                )
                assert compat.status_code == 200
                assert compat.json()["authored_by"] == exp_authored
    finally:
        srv_ok.shutdown()
        srv_ok.server_close()
        srv_err.shutdown()
        srv_err.server_close()


def test_f6_and_f7_viewport_receipt_identity_and_resume_revalidation(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#106 (F6) & #107 (F7): Enforce receipt `(target, session, command_id, seq)` identity & TS resume guards."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "state-f6"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_synthetic_policy_repo(tmp_path / "audit-repo")

    app = create_app()
    with TestClient(app) as client:
        _register_target(client, "audit", repo_dir)
        for sid in ("session-a", "session-b"):
            client.post(
                "/api/v1/investigations",
                json={"target_slug": "audit", "session_id": sid, "client_id": f"{sid}-browser"},
            )

        cmd_payload = {
            "target_slug": "audit",
            "session_id": "session-a",
            "correlation_id": "cross-session-probe",
            "focus_node_ids": ["t:quota_policies"],
        }
        ack = client.post("/api/v1/viewport/command", json=cmd_payload).json()
        cmd_id = ack["command_id"]
        seq = ack["seq"]

        # 1) Cross-session receipt (`session-b` on `session-a` command) -> HTTP 422, zero mutation
        cross_rcpt = client.post(
            "/api/v1/viewport/receipts",
            json={
                "target_slug": "audit",
                "command_id": cmd_id,
                "session_id": "session-b",
                "client_id": "session-b-browser",
                "outcome": "applied",
            },
        )
        assert cross_rcpt.status_code in (404, 422), cross_rcpt.text

        # 2) Unknown `command_id` with valid `seq` -> HTTP 404 (never falls back to `WHERE seq = ?`)
        bad_id = client.post(
            "/api/v1/viewport/receipts",
            json={
                "target_slug": "audit",
                "command_id": "never-issued",
                "seq": seq,
                "session_id": "session-a",
                "client_id": "session-a-browser",
                "outcome": "applied",
            },
        )
        assert bad_id.status_code == 404, bad_id.text

        # 3) Valid `command_id` with contradictory `seq` -> HTTP 422, zero mutation
        bad_seq = client.post(
            "/api/v1/viewport/receipts",
            json={
                "target_slug": "audit",
                "command_id": cmd_id,
                "seq": seq + 77,
                "session_id": "session-a",
                "client_id": "session-a-browser",
                "outcome": "applied",
            },
        )
        assert bad_seq.status_code == 422, bad_seq.text

        # Confirm zero mutation across all three rejected receipts
        replay = client.post("/api/v1/viewport/command", json=cmd_payload).json()
        assert replay["delivery_state"] == "accepted_by_service"
        assert replay["applied_by_client_ids"] == []
        assert list_viewport_receipts(target_slug="audit", command_id=cmd_id) == []

        # 4) Multi-client collaboration within the SAME `session-a` succeeds for both tabs
        for cli_id in ("session-a-tab1", "session-a-tab2"):
            ok_rcpt = client.post(
                "/api/v1/viewport/receipts",
                json={
                    "target_slug": "audit",
                    "command_id": cmd_id,
                    "seq": seq,
                    "session_id": "session-a",
                    "client_id": cli_id,
                    "outcome": "applied",
                },
            )
            assert ok_rcpt.status_code == 200, ok_rcpt.text
        vp_state = get_viewport_state("audit", session_id="session-a")
        assert vp_state.latest is not None
        assert vp_state.latest.delivery_state == "applied_by_browser"
        assert vp_state.latest.applied_by_client_ids == ["session-a-tab1", "session-a-tab2"]

    # 5) Verify frontend #107 (F7) `page.tsx` resume revalidation & run TS choreography unit test if tsc present
    repo_root = Path(__file__).resolve().parents[2]
    page_tsx = (repo_root / "frontend" / "src" / "app" / "page.tsx").read_text(encoding="utf-8")
    assert "source: 'resume'" in page_tsx
    assert "resumeDecision.action !== 'apply'" in page_tsx
    tsc_bin = repo_root / "frontend" / "node_modules" / "typescript" / "bin" / "tsc"
    if tsc_bin.is_file():
        fe_dir = repo_root / "frontend"
        with tempfile.TemporaryDirectory(prefix="wythe-f7-ts-") as out_dir:
            tmp_tsconfig = Path(out_dir) / "tsconfig.f7.json"
            tmp_tsconfig.write_text(
                json.dumps(
                    {
                        "extends": str(fe_dir / "tsconfig.json"),
                        "compilerOptions": {
                            "module": "commonjs",
                            "moduleResolution": "node",
                            "noEmit": False,
                            "incremental": False,
                            "baseUrl": str(fe_dir),
                            "paths": {"@/*": [str(fe_dir / "src" / "*")]},
                            "typeRoots": [str(fe_dir / "node_modules" / "@types")],
                            "rootDir": str(fe_dir / "src"),
                            "outDir": out_dir,
                        },
                        "include": [
                            str(fe_dir / "src" / "lib" / "__tests__" / "wytheCameraChoreography.test.ts")
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tsc_res = subprocess.run(
                ["node", str(tsc_bin), "-p", str(tmp_tsconfig)],
                check=False,
                capture_output=True,
                text=True,
                cwd=fe_dir,
            )
            assert tsc_res.returncode == 0, f"{tsc_res.stdout}\n{tsc_res.stderr}"
            compiled_js = Path(out_dir) / "lib" / "__tests__" / "wytheCameraChoreography.test.js"
            node_env = {**os.environ, "NODE_PATH": str(fe_dir / "node_modules")}
            run_res = subprocess.run(
                ["node", "--test", str(compiled_js)],
                check=False,
                capture_output=True,
                text=True,
                env=node_env,
            )
            assert run_res.returncode == 0, f"{run_res.stdout}\n{run_res.stderr}"
