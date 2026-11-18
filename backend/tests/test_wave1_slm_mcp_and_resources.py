"""Wave 1 Slice C (#93): Compact SLM MCP slice, `wythe://` resources, and parity fixes."""

from __future__ import annotations

import http.server
import io
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.main import create_app
from app.schemas.atlas import OnDeviceEngineStatus
from app.services import on_device_llm_service
from app.services.mcp_service import (
    MCP_SLM_TOOLS,
    MCP_TOOLS,
    dispatch_mcp_request,
    run_mcp_stdio_server,
)

TINY_WEBP_DATA_URL = (
    "data:image/webp;base64,UklGRhIAAABXRUJQVlA4TAYAAAAvAAAAAAfQ//73v/+BiOh/AAA="
)
TINY_JPEG_DATA_URL = (
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA="
)


def _create_git_three_tier_repo(repo_dir: Path, *, with_policy_bypass: bool = False) -> Path:
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True)

    schema_sql = (
        "CREATE TABLE orders (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  customer_code TEXT NOT NULL,\n"
        "  total_cents INTEGER NOT NULL\n"
        ");\n"
    )
    service_py = (
        "def record_order(db):\n"
        '    db.execute("SELECT id, total_cents FROM orders")\n'
        '    db.execute("INSERT INTO orders (customer_code, total_cents) VALUES (\'c1\', 100)")\n'
        "    return {'ok': True}\n"
    )
    main_imports = "from app.service import record_order\n"
    main_call = "    return record_order(None)\n"
    if with_policy_bypass:
        schema_sql += (
            "\nCREATE TABLE active_policies (\n"
            "  id SERIAL PRIMARY KEY,\n"
            "  max_shift_cap INTEGER NOT NULL\n"
            ");\n"
        )
        service_py = (
            "from app.models import ActivePolicy\n\n"
            + service_py
            + "\nMAX_SHIFT_CAP = 12\n\n"
            "def evaluate_shift_limit(session):\n"
            "    policy = session.query(ActivePolicy).first()\n"
            "    _ = policy.id\n"
            "    return MAX_SHIFT_CAP\n"
        )
        main_imports = "from app.service import evaluate_shift_limit, record_order\n"
        main_call = "    _ = evaluate_shift_limit(None)\n    return record_order(None)\n"
        (repo_dir / "backend" / "app" / "models.py").write_text(
            "from sqlalchemy import Column, Integer\n"
            "from sqlalchemy.orm import declarative_base\n\n"
            "Base = declarative_base()\n\n"
            "class ActivePolicy(Base):\n"
            "    __tablename__ = 'active_policies'\n"
            "    id = Column(Integer, primary_key=True)\n"
            "    max_shift_cap = Column(Integer, nullable=False)\n",
            encoding="utf-8",
        )

    (repo_dir / "backend" / "schema.sql").write_text(schema_sql, encoding="utf-8")
    (repo_dir / "backend" / "app" / "service.py").write_text(service_py, encoding="utf-8")
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        + main_imports
        + "\napp = FastAPI()\n\n"
        '@app.post("/api/v1/orders")\n'
        "def post_order():\n"
        + main_call,
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function OrdersPage() {\n"
        "  async function submit() {\n"
        "    await fetch('/api/v1/orders', { method: 'POST' });\n"
        "  }\n"
        "  return <button type=\"button\" onClick={submit}>Submit order</button>;\n"
        "}\n",
        encoding="utf-8",
    )

    git_env = {
        "GIT_AUTHOR_NAME": "Test Bot",
        "GIT_AUTHOR_EMAIL": "bot@example.invalid",
        "GIT_COMMITTER_NAME": "Test Bot",
        "GIT_COMMITTER_EMAIL": "bot@example.invalid",
    }
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial clean 3-tier fixture"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        env={**git_env, "PATH": "/usr/bin:/bin:/opt/homebrew/bin"},
    )
    return repo_dir


def test_slm_slice_budget_and_tool_surface_stdio_cli_and_http(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `--slice slm` `<2,000 B` budget, CLI/HTTP/stdio parity, and cross-slice tool execution."""
    assert isolated_db_url.startswith("sqlite:")
    encoded_slm = json.dumps(MCP_SLM_TOOLS, separators=(",", ":")).encode("utf-8")
    assert len(MCP_SLM_TOOLS) == 4
    assert len(encoded_slm) < 2000
    assert [t["name"] for t in MCP_SLM_TOOLS] == [
        "wythe_context",
        "wythe_lineage_cone",
        "wythe_check_change",
        "wythe_what_is_this",
    ]
    for tool_def in MCP_SLM_TOOLS:
        props = tool_def["inputSchema"]["properties"]
        assert len(props) <= 4
        for prop_schema in props.values():
            assert prop_schema["type"] in ("string", "boolean", "integer", "number")

    # Default signature `dispatch_mcp_request(session, msg)` preserves all full tools
    full_list = dispatch_mcp_request(db_session, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert full_list is not None
    assert len(full_list["result"]["tools"]) == len(MCP_TOOLS) == 11

    slm_list = dispatch_mcp_request(
        db_session, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, slice_mode="slm"
    )
    assert slm_list is not None
    assert [t["name"] for t in slm_list["result"]["tools"]] == [
        "wythe_context",
        "wythe_lineage_cone",
        "wythe_check_change",
        "wythe_what_is_this",
    ]

    # Verify CLI `wythe mcp --slice slm` AND direct `run_mcp_stdio_server(slice_mode="slm")`
    direct_in = io.BytesIO(
        (json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}) + "\n").encode("utf-8")
    )
    direct_out = io.BytesIO()
    assert run_mcp_stdio_server(stdin=direct_in, stdout=direct_out, slice_mode="slm") == 0
    assert len(json.loads(direct_out.getvalue().decode("utf-8").strip())["result"]["tools"]) == 4

    stdio_in = io.BytesIO(
        (json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}) + "\n").encode("utf-8")
    )
    stdio_out = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", type("_FakeStd", (), {"buffer": stdio_in})())
    monkeypatch.setattr(sys, "stdout", type("_FakeStd", (), {"buffer": stdio_out})())
    assert cli_main(["mcp", "--slice", "slm"]) == 0
    cli_parsed = json.loads(stdio_out.getvalue().decode("utf-8").strip())
    assert len(cli_parsed["result"]["tools"]) == 4

    repo_dir = _create_git_three_tier_repo(tmp_path / "slm-orders", with_policy_bypass=True)
    app = create_app()
    with TestClient(app) as client:
        reg = client.post(
            "/api/v1/targets",
            json={
                "slug": "slm-orders",
                "name": "SLM Orders",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        assert reg.status_code in (200, 201)

        m_full = client.get("/api/v1/mcp").json()
        assert m_full["slice"] == "full"
        assert len(m_full["tools"]) == len(MCP_TOOLS) == 11

        m_slm = client.get("/api/v1/mcp?slice=slm").json()
        assert m_slm["slice"] == "slm"
        assert len(m_slm["tools"]) == 4

        # Both `slm` and `full` modes execute all 4 SLM tools AND all 8 full tools cleanly
        for mode in ("slm", "full"):
            for call_name, call_args in (
                ("wythe_context", {"target": "slm-orders", "section": "all"}),
                ("wythe_lineage_cone", {"target": "slm-orders", "query": "active_policies"}),
                ("wythe_check_change", {"target": "slm-orders", "base_ref": "WORKING"}),
                ("wythe_what_is_this", {"target": "slm-orders"}),
                ("wythe_list_targets", {}),
                ("wythe_plugins", {}),
            ):
                rpc = client.post(
                    f"/api/v1/mcp?slice={mode}",
                    json={
                        "jsonrpc": "2.0",
                        "id": 50,
                        "method": "tools/call",
                        "params": {"name": call_name, "arguments": call_args},
                    },
                ).json()
                assert rpc["result"]["isError"] is False
                text_out = rpc["result"]["content"][0]["text"]
                if call_name == "wythe_context":
                    assert "Active UI Focus Summary" in text_out
                    assert "# Findings :: `slm-orders`" in text_out
                elif call_name == "wythe_lineage_cone":
                    assert "## Policy Field Consumption" in text_out
                    assert "bypassed" in text_out
                    assert "MAX_SHIFT_CAP" in text_out


def test_actionable_steering_hints_and_passive_mcp_resources(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
) -> None:
    """Verify steering hints on unknown target / unmatched query and `wythe://` MCP resources."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _create_git_three_tier_repo(tmp_path / "billing-app", with_policy_bypass=True)
    app = create_app()
    with TestClient(app) as client:
        client.post(
            "/api/v1/targets",
            json={
                "slug": "billing-app",
                "name": "Billing App",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "billing-app",
                "selected_node_id": "t:orders",
                "camera_revision": 1,
                "snapshot_data_url": TINY_WEBP_DATA_URL,
            },
        )

    # 1. Unknown target slug -> actionable steering hint listing registered target slugs
    bad_target = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {"name": "wythe_context", "arguments": {"target": "biling-ap"}},
        },
        slice_mode="slm",
    )
    assert bad_target is not None
    assert bad_target["result"]["isError"] is True
    err_txt = bad_target["result"]["content"][0]["text"]
    assert "billing-app" in err_txt
    assert "wythe" in err_txt

    # 2. Unmatched query in `wythe_lineage_cone` -> closest matching node IDs & labels
    bad_query = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "wythe_lineage_cone",
                "arguments": {"target": "billing-app", "query": "ordrs"},
            },
        },
        slice_mode="slm",
    )
    assert bad_query is not None
    assert bad_query["result"]["isError"] is True
    q_txt = bad_query["result"]["content"][0]["text"]
    assert "t:orders" in q_txt
    assert "orders" in q_txt

    # 3. `initialize` advertises both `tools` and `resources`
    init_res = dispatch_mcp_request(
        db_session, {"jsonrpc": "2.0", "id": 102, "method": "initialize"}
    )
    assert init_res is not None
    assert init_res["result"]["capabilities"] == {"tools": {}, "resources": {}}

    # 4. `resources/list` & `resources/templates/list`
    r_list = dispatch_mcp_request(
        db_session, {"jsonrpc": "2.0", "id": 103, "method": "resources/list"}
    )
    assert r_list is not None
    uris = {r["uri"] for r in r_list["result"]["resources"]}
    assert "wythe://billing-app/llms" in uris
    assert "wythe://billing-app/ui-focus" in uris
    assert "wythe://billing-app/findings" in uris

    t_list = dispatch_mcp_request(
        db_session, {"jsonrpc": "2.0", "id": 104, "method": "resources/templates/list"}
    )
    assert t_list is not None
    tpl_uris = {t["uriTemplate"] for t in t_list["result"]["resourceTemplates"]}
    assert tpl_uris == {
        "wythe://{slug}/llms",
        "wythe://{slug}/ui-focus",
        "wythe://{slug}/findings",
        "wythe://{slug}/cone/{node_id}",
        "wythe://{slug}/investigation/{session_id}",
    }

    # 5. `resources/read` across llms, ui-focus, findings, cone/{node_id}, and unknown slug
    for read_uri, expected_snippet in (
        ("wythe://billing-app/llms", "orders"),
        ("wythe://billing-app/ui-focus", "image/webp"),
        ("wythe://billing-app/findings", "# Findings :: `billing-app`"),
        ("wythe://billing-app/cone/t:active_policies", "## Policy Field Consumption"),
    ):
        read_res = dispatch_mcp_request(
            db_session,
            {"jsonrpc": "2.0", "id": 105, "method": "resources/read", "params": {"uri": read_uri}},
        )
        assert read_res is not None
        contents = read_res["result"]["contents"]
        assert contents[0]["uri"] == read_uri
        assert contents[0]["mimeType"] == "text/markdown"
        assert expected_snippet in contents[0]["text"]
        if read_uri.endswith("/ui-focus"):
            assert len(contents) == 2
            assert contents[1]["mimeType"] == "image/webp"

    miss_res = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 106,
            "method": "resources/read",
            "params": {"uri": "wythe://missing-slug/llms"},
        },
    )
    assert miss_res is not None
    assert "error" in miss_res
    assert "billing-app" in miss_res["error"]["message"]


def test_diff_backed_blast_radius_and_ui_focus_staleness(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Verify working-tree git diff avoids false INCOMPLETE and stale frames are omitted."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _create_git_three_tier_repo(tmp_path / "diff-orders", with_policy_bypass=False)

    # Modify a tracked file in the working tree (`changes.before` is non-empty!)
    (repo_dir / "backend" / "app" / "service.py").write_text(
        "def record_order(db):\n"
        '    db.execute("SELECT id, customer_code, total_cents FROM orders")\n'
        '    db.execute("INSERT INTO orders (customer_code, total_cents) VALUES (\'c2\', 250)")\n'
        "    return {'ok': True, 'updated': True}\n",
        encoding="utf-8",
    )

    app = create_app()
    with TestClient(app) as client:
        client.post(
            "/api/v1/targets",
            json={
                "slug": "diff-orders",
                "name": "Diff Orders",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        for tool_name in ("wythe_blast_radius", "wythe_check_change"):
            res = client.post(
                "/api/v1/mcp?slice=slm",
                json={
                    "jsonrpc": "2.0",
                    "id": 200,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": {"target": "diff-orders", "base_ref": "WORKING"},
                    },
                },
            ).json()
            assert res["result"]["isError"] is False
            text = res["result"]["content"][0]["text"]
            assert "Verdict: `PASS`" in text
            assert "Base Graph: `available`" in text
            assert "Verdict: `INCOMPLETE`" not in text

        # WebP snapshot preserved as `ui_focus_latest.webp` (`image/webp`), fresh @ camera_revision=1
        ack1 = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "diff-orders",
                "selected_node_id": "t:orders",
                "lens": "status",
                "in_frustum_count": 4,
                "camera_revision": 1,
                "snapshot_data_url": TINY_WEBP_DATA_URL,
            },
        ).json()
        assert ack1["snapshot_path"].endswith("ui_focus_latest.webp")
        assert ack1["snapshot_mime_type"] == "image/webp"
        assert ack1["camera_revision"] == 1
        assert ack1["snapshot_stale"] is False

        mcp_fresh = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 201,
                "method": "tools/call",
                "params": {"name": "wythe_what_is_this", "arguments": {"include_image": True}},
            },
        ).json()
        fresh_blocks = mcp_fresh["result"]["content"]
        assert len(fresh_blocks) == 2
        assert fresh_blocks[1]["mimeType"] == "image/webp"

        # JPEG snapshot replaces WebP cleanly
        ack_jpg = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "diff-orders",
                "selected_node_id": "t:orders",
                "lens": "status",
                "in_frustum_count": 4,
                "camera_revision": 2,
                "snapshot_data_url": TINY_JPEG_DATA_URL,
            },
        ).json()
        assert ack_jpg["snapshot_path"].endswith("ui_focus_latest.jpg")
        assert ack_jpg["snapshot_mime_type"] == "image/jpeg"
        assert not (Path(ack_jpg["snapshot_path"]).parent / "ui_focus_latest.webp").exists()

        # Newer `camera_revision=3` with NO `snapshot_data_url` marks snapshot stale & omits image block!
        ack_stale = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "diff-orders",
                "selected_node_id": "t:orders",
                "lens": "status",
                "in_frustum_count": 4,
                "camera_revision": 3,
            },
        ).json()
        assert ack_stale["snapshot_stale"] is True

        exp_stale = client.get("/api/v1/ui-focus").json()
        assert exp_stale["snapshot_stale"] is True
        assert exp_stale["camera_revision"] == 3

        mcp_stale = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {"name": "wythe_what_is_this", "arguments": {"include_image": True}},
            },
        ).json()
        assert len(mcp_stale["result"]["content"]) == 1

        # Fresh WebP restores `snapshot_stale=False`, then changed `lens` without frame marks stale again
        ack_re = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "diff-orders",
                "selected_node_id": "t:orders",
                "lens": "status",
                "in_frustum_count": 4,
                "camera_revision": 4,
                "snapshot_data_url": TINY_WEBP_DATA_URL,
            },
        ).json()
        assert ack_re["snapshot_stale"] is False

        ack_lens_change = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "diff-orders",
                "selected_node_id": "t:orders",
                "lens": "contention",
                "in_frustum_count": 4,
            },
        ).json()
        assert ack_lens_change["snapshot_stale"] is True


def test_vision_aware_auto_cascade_prefers_vlm_with_image_and_apple_for_text(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `auto` checks vision-capable `/v1` VLMs before Apple FM when an image is attached."""
    assert isolated_db_url.startswith("sqlite:")
    apple_calls: list[str] = []
    vlm_payloads: list[dict[str, Any]] = []

    def _mock_apple_ready() -> OnDeviceEngineStatus:
        return OnDeviceEngineStatus(
            engine="apple",
            label="Apple Intelligence",
            state="ready",
            model_id="apple-foundation-models-on-device",
            supports_vision=False,
            note="Mock Apple FM ready.",
        )

    def _mock_apple_run(_instructions: str, prompt: str) -> tuple[str, list[str]]:
        apple_calls.append(prompt)
        return "Apple FM text-only answer citing `atlas_rule_policies`.", ["t:atlas_rule_policies"]

    monkeypatch.setattr(on_device_llm_service, "check_apple_engine_status", _mock_apple_ready)
    monkeypatch.setattr(on_device_llm_service, "run_apple_engine_ask", _mock_apple_run)

    def _make_openai_server(model_id: str, *, fail_chat: bool = False) -> tuple[http.server.ThreadingHTTPServer, str]:
        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.path == "/v1/models":
                    out = json.dumps(
                        {"object": "list", "data": [{"id": model_id, "owned_by": "pinned-model-proxy"}]}
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(out)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                raw = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length") or "0")).decode("utf-8")
                )
                vlm_payloads.append(raw)
                if fail_chat:
                    self.send_response(500)
                    self.end_headers()
                    return
                out = json.dumps(
                    {
                        "choices": [
                            {
                                "finish_reason": "stop",
                                "message": {"content": f"VLM `{model_id}` inspected `atlas_rule_policies`."},
                            }
                        ]
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1"

    text_srv, text_url = _make_openai_server("Qwen3-8B-Instruct-4bit")
    vlm_srv, vlm_url = _make_openai_server("mlx-community/gemma-4-26b-a4b-it-4bit")
    monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (text_url, vlm_url))

    try:
        app = create_app()
        with TestClient(app) as client:
            # 1. Multimodal image attached + `engine="auto"` -> skips text-only seat, uses VLM before Apple FM!
            res_img = client.post(
                "/api/v1/ask",
                json={
                    "question": "What does this highlighted cluster show?",
                    "engine": "auto",
                    "target_slug": "wythe",
                    "include_vision_snapshot": True,
                    "snapshot_data_url": TINY_WEBP_DATA_URL,
                },
            )
            assert res_img.status_code == 200
            body_img = res_img.json()
            assert body_img["engine_used"] == "local"
            assert "gemma-4" in body_img["model_id"]
            assert body_img["used_vision_snapshot"] is True
            assert len(apple_calls) == 0

            # 2. Text-only non-tool query on an unpinned `default_model` seat -> Apple FM runs FIRST!
            unpinned_srv, unpinned_url = _make_openai_server("default_model")
            try:
                monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (unpinned_url,))
                res_txt = client.post(
                    "/api/v1/ask",
                    json={
                        "question": "Summarize the rule policy table.",
                        "engine": "auto",
                        "target_slug": "wythe",
                        "include_vision_snapshot": False,
                    },
                )
                assert res_txt.status_code == 200
                body_txt = res_txt.json()
                assert body_txt["engine_used"] == "apple"
                assert body_txt["used_vision_snapshot"] is False
                assert len(apple_calls) == 1
            finally:
                unpinned_srv.shutdown()
                unpinned_srv.server_close()

            # 3. Failing VLM (`fail_chat=True` HTTP 500) AND `TimeoutError` during completion -> falls back to Apple FM cleanly!
            fail_srv, fail_url = _make_openai_server("mlx-community/qwen-vl-7b-4bit", fail_chat=True)
            try:
                monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (fail_url,))
                res_http_fb = client.post(
                    "/api/v1/ask",
                    json={
                        "question": "Explain this view after VLM 500.",
                        "engine": "auto",
                        "target_slug": "wythe",
                        "include_vision_snapshot": True,
                        "snapshot_data_url": TINY_WEBP_DATA_URL,
                    },
                )
                assert res_http_fb.status_code == 200
                assert res_http_fb.json()["engine_used"] == "apple"
                assert len(apple_calls) == 2
            finally:
                fail_srv.shutdown()
                fail_srv.server_close()

            import contextlib

            monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (vlm_url,))
            real_open = on_device_llm_service._no_proxy_opener.open

            class _TimeoutReader:
                def read(self) -> bytes:
                    raise TimeoutError("read operation timed out")

            @contextlib.contextmanager
            def _timeout_ctx() -> Any:
                yield _TimeoutReader()

            def _timeout_on_chat(req: Any, timeout: float = 60.0) -> Any:
                url = req.full_url if hasattr(req, "full_url") else str(req)
                if url.endswith("/chat/completions"):
                    return _timeout_ctx()
                return real_open(req, timeout=timeout)

            monkeypatch.setattr(on_device_llm_service._no_proxy_opener, "open", _timeout_on_chat)
            res_to = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain this view after VLM read timeout.",
                    "engine": "auto",
                    "target_slug": "wythe",
                    "include_vision_snapshot": True,
                    "snapshot_data_url": TINY_WEBP_DATA_URL,
                },
            )
            assert res_to.status_code == 200
            assert res_to.json()["engine_used"] == "apple"
            assert len(apple_calls) == 3
    finally:
        text_srv.shutdown()
        text_srv.server_close()
        vlm_srv.shutdown()
        vlm_srv.server_close()


def test_webmcp_four_tool_parity_and_drawer_webp_sync_source_contracts(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify M10 partial-update drawer sync, L2 orbit staleness without camera_revision, and L7 explicit text model."""
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        # 1. Page syncs active filters (`connected_only=True`, `neighborhood_hops=2`) + fresh snapshot (`camera_revision=7`)
        client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "wythe",
                "selected_node_id": "t:atlas_rule_policies",
                "lens": "status",
                "connected_only": True,
                "neighborhood_hops": 2,
                "in_frustum_count": 4,
                "camera_revision": 7,
                "snapshot_data_url": TINY_WEBP_DATA_URL,
            },
        )
        # 2. L2 (R9): Camera orbit telemetry WITHOUT `camera_revision` marks snapshot stale!
        orbit_ack = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "wythe",
                "selected_node_id": "t:atlas_rule_policies",
                "lens": "status",
                "connected_only": True,
                "neighborhood_hops": 2,
                "camera_position": "12.0,40.0,-9.0",
                "camera_target": "0.0,0.0,0.0",
                "in_frustum_count": 4,
            },
        ).json()
        assert orbit_ack["snapshot_stale"] is True

        # 3. M10 (R10): Drawer snapshot-only sync (`active_slug`, `camera_revision`, `snapshot_data_url`) preserves `connected_only=True` & `neighborhood_hops=2`!
        drawer_ack = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "wythe",
                "camera_revision": 8,
                "snapshot_data_url": TINY_WEBP_DATA_URL,
            },
        ).json()
        assert drawer_ack["snapshot_stale"] is False
        brief = client.get("/api/v1/ui-focus").json()["markdown_brief"]
        assert "Connected only: `True` | Neighborhood hops: `2`" in brief

    # 4. L7 backend: Explicit `preferred_model` text seat is selected even when `prefer_vision=True`
    def _make_seat(model_id: str) -> tuple[http.server.ThreadingHTTPServer, str]:
        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                out = json.dumps({"data": [{"id": model_id, "owned_by": "pinned"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out)

        s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        return s, f"http://127.0.0.1:{s.server_address[1]}/v1"

    txt_s, txt_u = _make_seat("Qwen3-8B-Instruct-4bit")
    vlm_s, vlm_u = _make_seat("mlx-community/gemma-4-26b-a4b-it-4bit")
    try:
        monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (txt_u, vlm_u))
        explicit_txt = on_device_llm_service.probe_local_openai_engine(
            None, "Qwen3-8B-Instruct-4bit", prefer_vision=True
        )
        assert explicit_txt.state == "ready"
        assert explicit_txt.model_id == "Qwen3-8B-Instruct-4bit"
        assert explicit_txt.supports_vision is False
    finally:
        txt_s.shutdown()
        txt_s.server_close()
        vlm_s.shutdown()
        vlm_s.server_close()


def test_m1_m11_l1_l6_snapshot_containment_mime_and_jsonrpc_params_validation(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify snapshot_path containment (M1), sniffed MIME (L1), JSON-RPC params validation (M11), and pre-scan URI validation (L6)."""
    import io

    from app.services import mcp_service, ui_focus_service

    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    outside_secret = tmp_path / "outside_key.pem"
    outside_secret.write_bytes(b"SECRET_MATERIAL_DO_NOT_SERVE")

    with TestClient(app) as client:
        # L1: WebP snapshot served with `image/webp` media_type
        client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "wythe",
                "camera_revision": 1,
                "snapshot_data_url": TINY_WEBP_DATA_URL,
            },
        )
        snap_resp = client.get("/api/v1/ui-focus/snapshot.png")
        assert snap_resp.status_code == 200
        assert snap_resp.headers["content-type"].startswith("image/webp")

        # M1(a): Planted outside `snapshot_path` in `ui_focus_state.json` is ignored across all 3 surfaces
        state_file, _ = ui_focus_service._resolve_focus_paths()
        focus_dir = state_file.parent
        for ext in (".webp", ".png", ".jpg"):
            (focus_dir / f"ui_focus_latest{ext}").unlink(missing_ok=True)
        planted = json.loads(state_file.read_text(encoding="utf-8"))
        planted["snapshot_path"] = str(outside_secret)
        planted["snapshot_stale"] = False
        state_file.write_text(json.dumps(planted), encoding="utf-8")

        assert client.get("/api/v1/ui-focus/snapshot.png").status_code == 404
        wit = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "wythe_what_is_this", "arguments": {"include_image": True}},
            },
        ).json()
        assert len(wit["result"]["content"]) == 1
        r_focus = client.post(
            "/api/v1/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "wythe://wythe/ui-focus"}},
        ).json()
        assert len(r_focus["result"]["contents"]) == 1

        # M1(b): Symlinked `ui_focus_latest.png -> outside_secret` is also rejected
        (focus_dir / "ui_focus_latest.png").symlink_to(outside_secret)
        assert client.get("/api/v1/ui-focus/snapshot.png").status_code == 404
        (focus_dir / "ui_focus_latest.png").unlink()

        # M11: Non-object `params` returns JSON-RPC `-32602` over HTTP and stdio keeps serving
        for bad_msg in (
            {"jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": ["wythe://wythe/llms"]},
            {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": "bad"},
            {"jsonrpc": "2.0", "id": 12, "method": "initialize", "params": "bad"},
        ):
            r_bad = client.post("/api/v1/mcp", json=bad_msg)
            assert r_bad.status_code == 200
            assert r_bad.json()["error"]["code"] == -32602

        # L6: Invalid resource path returns `-32602` WITHOUT invoking `run_target_scan`; missing slug returns `-32002`
        scans_run: list[str] = []
        orig_scan = mcp_service.run_target_scan

        def _counted_scan(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            scans_run.append("scan")
            return orig_scan(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(mcp_service, "run_target_scan", _counted_scan)
        r_trav = client.post(
            "/api/v1/mcp",
            json={"jsonrpc": "2.0", "id": 13, "method": "resources/read", "params": {"uri": "wythe://wythe/../../etc/passwd"}},
        ).json()
        assert r_trav["error"]["code"] == -32602
        assert len(scans_run) == 0

        r_unknown_slug = client.post(
            "/api/v1/mcp",
            json={"jsonrpc": "2.0", "id": 14, "method": "resources/read", "params": {"uri": "wythe://no-such-target/llms"}},
        ).json()
        assert r_unknown_slug["error"]["code"] == -32002

    # M11 stdio server keeps serving after malformed `params`
    stdio_in = io.BytesIO(
        b'{"jsonrpc":"2.0","id":20,"method":"resources/read","params":["bad"]}\n'
        b'{"jsonrpc":"2.0","id":21,"method":"ping"}\n'
    )
    stdio_out = io.BytesIO()
    mcp_service.run_mcp_stdio_server(stdin=stdio_in, stdout=stdio_out, slice_mode="slm")
    lines = [json.loads(ln) for ln in stdio_out.getvalue().decode("utf-8").strip().splitlines()]
    assert len(lines) == 2
    assert lines[0]["error"]["code"] == -32602
    assert lines[1]["result"] == {}
