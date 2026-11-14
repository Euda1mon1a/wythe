"""Tests for token-budgeted `llms.txt`, surgical 3-tier Lineage Cone slicer, and stdio MCP server."""

from __future__ import annotations

import http.server
import io
import json
import threading

from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.main import create_app
from app.services.mcp_service import run_mcp_stdio_server
from app.services.on_device_llm_service import _select_safe_seat_model


def test_llms_txt_brief_and_context_cone_over_http_and_cli(isolated_db_url: str) -> None:
    """Verify `/llms`, `/llms.txt`, `/context`, and CLI `llms`/`context` subcommands."""
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        brief_resp = client.get("/api/v1/scans/wythe/llms?max_tokens=1500")
        assert brief_resp.status_code == 200
        brief = brief_resp.json()
        assert brief["target_slug"] == "wythe"
        assert brief["approx_tokens"] <= 1600
        assert "## Tier 1 — Database Truth & Ephemeral Queue Pointers" in brief["markdown"]
        assert "atlas_rule_policies" in brief["markdown"]

        txt_resp = client.get("/api/v1/scans/wythe/llms.txt")
        assert txt_resp.status_code == 200
        assert txt_resp.headers["content-type"].startswith("text/plain")
        assert "# Wythe" in txt_resp.text

        cone_resp = client.get("/api/v1/scans/wythe/context?q=atlas_rule_policies")
        assert cone_resp.status_code == 200
        cone = cone_resp.json()
        assert any("atlas_rule_policies" in sid for sid in cone["matched_seed_ids"])
        assert len(cone["manipulator_nodes"]) >= 1
        assert len(cone["upstream_display_nodes"]) >= 1
        assert "3-Tier Lineage Cone" in cone["markdown"]

        miss_resp = client.get("/api/v1/scans/wythe/context?q=nonexistent_rule_xyz")
        assert miss_resp.status_code == 200
        assert miss_resp.json()["matched_seed_ids"] == []

    assert cli_main(["llms", "wythe", "--max-tokens", "1200"]) == 0
    assert cli_main(["context", "wythe", "atlas_rule_policies"]) == 0
    assert cli_main(["context", "wythe", "totally_nonexistent_symbol_999"]) == 1


def test_mcp_stdio_server_jsonlines_and_content_length(isolated_db_url: str) -> None:
    """Verify read-only MCP server handles initialize, tools/list, and tools/call framings."""
    assert isolated_db_url.startswith("sqlite:")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "wythe_overview", "arguments": {"target": "wythe", "max_tokens": 1200}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "wythe_lineage_cone",
                "arguments": {"target": "wythe", "query": "governance_service"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "wythe_blast_radius", "arguments": {"target": "wythe", "base_ref": "HEAD"}},
        },
    ]

    # Mix JSON-lines for requests 1..5 and Content-Length framing for request 6
    buf_in = io.BytesIO()
    for req in requests[:-1]:
        buf_in.write((json.dumps(req) + "\n").encode("utf-8"))
    last_bytes = json.dumps(requests[-1]).encode("utf-8")
    buf_in.write(f"Content-Length: {len(last_bytes)}\r\n\r\n".encode("ascii") + last_bytes)
    buf_in.seek(0)

    buf_out = io.BytesIO()
    assert run_mcp_stdio_server(stdin=buf_in, stdout=buf_out) == 0

    raw_out = buf_out.getvalue().decode("utf-8")
    assert '"name":"wythe"' in raw_out
    assert '"wythe_lineage_cone"' in raw_out
    assert '"wythe_what_is_this"' in raw_out
    assert "3-Tier Lineage Cone" in raw_out
    assert "Diff Blast Radius" in raw_out


def test_ui_focus_bridge_http_cli_and_mcp_what_is_this(isolated_db_url: str) -> None:
    """Verify zero-copy-paste Human <-> Vision/MCP Bridge across HTTP, CLI, and MCP."""
    assert isolated_db_url.startswith("sqlite:")
    tiny_png = (
        "data:image/png;base64,"
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )
    app = create_app()
    with TestClient(app) as client:
        sync_resp = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "wythe",
                "active_tab": "3d",
                "selected_node_id": "t:atlas_rule_policies",
                "lens": "contention",
                "layout_mode": "cluster",
                "connected_only": True,
                "neighborhood_hops": 2,
                "blast_mode": "off",
                "diff_base_ref": "HEAD~1",
                "snapshot_data_url": tiny_png,
            },
        )
        assert sync_resp.status_code == 200
        ack = sync_resp.json()
        assert ack["has_snapshot"] is True

        exp_resp = client.get("/api/v1/ui-focus")
        assert exp_resp.status_code == 200
        exp = exp_resp.json()
        assert exp["active_slug"] == "wythe"
        assert exp["focused_node"]["label"] == "atlas_rule_policies"
        assert exp["has_snapshot"] is True
        assert "atlas_rule_policies" in exp["markdown_brief"]
        assert "Connected only: `True` | Neighborhood hops: `2`" in exp["markdown_brief"]
        invalid = client.post(
            "/api/v1/ui-focus", json={"active_slug": "wythe", "neighborhood_hops": 3}
        )
        assert invalid.status_code == 422

        snap_resp = client.get("/api/v1/ui-focus/snapshot.png")
        assert snap_resp.status_code == 200
        assert snap_resp.headers["content-type"] == "image/png"

    assert cli_main(["focus"]) == 0
    assert cli_main(["focus", "--json"]) == 0

    mcp_req = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": "wythe_what_is_this", "arguments": {"include_image": True}},
    }
    buf_in = io.BytesIO((json.dumps(mcp_req) + "\n").encode("utf-8"))
    buf_out = io.BytesIO()
    assert run_mcp_stdio_server(stdin=buf_in, stdout=buf_out) == 0
    mcp_resp = json.loads(buf_out.getvalue().decode("utf-8").strip())
    blocks = mcp_resp["result"]["content"]
    assert len(blocks) == 2
    assert blocks[0]["type"] == "text"
    assert "atlas_rule_policies" in blocks[0]["text"]
    assert blocks[1]["type"] == "image"
    assert blocks[1]["mimeType"] == "image/png"


def test_streamable_http_mcp_single_and_batch(isolated_db_url: str) -> None:
    """Verify `/api/v1/mcp` Streamable HTTP discovery, notification 202, and JSON-RPC batch."""
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        manifest = client.get("/api/v1/mcp")
        assert manifest.status_code == 200
        mjson = manifest.json()
        assert mjson["transport"] == "streamable-http"
        assert any(t["name"] == "wythe_what_is_this" for t in mjson["tools"])

        notif = client.post(
            "/api/v1/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert notif.status_code == 202

        batch = client.post(
            "/api/v1/mcp",
            json=[
                {"jsonrpc": "2.0", "id": 10, "method": "ping"},
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {"name": "wythe_list_targets", "arguments": {}},
                },
            ],
        )
        assert batch.status_code == 200
        items = batch.json()
        assert len(items) == 2
        assert items[0]["id"] == 10
        assert "wythe" in items[1]["result"]["content"][0]["text"]


def test_on_device_ask_engines_ssrf_guard_and_mock_local_v1(isolated_db_url: str) -> None:
    """Verify `/api/v1/ask/engines`, non-private SSRF refusal, and `/api/v1/ask` local `/v1`."""
    assert isolated_db_url.startswith("sqlite:")
    captured_bodies: list[dict] = []

    class MockOpenAIHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                body = json.dumps(
                    {"object": "list", "data": [{"id": "qwen3-vl-mock-4bit", "object": "model"}]}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            raw = json.loads(self.rfile.read(length).decode("utf-8"))
            captured_bodies.append(raw)
            reply = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": "Table `atlas_rule_policies` stores rule governance rows cleanly."
                        },
                    }
                ]
            }
            out = json.dumps(reply).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockOpenAIHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    try:
        app = create_app()
        with TestClient(app) as client:
            ssrf = client.get("/api/v1/ask/engines?local_base_url=https://example.com/v1")
            assert ssrf.status_code == 200
            local_entry = next(e for e in ssrf.json()["engines"] if e["engine"] == "local")
            assert local_entry["state"] == "unavailable"
            assert "private" in local_entry["note"].lower() or "loopback" in local_entry["note"].lower()

            tiny_png = (
                "data:image/png;base64,"
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            )
            client.post(
                "/api/v1/ui-focus",
                json={
                    "active_slug": "wythe",
                    "selected_node_id": "t:atlas_rule_policies",
                    "snapshot_data_url": tiny_png,
                },
            )
            ask_res = client.post(
                "/api/v1/ask",
                json={
                    "question": "What is this table?",
                    "engine": "local",
                    "target_slug": "wythe",
                    "local_base_url": f"http://127.0.0.1:{port}/v1",
                    "include_vision_snapshot": True,
                },
            )
            assert ask_res.status_code == 200
            ans = ask_res.json()
            assert ans["engine_used"] == "local"
            assert ans["model_id"] == "qwen3-vl-mock-4bit"
            assert ans["used_vision_snapshot"] is True
            assert "t:atlas_rule_policies" in ans["referenced_node_ids"]
            assert captured_bodies[0]["chat_template_kwargs"] == {"enable_thinking": False}
    finally:
        srv.shutdown()
        srv.server_close()


def test_select_safe_seat_model_prevents_mlx_lm_weight_swaps() -> None:
    """Ensure multi-dir `mlx_lm.server` seats use `default_model` while pinned proxies keep their ID."""
    mlx_multi_cache_items = [
        {"id": "mlx-community/FLUX.1-schnell-4bit", "owned_by": "organization_owner"},
        {"id": "mlx-community/Phi-4-mini-instruct-4bit", "owned_by": "organization_owner"},
        {
            "id": "/Users/owner/.cache/huggingface/hub/models--mlx-community--Qwen3.6-35B-A3B-4bit/snapshots/38740b84",
            "owned_by": "organization_owner",
        },
    ]
    assert _select_safe_seat_model(mlx_multi_cache_items, None) == (
        "default_model",
        "mlx-community/Qwen3.6-35B-A3B-4bit",
    )

    pinned_vlm_seat = [
        {"id": "mlx-community/gemma-4-26b-a4b-it-4bit", "owned_by": "pinned-model-proxy"},
    ]
    assert _select_safe_seat_model(pinned_vlm_seat, None) == (
        "mlx-community/gemma-4-26b-a4b-it-4bit",
        "mlx-community/gemma-4-26b-a4b-it-4bit",
    )

    ocr_and_embed_only = [
        {"id": "mlx-community/PaddleOCR-VL-1.5-8bit"},
        {"id": "mlx-community/all-MiniLM-L6-v2-4bit"},
    ]
    assert _select_safe_seat_model(ocr_and_embed_only, None) is None

    unpinned_mlx_vlm_ocr = [
        {"id": "mlx-community/PaddleOCR-VL-1.5-8bit", "created": 1774905518},
        {"id": "mlx-community/Qwen3.6-35B-A3B-4bit", "created": 1782796936},
    ]
    assert _select_safe_seat_model(unpinned_mlx_vlm_ocr, None, server_header="mlx_vlm/0.6.17") is None
    assert _select_safe_seat_model(unpinned_mlx_vlm_ocr, None) is None


def test_realtime_selected_priority_live_frustum_webp_and_multiturn_history(isolated_db_url: str) -> None:
    """Verify selected beats hover, WebP inline frame works, and multi-turn history flows to /v1."""
    assert isolated_db_url.startswith("sqlite:")
    captured: list[dict] = []

    class MockVlmHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                body = json.dumps(
                    {
                        "object": "list",
                        "data": [{"id": "mlx-community/gemma-4-26b-a4b-it-4bit", "owned_by": "pinned-model-proxy"}],
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
            captured.append(raw)
            out = json.dumps(
                {"choices": [{"finish_reason": "stop", "message": {"content": "Confirmed `atlas_rule_policies`."}}]}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockVlmHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        app = create_app()
        with TestClient(app) as client:
            client.post(
                "/api/v1/ui-focus",
                json={
                    "active_slug": "wythe",
                    "selected_node_id": "t:atlas_rule_policies",
                    "hovered_node_id": "t:atlas_scan_snapshots",
                    "in_frustum_count": 14,
                    "live_viewport_brief": "### Live 3D Camera Frustum\n- **Red / Crimson**: 2 nodes on screen",
                },
            )
            exp = client.get("/api/v1/ui-focus").json()
            assert exp["focused_node"]["id"] == "t:atlas_rule_policies"
            assert "Cursor Also Hovering" in exp["markdown_brief"]
            assert "Red / Crimson" in exp["markdown_brief"]

            fake_webp = "data:image/webp;base64,UklGRhIAAABXRUJQVlA4TAYAAAAvAAAAAAfQ//73v/+BiOh/AAA="
            res = client.post(
                "/api/v1/ask",
                json={
                    "question": "And what about now?",
                    "engine": "local",
                    "target_slug": "wythe",
                    "local_base_url": f"http://127.0.0.1:{port}/v1",
                    "history": [
                        {"role": "user", "content": "What did I click?"},
                        {"role": "assistant", "content": "You clicked atlas_rule_policies."},
                    ],
                    "snapshot_data_url": fake_webp,
                },
            )
            assert res.status_code == 200
            assert res.json()["used_vision_snapshot"] is True
            msgs = captured[0]["messages"]
            assert len(msgs) == 4
            assert msgs[1]["role"] == "user" and "What did I click?" in msgs[1]["content"]
            assert msgs[3]["content"][1]["image_url"]["url"].startswith("data:image/webp;base64,")
    finally:
        srv.shutdown()
        srv.server_close()



