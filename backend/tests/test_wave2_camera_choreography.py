"""Wave 2 (#86 + #88 hook): MCP camera choreography, SSE viewport bus, and ChronicleFrame tests."""

from __future__ import annotations

import asyncio
import io
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import create_app
from app.schemas.atlas import (
    ChronicleFrame,
    TourKeyframe,
    ViewportCommand,
    sanitize_viewport_plain_text,
)
from app.services.mcp_service import (
    MCP_SLM_TOOLS,
    MCP_TOOLS,
    dispatch_mcp_request,
    run_mcp_stdio_server,
)
from app.services.scanner_service import run_target_scan
from app.services.viewport_service import (
    VIEWPORT_RING_MAXLEN,
    build_viewport_permalink,
    publish_viewport_command,
    reset_viewport_bus,
    stream_viewport_events,
)


@pytest.fixture(autouse=True)
def _clean_viewport_bus() -> Any:
    reset_viewport_bus()
    yield
    reset_viewport_bus()


def _create_mini_three_tier_repo(repo_dir: Path) -> Path:
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True)
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE orders (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  total_cents INTEGER NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "service.py").write_text(
        "def record_order(db):\n"
        '    db.execute("SELECT id, total_cents FROM orders")\n'
        '    db.execute("INSERT INTO orders (total_cents) VALUES (100)")\n'
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.service import record_order\n\n"
        "app = FastAPI()\n\n"
        '@app.post("/api/v1/orders")\n'
        "def post_order():\n"
        "    return record_order(None)\n",
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function OrdersPage() {\n"
        "  async function submit() {\n"
        "    await fetch('/api/v1/orders', { method: 'POST' });\n"
        "  }\n"
        '  return <button type="button" onClick={submit}>Submit order</button>;\n'
        "}\n",
        encoding="utf-8",
    )
    git_env = {
        "GIT_AUTHOR_NAME": "Test Bot",
        "GIT_AUTHOR_EMAIL": "bot@example.invalid",
        "GIT_COMMITTER_NAME": "Test Bot",
        "GIT_COMMITTER_EMAIL": "bot@example.invalid",
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial fixture"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        env=git_env,
    )
    return repo_dir


def _parse_sse_events(raw_body: str) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for block in raw_body.split("\n\n"):
        lines = [ln for ln in block.splitlines() if ln and not ln.startswith(":")]
        if not lines:
            continue
        frame: dict[str, Any] = {}
        for ln in lines:
            if ln.startswith("id: "):
                frame["id"] = int(ln.removeprefix("id: ").strip())
            elif ln.startswith("event: "):
                frame["event"] = ln.removeprefix("event: ").strip()
            elif ln.startswith("data: "):
                frame["data"] = json.loads(ln.removeprefix("data: ").strip())
        if frame:
            frames.append(frame)
    return frames


def _extract_fenced_json(markdown_text: str) -> dict[str, Any]:
    match = re.search(r"```json\s*(\{[\s\S]+?\})\s*```", markdown_text)
    assert match is not None, f"Expected fenced JSON block in:\n{markdown_text}"
    return json.loads(match.group(1))


def test_strict_schemas_xss_sanitization_and_coordinate_smuggling_rejection() -> None:
    """Verify StrictSchema extra-field rejection, XSS rejection/stripping, and semantic-ID-only enforcement."""
    # 1. Benign HTML tags stripped cleanly while Wythe `<->` and `->` arrows stay intact
    cmd = ViewportCommand(
        target_slug="wythe",
        focus_node_ids=["t:orders"],
        highlight_edge_ids=["e:d:page.tsx->r:post:/api/v1/orders:mutates_endpoint"],
        framing_preset="wythe_cross_section",
        z_wythe_slice="z0_blueprint",
        zoom_stratum=2,
        caption="  <b>Truth <-> Manipulate <-> Display</b> <img src='x'> <svg><g/></svg> <tag>  ",
        tour_keyframes=[
            TourKeyframe(
                step_index=0,
                title="<span>Step 1: Z=0 -> Z=2</span> <img src=a",
                focus_node_ids=["t:orders"],
                caption="<i>Clean plain text</i>",
            )
        ],
        chronicle_frames=[
            ChronicleFrame(
                phase_index=0,
                phase_key="[1.Load]",
                phase_label="<div>Phase 1: Truth -> Manipulate</div>",
                tier="truth",
                focus_node_ids=["t:orders"],
                substeps=["<b>Read schema</b>", "Verify <tag>columns"],
            )
        ],
    )
    assert cmd.caption == "Truth <-> Manipulate <-> Display"
    assert cmd.tour_keyframes[0].title == "Step 1: Z=0 -> Z=2"
    assert cmd.tour_keyframes[0].caption == "Clean plain text"
    assert cmd.chronicle_frames[0].phase_label == "Phase 1: Truth -> Manipulate"
    assert cmd.chronicle_frames[0].substeps == ["Read schema", "Verify columns"]

    # 2. `<script>`, nested `<scr<tag>ipt>`, `javascript:`, and `onerror=` rejected with ValidationError
    for bad_text in (
        "<script>alert(1)</script>",
        "<scr<tag>ipt>alert(1)</script>",
        "Click javascript:alert(1)",
        "java<b></b>script:void(0)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ):
        with pytest.raises(ValidationError):
            ViewportCommand(target_slug="wythe", caption=bad_text)
        with pytest.raises(ValidationError):
            TourKeyframe(step_index=0, title=bad_text)
        with pytest.raises(ValidationError):
            ChronicleFrame(
                phase_index=0,
                phase_key="p1",
                phase_label=bad_text,
                tier="manipulate",
            )
        with pytest.raises(ValidationError):
            ChronicleFrame(
                phase_index=0,
                phase_key="p1",
                phase_label="Clean label",
                tier="manipulate",
                substeps=[bad_text],
            )

    # 3. Raw numeric coordinates rejected in extra fields AND inside semantic ID lists
    with pytest.raises(ValidationError):
        ViewportCommand.model_validate(
            {"target_slug": "wythe", "camera_position": [10.0, 20.0, 30.0]}
        )
    with pytest.raises(ValidationError):
        TourKeyframe.model_validate({"step_index": 0, "title": "Bad", "x": 1.0, "y": 2.0, "z": 3.0})

    for coord_smuggle in (
        "12.0,40.0,-9.0",
        "[10, 20, 30]",
        "(1.5, 2.5, 3.5)",
        "x=10,y=20,z=30",
        "camera_position:1,2,3",
        "42",
    ):
        with pytest.raises(ValidationError):
            ViewportCommand(target_slug="wythe", focus_node_ids=[coord_smuggle])
        with pytest.raises(ValidationError):
            ViewportCommand(target_slug="wythe", highlight_edge_ids=[coord_smuggle])
        with pytest.raises(ValidationError):
            ViewportCommand(target_slug="wythe", finding_id=coord_smuggle)


def test_permalink_determinism_and_canonical_key_order() -> None:
    """Verify canonical key order, unset-key omission, and byte-identical determinism."""
    minimal = ViewportCommand(target_slug="wythe")
    assert (
        build_viewport_permalink(minimal)
        == "http://127.0.0.1:8780/#target=wythe&preset=iso_overview&zoom=1"
    )
    assert build_viewport_permalink(minimal, base_origin="") == "/#target=wythe&preset=iso_overview&zoom=1"

    full_a = ViewportCommand(
        target_slug="shop-alpha",
        focus_node_ids=["t:orders", "r:post:/api/v1/orders", "t:orders"],
        highlight_edge_ids=["e:d:page->r:orders:mutates_endpoint"],
        lens="contention",
        layout_mode="lifecycle_z",
        framing_preset="corridor_trace",
        z_wythe_slice="z2_runtime",
        zoom_stratum=3,
    )
    full_b = ViewportCommand(**full_a.model_dump())
    link_a = build_viewport_permalink(full_a)
    link_b = build_viewport_permalink(full_b)
    assert link_a == link_b
    assert link_a == (
        "http://127.0.0.1:8780/#"
        "target=shop-alpha"
        "&focus=t%3Aorders,r%3Apost%3A%2Fapi%2Fv1%2Forders"
        "&edges=e%3Ad%3Apage-%3Er%3Aorders%3Amutates_endpoint"
        "&lens=contention"
        "&layout=lifecycle_z"
        "&preset=corridor_trace"
        "&z=z2_runtime"
        "&zoom=3"
    )


def test_viewport_http_command_state_ring_buffer_and_sse_isolation(
    isolated_db_url: str,
) -> None:
    """Verify POST /command, GET /state, GET /events SSE scoping, live delivery, and 64-item ring cap."""
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        # 1. Invalid XSS or coordinate payloads return 422
        bad_xss = client.post(
            "/api/v1/viewport/command",
            json={"target_slug": "shop-a", "caption": "<script>evil()</script>"},
        )
        assert bad_xss.status_code == 422

        bad_coord = client.post(
            "/api/v1/viewport/command",
            json={"target_slug": "shop-a", "focus_node_ids": ["10.0, 20.0, 30.0"]},
        )
        assert bad_coord.status_code == 422

        # 2. Publish broadcast (`session_id=None`), `tab-1`, `tab-2`, and separate `shop-b` target
        r1 = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "shop-a",
                "focus_node_ids": ["t:orders"],
                "framing_preset": "iso_overview",
                "caption": "Broadcast beat",
            },
        )
        assert r1.status_code == 200
        assert r1.json()["seq"] == 1

        r2 = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "shop-a",
                "session_id": "tab-1",
                "focus_node_ids": ["m:service"],
                "framing_preset": "tier_elevation",
                "caption": "Tab-1 private beat",
            },
        )
        assert r2.status_code == 200
        assert r2.json()["seq"] == 2

        r3 = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "shop-a",
                "session_id": "tab-2",
                "focus_node_ids": ["d:page"],
                "caption": "Tab-2 private beat",
            },
        )
        assert r3.status_code == 200

        r4 = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "shop-b",
                "focus_node_ids": ["t:other"],
                "caption": "Other target beat",
            },
        )
        assert r4.status_code == 200

        # 3. `GET /api/v1/viewport/events?once=true` enforces target_slug + session_id isolation
        sse_tab1 = client.get("/api/v1/viewport/events?target_slug=shop-a&session_id=tab-1&once=true")
        assert sse_tab1.status_code == 200
        assert sse_tab1.headers["content-type"].startswith("text/event-stream")
        ev_tab1 = _parse_sse_events(sse_tab1.text)
        assert [f["id"] for f in ev_tab1] == [1, 2]
        assert all(f["event"] == "viewport_command" for f in ev_tab1)
        assert [f["data"]["command"]["caption"] for f in ev_tab1] == [
            "Broadcast beat",
            "Tab-1 private beat",
        ]

        # Unscoped subscriber on `shop-a` receives ONLY broadcast (`seq=1`), never `tab-1`/`tab-2`
        sse_unscoped = client.get("/api/v1/viewport/events?target_slug=shop-a&once=true")
        ev_unscoped = _parse_sse_events(sse_unscoped.text)
        assert [f["id"] for f in ev_unscoped] == [1]

        # `Last-Event-ID: 1` skips `seq=1` and delivers only `seq=2` to `tab-1`
        sse_resume = client.get(
            "/api/v1/viewport/events?target_slug=shop-a&session_id=tab-1&once=true",
            headers={"Last-Event-ID": "1"},
        )
        assert [f["id"] for f in _parse_sse_events(sse_resume.text)] == [2]

        # Empty target returns cleanly without hanging
        sse_empty = client.get("/api/v1/viewport/events?target_slug=unused-target&once=true")
        assert sse_empty.status_code == 200
        assert _parse_sse_events(sse_empty.text) == []

        # 4. `GET /api/v1/viewport/state` mirrors scoping and `since_seq`
        st_tab1 = client.get("/api/v1/viewport/state?target_slug=shop-a&session_id=tab-1&since_seq=1").json()
        assert st_tab1["latest"]["seq"] == 2
        assert [e["seq"] for e in st_tab1["history"]] == [2]

        # 5. Ring buffer caps at `VIEWPORT_RING_MAXLEN` (64)
        for idx in range(70):
            client.post(
                "/api/v1/viewport/command",
                json={"target_slug": "ring-target", "caption": f"Step {idx}"},
            )
        st_ring = client.get("/api/v1/viewport/state?target_slug=ring-target").json()
        assert len(st_ring["history"]) == VIEWPORT_RING_MAXLEN == 64
        assert st_ring["history"][0]["command"]["caption"] == "Step 6"
        assert st_ring["latest"]["command"]["caption"] == "Step 69"

    # 6. Verify live async SSE `once=False` queue wakeup and clean subscriber teardown
    async def _exercise_live_stream() -> None:
        disconnected = False

        async def _check_disc() -> bool:
            return disconnected

        agen = stream_viewport_events(
            "live-target",
            session_id="live-tab",
            once=False,
            is_disconnected=_check_disc,
        )
        first_comment = await anext(agen)
        assert first_comment.startswith(": viewport-bus connected")

        ack = publish_viewport_command(
            ViewportCommand(
                target_slug="live-target",
                session_id="live-tab",
                focus_node_ids=["t:orders"],
                caption="Live pushed beat",
            )
        )
        assert ack.subscriber_count == 1
        live_frame = await anext(agen)
        parsed = _parse_sse_events(live_frame)
        assert len(parsed) == 1
        assert parsed[0]["data"]["command"]["caption"] == "Live pushed beat"
        disconnected = True
        await agen.aclose()

        after_close = publish_viewport_command(
            ViewportCommand(target_slug="live-target", caption="After disconnect")
        )
        assert after_close.subscriber_count == 0

    asyncio.run(_exercise_live_stream())


def test_mcp_stdio_and_http_camera_choreography_slm_budget_and_digest_invariance(
    isolated_db_url: str,
    db_session: Any,
    tmp_path: Path,
) -> None:
    """Verify MCP stdio + HTTP parity, ChronicleFrame[] round-trip, SLM <2,000 B budget, and digest invariance."""
    assert isolated_db_url.startswith("sqlite:")

    # 1. Confirm `MCP_SLM_TOOLS` stays compact at 4 tools and <2,000 UTF-8 bytes (#93 invariant)
    slm_bytes = json.dumps(MCP_SLM_TOOLS, separators=(",", ":")).encode("utf-8")
    assert len(MCP_SLM_TOOLS) == 4
    assert len(slm_bytes) < 2000

    # Confirm `wythe_focus_camera` & `wythe_camera_tour` annotations in `MCP_TOOLS`
    by_name = {t["name"]: t for t in MCP_TOOLS}
    for cam_tool in ("wythe_focus_camera", "wythe_camera_tour"):
        assert cam_tool in by_name
        assert by_name[cam_tool]["annotations"] == {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }

    repo_dir = _create_mini_three_tier_repo(tmp_path / "cam-orders")
    app = create_app()
    with TestClient(app) as client:
        reg = client.post(
            "/api/v1/targets",
            json={
                "slug": "cam-orders",
                "name": "Camera Orders",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        assert reg.status_code in (200, 201)

    from app.services.governance_service import get_target_by_slug

    target_obj = get_target_by_slug(db_session, "cam-orders")
    assert target_obj is not None
    before_scan = run_target_scan(db_session, target_obj, strict_gate=True, persist_snapshot=False)
    digest_before = before_scan.content_digest

    # 2. Call `wythe_focus_camera` over `run_mcp_stdio_server` (resolving label `orders` -> `t:orders` + warning on missing node)
    stdio_req = {
        "jsonrpc": "2.0",
        "id": 71,
        "method": "tools/call",
        "params": {
            "name": "wythe_focus_camera",
            "arguments": {
                "target": "cam-orders",
                "focus_node_ids": ["orders", "t:nonexistent_ghost"],
                "finding_id": "f:MISSING-999:0",
                "lens": "status",
                "layout_mode": "lifecycle_z",
                "z_wythe_slice": "z0_blueprint",
                "zoom_stratum": 2,
                "framing_preset": "wythe_cross_section",
                "caption": "Inspect <b>orders</b> table lineage",
            },
        },
    }
    in_buf = io.BytesIO((json.dumps(stdio_req) + "\n").encode("utf-8"))
    out_buf = io.BytesIO()
    assert run_mcp_stdio_server(stdin=in_buf, stdout=out_buf) == 0
    stdio_resp = json.loads(out_buf.getvalue().decode("utf-8").strip())
    assert stdio_resp["result"]["isError"] is False
    stdio_md = stdio_resp["result"]["content"][0]["text"]
    assert "Resolved label `orders` -> canonical node ID `t:orders`" in stdio_md
    assert "t:nonexistent_ghost" in stdio_md
    stdio_art = _extract_fenced_json(stdio_md)
    assert stdio_art["focus_node_ids"] == ["t:orders", "t:nonexistent_ghost"]
    assert stdio_art["unresolved_focus_ids"] == ["t:nonexistent_ghost"]
    assert stdio_art["unresolved_finding_ids"] == ["f:MISSING-999:0"]
    assert "#target=cam-orders&focus=t%3Aorders,t%3Anonexistent_ghost" in stdio_art["permalink"]
    assert len(stdio_art["tour_keyframes"]) == 1
    assert stdio_art["tour_keyframes"][0]["caption"] == "Inspect orders table lineage"

    # 3. Call `wythe_camera_tour` + `ChronicleFrame[]` over Streamable HTTP `/api/v1/mcp` and verify SSE bus parity
    chronicle_payload = [
        {
            "phase_index": 0,
            "phase_key": "1.load",
            "phase_label": "[1.Load] Context Ingestion",
            "tier": "truth",
            "focus_node_ids": ["t:orders"],
            "status": "ok",
            "caption": "Read authoritative SQL rows",
            "substeps": ["Fetch orders rows", "Validate schema"],
        },
        {
            "phase_index": 1,
            "phase_key": "2.render",
            "phase_label": "[2.Render] UI Projection",
            "tier": "display",
            "focus_node_ids": ["t:orders"],
            "status": "warning",
            "caption": "Project response to OrdersPage",
            "substeps": ["Render table"],
        },
    ]
    with TestClient(app) as client:
        tour_rpc = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 72,
                "method": "tools/call",
                "params": {
                    "name": "wythe_camera_tour",
                    "arguments": {
                        "target": "cam-orders",
                        "session_id": "review-tab",
                        "tour_keyframes": [
                            {
                                "title": "Beat 1: SQL Table",
                                "focus_node_ids": ["t:orders"],
                                "framing_preset": "iso_overview",
                                "caption": "Authoritative orders table",
                            },
                            {
                                "title": "Beat 2: Cross-Section",
                                "focus_node_ids": ["orders"],
                                "layout_mode": "temporal_z",
                                "z_wythe_slice": "z_head",
                                "framing_preset": "corridor_trace",
                                "caption": "Compare base -> HEAD seam",
                            },
                        ],
                        "chronicle_frames": chronicle_payload,
                    },
                },
            },
        ).json()
        assert tour_rpc["result"]["isError"] is False
        tour_md = tour_rpc["result"]["content"][0]["text"]
        tour_art = _extract_fenced_json(tour_md)
        assert len(tour_art["tour_keyframes"]) == 2
        assert tour_art["tour_keyframes"][0]["step_index"] == 0
        assert tour_art["tour_keyframes"][1]["step_index"] == 1
        assert tour_art["tour_keyframes"][1]["focus_node_ids"] == ["t:orders"]
        assert len(tour_art["chronicle_frames"]) == 2
        assert tour_art["chronicle_frames"][1]["phase_key"] == "2.render"

        # Confirm event landed on SSE `/api/v1/viewport/events` with ChronicleFrame[] intact
        sse_tour = client.get(
            "/api/v1/viewport/events?target_slug=cam-orders&session_id=review-tab&once=true"
        )
        sse_frames = _parse_sse_events(sse_tour.text)
        assert len(sse_frames) == 2  # seq 1 (stdio broadcast) + seq 2 (review-tab tour)
        assert sse_frames[-1]["data"]["permalink"] == tour_art["permalink"]
        assert len(sse_frames[-1]["data"]["command"]["chronicle_frames"]) == 2

        # Reject coordinate smuggling & `<script>` over `/api/v1/mcp`
        for bad_args in (
            {"target": "cam-orders", "camera_position": "1,2,3"},
            {"target": "cam-orders", "caption": "<script>alert(1)</script>"},
        ):
            err_rpc = client.post(
                "/api/v1/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 73,
                    "method": "tools/call",
                    "params": {"name": "wythe_focus_camera", "arguments": bad_args},
                },
            ).json()
            assert err_rpc["result"]["isError"] is True

        # Set active UI focus and verify `dispatch_mcp_request` resolves omitted `target` automatically
        client.post("/api/v1/ui-focus", json={"active_slug": "cam-orders"})

    direct_focus = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 74,
            "method": "tools/call",
            "params": {
                "name": "wythe_focus_camera",
                "arguments": {"focus_node_ids": ["t:orders"], "framing_preset": "tier_elevation"},
            },
        },
    )
    assert direct_focus is not None
    assert direct_focus["result"]["isError"] is False
    assert "#target=cam-orders&focus=t%3Aorders&preset=tier_elevation&zoom=1" in (
        direct_focus["result"]["content"][0]["text"]
    )

    # 4. Confirm scan `content_digest` and git working tree are 100% unchanged
    after_scan = run_target_scan(db_session, target_obj, strict_gate=True, persist_snapshot=False)
    assert after_scan.content_digest == digest_before
    git_stat = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    assert git_stat.stdout.strip() == ""


def test_adversarial_sanitizer_comparison_operators_and_mcp_falsy_type_guards(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
) -> None:
    """Regression suite for #82 items 4 & 5: preserve `a < b`, block deep/null `<script>`, reject falsy non-list/bool MCP args."""
    assert isolated_db_url.startswith("sqlite:")

    # Item 4: Legitimate math/code comparisons stay intact while null-byte & >8-deep nested script tags raise ValueError
    assert sanitize_viewport_plain_text("a < b") == "a < b"
    assert sanitize_viewport_plain_text("if a < b and c > d") == "if a < b and c > d"
    assert sanitize_viewport_plain_text("list[str] <-> dict[str, int]") == "list[str] <-> dict[str, int]"

    for malicious in (
        "<\x00script>alert(1)</script>",
        "java\x00script:alert(1)",
        "<scr<a<b<c<d<e<f<g<h<i<j>i>h>g>f>e>d>c>b>a>ipt>alert(1)</script>",
        "< script>alert(1)</script>",
    ):
        with pytest.raises(ValueError):
            sanitize_viewport_plain_text(malicious)

    # Item 5: Reject bool for zoom_stratum / step_index / phase_index in Pydantic models
    with pytest.raises(ValidationError):
        ViewportCommand(target_slug="demo", zoom_stratum=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        TourKeyframe(step_index=0, title="Beat", zoom_stratum=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        TourKeyframe(step_index=True, title="Beat")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ChronicleFrame(phase_index=True, phase_key="p1", phase_label="P1", tier="truth")  # type: ignore[arg-type]

    # Item 5: Reject falsy non-list/non-str MCP arguments (`False`, `0`, `{}`) with isError=True
    repo_dir = _create_mini_three_tier_repo(tmp_path / "falsy-guard-app")
    for idx, bad_args in enumerate(
        (
            {"target": str(repo_dir), "focus_node_ids": False},
            {"target": str(repo_dir), "highlight_edge_ids": 0},
            {"target": str(repo_dir), "chronicle_frames": {}},
            {"target": str(repo_dir), "caption": False},
            {"target": str(repo_dir), "zoom_stratum": True},
        ),
        start=200,
    ):
        resp = dispatch_mcp_request(
            db_session,
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": "wythe_focus_camera", "arguments": bad_args},
            },
        )
        assert resp is not None
        assert resp["result"]["isError"] is True, f"Expected isError=True for {bad_args}"
