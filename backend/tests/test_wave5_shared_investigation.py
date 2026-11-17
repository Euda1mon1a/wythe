"""Wave 5 tests: shared human-agent investigation, receipts, citations, scan reuse, and MCP continuity."""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.adapters.plugin_registry import discover_plugins
from app.main import create_app
from app.services import on_device_llm_service
from app.services.governance_service import get_target_by_slug
from app.services.investigation_service import (
    MAX_INVESTIGATION_SESSIONS,
    build_evidence_identity,
    clear_scan_reuse_cache,
    get_or_run_cached_scan,
    get_scan_cache_stats,
)
from app.services.mcp_service import MCP_SLM_TOOLS, MCP_TOOLS
from app.services.ui_focus_service import explain_ui_focus
from app.services.viewport_service import publish_viewport_command, stream_viewport_events

TINY_PNG_A = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)
TINY_WEBP_B = "data:image/webp;base64,UklGRhIAAABXRUJQVlA4TAYAAAAvAAAAAAfQ//73v/+BiOh/AAA="


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _write_synthetic_policy_repo(repo_dir: Path, *, init_git: bool = True) -> Path:
    """Create a synthetic 3-tier FastAPI + SQL + Next.js repo with a bypassed policy column and helper."""
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True)

    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE quota_policies (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  scope_name TEXT NOT NULL,\n"
        "  max_hours_limit INTEGER NOT NULL,\n"
        "  cooldown_minutes INTEGER NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "helper_calc.py").write_text(
        "def format_quota_banner(label: str) -> str:\n"
        "    return f'Quota: {label}'\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "quota_service.py").write_text(
        "from app.helper_calc import format_quota_banner\n\n"
        "HARDCODED_MAX_HOURS = 80\n\n"
        "def evaluate_quota(db):\n"
        '    row = db.execute("SELECT id, scope_name, max_hours_limit FROM quota_policies").fetchone()\n'
        "    effective_cap = HARDCODED_MAX_HOURS\n"
        "    return {'cap': effective_cap, 'banner': format_quota_banner(row.scope_name)}\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.quota_service import evaluate_quota\n\n"
        "app = FastAPI()\n\n"
        '@app.get("/api/v1/quotas")\n'
        "def get_quotas():\n"
        "    return evaluate_quota(None)\n",
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
    if init_git:
        git_env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Euda1mon1a",
            "GIT_AUTHOR_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
            "GIT_COMMITTER_NAME": "Euda1mon1a",
            "GIT_COMMITTER_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        }
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True, env=git_env)
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True, env=git_env)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "Initial synthetic repo"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            env=git_env,
        )
    return repo_dir


def _register_repo(client: TestClient, slug: str, repo_dir: Path) -> None:
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


def test_evidence_identity_git_vs_nongit_and_fast_scan_reuse_cache(
    isolated_db_url: str,
    db_session: Any,
    tmp_path: Path,
) -> None:
    """Verify non-Git `non_git:<sha256>` identity, deterministic revision hash, and <15ms scan reuse."""
    assert isolated_db_url.startswith("sqlite:")
    git_repo = _write_synthetic_policy_repo(tmp_path / "git-quotas", init_git=True)
    nongit_repo = _write_synthetic_policy_repo(tmp_path / "nongit-quotas", init_git=False)

    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "git-quotas", git_repo)
        _register_repo(client, "nongit-quotas", nongit_repo)

    t_git = get_target_by_slug(db_session, "git-quotas")
    t_nongit = get_target_by_slug(db_session, "nongit-quotas")
    assert t_git is not None and t_nongit is not None

    clear_scan_reuse_cache()
    rep_nongit = get_or_run_cached_scan(db_session, t_nongit)
    ev_nongit = build_evidence_identity(rep_nongit)
    assert ev_nongit.source_commit.startswith("non_git:")
    assert ev_nongit.content_tree_sha256 is not None
    assert len(ev_nongit.content_tree_sha256) == 64
    assert ev_nongit.source_commit == f"non_git:{ev_nongit.content_tree_sha256}"
    assert ev_nongit.evidence_revision_id.startswith("ev_")
    src_kinds = {s.kind for s in ev_nongit.evidence_sources}
    assert "source_static" in src_kinds

    # Verify deterministic evidence_revision_id and <15ms cached focus reads with 0 redundant rescans
    clear_scan_reuse_cache()
    first_rep = get_or_run_cached_scan(db_session, t_git)
    ev_first = build_evidence_identity(first_rep)
    stats_after_cold = get_scan_cache_stats()
    assert stats_after_cold == {"hits": 0, "misses": 1}

    t0 = time.perf_counter()
    for _ in range(5):
        exp = explain_ui_focus(db_session, target_override="git-quotas")
        assert exp.evidence_revision_id == ev_first.evidence_revision_id
    avg_ms = ((time.perf_counter() - t0) * 1000.0) / 5.0
    stats_after_warm = get_scan_cache_stats()
    assert stats_after_warm["misses"] == 1
    assert stats_after_warm["hits"] == 5
    assert avg_ms < 15.0, f"Expected cached focus read < 15ms, got {avg_ms:.2f}ms"

    # Modify worktree file -> cache invalidates automatically and produces new evidence_revision_id
    (git_repo / "backend" / "app" / "helper_calc.py").write_text(
        "def format_quota_banner(label: str) -> str:\n    return f'Updated: {label}'\n",
        encoding="utf-8",
    )
    edited_rep = get_or_run_cached_scan(db_session, t_git)
    ev_edited = build_evidence_identity(edited_rep)
    assert ev_edited.evidence_revision_id != ev_first.evidence_revision_id
    assert get_scan_cache_stats()["misses"] == 2


def test_multitab_focus_isolation_ambiguity_and_single_session_convenience(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Verify two browser tabs on one target never overwrite focus/snapshots and surface ambiguity."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_policy_repo(tmp_path / "tab-demo")
    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "tab-demo", repo_dir)

        # 1. Single tab (`tab-a`) -> zero-config unscoped GET resolves `tab-a` without ambiguity
        ack_a = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "tab-demo",
                "session_id": "tab-a",
                "client_id": "browser-a",
                "selected_node_id": "t:quota_policies",
                "camera_revision": 1,
                "snapshot_data_url": TINY_PNG_A,
            },
        ).json()
        assert ack_a["session_id"] == "tab-a"
        assert ack_a["focus_revision"] == 1
        assert ack_a["snapshot_focus_revision"] == 1
        assert ack_a["snapshot_evidence_revision"].startswith("ev_")

        unscoped_single = client.get("/api/v1/ui-focus?target=tab-demo").json()
        assert unscoped_single["session_id"] == "tab-a"
        assert unscoped_single["ambiguous_session_ids"] == []
        assert unscoped_single["focused_node"]["id"] == "t:quota_policies"
        assert unscoped_single["has_snapshot"] is True

        # 2. Second tab (`tab-b`) opens on same `tab-demo` with different selection + WebP image
        ack_b = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "tab-demo",
                "session_id": "tab-b",
                "client_id": "browser-b",
                "selected_node_id": "m:service:quota_service",
                "active_tab": "accessible",
                "camera_revision": 1,
                "snapshot_data_url": TINY_WEBP_B,
            },
        ).json()
        assert ack_b["session_id"] == "tab-b"
        assert ack_b["snapshot_path"] != ack_a["snapshot_path"]

        # Scoped reads never overwrite each other's node, tab, or image
        exp_a = client.get("/api/v1/ui-focus?target=tab-demo&session_id=tab-a").json()
        exp_b = client.get("/api/v1/ui-focus?target=tab-demo&session_id=tab-b").json()
        assert exp_a["focused_node"]["id"] == "t:quota_policies"
        assert exp_a["active_tab"] == "3d"
        assert exp_b["focused_node"]["id"] == "m:service:quota_service"
        assert exp_b["active_tab"] == "accessible"

        snap_a = client.get("/api/v1/ui-focus/snapshot.png?session_id=tab-a")
        snap_b = client.get("/api/v1/ui-focus/snapshot.png?session_id=tab-b")
        assert snap_a.status_code == 200 and snap_a.headers["content-type"].startswith("image/png")
        assert snap_b.status_code == 200 and snap_b.headers["content-type"].startswith("image/webp")
        assert client.get("/api/v1/ui-focus/snapshot.png").status_code == 404

        # Unscoped read when >=2 sessions exist reports explicit ambiguity instead of picking a tab
        exp_amb = client.get("/api/v1/ui-focus?target=tab-demo").json()
        assert set(exp_amb["ambiguous_session_ids"]) == {"tab-a", "tab-b"}
        assert exp_amb["focused_node"] is None
        assert exp_amb["has_snapshot"] is False
        assert "Ambiguous Active Sessions Warning" in exp_amb["markdown_brief"]


def test_investigation_lifecycle_retention_corrections_and_governance_isolation(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Verify full `/api/v1/investigations` lifecycle, 64-session retention, and `promoted_to_ruling=False`."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_policy_repo(tmp_path / "inv-lifecycle")
    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "inv-lifecycle", repo_dir)
        rules_before = client.get("/api/v1/rules").json()
        rulings_before = client.get("/api/v1/rulings/inv-lifecycle").json()

        created = client.post(
            "/api/v1/investigations",
            json={
                "target_slug": "inv-lifecycle",
                "session_id": "sess-main",
                "client_id": "tab-1",
                "title": "Quota bypass review",
            },
        )
        assert created.status_code == 200
        sess = created.json()
        assert sess["session_id"] == "sess-main"
        assert sess["follow_state"] == "following"
        assert sess["retention_policy"]["max_sessions"] == MAX_INVESTIGATION_SESSIONS == 64

        # Reopen adds second client_id cleanly
        reopened = client.post(
            "/api/v1/investigations",
            json={"target_slug": "inv-lifecycle", "session_id": "sess-main", "client_id": "tab-3"},
        ).json()
        assert reopened["participating_client_ids"] == ["tab-1", "tab-3"]

        # Record correction -> promoted_to_ruling is False and governance rules/rulings remain untouched
        corr = client.post(
            "/api/v1/investigations/sess-main/corrections",
            json={
                "client_id": "tab-1",
                "actor": "human",
                "target_ref_id": "m:service:quota_service",
                "kind": "tuning_vs_policy",
                "note": "That is an algorithmic tuning value, not domain policy.",
            },
        )
        assert corr.status_code == 200
        assert corr.json()["promoted_to_ruling"] is False
        assert client.get("/api/v1/rules").json() == rules_before
        assert client.get("/api/v1/rulings/inv-lifecycle").json() == rulings_before

        # Persist browser-local turn + pause follow + read delta events + export + reset + delete
        t_res = client.post(
            "/api/v1/investigations/sess-main/turns",
            json={
                "client_id": "tab-1",
                "question": "Why is max_hours_limit bypassed?",
                "answer_markdown": "Service `m:service:quota_service` substitutes `HARDCODED_MAX_HOURS` over `t:quota_policies`.",
                "engine": "chrome",
                "model_id": "gemini-nano",
                "authored_by": "model",
                "referenced_ids": ["t:quota_policies"],
            },
        )
        assert t_res.status_code == 200
        assert t_res.json()["status"] == "answered"
        assert any(
            r["ref_id"] == "t:quota_policies" and r["validation_state"] == "validated"
            for r in t_res.json()["validated_references"]
        )

        f_res = client.post(
            "/api/v1/investigations/sess-main/follow",
            json={"client_id": "tab-1", "follow_state": "paused", "reason": "Manual orbit"},
        )
        assert f_res.status_code == 200
        assert f_res.json()["follow_state"] == "paused"

        deltas = client.get("/api/v1/investigations/sess-main/events?since_revision=1").json()
        event_kinds = [e["event_kind"] for e in deltas["events"]]
        assert "correction_added" in event_kinds
        assert "turn_recorded" in event_kinds
        assert "follow_updated" in event_kinds

        exported = client.get("/api/v1/investigations/sess-main/export")
        assert exported.status_code == 200
        assert exported.json()["session"]["session_id"] == "sess-main"

        reset_s = client.post("/api/v1/investigations/sess-main/reset").json()
        assert reset_s["turns"] == []
        assert reset_s["corrections"] == []
        assert reset_s["follow_state"] == "following"

        assert client.delete("/api/v1/investigations/sess-main").status_code == 200
        assert client.get("/api/v1/investigations/sess-main").status_code == 404

        # Verify bounded retention caps stored sessions at 64
        for idx in range(68):
            client.post(
                "/api/v1/investigations",
                json={"target_slug": "inv-lifecycle", "session_id": f"cap-{idx:03d}"},
            )
        listed = client.get("/api/v1/investigations?target_slug=inv-lifecycle").json()
        assert len(listed["sessions"]) == 64


def test_bidirectional_viewport_delivery_states_idempotency_receipts_and_reconnect(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Verify `accepted_by_service` -> `waiting_for_follow` -> `applied_by_browser`, idempotency, stale, and reload safety."""
    from app.schemas.atlas import ViewportCommand

    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_policy_repo(tmp_path / "vp-receipts")
    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "vp-receipts", repo_dir)
        inv = client.post(
            "/api/v1/investigations",
            json={"target_slug": "vp-receipts", "session_id": "tab-1", "client_id": "browser-1"},
        ).json()
        valid_ev = inv["latest_evidence"]["evidence_revision_id"]

        # 1. Headless publish (no SSE subscriber) -> accepted_by_service (never applied_by_browser!)
        headless_ack = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "vp-receipts",
                "session_id": "tab-1",
                "correlation_id": "walk-1",
                "expected_evidence_revision": valid_ev,
                "focus_node_ids": ["t:quota_policies"],
                "caption": "Step 1",
            },
        ).json()
        assert headless_ack["delivery_state"] == "accepted_by_service"
        assert headless_ack["applied_by_client_ids"] == []
        cmd_id = headless_ack["command_id"]

        # 2. Browser applies and posts receipt -> delivery_state becomes applied_by_browser
        rcpt = client.post(
            "/api/v1/viewport/receipts",
            json={
                "command_id": cmd_id,
                "target_slug": "vp-receipts",
                "session_id": "tab-1",
                "client_id": "browser-1",
                "outcome": "applied",
                "applied_focus_revision": 2,
            },
        )
        assert rcpt.status_code == 200
        assert rcpt.json()["delivery_state"] == "applied_by_browser"
        assert rcpt.json()["applied_by_client_ids"] == ["browser-1"]

        # 3. Idempotent retry with same correlation_id returns existing seq + updated delivery_state
        dup_ack = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "vp-receipts",
                "session_id": "tab-1",
                "correlation_id": "walk-1",
                "focus_node_ids": ["t:quota_policies"],
            },
        ).json()
        assert dup_ack["seq"] == headless_ack["seq"]
        assert dup_ack["idempotent_replay"] is True
        assert dup_ack["delivery_state"] == "applied_by_browser"

        # 4. Stale revision & expired commands never claim delivery
        stale_ack = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "vp-receipts",
                "session_id": "tab-1",
                "expected_evidence_revision": "ev_stale_00000000",
                "focus_node_ids": ["t:quota_policies"],
            },
        ).json()
        assert stale_ack["delivery_state"] == "stale"

        past_ts = (datetime.now(UTC) - timedelta(seconds=30)).isoformat()
        exp_ack = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "vp-receipts",
                "session_id": "tab-1",
                "expires_at": past_ts,
                "focus_node_ids": ["t:quota_policies"],
            },
        ).json()
        assert exp_ack["delivery_state"] == "expired"

        # 5. Human pauses follow -> subsequent command starts as paused_by_human
        client.post(
            "/api/v1/investigations/tab-1/follow",
            json={"client_id": "browser-1", "follow_state": "paused"},
        )
        paused_ack = client.post(
            "/api/v1/viewport/command",
            json={
                "target_slug": "vp-receipts",
                "session_id": "tab-1",
                "focus_node_ids": ["t:quota_policies"],
            },
        ).json()
        assert paused_ack["delivery_state"] == "paused_by_human"

        client.post(
            "/api/v1/investigations/tab-1/follow",
            json={"client_id": "browser-1", "follow_state": "following"},
        )

    # 6. Live SSE stream: fresh reload (`since_seq=0`) does NOT replay historical commands,
    #    and connected subscriber yields `waiting_for_follow` on new command
    async def _check_live_waiting_and_reload() -> None:
        agen = stream_viewport_events("vp-receipts", session_id="tab-1", once=False)
        banner = await anext(agen)
        assert banner.startswith(": viewport-bus connected")

        live_ack = publish_viewport_command(
            ViewportCommand(
                target_slug="vp-receipts",
                session_id="tab-1",
                focus_node_ids=["t:quota_policies"],
                caption="Live while connected",
            )
        )
        assert live_ack.delivery_state == "waiting_for_follow"
        frame = await anext(agen)
        assert "Live while connected" in frame
        await agen.aclose()

    asyncio.run(_check_live_waiting_and_reload())


def test_revision_comparison_vanished_refs_never_rebound(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Verify `/compare` preserves pinned evidence, detects resolved findings, and marks deleted nodes `vanished_in_current_scan`."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_policy_repo(tmp_path / "drift-repo")
    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "drift-repo", repo_dir)
        scan0 = client.get("/api/v1/scans/drift-repo").json()
        helper_node = next(n for n in scan0["nodes"] if "helper_calc" in n["source_file"])
        svc_node = next(n for n in scan0["nodes"] if "quota_service" in n["source_file"])

        inv0 = client.post(
            "/api/v1/investigations",
            json={"target_slug": "drift-repo", "session_id": "drift-s1", "client_id": "tab-1"},
        ).json()
        pinned_rev_0 = inv0["pinned_evidence"]["evidence_revision_id"]

        client.post(
            "/api/v1/investigations/drift-s1/turns",
            json={
                "question": "What uses helper_calc and quota_policies?",
                "answer_markdown": f"Helper `{helper_node['id']}` formats labels for `{svc_node['id']}`.",
                "engine": "local",
                "model_id": "mock-m",
                "referenced_ids": [
                    helper_node["id"],
                    svc_node["id"],
                    "t:quota_policies",
                    "backend/app/main.py:1",
                    "backend/app/helper_calc.py:1",
                ],
            },
        )

        # Modify source on disk: fix bypassed policy column AND remove helper_calc.py entirely
        (repo_dir / "backend" / "app" / "helper_calc.py").unlink()
        (repo_dir / "backend" / "app" / "quota_service.py").write_text(
            "def evaluate_quota(db):\n"
            '    row = db.execute("SELECT id, scope_name, max_hours_limit, cooldown_minutes FROM quota_policies").fetchone()\n'
            "    return {'cap': row.max_hours_limit, 'cooldown': row.cooldown_minutes, 'scope': row.scope_name}\n",
            encoding="utf-8",
        )

        comp = client.get("/api/v1/investigations/drift-s1/compare").json()
        assert comp["digest_changed"] is True
        assert comp["pinned_evidence"]["evidence_revision_id"] == pinned_rev_0
        assert comp["current_evidence"]["evidence_revision_id"] != pinned_rev_0

        vanished_by_id = {v["ref_id"]: v for v in comp["vanished_refs"]}
        assert helper_node["id"] in vanished_by_id
        assert vanished_by_id[helper_node["id"]]["validation_state"] == "vanished_in_current_scan"
        assert "helper_calc.py" in (vanished_by_id[helper_node["id"]]["source_file"] or "")
        assert "backend/app/helper_calc.py:1" in vanished_by_id
        assert "backend/app/main.py:1" not in vanished_by_id

        surviving_or_mod = {
            r["ref_id"] for r in (*comp["surviving_refs"], *comp["modified_refs"])
        }
        assert "t:quota_policies" in surviving_or_mod
        assert "backend/app/main.py:1" in surviving_or_mod
        assert helper_node["id"] not in surviving_or_mod
        assert len(comp["invalidated_turn_ids"]) >= 1

        reloaded = client.get("/api/v1/investigations/drift-s1").json()
        assert reloaded["evidence_drifted"] is True
        assert reloaded["turns"][0]["needs_revalidation"] is True
        reloaded_refs = {r["ref_id"]: r["validation_state"] for r in reloaded["turns"][0]["validated_references"]}
        assert reloaded_refs[helper_node["id"]] == "vanished_in_current_scan"
        assert reloaded_refs["t:quota_policies"] == "historical_needs_revalidation"


def test_authored_ask_corrections_section_budget_validated_refs_and_unavailable_preservation(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Verify `/api/v1/ask` injects corrections, returns section budget & validated citations, and preserves failed questions."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_policy_repo(tmp_path / "ask-repo")
    captured_requests: list[dict[str, Any]] = []

    class _MockLocalModelHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                out = json.dumps({"data": [{"id": "mock-coder-8b", "owned_by": "pinned"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            captured_requests.append(json.loads(self.rfile.read(length).decode("utf-8")))
            reply = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": (
                                "Acknowledging human correction: `HARDCODED_MAX_HOURS` in "
                                "`backend/app/quota_service.py:5` is treated as tuning, while "
                                "`t:quota_policies` and quota_service remain tracked."
                            )
                        },
                    }
                ]
            }
            out = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockLocalModelHandler)
    live_url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(on_device_llm_service, "_default_local_seats", (live_url,))

    try:
        app = create_app()
        with TestClient(app) as client:
            _register_repo(client, "ask-repo", repo_dir)
            client.post(
                "/api/v1/investigations",
                json={"target_slug": "ask-repo", "session_id": "ask-s1", "client_id": "tab-1"},
            )
            client.post(
                "/api/v1/investigations/ask-s1/corrections",
                json={
                    "client_id": "tab-1",
                    "kind": "tuning_vs_policy",
                    "note": "That is an algorithmic tuning value, not domain policy.",
                },
            )

            ok = client.post(
                "/api/v1/ask",
                json={
                    "question": "Why is this limit being ignored?",
                    "engine": "local",
                    "target_slug": "ask-repo",
                    "session_id": "ask-s1",
                    "selected_node_id": "t:quota_policies",
                    "local_base_url": live_url,
                    "include_vision_snapshot": False,
                },
            )
            assert ok.status_code == 200, ok.text
            ans = ok.json()
            assert ans["session_id"] == "ask-s1"
            assert ans["turn_id"].startswith("turn_")
            assert ans["authored_by"] == "model"
            assert ans["image_supplied"] is False
            assert ans["evidence_identity"]["evidence_revision_id"].startswith("ev_")
            assert ans["context_budget"]["included_counts"]["corrections"] == 1

            # Verify human correction actually shaped the model prompt
            sent_user_prompt = str(captured_requests[0]["messages"][-1]["content"])
            assert "algorithmic tuning value, not domain policy" in sent_user_prompt

            # Verify explicit IDs are `validated` while prose label match is `text_convenience`
            refs_by_id = {r["ref_id"]: r for r in ans["validated_references"]}
            assert refs_by_id["t:quota_policies"]["validation_state"] == "validated"
            assert refs_by_id["backend/app/quota_service.py:5"]["validation_state"] == "validated"
            assert any(
                r["validation_state"] == "text_convenience" for r in ans["validated_references"]
            )

            # Now point `/api/v1/ask` at a CLOSED loopback port -> must NOT fall back to `live_url`!
            closed_port = _free_port()
            fail = client.post(
                "/api/v1/ask",
                json={
                    "question": "Does cooldown_minutes reach the response when offline?",
                    "engine": "auto",
                    "target_slug": "ask-repo",
                    "session_id": "ask-s1",
                    "local_base_url": f"http://127.0.0.1:{closed_port}/v1",
                },
            )
            assert fail.status_code == 503

            # Verify question was preserved in `unresolved_questions` and headless MCP still works!
            sess_after = client.get("/api/v1/investigations/ask-s1").json()
            assert len(sess_after["unresolved_questions"]) == 1
            assert (
                sess_after["unresolved_questions"][0]["question"]
                == "Does cooldown_minutes reach the response when offline?"
            )
            assert sess_after["unresolved_questions"][0]["answer_markdown"] is None

            mcp_ok = client.post(
                "/api/v1/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "wythe_what_is_this",
                        "arguments": {"target": "ask-repo", "session_id": "ask-s1"},
                    },
                },
            ).json()
            assert mcp_ok["result"]["isError"] is False
    finally:
        srv.shutdown()
        srv.server_close()


def test_mcp_continuity_slm_budget_investigation_resource_and_plugin_capabilities(
    tmp_path: Path,
) -> None:
    """Verify `<2,000 B` SLM budget, cross-process `wythe mcp` continuity, `wythe://.../investigation/...`, and plugin caps."""
    slm_encoded = json.dumps(MCP_SLM_TOOLS, separators=(",", ":")).encode()
    assert len(MCP_SLM_TOOLS) == 4
    assert len(slm_encoded) < 2000
    assert any(t["name"] == "wythe_investigation" for t in MCP_TOOLS)

    for spec in discover_plugins():
        meta = spec.to_metadata()
        assert isinstance(meta["interaction_capabilities"], list)
        assert "structured_evidence" in meta["interaction_capabilities"]  # type: ignore[operator]
        assert isinstance(meta["unsupported_interaction_capabilities"], list)
        assert isinstance(meta["evidence_source_kinds"], list)

    state_dir = tmp_path / "shared-state"
    state_dir.mkdir()
    repo_dir = _write_synthetic_policy_repo(tmp_path / "mcp-shared")
    backend_root = Path(__file__).resolve().parents[1]
    sub_env = {
        **os.environ,
        "PYTHONPATH": str(backend_root),
        "WYTHE_STATE_DIR": str(state_dir),
        "WYTHE_DATABASE_URL": f"sqlite:///{(state_dir / 'wythe.db').as_posix()}",
    }
    sub_env.pop("WYTHE_SERVER_URL", None)

    # Register target + focus + correction via HTTP app bound to `state_dir`, then read from separate `wythe mcp` process!
    old_db = os.environ.get("WYTHE_DATABASE_URL")
    old_st = os.environ.get("WYTHE_STATE_DIR")
    os.environ["WYTHE_STATE_DIR"] = str(state_dir)
    os.environ["WYTHE_DATABASE_URL"] = sub_env["WYTHE_DATABASE_URL"]
    from app.db.session import get_session_factory
    from app.main import initialize_database

    get_session_factory.cache_clear()
    initialize_database(sub_env["WYTHE_DATABASE_URL"])
    try:
        app = create_app()
        with TestClient(app) as client:
            _register_repo(client, "mcp-shared", repo_dir)
            client.post(
                "/api/v1/ui-focus",
                json={
                    "active_slug": "mcp-shared",
                    "session_id": "shared-tab-1",
                    "client_id": "browser-tab-1",
                    "selected_node_id": "t:quota_policies",
                },
            )
            client.post(
                "/api/v1/investigations/shared-tab-1/corrections",
                json={
                    "client_id": "browser-tab-1",
                    "note": "Confirmed scope_name is organizational metadata.",
                },
            )

            # Separate stdio `wythe mcp` process reads focus + correction + resource + emits camera focus
            reqs = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "wythe_what_is_this",
                        "arguments": {"target": "mcp-shared", "session_id": "shared-tab-1"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "wythe_focus_camera",
                        "arguments": {
                            "target": "mcp-shared",
                            "session_id": "shared-tab-1",
                            "correlation_id": "stdio-walk-1",
                            "focus_node_ids": ["t:quota_policies"],
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "resources/read",
                    "params": {"uri": "wythe://mcp-shared/investigation/shared-tab-1"},
                },
            ]
            proc = subprocess.run(
                [sys.executable, "-m", "app.cli", "mcp"],
                input="\n".join(json.dumps(r) for r in reqs) + "\n",
                env=sub_env,
                text=True,
                capture_output=True,
                timeout=30.0,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            replies = [json.loads(line) for line in proc.stdout.strip().splitlines()]
            assert len(replies) == 3
            wit_text = replies[0]["result"]["content"][0]["text"]
            assert "t:quota_policies" in wit_text
            assert "organizational metadata" in wit_text

            cam_text = replies[1]["result"]["content"][0]["text"]
            assert "#target=mcp-shared&session=shared-tab-1" in cam_text
            cam_json = json.loads(cam_text.split("```json\n", 1)[1].split("\n```", 1)[0])
            assert cam_json["delivery_state"] == "accepted_by_service"
            cmd_id = cam_json["command_id"]

            res_text = replies[2]["result"]["contents"][0]["text"]
            assert "shared-tab-1" in res_text

            # Browser posts receipt -> separate stdio `wythe_investigation(get_receipts)` sees `applied_by_browser`!
            client.post(
                "/api/v1/viewport/receipts",
                json={
                    "command_id": cmd_id,
                    "target_slug": "mcp-shared",
                    "session_id": "shared-tab-1",
                    "client_id": "browser-tab-1",
                    "outcome": "applied",
                },
            )
            proc2 = subprocess.run(
                [sys.executable, "-m", "app.cli", "mcp"],
                input=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "wythe_investigation",
                            "arguments": {
                                "action": "get_receipts",
                                "target": "mcp-shared",
                                "session_id": "shared-tab-1",
                                "command_id": cmd_id,
                            },
                        },
                    }
                )
                + "\n",
                env=sub_env,
                text=True,
                capture_output=True,
                timeout=30.0,
                check=False,
            )
            assert proc2.returncode == 0, proc2.stderr
            rcpt_reply = json.loads(proc2.stdout.strip())
            assert "applied_by_browser" in rcpt_reply["result"]["content"][0]["text"]
            assert "browser-tab-1" in rcpt_reply["result"]["content"][0]["text"]
    finally:
        if old_db is not None:
            os.environ["WYTHE_DATABASE_URL"] = old_db
        else:
            os.environ.pop("WYTHE_DATABASE_URL", None)
        if old_st is not None:
            os.environ["WYTHE_STATE_DIR"] = old_st
        else:
            os.environ.pop("WYTHE_STATE_DIR", None)
        get_session_factory.cache_clear()


def test_stage2a_wiretap_cli_runtime_provenance_and_understanding_integration(
    isolated_db_url: str,
    db_session: Any,
    tmp_path: Path,
    monkeypatch: Any,
    capsys: Any,
) -> None:
    """Verify wiretap CLI/companion/stratum flags, fail-closed missing plugin, runtime_capture identity, and Wave 6 Understanding routes/CLI/MCP."""
    import importlib.metadata

    from app.adapters.plugin_registry import stratum_artifacts_scope
    from app.cli import main as cli_main
    from app.services.investigation_service import validate_references_against_report

    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_policy_repo(tmp_path / "wiretap-cli-repo")
    (repo_dir / "compose.yaml").write_text(
        "services:\n  api:\n    ports:\n      - '127.0.0.1:8780:8780'\n",
        encoding="utf-8",
    )

    otel_file = tmp_path / "traces.json"
    otel_file.write_text(
        json.dumps(
            {
                "spans": [
                    {
                        "name": "GET /api/v1/quotas",
                        "attributes": {
                            "http.method": "GET",
                            "http.route": "/api/v1/quotas",
                            "db.statement": "SELECT id FROM quota_policies WHERE id = 42",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    listeners_file = tmp_path / "listeners.json"
    listeners_file.write_text(
        json.dumps(
            [
                {
                    "protocol": "tcp",
                    "bind_address": "0.0.0.0",
                    "port": 8780,
                    "command": "api",
                    "pid": 1234,
                }
            ]
        ),
        encoding="utf-8",
    )

    # 1. Fail closed (rc=2) when wiretap flags are passed without wythe-plugin-wiretap installed
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])
    rc_missing = cli_main(
        ["companion", str(repo_dir), "--otel-traces", str(otel_file)]
    )
    captured_err = capsys.readouterr()
    assert rc_missing == 2
    assert "wythe-plugin-wiretap" in captured_err.err

    # 2. With wythe-plugin-wiretap enabled via --allow-local-plugins, Zoom 1 digest is invariant & companion succeeds
    base_json = tmp_path / "base_scan.json"
    assert cli_main(["scan", "--strict", str(repo_dir), "--json", str(base_json)]) == 0
    capsys.readouterr()
    digest_base = json.loads(base_json.read_text(encoding="utf-8"))["content_digest"]

    comp_out = tmp_path / "wiretap_comp.json"
    rc_comp = cli_main(
        [
            "companion",
            str(repo_dir),
            "--allow-local-plugins",
            "--plugin",
            "wythe_plugin_wiretap.plugin",
            "--otel-traces",
            str(otel_file),
            "--port-listeners",
            str(listeners_file),
            "--json",
            str(comp_out),
        ]
    )
    comp_io = capsys.readouterr()
    assert rc_comp == 0, comp_io.err
    comp_data = json.loads(comp_out.read_text(encoding="utf-8"))
    assert comp_data["content_digest"] == digest_base
    assert comp_data["automated_security_audit"] is False
    assert comp_data["wiretap_companion"]["present"] is True
    assert any(
        f["rule_code"] == "PORT-002" for f in comp_data["wiretap_companion"]["findings"]
    )

    # 3. Runtime capture provenance in EvidenceIdentityRead & ValidatedReferenceRead
    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "wiretap-cli-repo", repo_dir)
        target = get_target_by_slug(db_session, "wiretap-cli-repo")
        assert target is not None
        with stratum_artifacts_scope(otel_traces=str(otel_file), port_listeners=str(listeners_file)):
            rep = get_or_run_cached_scan(db_session, target)
            ev = build_evidence_identity(rep)
            rt_sources = [s for s in ev.evidence_sources if s.kind == "runtime_capture"]
            assert any(s.producer == "wiretap:otel_traces" for s in rt_sources)
            assert any("static dark matter" in s.sampling_note for s in rt_sources)
            v_refs = validate_references_against_report(
                ["z3:m:route:main:port:1:8780"],
                rep,
                evidence_revision_id=ev.evidence_revision_id,
            )
            assert v_refs[0].epistemic_kind == "runtime_capture"
            assert v_refs[0].validation_state == "validated"

        # 4. Wave 6 Understanding REST, CLI, and MCP parity on both shipped examples
        ex_res = client.get("/api/v1/understanding/examples")
        assert ex_res.status_code == 200
        ex_slugs = {item["slug"] for item in ex_res.json()}
        assert {"schedule-policy-to-export", "assistant-context-to-delivery"} <= ex_slugs

        exp_res = client.get("/api/v1/understanding/explain?example_slug=schedule-policy-to-export")
        assert exp_res.status_code == 200
        assert len(exp_res.json()["links"]) == 6

        mcp_und = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {
                    "name": "wythe_investigation",
                    "arguments": {
                        "action": "explain_understanding",
                        "example_slug": "assistant-context-to-delivery",
                    },
                },
            },
        ).json()
        assert mcp_und["result"]["isError"] is False
        assert "assistant-context-to-delivery" in mcp_und["result"]["content"][0]["text"]

    und_out = tmp_path / "und_cli.json"
    assert (
        cli_main(
            ["understand", "schedule-policy-to-export", "--json", "--out", str(und_out)]
        )
        == 0
    )
    capsys.readouterr()
    und_json = json.loads(und_out.read_text(encoding="utf-8"))
    assert und_json["example_slug"] == "schedule-policy-to-export"
    assert und_json["target_code_executed"] is False
    assert und_json["automated_security_audit"] is False
    assert cli_main(["understand", "assistant-context-to-delivery"]) == 0
    capsys.readouterr()


def test_round1_e2e_remediations_cross_target_isolation_semantic_findings_and_vlm_500_fallback(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Regression coverage for E2E verifier findings #1, #2, #4a, and #4b."""
    from wythe_examples.truth_in_python_lab import materialize_truth_in_python_fixture

    assert isolated_db_url.startswith("sqlite:")
    repo_a = _write_synthetic_policy_repo(tmp_path / "repo-alpha")
    lab_repo = materialize_truth_in_python_fixture(tmp_path / "truth-lab")

    # Local mock VLM returning HTTP 500 on image_url payloads and 200 on text-only fallback
    call_shapes: list[str] = []

    class _Vlm500Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                out = json.dumps({"data": [{"id": "gemma-4-vlm-4bit", "owned_by": "local"}]}).encode()
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
            user_msg = body["messages"][-1]["content"]
            if isinstance(user_msg, list):
                call_shapes.append("multimodal")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error":"patch resize failure"}')
                return
            call_shapes.append("text_only")
            reply = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "Answered cleanly via text-only fallback on `t:quota_policies`."},
                    }
                ]
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Vlm500Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    try:
        app = create_app()
        with TestClient(app) as client:
            _register_repo(client, "repo-alpha", repo_a)
            _register_repo(client, "truth-lab", lab_repo)

            # 1. Cross-target session_id reuse is rejected (never migrates repo-alpha's session onto truth-lab)
            s_alpha = client.post(
                "/api/v1/investigations",
                json={"target_slug": "repo-alpha", "session_id": "inv-alpha-1", "client_id": "tab-1"},
            )
            assert s_alpha.status_code == 200
            cross_reopen = client.post(
                "/api/v1/investigations",
                json={"target_slug": "truth-lab", "session_id": "inv-alpha-1", "client_id": "tab-1"},
            )
            assert cross_reopen.status_code == 422
            cross_focus = client.post(
                "/api/v1/ui-focus",
                json={
                    "active_slug": "truth-lab",
                    "session_id": "inv-alpha-1",
                    "client_id": "tab-1",
                    "selected_node_id": "t:quota_policies",
                },
            )
            assert cross_focus.status_code == 422
            assert client.get("/api/v1/investigations?target_slug=truth-lab").json()["sessions"] == []
            assert client.get("/api/v1/investigations/inv-alpha-1").json()["target_slug"] == "repo-alpha"

            # 2. Positional BoundaryFinding.id (f:MANIP-001:0 vs f:MANIP-001:1) matches semantically without rebinding
            scan_lab = client.get("/api/v1/scans/truth-lab").json()
            manip_findings = [f for f in scan_lab["findings"] if f["rule_code"] == "MANIP-001"]
            assert len(manip_findings) >= 2
            f_case2 = next(f for f in manip_findings if "case2_bypassed" in f["source_file"])
            f_case5 = next(f for f in manip_findings if "case5_shadowed" in f["source_file"])

            inv_lab = client.post(
                "/api/v1/investigations",
                json={"target_slug": "truth-lab", "session_id": "inv-lab-1", "client_id": "tab-1"},
            ).json()
            assert inv_lab["session_id"] == "inv-lab-1"
            client.post(
                "/api/v1/investigations/inv-lab-1/turns",
                json={
                    "question": "Which finding is on case2?",
                    "answer_markdown": f"Finding `{f_case2['id']}` flags `{f_case2['source_file']}`.",
                    "engine": "local",
                    "model_id": "mock",
                    "referenced_ids": [f_case2["id"], f_case5["id"]],
                },
            )

            # Fix case2_bypassed_validator.py so f_case5 shifts into f:MANIP-001:0
            case2_file = next(lab_repo.rglob("*case2_bypassed*"))
            case2_file.write_text(
                "def enforce_batch_quota(row, requested: int) -> bool:\n"
                "    return requested <= row.max_batch_quota\n",
                encoding="utf-8",
            )
            comp = client.get("/api/v1/investigations/inv-lab-1/compare").json()
            assert f_case2["id"] in comp["resolved_finding_ids"]
            assert f_case5["id"] not in comp["resolved_finding_ids"]
            vanished_map = {v["ref_id"]: v for v in comp["vanished_refs"]}
            assert f_case2["id"] in vanished_map
            assert "case2_bypassed" in (vanished_map[f_case2["id"]]["source_file"] or "")

            # 3. VLM HTTP 500 retries text-only and preserves image_supplied=True + fallback_reason
            ask_res = client.post(
                "/api/v1/ask",
                json={
                    "target_slug": "repo-alpha",
                    "session_id": "inv-alpha-1",
                    "client_id": "tab-1",
                    "question": "Explain quota_policies.",
                    "engine": "local",
                    "local_base_url": f"http://127.0.0.1:{port}/v1",
                    "local_model_id": "gemma-4-vlm-4bit",
                    "include_vision_snapshot": True,
                    "snapshot_data_url": TINY_PNG_A,
                },
            )
            assert ask_res.status_code == 200, ask_res.text
            ask_json = ask_res.json()
            assert call_shapes == ["multimodal", "text_only"]
            assert ask_json["used_vision_snapshot"] is False
            assert ask_json["image_supplied"] is True
            assert ask_json["fallback_reason"] is not None
            stored_alpha = client.get("/api/v1/investigations/inv-alpha-1").json()
            assert stored_alpha["turns"][-1]["image_supplied"] is True
            assert stored_alpha["turns"][-1]["used_vision"] is False
    finally:
        srv.shutdown()
        srv.server_close()
