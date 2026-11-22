"""Regression tests for v0.2.9 viewport, SSE, receipt, frontend, container, and CI hardening."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.adapters.dockerfile_sources import parse_dockerfile, parse_dockerignore
from app.main import create_app
from app.schemas.atlas import ViewportCommand, ViewportCommandReceiptCreate
from app.services.viewport_service import (
    VIEWPORT_RECEIPTS_MAXLEN,
    list_viewport_receipts,
    publish_viewport_command,
    record_viewport_receipt,
    reset_viewport_bus,
    stream_viewport_events,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clean_bus() -> Any:
    reset_viewport_bus()
    yield
    reset_viewport_bus()


def test_sse_replay_includes_paused_by_human_and_offloads_sqlite_poll(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SSE `since_seq > 0` replay must deliver `paused_by_human` and never stall asyncio."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "sse-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))

    app = create_app()
    repo_dir = tmp_path / "sse-demo-repo"
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    with TestClient(app) as client:
        reg_res = client.post(
            "/api/v1/targets",
            json={
                "slug": "sse-demo",
                "name": "SSE Demo",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
            },
        )
        assert reg_res.status_code in (200, 201), reg_res.text
        inv_res = client.post(
            "/api/v1/investigations",
            json={"target_slug": "sse-demo", "session_id": "tab-paused", "client_id": "cli-1"},
        )
        assert inv_res.status_code in (200, 201), inv_res.text
        follow_res = client.post(
            "/api/v1/investigations/tab-paused/follow",
            json={"client_id": "cli-1", "follow_state": "paused"},
        )
        assert follow_res.status_code == 200, follow_res.text
        ack1 = publish_viewport_command(
            ViewportCommand(
                target_slug="sse-demo",
                session_id="tab-paused",
                focus_node_ids=["t:orders"],
                caption="First while paused",
            )
        )
        ack2 = publish_viewport_command(
            ViewportCommand(
                target_slug="sse-demo",
                session_id="tab-paused",
                focus_node_ids=["t:invoices"],
                caption="Second while paused",
            )
        )
        assert ack1.delivery_state == "paused_by_human"
        assert ack2.delivery_state == "paused_by_human"

    async def _run_reconnect() -> None:
        thread_calls: list[str] = []
        orig_to_thread = asyncio.to_thread

        async def _spy_to_thread(func: Any, /, *args: Any, **kwargs: Any) -> Any:
            thread_calls.append(getattr(func, "__name__", str(func)))
            return await orig_to_thread(func, *args, **kwargs)

        monkeypatch.setattr(asyncio, "to_thread", _spy_to_thread)

        agen = stream_viewport_events(
            "sse-demo",
            session_id="tab-paused",
            since_seq=ack1.seq,
            once=False,
        )
        banner = await anext(agen)
        assert banner.startswith(": viewport-bus connected")
        replayed = await anext(agen)
        assert "Second while paused" in replayed
        assert "paused_by_human" in replayed
        await agen.aclose()
        assert len(thread_calls) >= 2

    asyncio.run(_run_reconnect())


def test_receipt_validation_terminal_states_pruning_and_seq_scoping(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enforce non-empty IDs, immutable expired/stale/rejected states, upsert+256 pruning, and seq join scoping."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "rcpt-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))

    # 1. Defense-in-depth rejects blank/whitespace command_id & client_id even via model_construct
    ok_ack = publish_viewport_command(
        ViewportCommand(
            target_slug="rcpt-demo",
            command_id="cmd-valid-1",
            focus_node_ids=["t:orders"],
        )
    )
    with pytest.raises(ValueError, match="command_id"):
        record_viewport_receipt(
            ViewportCommandReceiptCreate.model_construct(
                command_id="   ",
                seq=ok_ack.seq,
                target_slug="rcpt-demo",
                session_id=None,
                client_id="cli-1",
                outcome="applied",
                applied_focus_revision=None,
                note="",
            )
        )
    with pytest.raises(ValueError, match="client_id"):
        record_viewport_receipt(
            ViewportCommandReceiptCreate.model_construct(
                command_id="cmd-valid-1",
                seq=ok_ack.seq,
                target_slug="rcpt-demo",
                session_id=None,
                client_id="  ",
                outcome="applied",
                applied_focus_revision=None,
                note="",
            )
        )

    # 2. Expired, stale, and rejected commands cannot be laundered to applied_by_browser or paused_by_human
    expired_ack = publish_viewport_command(
        ViewportCommand(
            target_slug="rcpt-demo",
            command_id="cmd-exp-1",
            expires_at=datetime.now(UTC) - timedelta(seconds=10),
        )
    )
    assert expired_ack.delivery_state == "expired"
    for bad_outcome in ("applied", "paused_by_human"):
        with pytest.raises(ValueError):
            record_viewport_receipt(
                ViewportCommandReceiptCreate(
                    command_id="cmd-exp-1",
                    seq=expired_ack.seq,
                    target_slug="rcpt-demo",
                    client_id="cli-1",
                    outcome=bad_outcome,  # type: ignore[arg-type]
                )
            )
    # Compliant browser rejecting an expired command succeeds while preserving delivery_state='expired'
    exp_rej = record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id="cmd-exp-1",
            seq=expired_ack.seq,
            target_slug="rcpt-demo",
            client_id="cli-1",
            outcome="rejected",
            note="expired",
        )
    )
    assert exp_rej.delivery_state == "expired"

    stale_ack = publish_viewport_command(
        ViewportCommand(
            target_slug="rcpt-demo",
            command_id="cmd-stale-1",
            expected_evidence_revision="ev-old",
        ),
        current_evidence_revision="ev-new",
    )
    assert stale_ack.delivery_state == "stale"
    with pytest.raises(ValueError):
        record_viewport_receipt(
            ViewportCommandReceiptCreate(
                command_id="cmd-stale-1",
                seq=stale_ack.seq,
                target_slug="rcpt-demo",
                client_id="cli-1",
                outcome="applied",
            )
        )

    rej_ack = publish_viewport_command(
        ViewportCommand(target_slug="rcpt-demo", command_id="cmd-rej-1")
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id="cmd-rej-1",
            seq=rej_ack.seq,
            target_slug="rcpt-demo",
            client_id="cli-1",
            outcome="rejected",
        )
    )
    with pytest.raises(ValueError):
        record_viewport_receipt(
            ViewportCommandReceiptCreate(
                command_id="cmd-rej-1",
                seq=rej_ack.seq,
                target_slug="rcpt-demo",
                client_id="cli-1",
                outcome="applied",
            )
        )

    # 3. Same command_id across distinct seqs must stay isolated in list_viewport_receipts(seq=...)
    seq_a = publish_viewport_command(
        ViewportCommand(target_slug="rcpt-demo", command_id="shared-cmd", session_id="s-a")
    )
    seq_b = publish_viewport_command(
        ViewportCommand(target_slug="rcpt-demo", command_id="shared-cmd", session_id="s-b")
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id="shared-cmd",
            seq=seq_a.seq,
            target_slug="rcpt-demo",
            session_id="s-a",
            client_id="cli-a",
            outcome="applied",
        )
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id="shared-cmd",
            seq=seq_b.seq,
            target_slug="rcpt-demo",
            session_id="s-b",
            client_id="cli-b",
            outcome="applied",
        )
    )
    rcpts_a = list_viewport_receipts(
        target_slug="rcpt-demo", session_id="s-a", command_id="shared-cmd", seq=seq_a.seq
    )
    assert len(rcpts_a) == 1
    assert rcpts_a[0].applied_by_client_ids == ["cli-a"]

    # 4. Upsert per (target, session, command_id, seq, client_id) + <= 256 per-target pruning
    for idx in range(VIEWPORT_RECEIPTS_MAXLEN + 15):
        cmd_id = f"cmd-prune-{idx}"
        ack = publish_viewport_command(
            ViewportCommand(target_slug="prune-target", command_id=cmd_id)
        )
        record_viewport_receipt(
            ViewportCommandReceiptCreate(
                command_id=cmd_id,
                seq=ack.seq,
                target_slug="prune-target",
                client_id="cli-1",
                outcome="applied",
            )
        )
        # Re-posting same tuple upserts instead of duplicating
        record_viewport_receipt(
            ViewportCommandReceiptCreate(
                command_id=cmd_id,
                seq=ack.seq,
                target_slug="prune-target",
                client_id="cli-1",
                outcome="applied",
            )
        )
    all_pruned = list_viewport_receipts(target_slug="prune-target", limit=200)
    assert len(all_pruned) == 200  # clamped by limit=200; verify oldest pruned via DB count
    from app.services.viewport_service import _open_bus_connection, _resolve_viewport_bus_db_path

    conn = _open_bus_connection(_resolve_viewport_bus_db_path(), create=False)
    assert conn is not None
    try:
        cnt_row = conn.execute(
            "SELECT COUNT(*) FROM viewport_receipts WHERE target_slug = 'prune-target'"
        ).fetchone()
        assert cnt_row is not None and int(cnt_row[0]) == VIEWPORT_RECEIPTS_MAXLEN == 256
    finally:
        conn.close()


def test_frontend_csrf_choreography_state_isolation_and_editor_deep_links() -> None:
    """Verify Wave 2 frontend CSRF headers, SSE/StrictMode/filter/resume fixes, and target-switch hygiene."""
    atlas_ts = (REPO_ROOT / "frontend/src/api/atlas.ts").read_text(encoding="utf-8")
    assert "'X-Wythe-Client': '1'" in atlas_ts
    assert "export function post<" in atlas_ts
    assert "export function patch<" in atlas_ts
    assert "export function del<" in atlas_ts
    assert "export function put<" in atlas_ts
    assert "export async function get<" in atlas_ts
    assert "from '@/lib/api'" not in atlas_ts

    choreo_ts = (REPO_ROOT / "frontend/src/lib/wytheCameraChoreography.ts").read_text(
        encoding="utf-8"
    )
    assert "cmd.search_query == null" in choreo_ts
    assert "(cmd.zoom_stratum == null || cmd.zoom_stratum === 1)" in choreo_ts
    assert "(cmd.framing_preset == null || cmd.framing_preset === 'iso_overview')" in choreo_ts
    assert "!cmd.caption" in choreo_ts

    page_tsx = (REPO_ROOT / "frontend/src/app/page.tsx").read_text(encoding="utf-8")
    assert "lastSeenSeqRef" in page_tsx
    assert "sinceSeq: lastSeenSeqRef.current" in page_tsx
    assert "report?.content_digest ? undefined : null" not in page_tsx
    assert "latestEvidenceRevRef.current ?? reportContentDigestRef.current ?? undefined" in page_tsx
    assert "latestEvidenceRevRef.current ?? report?.content_digest ?? undefined" in page_tsx
    assert "activeEvent: prev.activeEvent ??" not in page_tsx
    assert "const cleanSid = switchTabSessionId(" in page_tsx
    assert "targetsRef.current" in page_tsx
    assert "setWhatsThisSnapshotUrl(null)" in page_tsx
    assert "setWhatsThisExplanation(null)" in page_tsx
    assert "setLiveViewportDigest(null)" in page_tsx
    assert "setSnapBaseId(null)" in page_tsx
    assert "resumeFollowFromPaused('window_wythe_bridge')" in page_tsx

    gov_tsx = (REPO_ROOT / "frontend/src/components/GovernanceAndDiffPanel.tsx").read_text(
        encoding="utf-8"
    )
    assert "setBaseSnapId(null);" in gov_tsx
    assert "setHeadSnapId(null);" in gov_tsx
    assert "setCommittedBaseRef('');" in gov_tsx
    assert "setSyncMessage(null);" in gov_tsx
    assert "validIds.has(prev)" in gov_tsx

    panel_tsx = (REPO_ROOT / "frontend/src/components/NodeSourceAndPromptPanel.tsx").read_text(
        encoding="utf-8"
    )
    assert "encodeURIComponent(segment)" in panel_tsx
    assert "encodeURI(snippet.abs_path)" not in panel_tsx


def test_container_and_ci_hygiene_contracts() -> None:
    """Verify `.dockerignore`, `Containerfile`, `ci.yml`, and `publish-pypi.yml` P2-6 hardening."""
    dockerignore_path = REPO_ROOT / ".dockerignore"
    assert dockerignore_path.is_file()
    dockerignore_text = dockerignore_path.read_text(encoding="utf-8")
    for expected in (
        ".git",
        ".venv",
        "__pycache__",
        "*.py[cod]",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "*.db",
        "*.sqlite3",
        ".env*",
        "frontend/node_modules",
        "frontend/.next",
        "frontend/out",
        "backend/tests",
        "dist",
        "build",
    ):
        assert expected in dockerignore_text

    ignore_spec = parse_dockerignore(REPO_ROOT, REPO_ROOT / "Containerfile", REPO_ROOT)
    assert ignore_spec.source_rel == ".dockerignore"
    assert ignore_spec.is_excluded(".git/HEAD")
    assert ignore_spec.is_excluded(".venv/bin/python")
    assert ignore_spec.is_excluded("backend/tests/test_api_and_cli.py")
    assert not ignore_spec.is_excluded("backend/app/cli.py")

    containerfile_text = (REPO_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "--no-install-recommends git" in containerfile_text
    assert "/var/lib/apt/lists/*" in containerfile_text
    assert "/opt/wythe/backend[treesitter]" in containerfile_text
    assert "USER 10001:10001" in containerfile_text
    assert parse_dockerfile(REPO_ROOT / "Containerfile", REPO_ROOT) is not None

    ci_yml = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "uv run ruff check backend/app backend/tests plugins" in ci_yml
    assert re.search(r"^\s+npm run test:scene\s*$", ci_yml, re.MULTILINE)

    pub_yml = (REPO_ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "uv run ruff check backend/app backend/tests plugins" in pub_yml
    assert "app/ui_dist/index.html" in pub_yml
    assert "wythe gate --strict ." in pub_yml


def test_pure_drawer_refresh_ts_behavior_when_tsc_available(tmp_path: Path) -> None:
    """When frontend toolchain is present, compile and execute behavioral `isPureDrawerRefreshCommand` checks."""
    import json
    import os
    import subprocess

    fe_dir = REPO_ROOT / "frontend"
    tsc_bin = fe_dir / "node_modules" / "typescript" / "bin" / "tsc"
    if not tsc_bin.is_file():
        pytest.skip("frontend/node_modules not present in isolated Python test environment")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    tsconfig_path = tmp_path / "tsconfig.probe.json"
    tsconfig_path.write_text(
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
                    "outDir": str(out_dir),
                },
                "include": [str(fe_dir / "src" / "lib" / "wytheCameraChoreography.ts")],
            }
        ),
        encoding="utf-8",
    )
    tsc_res = subprocess.run(
        ["node", str(tsc_bin), "-p", str(tsconfig_path)],
        capture_output=True,
        text=True,
        cwd=fe_dir,
        check=False,
    )
    assert tsc_res.returncode == 0, f"{tsc_res.stdout}\n{tsc_res.stderr}"
    compiled_mod = out_dir / "lib" / "wytheCameraChoreography.js"
    assert compiled_mod.is_file(), f"Missing {compiled_mod}"
    js_script = (
        "const assert = require('node:assert/strict');\n"
        f"const {{ isPureDrawerRefreshCommand }} = require({json.dumps(str(compiled_mod))});\n"
        "assert.equal(isPureDrawerRefreshCommand({ target_slug: 'w', refresh_session_id: 's', zoom_stratum: 1, framing_preset: 'iso_overview', caption: '' }), true);\n"
        "assert.equal(isPureDrawerRefreshCommand({ target_slug: 'w', refresh_session_id: 's', search_query: '' }), false);\n"
        "assert.equal(isPureDrawerRefreshCommand({ target_slug: 'w', refresh_session_id: 's', zoom_stratum: 2 }), false);\n"
        "assert.equal(isPureDrawerRefreshCommand({ target_slug: 'w', refresh_session_id: 's', framing_preset: 'tier_elevation' }), false);\n"
        "assert.equal(isPureDrawerRefreshCommand({ target_slug: 'w', refresh_session_id: 's', caption: 'Look here' }), false);\n"
    )
    node_res = subprocess.run(
        ["node", "-e", js_script],
        env={**os.environ, "NODE_PATH": str(fe_dir / "node_modules")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert node_res.returncode == 0, f"{node_res.stdout}\n{node_res.stderr}"
