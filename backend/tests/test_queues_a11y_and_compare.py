"""Tests for Celery/Beat named queue lineage, WCAG DISP-005 a11y, wild-repo idioms, & snapshot comparison."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.a11y_inspect import scan_a11y_markup_findings
from app.schemas.atlas import TargetProjectCreate
from app.services.diff_and_sarif_service import compare_recorded_snapshots
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import run_target_scan


def test_celery_named_queues_and_beat_schedule_lineage(db_session: Session, tmp_path: Path) -> None:
    """Verify Beat schedule + task_routes + @shared_task(queue=...) resolve named Redis queue lanes."""
    repo = tmp_path / "celery_lanes_app"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE audit_exports (id INTEGER PRIMARY KEY, status TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models" / "exports.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class AuditExport(Base):\n"
        "    __tablename__ = 'audit_exports'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    status: Mapped[str]\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "workers" / "celery_app.py").write_text(
        "from celery import Celery\n"
        "CELERY_QUEUE_NAMES = ('default', 'exports', 'notifications')\n"
        "celery_app = Celery('demo')\n"
        "celery_app.conf.task_routes = {'app.workers.tasks.nightly_export': {'queue': 'exports'}}\n"
        "celery_app.conf.beat_schedule = {\n"
        "    'nightly-audit-export': {\n"
        "        'task': 'app.workers.tasks.nightly_export',\n"
        "        'schedule': 3600.0,\n"
        "        'options': {'queue': 'exports'},\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "workers" / "tasks.py").write_text(
        "from celery import shared_task\n"
        "from sqlalchemy import select\n"
        "from app.models.exports import AuditExport\n"
        "@shared_task(name='app.workers.tasks.nightly_export', queue='exports')\n"
        "def nightly_export(db=None):\n"
        "    return db.scalars(select(AuditExport)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.workers.tasks import nightly_export\n"
        "router = APIRouter()\n"
        "@router.post('/exports/trigger')\n"
        "def trigger_export():\n"
        "    nightly_export.delay()\n"
        "    return {'queued': True}\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function Page() {\n"
        "  return <button type='button' onClick={() => fetch('/api/v1/exports/trigger', { method: 'POST' })}>Run</button>;\n"
        "}\n",
        encoding="utf-8",
    )

    register_target(
        db_session,
        TargetProjectCreate(slug="celery-lanes", name="Celery Lanes", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "celery-lanes")
    assert target is not None
    report = run_target_scan(db_session, target, strict_gate=True)

    node_ids = {n.id for n in report.nodes}
    assert "t:redis:queue_exports" in node_ids
    edges_by_pair = {(e.source_id, e.target_id, e.kind) for e in report.edges}
    assert any(
        tgt == "t:redis:queue_exports" and kind == "writes_truth"
        for _, tgt, kind in edges_by_pair
    ), "Beat schedule and route .delay() should write tickets into t:redis:queue_exports"
    assert any(
        tgt == "t:redis:queue_exports" and kind == "reads_truth"
        for _, tgt, kind in edges_by_pair
    ), "Worker task module should consume from t:redis:queue_exports"


def test_disp_005_wcag_markup_inspector_catches_violations_and_passes_accessible_markup() -> None:
    """Verify DISP-005 catches missing alt, non-keyboard div click, nameless button, and unlabeled input."""
    bad_tsx = (
        "export function BadSurface() {\n"
        "  return (\n"
        "    <section>\n"
        "      <img src='/diagram.png' />\n"
        "      <div onClick={() => console.log('clicked')}>Row</div>\n"
        "      <button type='button'><CloseIcon /></button>\n"
        "      <input type='text' placeholder='Search nodes' />\n"
        "    </section>\n"
        "  );\n"
        "}\n"
    )
    findings = scan_a11y_markup_findings(bad_tsx, "frontend/src/BadSurface.tsx", "d:comp:bad")
    codes = [f.rule_code for f in findings]
    assert codes.count("DISP-005") == 4

    good_tsx = (
        "export function GoodSurface() {\n"
        "  return (\n"
        "    <section>\n"
        "      <img src='/diagram.png' alt='Stratified 3-tier lineage graph' />\n"
        "      <div role='button' tabIndex={0} onClick={() => {}} onKeyDown={() => {}}>Row</div>\n"
        "      <button type='button' aria-label='Close inspector'><CloseIcon /></button>\n"
        "      <label htmlFor='q'>Search</label>\n"
        "      <input id='q' type='text' />\n"
        "    </section>\n"
        "  );\n"
        "}\n"
    )
    clean_findings = scan_a11y_markup_findings(good_tsx, "frontend/src/GoodSurface.tsx", "d:comp:good")
    assert clean_findings == []


def test_sveltekit_drizzle_and_snapshot_comparison_deltas(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify SvelteKit +page.server.ts + Drizzle E2E chain and snapshot-to-snapshot diffing."""
    repo = tmp_path / "sveltekit_drizzle_demo"
    (repo / "src" / "lib" / "server").mkdir(parents=True)
    (repo / "src" / "routes" / "tasks").mkdir(parents=True)

    (repo / "svelte.config.js").write_text("export default {};\n", encoding="utf-8")
    (repo / "drizzle.config.ts").write_text("export default { schema: './src/lib/server/schema.ts' };\n", encoding="utf-8")
    (repo / "package.json").write_text(
        '{"dependencies": {"@sveltejs/kit": "^2.0.0", "drizzle-orm": "^0.36.0"}}',
        encoding="utf-8",
    )
    (repo / "src" / "lib" / "server" / "schema.ts").write_text(
        "import { pgTable, serial, text } from 'drizzle-orm/pg-core';\n"
        "export const tasks = pgTable('tasks', { id: serial('id').primaryKey(), title: text('title') });\n",
        encoding="utf-8",
    )
    (repo / "src" / "routes" / "tasks" / "+page.server.ts").write_text(
        "import { db } from '$lib/server/db';\n"
        "import { tasks } from '$lib/server/schema';\n"
        "export const load = async () => ({ items: await db.select().from(tasks) });\n",
        encoding="utf-8",
    )
    page_svelte = repo / "src" / "routes" / "tasks" / "+page.svelte"
    page_svelte.write_text(
        "<script lang='ts'>\n  export let data;\n</script>\n<h1>Tasks ({data.items.length})</h1>\n",
        encoding="utf-8",
    )

    register_target(
        db_session,
        TargetProjectCreate(
            slug="sveltekit-demo",
            name="SvelteKit Demo",
            repo_path=str(repo),
            stack_profile_slug="postgres-drizzle-sveltekit",
            backend_subdir=".",
            frontend_subdir=".",
        ),
    )
    target = get_target_by_slug(db_session, "sveltekit-demo")
    assert target is not None

    snap_1 = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=True)
    assert snap_1.snapshot_id is not None
    assert len(snap_1.chains) >= 1
    assert any("tasks" in c.truth_table_labels for c in snap_1.chains)

    # Introduce an unlabeled <input> to trigger DISP-005 in snapshot 2 and verify comparison delta!
    page_svelte.write_text(
        "<script lang='ts'>\n  export let data;\n</script>\n"
        "<h1>Tasks ({data.items.length})</h1>\n<input type='text' />\n",
        encoding="utf-8",
    )
    snap_2 = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=True)
    assert snap_2.snapshot_id is not None

    comp = compare_recorded_snapshots(
        db_session, target.id, target.slug, snap_1.snapshot_id, snap_2.snapshot_id
    )
    assert comp.warning_delta >= 1
    assert any(f.rule_code == "DISP-005" for f in comp.new_findings)
