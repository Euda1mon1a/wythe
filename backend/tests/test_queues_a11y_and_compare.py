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
        "import { CloseIcon } from 'lucide-react';\n"
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
    findings = scan_a11y_markup_findings(bad_tsx, "d:comp:bad", "frontend/src/BadSurface.tsx")
    codes = [f.rule_code for f in findings]
    assert codes.count("DISP-005") == 4

    unobserved: list[str] = []
    opaque_hits = scan_a11y_markup_findings(
        "<button type='button'><OpaqueAction label='Close' /></button>",
        "d:comp:opaque",
        "frontend/src/Opaque.tsx",
        unobserved_out=unobserved,
    )
    assert opaque_hits == []
    assert len(unobserved) == 1 and "OpaqueAction" in unobserved[0]

    good_tsx = (
        "import { CloseIcon } from 'lucide-react';\n"
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


def test_tsx_default_export_and_expression_arrow_a11y_resolution(tmp_path: Path) -> None:
    """Resolve `export default` declarations in multi-component TSX files without sibling bleed."""
    from app.adapters.typescript_react import TypeScriptReactSpaAdapter

    (tmp_path / "src" / "components").mkdir(parents=True)
    (tmp_path / "package.json").write_text('{"dependencies":{"react":"^18.0.0"}}', encoding="utf-8")

    # Helper Icon precedes the actual `export default function Label`
    (tmp_path / "src" / "components" / "Label.tsx").write_text(
        "function HelperIcon() {\n  return <svg />;\n}\n"
        "const localText = 'Save';\n"
        "export default function Label(): { node: unknown } {\n"
        "  return <span>{localText}</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    # Unused helper precedes a semicolon-free expression-bodied arrow component exported by name
    (tmp_path / "src" / "components" / "DefaultIcon.tsx").write_text(
        "const UnusedLabel = () => (<span>Unused</span>)\n"
        "const DefaultIcon = () => (<svg aria-hidden='true' />)\n"
        "export default DefaultIcon;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "App.tsx").write_text(
        "import Label from './components/Label';\n"
        "import DefaultIcon from './components/DefaultIcon';\n"
        "export function App() {\n"
        "  return (\n"
        "    <main>\n"
        "      <button type='button'><Label /></button>\n"
        "      <button type='button'><DefaultIcon /></button>\n"
        "    </main>\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )

    res = TypeScriptReactSpaAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    assert [(f.source_file, f.line) for f in disp_005] == [("src/App.tsx", 7)], disp_005


def test_tsx_spread_props_and_destructured_aliases_a11y(tmp_path: Path) -> None:
    """Resolve static spread objects/destructured aliases and keep dynamic spreads unobserved."""
    from app.adapters.typescript_react import TypeScriptReactSpaAdapter

    (tmp_path / "src" / "components").mkdir(parents=True)
    (tmp_path / "package.json").write_text('{"dependencies":{"react":"^18.0.0"}}', encoding="utf-8")

    (tmp_path / "src" / "components" / "Label.tsx").write_text(
        "export function Label({ text }: { text?: string }) {\n  return <span>{text}</span>;\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "components" / "AliasedLabel.tsx").write_text(
        "export default function AliasedLabel({ text: caption, fallback: altTxt = '' }: { text?: string; fallback?: string }) {\n"
        "  return <span>{caption || altTxt}</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "components" / "IconOnly.tsx").write_text(
        "export default function IconOnly({ className }: { className?: string }) {\n"
        "  return <svg className={className} aria-hidden='true' />;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "App.tsx").write_text(
        "import { Label } from './components/Label';\n"
        "import AliasedLabel from './components/AliasedLabel';\n"
        "import IconOnly from './components/IconOnly';\n"
        "export function App(extra: Record<string, string>) {\n"
        "  return (\n"
        "    <main>\n"
        "      <button type='button'><Label {...{ text: 'Save' }} /></button>\n"
        "      <button type='button'><Label {...extra} /></button>\n"
        "      <button type='button'><Label {...extra} text='' /></button>\n"
        "      <button type='button'><AliasedLabel text='Save' /></button>\n"
        "      <button type='button'><AliasedLabel caption='WrongProp' /></button>\n"
        "      <button type='button'><IconOnly {...extra} /></button>\n"
        "    </main>\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )

    res = TypeScriptReactSpaAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    # Line 7: static spread {text: 'Save'} -> clean; Line 8: dynamic spread -> unobserved
    # Line 9: explicit text='' after spread -> flagged; Line 10: aliased text='Save' -> clean
    # Line 11: passing local alias caption= instead of source text= -> flagged; Line 12: pure icon -> flagged
    assert [(f.source_file, f.line) for f in disp_005] == [
        ("src/App.tsx", 9),
        ("src/App.tsx", 11),
        ("src/App.tsx", 12),
    ], disp_005


def test_tsx_conditional_returns_undefined_defaults_and_default_children_a11y(
    tmp_path: Path,
) -> None:
    """Handle multi-return uncertainty, explicit `undefined` prop defaults, and default children."""
    from app.adapters.typescript_react import TypeScriptReactSpaAdapter

    (tmp_path / "src" / "components").mkdir(parents=True)
    (tmp_path / "package.json").write_text('{"dependencies":{"react":"^18.0.0"}}', encoding="utf-8")

    (tmp_path / "src" / "components" / "ConditionalLabel.tsx").write_text(
        "export function ConditionalLabel({ loading }: { loading?: boolean }) {\n"
        "  if (loading) {\n"
        "    return <svg aria-hidden='true' />;\n"
        "  }\n"
        "  return <span>Save</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "components" / "DefaultText.tsx").write_text(
        "export function DefaultText({ text = 'Save' }: { text?: string | null }) {\n"
        "  return <span>{text}</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "components" / "DefaultChildren.tsx").write_text(
        "export function DefaultChildren({ children = 'Save' }: { children?: unknown }) {\n"
        "  return <span>{children}</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "App.tsx").write_text(
        "import { ConditionalLabel } from './components/ConditionalLabel';\n"
        "import { DefaultText } from './components/DefaultText';\n"
        "import { DefaultChildren } from './components/DefaultChildren';\n"
        "export function App() {\n"
        "  return (\n"
        "    <main>\n"
        "      <button type='button'><ConditionalLabel loading={false} /></button>\n"
        "      <button type='button'><DefaultText text={undefined} /></button>\n"
        "      <button type='button'><DefaultText text={null} /></button>\n"
        "      <button type='button'><DefaultChildren /></button>\n"
        "      <button type='button'><DefaultChildren children={undefined} /></button>\n"
        "      <button type='button'><DefaultChildren children={null} /></button>\n"
        "    </main>\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )

    res = TypeScriptReactSpaAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    # ConditionalLabel -> uncertain across branches (not flagged)
    # DefaultText text={undefined} -> applies 'Save' default (clean); text={null} -> flagged (line 9)
    # DefaultChildren -> applies 'Save' default for omitted and {undefined}; children={null} -> flagged (line 12)
    assert [(f.source_file, f.line) for f in disp_005] == [
        ("src/App.tsx", 9),
        ("src/App.tsx", 12),
    ], disp_005


def test_tsx_signature_only_props_computed_exprs_and_aria_img_a11y(
    tmp_path: Path,
) -> None:
    """Restrict prop destructuring to signature, keep computed exprs uncertain, honor img ARIA names."""
    from app.adapters.typescript_react import TypeScriptReactSpaAdapter

    (tmp_path / "src" / "components").mkdir(parents=True)
    (tmp_path / "package.json").write_text('{"dependencies":{"react":"^18.0.0"}}', encoding="utf-8")

    (tmp_path / "src" / "components" / "BodyCallLabel.tsx").write_text(
        "const label = 'Save';\n"
        "export function BodyCallLabel() {\n"
        "  console.debug({ label });\n"
        "  return <span>{label}</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "components" / "LengthLabel.tsx").write_text(
        "export function LengthLabel({ text }: { text: string }) {\n"
        "  return <span>{text.length}</span>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "App.tsx").write_text(
        "import { BodyCallLabel } from './components/BodyCallLabel';\n"
        "import { LengthLabel } from './components/LengthLabel';\n"
        "export function App() {\n"
        "  return (\n"
        "    <main>\n"
        "      <button type='button'><BodyCallLabel /></button>\n"
        "      <button type='button'><LengthLabel text='' /></button>\n"
        "      <button type='button'><img src='/close.svg' role='img' alt='' aria-label='Close' /></button>\n"
        "      <button type='button'><img src='/close.svg' alt='' /></button>\n"
        "    </main>\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )

    res = TypeScriptReactSpaAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    # Line 6: BodyCallLabel module const + console.debug({label}) -> unobserved (clean)
    # Line 7: LengthLabel {text.length} renders '0' -> unobserved (clean)
    # Line 8: img with aria-label='Close' -> named (clean)
    # Line 9: img with empty alt='' and no ARIA name -> flagged icon-only
    assert [(f.source_file, f.line) for f in disp_005] == [("src/App.tsx", 9)], disp_005
