"""Import evidence must distinguish selected code, eager effects and unknown targets."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter
from app.schemas.atlas import TargetProjectCreate
from app.services.diff_and_sarif_service import _directional_slice
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import run_target_scan


@pytest.mark.parametrize("separator", ["\n ", " "])
def test_each_multi_declaration_export_keeps_its_live_call(tmp_path: Path, separator: str) -> None:
    _write(tmp_path, "frontend/src/app/page.tsx", (
        "import { Second } from '../features/widgets';\n"
        "export default function Page() { return Second(); }\n"
    ))
    _write(tmp_path, "frontend/src/features/widgets.ts", (
        f"export const First = () => 1,{separator}Second = () => fetch('/missing');\n"
    ))
    result = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    assert next(c for c in result.http_calls if c.raw_path == "/missing").reachable is True


def test_unreadable_entry_does_not_crash_or_prove_other_code_unused(tmp_path: Path) -> None:
    _write(tmp_path, "frontend/src/app/page.tsx", "")
    (tmp_path / "frontend/src/app/page.tsx").write_bytes(b"\xff\xfe")
    _write(tmp_path, "frontend/src/features/feature.ts", "export const load = () => fetch('/missing');\n")
    result = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    assert next(c for c in result.http_calls if c.raw_path == "/missing").reachable is None
    assert any("Unreadable source" in note for note in result.notes)


def _write(root: Path, name: str, source: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)


def _repo(root: Path, selector: str) -> Path:
    _write(root, "backend/schema.sql", "CREATE TABLE widgets (id INTEGER PRIMARY KEY);\n")
    _write(root, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(root, "frontend/src/app/page.tsx", (
        "import dynamic from 'next/dynamic';\n"
        f"const Selected = dynamic(() => import('@/features/widgets'){selector});\n"
        "export default function Page() { return <Selected/>; }\n"
    ))
    _write(root, "frontend/src/features/widgets/index.ts", (
        "export { Active } from './active';\n"
        "export { Dormant } from './dormant';\n"
        "export { initialize } from './registration';\n"
    ))
    _write(root, "frontend/src/features/widgets/active.ts", (
        "export function Active() { return fetch('/missing-active'); }\n"
    ))
    _write(root, "frontend/src/features/widgets/dormant.ts", (
        "export function Dormant() { return fetch('/missing-dormant'); }\n"
        "export default Dormant;\n"
    ))
    _write(root, "frontend/src/features/widgets/registration.ts", (
        "export const initialize = fetch('/missing-eager');\n"
        "export function Unused() { return fetch('/missing-unused'); }\n"
        "fetch('/missing-top-level');\n"
    ))
    return root


@pytest.mark.parametrize("selector", [
    ".then(m => m.Active)",
    ".then((module) => module.Active)",
    ".then(m => { return m.Active; })",
])
def test_selected_export_keeps_dead_calls_and_import_time_effects_distinct(
    tmp_path: Path, selector: str,
) -> None:
    result = TypeScriptNextJsAdapter().extract(_repo(tmp_path, selector), "frontend")
    calls = {c.raw_path: c for c in result.http_calls}
    assert calls["/missing-active"].reachable is True
    assert calls["/missing-dormant"].reachable is False
    assert calls["/missing-eager"].reachable is True
    assert calls["/missing-top-level"].reachable is True
    assert any("selected export Active" in n for n in result.notes)

    # The existing directional blast-radius traversal must include the dynamic consumer.
    active = next(n for n in result.nodes if n.source_file.endswith("/active.ts"))
    page = next(n for n in result.nodes if n.subkind == "page")
    reverse: dict[str, set[str]] = {}
    for edge in result.edges:
        reverse.setdefault(edge.target_id, set()).add(edge.source_id)
    assert page.id in _directional_slice({active.id}, reverse)
    eager = next(n for n in result.nodes if n.source_file.endswith("/registration.ts"))
    assert page.id in _directional_slice({eager.id}, reverse)
    dormant = next(n for n in result.nodes if n.source_file.endswith("/dormant.ts"))
    assert page.id not in _directional_slice({dormant.id}, reverse)


@pytest.mark.parametrize("selector", [
    "", ".then(m => m[chosen])", ".then(m => { m.initialize(); return m.Active; })",
    ".then(m => flag ? m.Active : m.Dormant)",
])
def test_unknown_dynamic_selector_keeps_all_exports_live(tmp_path: Path, selector: str) -> None:
    result = TypeScriptNextJsAdapter().extract(_repo(tmp_path, selector), "frontend")
    calls = {c.raw_path: c for c in result.http_calls}
    assert calls["/missing-dormant"].reachable is True
    assert any("all exports conservatively retained" in n for n in result.notes)


def test_blast_radius_retains_every_dynamic_consumer(tmp_path: Path) -> None:
    _repo(tmp_path, ".then(m => m.Active)")
    _write(tmp_path, "frontend/src/app/other/page.tsx", (
        "const Chart = dynamic(() => import('@/features/widgets').then(m => m.Active));\n"
        "export default function Page() { return <Chart/>; }\n"
    ))
    result = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    active = next(n for n in result.nodes if n.source_file.endswith('/active.ts'))
    pages = {n.id for n in result.nodes if n.subkind == 'page'}
    assert len(pages) == 2
    assert {e.source_id for e in result.edges if e.target_id == active.id} >= pages


def test_unknown_target_is_reported_and_not_silent(tmp_path: Path) -> None:
    _repo(tmp_path, ".then(m => m.Active)")
    _write(tmp_path, "frontend/src/app/page.tsx", (
        "export default function Page() { return import(modulePath); }\n"
    ))
    result = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    assert any("target unresolved" in n for n in result.notes)
    assert any("not evidence of no caller" in n for n in result.notes)
    assert all(c.reachable is None for c in result.http_calls)


def test_require_keeps_conservative_dependencies(tmp_path: Path) -> None:
    _repo(tmp_path, "")
    _write(tmp_path, "frontend/src/app/page.tsx", (
        "export default function Page() { return require('@/features/widgets'); }\n"
    ))
    result = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    calls = {c.raw_path: c for c in result.http_calls}
    assert calls["/missing-dormant"].reachable is True
    assert calls["/missing-eager"].reachable is True
    assert calls["/missing-top-level"].reachable is True


def test_type_only_reexport_does_not_execute_module(tmp_path: Path) -> None:
    _repo(tmp_path, ".then(m => m.Active)")
    _write(tmp_path, "frontend/src/features/widgets/index.ts", (
        "export { Active } from './active';\n"
        "export type * from './registration';\n"
    ))
    result = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    calls = {c.raw_path: c for c in result.http_calls}
    assert calls["/missing-eager"].reachable is False


def test_fallback_does_not_claim_selective_import_proof(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    result = TypeScriptNextJsAdapter().extract(_repo(tmp_path, ".then(m => m.Active)"), "frontend")
    calls = {c.raw_path: c for c in result.http_calls}
    assert calls["/missing-dormant"].reachable is True
    assert any("all exports conservatively retained" in n for n in result.notes)


def test_scan_preserves_inactive_findings_and_analysis_limits(db_session: Session, tmp_path: Path) -> None:
    _repo(tmp_path, ".then(m => m.Active)")
    register_target(db_session, TargetProjectCreate(slug="imports", name="Imports", repo_path=str(tmp_path)))
    target = get_target_by_slug(db_session, "imports")
    assert target is not None
    report = run_target_scan(db_session, target, persist_snapshot=False)
    inactive = [f for f in report.findings if "/missing-dormant" in f.title]
    assert len(inactive) == 1
    assert inactive[0].rule_code == "DISP-007"
    assert "runtime registration" in inactive[0].detail
    assert any("not removal approval" in n for n in report.scan_notes)
