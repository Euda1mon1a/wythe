"""Regression tests for classification precision (issues #5-#12).

Each block pins behavior that used to misclassify real code: runtime-built URLs, truncated
template paths, Next.js route handlers, separate declarative bases, migration DDL kept in
constants/helpers, dead code vs reachable code, dirty worktrees, and the live route probe.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from app.adapters.base import RawCandidateFinding
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter, _scan_model_module
from app.adapters.treesitter_engine import extract_ts_http_calls_cst, has_treesitter
from app.adapters.typescript_nextjs import _normalize_ts_url
from app.cli import _commit_label
from app.schemas.atlas import TargetProjectCreate
from app.services.diff_and_sarif_service import build_sarif_log
from app.services.governance_service import get_target_by_slug, register_target
from app.services.route_probe_service import apply_live_route_probe
from app.services.scanner_service import _git_dirty_path_count, run_target_scan


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- #6: URL normalizer ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/attempts/${encodeURIComponent(id ?? '')}/review", "/attempts/{param}/review"),
        ("/users/${params.id}/posts", "/users/{param}/posts"),
        ("/reports/${searchId}/rows", "/reports/{param}/rows"),
        ("/users/${id}", "/users/{param}"),
        ("/${resource}/items", "/{param}/items"),
        ("/items${qs ? `?${qs}` : ''}", "/items"),
        ("/items?${params.toString()}", "/items"),
        ("/search${query}", "/search"),
        ("/items/${buildQuery(filters)}", "/items"),
        ("/things/${id}#section", "/things/{param}"),
    ],
)
def test_normalizer_keeps_path_segments_and_drops_query_strings(raw: str, expected: str) -> None:
    assert _normalize_ts_url(raw) == expected


@pytest.mark.skipif(not has_treesitter(), reason="tree-sitter extra not installed")
def test_treesitter_sees_awaited_generic_calls() -> None:
    src = (
        "async function load() {\n"
        "  const a = await post<Summary>(\n"
        "    '/reports/summary', { topN: 5 }\n"
        "  );\n"
        "  const b = await get<User>(`/admin/users/${id}`);\n"
        "  return [a, b];\n"
        "}\n"
    )
    calls = extract_ts_http_calls_cst(src, is_tsx=False) or []
    assert ("POST", "/reports/summary", 2) in calls
    assert ("GET", "/admin/users/${id}", 5) in calls


# --- #5 / #7 / #9: unbacked frontend calls --------------------------------------------


def _build_fullstack_repo(root: Path) -> Path:
    repo = root / "fullstack"
    _write(repo, "backend/schema.sql", "CREATE TABLE things (id INTEGER PRIMARY KEY);\n")
    _write(
        repo,
        "backend/app/models/domain.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Thing(Base):\n"
        "    __tablename__ = 'things'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
    )
    _write(
        repo,
        "backend/app/api/routes.py",
        "from fastapi import APIRouter\n"
        "from app.models.domain import Thing\n"
        "router = APIRouter()\n"
        "@router.get('/things/history')\n"
        "def history(db=None):\n"
        "    return db.query(Thing).all()\n"
        "@router.get('/teams/items')\n"
        "def team_items():\n"
        "    return []\n"
        "@router.get('/projects/items')\n"
        "def project_items():\n"
        "    return []\n",
    )
    _write(
        repo,
        "backend/app/main.py",
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
    )
    _write(
        repo,
        "frontend/tsconfig.json",
        '{\n  // comments and trailing commas are allowed\n'
        '  "compilerOptions": { "paths": { "@/*": ["./src/*"], }, },\n}\n',
    )
    _write(
        repo,
        "frontend/src/lib/api.ts",
        "export async function get<T>(url: string): Promise<T> { return (await fetch(url)).json(); }\n"
        "export async function post<T>(url: string, body: unknown): Promise<T> {\n"
        "  return (await fetch(url, { method: 'POST', body: JSON.stringify(body) })).json();\n"
        "}\n",
    )
    # One module holds a live hook, a dead hook, and a working hook (#9).
    _write(
        repo,
        "frontend/src/hooks/useThings.ts",
        "import { get, post } from '@/lib/api';\n"
        "export interface ThingList { items: string[] }\n"
        "export async function useThingList() {\n"
        "  return await get<ThingList>('/api/v1/things');\n"
        "}\n"
        "export function useThingCreate() {\n"
        "  return post('/api/v1/things', {});\n"
        "}\n"
        "export function useThingHistory() {\n"
        "  return get('/api/v1/things/history');\n"
        "}\n",
    )
    _write(
        repo,
        "frontend/src/hooks/useItems.ts",
        "import { get } from '@/lib/api';\n"
        "export function useItems(kind: string) {\n"
        "  return get(`/api/v1/${kind}/items`);\n"
        "}\n",
    )
    # Barrel with a type-only re-export, plus a legacy re-export of the whole barrel: importing
    # the type name without `type` must not mark every hook in the barrel live.
    _write(
        repo,
        "frontend/src/hooks/index.ts",
        "export * from './useThings';\n"
        "export * from './useItems';\n"
        "export type { ThingList as ThingListAlias } from './useThings';\n",
    )
    _write(repo, "frontend/src/lib/hooks.ts", "export * from '@/hooks';\n")
    _write(
        repo,
        "frontend/src/components/ThingsSidebar.tsx",
        "import { useThingList, ThingListAlias, useItems } from '@/lib/hooks';\n"
        "export function ThingsSidebar() {\n"
        "  void useThingList();\n"
        "  void useItems('teams');\n"
        "  const x: ThingListAlias | null = null;\n"
        "  return <aside>{String(x)}</aside>;\n"
        "}\n",
    )
    # A same-origin call to the frontend's own route handler (#7).
    _write(
        repo,
        "frontend/src/app/admin/report-data/route.ts",
        "export async function GET() { return Response.json({}); }\n",
    )
    _write(
        repo,
        "frontend/src/api/report.ts",
        "export const reportApi = {\n"
        "  load: (year: number) => fetch(`/admin/report-data?year=${year}`),\n"
        "};\n",
    )
    _write(
        repo,
        "frontend/src/app/things/page.tsx",
        "import { ThingsSidebar } from '@/components/ThingsSidebar';\n"
        "import { reportApi } from '@/api/report';\n"
        "export default function ThingsPage() {\n"
        "  void reportApi.load(2026);\n"
        "  return <ThingsSidebar />;\n"
        "}\n",
    )
    return repo


def test_unbacked_calls_split_into_reachable_dead_unresolved_and_local(
    db_session: Session, tmp_path: Path
) -> None:
    repo = _build_fullstack_repo(tmp_path)
    register_target(db_session, TargetProjectCreate(slug="fullstack", name="Fullstack", repo_path=str(repo)))
    target = get_target_by_slug(db_session, "fullstack")
    assert target is not None

    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    by_rule: dict[str, list] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_code, []).append(f)

    disp004 = by_rule.get("DISP-004", [])
    assert [f.title for f in disp004] == [
        "Frontend `GET /api/v1/things` has no matching backend route"
    ]
    assert "Reached from:" in disp004[0].detail
    assert "app/things/page.tsx" in disp004[0].detail
    assert "useThings.ts#useThingList" in disp004[0].detail
    assert disp004[0].blocks_gate is True

    disp007 = by_rule.get("DISP-007", [])
    assert [f.title for f in disp007] == [
        "Frontend `POST /api/v1/things` has no matching backend route (unreachable code)"
    ]
    assert "`useThingCreate`" in disp007[0].detail
    assert disp007[0].blocks_gate is False

    disp006 = by_rule.get("DISP-006", [])
    assert len(disp006) == 1
    assert "`GET /api/v1/{param}/items`" in disp006[0].title
    assert "/teams/items" in disp006[0].detail and "/projects/items" in disp006[0].detail
    assert disp006[0].blocks_gate is False

    assert not any("report-data" in f.title for f in report.findings), "route.ts handlers are not backend calls"
    assert not any("/things/history" in f.title for f in report.findings)


# --- #8 / #10: separate bases and migration DDL ------------------------------------------


def _build_truth_repo(root: Path) -> Path:
    repo = root / "truthrepo"
    _write(
        repo,
        "backend/app/models/domain.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "AUDIT_SCHEMA = 'audit'\n"
        "class Base(DeclarativeBase): pass\n"
        "class WorkspaceBase(DeclarativeBase): pass\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "class Customer(Base):\n"
        "    __tablename__ = 'customers'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "class Legacy(Base):\n"
        "    __tablename__ = 'legacy'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "class Extra(Base):\n"
        "    __tablename__ = 'extras'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "class AuditRow(Base):\n"
        "    __tablename__ = 'rows'\n"
        "    __table_args__ = ({'schema': AUDIT_SCHEMA},)\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "class Draft(WorkspaceBase):\n"
        "    __tablename__ = 'drafts'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
    )
    _write(repo, "backend/schema.sql", "CREATE TABLE customers (id INTEGER PRIMARY KEY);\n")
    # File names sort opposite to the revision chain: ordering must follow down_revision.
    _write(
        repo,
        "backend/alembic/versions/a_drop_legacy.py",
        "from alembic import op\n"
        "revision = '0003'\n"
        "down_revision = '0002'\n"
        "def upgrade():\n"
        "    op.drop_table('legacy')\n",
    )
    _write(
        repo,
        "backend/alembic/versions/b_initial.py",
        "import sqlalchemy as sa\n"
        "from alembic import op\n"
        "revision = '0001'\n"
        "down_revision = None\n"
        "_TABLE = 'orders'\n"
        "def upgrade():\n"
        "    op.create_table(_TABLE, sa.Column('id', sa.Integer()))\n"
        "    op.create_table('legacy', sa.Column('id', sa.Integer()))\n",
    )
    _write(
        repo,
        "backend/alembic/versions/c_ledger.py",
        "import sqlalchemy as sa\n"
        "from alembic import op\n"
        "revision = '0002'\n"
        "down_revision = '0001'\n"
        "_NAME = 'ledger'\n"
        '_DDL = f"""CREATE TABLE public.{_NAME} (id int);\n'
        "CREATE OR REPLACE FUNCTION public.ledger_guard() RETURNS trigger AS $$ BEGIN RETURN NEW; END $$ LANGUAGE plpgsql;\n"
        '"""\n'
        "def _create():\n"
        "    op.execute(sa.text(_DDL))\n"
        "def upgrade():\n"
        "    _create()\n"
        "    op.execute('CREATE TEMP TABLE scratch (x int)')\n"
        "    for name in ('a', 'b'):\n"
        "        op.execute(f'CREATE TABLE IF NOT EXISTS {name}.x (id int)')\n",
    )
    return repo


def test_truth_adapter_reads_migration_constants_helpers_order_and_separate_bases(tmp_path: Path) -> None:
    repo = _build_truth_repo(tmp_path)
    res = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    node_ids = {n.id for n in res.nodes}
    assert "t:ledger" in node_ids, "f-string DDL in a module constant run by a helper is a table"
    assert "fn:ledger_guard" in node_ids
    assert "t:if" not in node_ids and "t:scratch" not in node_ids, "no IF/TEMP artifacts"

    truth002 = sorted(f.node_id for f in res.findings if f.rule_code == "TRUTH-002")
    # orders (create_table via constant) and customers (schema.sql) are fine; legacy was dropped
    # by a later revision; extras has no DDL; drafts is on a separate base; audit.rows is schema-qualified.
    assert truth002 == ["t:extras", "t:legacy"]
    assert any("`WorkspaceBase`" in note for note in res.notes)
    drafts = next(n for n in res.nodes if n.id == "t:drafts")
    assert "separate declarative base `WorkspaceBase`" in drafts.summary


def test_truth_adapter_live_catalog_separates_unmigrated_from_missing(tmp_path: Path) -> None:
    repo = _build_truth_repo(tmp_path)
    db_file = tmp_path / "live.sqlite"
    with sqlite3.connect(db_file) as conn:
        for tbl in ("orders", "customers", "extras", "rows"):
            conn.execute(f"CREATE TABLE {tbl} (id INTEGER)")
    res = PostgresSqlAlchemyAdapter().extract(repo, "backend", pg_dsn=f"sqlite:///{db_file}")
    codes = sorted((f.rule_code, f.node_id) for f in res.findings)
    # extras exists live with no DDL -> TRUTH-005 (warning); legacy is gone live -> TRUTH-002 once.
    # audit.rows is checked under its schema-qualified name (SQLite has no schemas, so it is absent).
    assert ("TRUTH-005", "t:extras") in codes
    assert [c for c in codes if c[1] == "t:legacy"] == [("TRUTH-002", "t:legacy")]
    assert not any(c[1] == "t:drafts" for c in codes), "separate-base models are not checked live"


def test_model_scan_resolves_schema_and_tablename_constants(tmp_path: Path) -> None:
    py = tmp_path / "m.py"
    py.write_text(
        "from sqlalchemy.orm import DeclarativeBase\n"
        "SCHEMA = 'staging'\n"
        "NAME = 'batches'\n"
        "class StagingBase(DeclarativeBase): pass\n"
        "class Batch(StagingBase):\n"
        "    __tablename__ = NAME\n"
        "    __table_args__ = (object(), {'schema': SCHEMA})\n",
        encoding="utf-8",
    )
    scan = _scan_model_module(py, "m.py")
    assert [(m[0], m[1]) for m in scan.models] == [("Batch", "staging.batches")]
    assert "StagingBase" in scan.roots


# --- #11: dirty worktree ----------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def test_dirty_worktree_is_counted_and_labelled(tmp_path: Path) -> None:
    repo = tmp_path / "gitrepo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("a\n")
    (repo / "c.txt").write_text("c\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    assert _git_dirty_path_count(repo) == 0

    (repo / "a.txt").write_text("changed\n")
    (repo / "b.txt").write_text("new\n")
    _git(repo, "mv", "c.txt", "d.txt")
    assert _git_dirty_path_count(repo) == 3  # modified, untracked, and one rename
    assert _git_dirty_path_count(tmp_path / "not-a-repo-dir") is None

    class _Rep:
        source_commit = "0123456789abcdef"
        dirty_path_count = 3

    assert _commit_label(_Rep()) == "0123456789ab + 3 uncommitted paths"


def test_report_and_sarif_carry_worktree_state(db_session: Session, tmp_path: Path) -> None:
    repo = _build_fullstack_repo(tmp_path)
    register_target(db_session, TargetProjectCreate(slug="fullstack2", name="Fullstack", repo_path=str(repo)))
    target = get_target_by_slug(db_session, "fullstack2")
    assert target is not None
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert report.worktree_dirty is None and report.dirty_path_count is None  # not a git repo
    props = build_sarif_log(report)["runs"][0]["properties"]
    assert set(props) == {"sourceCommit", "worktreeDirty", "dirtyPathCount", "observationSource", "scanNotes"}


# --- #12: live route probe ----------------------------------------------------------------


def _finding(code: str, method: str, path: str) -> RawCandidateFinding:
    return RawCandidateFinding(
        rule_code=code,
        node_id="d:hook:x",
        source_file="frontend/src/hooks/x.ts",
        line=1,
        title=f"Frontend `{method} {path}` has no matching backend route",
        detail="static detail.",
        remediation="fix",
        http_method=method,
        http_path=path,
    )


def _mock_backend(status_by_path: dict[str, int], seen: list[httpx.Request]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.method == "GET", "the probe must never send a write"
        assert "cookie" not in request.headers
        if request.url.path.startswith("/__wythe_probe_absent_"):
            return httpx.Response(404)
        return httpx.Response(status_by_path.get(request.url.path, 404), headers={"set-cookie": "s=1"})

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_probe_confirms_clears_and_never_writes() -> None:
    seen: list[httpx.Request] = []
    client = _mock_backend({"/api/v1/widgets": 401, "/api/v1/orders": 405}, seen)
    findings = [
        _finding("DISP-004", "GET", "/api/v1/things"),
        _finding("DISP-004", "GET", "/api/v1/widgets"),
        _finding("DISP-007", "POST", "/api/v1/jobs/{param}"),
        _finding("DISP-004", "POST", "/api/v1/orders"),
        _finding("DISP-001", "GET", "/ignored"),
    ]
    out, note = apply_live_route_probe(findings, "http://127.0.0.1:8000", client=client)
    by_path = {f.http_path: f for f in out}

    assert by_path["/api/v1/things"].rule_code == "DISP-004"
    assert "(confirmed)" in by_path["/api/v1/things"].detail
    assert by_path["/api/v1/widgets"].rule_code == "DISP-006"
    assert "static matcher missed it" in by_path["/api/v1/widgets"].detail
    assert "returned 404" in by_path["/api/v1/jobs/{param}"].detail
    assert "was not verified" in by_path["/api/v1/orders"].detail
    assert by_path["/ignored"].detail == "static detail."
    assert any(r.url.path == "/api/v1/jobs/wythe-probe" for r in seen)
    assert "1 confirmed missing" in note and "1 answered by a live route" in note


def test_probe_refuses_to_conclude_when_control_path_is_not_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    findings = [_finding("DISP-004", "GET", "/api/v1/things")]
    out, note = apply_live_route_probe(findings, "http://127.0.0.1:8000", client=client)
    assert out == findings
    assert note.startswith("Live route probe skipped")


def test_probe_refuses_public_hosts_unless_allowed() -> None:
    with pytest.raises(ValueError, match="not loopback or private"):
        apply_live_route_probe([_finding("DISP-004", "GET", "/x")], "http://93.184.216.34")
    with pytest.raises(ValueError, match="absolute http"):
        apply_live_route_probe([_finding("DISP-004", "GET", "/x")], "ftp://127.0.0.1")
