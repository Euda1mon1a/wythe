"""Regression tests for post-sweep review edge cases across Truth, Manipulate, Display, and CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters import typescript_nextjs
from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_ast_inspect import parse_python_module
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.redis_ephemeral import augment_redis_ephemeral_lineage
from app.adapters.treesitter_engine import has_treesitter
from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter
from app.cli import _resolve_cli_target
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- 1-4. Alembic & SQL migration replay, column provenance, and SQL comment blanking ----------


def test_migration_helper_replayed_after_intervening_drop(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/alembic/versions/001_replay.py",
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        "def _build_widgets():\n"
        "    op.create_table('widgets', sa.Column('id', sa.Integer, primary_key=True))\n\n"
        "def upgrade():\n"
        "    _build_widgets()\n"
        "    op.drop_table('widgets')\n"
        "    _build_widgets()\n",
    )
    res = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in res.nodes}
    assert "t:widgets" in by_id


def test_migration_create_rename_recreate_preserves_distinct_columns(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/alembic/versions/002_swap.py",
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        "def upgrade():\n"
        "    op.create_table('ledger', sa.Column('legacy_code', sa.String()))\n"
        "    op.rename_table('ledger', 'ledger_archive')\n"
        "    op.create_table('ledger', sa.Column('entry_id', sa.Integer()))\n"
        "    op.execute('''\n"
        "        CREATE TABLE entries (old_ref TEXT);\n"
        "        ALTER TABLE entries RENAME TO entries_archive;\n"
        "        CREATE TABLE entries (new_ref BIGINT);\n"
        "    ''')\n",
    )
    res = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in res.nodes}
    assert by_id["t:ledger_archive"].columns == ["legacy_code"]
    assert by_id["t:ledger"].columns == ["entry_id"]
    assert by_id["t:entries_archive"].columns == ["old_ref"]
    assert by_id["t:entries"].columns == ["new_ref"]


def test_sql_comments_ignored_without_shifting_line_numbers(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/schema.sql",
        "-- CREATE TABLE phantom_line (id INT);\n"
        "/*\n"
        "CREATE TABLE phantom_block (id INT);\n"
        "*/\n"
        "CREATE TABLE accounts (\n"
        "    id SERIAL PRIMARY KEY\n"
        ");\n"
        "CREATE FUNCTION compute_fee() RETURNS INT AS $$ BEGIN RETURN 1; END; $$ LANGUAGE plpgsql;\n",
    )
    _write(
        tmp_path,
        "backend/alembic/versions/001_init.py",
        "from alembic import op\n\n"
        "def upgrade():\n"
        "    op.execute('''\n"
        "        -- DROP TABLE accounts;\n"
        "        /* ALTER TABLE accounts RENAME TO vanished;\n"
        "           DROP FUNCTION compute_fee; */\n"
        "        CREATE TABLE invoices (id INT);\n"
        "    ''')\n",
    )
    res = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in res.nodes}
    assert "t:accounts" in by_id
    assert by_id["t:accounts"].line == 5
    assert "t:invoices" in by_id
    assert "compute_fee" in res.function_symbol_map
    assert "t:phantom_line" not in by_id
    assert "t:phantom_block" not in by_id
    assert "t:vanished" not in by_id


def test_repeated_sql_constant_execution_replays_after_drop(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/alembic/versions/003_const_replay.py",
        "from alembic import op\n\n"
        "TOKENS_DDL = 'CREATE TABLE tokens (id INT PRIMARY KEY);'\n\n"
        "def upgrade():\n"
        "    op.execute(TOKENS_DDL)\n"
        "    op.drop_table('tokens')\n"
        "    op.execute(f'{TOKENS_DDL}\\nCREATE TABLE sessions (id INT PRIMARY KEY);')\n",
    )
    res = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in res.nodes}
    assert "t:tokens" in by_id
    assert "t:sessions" in by_id


# --- 5. Redis receiver-sensitive TTL matching ---------------------------------------------------


def test_redis_expiry_requires_matching_client_receiver(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/services/cache_pair.py",
        "import redis\n\n"
        "def write_mismatch(redis_primary, redis_secondary, payload):\n"
        "    redis_primary.hset('mismatch_job:state', mapping=payload)\n"
        "    redis_secondary.expire('mismatch_job:state', 60)\n\n"
        "def write_matched(redis_primary, payload):\n"
        "    redis_primary.hset('matched_job:clean', mapping=payload)\n"
        "    redis_primary.expire('matched_job:clean', 60)\n",
    )
    truth = TruthExtractionResult(
        nodes=[], table_symbol_map={}, function_symbol_map={}, findings=[], observation_source="static_ast"
    )
    manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    augment_redis_ephemeral_lineage(tmp_path, "backend", truth, manip)
    titles = [f.title for f in manip.findings if f.rule_code == "TRUTH-004"]
    assert any("mismatch_job:*" in t for t in titles)
    assert not any("matched_job:*" in t for t in titles)


# --- 6-8. Lexical clock scopes, zero-arg clock factories, and sequential ORM row writes ---------


def test_function_local_datetime_import_does_not_bleed_into_siblings() -> None:
    pm = parse_python_module(
        "from datetime import datetime\n\n"
        "def uses_vendor_clock():\n"
        "    from vendor_clock import datetime\n"
        "    return datetime.now()\n\n"
        "def uses_stdlib_clock():\n"
        "    return datetime.now()\n",
        "backend/app/services/clocks.py",
        "app.services.clocks",
    )
    assert pm is not None
    assert [line for _expr, line in pm.raw_clock_calls] == [8]


def test_uncalled_clock_attributes_only_flag_zero_arg_factories() -> None:
    pm = parse_python_module(
        "from collections import defaultdict\n"
        "from dataclasses import dataclass, field\n"
        "from datetime import UTC, date, datetime\n"
        "from functools import partial\n"
        "from sqlalchemy import Column, Date\n\n"
        "def benign_higher_order():\n"
        "    stamps = list(map(datetime.now, [UTC]))\n"
        "    label = getattr(datetime.now, '__name__')\n"
        "    aware_factory = partial(datetime.now, UTC)\n"
        "    return stamps, label, aware_factory\n\n"
        "@dataclass\n"
        "class BadFactories:\n"
        "    created_at: datetime = field(default_factory=datetime.now)\n"
        "    day_col = Column(Date, default=date.today)\n"
        "    lam_at: datetime = field(default_factory=lambda: datetime.now())\n\n"
        "def bad_call_factories():\n"
        "    buckets = defaultdict(datetime.now)\n"
        "    lazy = partial(datetime.now)\n"
        "    shadow_lam = lambda datetime: datetime.now()\n"
        "    return buckets, lazy, shadow_lam\n",
        "backend/app/services/factories.py",
        "app.services.factories",
    )
    assert pm is not None
    assert sorted(line for _expr, line in pm.raw_clock_calls) == [15, 16, 17, 20, 21]


def test_reassigned_local_row_attributes_writes_only_to_latest_table() -> None:
    reassign_pm = parse_python_module(
        "def mutate_after_reassign(db):\n"
        "    row = db.get(User, 1)\n"
        "    _ = row.email\n"
        "    row = db.get(Team, 2)\n"
        "    row.title = 'Platform'\n"
        "    db.commit()\n",
        "backend/app/services/mutations.py",
        "app.services.mutations",
    )
    assert reassign_pm is not None
    assert "Team" in reassign_pm.persisted
    assert "User" not in reassign_pm.persisted
    assert reassign_pm.write_lines["Team"] == 5

    branch_pm = parse_python_module(
        "def mutate_after_partial_branch(db, switch, mode):\n"
        "    item = db.get(User, 1)\n"
        "    if switch:\n"
        "        item = db.get(Team, 2)\n"
        "    item.title = 'Merged'\n"
        "    acct = db.get(Account, 3)\n"
        "    match mode:\n"
        "        case 'activate':\n"
        "            acct.active = True\n"
        "    db.commit()\n",
        "backend/app/services/mutations_branch.py",
        "app.services.mutations_branch",
    )
    assert branch_pm is not None
    assert {"User", "Team", "Account"} <= branch_pm.persisted


# --- 9-11. Module-qualified ORM/Table reads, chained wildcard exports, TYPE_CHECKING & duck types


def test_module_qualified_orm_and_core_table_reads_and_init_relative_imports(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/schema.sql",
        "CREATE TABLE tag_links (id INT PRIMARY KEY);\n"
        "CREATE TABLE objectives (id INT PRIMARY KEY);\n"
        "CREATE TABLE orders (id INT PRIMARY KEY);\n",
    )
    _write(
        tmp_path,
        "backend/app/models/__init__.py",
        "from .catalog import Objective\n",
    )
    _write(
        tmp_path,
        "backend/app/models/catalog.py",
        "from sqlalchemy import Column, Integer, MetaData, Table\n"
        "from sqlalchemy.orm import DeclarativeBase\n\n"
        "class Base(DeclarativeBase):\n"
        "    pass\n\n"
        "metadata = MetaData()\n"
        "tag_links = Table('tag_links', metadata, Column('id', Integer, primary_key=True))\n\n"
        "class Objective(Base):\n"
        "    __tablename__ = 'objectives'\n"
        "    id = Column(Integer, primary_key=True)\n\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id = Column(Integer, primary_key=True)\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/catalog.py",
        "from fastapi import APIRouter\n"
        "from sqlalchemy import select\n"
        "from app.models import Objective, catalog\n\n"
        "router = APIRouter()\n\n"
        "class LocalHolder:\n"
        "    def __init__(self):\n"
        "        self.orders = []\n"
        "    def local_only(self):\n"
        "        return self.orders\n\n"
        "@router.get('/api/v1/catalog')\n"
        "def read_catalog(db):\n"
        "    db.execute(select(catalog.tag_links))\n"
        "    db.execute(select(catalog.Objective))\n"
        "    return Objective.__name__\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    read_targets = {e.target_id for e in manip.edges if e.kind == "reads_truth"}
    assert "t:tag_links" in read_targets
    assert "t:objectives" in read_targets
    assert "t:orders" not in read_targets


def _extract_manip(root: Path) -> ManipulatorExtractionResult:
    empty_truth = TruthExtractionResult(
        nodes=[], table_symbol_map={}, function_symbol_map={}, findings=[], observation_source="static_ast"
    )
    return PythonFastApiAdapter().extract(root, "backend", empty_truth)


def test_chained_wildcard_reexports_across_packages(tmp_path: Path) -> None:
    _write(tmp_path, "backend/app/services/worker.py", "def run_task():\n    return 'ok'\n")
    _write(tmp_path, "backend/app/services/__init__.py", "from .worker import run_task\n")
    _write(tmp_path, "backend/app/facade/__init__.py", "from app.services import *\n")
    _write(
        tmp_path,
        "backend/app/api/routes/jobs.py",
        "from fastapi import APIRouter\n"
        "from app.facade import run_task\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/jobs')\n"
        "def trigger_job():\n"
        "    return run_task()\n",
    )
    res = _extract_manip(tmp_path)
    helper_targets = {e.target_id for e in res.edges if e.kind == "calls_helper"}
    inert = {f.node_id for f in res.findings if f.rule_code == "MANIP-003"}
    assert "m:service:services.worker" in helper_targets
    assert "m:service:services.worker" not in inert


def test_type_checking_imports_and_incompatible_duck_types_do_not_forge_edges(tmp_path: Path) -> None:
    _write(tmp_path, "backend/app/services/ghost.py", "class GhostType:\n    pass\n")
    _write(
        tmp_path,
        "backend/app/services/slot_catalog.py",
        "class SlotCatalog:\n"
        "    def list_slots(self):\n"
        "        return []\n",
    )
    _write(
        tmp_path,
        "backend/app/services/compatible_caller.py",
        "def fetch_slots(catalog):\n"
        "    return catalog.list_slots()\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/slots.py",
        "from typing import TYPE_CHECKING\n"
        "from fastapi import APIRouter\n"
        "from app.services.compatible_caller import fetch_slots\n\n"
        "if TYPE_CHECKING:\n"
        "    from app.services.ghost import GhostType\n\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/slots')\n"
        "def read_slots(db):\n"
        "    db.execute('SELECT 1')\n"
        "    return db.list_slots(), fetch_slots(None)\n",
    )
    res = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in res.edges if e.kind == "calls_helper"}
    inert = {f.node_id for f in res.findings if f.rule_code == "MANIP-003"}
    assert "m:service:services.ghost" in inert
    assert ("m:route:slots", "m:service:services.slot_catalog") not in pairs
    assert ("m:service:services.compatible_caller", "m:service:services.slot_catalog") in pairs


# --- 12-14. TS URL constant method/shadowing, JSX regex open-tag scan, and CLI '.'/'..' paths ---


def test_ts_url_constant_method_and_shadowed_binding_both_engines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert has_treesitter() is True
    src = (
        "const ENDPOINT = '/api/v1/widgets';\n"
        "const BASE = '/api/v1/widgets';\n"
        "export async function createWidget() {\n"
        "  return fetch(ENDPOINT, { method: 'POST' });\n"
        "}\n"
        "export async function loadUsers() {\n"
        "  const USERS_URL = '/api/v1/users';\n"
        "  return fetch(USERS_URL);\n"
        "}\n"
        "export async function loadCustom(BASE: string) {\n"
        "  return fetch(`${BASE}/items`);\n"
        "}\n"
        "export async function loadDynamic(host: string) {\n"
        "  const BASE = host;\n"
        "  return fetch(`${BASE}/dynamic`);\n"
        "}\n"
        "export default function Page() { return null; }\n"
    )
    _write(tmp_path, "frontend/src/app/widgets/page.tsx", src)
    ts_res = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    ts_calls = {(c.http_method, c.normalized_path) for c in ts_res.http_calls}
    assert ("POST", "/api/v1/widgets") in ts_calls
    assert ("GET", "/api/v1/users") in ts_calls
    assert not any(p.startswith("/api/v1/widgets/items") for _m, p in ts_calls)
    assert not any(p.startswith("/api/v1/widgets/dynamic") for _m, p in ts_calls)

    monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    fallback_res = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    fb_calls = {(c.http_method, c.normalized_path) for c in fallback_res.http_calls}
    assert ("POST", "/api/v1/widgets") in fb_calls
    assert ("GET", "/api/v1/users") in fb_calls
    assert not any(p.startswith("/api/v1/widgets/items") for _m, p in fb_calls)
    assert not any(p.startswith("/api/v1/widgets/dynamic") for _m, p in fb_calls)


def test_jsx_open_tag_scanner_skips_regex_braces_and_angles(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "frontend/src/app/filter/page.tsx",
        "export default function FilterPage() {\n"
        "  return (\n"
        "    <input onChange={(e) => e.target.value.replace(/\\{|>/g, '')} />\n"
        "  );\n"
        "}\n",
    )
    res = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    a11y = [f for f in res.findings if f.rule_code == "DISP-005"]
    assert len(a11y) == 1


def test_cli_dot_and_dotdot_paths_resolve_to_filesystem_over_slug_collision(
    tmp_path: Path, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    actual = tmp_path / "parent_dir" / "child_repo"
    (actual / "backend").mkdir(parents=True)
    register_target(
        db_session,
        TargetProjectCreate(
            slug="child_repo",
            name="Decoy Collision",
            repo_path=str(decoy),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    monkeypatch.chdir(actual)
    dot_target, dot_persisted = _resolve_cli_target(db_session, ".", "auto")
    assert dot_persisted is False
    assert Path(dot_target.repo_path).resolve() == actual.resolve()

    dotdot_target, _ = _resolve_cli_target(db_session, "..", "auto")
    assert Path(dotdot_target.repo_path).resolve() == actual.parent.resolve()



def test_loop_branch_row_bindings_and_deferred_module_clock_imports() -> None:
    loop_pm = parse_python_module(
        "def update_after_loop(db, ids):\n"
        "    for uid in ids:\n"
        "        if uid > 0:\n"
        "            row = db.get(Widget, uid)\n"
        "        else:\n"
        "            row = db.get(Widget, 1)\n"
        "    row.name = 'changed'\n"
        "    db.commit()\n",
        "backend/app/services/loop_mut.py",
        "app.services.loop_mut",
    )
    assert loop_pm is not None
    assert "Widget" in loop_pm.persisted

    clock_pm = parse_python_module(
        "def read_now():\n"
        "    return dt.datetime.now()\n\n"
        "import datetime as dt\n",
        "backend/app/services/late_import.py",
        "app.services.late_import",
    )
    assert clock_pm is not None
    assert [line for _expr, line in clock_pm.raw_clock_calls] == [2]


def test_nested_callback_partial_param_shadow_preserves_unshadowed_duck_type(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/services/task_runner.py",
        "class TaskRunner:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/tasks.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/tasks')\n"
        "def run_all(service, data):\n"
        "    def callback(data):\n"
        "        return service.execute_tasks(), data\n"
        "    return callback(data)\n",
    )
    res = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in res.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.tasks", "m:service:services.task_runner") in pairs


def test_fallback_param_defaults_and_jsx_postfix_division(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        "frontend/src/app/calc/page.tsx",
        "const BASE = '/api/v1/calc';\n"
        "export async function loadCalc(url: string = BASE) {\n"
        "  return fetch(BASE);\n"
        "}\n"
        "export default function CalcPage({ total, count }: { total?: number; count: number }) {\n"
        "  let idx = 1;\n"
        "  return (\n"
        "    <div>\n"
        "      <input value={total! / count} readOnly />\n"
        "      <input value={idx++ / count} readOnly />\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    res = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    calls = {(c.http_method, c.normalized_path) for c in res.http_calls}
    assert ("GET", "/api/v1/calc") in calls
    a11y = [f for f in res.findings if f.rule_code == "DISP-005"]
    assert len(a11y) == 2



def test_try_handler_row_bindings_inherited_method_profiles_and_local_migration_helpers(
    tmp_path: Path,
) -> None:
    try_pm = parse_python_module(
        "def recover_row(db):\n"
        "    row = None\n"
        "    try:\n"
        "        row = db.get(Widget, 1)\n"
        "        raise RuntimeError('boom')\n"
        "    except RuntimeError:\n"
        "        if row is not None:\n"
        "            row.state = 'failed'\n"
        "            db.commit()\n",
        "backend/app/services/recover.py",
        "app.services.recover",
    )
    assert try_pm is not None
    assert "Widget" in try_pm.persisted

    _write(
        tmp_path,
        "backend/app/services/base_runner.py",
        "class BaseRunner:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/services/runner.py",
        "from app.services.base_runner import BaseRunner\n\n"
        "class Runner(BaseRunner):\n"
        "    def __init__(self):\n"
        "        self.config = {}\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/run.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/run')\n"
        "def trigger(runner):\n"
        "    _ = runner.config\n"
        "    return runner.execute_tasks()\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.run", "m:service:services.base_runner") in pairs
    assert ("m:route:api.routes.run", "m:service:services.runner") in pairs

    _write(
        tmp_path,
        "backend/alembic/versions/004_nested.py",
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        "def upgrade():\n"
        "    def _create_live():\n"
        "        op.create_table('nested_live', sa.Column('id', sa.Integer()))\n\n"
        "    def _uncalled_dead():\n"
        "        op.create_table('nested_dead', sa.Column('id', sa.Integer()))\n\n"
        "    _create_live()\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert "t:nested_live" in by_id
    assert "t:nested_dead" not in by_id


def test_dollar_quoted_sql_column_defaults_string_literal_bind_ignore_and_eof_url_const(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        "backend/schema.sql",
        "CREATE TABLE scripts (\n"
        "    id INT,\n"
        "    body TEXT DEFAULT $$it's, (here)$$,\n"
        "    title TEXT\n"
        ");\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert by_id["t:scripts"].columns == ["id", "body", "title"]

    _write(
        tmp_path,
        "frontend/src/app/users/page.tsx",
        "const label = 'const URL placeholder';\n"
        "const rx = /'const URL = 1'/g;\n"
        "const note = `${[1].map((x) => { let URL = '/shadow'; return x; })}`;\n"
        "export function UsersPage() {\n"
        "  return <div><p>Don't drop URL</p><button onClick={() => fetch(URL)}>Go</button></div>;\n"
        "}\n"
        "const URL = '/api/v1/users'",
    )
    monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    disp = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    calls = {(c.http_method, c.normalized_path) for c in disp.http_calls}
    assert ("GET", "/api/v1/users") in calls


def test_loop_else_mutations_comprehension_param_shadow_and_lexical_migration_helpers(
    tmp_path: Path,
) -> None:
    for_else_pm = parse_python_module(
        "def finalize_for(db, ids):\n"
        "    for uid in ids:\n"
        "        row = db.get(Widget, uid)\n"
        "    else:\n"
        "        row.name = 'done'\n"
        "    db.commit()\n",
        "backend/app/services/for_else.py",
        "app.services.for_else",
    )
    assert for_else_pm is not None
    assert "Widget" in for_else_pm.persisted

    while_else_pm = parse_python_module(
        "def finalize_while(db, pending):\n"
        "    while pending:\n"
        "        row = db.get(Gadget, pending.pop())\n"
        "    else:\n"
        "        row.status = 'done'\n"
        "    db.commit()\n",
        "backend/app/services/while_else.py",
        "app.services.while_else",
    )
    assert while_else_pm is not None
    assert "Gadget" in while_else_pm.persisted

    _write(
        tmp_path,
        "backend/app/services/worker_svc.py",
        "class WorkerService:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/jobs.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/jobs')\n"
        "def run_jobs(worker, employees):\n"
        "    labels = [worker.name for worker in employees]\n"
        "    by_id = {worker.id: worker.role for worker in employees}\n"
        "    return worker.execute_tasks(), labels, by_id\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.jobs", "m:service:services.worker_svc") in pairs

    _write(
        tmp_path,
        "backend/alembic/versions/005_lexical_helper.py",
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        "def build_widgets():\n"
        "    op.create_table('live_widgets', sa.Column('id', sa.Integer()))\n\n"
        "def run_helper():\n"
        "    build_widgets()\n\n"
        "def upgrade():\n"
        "    def build_widgets():\n"
        "        op.create_table('local_widgets', sa.Column('id', sa.Integer()))\n\n"
        "    run_helper()\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert "t:live_widgets" in by_id
    assert "t:local_widgets" not in by_id


def test_rebound_injected_param_excludes_post_rebind_attributes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/services/worker_only.py",
        "class WorkerOnly:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/rebind.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/rebind-assign')\n"
        "def rebind_assign(worker, flag):\n"
        "    if flag:\n"
        "        worker = object()\n"
        "        return getattr(worker, 'unused', None) or worker.early_name\n"
        "    def show_later():\n"
        "        return worker.closure_name\n"
        "    res = worker.execute_tasks()\n"
        "    worker = object()\n"
        "    return res, worker.name, show_later()\n\n"
        "@router.post('/api/v1/rebind-loop')\n"
        "def rebind_loop(worker, emp):\n"
        "    res = worker.execute_tasks()\n"
        "    for worker in [emp]:\n"
        "        _ = worker.badge\n"
        "    return res, worker.role\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.rebind", "m:service:services.worker_only") in pairs


def test_kwarg_injected_param_calls_and_sql_array_column_defaults(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/schema.sql",
        "CREATE TABLE feature_flags (\n"
        "    id INT,\n"
        "    flags BOOLEAN[] DEFAULT ARRAY[false, false, false],\n"
        "    title TEXT\n"
        ");\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert by_id["t:feature_flags"].columns == ["id", "flags", "title"]

    _write(
        tmp_path,
        "backend/app/services/dispatcher_worker.py",
        "class DispatcherWorker:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/dispatch.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "def send(**kwargs):\n"
        "    return kwargs\n\n"
        "@router.post('/api/v1/dispatch')\n"
        "def run_dispatch(worker):\n"
        "    return send(result=worker.execute_tasks())\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.dispatch", "m:service:services.dispatcher_worker") in pairs


def test_branch_isolated_callbacks_deferred_lambda_row_writes_and_logged_sql_consts(
    tmp_path: Path,
) -> None:
    readonly_pm = parse_python_module(
        "def read_with_deferred_lambda(db):\n"
        "    row = db.get(User, 1)\n"
        "    callback = lambda: setattr(row, 'name', 'changed')\n"
        "    db.commit()\n"
        "    return row, callback\n",
        "backend/app/services/deferred_lam.py",
        "app.services.deferred_lam",
    )
    assert readonly_pm is not None
    assert "User" not in readonly_pm.persisted

    _write(
        tmp_path,
        "backend/app/services/branch_worker.py",
        "class BranchWorker:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/branch_cb.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/branch-cb')\n"
        "def run_branch_cb(worker, flag):\n"
        "    def callback():\n"
        "        return worker.execute_tasks()\n"
        "    if flag:\n"
        "        callback = None\n"
        "    else:\n"
        "        return callback()\n"
        "    return None\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.branch_cb", "m:service:services.branch_worker") in pairs

    _write(
        tmp_path,
        "backend/alembic/versions/006_logged_const.py",
        "from alembic import op\n\n"
        "CREATE_WIDGETS = 'CREATE TABLE widgets (id INT PRIMARY KEY);'\n\n"
        "def upgrade():\n"
        "    op.execute(CREATE_WIDGETS)\n"
        "    op.drop_table('widgets')\n"
        "    print(CREATE_WIDGETS)\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert "t:widgets" not in by_id


def test_zero_iteration_loop_preserves_injected_param_liveness(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/services/zero_iter_worker.py",
        "class ZeroIterWorker:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/zero_iter.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/zero-iter-loop')\n"
        "def run_zero_iter(worker, candidates):\n"
        "    for worker in candidates:\n"
        "        _ = worker.badge\n"
        "    return worker.execute_tasks()\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/zero_iter_comp.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/zero-iter-comp')\n"
        "def run_zero_iter_comp(worker, candidates):\n"
        "    seen = [(worker := c, worker.badge) for c in [*candidates]]\n"
        "    return seen, worker.execute_tasks()\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.zero_iter", "m:service:services.zero_iter_worker") in pairs
    assert ("m:route:api.routes.zero_iter_comp", "m:service:services.zero_iter_worker") in pairs


def test_migration_helper_defaults_closures_and_asi_arrow_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        "backend/alembic/versions/007_defaults_and_closures.py",
        "from alembic import op\n\n"
        "CREATE_DEFAULT = 'CREATE TABLE default_widgets (id INT PRIMARY KEY);'\n"
        "CREATE_KW = 'CREATE TABLE kw_widgets (id INT PRIMARY KEY);'\n"
        "CREATE_NESTED = 'CREATE TABLE nested_widgets (id INT PRIMARY KEY);'\n"
        "CREATE_SKIPPED = 'CREATE TABLE skipped_widgets (id INT PRIMARY KEY);'\n\n"
        "def run_default(sql=CREATE_DEFAULT, *, extra=CREATE_KW):\n"
        "    op.execute(sql)\n"
        "    op.execute(extra)\n\n"
        "def run_skipped(sql=CREATE_SKIPPED):\n"
        "    op.execute(sql)\n\n"
        "def run_nested(sql):\n"
        "    def inner():\n"
        "        op.execute(sql)\n"
        "    inner()\n\n"
        "def upgrade():\n"
        "    run_default()\n"
        "    run_skipped(None)\n"
        "    run_nested(CREATE_NESTED)\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert "t:default_widgets" in by_id
    assert "t:kw_widgets" in by_id
    assert "t:nested_widgets" in by_id
    assert "t:skipped_widgets" not in by_id

    _write(
        tmp_path,
        "frontend/src/app/items/page.tsx",
        "const URL = '/api/v1/items'\n"
        "const identity = URL => URL\n"
        "const chained = URL =>\n"
        "  fetch(URL)\n"
        "    .then(r => r.json())\n"
        "export function ItemsPage() {\n"
        "  identity('/shadow')\n"
        "  chained('/shadow-2')\n"
        "  fetch(URL)\n"
        "  return <div />\n"
        "}\n",
    )
    monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    disp = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    calls = {(c.http_method, c.normalized_path) for c in disp.http_calls}
    assert ("GET", "/api/v1/items") in calls


def test_finally_preserves_terminating_paths_without_polluting_fallthrough(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/services/finally_worker.py",
        "class FinallyWorker:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/finally_route.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/finally-return')\n"
        "def run_finally_return(worker, flag, replacement):\n"
        "    try:\n"
        "        if flag:\n"
        "            return None\n"
        "        worker = replacement\n"
        "    finally:\n"
        "        worker.execute_tasks()\n"
        "    return worker.post_rebind_only\n\n"
        "@router.post('/api/v1/finally-break')\n"
        "def run_finally_break(worker, flag, replacement):\n"
        "    for _ in [1]:\n"
        "        try:\n"
        "            if flag:\n"
        "                break\n"
        "            worker = replacement\n"
        "        finally:\n"
        "            worker.execute_tasks()\n"
        "    return None\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.finally_route", "m:service:services.finally_worker") in pairs


def test_variadic_migration_helpers_and_caller_stored_service_attrs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        "backend/alembic/versions/0001_variadic.py",
        "revision = '0001'\n"
        "down_revision = None\n"
        "from alembic import op\n\n"
        "CREATE_ALPHA = 'CREATE TABLE alpha_items (id INT PRIMARY KEY);'\n"
        "CREATE_BETA = 'CREATE TABLE beta_items (id INT PRIMARY KEY);'\n"
        "DROP_BETA = 'DROP TABLE beta_items;'\n"
        "CREATE_GAMMA = 'CREATE TABLE gamma_items (id INT PRIMARY KEY);'\n"
        "CREATE_DELTA = 'CREATE TABLE delta_items (id INT PRIMARY KEY);'\n\n"
        "def execute_all(*statements):\n"
        "    for sql in statements:\n"
        "        op.execute(sql)\n\n"
        "def execute_named(**queries):\n"
        "    for key in queries:\n"
        "        op.execute(queries[key])\n\n"
        "def upgrade():\n"
        "    execute_all(CREATE_ALPHA, CREATE_BETA)\n"
        "    execute_all(DROP_BETA)\n"
        "    execute_named(gamma=CREATE_GAMMA, delta=CREATE_DELTA)\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert "t:alpha_items" in by_id
    assert "t:gamma_items" in by_id
    assert "t:delta_items" in by_id
    assert "t:beta_items" not in by_id

    _write(
        tmp_path,
        "backend/app/services/base_worker.py",
        "class BaseWorker:\n"
        "    def execute_tasks(self):\n"
        "        return 1\n",
    )
    _write(
        tmp_path,
        "backend/app/services/concrete_worker.py",
        "from app.services.base_worker import BaseWorker\n\n"
        "class ConcreteWorker(BaseWorker):\n"
        "    def run_extra(self):\n"
        "        return 2\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/trace_route.py",
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/traced-work')\n"
        "def run_traced(worker):\n"
        "    worker.trace_id = 'request-1'\n"
        "    _ = worker.trace_id\n"
        "    setattr(worker, 'span_id', 'span-1')\n"
        "    worker.local_cb = lambda: 0\n"
        "    worker.local_cb()\n"
        "    if hasattr(worker, 'optional_flush'):\n"
        "        worker.optional_flush()\n"
        "    return worker.run_extra() + worker.execute_tasks()\n",
    )
    manip = _extract_manip(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:route:api.routes.trace_route", "m:service:services.concrete_worker") in pairs

    _write(
        tmp_path,
        "frontend/src/app/users/page.tsx",
        "const USERS_URL = '/api/v1/users';\n"
        "const UPDATE_URL = '/api/v1/users/sync';\n"
        "export function UsersPage() {\n"
        "  void fetch(USERS_URL, { headers: { method: 'POST' } });\n"
        "  void fetch('/api/v1/direct', { headers: { method: 'DELETE' } });\n"
        "  void fetch(UPDATE_URL, { headers: { method: 'DELETE' }, method: 'POST' });\n"
        "  return <div />;\n"
        "}\n",
    )
    disp_cst = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    cst_calls = {(c.http_method, c.normalized_path) for c in disp_cst.http_calls}
    assert ("GET", "/api/v1/users") in cst_calls
    assert ("POST", "/api/v1/users") not in cst_calls
    assert ("GET", "/api/v1/direct") in cst_calls
    assert ("POST", "/api/v1/users/sync") in cst_calls

    monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    disp_fb = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    fb_calls = {(c.http_method, c.normalized_path) for c in disp_fb.http_calls}
    assert ("GET", "/api/v1/users") in fb_calls
    assert ("POST", "/api/v1/users") not in fb_calls
    assert ("GET", "/api/v1/direct") in fb_calls
    assert ("POST", "/api/v1/users/sync") in fb_calls








