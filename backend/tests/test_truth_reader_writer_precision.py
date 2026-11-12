"""Truth-tier precision: who really reads/writes a table, and when a Redis write is bounded."""

from __future__ import annotations

from pathlib import Path

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.redis_ephemeral import augment_redis_ephemeral_lineage

_BASE = "from sqlalchemy.orm import DeclarativeBase\nclass Base(DeclarativeBase): pass\n"


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _extract(repo: Path) -> tuple[TruthExtractionResult, ManipulatorExtractionResult]:
    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)
    augment_redis_ephemeral_lineage(repo, "backend", truth, manip)
    return truth, manip


def _findings(manip: ManipulatorExtractionResult, code: str) -> list:
    return [f for f in manip.findings if f.rule_code == code]


# --- TRUTH-003: what counts as a route write -------------------------------------------


def _write_route_repo(root: Path) -> Path:
    repo = root / "routes_repo"
    _write(repo, "backend/schema.sql", "CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT);\n")
    _write(repo, "backend/app/db/base.py", _BASE)
    _write(
        repo,
        "backend/app/models/widget.py",
        "from sqlalchemy.orm import Mapped, mapped_column\n"
        "from app.db.base import Base\n"
        "class Widget(Base):\n"
        "    __tablename__ = 'widgets'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    name: Mapped[str]\n",
    )
    _write(
        repo,
        "backend/app/schemas/widget.py",
        "from pydantic import BaseModel\nclass Widget(BaseModel):\n    id: int\n",
    )
    # A response schema that shares the ORM class name is not the table.
    _write(
        repo,
        "backend/app/api/routes/show.py",
        "from fastapi import APIRouter\n"
        "from app.schemas.widget import Widget\n"
        "router = APIRouter()\n"
        "@router.get('/widgets/{wid}')\n"
        "def show(wid: int) -> Widget:\n"
        "    return Widget(id=wid)\n",
    )
    # A transient ORM object built for a response in a module that never writes to a session.
    _write(
        repo,
        "backend/app/api/routes/preview.py",
        "from fastapi import APIRouter\n"
        "from app.models.widget import Widget\n"
        "router = APIRouter()\n"
        "@router.get('/preview')\n"
        "def preview(db=None):\n"
        "    draft = Widget(id=0, name='draft')\n"
        "    return {'name': draft.name}\n",
    )
    # Deleting and updating rows loaded from the session are writes, reported on their line.
    _write(
        repo,
        "backend/app/api/routes/manage.py",
        "from fastapi import APIRouter\n"
        "from app.models.widget import Widget\n"
        "router = APIRouter()\n"
        "@router.delete('/widgets/{wid}')\n"
        "def remove(wid: int, db=None):\n"
        "    row = db.get(Widget, wid)\n"
        "    db.delete(row)\n"
        "    db.commit()\n",
    )
    _write(
        repo,
        "backend/app/api/routes/rename.py",
        "from fastapi import APIRouter\n"
        "from app.models.widget import Widget\n"
        "router = APIRouter()\n"
        "@router.patch('/widgets/{wid}')\n"
        "def rename(wid: int, name: str, db=None):\n"
        "    row = db.query(Widget).filter(Widget.id == wid).first()\n"
        "    row.name = name\n"
        "    db.commit()\n",
    )
    return repo


def test_route_writes_need_the_orm_class_and_a_session_and_carry_the_write_line(tmp_path: Path) -> None:
    repo = _write_route_repo(tmp_path)
    _, manip = _extract(repo)
    t3 = {Path(f.source_file).stem: f for f in _findings(manip, "TRUTH-003")}

    assert "show" not in t3, "a same-named response schema is not the `widgets` table"
    assert "preview" not in t3, "an ORM object that never reaches a session is not a write"
    assert t3["manage"].line == 7, "db.delete(row) on a loaded row is a write, reported on its line"
    assert t3["rename"].line == 7, "an attribute update on a loaded row, then commit, is a write"


# --- TRUTH-001: readers outside Python, and names that only look like tables ------------


def _write_reader_repo(root: Path) -> Path:
    repo = root / "readers_repo"
    _write(
        repo,
        "backend/schema.sql",
        "CREATE TABLE leases (id INTEGER PRIMARY KEY);\n"
        "CREATE TABLE prefixes (code TEXT PRIMARY KEY);\n"
        "CREATE TABLE objectives (id INTEGER PRIMARY KEY, prefix TEXT REFERENCES prefixes(code));\n"
        "CREATE TABLE zones (id INTEGER PRIMARY KEY);\n"
        "CREATE TABLE zone_notes (id INTEGER PRIMARY KEY, zone_id INTEGER);\n"
        "ALTER TABLE ONLY public.zone_notes\n"
        "    ADD CONSTRAINT zone_notes_zone_fk FOREIGN KEY (zone_id) REFERENCES public.zones(id);\n"
        "CREATE TABLE mail_templates (id INTEGER PRIMARY KEY);\n"
        "CREATE TABLE tag_links (id INTEGER PRIMARY KEY);\n"
        "CREATE FUNCTION public.current_lease() RETURNS integer LANGUAGE sql\n"
        "    AS $$ SELECT id FROM public.leases ORDER BY id DESC LIMIT 1 $$;\n",
    )
    _write(repo, "backend/app/db/base.py", _BASE)
    _write(
        repo,
        "backend/app/models/catalog.py",
        "from sqlalchemy import Column, Integer, Table\n"
        "from sqlalchemy.orm import Mapped, mapped_column\n"
        "from app.db.base import Base\n"
        "class Objective(Base):\n"
        "    __tablename__ = 'objectives'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "tag_links = Table('tag_links', Base.metadata, Column('id', Integer, primary_key=True))\n",
    )
    _write(
        repo,
        "backend/app/services/objective_service.py",
        "from sqlalchemy import select, text\n"
        "from app.models.catalog import Objective, tag_links\n"
        "def list_objectives(db):\n"
        "    return db.scalars(select(Objective)).all()\n"
        "def list_links(db):\n"
        "    return db.execute(select(tag_links)).all()\n"
        "def latest_lease(db):\n"
        "    return db.execute(text('SELECT public.current_lease()')).scalar()\n",
    )
    # An attribute that merely shares a table's name is not a read of that table.
    _write(
        repo,
        "backend/app/services/mailer.py",
        "class Mailer:\n"
        "    def send(self):\n"
        "        return self.mail_templates.render()\n",
    )
    return repo


def test_sql_functions_and_foreign_keys_read_tables_but_name_collisions_do_not(tmp_path: Path) -> None:
    repo = _write_reader_repo(tmp_path)
    _, manip = _extract(repo)
    orphaned = {f.node_id for f in _findings(manip, "TRUTH-001")}

    assert "t:leases" not in orphaned, "a SQL function body that selects from the table reads it"
    assert "t:prefixes" not in orphaned, "a foreign key from a table in use consults its target"
    assert "t:tag_links" not in orphaned, "a Table object imported from the models is a read"
    assert "t:zones" in orphaned, "a foreign key from an unused table does not make the target used"
    assert "t:mail_templates" in orphaned, "`self.mail_templates` is an attribute, not the table"
    edge_kinds = {(e.source_id, e.target_id, e.kind) for e in manip.edges}
    assert ("fn:current_lease", "t:leases", "reads_truth") in edge_kinds
    assert ("t:objectives", "t:prefixes", "guards_truth") in edge_kinds


def test_function_redefined_without_a_readable_body_keeps_its_last_reads(tmp_path: Path) -> None:
    repo = tmp_path / "redefine_repo"
    _write(repo, "backend/schema.sql", "CREATE TABLE carry (id INTEGER PRIMARY KEY);\n")
    _write(repo, "backend/app/db/base.py", _BASE)
    _write(
        repo,
        "backend/alembic/versions/a_fn.py",
        "from alembic import op\n"
        "revision = '0001'\n"
        "down_revision = None\n"
        "def upgrade():\n"
        "    op.execute('CREATE FUNCTION public.publish() RETURNS void LANGUAGE sql AS $$ SELECT id FROM carry $$')\n",
    )
    # A later revision splices text into the fetched definition: the header is visible, the body is not.
    _write(
        repo,
        "backend/alembic/versions/b_patch.py",
        "from alembic import op\n"
        "revision = '0002'\n"
        "down_revision = '0001'\n"
        "_REPLACEMENTS = (('CREATE OR REPLACE FUNCTION public.publish(', 'CREATE OR REPLACE FUNCTION public.publish('),)\n"
        "def upgrade():\n"
        "    for old, new in _REPLACEMENTS:\n"
        "        op.execute(new)\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    assert "fn:publish" in truth.db_readers.get("t:carry", {})


# --- W6: models outside app/models ------------------------------------------------------


def test_models_outside_the_models_package_are_discovered(tmp_path: Path) -> None:
    repo = tmp_path / "feature_models_repo"
    _write(repo, "backend/schema.sql", "CREATE TABLE experiments (id INTEGER PRIMARY KEY);\n")
    _write(repo, "backend/app/db/base.py", _BASE)
    _write(repo, "backend/app/models/__init__.py", "")
    _write(
        repo,
        "backend/app/jobs/records.py",
        "from sqlalchemy.orm import Mapped, mapped_column\n"
        "from app.db.base import Base\n"
        "class JobRun(Base):\n"
        "    __tablename__ = 'job_runs'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "class ExperimentRecord(Base):\n"
        "    __tablename__ = 'experiments'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "def latest(db):\n"
        "    return db.query(ExperimentRecord).first()\n",
    )
    truth, manip = _extract(repo)
    assert [f.node_id for f in truth.findings if f.rule_code == "TRUTH-002"] == ["t:job_runs"]
    assert "t:experiments" not in {f.node_id for f in _findings(manip, "TRUTH-001")}


# --- TRUTH-004: when a Python Redis write is bounded -------------------------------------


def test_python_redis_ttl_detection_and_key_prefixes(tmp_path: Path) -> None:
    repo = tmp_path / "redis_repo"
    _write(repo, "backend/schema.sql", "CREATE TABLE jobs (id INTEGER PRIMARY KEY);\n")
    _write(repo, "backend/app/models/__init__.py", "")
    _write(
        repo,
        "backend/app/services/store.py",
        "import redis\n"
        "redis_client = redis.Redis()\n"
        "def documented():\n"
        '    """Example:\n'
        "        redis_client.set('example:1', 'v')\n"
        '    """\n'
        "def keep(key, value):\n"
        "    redis_client.set(key, value, keepttl=True)\n"
        "def wrapped(cache, key, value):\n"
        "    cache.set(key, value, ttl=60)\n"
        "def positional(value):\n"
        "    redis_client.set('pos:1', value, 30)\n"
        "def hashed(user_id, data):\n"
        "    key = f'profile:{user_id}'\n"
        "    redis_client.hset(key, mapping=data)\n"
        "    redis_client.expire(key, 3600)\n"
        "def maybe(user_id, data, ttl=None):\n"
        "    key = f'limits:{user_id}'\n"
        "    redis_client.hset(key, mapping=data)\n"
        "    if ttl:\n"
        "        redis_client.expire(key, ttl)\n",
    )
    truth, manip = _extract(repo)
    t4 = _findings(manip, "TRUTH-004")
    assert [(f.line, "limits:*" in f.title) for f in t4] == [(19, True)], (
        "only the hset whose expire is conditional stays unbounded; it keeps its f-string prefix"
    )
    stores = {n.id for n in truth.nodes if n.subkind == "cache_store"}
    assert "t:redis:example" not in stores, "a docstring example is not a Redis call"
    assert {"t:redis:profile", "t:redis:limits"} <= stores
