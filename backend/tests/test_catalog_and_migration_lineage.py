"""Truth-tier lineage: privilege-blind live catalog, migration renames, DDL provenance, rule seed."""

from __future__ import annotations

from pathlib import Path
from typing import Self

import pytest

from app.adapters import db_catalog_probe
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter, _collect_migration_effects
from app.db.seed import INITIAL_RULE_POLICIES


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- live catalog: names come from pg_catalog, not the privilege-filtered information_schema --


class _FakeCursor:
    def __init__(self, sink: list[str], rows: list[tuple[str, str]]) -> None:
        self._sink, self._rows = sink, rows

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: str) -> None:
        self._sink.append(sql)

    def fetchall(self) -> list[tuple[str, str]]:
        return self._rows


class _FakeConn:
    def __init__(self, sink: list[str], rows: list[tuple[str, str]]) -> None:
        self._sink, self._rows = sink, rows

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: str) -> None:
        self._sink.append(sql)

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._sink, self._rows)


def test_pg_probe_reads_pg_catalog_read_only_and_keys_by_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[str] = []
    rows = [("public", "Orders"), ("audit", "events")]

    def fake_connect(url: str, autocommit: bool = False) -> _FakeConn:
        assert autocommit is True, "one autocommit statement: no transaction holds catalog locks"
        return _FakeConn(sent, rows)

    monkeypatch.setattr(db_catalog_probe.psycopg, "connect", fake_connect)
    tables, source = db_catalog_probe.probe_live_catalog_tables("postgresql://probe@127.0.0.1/app")

    assert tables == {"orders", "audit.events"}
    assert source == "static_ast+pg_catalog_readonly"
    assert sent[0] == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
    query = sent[1]
    # information_schema.tables hides every table the probe role holds no privilege on, which
    # turned least-privilege probes into false "absent from live catalog" drift.
    assert "information_schema.tables" not in query
    assert "pg_catalog.pg_class" in query and "relispartition" in query


# --- migrations: renames retire the old name, in the order the revision runs ------------------


def _migration(rev: str, down: str | None, body: str) -> str:
    return (
        "import sqlalchemy as sa\n"
        "from alembic import op\n"
        f"revision = {rev!r}\n"
        f"down_revision = {down!r}\n"
        f"{body}"
    )


def test_sql_and_op_renames_replace_the_old_table_name(tmp_path: Path) -> None:
    repo = tmp_path / "renames"
    _write(
        repo,
        "backend/app/models/m.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Item(Base):\n"
        "    __tablename__ = 'items'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
    )
    # schema.sql switches static drift on; `items` itself must come from the migration replay.
    _write(repo, "backend/schema.sql", "CREATE TABLE unrelated (id int);\n")
    _write(
        repo,
        "backend/alembic/versions/r1.py",
        _migration(
            "r1",
            None,
            "def upgrade():\n"
            "    op.create_table('item_history', sa.Column('id', sa.Integer()), sa.Column('note', sa.Text()))\n"
            "    op.create_table('item', sa.Column('id', sa.Integer()))\n",
        ),
    )
    _write(
        repo,
        "backend/alembic/versions/r2.py",
        _migration(
            "r2",
            "r1",
            "_RENAME = '''\n"
            "DO $$ BEGIN\n"
            "  IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'item_history') THEN\n"
            "    ALTER TABLE item_history RENAME TO items_history;\n"
            "  END IF;\n"
            "END $$;\n"
            "ALTER TABLE items_history RENAME COLUMN note TO remark;\n"
            "'''\n"
            "def upgrade():\n"
            "    op.execute(_RENAME)\n"
            "    op.rename_table('item', 'items')\n",
        ),
    )
    res = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    tables = {n.id: n for n in res.nodes if n.subkind == "table"}

    assert "t:item_history" not in tables and "t:item" not in tables, "renamed-away names are not tables"
    assert "t:items_history" in tables
    assert "t:remark" not in tables, "RENAME COLUMN is not a table rename"
    assert not [f for f in res.findings if f.rule_code == "TRUTH-002"], "items exists after op.rename_table"
    hist = tables["t:items_history"]
    assert hist.source_file == "backend/alembic/versions/r2.py"
    assert hist.columns == ["id", "note"], "a rename keeps the columns its create declared"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # Swap: keep the old table as a backup, then create a fresh one under the old name.
        (
            (
                "def upgrade():\n"
                "    op.rename_table('ledger', 'ledger_old')\n"
                "    op.create_table('ledger', sa.Column('id', sa.Integer()))\n"
            ),
            {"ledger", "ledger_old"},
        ),
        # Build-and-swap: create the replacement, drop the original, move the replacement in.
        (
            (
                "def upgrade():\n"
                "    op.create_table('ledger_new', sa.Column('id', sa.Integer()))\n"
                "    op.drop_table('ledger')\n"
                "    op.rename_table('ledger_new', 'ledger')\n"
            ),
            {"ledger"},
        ),
        # The same build-and-swap with its steps in a helper that upgrade() calls first.
        (
            (
                "def _build():\n"
                "    op.create_table('ledger_new', sa.Column('id', sa.Integer()))\n"
                "def upgrade():\n"
                "    _build()\n"
                "    op.execute('DROP TABLE ledger; ALTER TABLE ledger_new RENAME TO ledger')\n"
            ),
            {"ledger"},
        ),
    ],
)
def test_rename_order_follows_the_revision(tmp_path: Path, body: str, expected: set[str]) -> None:
    repo = tmp_path / "swap"
    _write(
        repo,
        "backend/alembic/versions/a.py",
        _migration("a", None, "def upgrade():\n    op.create_table('ledger', sa.Column('id', sa.Integer()))\n"),
    )
    _write(repo, "backend/alembic/versions/b.py", _migration("b", "a", body))
    res = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    assert {n.label for n in res.nodes if n.subkind == "table"} == expected


def test_migration_effects_keep_downgrade_out(tmp_path: Path) -> None:
    import ast

    effects = _collect_migration_effects(
        ast.parse(
            _migration(
                "x",
                None,
                "def upgrade():\n    op.rename_table('a', 'b')\n"
                "def downgrade():\n    op.rename_table('b', 'a')\n",
            )
        )
    )
    assert [(e[1], e[2], e[3]) for e in effects.table_events] == [("rename", "a", "b")]


# --- provenance: DDL-only tables point at their CREATE TABLE, not line 1 ----------------------


def test_ddl_only_tables_carry_their_create_table_line_and_columns(tmp_path: Path) -> None:
    repo = tmp_path / "prov"
    _write(
        repo,
        "backend/schema.sql",
        "-- dump header\n"
        "\n"
        "CREATE TABLE public.audit_trail (\n"
        "    id integer NOT NULL,\n"
        "    actor text,\n"
        "    CONSTRAINT audit_trail_pkey PRIMARY KEY (id)\n"
        ");\n",
    )
    _write(
        repo,
        "backend/alembic/versions/m1.py",
        _migration(
            "m1",
            None,
            "_DDL = '''\n"
            "CREATE TABLE IF NOT EXISTS public.outbox (id int);\n"
            "'''\n"
            "def upgrade():\n"
            "    op.create_table('batches', sa.Column('id', sa.Integer()), sa.Column('size', sa.Integer()))\n"
            "    op.execute(_DDL)\n",
        ),
    )
    res = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    tables = {n.label: n for n in res.nodes if n.subkind == "table"}

    assert (tables["audit_trail"].source_file, tables["audit_trail"].line) == ("backend/schema.sql", 3)
    assert tables["audit_trail"].columns == ["id", "actor"]
    batches = tables["batches"]
    assert (batches.source_file, batches.line, batches.columns) == (
        "backend/alembic/versions/m1.py",
        9,
        ["id", "size"],
    )
    outbox = tables["outbox"]
    assert (outbox.source_file, outbox.line) == ("backend/alembic/versions/m1.py", 6), "the constant's own line"


# --- rule catalog: severity and gate behaviour agree ------------------------------------------


def test_seeded_rule_severity_matches_gate_behaviour() -> None:
    for rule in INITIAL_RULE_POLICIES:
        assert (rule["severity"] == "blocking") == rule["blocks_gate"], rule["rule_code"]
