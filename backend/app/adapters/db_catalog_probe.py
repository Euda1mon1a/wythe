"""Shared multi-dialect SQL DDL parser and read-only live database catalog probe.

Supports PostgreSQL, MySQL/MariaDB, and SQLite metadata inspection with zero row/PII reads.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

import psycopg
from sqlalchemy import create_engine, text

_IDENT = r'(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)'
_CREATE_TABLE_DDL_RE = re.compile(
    rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?P<schema>{_IDENT})\.)?(?P<table>{_IDENT})\s*\((?P<body>[\s\S]*?)\)\s*(?:;|WITHOUT\b|ENGINE\b|STRICT\b)",
    re.IGNORECASE,
)
_CREATE_TABLE_HEAD_RE = re.compile(
    rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?P<schema>{_IDENT})\.)?(?P<table>{_IDENT})",
    re.IGNORECASE,
)
_CREATE_GUARD_RE = re.compile(
    rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?P<schema>{_IDENT})\.)?(?P<func>{_IDENT})",
    re.IGNORECASE,
)
_COL_SKIP_HEADS = frozenset(
    {
        "constraint",
        "primary",
        "foreign",
        "unique",
        "check",
        "index",
        "key",
        "exclude",
    }
)
_RECORD_TABLE_MARKERS = (
    "_log",
    "_logs",
    "_history",
    "_snapshot",
    "_snapshots",
    "_receipt",
    "_receipts",
    "_record",
    "_records",
    "_audit",
    "_journal",
    "_version",
    "_versions",
    "transaction",
)
_MIGRATION_META_TABLES = frozenset(
    {
        "alembic_version",
        "spatial_ref_sys",
        "_prisma_migrations",
        "__drizzle_migrations",
        "django_migrations",
        "schema_migrations",
        "goose_db_version",
        "flyway_schema_history",
        "_sqlx_migrations",
    }
)


def clean_sql_ident(raw: str | None) -> str:
    if not raw:
        return ""
    return raw.strip().strip('"`[]').lower()


def is_migration_meta_table(table_key: str) -> bool:
    base = table_key.split(".", 1)[-1].lower()
    return base in _MIGRATION_META_TABLES


def infer_table_role(table_name: str) -> str:
    lowered = table_name.lower()
    if any(lowered.endswith(m) or m in lowered for m in _RECORD_TABLE_MARKERS):
        return "record"
    return "input"


def parse_sql_ddl_objects(
    sql_text: str,
) -> tuple[dict[str, tuple[int, list[str]]], dict[str, int]]:
    """Extract {table_key: (lineno, columns)} and {guard_name: lineno} across SQL dialects."""
    tables: dict[str, tuple[int, list[str]]] = {}
    guards: dict[str, int] = {}

    for m in _CREATE_TABLE_DDL_RE.finditer(sql_text):
        schema = clean_sql_ident(m.group("schema")) or "public"
        tbl = clean_sql_ident(m.group("table"))
        key = tbl if schema in ("public", "main", "dbo") else f"{schema}.{tbl}"
        lineno = sql_text.count("\n", 0, m.start()) + 1
        cols: list[str] = []
        for raw_line in m.group("body").splitlines():
            stripped = raw_line.strip().rstrip(",")
            if not stripped or stripped.startswith(("--", "/*", ")")):
                continue
            first_tok = clean_sql_ident(stripped.split()[0])
            if first_tok and first_tok not in _COL_SKIP_HEADS and re.match(r"^[a-z_]\w*$", first_tok):
                cols.append(first_tok)
        tables[key] = (lineno, cols[:40])

    for m in _CREATE_TABLE_HEAD_RE.finditer(sql_text):
        schema = clean_sql_ident(m.group("schema")) or "public"
        tbl = clean_sql_ident(m.group("table"))
        key = tbl if schema in ("public", "main", "dbo") else f"{schema}.{tbl}"
        if key not in tables:
            lineno = sql_text.count("\n", 0, m.start()) + 1
            tables[key] = (lineno, [])

    for m in _CREATE_GUARD_RE.finditer(sql_text):
        schema = clean_sql_ident(m.group("schema")) or "public"
        fn = clean_sql_ident(m.group("func"))
        key = fn if schema in ("public", "main", "dbo") else f"{schema}.{fn}"
        guards[key] = sql_text.count("\n", 0, m.start()) + 1

    return tables, guards


def probe_live_catalog_tables(dsn: str) -> tuple[set[str], str]:
    """Perform read-only table-catalog reflection on PostgreSQL, SQLite, or MySQL."""
    lower = dsn.lower()
    if lower.startswith("sqlite:"):
        parsed = urlparse(dsn)
        raw_path = dsn.split("sqlite:///", 1)[-1] if "sqlite:///" in dsn else parsed.path
        db_path = Path(raw_path).expanduser().resolve()
        if not db_path.is_file():
            raise FileNotFoundError(f"SQLite database file not found: {db_path}")
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        return {str(r[0]).lower() for r in rows}, "static_ast+sqlite_catalog_readonly"

    if lower.startswith(("postgresql:", "postgres:", "postgresql+psycopg:")):
        pg_url = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
        query = (
            "SELECT table_schema, table_name "
            "FROM information_schema.tables "
            "WHERE table_type = 'BASE TABLE' "
            "AND table_schema NOT IN ('pg_catalog', 'information_schema')"
        )
        found: set[str] = set()
        with psycopg.connect(pg_url, autocommit=True) as conn:
            conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            with conn.cursor() as cur:
                cur.execute(query)
                for schema_name, table_name in cur.fetchall():
                    s_clean = str(schema_name).lower()
                    t_clean = str(table_name).lower()
                    found.add(t_clean if s_clean == "public" else f"{s_clean}.{t_clean}")
        return found, "static_ast+pg_catalog_readonly"

    if lower.startswith(("mysql:", "mysql+", "mariadb:")):
        engine = create_engine(dsn, future=True)
        try:
            with engine.connect() as conn:
                conn.execute(text("SET SESSION TRANSACTION READ ONLY"))
                rows = conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
                    )
                ).fetchall()
            return {str(r[0]).lower() for r in rows}, "static_ast+mysql_catalog_readonly"
        finally:
            engine.dispose()

    raise ValueError(f"Unsupported live catalog DSN scheme: {dsn.split(':', 1)[0]}")
