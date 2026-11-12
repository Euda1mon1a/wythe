"""Tier 1 Adapter: PostgreSQL + SQLAlchemy + Alembic + schema.sql (+ optional pg_catalog)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    is_migration_meta_table,
    probe_live_catalog_tables,
)
from app.schemas.atlas import AtlasNode

_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r'(?:(?P<schema>"?[A-Za-z_]\w*"?)\.)?(?P<table>"?[A-Za-z_]\w*"?)',
    re.IGNORECASE,
)
_CREATE_FUNC_RE = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+"
    r'(?:(?P<schema>"?[A-Za-z_]\w*"?)\.)?(?P<func>"?[A-Za-z_]\w*"?)\s*\(',
    re.IGNORECASE,
)
_DROP_FUNC_RE = re.compile(
    r"DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?"
    r'(?:(?P<schema>"?[A-Za-z_]\w*"?)\.)?(?P<func>"?[A-Za-z_]\w*"?)\b',
    re.IGNORECASE,
)
_RECORD_SUFFIXES = (
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


def _infer_table_role(table_name: str) -> str:
    lowered = table_name.lower()
    if any(lowered == suffix.lstrip("_") or lowered.endswith(suffix) for suffix in _RECORD_SUFFIXES):
        return "record"
    return "input"


def _extract_model_classes(py_file: Path, rel_path: str) -> list[tuple[str, str, int, list[str], str]]:
    """Return (class_name, table_name, lineno, columns, docstring_summary) from a Python file."""
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return []

    discovered: list[tuple[str, str, int, list[str], str]] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        table_name: str | None = None
        table_schema: str | None = None
        is_abstract = False
        columns: list[str] = []
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "__tablename__":
                        if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                            table_name = stmt.value.value
                    elif isinstance(target, ast.Name) and target.id == "__table_args__":
                        for sub in ast.walk(stmt.value):
                            if isinstance(sub, ast.Dict):
                                for k, v in zip(sub.keys, sub.values):
                                    if (
                                        isinstance(k, ast.Constant)
                                        and k.value == "schema"
                                        and isinstance(v, ast.Constant)
                                        and isinstance(v.value, str)
                                    ):
                                        table_schema = v.value
                    elif isinstance(target, ast.Name) and target.id == "__abstract__":
                        if isinstance(stmt.value, ast.Constant) and stmt.value.value is True:
                            is_abstract = True
                    elif isinstance(target, ast.Name) and isinstance(stmt.value, ast.Call):
                        fn = stmt.value.func
                        fn_name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                        if fn_name in ("Column", "mapped_column"):
                            columns.append(target.id)
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and isinstance(stmt.value, ast.Call)
            ):
                fn = stmt.value.func
                fn_name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if fn_name in ("Column", "mapped_column"):
                    columns.append(stmt.target.id)

        if table_name and not is_abstract:
            qualified = (
                f"{table_schema.lower()}.{table_name}"
                if table_schema and table_schema.lower() != "public"
                else table_name
            )
            doc = (ast.get_docstring(node) or "").strip().splitlines()
            first_line = doc[0].strip() if doc else f"Persisted table `{qualified}` ({rel_path})."
            discovered.append((node.name, qualified, node.lineno, columns, first_line))
    return discovered


def _parse_sql_objects(sql_text: str) -> tuple[set[str], dict[str, int]]:
    """Extract table names and function names -> approx line numbers from SQL text."""
    tables: set[str] = set()
    functions: dict[str, int] = {}
    for match in _CREATE_TABLE_RE.finditer(sql_text):
        schema = (match.group("schema") or "public").replace('"', "").lower()
        table = match.group("table").replace('"', "").lower()
        tables.add(table if schema == "public" else f"{schema}.{table}")
    for match in _CREATE_FUNC_RE.finditer(sql_text):
        schema = (match.group("schema") or "public").replace('"', "").lower()
        func = match.group("func").replace('"', "").lower()
        key = func if schema == "public" else f"{schema}.{func}"
        line = sql_text.count("\n", 0, match.start()) + 1
        functions[key] = line
    return tables, functions


class PostgresSqlAlchemyAdapter:
    """Inspects SQLAlchemy 2.0 models, schema.sql, Alembic migrations, and optional pg_catalog."""

    name = "postgres-sqlalchemy"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        backend_dir = repo_root / backend_subdir
        models_dir = backend_dir / "app" / "models"
        schema_sql_path = backend_dir / "schema.sql"
        alembic_dir = backend_dir / "alembic" / "versions"

        nodes: list[AtlasNode] = []
        table_symbol_map: dict[str, str] = {}
        function_symbol_map: dict[str, str] = {}
        findings: list[RawCandidateFinding] = []

        orm_tables: dict[str, tuple[str, int, list[str], str, list[str]]] = {}
        if models_dir.is_dir():
            for py_file in sorted(models_dir.rglob("*.py")):
                if "__pycache__" in py_file.parts:
                    continue
                rel_path = py_file.relative_to(repo_root).as_posix()
                for cls_name, tbl_name, lineno, cols, summary in _extract_model_classes(py_file, rel_path):
                    key = tbl_name.lower()
                    if key not in orm_tables:
                        orm_tables[key] = (rel_path, lineno, cols, summary, [cls_name])
                    else:
                        orm_tables[key][4].append(cls_name)

        sql_tables: set[str] = set()
        sql_functions: dict[str, tuple[str, int]] = {}
        if schema_sql_path.is_file():
            rel_schema = schema_sql_path.relative_to(repo_root).as_posix()
            text = schema_sql_path.read_text(encoding="utf-8", errors="replace")
            parsed_tables, parsed_funcs = _parse_sql_objects(text)
            sql_tables |= parsed_tables
            for fn_name, fn_line in parsed_funcs.items():
                sql_functions[fn_name] = (rel_schema, fn_line)

        if alembic_dir.is_dir():
            for mig_file in sorted(alembic_dir.glob("*.py")):
                rel_mig = mig_file.relative_to(repo_root).as_posix()
                try:
                    tree = ast.parse(mig_file.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, SyntaxError):
                    continue
                for stmt in tree.body:
                    if isinstance(stmt, ast.FunctionDef) and stmt.name == "upgrade":
                        for sub in ast.walk(stmt):
                            if (
                                isinstance(sub, ast.Call)
                                and isinstance(sub.func, ast.Attribute)
                                and sub.func.attr == "create_table"
                                and sub.args
                                and isinstance(sub.args[0], ast.Constant)
                                and isinstance(sub.args[0].value, str)
                            ):
                                t_name = sub.args[0].value.lower()
                                t_schema = "public"
                                for kw in sub.keywords:
                                    if (
                                        kw.arg == "schema"
                                        and isinstance(kw.value, ast.Constant)
                                        and isinstance(kw.value.value, str)
                                    ):
                                        t_schema = kw.value.value.lower()
                                sql_tables.add(t_name if t_schema == "public" else f"{t_schema}.{t_name}")
                            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                                mig_tables, parsed_funcs = _parse_sql_objects(sub.value)
                                sql_tables |= mig_tables
                                for fn_name in parsed_funcs:
                                    sql_functions[fn_name] = (rel_mig, sub.lineno)
                                for drop_match in _DROP_FUNC_RE.finditer(sub.value):
                                    schema = (drop_match.group("schema") or "public").replace('"', "").lower()
                                    fn = drop_match.group("func").replace('"', "").lower()
                                    key = fn if schema == "public" else f"{schema}.{fn}"
                                    sql_functions.pop(key, None)

        all_table_keys = sorted(set(orm_tables.keys()) | sql_tables)
        for tbl_key in all_table_keys:
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
            if tbl_key in orm_tables:
                src_file, lineno, cols, summary, cls_names = orm_tables[tbl_key]
                for cls_name in cls_names:
                    table_symbol_map[cls_name] = node_id
            else:
                src_file = (
                    schema_sql_path.relative_to(repo_root).as_posix()
                    if schema_sql_path.is_file()
                    else f"{backend_subdir}/schema.sql"
                )
                lineno, cols, summary = 1, [], f"SQL-defined table `{tbl_key}`."

            table_symbol_map[tbl_key] = node_id
            if "." in tbl_key:
                table_symbol_map[tbl_key.split(".", 1)[1]] = node_id
            cluster = tbl_key.split("_", 1)[0] if "_" in tbl_key else "core"
            nodes.append(
                AtlasNode(
                    id=node_id,
                    tier="truth",
                    subkind="table",
                    label=tbl_key,
                    source_file=src_file,
                    line=lineno,
                    status="clean",
                    role=_infer_table_role(tbl_key),
                    cluster=cluster,
                    summary=summary,
                    columns=cols[:40],
                )
            )

        if schema_sql_path.is_file():
            for tbl_key, (src_file, lineno, _, _, _) in sorted(orm_tables.items()):
                if "." not in tbl_key and tbl_key not in sql_tables and not tbl_key.endswith("_version"):
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"ORM model `{tbl_key}` missing from schema.sql",
                            detail=f"SQLAlchemy declares `{tbl_key}` in {src_file}, but schema.sql has no CREATE TABLE for it.",
                            remediation="Generate/apply the migration and refresh schema.sql, or retire the unmapped model.",
                        )
                    )

        for fn_key, (fn_src, fn_line) in sorted(sql_functions.items()):
            fn_node_id = f"fn:{fn_key}"
            function_symbol_map[fn_key] = fn_node_id
            nodes.append(
                AtlasNode(
                    id=fn_node_id,
                    tier="truth",
                    subkind="sql_function",
                    label=f"{fn_key}()",
                    source_file=fn_src,
                    line=fn_line,
                    status="clean",
                    role="mechanism",
                    cluster="db_guard",
                    summary=f"PostgreSQL stored function / write-lane guard `{fn_key}`.",
                )
            )

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            for tbl_key, (src_file, lineno, _, _, _) in sorted(orm_tables.items()):
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"ORM model `{tbl_key}` absent from live database catalog",
                            detail=f"Read-only catalog check ({obs_source}) did not find base table `{tbl_key}`.",
                            remediation="Apply pending migrations on the target database before trusting ORM consumers.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
        )
