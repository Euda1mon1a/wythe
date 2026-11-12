"""Tier 1 Adapter: PostgreSQL + SQLAlchemy + Alembic + schema.sql (+ optional pg_catalog)."""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.schemas.atlas import AtlasNode

_IDENT = r'"?[A-Za-z_]\w*"?'
# TEMP tables are deliberately not matched: they never become schema truth. The `(?!IF\s+NOT\b)`
# guard stops `IF NOT EXISTS <unresolved name>` from being read as a table called `if`.
_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?!IF\s+NOT\b)"
    rf"(?:(?P<schema>{_IDENT})\.)?(?P<table>{_IDENT})(?![.\w])",
    re.IGNORECASE,
)
_DROP_TABLE_RE = re.compile(
    r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<names>[^;()]+?)\s*(?:\bCASCADE\b|\bRESTRICT\b|;|$)",
    re.IGNORECASE | re.MULTILINE,
)
_TABLE_NAME_RE = re.compile(rf"^\s*(?:(?P<schema>{_IDENT})\.)?(?P<table>{_IDENT})\s*$")
# `ALTER TABLE [IF EXISTS] [ONLY] old RENAME TO new`. `RENAME COLUMN a TO b` and the bare
# `RENAME a TO b` column form do not match: `TO` must follow `RENAME` directly.
_RENAME_TABLE_RE = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"
    rf"(?:(?P<schema>{_IDENT})\.)?(?P<old>{_IDENT})\s+RENAME\s+TO\s+(?P<new>{_IDENT})",
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
_QUALIFIED = rf"{_IDENT}(?:\.{_IDENT})?"
# Body of `CREATE FUNCTION ... AS $tag$ <body> $tag$` (dollar-quoted; the header has no `;`).
_DOLLAR_BODY_RE = re.compile(r"\bAS\s+(\$[A-Za-z0-9_]*\$)", re.IGNORECASE)
_DOLLAR_TAG_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
# Tables a SQL body reads. `DELETE FROM t` is a write, so it is matched (and skipped) as a unit;
# `FROM fn(...)` is a set-returning function call, not a table.
_BODY_READ_RE = re.compile(
    rf"\b(?P<kw>DELETE\s+FROM|FROM|JOIN)\s+(?:ONLY\s+)?(?P<t>{_QUALIFIED})(?![\w\".])(?!\s*\()",
    re.IGNORECASE,
)
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
# One CREATE/ALTER TABLE statement (up to its `;`), to pair each REFERENCES with its source table.
_FK_STMT_RE = re.compile(
    r"\b(?:CREATE\s+(?:UNLOGGED\s+)?TABLE|ALTER\s+TABLE)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?"
    rf"(?P<src>{_QUALIFIED})(?P<rest>[^;]*)",
    re.IGNORECASE,
)
_REFERENCES_RE = re.compile(rf"\bREFERENCES\s+(?:ONLY\s+)?(?P<dst>{_QUALIFIED})", re.IGNORECASE)
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
_DECLARATIVE_ROOT_BASES = frozenset({"DeclarativeBase", "DeclarativeBaseNoMeta"})
_DECLARATIVE_FACTORIES = frozenset({"declarative_base", "generate_base"})
_DEFAULT_GROUP = ""  # models whose base is imported from outside the models package
_UNRESOLVED = "\x00"  # an f-string part whose value is not known statically


def _infer_table_role(table_name: str) -> str:
    lowered = table_name.lower()
    if any(lowered == suffix.lstrip("_") or lowered.endswith(suffix) for suffix in _RECORD_SUFFIXES):
        return "record"
    return "input"


def _expr_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    if isinstance(node, ast.Subscript):
        return _expr_name(node.value)
    return ""


@dataclass
class _ModelScan:
    """Models, class -> base names, and declarative roots found in one module."""

    models: list[tuple[str, str, int, list[str], str, list[str]]] = field(default_factory=list)
    class_bases: dict[str, list[str]] = field(default_factory=dict)
    roots: set[str] = field(default_factory=set)
    # (referencing table, "table" key or "class" name of the referenced side) from ForeignKey(...).
    fk_refs: list[tuple[str, str, str]] = field(default_factory=list)


def _scan_model_module(py_file: Path, rel_path: str) -> _ModelScan:
    """Return models as (class, table, lineno, columns, summary, base names) plus base metadata."""
    scan = _ModelScan()
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return scan

    # Module-level string constants, so `{"schema": AUDIT_SCHEMA}` resolves.
    str_consts: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    str_consts[t.id] = node.value.value

    def str_value(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        if isinstance(expr, ast.Name):
            return str_consts.get(expr.id)
        return None

    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if _expr_name(node.value.func) in _DECLARATIVE_FACTORIES:
                scan.roots.update(t.id for t in node.targets if isinstance(t, ast.Name))
            continue
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = [_expr_name(b) for b in node.bases]
        scan.class_bases[node.name] = base_names
        decorated_root = any("declarative" in _expr_name(d) for d in node.decorator_list)
        if decorated_root or any(b in _DECLARATIVE_ROOT_BASES for b in base_names):
            scan.roots.add(node.name)

        table_name: str | None = None
        table_schema: str | None = None
        is_abstract = False
        columns: list[str] = []
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "__tablename__":
                        table_name = str_value(stmt.value) or table_name
                    elif isinstance(target, ast.Name) and target.id == "__table_args__":
                        for sub in ast.walk(stmt.value):
                            if isinstance(sub, ast.Dict):
                                for k, v in zip(sub.keys, sub.values):
                                    if isinstance(k, ast.Constant) and k.value == "schema" and v is not None:
                                        table_schema = str_value(v) or table_schema
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
            scan.models.append((node.name, qualified, node.lineno, columns, first_line, base_names))
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                callee = _expr_name(sub.func)
                targets: list[ast.expr] = []
                if callee == "ForeignKey" and sub.args:
                    targets = [sub.args[0]]
                elif callee == "ForeignKeyConstraint" and len(sub.args) >= 2 and isinstance(sub.args[1], (ast.List, ast.Tuple)):
                    targets = list(sub.args[1].elts)
                for tgt in targets:
                    text_target = str_value(tgt)
                    fk_table = _fk_target_table(text_target) if text_target else None
                    if fk_table:
                        scan.fk_refs.append((qualified, "table", fk_table))
                    elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
                        scan.fk_refs.append((qualified, "class", tgt.value.id))  # ForeignKey(Parent.id)
    return scan


def _model_group(
    base_names: list[str],
    class_bases: dict[str, list[str]],
    roots: set[str],
    seen: frozenset[str] = frozenset(),
) -> str:
    """Name of the declarative root a model inherits from (`""` when it is imported/unknown)."""
    for name in base_names:
        if name in roots:
            return name
    for name in base_names:
        if name in class_bases and name not in seen:
            group = _model_group(class_bases[name], class_bases, roots, seen | {name})
            if group != _DEFAULT_GROUP:
                return group
    return _DEFAULT_GROUP


_SQL_COL_SKIP_HEADS = frozenset(
    {"constraint", "primary", "foreign", "unique", "check", "index", "key", "exclude", "like"}
)


def _blank_sql_comments(sql_text: str) -> str:
    """Replace `--` and `/* ... */` SQL comments with spaces while preserving quotes, `$tag$`, and `\\n`."""
    out: list[str] = []
    i = 0
    n = len(sql_text)
    while i < n:
        ch = sql_text[i]
        nxt = sql_text[i + 1] if i + 1 < n else ""
        if ch == "-" and nxt == "-":
            while i < n and sql_text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            depth = 1
            while i < n and depth > 0:
                if sql_text[i] == "/" and i + 1 < n and sql_text[i + 1] == "*":
                    out.append("  ")
                    i += 2
                    depth += 1
                elif sql_text[i] == "*" and i + 1 < n and sql_text[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    depth -= 1
                else:
                    out.append("\n" if sql_text[i] == "\n" else " ")
                    i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = sql_text[i]
                out.append(c)
                if c == "\\" and quote == "'" and i + 1 < n:
                    out.append(sql_text[i + 1])
                    i += 2
                    continue
                if c == quote:
                    if i + 1 < n and sql_text[i + 1] == quote:
                        out.append(quote)
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "$":
            dm = _DOLLAR_TAG_RE.match(sql_text, i)
            if dm:
                tag = dm.group(0)
                end = sql_text.find(tag, i + len(tag))
                if end >= 0:
                    out.append(sql_text[i : end + len(tag)])
                    i = end + len(tag)
                    continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_create_columns_at(cleaned_sql: str, pos: int) -> list[str]:
    """Extract column names from the `(...)` body immediately following `CREATE TABLE <name>`."""
    n = len(cleaned_sql)
    i = pos
    while i < n and cleaned_sql[i].isspace():
        i += 1
    if i >= n or cleaned_sql[i] != "(":
        return []
    depth = 1
    start = i + 1
    j = start
    quote: str | None = None
    top_parts: list[str] = []
    seg_start = start
    while j < n and depth > 0:
        c = cleaned_sql[j]
        if quote:
            if c == "\\" and quote == "'" and j + 1 < n:
                j += 2
                continue
            if c == quote:
                if j + 1 < n and cleaned_sql[j + 1] == quote:
                    j += 2
                    continue
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == "$":
            dm = _DOLLAR_TAG_RE.match(cleaned_sql, j)
            if dm:
                tag = dm.group(0)
                end = cleaned_sql.find(tag, j + len(tag))
                if end >= 0:
                    j = end + len(tag)
                    continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                top_parts.append(cleaned_sql[seg_start:j])
                break
        elif c == "," and depth == 1:
            top_parts.append(cleaned_sql[seg_start:j])
            seg_start = j + 1
        j += 1
    cols: list[str] = []
    for part in top_parts:
        stripped = part.strip()
        if not stripped:
            continue
        first_raw = stripped.split()[0].rstrip("(")
        first_tok = _clean_sql_name(first_raw)
        if first_tok and first_tok not in _SQL_COL_SKIP_HEADS and re.match(r"^[a-z_]\w*$", first_tok):
            cols.append(first_tok)
    return cols[:40]


def _clean_sql_name(raw: str | None) -> str:
    return (raw or "").replace('"', "").lower()


def _parse_sql_objects(sql_text: str) -> tuple[set[str], dict[str, int]]:
    """Extract table names and function names -> approx line numbers from SQL text."""
    cleaned = _blank_sql_comments(sql_text)
    tables: set[str] = set()
    functions: dict[str, int] = {}
    for match in _CREATE_TABLE_RE.finditer(cleaned):
        schema = _clean_sql_name(match.group("schema")) or "public"
        table = _clean_sql_name(match.group("table"))
        tables.add(table if schema == "public" else f"{schema}.{table}")
    for match in _CREATE_FUNC_RE.finditer(cleaned):
        schema = _clean_sql_name(match.group("schema")) or "public"
        func = _clean_sql_name(match.group("func"))
        key = func if schema == "public" else f"{schema}.{func}"
        line = cleaned.count("\n", 0, match.start()) + 1
        functions[key] = line
    return tables, functions


def _parse_dropped_tables(sql_text: str) -> set[str]:
    cleaned = _blank_sql_comments(sql_text)
    dropped: set[str] = set()
    for match in _DROP_TABLE_RE.finditer(cleaned):
        for raw_name in match.group("names").split(","):
            nm = _TABLE_NAME_RE.match(raw_name)
            if nm:
                schema = _clean_sql_name(nm.group("schema")) or "public"
                table = _clean_sql_name(nm.group("table"))
                dropped.add(table if schema == "public" else f"{schema}.{table}")
    return dropped


def _sql_table_key(raw: str) -> str:
    """`public.t` / `"S"."T"` / `t` -> the key Wythe uses for table nodes (public is implicit)."""
    parts = [_clean_sql_name(p) for p in raw.split(".")]
    if len(parts) == 2 and parts[0] != "public":
        return f"{parts[0]}.{parts[1]}"
    return parts[-1]


def _parse_sql_lineage(sql_text: str) -> tuple[dict[str, set[str]], set[tuple[str, str]]]:
    """Database-side consumers of tables in SQL text.

    Returns ({function key: tables its dollar-quoted body reads}, {(referencing table,
    referenced table)} from REFERENCES clauses of CREATE/ALTER TABLE statements).
    """
    cleaned = _blank_sql_comments(sql_text)
    function_reads: dict[str, set[str]] = {}
    for match in _CREATE_FUNC_RE.finditer(cleaned):
        schema = _clean_sql_name(match.group("schema")) or "public"
        func = _clean_sql_name(match.group("func"))
        key = func if schema == "public" else f"{schema}.{func}"
        tag = _DOLLAR_BODY_RE.search(cleaned, match.end())
        if tag is None or ";" in cleaned[match.end() : tag.start()]:
            continue
        body_start = tag.end()
        body_end = cleaned.find(tag.group(1), body_start)
        if body_end < 0:
            continue
        body = _blank_sql_comments(cleaned[body_start:body_end])
        reads = function_reads.setdefault(key, set())
        for read in _BODY_READ_RE.finditer(body):
            if not read.group("kw").upper().startswith("DELETE"):
                reads.add(_sql_table_key(read.group("t")))
    fk_refs: set[tuple[str, str]] = set()
    for stmt in _FK_STMT_RE.finditer(cleaned):
        src = _sql_table_key(stmt.group("src"))
        for ref in _REFERENCES_RE.finditer(stmt.group("rest")):
            dst = _sql_table_key(ref.group("dst"))
            if dst != src:
                fk_refs.add((src, dst))
    return function_reads, fk_refs


def _fk_target_table(target: str) -> str | None:
    """SQLAlchemy `ForeignKey("table.col")` / `"schema.table.col"` target -> table key."""
    parts = [p.lower() for p in target.split(".")]
    if len(parts) == 2:
        return parts[0]
    if len(parts) == 3:
        return parts[1] if parts[0] == "public" else f"{parts[0]}.{parts[1]}"
    return None


def _eval_str(node: ast.AST | None, consts: dict[str, str]) -> str | None:
    """Statically evaluate a string expression: literals, f-strings, `+`, `text()`, `"".join()`."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner = _eval_str(value.value, consts)
                parts.append(inner if inner is not None else _UNRESOLVED)
            else:
                parts.append(_UNRESOLVED)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_str(node.left, consts)
        right = _eval_str(node.right, consts)
        return left + right if left is not None and right is not None else None
    if isinstance(node, (ast.Tuple, ast.List)):
        items = [_eval_str(e, consts) for e in node.elts]
        known = [i for i in items if i is not None]
        return "\n".join(known) if known else None
    if isinstance(node, ast.Call):
        fname = _expr_name(node.func)
        if (
            fname == "join"
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
            and node.args
            and isinstance(node.args[0], (ast.Tuple, ast.List))
        ):
            items = [_eval_str(e, consts) for e in node.args[0].elts]
            return node.func.value.value.join(i for i in items if i is not None)
        if fname in ("text", "dedent", "strip") and node.args:
            return _eval_str(node.args[0], consts)
    return None


def _table_key(schema: str | None, table: str) -> str:
    schema = schema or "public"
    return table if schema == "public" else f"{schema}.{table}"


def _sql_table_events(sql_text: str) -> list[tuple[int, str, str, str | None, int, list[str]]]:
    """CREATE / DROP / RENAME TO table statements in `sql_text`, in text order.

    Each event is (offset, kind, table, new_table, line_offset, columns) where kind is
    "create", "drop" or "rename" and new_table is set only for a rename.
    """
    cleaned = _blank_sql_comments(sql_text)
    events: list[tuple[int, str, str, str | None, int, list[str]]] = []
    for match in _CREATE_TABLE_RE.finditer(cleaned):
        key = _table_key(_clean_sql_name(match.group("schema")), _clean_sql_name(match.group("table")))
        cols = _extract_create_columns_at(cleaned, match.end())
        events.append((match.start(), "create", key, None, cleaned.count("\n", 0, match.start()), cols))
    for match in _DROP_TABLE_RE.finditer(cleaned):
        for raw_name in match.group("names").split(","):
            nm = _TABLE_NAME_RE.match(raw_name)
            if nm:
                key = _table_key(_clean_sql_name(nm.group("schema")), _clean_sql_name(nm.group("table")))
                events.append((match.start(), "drop", key, None, cleaned.count("\n", 0, match.start()), []))
    for match in _RENAME_TABLE_RE.finditer(cleaned):
        schema = _clean_sql_name(match.group("schema"))
        old = _table_key(schema, _clean_sql_name(match.group("old")))
        new = _table_key(schema, _clean_sql_name(match.group("new")))  # a rename keeps the schema
        events.append((match.start(), "rename", old, new, cleaned.count("\n", 0, match.start()), []))
    events.sort(key=lambda e: e[0])
    return events


@dataclass
class _MigrationEffects:
    revision: str | None = None
    down_revisions: tuple[str, ...] = ()
    # Ordered table effects: (order key, kind, table, new_table, line, columns). The order key
    # follows source position inside upgrade() and, for helpers, each call site that runs them.
    table_events: list[tuple[tuple, str, str, str | None, int, list[str]]] = field(default_factory=list)
    created_functions: dict[str, int] = field(default_factory=dict)
    dropped_functions: set[str] = field(default_factory=set)
    creates_all_metadata: bool = False
    touches_ddl: bool = False
    function_reads: dict[str, set[str]] = field(default_factory=dict)
    fk_refs: set[tuple[str, str]] = field(default_factory=set)


def _collect_migration_effects(tree: ast.Module) -> _MigrationEffects:
    """Tables/functions an Alembic revision's `upgrade()` creates or drops.

    Follows module-level string constants (including f-strings built from other constants)
    and module-level helper functions that `upgrade()` calls, so DDL kept outside the
    function body is still seen.
    """
    effects = _MigrationEffects()
    consts: dict[str, str] = {}
    const_lines: dict[str, int] = {}
    module_fns: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, Any]]] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module_fns[stmt.name] = (stmt, module_fns)
            continue
        targets: list[str] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            targets, value = [stmt.target.id], stmt.value
        if not targets or value is None:
            continue
        if "revision" in targets and isinstance(value, ast.Constant) and isinstance(value.value, str):
            effects.revision = value.value
        if "down_revision" in targets:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                effects.down_revisions = (value.value,)
            elif isinstance(value, (ast.Tuple, ast.List)):
                effects.down_revisions = tuple(
                    e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                )
        evaluated = _eval_str(value, consts)
        if evaluated is not None:
            for name in targets:
                consts[name] = evaluated
                const_lines[name] = value.lineno

    upgrade_entry = module_fns.get("upgrade")
    if upgrade_entry is None:
        return effects

    def add_event(
        order: tuple, kind: str, table: str, new_table: str | None, lineno: int, cols: list[str] | None = None
    ) -> None:
        effects.table_events.append((order, kind, table, new_table, lineno, list(cols or [])))

    def absorb_sql(sql_text: str, lineno: int, order: tuple) -> None:
        cleaned = _blank_sql_comments(sql_text)
        _, funcs = _parse_sql_objects(sql_text)
        for offset, kind, table, new_table, line_offset, cols in _sql_table_events(sql_text):
            add_event((*order, (offset,)), kind, table, new_table, lineno + line_offset, cols)
        for fn_name in funcs:
            effects.created_functions[fn_name] = lineno
        for drop_match in _DROP_FUNC_RE.finditer(cleaned):
            schema = _clean_sql_name(drop_match.group("schema")) or "public"
            fn = _clean_sql_name(drop_match.group("func"))
            effects.dropped_functions.add(fn if schema == "public" else f"{schema}.{fn}")
        fn_reads, fk_refs = _parse_sql_lineage(sql_text)
        for fn_name, read_tables in fn_reads.items():
            effects.function_reads.setdefault(fn_name, set()).update(read_tables)
        effects.fk_refs |= fk_refs

    def fk_targets_in(node: ast.AST) -> set[str]:
        found: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _expr_name(sub.func) == "ForeignKey" and sub.args:
                target = _eval_str(sub.args[0], consts)
                fk_table = _fk_target_table(target) if target and _UNRESOLVED not in target else None
                if fk_table:
                    found.add(fk_table)
        return found

    def table_key(call: ast.Call, arg_index: int = 0) -> str | None:
        name = _eval_str(call.args[arg_index], consts) if len(call.args) > arg_index else None
        if not name or _UNRESOLVED in name:
            return None
        schema = "public"
        for kw in call.keywords:
            if kw.arg == "schema":
                schema = (_eval_str(kw.value, consts) or "public").lower()
        return name.lower() if schema == "public" else f"{schema}.{name.lower()}"

    def column_names(call: ast.Call) -> list[str]:
        names: list[str] = []
        for arg in call.args[1:]:
            if isinstance(arg, ast.Call) and _expr_name(arg.func) == "Column" and arg.args:
                col = _eval_str(arg.args[0], consts)
                if col and _UNRESOLVED not in col:
                    names.append(col.lower())
        return names

    active_fns: set[int] = set()

    def walk_node(
        sub: ast.AST,
        ctx: tuple,
        scope_fns: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, Any]]],
    ) -> None:
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope_fns[sub.name] = (sub, scope_fns)
            return
        if isinstance(sub, ast.ClassDef):
            scope_fns.pop(sub.name, None)
            return
        if isinstance(sub, ast.Lambda):
            return
        if isinstance(sub, ast.Assign):
            walk_node(sub.value, ctx, scope_fns)
            if len(sub.targets) == 1 and isinstance(sub.targets[0], ast.Name) and isinstance(sub.value, ast.Name) and sub.value.id in scope_fns:
                scope_fns[sub.targets[0].id] = scope_fns[sub.value.id]
            else:
                for tgt in sub.targets:
                    for bound in ast.walk(tgt):
                        if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                            scope_fns.pop(bound.id, None)
            return
        if isinstance(sub, ast.AnnAssign):
            if sub.value is not None:
                walk_node(sub.value, ctx, scope_fns)
            if isinstance(sub.target, ast.Name):
                if isinstance(sub.value, ast.Name) and sub.value.id in scope_fns:
                    scope_fns[sub.target.id] = scope_fns[sub.value.id]
                else:
                    scope_fns.pop(sub.target.id, None)
            return
        order = (*ctx, (getattr(sub, "lineno", 0), getattr(sub, "col_offset", 0)))
        if isinstance(sub, ast.Call):
            callee = _expr_name(sub.func)
            if callee == "create_table":
                key = table_key(sub)
                if key:
                    add_event(order, "create", key, None, sub.lineno, column_names(sub))
                    effects.fk_refs |= {(key, dst) for dst in fk_targets_in(sub) if dst != key}
                return
            if callee == "create_foreign_key" and len(sub.args) >= 3:
                src = _eval_str(sub.args[1], consts)
                dst = _eval_str(sub.args[2], consts)
                kw = {k.arg: _eval_str(k.value, consts) for k in sub.keywords if k.arg}
                if src and dst and _UNRESOLVED not in src + dst:
                    src_schema = (kw.get("source_schema") or "public").lower()
                    dst_schema = (kw.get("referent_schema") or "public").lower()
                    src_key = src.lower() if src_schema == "public" else f"{src_schema}.{src.lower()}"
                    dst_key = dst.lower() if dst_schema == "public" else f"{dst_schema}.{dst.lower()}"
                    if src_key != dst_key:
                        effects.fk_refs.add((src_key, dst_key))
                return
            if callee == "drop_table":
                key = table_key(sub)
                if key:
                    add_event(order, "drop", key, None, sub.lineno)
                return
            if callee == "rename_table":
                old, new = table_key(sub, 0), table_key(sub, 1)
                if old and new:
                    add_event(order, "rename", old, new, sub.lineno)
                return
            if callee == "create_all":
                effects.creates_all_metadata = True
            elif callee in ("add_column", "drop_column", "alter_column"):
                effects.touches_ddl = True
            elif isinstance(sub.func, ast.Name) and sub.func.id in scope_fns:
                for arg_expr in (*sub.args, *(kw.value for kw in sub.keywords)):
                    walk_node(arg_expr, ctx, scope_fns)
                target_fn, target_env = scope_fns[sub.func.id]
                visit(target_fn, order, target_env)
                return
        elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in consts:
            cleaned_u = _blank_sql_comments(consts[sub.id]).upper()
            if "ALTER TABLE" in cleaned_u:
                effects.touches_ddl = True
            absorb_sql(consts[sub.id], const_lines.get(sub.id, sub.lineno), order)
            return
        elif isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            text = _eval_str(sub, consts)
            if text is not None:
                cleaned_u = _blank_sql_comments(text).upper()
                if "TABLE" in cleaned_u or "FUNCTION" in cleaned_u:
                    if "ALTER TABLE" in cleaned_u:
                        effects.touches_ddl = True
                    absorb_sql(text, getattr(sub, "lineno", 1), order)
                return
        for child in ast.iter_child_nodes(sub):
            walk_node(child, ctx, scope_fns)

    def visit(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        ctx: tuple,
        defining_fns: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, Any]]],
    ) -> None:
        if id(fn) in active_fns:
            return
        active_fns.add(id(fn))
        local_fns = dict(defining_fns)
        for p in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs, fn.args.vararg, fn.args.kwarg):
            if p is not None:
                local_fns.pop(p.arg, None)
        try:
            for stmt in fn.body:
                walk_node(stmt, ctx, local_fns)
        finally:
            active_fns.discard(id(fn))

    visit(upgrade_entry[0], (), upgrade_entry[1])
    if (
        effects.table_events
        or effects.created_functions
        or effects.dropped_functions
        or effects.creates_all_metadata
    ):
        effects.touches_ddl = True
    return effects


def _order_migrations(
    entries: list[tuple[Path, _MigrationEffects]],
) -> list[tuple[Path, _MigrationEffects]]:
    """Order revisions by their `down_revision` chain; fall back to file name order."""
    if not entries or any(e.revision is None for _, e in entries):
        return entries
    by_rev = {e.revision: (p, e) for p, e in entries}
    pending = {rev: {d for d in e.down_revisions if d in by_rev} for rev, (_, e) in by_rev.items()}
    ordered: list[tuple[Path, _MigrationEffects]] = []
    ready = sorted((rev for rev, deps in pending.items() if not deps), key=lambda r: str(by_rev[r][0]))
    while ready:
        rev = ready.pop(0)
        ordered.append(by_rev[rev])
        del pending[rev]
        newly = [r for r, deps in pending.items() if rev in deps and len(deps) == 1]
        for deps in pending.values():
            deps.discard(rev)
        ready.extend(sorted(newly, key=lambda r: str(by_rev[r][0])))
    if pending:  # a cycle or a revision missing its parent: keep file order for the rest
        ordered.extend(by_rev[r] for r in sorted(pending, key=lambda r: str(by_rev[r][0])))
    return ordered


_MODEL_SCAN_SKIP_PARTS = frozenset({"__pycache__", "tests", "test"})


def _model_source_files(app_dir: Path, models_dir: Path) -> list[Path]:
    """Python files that may declare ORM models or declarative bases.

    Every file under `app/models`, then any other file in the app package whose text declares
    a `__tablename__` or a declarative base (models and bases also live in `db/`, feature
    packages, and so on).
    """
    files = (
        [p for p in sorted(models_dir.rglob("*.py")) if "__pycache__" not in p.parts]
        if models_dir.is_dir()
        else []
    )
    seen = set(files)
    if app_dir.is_dir():
        for py_file in sorted(app_dir.rglob("*.py")):
            if py_file in seen or _MODEL_SCAN_SKIP_PARTS.intersection(py_file.relative_to(app_dir).parts):
                continue
            try:
                text = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if "__tablename__" in text or "declarative" in text.lower():
                files.append(py_file)
    return files


def _dotted_module(app_dir: Path, py_file: Path) -> str:
    """`<backend>/app/models/user.py` -> `app.models.user` (package `__init__` -> the package)."""
    try:
        parts = list(py_file.relative_to(app_dir).with_suffix("").parts)
    except ValueError:
        return py_file.stem
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join([app_dir.name, *parts])


def _git_last_commit_epoch(repo_root: Path, rel_path: str) -> int | None:
    try:
        res = subprocess.run(
            ["git", "log", "-1", "--format=%ct", "--", rel_path],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = res.stdout.strip()
    return int(out) if out.isdigit() else None


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
        notes: list[str] = []

        # 1. Models, grouped by the declarative base they inherit from.
        orm_tables: dict[str, tuple[str, int, list[str], str, list[str]]] = {}
        model_bases: dict[str, list[str]] = {}
        class_bases: dict[str, list[str]] = {}
        class_modules: dict[str, set[str]] = {}
        model_modules: set[str] = set()
        model_fk_refs: list[tuple[str, str, str, str]] = []  # (src table, kind, target, evidence path)
        roots: set[str] = set()
        app_dir = backend_dir / "app"
        for py_file in _model_source_files(app_dir, models_dir):
            rel_path = py_file.relative_to(repo_root).as_posix()
            scan = _scan_model_module(py_file, rel_path)
            class_bases.update(scan.class_bases)
            roots |= scan.roots
            module = _dotted_module(app_dir, py_file)
            if scan.models or models_dir in py_file.parents:
                model_modules.add(module)
            model_fk_refs.extend((src, kind, target, rel_path) for src, kind, target in scan.fk_refs)
            for cls_name, tbl_name, lineno, cols, summary, bases in scan.models:
                class_modules.setdefault(cls_name, set()).add(module)
                key = tbl_name.lower()
                if key not in orm_tables:
                    orm_tables[key] = (rel_path, lineno, cols, summary, [cls_name])
                    model_bases[key] = bases
                else:
                    orm_tables[key][4].append(cls_name)

        table_group = {
            key: _model_group(model_bases.get(key, []), class_bases, roots) for key in orm_tables
        }
        group_sizes: dict[str, int] = {}
        for grp in table_group.values():
            group_sizes[grp] = group_sizes.get(grp, 0) + 1
        primary_group = (
            max(group_sizes, key=lambda g: (group_sizes[g], g == _DEFAULT_GROUP, g == "Base", g))
            if group_sizes
            else _DEFAULT_GROUP
        )
        separate = {k for k, g in table_group.items() if g != primary_group}
        if separate:
            other = sorted({table_group[k] or "an imported base" for k in separate})
            notes.append(
                f"{len(separate)} model(s) on a separate declarative base ({', '.join(f'`{g}`' for g in other)}) "
                "were not checked for drift against schema.sql, migrations, or the live catalog: they use "
                "their own metadata, often for another database or schema."
            )

        # 2. DDL sources: schema.sql and Alembic upgrade() bodies.
        sql_tables: set[str] = set()
        sql_functions: dict[str, tuple[str, int]] = {}
        function_reads: dict[str, set[str]] = {}
        fk_refs: dict[tuple[str, str], str] = {}  # (referencing, referenced) -> evidence path
        # Where each DDL-only table is defined, so its node points at the CREATE TABLE.
        table_origin: dict[str, tuple[str, int, list[str]]] = {}
        if schema_sql_path.is_file():
            rel_schema = schema_sql_path.relative_to(repo_root).as_posix()
            text = schema_sql_path.read_text(encoding="utf-8", errors="replace")
            parsed_tables, parsed_funcs = _parse_sql_objects(text)
            sql_tables |= parsed_tables
            for fn_name, fn_line in parsed_funcs.items():
                sql_functions[fn_name] = (rel_schema, fn_line)
            schema_fn_reads, schema_fks = _parse_sql_lineage(text)
            function_reads.update(schema_fn_reads)
            for pair in schema_fks:
                fk_refs.setdefault(pair, rel_schema)
            ddl_detail, _ = parse_sql_ddl_objects(_blank_sql_comments(text))
            for _offset, kind, tbl, _new, line_offset, ev_cols in _sql_table_events(text):
                if kind == "create" and tbl in parsed_tables and tbl not in table_origin:
                    cols = ev_cols or ddl_detail.get(tbl, (0, []))[1]
                    table_origin[tbl] = (rel_schema, line_offset + 1, cols)

        migration_entries: list[tuple[Path, _MigrationEffects]] = []
        if alembic_dir.is_dir():
            for mig_file in sorted(alembic_dir.glob("*.py")):
                try:
                    tree = ast.parse(mig_file.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, SyntaxError):
                    continue
                migration_entries.append((mig_file, _collect_migration_effects(tree)))

        migrated_tables: set[str] = set()
        mig_origin: dict[str, tuple[str, int, list[str]]] = {}
        metadata_create_all = False
        for mig_file, effects in _order_migrations(migration_entries):
            rel_mig = mig_file.relative_to(repo_root).as_posix()
            # Replay in the order the revision runs them: drop-then-recreate keeps a table,
            # and `ALTER TABLE a RENAME TO b` / `op.rename_table(a, b)` retires `a`.
            for _order, kind, tbl, new_tbl, line, ev_cols in sorted(effects.table_events, key=lambda e: e[0]):
                if kind == "create":
                    migrated_tables.add(tbl)
                    mig_origin[tbl] = (rel_mig, line, ev_cols)
                elif kind == "drop":
                    migrated_tables.discard(tbl)
                    mig_origin.pop(tbl, None)
                elif new_tbl:
                    migrated_tables.discard(tbl)
                    migrated_tables.add(new_tbl)
                    prior = mig_origin.pop(tbl, None)
                    mig_origin[new_tbl] = (rel_mig, line, prior[2] if prior else [])
            metadata_create_all |= effects.creates_all_metadata
            for fn_name, fn_line in effects.created_functions.items():
                sql_functions[fn_name] = (rel_mig, fn_line)
                # A (re)definition with a readable body replaces what the function reads. A header
                # without a parsable body (e.g. text spliced into a fetched definition) leaves the
                # last known body in place.
                if fn_name in effects.function_reads:
                    function_reads[fn_name] = set(effects.function_reads[fn_name])
            for fn_name in effects.dropped_functions - set(effects.created_functions):
                sql_functions.pop(fn_name, None)
                function_reads.pop(fn_name, None)
            for pair in effects.fk_refs:
                fk_refs.setdefault(pair, rel_mig)
        sql_tables |= migrated_tables
        for tbl in migrated_tables:
            if tbl not in table_origin and tbl in mig_origin:
                table_origin[tbl] = mig_origin[tbl]
        if metadata_create_all:
            # A revision runs `metadata.create_all()`: every primary-base model is created by it.
            sql_tables |= {k for k in orm_tables if k not in separate}

        has_schema_sql = schema_sql_path.is_file()
        has_migrations = bool(migration_entries)
        ddl_mig_files = [mf for mf, eff in migration_entries if eff.touches_ddl]
        stale_note = ""
        if has_schema_sql and ddl_mig_files:
            sql_epoch = _git_last_commit_epoch(repo_root, schema_sql_path.relative_to(repo_root).as_posix())
            ddl_epochs = [
                ep
                for mf in ddl_mig_files
                if (ep := _git_last_commit_epoch(repo_root, mf.relative_to(repo_root).as_posix())) is not None
            ]
            mig_epoch = max(ddl_epochs) if ddl_epochs else None
            if sql_epoch is not None and mig_epoch is not None and mig_epoch > sql_epoch:
                days = max(1, (mig_epoch - sql_epoch) // 86400)
                stale_note = f" (schema.sql was last changed {days} day(s) before the newest DDL migration)"
                notes.append(
                    f"schema.sql was last changed {days} day(s) before the newest DDL migration; "
                    "migrations were read as DDL too, so tables they create are not reported missing."
                )

        # 3. Nodes.
        all_table_keys = sorted(set(orm_tables.keys()) | sql_tables)
        for tbl_key in all_table_keys:
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
            if tbl_key in orm_tables:
                src_file, lineno, cols, summary, cls_names = orm_tables[tbl_key]
                for cls_name in cls_names:
                    table_symbol_map[cls_name] = node_id
                if tbl_key in separate:
                    base = table_group[tbl_key] or "an imported base"
                    summary = f"{summary} (separate declarative base `{base}`; not checked against the primary schema.)"
            elif tbl_key in table_origin:
                src_file, lineno, cols = table_origin[tbl_key]
                summary = f"SQL-defined table `{tbl_key}`."
            else:
                src_file = (
                    schema_sql_path.relative_to(repo_root).as_posix()
                    if has_schema_sql
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

        # 3b. Database-side readers: SQL function bodies and foreign keys consume tables too.
        def table_node(key: str) -> str | None:
            nid = table_symbol_map.get(key)
            return nid if nid and nid.startswith("t:") else None

        db_readers: dict[str, dict[str, tuple[str, str, str]]] = {}
        for fn_key, read_tables in sorted(function_reads.items()):
            if fn_key not in sql_functions:
                continue
            fn_src = sql_functions[fn_key][0]
            for tbl in sorted(read_tables):
                tid = table_node(tbl)
                if tid:
                    db_readers.setdefault(tid, {}).setdefault(
                        f"fn:{fn_key}",
                        (fn_src, "reads_truth", f"SQL function `{fn_key}()` reads `{tbl}`."),
                    )
        for src_kind_target in model_fk_refs:
            src, kind, target, evidence = src_kind_target
            dst = table_node(target) if kind == "table" else table_symbol_map.get(target)
            if dst:
                fk_refs.setdefault((src, dst.removeprefix("t:")), evidence)
        for (src, dst), evidence in sorted(fk_refs.items()):
            src_id, dst_id = table_node(src), table_node(dst)
            if src_id and dst_id and src_id != dst_id:
                db_readers.setdefault(dst_id, {}).setdefault(
                    src_id,
                    (evidence, "guards_truth", f"Foreign key from `{src}` references `{dst}`."),
                )

        # 4. Drift: primary-base models with no DDL, and (with --dsn) models absent live.
        checked = {k: v for k, v in orm_tables.items() if k not in separate}
        ddl_source = "schema.sql or any migration" if has_migrations else "schema.sql"
        static_missing: set[str] = set()
        # Gated on schema.sql as before: a migrations-only repo whose DDL style is not
        # recognized would otherwise get new false alarms.
        if has_schema_sql:
            static_missing = {
                k
                for k in checked
                if "." not in k and k not in sql_tables and not k.endswith("_version")
            }

        obs_source = "static_ast"
        live_missing: set[str] = set()
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            live_missing = {k for k in checked if k not in live_tables}

        for tbl_key in sorted(static_missing - live_missing):
            src_file, lineno, _, _, _ = checked[tbl_key]
            if pg_dsn:
                findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-005",
                        node_id=f"t:{tbl_key}",
                        source_file=src_file,
                        line=lineno,
                        title=f"Table `{tbl_key}` exists live but no CREATE TABLE in {ddl_source} creates it",
                        detail=(
                            f"SQLAlchemy declares `{tbl_key}` in {src_file} and the live catalog has it, but "
                            f"Wythe found no CREATE TABLE for it in {ddl_source}{stale_note}."
                        ),
                        remediation="Add the migration that creates it (or confirm how it is created) so the schema can be rebuilt from source.",
                    )
                )
            else:
                findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-002",
                        node_id=f"t:{tbl_key}",
                        source_file=src_file,
                        line=lineno,
                        title=f"ORM model `{tbl_key}` has no CREATE TABLE in {ddl_source}",
                        detail=(
                            f"SQLAlchemy declares `{tbl_key}` in {src_file}, but {ddl_source} has no "
                            f"CREATE TABLE for it{stale_note}. Pass --dsn to check the live database."
                        ),
                        remediation="Add the migration that creates the table, or retire the unmapped model.",
                    )
                )

        for tbl_key in sorted(live_missing):
            src_file, lineno, _, _, _ = checked[tbl_key]
            also = (
                f" No CREATE TABLE in {ddl_source} creates it either."
                if tbl_key in static_missing
                else ""
            )
            findings.append(
                RawCandidateFinding(
                    rule_code="TRUTH-002",
                    node_id=f"t:{tbl_key}",
                    source_file=src_file,
                    line=lineno,
                    title=f"ORM model `{tbl_key}` absent from live database catalog",
                    detail=f"Read-only catalog check ({obs_source}) did not find base table `{tbl_key}`.{also}",
                    remediation="Apply pending migrations on the target database before trusting ORM consumers.",
                )
            )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
            notes=notes,
            class_modules=class_modules,
            model_modules=model_modules,
            db_readers=db_readers,
        )
