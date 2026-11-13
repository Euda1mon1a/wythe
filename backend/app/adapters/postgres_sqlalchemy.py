"""Tier 1 Adapter: PostgreSQL + SQLAlchemy + Alembic + schema.sql (+ optional pg_catalog)."""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path

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
    bracket_depth = 0
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
        elif c == "[":
            bracket_depth += 1
        elif c == "]" and bracket_depth > 0:
            bracket_depth -= 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                top_parts.append(cleaned_sql[seg_start:j])
                break
        elif c == "," and depth == 1 and bracket_depth == 0:
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


def _eval_str(
    node: ast.AST | None,
    consts: dict[str, str],
    seqs: dict[str, list[tuple[str, int]]] | None = None,
    dicts: dict[str, dict[str, tuple[str, int]]] | None = None,
) -> str | None:
    """Statically evaluate a string expression: literals, f-strings, `+`, `text()`, `"".join()`."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        vname = node.value.id
        sl = node.slice
        if seqs and vname in seqs:
            idx: int | None = None
            if isinstance(sl, ast.Constant) and isinstance(sl.value, int) and not isinstance(sl.value, bool):
                idx = sl.value
            elif (
                isinstance(sl, ast.UnaryOp)
                and isinstance(sl.op, ast.USub)
                and isinstance(sl.operand, ast.Constant)
                and isinstance(sl.operand.value, int)
            ):
                idx = -sl.operand.value
            if idx is not None and -len(seqs[vname]) <= idx < len(seqs[vname]):
                return seqs[vname][idx][0]
        if dicts and vname in dicts:
            sl_key = _eval_str(sl, consts, seqs, dicts)
            if sl_key is not None and _UNRESOLVED not in sl_key:
                hit = dicts[vname].get(sl_key)
                if hit is not None:
                    return hit[0]
        return None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner = _eval_str(value.value, consts, seqs, dicts)
                parts.append(inner if inner is not None else _UNRESOLVED)
            else:
                parts.append(_UNRESOLVED)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_str(node.left, consts, seqs, dicts)
        right = _eval_str(node.right, consts, seqs, dicts)
        return left + right if left is not None and right is not None else None
    if isinstance(node, (ast.Tuple, ast.List)):
        items = [_eval_str(e, consts, seqs, dicts) for e in node.elts]
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
        ):
            arg0 = node.args[0]
            if isinstance(arg0, (ast.Tuple, ast.List)):
                items = [_eval_str(e, consts, seqs, dicts) for e in arg0.elts]
                return node.func.value.value.join(i for i in items if i is not None)
            if seqs and isinstance(arg0, ast.Name) and arg0.id in seqs:
                return node.func.value.value.join(s for s, _ in seqs[arg0.id] if _UNRESOLVED not in s)
        if (
            fname == "get"
            and dicts
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in dicts
            and 1 <= len(node.args) <= 2
            and not node.keywords
        ):
            k_str = _eval_str(node.args[0], consts, seqs, dicts)
            if k_str is not None and _UNRESOLVED not in k_str:
                hit = dicts[node.func.value.id].get(k_str)
                if hit is not None:
                    return hit[0]
                if len(node.args) == 2:
                    return _eval_str(node.args[1], consts, seqs, dicts)
        if fname in ("text", "dedent", "strip") and node.args:
            return _eval_str(node.args[0], consts, seqs, dicts)
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


@dataclass
class _MigrationEnv:
    scope_id: int = 0
    fns: dict[str, list[_MigrationHelper]] = field(default_factory=dict)
    consts: dict[str, str] = field(default_factory=dict)
    lines: dict[str, int] = field(default_factory=dict)
    alts: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    seqs: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    dicts: dict[str, dict[str, tuple[str, int]]] = field(default_factory=dict)
    seq_ids: dict[str, int] = field(default_factory=dict)
    seq_heap: dict[int, list[tuple[str, int]]] = field(default_factory=dict)
    dict_ids: dict[str, int] = field(default_factory=dict)
    dict_heap: dict[int, dict[str, tuple[str, int]]] = field(default_factory=dict)
    _next_cid: list[int] = field(default_factory=lambda: [1])
    mutable_seq_cids: set[int] = field(default_factory=set)
    local_defs: set[str] = field(default_factory=set)
    globals_set: set[str] = field(default_factory=set)
    dirty_globals: set[str] = field(default_factory=set)

    def alloc_cid(self) -> int:
        cid = self._next_cid[0]
        self._next_cid[0] += 1
        return cid

    def bind_seq(
        self,
        name: str,
        items: list[tuple[str, int]],
        cid: int | None = None,
        *,
        mutable: bool = True,
    ) -> int:
        if cid is None:
            cid = self.alloc_cid()
            self.seq_heap[cid] = list(items)
            if mutable:
                self.mutable_seq_cids.add(cid)
        elif cid not in self.seq_heap:
            self.seq_heap[cid] = list(items)
            if mutable:
                self.mutable_seq_cids.add(cid)
        self.seq_ids[name] = cid
        self.seqs[name] = self.seq_heap[cid]
        return cid

    def bind_dict(self, name: str, dmap: dict[str, tuple[str, int]], cid: int | None = None) -> int:
        if cid is None:
            cid = self.alloc_cid()
            self.dict_heap[cid] = dict(dmap)
        elif cid not in self.dict_heap:
            self.dict_heap[cid] = dict(dmap)
        self.dict_ids[name] = cid
        self.dicts[name] = self.dict_heap[cid]
        return cid

    def sync_seq_cid(self, cid: int) -> None:
        buf = self.seq_heap.get(cid)
        if buf is None:
            return
        known = [(s, ln) for s, ln in buf if s and _UNRESOLVED not in s]
        for k, k_cid in list(self.seq_ids.items()):
            if k_cid != cid:
                continue
            self.seqs[k] = buf
            self.alts.pop(k, None)
            if known:
                self.consts[k] = "\n".join(s for s, _ in known)
                self.lines[k] = known[0][1]
            else:
                self.consts.pop(k, None)
                self.lines.pop(k, None)

    def sync_dict_cid(self, cid: int) -> None:
        buf = self.dict_heap.get(cid)
        if buf is None:
            return
        for k, k_cid in list(self.dict_ids.items()):
            if k_cid == cid:
                self.dicts[k] = buf

    def clone(self, scope_id: int | None = None) -> _MigrationEnv:
        new_seq_heap = {cid: list(v) for cid, v in self.seq_heap.items()}
        new_dict_heap = {cid: dict(v) for cid, v in self.dict_heap.items()}
        new_seq_ids = dict(self.seq_ids)
        new_dict_ids = dict(self.dict_ids)
        return _MigrationEnv(
            scope_id=self.scope_id if scope_id is None else scope_id,
            fns={k: list(v) for k, v in self.fns.items() if v},
            consts=dict(self.consts),
            lines=dict(self.lines),
            alts={k: list(v) for k, v in self.alts.items() if v},
            seqs={k: new_seq_heap[cid] for k, cid in new_seq_ids.items() if cid in new_seq_heap},
            dicts={k: new_dict_heap[cid] for k, cid in new_dict_ids.items() if cid in new_dict_heap},
            seq_ids=new_seq_ids,
            seq_heap=new_seq_heap,
            dict_ids=new_dict_ids,
            dict_heap=new_dict_heap,
            _next_cid=self._next_cid,
            mutable_seq_cids=self.mutable_seq_cids,
            local_defs=set(self.local_defs),
            globals_set=set(self.globals_set),
            dirty_globals=set(self.dirty_globals),
        )

    def pop_name(self, name: str) -> None:
        self.fns.pop(name, None)
        self.consts.pop(name, None)
        self.lines.pop(name, None)
        self.alts.pop(name, None)
        self.seqs.pop(name, None)
        self.dicts.pop(name, None)
        self.seq_ids.pop(name, None)
        self.dict_ids.pop(name, None)


@dataclass
class _MigrationHelper:
    fn: ast.FunctionDef | ast.AsyncFunctionDef
    scope_id: int
    captured: _MigrationEnv
    default_consts: dict[str, str]
    default_lines: dict[str, int]
    default_alts: dict[str, list[tuple[str, int]]]
    default_seqs: dict[str, list[tuple[str, int]]]
    default_dicts: dict[str, dict[str, tuple[str, int]]] = field(default_factory=dict)
    default_seq_ids: dict[str, int] = field(default_factory=dict)
    default_dict_ids: dict[str, int] = field(default_factory=dict)
    default_fns: dict[str, list[_MigrationHelper]] = field(default_factory=dict)


def _stmts_always_exit(stmts: list[ast.stmt]) -> bool:
    for s in stmts:
        if isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return True
        if isinstance(s, ast.If) and _stmts_always_exit(s.body) and _stmts_always_exit(s.orelse):
            return True
    return False


def _merge_migration_envs(target: _MigrationEnv, branches: list[_MigrationEnv]) -> None:
    if not branches:
        return
    if len(branches) == 1:
        only = branches[0]
        for entries in only.fns.values():
            for h in entries:
                if h.captured is only:
                    h.captured = target
        target.fns.clear()
        target.fns.update({k: list(v) for k, v in only.fns.items() if v})
        target.consts.clear()
        target.consts.update(only.consts)
        target.lines.clear()
        target.lines.update(only.lines)
        target.alts.clear()
        target.alts.update({k: list(v) for k, v in only.alts.items() if v})
        target.seq_heap.clear()
        target.seq_heap.update({cid: list(v) for cid, v in only.seq_heap.items()})
        target.dict_heap.clear()
        target.dict_heap.update({cid: dict(v) for cid, v in only.dict_heap.items()})
        target.seq_ids.clear()
        target.seq_ids.update(only.seq_ids)
        target.dict_ids.clear()
        target.dict_ids.update(only.dict_ids)
        target.seqs.clear()
        target.seqs.update(
            {k: target.seq_heap[cid] for k, cid in target.seq_ids.items() if cid in target.seq_heap}
        )
        target.dicts.clear()
        target.dicts.update(
            {k: target.dict_heap[cid] for k, cid in target.dict_ids.items() if cid in target.dict_heap}
        )
        target.dirty_globals.update(only.dirty_globals)
        return

    branch_set = tuple(branches)
    merged_fns: dict[str, list[_MigrationHelper]] = {}
    for br in branches:
        for k, entries in br.fns.items():
            bucket = merged_fns.setdefault(k, [])
            seen_ids = {id(h.fn) for h in bucket}
            for h in entries:
                if any(h.captured is b for b in branch_set):
                    h.captured = target
                if id(h.fn) not in seen_ids:
                    seen_ids.add(id(h.fn))
                    bucket.append(h)

    all_str_keys: set[str] = set()
    for br in branches:
        all_str_keys.update(br.consts)
        all_str_keys.update(br.alts)
    merged_consts: dict[str, str] = {}
    merged_lines: dict[str, int] = {}
    merged_alts: dict[str, list[tuple[str, int]]] = {}
    for k in all_str_keys:
        cands: list[tuple[str, int]] = []
        seen_vals: set[str] = set()
        every_branch_has = True
        for br in branches:
            if k in br.consts:
                pairs = [(br.consts[k], br.lines.get(k, 1))]
            elif br.alts.get(k):
                pairs = br.alts[k]
            else:
                every_branch_has = False
                pairs = []
            for v_str, v_ln in pairs:
                if v_str not in seen_vals:
                    seen_vals.add(v_str)
                    cands.append((v_str, v_ln))
        if every_branch_has and len(cands) == 1:
            merged_consts[k] = cands[0][0]
            merged_lines[k] = cands[0][1]
        elif cands:
            merged_alts[k] = cands

    merged_seq_heap: dict[int, list[tuple[str, int]]] = {}
    for cid in {c for br in branches for c in br.seq_heap}:
        holders = [br.seq_heap[cid] for br in branches if cid in br.seq_heap]
        if all(h == holders[0] for h in holders[1:]):
            merged_seq_heap[cid] = list(holders[0])
            continue
        combined_seq: list[tuple[str, int]] = []
        seen_seq: set[tuple[str, int]] = set()
        for h in holders:
            for item in h:
                if item not in seen_seq:
                    seen_seq.add(item)
                    combined_seq.append(item)
        merged_seq_heap[cid] = combined_seq

    merged_dict_heap: dict[int, dict[str, tuple[str, int]]] = {}
    for cid in {c for br in branches for c in br.dict_heap}:
        combined_d: dict[str, tuple[str, int]] = {}
        for br in branches:
            if cid not in br.dict_heap:
                continue
            for dk, dval in br.dict_heap[cid].items():
                if dk not in combined_d:
                    combined_d[dk] = dval
                elif combined_d[dk][0] != dval[0]:
                    existing_parts = combined_d[dk][0].split("\n")
                    if dval[0] not in existing_parts:
                        combined_d[dk] = (f"{combined_d[dk][0]}\n{dval[0]}", combined_d[dk][1])
        merged_dict_heap[cid] = combined_d

    merged_seq_ids: dict[str, int] = {}
    for k in {k for br in branches for k in br.seq_ids}:
        cids = {br.seq_ids[k] for br in branches if k in br.seq_ids}
        if len(cids) == 1 and all(k in br.seq_ids for br in branches):
            merged_seq_ids[k] = next(iter(cids))
        else:
            mcid = target.alloc_cid()
            comb_k: list[tuple[str, int]] = []
            seen_k: set[tuple[str, int]] = set()
            for br in branches:
                if k in br.seq_ids:
                    for item in merged_seq_heap.get(br.seq_ids[k], ()):
                        if item not in seen_k:
                            seen_k.add(item)
                            comb_k.append(item)
            merged_seq_heap[mcid] = comb_k
            if any(br.seq_ids.get(k) in target.mutable_seq_cids for br in branches):
                target.mutable_seq_cids.add(mcid)
            merged_seq_ids[k] = mcid

    merged_dict_ids: dict[str, int] = {}
    for k in {k for br in branches for k in br.dict_ids}:
        cids = {br.dict_ids[k] for br in branches if k in br.dict_ids}
        if len(cids) == 1 and all(k in br.dict_ids for br in branches):
            merged_dict_ids[k] = next(iter(cids))
        else:
            mcid = target.alloc_cid()
            comb_d: dict[str, tuple[str, int]] = {}
            for br in branches:
                if k not in br.dict_ids:
                    continue
                for dk, dval in merged_dict_heap.get(br.dict_ids[k], {}).items():
                    if dk not in comb_d:
                        comb_d[dk] = dval
                    elif comb_d[dk][0] != dval[0]:
                        existing_parts = comb_d[dk][0].split("\n")
                        if dval[0] not in existing_parts:
                            comb_d[dk] = (f"{comb_d[dk][0]}\n{dval[0]}", comb_d[dk][1])
            merged_dict_heap[mcid] = comb_d
            merged_dict_ids[k] = mcid

    target.fns.clear()
    target.fns.update(merged_fns)
    target.consts.clear()
    target.consts.update(merged_consts)
    target.lines.clear()
    target.lines.update(merged_lines)
    target.alts.clear()
    target.alts.update(merged_alts)
    target.seq_heap.clear()
    target.seq_heap.update(merged_seq_heap)
    target.dict_heap.clear()
    target.dict_heap.update(merged_dict_heap)
    target.seq_ids.clear()
    target.seq_ids.update(merged_seq_ids)
    target.dict_ids.clear()
    target.dict_ids.update(merged_dict_ids)
    target.seqs.clear()
    target.seqs.update(
        {k: target.seq_heap[cid] for k, cid in target.seq_ids.items() if cid in target.seq_heap}
    )
    target.dicts.clear()
    target.dicts.update(
        {k: target.dict_heap[cid] for k, cid in target.dict_ids.items() if cid in target.dict_heap}
    )
    for br in branches:
        target.dirty_globals.update(br.dirty_globals)


def _eval_str_variants(node: ast.AST | None, env: _MigrationEnv) -> list[tuple[str, int]]:
    if node is None:
        return []
    if isinstance(node, ast.Name) and node.id in env.alts:
        return list(env.alts[node.id])
    alt_names: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in env.alts and n.id not in alt_names:
            alt_names.append(n.id)
    if not alt_names:
        ev = _eval_str(node, env.consts, env.seqs, env.dicts)
        if ev is not None and _UNRESOLVED not in ev:
            ln = env.lines[node.id] if isinstance(node, ast.Name) and node.id in env.lines else getattr(node, "lineno", 1)
            return [(ev, ln)]
        return []
    combos: list[tuple[dict[str, str], int]] = [(dict(env.consts), getattr(node, "lineno", 1))]
    for k in alt_names[:4]:
        combos = [
            ({**c_map, k: v_s}, v_ln if isinstance(node, ast.Name) else c_ln)
            for c_map, c_ln in combos
            for v_s, v_ln in env.alts[k][:8]
        ][:32]
    out: list[tuple[str, int]] = []
    seen: set[str] = set()
    for c_map, c_ln in combos:
        ev_c = _eval_str(node, c_map, env.seqs, env.dicts)
        if ev_c is not None and _UNRESOLVED not in ev_c and ev_c not in seen:
            seen.add(ev_c)
            out.append((ev_c, c_ln))
    return out


def _eval_int_index(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.USub, ast.UAdd))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        return -node.operand.value if isinstance(node.op, ast.USub) else node.operand.value
    return None


def _is_mutable_seq_expr(node: ast.AST | None, env: _MigrationEnv) -> bool:
    if isinstance(node, ast.List):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id == "list":
            return True
        if node.func.id == "tuple":
            return False
    if isinstance(node, ast.Name) and node.id in env.seq_ids:
        return env.seq_ids[node.id] in env.mutable_seq_cids
    return False


def _sync_seq_const(cur_env: _MigrationEnv, vname: str) -> None:
    cid = cur_env.seq_ids.get(vname)
    if cid is not None:
        cur_env.sync_seq_cid(cid)
        return
    seq_list = cur_env.seqs.get(vname)
    if seq_list is None:
        return
    known = [(s, ln) for s, ln in seq_list if s and _UNRESOLVED not in s]
    cur_env.alts.pop(vname, None)
    if known:
        cur_env.consts[vname] = "\n".join(s for s, _ in known)
        cur_env.lines[vname] = known[0][1]
    else:
        cur_env.consts.pop(vname, None)
        cur_env.lines.pop(vname, None)


def _bind_subscript(tgt: ast.Subscript, variants: list[tuple[str, int]], cur_env: _MigrationEnv) -> bool:
    if not isinstance(tgt.value, ast.Name):
        return False
    vname = tgt.value.id
    combined: tuple[str, int] | None = None
    if variants:
        combined = (
            variants[0]
            if len(variants) == 1
            else ("\n".join(dict.fromkeys(v for v, _ in variants)), variants[0][1])
        )
    if vname in cur_env.dicts:
        key_variants = _eval_str_variants(tgt.slice, cur_env)
        if not key_variants:
            return False
        d_ref = cur_env.dicts[vname]
        for k_str, _ in key_variants:
            d_ref[k_str] = combined if combined is not None else (_UNRESOLVED, 0)
        return True
    if vname in cur_env.seqs:
        idx = _eval_int_index(tgt.slice)
        seq_ref = cur_env.seqs[vname]
        if idx is None or not (-len(seq_ref) <= idx < len(seq_ref)):
            return False
        seq_ref[idx] = combined if combined is not None else (_UNRESOLVED, 0)
        _sync_seq_const(cur_env, vname)
        return True
    return False


def _eval_seq_items(node: ast.AST | None, env: _MigrationEnv) -> list[tuple[str, int]] | None:
    if isinstance(node, ast.Name) and node.id in env.seqs:
        return list(env.seqs[node.id])
    if isinstance(node, (ast.Tuple, ast.List)):
        out: list[tuple[str, int]] = []
        for elt in node.elts:
            if isinstance(elt, ast.Starred):
                if isinstance(elt.value, ast.Name) and elt.value.id in env.seqs:
                    out.extend(env.seqs[elt.value.id])
                else:
                    out.append((_UNRESOLVED, 0))
                continue
            elt_vars = _eval_str_variants(elt, env)
            if elt_vars:
                out.extend(elt_vars)
            else:
                out.append((_UNRESOLVED, 0))
        return out
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("list", "tuple")
        and not node.keywords
    ):
        if not node.args:
            return []
        if len(node.args) == 1:
            return _eval_seq_items(node.args[0], env)
    return None


def _eval_dict_items(node: ast.AST | None, env: _MigrationEnv) -> dict[str, tuple[str, int]] | None:
    if isinstance(node, ast.Name) and node.id in env.dicts:
        return dict(env.dicts[node.id])
    if isinstance(node, ast.Dict):
        dmap: dict[str, tuple[str, int]] = {}
        for dk, dv in zip(node.keys, node.values, strict=False):
            if dk is None and isinstance(dv, ast.Name) and dv.id in env.dicts:
                dmap.update(env.dicts[dv.id])
            elif isinstance(dk, ast.Constant) and isinstance(dk.value, str):
                variants = _eval_str_variants(dv, env)
                dmap[dk.value] = (
                    (
                        variants[0]
                        if len(variants) == 1
                        else ("\n".join(dict.fromkeys(v for v, _ in variants)), variants[0][1])
                    )
                    if variants
                    else (_UNRESOLVED, 0)
                )
        return dmap if dmap or not node.keys else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        if len(node.args) > 1:
            return None
        dmap = {}
        if len(node.args) == 1:
            base_d = _eval_dict_items(node.args[0], env)
            if base_d is None:
                return None
            dmap.update(base_d)
        for kw in node.keywords:
            if kw.arg is not None:
                variants = _eval_str_variants(kw.value, env)
                dmap[kw.arg] = (
                    (
                        variants[0]
                        if len(variants) == 1
                        else ("\n".join(dict.fromkeys(v for v, _ in variants)), variants[0][1])
                    )
                    if variants
                    else (_UNRESOLVED, 0)
                )
            elif isinstance(kw.value, ast.Name) and kw.value.id in env.dicts:
                dmap.update(env.dicts[kw.value.id])
            else:
                return None
        return dmap if dmap or (not node.args and not node.keywords) else None
    return None


def _extract_fn_defaults(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    def_env: _MigrationEnv,
) -> tuple[
    dict[str, str],
    dict[str, int],
    dict[str, list[tuple[str, int]]],
    dict[str, list[tuple[str, int]]],
    dict[str, dict[str, tuple[str, int]]],
    dict[str, int],
    dict[str, int],
]:
    d_consts: dict[str, str] = {}
    d_lines: dict[str, int] = {}
    d_alts: dict[str, list[tuple[str, int]]] = {}
    d_seqs: dict[str, list[tuple[str, int]]] = {}
    d_dicts: dict[str, dict[str, tuple[str, int]]] = {}
    d_seq_ids: dict[str, int] = {}
    d_dict_ids: dict[str, int] = {}
    pos_params = [*fn.args.posonlyargs, *fn.args.args]
    pairs: list[tuple[ast.arg, ast.expr]] = []
    if fn.args.defaults:
        pairs.extend(zip(pos_params[-len(fn.args.defaults) :], fn.args.defaults, strict=False))
    for param, dflt in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=False):
        if dflt is not None:
            pairs.append((param, dflt))
    for param, dflt in pairs:
        seq = _eval_seq_items(dflt, def_env)
        if seq is not None:
            d_seqs[param.arg] = seq
            if isinstance(dflt, ast.Name) and dflt.id in def_env.seq_ids:
                d_seq_ids[param.arg] = def_env.seq_ids[dflt.id]
            else:
                d_seq_ids[param.arg] = def_env.bind_seq(
                    f"__default_seq_{id(fn)}_{param.arg}",
                    seq,
                    mutable=_is_mutable_seq_expr(dflt, def_env),
                )
                def_env.pop_name(f"__default_seq_{id(fn)}_{param.arg}")
        dmap = _eval_dict_items(dflt, def_env)
        if dmap is not None:
            d_dicts[param.arg] = dmap
            if isinstance(dflt, ast.Name) and dflt.id in def_env.dict_ids:
                d_dict_ids[param.arg] = def_env.dict_ids[dflt.id]
            else:
                d_dict_ids[param.arg] = def_env.bind_dict(f"__default_dict_{id(fn)}_{param.arg}", dmap)
                def_env.pop_name(f"__default_dict_{id(fn)}_{param.arg}")
        variants = [] if isinstance(dflt, ast.Dict) else _eval_str_variants(dflt, def_env)
        if len(variants) == 1:
            d_consts[param.arg], d_lines[param.arg] = variants[0]
        elif len(variants) > 1:
            d_alts[param.arg] = variants
    return d_consts, d_lines, d_alts, d_seqs, d_dicts, d_seq_ids, d_dict_ids


def _extract_fn_default_callables(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    def_env: _MigrationEnv,
) -> dict[str, list[_MigrationHelper]]:
    d_fns: dict[str, list[_MigrationHelper]] = {}
    pos_params = [*fn.args.posonlyargs, *fn.args.args]
    pairs: list[tuple[ast.arg, ast.expr]] = []
    if fn.args.defaults:
        pairs.extend(zip(pos_params[-len(fn.args.defaults) :], fn.args.defaults, strict=False))
    for param, dflt in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=False):
        if dflt is not None:
            pairs.append((param, dflt))
    for param, dflt in pairs:
        if isinstance(dflt, ast.Name) and dflt.id in def_env.fns:
            d_fns[param.arg] = list(def_env.fns[dflt.id])
    return d_fns


def _shallow_scope_decls(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[set[str], set[str]]:
    nonlocals: set[str] = set()
    globals_: set[str] = set()
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Nonlocal):
            nonlocals.update(node.names)
        elif isinstance(node, ast.Global):
            globals_.update(node.names)
        else:
            stack.extend(ast.iter_child_nodes(node))
    return nonlocals, globals_


def _local_assigned_names(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    nonlocals: set[str],
    globals_: set[str],
) -> set[str]:
    names: set[str] = {
        p.arg
        for p in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs, fn.args.vararg, fn.args.kwarg)
        if p is not None
    }
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
        stack.extend(ast.iter_child_nodes(node))
    return names - (nonlocals | globals_)


def _copy_env_binding(dst: _MigrationEnv, src: _MigrationEnv, name: str) -> None:
    dst.pop_name(name)
    if name in src.fns:
        dst.fns[name] = list(src.fns[name])
    if name in src.consts:
        dst.consts[name] = src.consts[name]
    if name in src.lines:
        dst.lines[name] = src.lines[name]
    if name in src.alts:
        dst.alts[name] = list(src.alts[name])
    if name in src.seqs:
        scid = src.seq_ids.get(name)
        if scid is not None:
            dst.seq_heap[scid] = list(src.seqs[name])
            dst.bind_seq(name, dst.seq_heap[scid], cid=scid, mutable=scid in src.mutable_seq_cids)
            dst.sync_seq_cid(scid)
        else:
            dst.bind_seq(name, src.seqs[name])
    if name in src.dicts:
        dcid = src.dict_ids.get(name)
        if dcid is not None:
            dst.dict_heap[dcid] = dict(src.dicts[name])
            dst.bind_dict(name, dst.dict_heap[dcid], cid=dcid)
            dst.sync_dict_cid(dcid)
        else:
            dst.bind_dict(name, src.dicts[name])


def _collect_migration_effects(tree: ast.Module) -> _MigrationEffects:
    """Tables/functions an Alembic revision's `upgrade()` creates or drops."""
    effects = _MigrationEffects()
    module_env = _MigrationEnv(scope_id=0)
    suppress_ddl = False

    def add_event(
        order: tuple, kind: str, table: str, new_table: str | None, lineno: int, cols: list[str] | None = None
    ) -> None:
        if suppress_ddl:
            return
        effects.table_events.append((order, kind, table, new_table, lineno, list(cols or [])))

    def absorb_sql(sql_text: str, lineno: int, order: tuple) -> None:
        if suppress_ddl:
            return
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

    def fk_targets_in(node: ast.AST, cur_env: _MigrationEnv) -> set[str]:
        found: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _expr_name(sub.func) == "ForeignKey" and sub.args:
                for target, _ in _eval_str_variants(sub.args[0], cur_env):
                    fk_table = _fk_target_table(target)
                    if fk_table:
                        found.add(fk_table)
        return found

    def table_keys(call: ast.Call, cur_env: _MigrationEnv, arg_index: int = 0) -> list[str]:
        if len(call.args) <= arg_index:
            return []
        names = [nm for nm, _ in _eval_str_variants(call.args[arg_index], cur_env) if nm]
        if not names:
            return []
        schemas = ["public"]
        for kw in call.keywords:
            if kw.arg == "schema":
                kw_vals = [sv.lower() for sv, _ in _eval_str_variants(kw.value, cur_env) if sv]
                schemas = kw_vals or ["public"]
        out: list[str] = []
        for schema in schemas:
            for name in names:
                key = name.lower() if schema == "public" else f"{schema}.{name.lower()}"
                if key not in out:
                    out.append(key)
        return out

    def column_names(call: ast.Call, cur_env: _MigrationEnv) -> list[str]:
        names: list[str] = []
        for arg in call.args[1:]:
            if isinstance(arg, ast.Call) and _expr_name(arg.func) == "Column" and arg.args:
                for col, _ in _eval_str_variants(arg.args[0], cur_env):
                    if col and col.lower() not in names:
                        names.append(col.lower())
        return names

    active_fns: set[int] = set()
    active_scope_envs: dict[int, _MigrationEnv] = {0: module_env}
    next_scope_seq = 1
    absorbed_consts: set[tuple[str, str]] = set()
    return_collectors: list[tuple[int, list[_MigrationHelper], list[list[list[_MigrationHelper]]]]] = []
    sql_exec_calls = frozenset({"execute", "exec_driver_sql", "run_sql", "scalar", "scalars"})
    non_exec_calls = frozenset(
        {"print", "info", "debug", "warning", "warn", "error", "exception", "critical", "log", "len", "repr", "str"}
    )

    def _dedup_helpers(items: list[_MigrationHelper]) -> list[_MigrationHelper]:
        out: list[_MigrationHelper] = []
        seen: set[tuple[int, int]] = set()
        for h in items:
            key = (id(h.fn), id(h.captured))
            if key not in seen:
                seen.add(key)
                out.append(h)
        return out

    def _snapshot_helper_closure(
        h: _MigrationHelper, cur_env: _MigrationEnv, fn_scope_id: int | None
    ) -> _MigrationHelper:
        if fn_scope_id is None or h.scope_id != fn_scope_id:
            return h
        cap_snap = cur_env.clone(scope_id=h.scope_id)
        for k_fn, entries in list(cap_snap.fns.items()):
            cap_snap.fns[k_fn] = [
                replace(sh, captured=cap_snap) if sh.scope_id == fn_scope_id else sh
                for sh in entries
            ]
        return replace(h, captured=cap_snap)

    def _lambda_to_helper(lam: ast.Lambda, cur_env: _MigrationEnv, fn_scope_id: int | None = None) -> _MigrationHelper:
        syn_fn = ast.FunctionDef(
            name="<lambda>",
            args=lam.args,
            body=[ast.Return(value=lam.body)],
            decorator_list=[],
            lineno=getattr(lam, "lineno", 1),
            col_offset=getattr(lam, "col_offset", 0),
        )
        d_consts, d_lines, d_alts, d_seqs, d_dicts, d_seq_ids, d_dict_ids = _extract_fn_defaults(syn_fn, cur_env)
        d_fns = _extract_fn_default_callables(syn_fn, cur_env)
        h = _MigrationHelper(
            fn=syn_fn,
            scope_id=cur_env.scope_id,
            captured=cur_env,
            default_consts=d_consts,
            default_lines=d_lines,
            default_alts=d_alts,
            default_seqs=d_seqs,
            default_dicts=d_dicts,
            default_seq_ids=d_seq_ids,
            default_dict_ids=d_dict_ids,
            default_fns=d_fns,
        )
        return _snapshot_helper_closure(h, cur_env, fn_scope_id)

    def _eval_callable_expr(
        expr: ast.AST | None, cur_env: _MigrationEnv, fn_scope_id: int | None = None
    ) -> list[_MigrationHelper]:
        if expr is None:
            return []
        if isinstance(expr, ast.Name) and expr.id in cur_env.fns:
            return [_snapshot_helper_closure(h, cur_env, fn_scope_id) for h in cur_env.fns[expr.id]]
        if isinstance(expr, ast.Lambda):
            return [_lambda_to_helper(expr, cur_env, fn_scope_id)]
        if isinstance(expr, ast.IfExp):
            return _dedup_helpers(
                _eval_callable_expr(expr.body, cur_env, fn_scope_id)
                + _eval_callable_expr(expr.orelse, cur_env, fn_scope_id)
            )
        return []

    def has_shallow_break(stmts: list[ast.stmt]) -> bool:
        stack: list[ast.AST] = list(stmts)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.For, ast.AsyncFor, ast.While, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(n, ast.Break):
                return True
            stack.extend(ast.iter_child_nodes(n))
        return False

    def run_in_branch_env(
        stmts: list[ast.stmt],
        br_env: _MigrationEnv,
        ctx_b: tuple,
        *,
        in_sql_exec: bool,
        in_non_exec: bool,
    ) -> None:
        prev = active_scope_envs.get(br_env.scope_id)
        active_scope_envs[br_env.scope_id] = br_env
        try:
            for s_item in stmts:
                walk_node(s_item, ctx_b, br_env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
        finally:
            if prev is not None:
                active_scope_envs[br_env.scope_id] = prev
            else:
                active_scope_envs.pop(br_env.scope_id, None)

    def snapshot_rhs(
        expr: ast.AST,
        cur_env: _MigrationEnv,
        ctx_s: tuple = (),
        *,
        in_sql_exec: bool = False,
        in_non_exec: bool = False,
    ) -> tuple:
        fns_list = _eval_callable_expr(expr, cur_env)
        fns: list[_MigrationHelper] | None = fns_list or None
        already_walked = isinstance(expr, ast.Lambda)
        call_tuple_snaps: list[tuple] | None = None
        if isinstance(expr, ast.Call):
            handled_c, c_fns, c_tup = eval_call_fns(
                expr, ctx_s, cur_env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
            )
            if handled_c:
                already_walked = True
                if c_fns:
                    fns = c_fns
                if c_tup is not None:
                    call_tuple_snaps = [
                        (elt_f or None, None, None, [], None, expr, None, None, False, True)
                        for elt_f in c_tup
                    ]
        seq = _eval_seq_items(expr, cur_env)
        dmap = _eval_dict_items(expr, cur_env)
        variants = [] if isinstance(expr, ast.Dict) else _eval_str_variants(expr, cur_env)
        seq_cid = cur_env.seq_ids.get(expr.id) if isinstance(expr, ast.Name) else None
        dict_cid = cur_env.dict_ids.get(expr.id) if isinstance(expr, ast.Name) else None
        is_mut_seq = _is_mutable_seq_expr(expr, cur_env)
        if seq is not None and seq_cid is None:
            seq_cid = cur_env.alloc_cid()
            cur_env.seq_heap[seq_cid] = list(seq)
            if is_mut_seq:
                cur_env.mutable_seq_cids.add(seq_cid)
        if dmap is not None and dict_cid is None:
            dict_cid = cur_env.alloc_cid()
            cur_env.dict_heap[dict_cid] = dict(dmap)
        sub_snaps = (
            call_tuple_snaps
            if call_tuple_snaps is not None
            else (
                [
                    snapshot_rhs(e, cur_env, ctx_s, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                    for e in expr.elts
                ]
                if isinstance(expr, (ast.Tuple, ast.List))
                else None
            )
        )
        return (fns, seq, dmap, variants, sub_snaps, expr, seq_cid, dict_cid, is_mut_seq, already_walked)

    def walk_unresolved_rhs(
        snap: tuple, ctx_r: tuple, cur_env: _MigrationEnv, *, in_sql_exec: bool, in_non_exec: bool
    ) -> None:
        fns, seq, dmap, variants, sub_snaps, expr, _seq_cid, _dict_cid, _is_mut_seq, already_walked = snap
        if already_walked:
            return
        if sub_snaps is not None:
            for elt_snap in sub_snaps:
                walk_unresolved_rhs(elt_snap, ctx_r, cur_env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(expr, ast.Dict):
            for dv in expr.values:
                if not _eval_str_variants(dv, cur_env):
                    walk_node(dv, ctx_r, cur_env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if (
            fns is None
            and (seq is None or (seq and all(_UNRESOLVED in s for s, _ in seq)))
            and dmap is None
            and not variants
        ):
            walk_node(expr, ctx_r, cur_env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)

    def bind_target(tgt: ast.AST, snap: tuple, cur_env: _MigrationEnv) -> bool:
        fns, seq, dmap, variants, sub_snaps, _expr, seq_cid, dict_cid, is_mut_seq, _already_walked = snap
        if isinstance(tgt, ast.Name):
            if fns is not None:
                cur_env.fns[tgt.id] = list(fns)
            if seq is not None:
                cur_env.bind_seq(tgt.id, seq, cid=seq_cid, mutable=is_mut_seq)
            if dmap is not None:
                cur_env.bind_dict(tgt.id, dmap, cid=dict_cid)
            if len(variants) == 1:
                cur_env.consts[tgt.id], cur_env.lines[tgt.id] = variants[0]
            elif len(variants) > 1:
                cur_env.alts[tgt.id] = list(variants)
            return True
        if isinstance(tgt, ast.Subscript):
            return _bind_subscript(tgt, variants, cur_env)
        if isinstance(tgt, (ast.Tuple, ast.List)) and not any(isinstance(e, ast.Starred) for e in tgt.elts):
            if sub_snaps is not None and len(tgt.elts) == len(sub_snaps):
                return all(
                    bind_target(t_elt, s_elt, cur_env) for t_elt, s_elt in zip(tgt.elts, sub_snaps, strict=False)
                )
            if seq is not None and len(tgt.elts) == len(seq):
                ok = True
                for t_elt, item_pair in zip(tgt.elts, seq, strict=False):
                    elt_vars = [] if _UNRESOLVED in item_pair[0] else [item_pair]
                    if not bind_target(
                        t_elt, (None, None, None, elt_vars, None, _expr, None, None, False, True), cur_env
                    ):
                        ok = False
                return ok
        return False

    def walk_node(
        sub: ast.AST,
        ctx: tuple,
        env: _MigrationEnv,
        *,
        in_sql_exec: bool = False,
        in_non_exec: bool = False,
    ) -> None:
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            d_consts, d_lines, d_alts, d_seqs, d_dicts, d_seq_ids, d_dict_ids = _extract_fn_defaults(sub, env)
            d_fns = _extract_fn_default_callables(sub, env)
            env.pop_name(sub.name)
            env.fns[sub.name] = [
                _MigrationHelper(
                    fn=sub,
                    scope_id=env.scope_id,
                    captured=env,
                    default_consts=d_consts,
                    default_lines=d_lines,
                    default_alts=d_alts,
                    default_seqs=d_seqs,
                    default_dicts=d_dicts,
                    default_seq_ids=d_seq_ids,
                    default_dict_ids=d_dict_ids,
                    default_fns=d_fns,
                )
            ]
            return
        if isinstance(sub, ast.Return):
            if sub.value is None:
                return
            collector = (
                return_collectors[-1]
                if return_collectors and return_collectors[-1][0] == env.scope_id
                else None
            )
            if isinstance(sub.value, ast.Call):
                handled_r, r_fns, r_tup = eval_call_fns(
                    sub.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
                )
                if handled_r:
                    if collector is not None:
                        collector[1].extend(r_fns)
                        if r_tup is not None:
                            collector[2].append(r_tup)
                    return
                walk_node(sub.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                return
            if isinstance(sub.value, (ast.Tuple, ast.List)) and not any(
                isinstance(e, ast.Starred) for e in sub.value.elts
            ):
                tup_fns: list[list[_MigrationHelper]] = []
                any_fn = False
                for elt in sub.value.elts:
                    if isinstance(elt, ast.Call):
                        eh, efns, _etup = eval_call_fns(
                            elt, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
                        )
                        if eh:
                            tup_fns.append(efns)
                            any_fn = any_fn or bool(efns)
                            continue
                    efns = _eval_callable_expr(elt, env, collector[0] if collector is not None else None)
                    tup_fns.append(efns)
                    if efns:
                        any_fn = True
                    else:
                        walk_node(elt, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                if any_fn and collector is not None:
                    collector[2].append(tup_fns)
                return
            direct_fns = _eval_callable_expr(
                sub.value, env, collector[0] if collector is not None else None
            )
            if direct_fns:
                if isinstance(sub.value, ast.IfExp):
                    walk_node(sub.value.test, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                if collector is not None:
                    collector[1].extend(direct_fns)
                return
            walk_node(sub.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, ast.ClassDef):
            env.pop_name(sub.name)
            return
        if isinstance(sub, ast.Lambda):
            return
        if isinstance(sub, ast.Delete):
            for tgt in sub.targets:
                if isinstance(tgt, ast.Name):
                    env.pop_name(tgt.id)
                elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                    vname = tgt.value.id
                    if vname in env.dicts:
                        for k_str, _ in _eval_str_variants(tgt.slice, env):
                            env.dicts[vname].pop(k_str, None)
                    elif vname in env.seqs:
                        idx = _eval_int_index(tgt.slice)
                        if idx is not None and -len(env.seqs[vname]) <= idx < len(env.seqs[vname]):
                            env.seqs[vname].pop(idx)
                            _sync_seq_const(env, vname)
                else:
                    walk_node(tgt, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, (ast.With, ast.AsyncWith)):
            for item in sub.items:
                walk_node(item.context_expr, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                if item.optional_vars is not None:
                    for bound in ast.walk(item.optional_vars):
                        if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                            env.pop_name(bound.id)
            for s_w in sub.body:
                walk_node(s_w, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, ast.If):
            walk_node(sub.test, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            b_env = env.clone()
            e_env = env.clone()
            run_in_branch_env(sub.body, b_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            run_in_branch_env(sub.orelse, e_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            live_branches: list[_MigrationEnv] = []
            if not _stmts_always_exit(sub.body):
                live_branches.append(b_env)
            if not _stmts_always_exit(sub.orelse):
                live_branches.append(e_env)
            _merge_migration_envs(env, live_branches)
            return
        if isinstance(sub, (ast.Try, ast.TryStar)):
            b_env = env.clone()
            run_in_branch_env(sub.body, b_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            o_env = b_env.clone()
            run_in_branch_env(sub.orelse, o_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            live_try: list[_MigrationEnv] = []
            if not _stmts_always_exit(sub.body) and not _stmts_always_exit(sub.orelse):
                live_try.append(o_env)
            h_base = env.clone()
            _merge_migration_envs(h_base, [env, b_env])
            for h in sub.handlers:
                h_env = h_base.clone()
                if h.name:
                    h_env.pop_name(h.name)
                run_in_branch_env(h.body, h_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                if not _stmts_always_exit(h.body):
                    live_try.append(h_env)
            if live_try:
                _merge_migration_envs(env, live_try)
            for s_f in sub.finalbody:
                walk_node(s_f, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, ast.Match):
            walk_node(sub.subject, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            live_cases: list[_MigrationEnv] = []
            has_wildcard = False
            for case in sub.cases:
                c_env = env.clone()
                for pat_node in ast.walk(case.pattern):
                    bound_nm = (
                        pat_node.name
                        if isinstance(pat_node, (ast.MatchAs, ast.MatchStar))
                        else pat_node.rest
                        if isinstance(pat_node, ast.MatchMapping)
                        else None
                    )
                    if bound_nm:
                        c_env.pop_name(bound_nm)
                if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                    has_wildcard = True
                if case.guard is not None:
                    walk_node(case.guard, ctx, c_env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                run_in_branch_env(case.body, c_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                if not _stmts_always_exit(case.body):
                    live_cases.append(c_env)
            if not has_wildcard:
                live_cases.append(env.clone())
            _merge_migration_envs(env, live_cases)
            return
        if isinstance(sub, ast.While):
            walk_node(sub.test, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            w_env = env.clone()
            run_in_branch_env(sub.body, w_env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            _merge_migration_envs(env, [env, w_env])
            for s_we in sub.orelse:
                walk_node(s_we, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, (ast.For, ast.AsyncFor)):
            for_order = (*ctx, (getattr(sub, "lineno", 0), getattr(sub, "col_offset", 0)))
            iter_bindings: list[list[tuple[str, str, int]]] | None = None
            seq_items = _eval_seq_items(sub.iter, env)
            if seq_items is None and isinstance(sub.iter, ast.Name) and sub.iter.id in env.dicts:
                seq_items = [(dk, ln) for dk, (_dv, ln) in env.dicts[sub.iter.id].items()]
            elif (
                seq_items is None
                and isinstance(sub.iter, ast.Call)
                and isinstance(sub.iter.func, ast.Attribute)
                and not sub.iter.args
                and isinstance(sub.iter.func.value, ast.Name)
                and sub.iter.func.value.id in env.dicts
            ):
                d_entries = env.dicts[sub.iter.func.value.id]
                if sub.iter.func.attr == "values":
                    seq_items = list(d_entries.values())
                elif sub.iter.func.attr == "keys":
                    seq_items = [(dk, ln) for dk, (_dv, ln) in d_entries.items()]
                elif (
                    sub.iter.func.attr == "items"
                    and isinstance(sub.target, (ast.Tuple, ast.List))
                    and len(sub.target.elts) == 2
                ):
                    kt, vt = sub.target.elts
                    iter_bindings = [
                        (
                            ([(kt.id, dk, ln)] if isinstance(kt, ast.Name) else [])
                            + ([(vt.id, dv, ln)] if isinstance(vt, ast.Name) and _UNRESOLVED not in dv else [])
                        )
                        for dk, (dv, ln) in d_entries.items()
                    ]
            elif (
                seq_items is None
                and isinstance(sub.iter, ast.Call)
                and isinstance(sub.iter.func, ast.Name)
                and sub.iter.func.id == "enumerate"
                and sub.iter.args
                and isinstance(sub.target, (ast.Tuple, ast.List))
                and len(sub.target.elts) == 2
                and isinstance(sub.target.elts[1], ast.Name)
            ):
                enum_seq = _eval_seq_items(sub.iter.args[0], env)
                if enum_seq is not None:
                    v_tgt = sub.target.elts[1].id
                    iter_bindings = [[] if _UNRESOLVED in s_val else [(v_tgt, s_val, s_ln)] for s_val, s_ln in enum_seq]
            if seq_items is not None:
                if isinstance(sub.target, ast.Name):
                    tname = sub.target.id
                    iter_bindings = [
                        [] if _UNRESOLVED in item_sql else [(tname, item_sql, item_ln)]
                        for item_sql, item_ln in seq_items
                    ]
                elif not seq_items:
                    iter_bindings = []
            if iter_bindings is not None:
                raw_iter = (
                    sub.iter.args[0]
                    if isinstance(sub.iter, ast.Call)
                    and isinstance(sub.iter.func, ast.Name)
                    and sub.iter.func.id == "enumerate"
                    and sub.iter.args
                    else sub.iter
                )
                if isinstance(raw_iter, (ast.Tuple, ast.List)):
                    for elt in raw_iter.elts:
                        if not _eval_str_variants(elt, env):
                            walk_node(elt, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                it_envs: list[_MigrationEnv] = []
                cur_it_env = env.clone()
                for idx_i, binds in enumerate(iter_bindings):
                    it_env = cur_it_env.clone()
                    for bound in ast.walk(sub.target):
                        if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                            it_env.pop_name(bound.id)
                    for b_name, b_sql, b_ln in binds:
                        it_env.consts[b_name] = b_sql
                        it_env.lines[b_name] = b_ln
                    it_ctx = (*for_order, (idx_i,))
                    run_in_branch_env(sub.body, it_env, it_ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                    it_envs.append(it_env)
                    cur_it_env = it_env
                if it_envs:
                    _merge_migration_envs(env, it_envs if has_shallow_break(sub.body) else [it_envs[-1]])
                for s_e in sub.orelse:
                    walk_node(s_e, for_order, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                return
            walk_node(sub.iter, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            dyn_env = env.clone()
            for bound in ast.walk(sub.target):
                if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                    dyn_env.pop_name(bound.id)
            run_in_branch_env(sub.body, dyn_env, for_order, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            _merge_migration_envs(env, [env, dyn_env])
            for s_e in sub.orelse:
                walk_node(s_e, for_order, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, ast.Assign):
            snap = snapshot_rhs(sub.value, env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            walk_unresolved_rhs(snap, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            for tgt in sub.targets:
                if isinstance(tgt, ast.Subscript):
                    walk_node(tgt.value, ctx, env, in_sql_exec=False, in_non_exec=True)
                    walk_node(tgt.slice, ctx, env, in_sql_exec=False, in_non_exec=True)
                for bound in ast.walk(tgt):
                    if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                        env.pop_name(bound.id)
            bound_all = [bind_target(tgt, snap, env) for tgt in sub.targets]
            if not all(bound_all) and snap[3] and not snap[9]:
                walk_node(sub.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, ast.AnnAssign):
            if sub.value is not None:
                snap = snapshot_rhs(sub.value, env, ctx, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                walk_unresolved_rhs(snap, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                if isinstance(sub.target, ast.Subscript):
                    walk_node(sub.target.value, ctx, env, in_sql_exec=False, in_non_exec=True)
                    walk_node(sub.target.slice, ctx, env, in_sql_exec=False, in_non_exec=True)
                for bound in ast.walk(sub.target):
                    if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                        env.pop_name(bound.id)
                if not bind_target(sub.target, snap, env) and snap[3] and not snap[9]:
                    walk_node(sub.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        if isinstance(sub, ast.AugAssign):
            if isinstance(sub.op, ast.Add) and isinstance(sub.target, ast.Name):
                tname = sub.target.id
                if tname in env.seqs:
                    rhs_seq = _eval_seq_items(sub.value, env)
                    if rhs_seq is not None:
                        if env.seq_ids.get(tname) in env.mutable_seq_cids:
                            env.seqs[tname].extend(rhs_seq)
                        else:
                            env.bind_seq(tname, [*env.seqs[tname], *rhs_seq], mutable=False)
                        _sync_seq_const(env, tname)
                        return
                aug_vars = _eval_str_variants(
                    ast.BinOp(left=ast.Name(id=tname, ctx=ast.Load()), op=ast.Add(), right=sub.value), env
                )
                env.pop_name(tname)
                if len(aug_vars) == 1:
                    env.consts[tname], env.lines[tname] = aug_vars[0]
                    return
                if len(aug_vars) > 1:
                    env.alts[tname] = list(aug_vars)
                    return
            elif isinstance(sub.op, ast.Add) and isinstance(sub.target, ast.Subscript):
                aug_vars = _eval_str_variants(
                    ast.BinOp(
                        left=ast.Subscript(value=sub.target.value, slice=sub.target.slice, ctx=ast.Load()),
                        op=ast.Add(),
                        right=sub.value,
                    ),
                    env,
                )
                if _bind_subscript(sub.target, aug_vars, env) and aug_vars:
                    return
            elif isinstance(sub.target, ast.Name):
                env.pop_name(sub.target.id)
            walk_node(sub.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            return
        order = (*ctx, (getattr(sub, "lineno", 0), getattr(sub, "col_offset", 0)))
        if isinstance(sub, ast.Call):
            callee = _expr_name(sub.func)
            if callee == "create_table":
                for idx_k, key in enumerate(table_keys(sub, env)):
                    add_event((*order, (idx_k,)), "create", key, None, sub.lineno, column_names(sub, env))
                    if not suppress_ddl:
                        effects.fk_refs |= {(key, dst) for dst in fk_targets_in(sub, env) if dst != key}
                return
            if callee == "create_foreign_key" and len(sub.args) >= 3:
                srcs = [s for s, _ in _eval_str_variants(sub.args[1], env) if s]
                dsts = [d for d, _ in _eval_str_variants(sub.args[2], env) if d]
                kw = {
                    k.arg: next((v for v, _ in _eval_str_variants(k.value, env) if v), None)
                    for k in sub.keywords
                    if k.arg
                }
                for src in srcs:
                    for dst in dsts:
                        src_schema = (kw.get("source_schema") or "public").lower()
                        dst_schema = (kw.get("referent_schema") or "public").lower()
                        src_key = src.lower() if src_schema == "public" else f"{src_schema}.{src.lower()}"
                        dst_key = dst.lower() if dst_schema == "public" else f"{dst_schema}.{dst.lower()}"
                        if src_key != dst_key and not suppress_ddl:
                            effects.fk_refs.add((src_key, dst_key))
                return
            if callee == "drop_table":
                for idx_k, key in enumerate(table_keys(sub, env)):
                    add_event((*order, (idx_k,)), "drop", key, None, sub.lineno)
                return
            if callee == "rename_table":
                olds, news = table_keys(sub, env, 0), table_keys(sub, env, 1)
                if len(olds) == 1 and len(news) == 1:
                    add_event(order, "rename", olds[0], news[0], sub.lineno)
                return
            if callee == "create_all":
                if not suppress_ddl:
                    effects.creates_all_metadata = True
            elif callee in ("add_column", "drop_column", "alter_column"):
                if not suppress_ddl:
                    effects.touches_ddl = True
            else:
                handled_call, _c_fns, _c_tup = eval_call_fns(
                    sub, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
                )
                if handled_call:
                    return
            if isinstance(sub.func, ast.Attribute) and isinstance(sub.func.value, ast.Name):
                recv_name = sub.func.value.id
                if callee == "append" and recv_name in env.seqs and len(sub.args) == 1 and not sub.keywords:
                    app_vars = _eval_str_variants(sub.args[0], env)
                    if app_vars:
                        item = (
                            app_vars[0]
                            if len(app_vars) == 1
                            else ("\n".join(dict.fromkeys(v for v, _ in app_vars)), app_vars[0][1])
                        )
                        env.seqs[recv_name].append(item)
                    else:
                        walk_node(sub.args[0], ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                        env.seqs[recv_name].append((_UNRESOLVED, 0))
                    _sync_seq_const(env, recv_name)
                    return
                if callee == "insert" and recv_name in env.seqs and len(sub.args) == 2 and not sub.keywords:
                    ins_idx = _eval_int_index(sub.args[0])
                    if ins_idx is not None:
                        ins_vars = _eval_str_variants(sub.args[1], env)
                        if ins_vars:
                            ins_item = (
                                ins_vars[0]
                                if len(ins_vars) == 1
                                else ("\n".join(dict.fromkeys(v for v, _ in ins_vars)), ins_vars[0][1])
                            )
                        else:
                            walk_node(sub.args[1], ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                            ins_item = (_UNRESOLVED, 0)
                        env.seqs[recv_name].insert(ins_idx, ins_item)
                        _sync_seq_const(env, recv_name)
                        return
                if callee == "extend" and recv_name in env.seqs and len(sub.args) == 1 and not sub.keywords:
                    ext_items = _eval_seq_items(sub.args[0], env)
                    if ext_items is not None:
                        env.seqs[recv_name].extend(ext_items)
                    else:
                        walk_node(sub.args[0], ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                        env.seqs[recv_name].append((_UNRESOLVED, 0))
                    _sync_seq_const(env, recv_name)
                    return
                if callee == "clear" and not sub.args and not sub.keywords:
                    if recv_name in env.seqs:
                        env.seqs[recv_name].clear()
                        _sync_seq_const(env, recv_name)
                        return
                    if recv_name in env.dicts:
                        env.dicts[recv_name].clear()
                        return
                if callee == "pop" and not sub.keywords:
                    if recv_name in env.seqs and len(sub.args) <= 1:
                        pop_idx = -1 if not sub.args else _eval_int_index(sub.args[0])
                        if pop_idx is not None and -len(env.seqs[recv_name]) <= pop_idx < len(env.seqs[recv_name]):
                            env.seqs[recv_name].pop(pop_idx)
                            _sync_seq_const(env, recv_name)
                            return
                    if recv_name in env.dicts and 1 <= len(sub.args) <= 2:
                        pop_keys = _eval_str_variants(sub.args[0], env)
                        if pop_keys:
                            for k_str, _ in pop_keys:
                                env.dicts[recv_name].pop(k_str, None)
                            return
                if callee == "setdefault" and recv_name in env.dicts and len(sub.args) == 2 and not sub.keywords:
                    sd_keys = _eval_str_variants(sub.args[0], env)
                    if sd_keys:
                        sd_vals = _eval_str_variants(sub.args[1], env)
                        if not sd_vals:
                            walk_node(sub.args[1], ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                        for k_str, _ in sd_keys:
                            if k_str not in env.dicts[recv_name]:
                                env.dicts[recv_name][k_str] = (
                                    (
                                        sd_vals[0]
                                        if len(sd_vals) == 1
                                        else ("\n".join(dict.fromkeys(v for v, _ in sd_vals)), sd_vals[0][1])
                                    )
                                    if sd_vals
                                    else (_UNRESOLVED, 0)
                                )
                        return
                if callee == "update" and recv_name in env.dicts and len(sub.args) <= 1:
                    d_ref = env.dicts[recv_name]
                    if sub.args:
                        arg_d = _eval_dict_items(sub.args[0], env)
                        if arg_d is not None:
                            d_ref.update(arg_d)
                        else:
                            walk_node(sub.args[0], ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                    for kw in sub.keywords:
                        if kw.arg is not None:
                            kv = _eval_str_variants(kw.value, env)
                            if kv:
                                d_ref[kw.arg] = (
                                    kv[0]
                                    if len(kv) == 1
                                    else ("\n".join(dict.fromkeys(v for v, _ in kv)), kv[0][1])
                                )
                            else:
                                d_ref[kw.arg] = (_UNRESOLVED, 0)
                                walk_node(kw.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                        elif isinstance(kw.value, ast.Name) and kw.value.id in env.dicts:
                            d_ref.update(env.dicts[kw.value.id])
                        else:
                            walk_node(kw.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                    return
                if (
                    callee == "get"
                    and recv_name in env.dicts
                    and 1 <= len(sub.args) <= 2
                    and not sub.keywords
                    and not in_non_exec
                    and not suppress_ddl
                ):
                    get_vars = _eval_str_variants(sub, env)
                    if get_vars:
                        for idx_g, (g_sql, g_ln) in enumerate(get_vars):
                            cleaned_g = _blank_sql_comments(g_sql).upper()
                            if "TABLE" in cleaned_g or "FUNCTION" in cleaned_g:
                                if "ALTER TABLE" in cleaned_g:
                                    effects.touches_ddl = True
                                absorb_sql(g_sql, getattr(sub, "lineno", g_ln), (*order, (idx_g,)))
                        return
            next_exec = in_sql_exec or callee in sql_exec_calls
            next_non_exec = in_non_exec or (callee in non_exec_calls and not next_exec)
            walk_node(sub.func, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            for arg_expr in (*sub.args, *(kw.value for kw in sub.keywords)):
                walk_node(arg_expr, ctx, env, in_sql_exec=next_exec, in_non_exec=next_non_exec)
            return
        elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in env.seqs:
            if in_non_exec or suppress_ddl:
                return
            for idx_s, (sql_val, sql_ln) in enumerate(env.seqs[sub.id]):
                if _UNRESOLVED in sql_val:
                    continue
                key_pair = (sub.id, sql_val)
                if not in_sql_exec and key_pair in absorbed_consts:
                    continue
                absorbed_consts.add(key_pair)
                cleaned_u = _blank_sql_comments(sql_val).upper()
                if "ALTER TABLE" in cleaned_u:
                    effects.touches_ddl = True
                absorb_sql(sql_val, sql_ln, (*order, (idx_s,)))
            return
        elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in env.consts:
            sql_val = env.consts[sub.id]
            key_pair = (sub.id, sql_val)
            if in_non_exec or suppress_ddl or (not in_sql_exec and key_pair in absorbed_consts):
                return
            absorbed_consts.add(key_pair)
            cleaned_u = _blank_sql_comments(sql_val).upper()
            if "ALTER TABLE" in cleaned_u:
                effects.touches_ddl = True
            absorb_sql(sql_val, env.lines.get(sub.id, sub.lineno), order)
            return
        elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in env.alts:
            if in_non_exec or suppress_ddl:
                return
            for idx_a, (sql_val, sql_ln) in enumerate(env.alts[sub.id]):
                key_pair = (sub.id, sql_val)
                if not in_sql_exec and key_pair in absorbed_consts:
                    continue
                absorbed_consts.add(key_pair)
                cleaned_u = _blank_sql_comments(sql_val).upper()
                if "ALTER TABLE" in cleaned_u:
                    effects.touches_ddl = True
                absorb_sql(sql_val, sql_ln, (*order, (idx_a,)))
            return
        elif isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Subscript)):
            if in_non_exec or suppress_ddl:
                return
            variants = _eval_str_variants(sub, env)
            if variants:
                ref_pairs = {
                    (n.id, v_s)
                    for n in ast.walk(sub)
                    if isinstance(n, ast.Name)
                    for v_s in (
                        [env.consts[n.id]]
                        if n.id in env.consts
                        else [s for s, _ in env.alts.get(n.id, ())]
                    )
                }
                if not in_sql_exec and ref_pairs and ref_pairs.issubset(absorbed_consts):
                    return
                matched_any = False
                for idx_v, (text, v_ln) in enumerate(variants):
                    cleaned_u = _blank_sql_comments(text).upper()
                    if "TABLE" in cleaned_u or "FUNCTION" in cleaned_u:
                        matched_any = True
                        if "ALTER TABLE" in cleaned_u:
                            effects.touches_ddl = True
                        absorb_sql(text, getattr(sub, "lineno", v_ln), (*order, (idx_v,)))
                if matched_any:
                    absorbed_consts.update(ref_pairs)
                return
        for child in ast.iter_child_nodes(sub):
            walk_node(child, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)

    def invoke_helpers(
        targets: list[_MigrationHelper],
        sub: ast.Call,
        ctx: tuple,
        order: tuple,
        env: _MigrationEnv,
        *,
        in_sql_exec: bool,
        in_non_exec: bool,
    ) -> tuple[list[_MigrationHelper], list[list[_MigrationHelper]] | None]:
        flat_pos: list[tuple[ast.expr | None, list[tuple[str, int]]]] = []
        unknown_star = False
        for a in sub.args:
            if isinstance(a, ast.Starred):
                if isinstance(a.value, (ast.Tuple, ast.List)):
                    for elt in a.value.elts:
                        flat_pos.append((elt, _eval_str_variants(elt, env)))
                elif isinstance(a.value, ast.Name) and a.value.id in env.seqs:
                    for s_val, s_ln in env.seqs[a.value.id]:
                        flat_pos.append((None, [] if _UNRESOLVED in s_val else [(s_val, s_ln)]))
                else:
                    unknown_star = True
                    walk_node(a.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                    break
            else:
                flat_pos.append((a, _eval_str_variants(a, env)))
        pos_arg_fns: dict[int, list[_MigrationHelper]] = {}
        for idx_p, (arg_expr, variants) in enumerate(flat_pos):
            if arg_expr is None:
                continue
            if isinstance(arg_expr, ast.Call):
                ah, afns, _atup = eval_call_fns(
                    arg_expr, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
                )
                if ah:
                    if afns:
                        pos_arg_fns[idx_p] = afns
                    continue
            else:
                afns = _eval_callable_expr(arg_expr, env)
                if afns:
                    pos_arg_fns[idx_p] = afns
                    continue
            if variants:
                continue
            if isinstance(arg_expr, (ast.Tuple, ast.List)):
                for elt in arg_expr.elts:
                    if not _eval_str_variants(elt, env):
                        walk_node(elt, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            elif isinstance(arg_expr, ast.Dict):
                for dv in arg_expr.values:
                    if not _eval_str_variants(dv, env):
                        walk_node(dv, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            elif _eval_seq_items(arg_expr, env) is None and _eval_dict_items(arg_expr, env) is None:
                walk_node(arg_expr, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
        kw_items: list[tuple[str, ast.expr | None, list[tuple[str, int]]]] = []
        unknown_kwstar = False
        for kw in sub.keywords:
            if kw.arg is not None:
                kw_items.append((kw.arg, kw.value, _eval_str_variants(kw.value, env)))
            elif isinstance(kw.value, ast.Dict):
                for dk, dv in zip(kw.value.keys, kw.value.values, strict=False):
                    if dk is None and isinstance(dv, ast.Name) and dv.id in env.dicts:
                        for dk_s, (dv_s, ln_d) in env.dicts[dv.id].items():
                            kw_items.append((dk_s, None, [] if _UNRESOLVED in dv_s else [(dv_s, ln_d)]))
                    elif isinstance(dk, ast.Constant) and isinstance(dk.value, str):
                        kw_items.append((dk.value, dv, _eval_str_variants(dv, env)))
                    else:
                        unknown_kwstar = True
            elif isinstance(kw.value, ast.Name) and kw.value.id in env.dicts:
                for dk_s, (dv_s, ln_d) in env.dicts[kw.value.id].items():
                    kw_items.append((dk_s, None, [] if _UNRESOLVED in dv_s else [(dv_s, ln_d)]))
            else:
                unknown_kwstar = True
                walk_node(kw.value, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
        kw_arg_fns: dict[int, list[_MigrationHelper]] = {}
        for idx_kw, (_kname, kw_expr, variants) in enumerate(kw_items):
            if kw_expr is None:
                continue
            if isinstance(kw_expr, ast.Call):
                kh, kfns, _ktup = eval_call_fns(
                    kw_expr, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
                )
                if kh:
                    if kfns:
                        kw_arg_fns[idx_kw] = kfns
                    continue
            else:
                kfns = _eval_callable_expr(kw_expr, env)
                if kfns:
                    kw_arg_fns[idx_kw] = kfns
                    continue
            if variants:
                continue
            if isinstance(kw_expr, (ast.Tuple, ast.List)):
                for elt in kw_expr.elts:
                    if not _eval_str_variants(elt, env):
                        walk_node(elt, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            elif isinstance(kw_expr, ast.Dict):
                for dv in kw_expr.values:
                    if not _eval_str_variants(dv, env):
                        walk_node(dv, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            elif _eval_seq_items(kw_expr, env) is None and _eval_dict_items(kw_expr, env) is None:
                walk_node(kw_expr, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
        post_call_envs: list[_MigrationEnv] = []
        multi_targets = len(targets) > 1
        all_ret_fns: list[_MigrationHelper] = []
        all_ret_tups: list[list[list[_MigrationHelper]]] = []
        for helper in targets:
            call_env = env.clone() if multi_targets else env
            call_consts: dict[str, str] = {}
            call_lines: dict[str, int] = {}
            call_alts: dict[str, list[tuple[str, int]]] = {}
            call_seqs: dict[str, list[tuple[str, int]]] = {}
            call_seq_ids: dict[str, int] = {}
            call_seq_mut: dict[str, bool] = {}
            call_dicts: dict[str, dict[str, tuple[str, int]]] = {}
            call_dict_ids: dict[str, int] = {}
            call_fns: dict[str, list[_MigrationHelper]] = {}
            supplied_params: set[str] = set()
            pos_params = [*helper.fn.args.posonlyargs, *helper.fn.args.args]
            named_params = {p.arg for p in (*pos_params, *helper.fn.args.kwonlyargs)}
            for idx_p, (p_node, (arg_expr, variants)) in enumerate(zip(pos_params, flat_pos, strict=False)):
                supplied_params.add(p_node.arg)
                if idx_p in pos_arg_fns:
                    call_fns[p_node.arg] = list(pos_arg_fns[idx_p])
                if arg_expr is not None:
                    seq_arg = _eval_seq_items(arg_expr, call_env)
                    if seq_arg is not None:
                        call_seqs[p_node.arg] = seq_arg
                        if isinstance(arg_expr, ast.Name) and arg_expr.id in call_env.seq_ids:
                            scid = call_env.seq_ids[arg_expr.id]
                            call_seq_ids[p_node.arg] = scid
                            call_seq_mut[p_node.arg] = scid in call_env.mutable_seq_cids
                        else:
                            call_seq_mut[p_node.arg] = _is_mutable_seq_expr(arg_expr, call_env)
                    dict_arg = _eval_dict_items(arg_expr, call_env)
                    if dict_arg is not None:
                        call_dicts[p_node.arg] = dict_arg
                        if isinstance(arg_expr, ast.Name) and arg_expr.id in call_env.dict_ids:
                            call_dict_ids[p_node.arg] = call_env.dict_ids[arg_expr.id]
                if len(variants) == 1 and not isinstance(arg_expr, ast.Dict):
                    call_consts[p_node.arg], call_lines[p_node.arg] = variants[0]
                elif len(variants) > 1 and not isinstance(arg_expr, ast.Dict):
                    call_alts[p_node.arg] = list(variants)
            if helper.fn.args.vararg is not None:
                vname = helper.fn.args.vararg.arg
                var_slice = flat_pos[len(pos_params) :]
                var_known = [pair for _expr, variants in var_slice for pair in variants]
                if var_known or (not var_slice and not unknown_star):
                    call_seqs[vname] = var_known
                    call_seq_mut[vname] = False
            if unknown_star:
                for p_node in pos_params[len(flat_pos) :]:
                    supplied_params.add(p_node.arg)
            extra_kw_map: dict[str, tuple[str, int]] = {}
            unresolved_extra_kw = False
            for idx_kw, (kname, kw_expr, variants) in enumerate(kw_items):
                if kname in named_params:
                    supplied_params.add(kname)
                    if idx_kw in kw_arg_fns:
                        call_fns[kname] = list(kw_arg_fns[idx_kw])
                    if kw_expr is not None:
                        seq_kw = _eval_seq_items(kw_expr, call_env)
                        if seq_kw is not None:
                            call_seqs[kname] = seq_kw
                            if isinstance(kw_expr, ast.Name) and kw_expr.id in call_env.seq_ids:
                                scid = call_env.seq_ids[kw_expr.id]
                                call_seq_ids[kname] = scid
                                call_seq_mut[kname] = scid in call_env.mutable_seq_cids
                            else:
                                call_seq_mut[kname] = _is_mutable_seq_expr(kw_expr, call_env)
                        dict_kw = _eval_dict_items(kw_expr, call_env)
                        if dict_kw is not None:
                            call_dicts[kname] = dict_kw
                            if isinstance(kw_expr, ast.Name) and kw_expr.id in call_env.dict_ids:
                                call_dict_ids[kname] = call_env.dict_ids[kw_expr.id]
                    if len(variants) == 1 and not isinstance(kw_expr, ast.Dict):
                        call_consts[kname], call_lines[kname] = variants[0]
                    elif len(variants) > 1 and not isinstance(kw_expr, ast.Dict):
                        call_alts[kname] = list(variants)
                elif helper.fn.args.kwarg is not None:
                    if len(variants) == 1:
                        extra_kw_map[kname] = variants[0]
                    else:
                        unresolved_extra_kw = True
            if unknown_kwstar:
                for kw_p in helper.fn.args.kwonlyargs:
                    supplied_params.add(kw_p.arg)
            if helper.fn.args.kwarg is not None and (
                extra_kw_map or (not unresolved_extra_kw and not unknown_kwstar)
            ):
                call_dicts[helper.fn.args.kwarg.arg] = extra_kw_map
            h_ret_fns, h_ret_tup = visit(
                helper,
                order,
                call_consts,
                call_lines,
                call_alts,
                call_seqs,
                call_dicts,
                supplied_params,
                bound_seq_ids=call_seq_ids,
                bound_seq_mut=call_seq_mut,
                bound_dict_ids=call_dict_ids,
                bound_arg_fns=call_fns,
                caller_env=call_env,
            )
            all_ret_fns.extend(h_ret_fns)
            if h_ret_tup is not None:
                all_ret_tups.append(h_ret_tup)
            if multi_targets:
                post_call_envs.append(call_env)
        if multi_targets and post_call_envs:
            _merge_migration_envs(env, post_call_envs)
        merged_tup: list[list[_MigrationHelper]] | None = None
        if all_ret_tups and len({len(t) for t in all_ret_tups}) == 1:
            tlen = len(all_ret_tups[0])
            merged_tup = [
                _dedup_helpers([h for t in all_ret_tups for h in t[idx_t]]) for idx_t in range(tlen)
            ]
        return _dedup_helpers(all_ret_fns), merged_tup

    def eval_call_fns(
        call_node: ast.Call,
        ctx: tuple,
        env: _MigrationEnv,
        *,
        in_sql_exec: bool,
        in_non_exec: bool,
    ) -> tuple[bool, list[_MigrationHelper], list[list[_MigrationHelper]] | None]:
        call_order = (*ctx, (getattr(call_node, "lineno", 0), getattr(call_node, "col_offset", 0)))
        direct_targets = _eval_callable_expr(call_node.func, env)
        if direct_targets:
            if isinstance(call_node.func, ast.IfExp):
                walk_node(call_node.func.test, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
            r_fns, r_tup = invoke_helpers(
                direct_targets, call_node, ctx, call_order, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
            )
            return True, r_fns, r_tup
        if isinstance(call_node.func, ast.Call):
            inner_h, inner_fns, _inner_tup = eval_call_fns(
                call_node.func, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
            )
            if inner_h:
                if inner_fns:
                    r_fns, r_tup = invoke_helpers(
                        inner_fns, call_node, ctx, call_order, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec
                    )
                    return True, r_fns, r_tup
                for arg_e in (*call_node.args, *(kw.value for kw in call_node.keywords)):
                    walk_node(arg_e, ctx, env, in_sql_exec=in_sql_exec, in_non_exec=in_non_exec)
                return True, [], None
        return False, [], None

    def visit(
        helper: _MigrationHelper,
        ctx: tuple,
        bound_arg_consts: dict[str, str] | None = None,
        bound_arg_lines: dict[str, int] | None = None,
        bound_arg_alts: dict[str, list[tuple[str, int]]] | None = None,
        bound_arg_seqs: dict[str, list[tuple[str, int]]] | None = None,
        bound_arg_dicts: dict[str, dict[str, tuple[str, int]]] | None = None,
        supplied_params: set[str] | None = None,
        *,
        bound_seq_ids: dict[str, int] | None = None,
        bound_seq_mut: dict[str, bool] | None = None,
        bound_dict_ids: dict[str, int] | None = None,
        bound_arg_fns: dict[str, list[_MigrationHelper]] | None = None,
        caller_env: _MigrationEnv | None = None,
    ) -> tuple[list[_MigrationHelper], list[list[_MigrationHelper]] | None]:
        nonlocal next_scope_seq
        fn = helper.fn
        if id(fn) in active_fns:
            return [], None
        active_fns.add(id(fn))
        nonlocals, globals_ = _shallow_scope_decls(fn)
        fn_locals = _local_assigned_names(fn, nonlocals, globals_)
        enclosing = active_scope_envs.get(helper.scope_id, helper.captured)
        fn_scope_id = next_scope_seq
        next_scope_seq += 1
        frame = enclosing.clone(scope_id=fn_scope_id)
        frame.local_defs = fn_locals
        frame.globals_set = set(globals_)
        frame.dirty_globals = set()
        if caller_env is not None:
            for scid, s_items in caller_env.seq_heap.items():
                frame.seq_heap[scid] = list(s_items)
                frame.sync_seq_cid(scid)
            for dcid, d_items in caller_env.dict_heap.items():
                frame.dict_heap[dcid] = dict(d_items)
                frame.sync_dict_cid(dcid)
            for gl_name in caller_env.dirty_globals | caller_env.globals_set:
                is_enclosing_cell = (
                    helper.scope_id != 0 and gl_name in enclosing.local_defs and gl_name not in globals_
                )
                if is_enclosing_cell or (gl_name in fn_locals and gl_name not in globals_):
                    continue
                src_gl = (
                    module_env
                    if (gl_name in caller_env.local_defs and gl_name not in caller_env.globals_set)
                    else caller_env
                )
                _copy_env_binding(frame, src_gl, gl_name)
                frame.dirty_globals.add(gl_name)
        for p in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs, fn.args.vararg, fn.args.kwarg):
            if p is not None:
                frame.pop_name(p.arg)
        supplied = supplied_params or set()
        for pname, dfns in helper.default_fns.items():
            if pname not in supplied:
                frame.fns[pname] = list(dfns)
        for pname, dval in helper.default_consts.items():
            if pname not in supplied:
                frame.consts[pname] = dval
                if pname in helper.default_lines:
                    frame.lines[pname] = helper.default_lines[pname]
        for pname, dalts in helper.default_alts.items():
            if pname not in supplied:
                frame.alts[pname] = list(dalts)
        for pname, dseq in helper.default_seqs.items():
            if pname not in supplied:
                d_scid = helper.default_seq_ids.get(pname)
                d_mut = d_scid in frame.mutable_seq_cids if d_scid is not None else True
                assigned_scid = frame.bind_seq(pname, dseq, cid=d_scid, mutable=d_mut)
                frame.sync_seq_cid(assigned_scid)
        for pname, ddict in helper.default_dicts.items():
            if pname not in supplied:
                d_dcid = helper.default_dict_ids.get(pname)
                assigned_dcid = frame.bind_dict(pname, ddict, cid=d_dcid)
                frame.sync_dict_cid(assigned_dcid)
        if bound_arg_fns:
            for pname, bfns in bound_arg_fns.items():
                frame.fns[pname] = list(bfns)
        if bound_arg_consts:
            frame.consts.update(bound_arg_consts)
        if bound_arg_lines:
            frame.lines.update(bound_arg_lines)
        if bound_arg_alts:
            frame.alts.update(bound_arg_alts)
        if bound_arg_seqs:
            for pname, bseq in bound_arg_seqs.items():
                b_scid = (bound_seq_ids or {}).get(pname)
                b_mut = (bound_seq_mut or {}).get(
                    pname, b_scid in frame.mutable_seq_cids if b_scid is not None else True
                )
                assigned_scid = frame.bind_seq(pname, bseq, cid=b_scid, mutable=b_mut)
                frame.sync_seq_cid(assigned_scid)
        if bound_arg_dicts:
            for pname, bdict in bound_arg_dicts.items():
                b_dcid = (bound_dict_ids or {}).get(pname)
                assigned_dcid = frame.bind_dict(pname, bdict, cid=b_dcid)
                frame.sync_dict_cid(assigned_dcid)
        body_stmts = (
            fn.body[1:]
            if fn.body
            and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)
            and isinstance(fn.body[0].value.value, str)
            else fn.body
        )
        ret_fns: list[_MigrationHelper] = []
        ret_tups: list[list[list[_MigrationHelper]]] = []
        active_scope_envs[fn_scope_id] = frame
        return_collectors.append((fn_scope_id, ret_fns, ret_tups))
        try:
            for stmt in body_stmts:
                walk_node(stmt, ctx, frame)
            for nl_name in nonlocals:
                _copy_env_binding(enclosing, frame, nl_name)
            for gl_name in globals_:
                _copy_env_binding(module_env, frame, gl_name)
                frame.dirty_globals.add(gl_name)
            if caller_env is not None:
                for scid, s_items in frame.seq_heap.items():
                    caller_env.seq_heap[scid] = list(s_items)
                    caller_env.sync_seq_cid(scid)
                for dcid, d_items in frame.dict_heap.items():
                    caller_env.dict_heap[dcid] = dict(d_items)
                    caller_env.sync_dict_cid(dcid)
                for gl_name in frame.dirty_globals:
                    caller_env.dirty_globals.add(gl_name)
                    if gl_name not in caller_env.local_defs or gl_name in caller_env.globals_set:
                        src_gl = (
                            module_env
                            if (gl_name in frame.local_defs and gl_name not in frame.globals_set)
                            else frame
                        )
                        _copy_env_binding(caller_env, src_gl, gl_name)
        finally:
            return_collectors.pop()
            active_scope_envs.pop(fn_scope_id, None)
            active_fns.discard(id(fn))
        merged_ret_tup: list[list[_MigrationHelper]] | None = None
        if ret_tups and len({len(t) for t in ret_tups}) == 1:
            rlen = len(ret_tups[0])
            merged_ret_tup = [_dedup_helpers([h for t in ret_tups for h in t[i]]) for i in range(rlen)]
        return _dedup_helpers(ret_fns), merged_ret_tup

    suppress_ddl = True
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            def_snap = module_env.clone()
            d_consts, d_lines, d_alts, d_seqs, d_dicts, d_seq_ids, d_dict_ids = _extract_fn_defaults(stmt, def_snap)
            d_fns = _extract_fn_default_callables(stmt, def_snap)
            for scid, s_items in def_snap.seq_heap.items():
                module_env.seq_heap.setdefault(scid, list(s_items))
            for dcid, d_items in def_snap.dict_heap.items():
                module_env.dict_heap.setdefault(dcid, dict(d_items))
            module_env.pop_name(stmt.name)
            module_env.fns[stmt.name] = [
                _MigrationHelper(
                    fn=stmt,
                    scope_id=0,
                    captured=module_env,
                    default_consts=d_consts,
                    default_lines=d_lines,
                    default_alts=d_alts,
                    default_seqs=d_seqs,
                    default_dicts=d_dicts,
                    default_seq_ids=d_seq_ids,
                    default_dict_ids=d_dict_ids,
                    default_fns=d_fns,
                )
            ]
            continue
        if isinstance(stmt, ast.ClassDef):
            module_env.pop_name(stmt.name)
            continue
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
            if isinstance(stmt.target, ast.Name):
                mt_name = stmt.target.id
                if mt_name in module_env.seqs:
                    m_rhs = _eval_seq_items(stmt.value, module_env)
                    if m_rhs is not None:
                        if module_env.seq_ids.get(mt_name) in module_env.mutable_seq_cids:
                            module_env.seqs[mt_name].extend(m_rhs)
                        else:
                            module_env.bind_seq(mt_name, [*module_env.seqs[mt_name], *m_rhs], mutable=False)
                        _sync_seq_const(module_env, mt_name)
                else:
                    m_aug = _eval_str_variants(
                        ast.BinOp(left=ast.Name(id=mt_name, ctx=ast.Load()), op=ast.Add(), right=stmt.value),
                        module_env,
                    )
                    module_env.pop_name(mt_name)
                    if len(m_aug) == 1:
                        module_env.consts[mt_name], module_env.lines[mt_name] = m_aug[0]
                    elif len(m_aug) > 1:
                        module_env.alts[mt_name] = list(m_aug)
            elif isinstance(stmt.target, ast.Subscript):
                m_aug = _eval_str_variants(
                    ast.BinOp(
                        left=ast.Subscript(value=stmt.target.value, slice=stmt.target.slice, ctx=ast.Load()),
                        op=ast.Add(),
                        right=stmt.value,
                    ),
                    module_env,
                )
                _bind_subscript(stmt.target, m_aug, module_env)
            continue
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)
            and isinstance(stmt.value.func.value, ast.Name)
        ):
            m_call = stmt.value
            m_recv = stmt.value.func.value.id
            m_attr = stmt.value.func.attr
            if m_attr == "append" and m_recv in module_env.seqs and len(m_call.args) == 1 and not m_call.keywords:
                m_vars = _eval_str_variants(m_call.args[0], module_env)
                module_env.seqs[m_recv].append(
                    (
                        m_vars[0]
                        if len(m_vars) == 1
                        else ("\n".join(dict.fromkeys(v for v, _ in m_vars)), m_vars[0][1])
                    )
                    if m_vars
                    else (_UNRESOLVED, 0)
                )
                _sync_seq_const(module_env, m_recv)
            elif m_attr == "extend" and m_recv in module_env.seqs and len(m_call.args) == 1 and not m_call.keywords:
                m_ext = _eval_seq_items(m_call.args[0], module_env)
                if m_ext is not None:
                    module_env.seqs[m_recv].extend(m_ext)
                    _sync_seq_const(module_env, m_recv)
            elif m_attr == "update" and m_recv in module_env.dicts and len(m_call.args) <= 1:
                if m_call.args:
                    m_d = _eval_dict_items(m_call.args[0], module_env)
                    if m_d is not None:
                        module_env.dicts[m_recv].update(m_d)
                for kw in m_call.keywords:
                    if kw.arg is not None:
                        kv = _eval_str_variants(kw.value, module_env)
                        if kv:
                            module_env.dicts[m_recv][kw.arg] = (
                                kv[0] if len(kv) == 1 else ("\n".join(dict.fromkeys(v for v, _ in kv)), kv[0][1])
                            )
                        else:
                            module_env.dicts[m_recv].pop(kw.arg, None)
                    elif isinstance(kw.value, ast.Name) and kw.value.id in module_env.dicts:
                        module_env.dicts[m_recv].update(module_env.dicts[kw.value.id])
            continue
        assign_targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            assign_targets = list(stmt.targets)
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            assign_targets = [stmt.target]
            value = stmt.value
        if not assign_targets or value is None:
            continue
        top_names = [t.id for t in assign_targets if isinstance(t, ast.Name)]
        if "revision" in top_names and isinstance(value, ast.Constant) and isinstance(value.value, str):
            effects.revision = value.value
        if "down_revision" in top_names:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                effects.down_revisions = (value.value,)
            elif isinstance(value, (ast.Tuple, ast.List)):
                effects.down_revisions = tuple(
                    e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                )
        snap = snapshot_rhs(value, module_env, (), in_sql_exec=False, in_non_exec=True)
        for tgt in assign_targets:
            for bound in ast.walk(tgt):
                if isinstance(bound, ast.Name) and isinstance(bound.ctx, ast.Store):
                    module_env.pop_name(bound.id)
            bind_target(tgt, snap, module_env)
    suppress_ddl = False

    upgrade_helpers = module_env.fns.get("upgrade")
    if not upgrade_helpers:
        return effects

    visit(upgrade_helpers[0], (), caller_env=module_env)
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
