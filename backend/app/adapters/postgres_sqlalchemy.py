"""Tier 1 Adapter: PostgreSQL + SQLAlchemy + Alembic + schema.sql (+ optional pg_catalog)."""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass, field
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


def _clean_sql_name(raw: str | None) -> str:
    return (raw or "").replace('"', "").lower()


def _parse_sql_objects(sql_text: str) -> tuple[set[str], dict[str, int]]:
    """Extract table names and function names -> approx line numbers from SQL text."""
    tables: set[str] = set()
    functions: dict[str, int] = {}
    for match in _CREATE_TABLE_RE.finditer(sql_text):
        schema = _clean_sql_name(match.group("schema")) or "public"
        table = _clean_sql_name(match.group("table"))
        tables.add(table if schema == "public" else f"{schema}.{table}")
    for match in _CREATE_FUNC_RE.finditer(sql_text):
        schema = _clean_sql_name(match.group("schema")) or "public"
        func = _clean_sql_name(match.group("func"))
        key = func if schema == "public" else f"{schema}.{func}"
        line = sql_text.count("\n", 0, match.start()) + 1
        functions[key] = line
    return tables, functions


def _parse_dropped_tables(sql_text: str) -> set[str]:
    dropped: set[str] = set()
    for match in _DROP_TABLE_RE.finditer(sql_text):
        for raw_name in match.group("names").split(","):
            nm = _TABLE_NAME_RE.match(raw_name)
            if nm:
                schema = _clean_sql_name(nm.group("schema")) or "public"
                table = _clean_sql_name(nm.group("table"))
                dropped.add(table if schema == "public" else f"{schema}.{table}")
    return dropped


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


def _sql_table_events(sql_text: str) -> list[tuple[int, str, str, str | None, int]]:
    """CREATE / DROP / RENAME TO table statements in `sql_text`, in text order.

    Each event is (offset, kind, table, new_table, line_offset) where kind is
    "create", "drop" or "rename" and new_table is set only for a rename.
    """
    events: list[tuple[int, str, str, str | None, int]] = []
    for match in _CREATE_TABLE_RE.finditer(sql_text):
        key = _table_key(_clean_sql_name(match.group("schema")), _clean_sql_name(match.group("table")))
        events.append((match.start(), "create", key, None, sql_text.count("\n", 0, match.start())))
    for match in _DROP_TABLE_RE.finditer(sql_text):
        for raw_name in match.group("names").split(","):
            nm = _TABLE_NAME_RE.match(raw_name)
            if nm:
                key = _table_key(_clean_sql_name(nm.group("schema")), _clean_sql_name(nm.group("table")))
                events.append((match.start(), "drop", key, None, sql_text.count("\n", 0, match.start())))
    for match in _RENAME_TABLE_RE.finditer(sql_text):
        schema = _clean_sql_name(match.group("schema"))
        old = _table_key(schema, _clean_sql_name(match.group("old")))
        new = _table_key(schema, _clean_sql_name(match.group("new")))  # a rename keeps the schema
        events.append((match.start(), "rename", old, new, sql_text.count("\n", 0, match.start())))
    events.sort(key=lambda e: e[0])
    return events


@dataclass
class _MigrationEffects:
    revision: str | None = None
    down_revisions: tuple[str, ...] = ()
    # Ordered table effects: (order key, kind, table, new_table, line). The order key follows
    # the source position inside upgrade() and, for helpers, the call site that ran them, so a
    # create-then-rename and a rename-then-create replay the way the revision runs them.
    table_events: list[tuple[tuple, str, str, str | None, int]] = field(default_factory=list)
    created_columns: dict[str, list[str]] = field(default_factory=dict)
    created_functions: dict[str, int] = field(default_factory=dict)
    dropped_functions: set[str] = field(default_factory=set)
    creates_all_metadata: bool = False
    touches_ddl: bool = False


def _collect_migration_effects(tree: ast.Module) -> _MigrationEffects:
    """Tables/functions an Alembic revision's `upgrade()` creates or drops.

    Follows module-level string constants (including f-strings built from other constants)
    and module-level helper functions that `upgrade()` calls, so DDL kept outside the
    function body is still seen.
    """
    effects = _MigrationEffects()
    consts: dict[str, str] = {}
    const_lines: dict[str, int] = {}
    functions: dict[str, ast.FunctionDef] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef):
            functions[stmt.name] = stmt
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

    upgrade = functions.get("upgrade")
    if upgrade is None:
        return effects

    def add_event(order: tuple, kind: str, table: str, new_table: str | None, lineno: int) -> None:
        effects.table_events.append((order, kind, table, new_table, lineno))

    def absorb_sql(sql_text: str, lineno: int, order: tuple) -> None:
        _, funcs = _parse_sql_objects(sql_text)
        for offset, kind, table, new_table, line_offset in _sql_table_events(sql_text):
            add_event((*order, (offset,)), kind, table, new_table, lineno + line_offset)
        for fn_name in funcs:
            effects.created_functions[fn_name] = lineno
        for drop_match in _DROP_FUNC_RE.finditer(sql_text):
            schema = _clean_sql_name(drop_match.group("schema")) or "public"
            fn = _clean_sql_name(drop_match.group("func"))
            effects.dropped_functions.add(fn if schema == "public" else f"{schema}.{fn}")

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

    visited_fns: set[str] = set()
    absorbed_consts: set[str] = set()

    def visit(fn: ast.FunctionDef, ctx: tuple) -> None:
        if fn.name in visited_fns:
            return
        visited_fns.add(fn.name)
        for sub in ast.walk(fn):
            order = (*ctx, (getattr(sub, "lineno", 0), getattr(sub, "col_offset", 0)))
            if isinstance(sub, ast.Call):
                callee = _expr_name(sub.func)
                if callee == "create_table":
                    key = table_key(sub)
                    if key:
                        add_event(order, "create", key, None, sub.lineno)
                        effects.created_columns[key] = column_names(sub)
                elif callee == "drop_table":
                    key = table_key(sub)
                    if key:
                        add_event(order, "drop", key, None, sub.lineno)
                elif callee == "rename_table":
                    old, new = table_key(sub, 0), table_key(sub, 1)
                    if old and new:
                        add_event(order, "rename", old, new, sub.lineno)
                elif callee == "create_all":
                    effects.creates_all_metadata = True
                elif callee in ("add_column", "drop_column", "alter_column"):
                    effects.touches_ddl = True
                elif isinstance(sub.func, ast.Name) and sub.func.id in functions:
                    visit(functions[sub.func.id], order)
            elif isinstance(sub, ast.Name) and sub.id in consts and sub.id not in absorbed_consts:
                absorbed_consts.add(sub.id)
                if "ALTER TABLE" in consts[sub.id].upper():
                    effects.touches_ddl = True
                absorb_sql(consts[sub.id], const_lines.get(sub.id, sub.lineno), order)
            elif isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                text = _eval_str(sub, consts)
                if text and ("TABLE" in text.upper() or "FUNCTION" in text.upper()):
                    if "ALTER TABLE" in text.upper():
                        effects.touches_ddl = True
                    absorb_sql(text, getattr(sub, "lineno", 1), order)

    visit(upgrade, ())
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
        roots: set[str] = set()
        if models_dir.is_dir():
            for py_file in sorted(models_dir.rglob("*.py")):
                if "__pycache__" in py_file.parts:
                    continue
                rel_path = py_file.relative_to(repo_root).as_posix()
                scan = _scan_model_module(py_file, rel_path)
                class_bases.update(scan.class_bases)
                roots |= scan.roots
                for cls_name, tbl_name, lineno, cols, summary, bases in scan.models:
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
        # Where each DDL-only table is defined, so its node points at the CREATE TABLE.
        table_origin: dict[str, tuple[str, int, list[str]]] = {}
        if schema_sql_path.is_file():
            rel_schema = schema_sql_path.relative_to(repo_root).as_posix()
            text = schema_sql_path.read_text(encoding="utf-8", errors="replace")
            parsed_tables, parsed_funcs = _parse_sql_objects(text)
            sql_tables |= parsed_tables
            for fn_name, fn_line in parsed_funcs.items():
                sql_functions[fn_name] = (rel_schema, fn_line)
            ddl_detail, _ = parse_sql_ddl_objects(text)
            for offset, kind, tbl, _new, line_offset in _sql_table_events(text):
                if kind == "create" and tbl in parsed_tables and tbl not in table_origin:
                    cols = ddl_detail.get(tbl, (0, []))[1]
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
            for _order, kind, tbl, new_tbl, line in sorted(effects.table_events, key=lambda e: e[0]):
                if kind == "create":
                    migrated_tables.add(tbl)
                    mig_origin[tbl] = (rel_mig, line, effects.created_columns.get(tbl, []))
                elif kind == "drop":
                    migrated_tables.discard(tbl)
                elif new_tbl:
                    migrated_tables.discard(tbl)
                    migrated_tables.add(new_tbl)
                    prior = mig_origin.get(tbl)
                    mig_origin[new_tbl] = (rel_mig, line, prior[2] if prior else [])
            metadata_create_all |= effects.creates_all_metadata
            for fn_name, fn_line in effects.created_functions.items():
                sql_functions[fn_name] = (rel_mig, fn_line)
            for fn_name in effects.dropped_functions - set(effects.created_functions):
                sql_functions.pop(fn_name, None)
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
        )
