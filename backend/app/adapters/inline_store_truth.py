"""Inline SQLite, PostgreSQL, and append-only JSONL Truth store discovery and disambiguation."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

from app.adapters.db_catalog_probe import (
    clean_sql_ident,
    infer_table_role,
    is_migration_meta_table,
)
from app.adapters.python_policy_consumption import classify_table_policy_columns
from app.adapters.service_sources import source_files
from app.schemas.atlas import AtlasNode

StoreEngine = Literal["sqlite", "postgres", "jsonl"]

_IDENT = r'(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)'
_CREATE_HEAD_RE = re.compile(
    rf"(?:^|;)\s*(?:(?:--[^\n]*\n|/\*[\s\S]*?\*/)\s*)*CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?P<schema>{_IDENT})\.)?(?P<table>{_IDENT})\s*\(",
    re.IGNORECASE,
)
_COL_SKIP_HEADS = frozenset(
    {"constraint", "primary", "foreign", "unique", "check", "index", "key", "exclude"}
)
_PG_DDL_MARKERS_RE = re.compile(
    r"\b(?:TIMESTAMPTZ|JSONB|BIGSERIAL|SMALLSERIAL|SERIAL|BYTEA|UUID|INET|CIDR)\b",
    re.IGNORECASE,
)
_SQLITE_DDL_MARKERS_RE = re.compile(
    r"\b(?:AUTOINCREMENT|WITHOUT\s+ROWID|PRAGMA\s+journal_mode)\b",
    re.IGNORECASE,
)
_DB_FILE_RE = re.compile(r"(?P<name>[A-Za-z0-9_.-]+)\.(?:db|sqlite3?|db3)$", re.IGNORECASE)
_JSONL_FILE_RE = re.compile(r"(?P<name>[A-Za-z0-9_.-]+)\.jsonl$", re.IGNORECASE)


@dataclass(frozen=True)
class InlineStoreObject:
    engine: StoreEngine
    qualifier: str
    table_name: str
    source_file: str
    line: int
    columns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class InlineStoreScanResult:
    stores: list[InlineStoreObject]
    ambiguous_bare_names: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ModuleStoreIo:
    engine_hint: str | None = None
    sqlite_stems: tuple[str, ...] = ()
    sql_reads: dict[str, set[str]] = field(default_factory=dict)
    sql_writes: dict[str, set[str]] = field(default_factory=dict)
    sql_calls: dict[str, set[str]] = field(default_factory=dict)
    jsonl_reads: dict[str, set[str]] = field(default_factory=dict)
    jsonl_writes: dict[str, set[str]] = field(default_factory=dict)


def _sanitize_stem(raw: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_]+", "_", raw.strip().lower()).strip("_")
    return cleaned


def _docstring_and_tc_ids(tree: ast.AST) -> set[int]:
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                skip.add(id(node.body[0].value))
        elif isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            ):
                for sub in node.body:
                    skip.update(id(c) for c in ast.walk(sub))
    return skip


def _split_top_level_commas(body: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    quote: str | None = None
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def parse_inline_create_tables(sql_text: str) -> dict[tuple[str, str], tuple[int, list[str]]]:
    """Extract `{(schema, table): (line_offset, columns)}` with balanced-parenthesis scanning."""
    found: dict[tuple[str, str], tuple[int, list[str]]] = {}
    n = len(sql_text)
    for m in _CREATE_HEAD_RE.finditer(sql_text):
        raw_schema = clean_sql_ident(m.group("schema"))
        tbl = clean_sql_ident(m.group("table"))
        if not tbl or "__dyn__" in tbl or "__dyn__" in raw_schema or is_migration_meta_table(tbl):
            continue
        open_paren = m.end() - 1
        depth = 1
        i = open_paren + 1
        quote: str | None = None
        while i < n and depth > 0:
            ch = sql_text[i]
            if quote:
                if ch == quote:
                    quote = None
            elif ch == "-" and i + 1 < n and sql_text[i + 1] == "-":
                nl = sql_text.find("\n", i + 2)
                i = n if nl == -1 else nl + 1
                continue
            elif ch in ("'", '"', "`"):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth != 0:
            continue
        body = sql_text[open_paren + 1 : i - 1]
        if "?" in body:
            continue
        cols: list[str] = []
        for clause in _split_top_level_commas(body):
            cleaned_lines = [
                ln.split("--", 1)[0].strip()
                for ln in clause.splitlines()
                if ln.split("--", 1)[0].strip()
            ]
            if not cleaned_lines:
                continue
            first_tok = clean_sql_ident(cleaned_lines[0].split()[0])
            if (
                first_tok
                and first_tok not in _COL_SKIP_HEADS
                and "__dyn__" not in first_tok
                and re.match(r"^[a-z_]\w*$", first_tok)
                and first_tok not in cols
            ):
                cols.append(first_tok)
        if not cols:
            continue
        line_off = sql_text.count("\n", 0, m.start())
        key = (raw_schema, tbl)
        if key not in found or (cols and not found[key][1]):
            found[key] = (line_off, cols[:40])
    return found


def infer_sql_file_engine(rel_path: str, sql_text: str) -> str:
    low_path = rel_path.lower()
    if "sqlite" in low_path:
        return "sqlite"
    if any(p in low_path for p in ("postgres", "pgsql", "pg_")):
        return "postgres"
    if _SQLITE_DDL_MARKERS_RE.search(sql_text) and not _PG_DDL_MARKERS_RE.search(sql_text):
        return "sqlite"
    if _PG_DDL_MARKERS_RE.search(sql_text):
        return "postgres"
    return "sql"


def _eval_str_expr(node: ast.AST | None, str_env: dict[str, str], depth: int = 0) -> str | None:
    if node is None or depth > 6:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in str_env:
        return str_env[node.id]
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                resolved = _eval_str_expr(val.value, str_env, depth + 1)
                parts.append(resolved if resolved is not None else "__dyn__")
            else:
                parts.append("__dyn__")
        return "".join(parts)
    if isinstance(node, ast.BinOp):
        left = _eval_str_expr(node.left, str_env, depth + 1)
        right = _eval_str_expr(node.right, str_env, depth + 1)
        if isinstance(node.op, ast.Add) and left is not None and right is not None:
            return left + right
        if isinstance(node.op, ast.Div) and right is not None:
            prefix = left if left is not None else "__dyn__"
            return f"{prefix.rstrip('/')}/{right.lstrip('/')}"
    if isinstance(node, ast.Call):
        fn_name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else ""
        )
        if fn_name in {"Path", "PurePath", "PurePosixPath", "str", "expanduser"} and node.args:
            return _eval_str_expr(node.args[0], str_env, depth + 1)
        if fn_name == "join" and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                sep = node.func.value.value
                if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                    items = [_eval_str_expr(e, str_env, depth + 1) for e in node.args[0].elts]
                    if all(x is not None for x in items):
                        return sep.join(x for x in items if x is not None)
            else:
                segs = [_eval_str_expr(a, str_env, depth + 1) for a in node.args]
                if segs and segs[-1] is not None:
                    return "/".join(s if s is not None else "__dyn__" for s in segs)
    return None


def _collect_str_bindings(stmts: list[ast.stmt], base_env: dict[str, str]) -> dict[str, str]:
    env = dict(base_env)
    for stmt in stmts:
        tgt_name: str | None = None
        val_node: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            tgt_name, val_node = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            tgt_name, val_node = stmt.target.id, stmt.value
        if tgt_name and val_node is not None:
            val = _eval_str_expr(val_node, env)
            if val is not None:
                env[tgt_name] = val
    return env


def _db_stem_from_str(raw: str) -> str | None:
    leaf = raw.replace("\\", "/").rsplit("/", 1)[-1].split("?", 1)[0]
    if leaf == ":memory:":
        return "memory"
    m = _DB_FILE_RE.search(leaf)
    if not m or "__dyn__" in m.group("name"):
        return None
    return _sanitize_stem(m.group("name")) or None


def _jsonl_stem_from_str(raw: str) -> str | None:
    leaf = raw.replace("\\", "/").rsplit("/", 1)[-1]
    m = _JSONL_FILE_RE.search(leaf)
    if not m or "__dyn__" in m.group("name"):
        return None
    return _sanitize_stem(m.group("name")) or None


def _inspect_module_drivers(
    tree: ast.Module, mod_env: dict[str, str], skip_ids: set[int]
) -> tuple[bool, bool, list[str]]:
    has_sqlite = False
    has_pg = False
    stems: list[str] = []

    for val in mod_env.values():
        st = _db_stem_from_str(val)
        if st and st not in stems:
            stems.append(st)

    for node in ast.walk(tree):
        if id(node) in skip_ids:
            continue
        if isinstance(node, ast.Import):
            for al in node.names:
                root_m = al.name.split(".", 1)[0]
                if root_m in {"sqlite3", "aiosqlite"}:
                    has_sqlite = True
                elif root_m in {"psycopg", "psycopg2", "asyncpg"}:
                    has_pg = True
        elif isinstance(node, ast.ImportFrom) and node.module:
            root_m = node.module.split(".", 1)[0]
            if root_m in {"sqlite3", "aiosqlite"}:
                has_sqlite = True
            elif root_m in {"psycopg", "psycopg2", "asyncpg"}:
                has_pg = True
        elif isinstance(node, ast.Call):
            fn = node.func
            attr = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            recv = (
                fn.value.id
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                else ""
            )
            if recv in {"sqlite3", "aiosqlite"} and attr == "connect":
                has_sqlite = True
                if node.args:
                    arg_s = _eval_str_expr(node.args[0], mod_env)
                    st = _db_stem_from_str(arg_s) if arg_s else None
                    if st:
                        if st in stems:
                            stems.remove(st)
                        stems.insert(0, st)
            elif recv in {"psycopg", "psycopg2", "asyncpg"} and attr in {"connect", "create_pool"}:
                has_pg = True
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            st = _db_stem_from_str(node.value)
            if st and st not in stems:
                stems.append(st)
    return has_sqlite, has_pg, stems


def _scope_Sqlite_stem(
    stmts: list[ast.stmt], env: dict[str, str], default_stems: list[str], fallback_stem: str
) -> str:
    for node in (n for s in stmts for n in ast.walk(s)):
        if isinstance(node, ast.Call):
            fn = node.func
            attr = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            if attr == "connect" and node.args:
                arg_s = _eval_str_expr(node.args[0], env)
                st = _db_stem_from_str(arg_s) if arg_s else None
                if st:
                    return st
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            st = _db_stem_from_str(node.value)
            if st:
                return st
    return default_stems[0] if default_stems else fallback_stem


def scan_inline_stores(repo_root: Path, backend_subdir: str) -> list[InlineStoreObject]:
    """Scan Python modules for inline SQLite/Postgres `CREATE TABLE` DDL and `.jsonl` ledgers."""
    real_root = repo_root.resolve()
    scan_roots: list[Path] = []
    if backend_subdir not in ("", "."):
        raw_be = real_root / backend_subdir
        if not raw_be.is_symlink() and raw_be.resolve().is_relative_to(real_root) and raw_be.resolve().is_dir():
            scan_roots.append(raw_be.resolve())
    scan_roots.append(real_root)

    py_files: list[Path] = []
    for root in dict.fromkeys(scan_roots):
        if not root.is_dir():
            continue
        found, _ = source_files(root, {".py"})
        for pf in found:
            pf_real = pf.resolve()
            if pf_real.is_relative_to(real_root) and pf_real not in py_files:
                py_files.append(pf_real)

    stores: list[InlineStoreObject] = []
    for pf in py_files:
        rel = pf.relative_to(real_root).as_posix()
        try:
            text = pf.read_text(encoding="utf-8-sig")
            tree = ast.parse(text)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        skip_ids = _docstring_and_tc_ids(tree)
        mod_env = _collect_str_bindings(tree.body, {})
        has_sqlite, has_pg, mod_stems = _inspect_module_drivers(tree, mod_env, skip_ids)
        fallback_stem = _sanitize_stem(PurePosixPath(rel).stem) or "app"

        scopes: list[tuple[list[ast.stmt], dict[str, str]]] = [(tree.body, mod_env)]
        for node in ast.walk(tree):
            if id(node) in skip_ids:
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scopes.append((node.body, _collect_str_bindings(node.body, mod_env)))

        seen_ddl_nodes: set[int] = set()
        for body, env in scopes:
            local_stem = _scope_Sqlite_stem(body, env, mod_stems, fallback_stem)
            for stmt in body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or id(stmt) in skip_ids:
                    continue
                for sub in ast.walk(stmt):
                    if id(sub) in skip_ids or id(sub) in seen_ddl_nodes:
                        continue
                    if isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                        s_val = _eval_str_expr(sub, env)
                        if not s_val:
                            continue
                        if "create" in s_val.lower() and "table" in s_val.lower():
                            parsed_tbls = parse_inline_create_tables(s_val)
                            if parsed_tbls:
                                seen_ddl_nodes.add(id(sub))
                                base_line = getattr(sub, "lineno", 1)
                                for (raw_sch, tbl), (off, cols) in parsed_tbls.items():
                                    sqlite_only_driver = has_sqlite and not has_pg
                                    use_pg = (
                                        (has_pg and not has_sqlite)
                                        or (raw_sch and raw_sch not in {"main", "temp"})
                                        or (not sqlite_only_driver and bool(_PG_DDL_MARKERS_RE.search(s_val)))
                                    )
                                    if use_pg and not bool(_SQLITE_DDL_MARKERS_RE.search(s_val)):
                                        sch = raw_sch or "public"
                                        stores.append(
                                            InlineStoreObject(
                                                engine="postgres",
                                                qualifier=sch,
                                                table_name=tbl,
                                                source_file=rel,
                                                line=base_line + off,
                                                columns=cols,
                                            )
                                        )
                                    elif has_sqlite or has_pg or mod_stems or "create table" in s_val.lower():
                                        stores.append(
                                            InlineStoreObject(
                                                engine="sqlite",
                                                qualifier=local_stem,
                                                table_name=tbl,
                                                source_file=rel,
                                                line=base_line + off,
                                                columns=cols,
                                            )
                                        )
                        j_stem = _jsonl_stem_from_str(s_val)
                        if j_stem:
                            seen_ddl_nodes.add(id(sub))
                            stores.append(
                                InlineStoreObject(
                                    engine="jsonl",
                                    qualifier=j_stem,
                                    table_name=j_stem,
                                    source_file=rel,
                                    line=getattr(sub, "lineno", 1),
                                    columns=[],
                                )
                            )
    return stores


_SQL_TARGET_IDENT = r'(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)(?:\.(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*))?'
_SQL_SKIP_REFS = frozenset(
    {
        "select",
        "from",
        "where",
        "join",
        "inner",
        "left",
        "right",
        "outer",
        "cross",
        "lateral",
        "unnest",
        "dual",
        "sqlite_master",
        "sqlite_schema",
        "pg_catalog",
        "information_schema",
    }
)
_SQL_CTE_RE = re.compile(r"\b(?:WITH(?:\s+RECURSIVE)?|,)\s+([A-Za-z_]\w*)\s+AS\s*\(", re.IGNORECASE)
_SQL_HELPER_CALL_RE = re.compile(
    r"(?:exec|query|sql|psql|sqlite|fetch|select|insert|update|delete|cursor|scalar)",
    re.IGNORECASE,
)


def _clean_dml_ref(raw: str) -> str | None:
    if "__dyn__" in raw:
        return None
    if "." in raw:
        s_part, t_part = raw.split(".", 1)
        sc = clean_sql_ident(s_part)
        tc = clean_sql_ident(t_part)
        if not tc or tc in _SQL_SKIP_REFS or sc in {"pg_catalog", "information_schema"}:
            return None
        return tc if sc in {"public", "main", "dbo"} else f"{sc}.{tc}"
    tc = clean_sql_ident(raw)
    if not tc or tc in _SQL_SKIP_REFS:
        return None
    return tc


def _extract_sql_dml_refs(sql_text: str, *, in_sql_call: bool = False) -> tuple[set[str], set[str], set[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    calls: set[str] = set()
    no_comments = re.sub(r"/\*[\s\S]*?\*/", " ", sql_text)
    no_comments = re.sub(r"--[^\n]*", " ", no_comments)

    for raw_stmt in no_comments.split(";"):
        stmt = raw_stmt.strip().lstrip("(").strip()
        if not stmt:
            continue
        m_head = re.match(r"[A-Za-z]+", stmt)
        if m_head is None:
            continue
        word = m_head.group(0)
        w_low = word.lower()
        if w_low not in {"select", "insert", "replace", "update", "delete", "with"}:
            continue
        if word not in (word.upper(), word.lower()):
            continue
        if (
            word.islower()
            and not in_sql_call
            and w_low in {"select", "with"}
            and not re.search(r"\b(?:where|order\s+by|group\s+by|limit|join)\b|\*|\?|%s|\$\d", stmt)
        ):
            continue
        ctes = {c.lower() for c in _SQL_CTE_RE.findall(stmt)}
        flags = 0 if word.isupper() else re.IGNORECASE

        ins_pat = (
            r"\b(?:INSERT(?:\s+OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK))?\s+INTO|REPLACE\s+INTO)\s+(?P<t>"
            + _SQL_TARGET_IDENT
            + r")"
        )
        upd_pat = r"\bUPDATE(?:\s+OR\s+\w+)?\s+(?P<t>" + _SQL_TARGET_IDENT + r")\s+(?:AS\s+\w+\s+)?SET\b"
        del_pat = r"\bDELETE\s+FROM\s+(?P<t>" + _SQL_TARGET_IDENT + r")"
        rd_pat = r"\b(?:FROM|JOIN)\s+(?P<t>" + _SQL_TARGET_IDENT + r")"

        stmt_dels: set[str] = set()
        for pat in (ins_pat, upd_pat):
            for hit in re.finditer(pat, stmt, flags):
                ref = _clean_dml_ref(hit.group("t"))
                if ref and ref not in ctes:
                    writes.add(ref)
        for hit in re.finditer(del_pat, stmt, flags):
            ref = _clean_dml_ref(hit.group("t"))
            if ref and ref not in ctes:
                writes.add(ref)
                stmt_dels.add(ref)
        for hit in re.finditer(rd_pat, stmt, flags):
            ref = _clean_dml_ref(hit.group("t"))
            if ref and ref not in ctes and ref not in stmt_dels:
                reads.add(ref)
        for fn_hit in re.finditer(r"\b([A-Za-z_]\w*\.[A-Za-z_]\w*)\s*\(", stmt):
            fn_ref = fn_hit.group(1).lower()
            if "__dyn__" not in fn_ref:
                calls.add(fn_ref)
    return reads, writes, calls


def _walk_scope_io(
    stmts: list[ast.stmt],
    scope_name: str,
    env: dict[str, str],
    skip_ids: set[int],
    io: ModuleStoreIo,
) -> None:
    call_arg_ids: dict[int, str] = {}
    for s in stmts:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or id(s) in skip_ids:
            continue
        for node in ast.walk(s):
            if id(node) in skip_ids or not isinstance(node, ast.Call):
                continue
            fn = node.func
            fn_name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                call_arg_ids[id(arg)] = fn_name

            # Check `.jsonl` open / Path.open / read_text / write_text / helper calls
            if fn_name == "open":
                target_expr = (
                    fn.value
                    if isinstance(fn, ast.Attribute)
                    else (node.args[0] if node.args else None)
                )
                mode_expr = (
                    node.args[0]
                    if isinstance(fn, ast.Attribute) and node.args
                    else (node.args[1] if not isinstance(fn, ast.Attribute) and len(node.args) >= 2 else None)
                )
                if mode_expr is None:
                    mode_expr = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
                t_str = _eval_str_expr(target_expr, env)
                j_stem = _jsonl_stem_from_str(t_str) if t_str else None
                if j_stem:
                    mode_s = _eval_str_expr(mode_expr, env) or "r"
                    if any(ch in mode_s for ch in ("a", "w", "x", "+")):
                        io.jsonl_writes.setdefault(j_stem, set()).add(scope_name)
                    else:
                        io.jsonl_reads.setdefault(j_stem, set()).add(scope_name)
            elif fn_name in {"write_text", "write_bytes"} and isinstance(fn, ast.Attribute):
                t_str = _eval_str_expr(fn.value, env)
                j_stem = _jsonl_stem_from_str(t_str) if t_str else None
                if j_stem:
                    io.jsonl_writes.setdefault(j_stem, set()).add(scope_name)
            elif fn_name in {"read_text", "read_bytes"} and isinstance(fn, ast.Attribute):
                t_str = _eval_str_expr(fn.value, env)
                j_stem = _jsonl_stem_from_str(t_str) if t_str else None
                if j_stem:
                    io.jsonl_reads.setdefault(j_stem, set()).add(scope_name)
            elif fn_name:
                low_fn = fn_name.lower()
                for arg in (*node.args, *(kw.value for kw in node.keywords)):
                    a_str = _eval_str_expr(arg, env)
                    j_stem = _jsonl_stem_from_str(a_str) if a_str else None
                    if j_stem:
                        if any(w in low_fn for w in ("append", "write", "record", "emit", "log", "save")):
                            io.jsonl_writes.setdefault(j_stem, set()).add(scope_name)
                        elif any(r in low_fn for r in ("read", "load", "tail", "scan", "iter", "parse")):
                            io.jsonl_reads.setdefault(j_stem, set()).add(scope_name)

        for node in ast.walk(s):
            if id(node) in skip_ids:
                continue
            if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name)):
                if isinstance(node, ast.Name) and node.id not in env:
                    continue
                if isinstance(node, ast.Name) and id(node) not in call_arg_ids:
                    continue
                s_val = _eval_str_expr(node, env)
                if not s_val:
                    continue
                callee = call_arg_ids.get(id(node), "")
                sr, sw, sc = _extract_sql_dml_refs(
                    s_val, in_sql_call=bool(callee and _SQL_HELPER_CALL_RE.search(callee))
                )
                for r_ref in sr:
                    io.sql_reads.setdefault(r_ref, set()).add(scope_name)
                for w_ref in sw:
                    io.sql_writes.setdefault(w_ref, set()).add(scope_name)
                for c_ref in sc:
                    io.sql_calls.setdefault(c_ref, set()).add(scope_name)


def extract_module_store_io(tree: ast.Module, rel_path: str) -> ModuleStoreIo:
    """Extract per-scope SQL & JSONL read/write targets and engine hints for a Python module."""
    skip_ids = _docstring_and_tc_ids(tree)
    mod_env = _collect_str_bindings(tree.body, {})
    has_sqlite, has_pg, mod_stems = _inspect_module_drivers(tree, mod_env, skip_ids)
    fallback_stem = _sanitize_stem(PurePosixPath(rel_path).stem) or "app"
    engine_hint: str | None = None
    if has_sqlite and not has_pg:
        engine_hint = "sqlite"
    elif has_pg and not has_sqlite:
        engine_hint = "postgres"
    stems_tuple = tuple(mod_stems) if mod_stems else ((fallback_stem,) if has_sqlite else ())
    io = ModuleStoreIo(engine_hint=engine_hint, sqlite_stems=stems_tuple)

    _walk_scope_io(tree.body, "*", mod_env, skip_ids, io)

    def _visit_fn(fn: ast.FunctionDef | ast.AsyncFunctionDef, sc_name: str, outer_env: dict[str, str]) -> None:
        fn_env = _collect_str_bindings(fn.body, outer_env)
        _walk_scope_io(fn.body, sc_name, fn_env, skip_ids, io)
        for child in fn.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(child) not in skip_ids:
                _visit_fn(child, sc_name, fn_env)

    for stmt in tree.body:
        if id(stmt) in skip_ids:
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _visit_fn(stmt, stmt.name, mod_env)
        elif isinstance(stmt, ast.ClassDef):
            cls_env = _collect_str_bindings(stmt.body, mod_env)
            _walk_scope_io(stmt.body, stmt.name, cls_env, skip_ids, io)
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(member) not in skip_ids:
                    _visit_fn(member, member.name, cls_env)
    return io


def resolve_store_target_id(
    ref: str, table_symbol_map: dict[str, str], io: ModuleStoreIo
) -> str | None:
    """Resolve a SQL table reference using the module's engine/DB stem first, then unambiguous aliases."""
    bare = ref.split(".", 1)[1] if ref.startswith(("public.", "main.", "dbo.")) else ref
    if io.engine_hint == "sqlite":
        for st in io.sqlite_stems:
            for cand in (f"sqlite:{st}:{bare}", f"{st}:{bare}"):
                if cand in table_symbol_map:
                    return table_symbol_map[cand]
        if f"sqlite:{bare}" in table_symbol_map:
            return table_symbol_map[f"sqlite:{bare}"]
    elif io.engine_hint == "postgres":
        if "." in bare:
            for cand in (f"postgres:{bare}", bare):
                if cand in table_symbol_map:
                    return table_symbol_map[cand]
        else:
            for cand in (f"postgres:public.{bare}", f"postgres:{bare}"):
                if cand in table_symbol_map:
                    return table_symbol_map[cand]
    return table_symbol_map.get(ref) or table_symbol_map.get(bare)


def reconcile_sql_and_inline_stores(
    ddl_tables: dict[str, tuple[str, int, list[str], str]],
    inline_stores: list[InlineStoreObject],
) -> tuple[list[AtlasNode], dict[str, str], dict[str, list[str]], dict[str, str]]:
    """Emit deduplicated Truth nodes and disambiguated `table_symbol_map` across SQL, SQLite, PG, and JSONL."""
    dedup_inline: dict[tuple[str, str, str], InlineStoreObject] = {}
    for item in inline_stores:
        key = (item.engine, item.qualifier, item.table_name)
        prev = dedup_inline.get(key)
        if prev is None:
            dedup_inline[key] = item
        elif item.columns:
            merged_cols = list(dict.fromkeys([*prev.columns, *item.columns]))
            dedup_inline[key] = InlineStoreObject(
                engine=prev.engine,
                qualifier=prev.qualifier,
                table_name=prev.table_name,
                source_file=prev.source_file,
                line=prev.line,
                columns=merged_cols[:40],
            )

    # Merge inline Postgres/SQLite definitions that match an identical standalone SQL DDL table.
    merged_ddl: dict[str, tuple[str, int, list[str], str]] = dict(ddl_tables)
    remaining_inline: list[InlineStoreObject] = []
    for item in dedup_inline.values():
        if item.engine == "postgres":
            ddl_key = item.table_name if item.qualifier == "public" else f"{item.qualifier}.{item.table_name}"
            if ddl_key in merged_ddl and merged_ddl[ddl_key][3] in {"postgres", "sql"}:
                src_f, ln, cols, _eng = merged_ddl[ddl_key]
                merged_ddl[ddl_key] = (
                    src_f,
                    ln,
                    list(dict.fromkeys([*cols, *item.columns]))[:40],
                    "postgres",
                )
                continue
        elif item.engine == "sqlite":
            ddl_key = item.table_name
            if ddl_key in merged_ddl and merged_ddl[ddl_key][3] in {"sqlite", "sql"}:
                src_f, ln, cols, _eng = merged_ddl[ddl_key]
                ddl_stem = _sanitize_stem(PurePosixPath(src_f).stem) or "main"
                if ddl_stem == item.qualifier:
                    merged_ddl[ddl_key] = (
                        src_f,
                        ln,
                        list(dict.fromkeys([*cols, *item.columns]))[:40],
                        "sqlite",
                    )
                    continue
        remaining_inline.append(item)

    # Count distinct stores per bare table/ledger name to detect collisions (`events`, `policy`).
    bare_counts: dict[str, int] = {}
    for tbl_key in merged_ddl:
        if is_migration_meta_table(tbl_key):
            continue
        bare = tbl_key.split(".", 1)[-1]
        bare_counts[bare] = bare_counts.get(bare, 0) + 1
    for item in remaining_inline:
        bare_counts[item.table_name] = bare_counts.get(item.table_name, 0) + 1

    nodes: list[AtlasNode] = []
    nodes_by_id: dict[str, AtlasNode] = {}
    alias_claims: dict[str, list[str]] = {}
    ddl_node_ids: dict[str, str] = {}

    def _claim(alias: str, nid: str) -> None:
        bucket = alias_claims.setdefault(alias, [])
        if nid not in bucket:
            bucket.append(nid)

    def _emit_or_merge_node(cand: AtlasNode, bare_name: str) -> None:
        prev = nodes_by_id.get(cand.id)
        if prev is None:
            nodes_by_id[cand.id] = cand
            nodes.append(cand)
            return
        merged_cols = list(dict.fromkeys([*prev.columns, *cand.columns]))[:40]
        prev.columns = merged_cols
        prev.policy_columns = classify_table_policy_columns(bare_name, merged_cols)
        loc_tag = f"{cand.source_file}:{cand.line}"
        if cand.source_file and cand.source_file not in prev.summary:
            prev.summary = f"{prev.summary.rstrip('.')} (also declared at {loc_tag})."

    for tbl_key, (src_file, lineno, cols, sql_eng) in sorted(merged_ddl.items()):
        if is_migration_meta_table(tbl_key):
            continue
        bare = tbl_key.split(".", 1)[-1]
        schema = tbl_key.split(".", 1)[0] if "." in tbl_key else "public"
        collides = bare_counts.get(bare, 0) > 1
        if not collides:
            nid = f"t:{tbl_key}"
            label = tbl_key
        elif sql_eng == "sqlite":
            db_stem = _sanitize_stem(PurePosixPath(src_file).stem) or "main"
            nid = f"t:sqlite:{db_stem}:{bare}"
            label = f"sqlite:{db_stem}:{bare}"
        else:
            nid = f"t:postgres:{schema}.{bare}"
            label = f"postgres:{schema}.{bare}"
        ddl_node_ids[tbl_key] = nid

        if sql_eng == "sqlite":
            db_stem = _sanitize_stem(PurePosixPath(src_file).stem) or "main"
            for al in (f"sqlite:{db_stem}:{bare}", f"{db_stem}:{bare}", f"sqlite:{bare}", tbl_key, bare):
                _claim(al, nid)
        else:
            for al in (f"postgres:{schema}.{bare}", f"postgres:{bare}", f"{schema}.{bare}", tbl_key, bare):
                _claim(al, nid)

        _emit_or_merge_node(
            AtlasNode(
                id=nid,
                tier="truth",
                subkind="table",
                label=label,
                source_file=src_file,
                line=lineno,
                status="clean",
                role=infer_table_role(bare),
                cluster=bare.split("_", 1)[0] if "_" in bare else "core",
                summary=f"SQL DDL table `{label}` ({src_file}).",
                columns=cols,
                policy_columns=classify_table_policy_columns(bare, cols),
            ),
            bare,
        )

    for item in sorted(remaining_inline, key=lambda s: (s.engine, s.qualifier, s.table_name)):
        if item.engine == "sqlite":
            nid = f"t:sqlite:{item.qualifier}:{item.table_name}"
            label = f"sqlite:{item.qualifier}:{item.table_name}"
            role = infer_table_role(item.table_name)
            cluster = "sqlite"
            summary = f"Inline SQLite table `{item.table_name}` in `{item.qualifier}.db` ({item.source_file}:{item.line})."
            for al in (
                f"sqlite:{item.qualifier}:{item.table_name}",
                f"{item.qualifier}:{item.table_name}",
                f"sqlite:{item.table_name}",
                item.table_name,
            ):
                _claim(al, nid)
        elif item.engine == "postgres":
            nid = f"t:postgres:{item.qualifier}.{item.table_name}"
            label = f"postgres:{item.qualifier}.{item.table_name}"
            role = infer_table_role(item.table_name)
            cluster = "postgres"
            summary = f"Inline PostgreSQL table `{item.qualifier}.{item.table_name}` ({item.source_file}:{item.line})."
            for al in (
                f"postgres:{item.qualifier}.{item.table_name}",
                f"{item.qualifier}.{item.table_name}",
                f"postgres:{item.table_name}",
                item.table_name,
            ):
                _claim(al, nid)
        else:
            nid = f"t:jsonl:{item.qualifier}"
            label = f"{item.qualifier}.jsonl"
            role = "record"
            cluster = "jsonl"
            summary = f"Append-only JSONL ledger `{item.qualifier}.jsonl` ({item.source_file}:{item.line})."
            for al in (f"jsonl:{item.qualifier}", f"{item.qualifier}.jsonl", item.qualifier):
                _claim(al, nid)

        _emit_or_merge_node(
            AtlasNode(
                id=nid,
                tier="truth",
                subkind="table",
                label=label,
                source_file=item.source_file,
                line=item.line,
                status="clean",
                role=role,
                cluster=cluster,
                summary=summary,
                columns=item.columns,
                policy_columns=classify_table_policy_columns(item.table_name, item.columns),
            ),
            item.table_name,
        )

    table_symbol_map: dict[str, str] = {}
    ambiguous_bare_names: dict[str, list[str]] = {}
    for alias, nids in sorted(alias_claims.items()):
        if len(nids) == 1:
            table_symbol_map[alias] = nids[0]
        elif ":" not in alias and not alias.endswith(".jsonl"):
            ambiguous_bare_names[alias] = sorted(nids)

    return nodes, table_symbol_map, ambiguous_bare_names, ddl_node_ids
