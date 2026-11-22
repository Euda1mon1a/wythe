"""Tier 1 Adapter: SQL DDL + Inline SQLite/PostgreSQL/JSONL Stores + Declarative Registries."""

from __future__ import annotations

import ast
import os
import re
import stat
from pathlib import Path, PurePosixPath

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    clean_sql_ident,
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.adapters.inline_store_truth import (
    _COL_SKIP_HEADS,
    _CREATE_HEAD_RE,
    _SQLITE_DDL_MARKERS_RE,
    InlineStoreObject,
    _collect_str_bindings,
    _docstring_and_tc_ids,
    _eval_str_expr,
    _inspect_module_drivers,
    _sanitize_stem,
    _split_top_level_commas,
    infer_sql_file_engine,
    parse_inline_create_tables,
    reconcile_sql_and_inline_stores,
    scan_inline_stores,
)
from app.adapters.registry_sources import extract_registry_truth_nodes
from app.adapters.service_sources import EXCLUDED_PARTS
from app.adapters.ts_workspace import (
    safe_read_repo_bytes,
    safe_read_repo_text,
    safe_resolve_contained_path,
)
from app.schemas.atlas import AtlasNode

_PG_EXT_DDL_RE = re.compile(
    r"(?:"
    r"\b(?:TIMESTAMPTZ|JSONB|BIGSERIAL|SMALLSERIAL|SERIAL|BYTEA|UUID|INET|CIDR|VECTOR)\b"
    r"|\bDOUBLE\s+PRECISION\b"
    r"|\bUSING\s+(?:hnsw|gin|ivfflat|gist)\b"
    r"|\[\s*\]"
    r")",
    re.IGNORECASE,
)
_PG_STRONG_ONLY_RE = re.compile(
    r"(?:"
    r"\b(?:TIMESTAMPTZ|JSONB|BIGSERIAL|SMALLSERIAL|BYTEA|VECTOR)\b"
    r"|\bDOUBLE\s+PRECISION\b"
    r"|\bUSING\s+(?:hnsw|gin|ivfflat|gist)\b"
    r"|\[\s*\]"
    r")",
    re.IGNORECASE,
)
_PG_INDEX_STMT_RE = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b[\s\S]{0,200}\bUSING\s+(?:hnsw|gin|ivfflat|gist)\b",
    re.IGNORECASE,
)
_SQL_WALK_SKIP_DIRS = frozenset(
    {
        "venv",
        ".venv",
        "env",
        "site-packages",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        "target",
        "vendor",
        ".git",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)


def _has_pyvenv_cfg(dir_path: Path) -> bool:
    try:
        (dir_path / "pyvenv.cfg").lstat()
        return True
    except OSError:
        return False


def _parse_pg_inline_create_tables(sql_text: str) -> dict[tuple[str, str], tuple[int, list[str]]]:
    """Extract inline Postgres `CREATE TABLE` blocks, tolerating `?` in comments and JSONB checks."""
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
            elif ch == "/" and i + 1 < n and sql_text[i + 1] == "*":
                end_blk = sql_text.find("*/", i + 2)
                i = n if end_blk == -1 else end_blk + 2
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
        cols: list[str] = []
        for clause in _split_top_level_commas(body):
            no_blk = re.sub(r"/\*[\s\S]*?\*/", " ", clause)
            cleaned_lines = [
                ln.split("--", 1)[0].strip()
                for ln in no_blk.splitlines()
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


def _check_dir_accessible(path: Path) -> None:
    if not os.access(path, os.R_OK | os.X_OK):
        raise PermissionError(f"Directory is not readable/traversable: {path}")
    with os.scandir(path) as it:
        next(it, None)


def _scan_supplemental_inline_pg_stores(
    real_root: Path, backend_subdir: str
) -> tuple[list[InlineStoreObject], set[tuple[str, str]], list[str], list[str]]:
    """Supplement `scan_inline_stores` for inline Postgres DDL blocks with PG types or JSONB `?` checks."""
    scan_roots: list[Path] = []
    failed_files: list[str] = []
    skipped_symlinks: list[str] = []
    seen_skipped: set[str] = set()
    if backend_subdir not in ("", "."):
        sub_p = Path(backend_subdir)
        if not sub_p.is_absolute() and ".." not in sub_p.parts and "\x00" not in backend_subdir:
            safe_be = safe_resolve_contained_path(sub_p, real_root)
            if safe_be is not None:
                try:
                    if safe_be.is_dir():
                        _check_dir_accessible(safe_be)
                        scan_roots.append(safe_be)
                except OSError:
                    failed_files.append(backend_subdir)
    scan_roots.append(real_root)

    py_files: list[Path] = []
    seen_py: set[Path] = set()

    def _on_walk_err(exc: OSError) -> None:
        raw = Path(exc.filename) if exc.filename else real_root
        rel_err = raw.relative_to(real_root).as_posix() if raw.is_relative_to(real_root) else str(raw)
        if rel_err not in failed_files:
            failed_files.append(rel_err)

    for root in dict.fromkeys(scan_roots):
        try:
            if not root.is_dir():
                continue
            _check_dir_accessible(root)
        except OSError:
            rel_root = root.relative_to(real_root).as_posix() if root.is_relative_to(real_root) else str(root)
            if rel_root not in failed_files:
                failed_files.append(rel_root)
            continue
        for parent, dirs, names in os.walk(root, followlinks=False, onerror=_on_walk_err):
            parent_p = Path(parent)
            if _has_pyvenv_cfg(parent_p):
                dirs[:] = []
                continue
            kept_dirs: list[str] = []
            for d in sorted(dirs):
                if d in EXCLUDED_PARTS or d in _SQL_WALK_SKIP_DIRS or d.startswith("."):
                    continue
                dp = parent_p / d
                rel_d = dp.relative_to(real_root).as_posix() if dp.is_relative_to(real_root) else str(dp)
                try:
                    dst = dp.lstat()
                except OSError:
                    if rel_d not in seen_skipped:
                        seen_skipped.add(rel_d)
                        skipped_symlinks.append(rel_d)
                    continue
                if stat.S_ISLNK(dst.st_mode):
                    if rel_d not in seen_skipped:
                        seen_skipped.add(rel_d)
                        skipped_symlinks.append(rel_d)
                    continue
                if stat.S_ISDIR(dst.st_mode):
                    if not os.access(dp, os.R_OK | os.X_OK):
                        if rel_d not in failed_files:
                            failed_files.append(rel_d)
                        continue
                    if _has_pyvenv_cfg(dp):
                        continue
                    kept_dirs.append(d)
            dirs[:] = kept_dirs

            for name in sorted(names):
                if not name.endswith(".py"):
                    continue
                pf = Path(parent) / name
                rel_p = pf.relative_to(real_root).as_posix() if pf.is_relative_to(real_root) else str(pf)
                try:
                    st = pf.lstat()
                except OSError:
                    if rel_p not in failed_files:
                        failed_files.append(rel_p)
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    if rel_p not in seen_skipped:
                        seen_skipped.add(rel_p)
                        skipped_symlinks.append(rel_p)
                    continue
                safe_pf = safe_resolve_contained_path(pf, real_root)
                if safe_pf is None:
                    if rel_p not in seen_skipped:
                        seen_skipped.add(rel_p)
                        skipped_symlinks.append(rel_p)
                    continue
                if safe_pf not in seen_py:
                    seen_py.add(safe_pf)
                    py_files.append(safe_pf)

    pg_stores: list[InlineStoreObject] = []
    override_keys: set[tuple[str, str]] = set()
    for pf in py_files:
        rel = pf.relative_to(real_root).as_posix()
        try:
            text = safe_read_repo_text(pf, real_root, encoding="utf-8-sig")
            tree = ast.parse(text)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            failed_files.append(rel)
            continue
        skip_ids = _docstring_and_tc_ids(tree)
        mod_env = _collect_str_bindings(tree.body, {})
        has_sqlite, has_pg, _ = _inspect_module_drivers(tree, mod_env, skip_ids)
        scopes: list[tuple[list[ast.stmt], dict[str, str]]] = [(tree.body, mod_env)]
        for node in ast.walk(tree):
            if id(node) not in skip_ids and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                scopes.append((node.body, _collect_str_bindings(node.body, mod_env)))
        seen_nodes: set[int] = set()
        for body, env in scopes:
            for stmt in body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or id(stmt) in skip_ids:
                    continue
                for sub in ast.walk(stmt):
                    if id(sub) in skip_ids or id(sub) in seen_nodes:
                        continue
                    if not isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                        continue
                    s_val = _eval_str_expr(sub, env)
                    if not s_val or "create" not in s_val.lower() or "table" not in s_val.lower():
                        continue
                    if _SQLITE_DDL_MARKERS_RE.search(s_val):
                        continue
                    parsed_tbls = _parse_pg_inline_create_tables(s_val)
                    if not parsed_tbls:
                        continue
                    has_ext_pg_str = bool(_PG_EXT_DDL_RE.search(s_val))
                    has_strong_pg_str = bool(_PG_STRONG_ONLY_RE.search(s_val))
                    sqlite_only = has_sqlite and not has_pg
                    base_line = getattr(sub, "lineno", 1)
                    for (raw_sch, tbl), (off, cols) in parsed_tbls.items():
                        has_tbl_pg_index = bool(
                            _PG_INDEX_STMT_RE.search(text)
                            and re.search(
                                rf"\bON\s+(?:[A-Za-z_]\w*\.)?{re.escape(tbl)}\b[\s\S]{{0,120}}\bUSING\s+(?:hnsw|gin|ivfflat|gist)\b",
                                text,
                                re.IGNORECASE,
                            )
                        )
                        has_ext_pg = has_ext_pg_str or has_tbl_pg_index
                        has_strong_pg = has_strong_pg_str or has_tbl_pg_index
                        use_pg = (
                            (has_pg and not has_sqlite)
                            or (raw_sch and raw_sch not in {"main", "temp"})
                            or (not sqlite_only and has_ext_pg)
                            or has_strong_pg
                        )
                        if not use_pg:
                            continue
                        seen_nodes.add(id(sub))
                        sch = raw_sch or "public"
                        pg_stores.append(
                            InlineStoreObject(
                                engine="postgres",
                                qualifier=sch,
                                table_name=tbl,
                                source_file=rel,
                                line=base_line + off,
                                columns=cols,
                            )
                        )
                        override_keys.add((rel, tbl))
    return pg_stores, override_keys, failed_files, skipped_symlinks

_SQLC_BLOCK_RE = re.compile(
    r"""--\s*name:\s*(?P<qname>[A-Za-z_]\w*)\s*:(?P<qkind>\w+)\s*\n(?P<sql>[\s\S]*?;)\s*(?=--\s*name:|\Z)"""
)
_SQL_READ_TBL_RE = re.compile(
    r"""\b(?:FROM|JOIN)\s+(?P<t>(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)(?:\.(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*))?)""",
    re.IGNORECASE,
)
_SQL_WRITE_TBL_RE = re.compile(
    r"""\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?P<t>(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)(?:\.(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*))?)""",
    re.IGNORECASE,
)


def _norm_sql_ref(raw: str) -> str:
    if "." in raw:
        sch, tbl = raw.split(".", 1)
        sc = clean_sql_ident(sch)
        tc = clean_sql_ident(tbl)
        return tc if sc in ("public", "main", "dbo") else f"{sc}.{tc}"
    return clean_sql_ident(raw)


class SqlDdlTruthAdapter:
    """Extracts SQL DDL schemas/migrations, inline SQLite/PG/JSONL stores, JSON registries, and catalog drift."""

    name = "sql-ddl"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        try:
            if repo_root.is_symlink():
                return TruthExtractionResult(
                    nodes=[],
                    table_symbol_map={},
                    function_symbol_map={},
                    coverage_complete=False,
                    notes=[f"Repository root `{repo_root}` is a symlink; SQL DDL truth coverage is incomplete."],
                )
            real_root = repo_root.resolve(strict=True)
            if not real_root.is_dir():
                return TruthExtractionResult(
                    nodes=[],
                    table_symbol_map={},
                    function_symbol_map={},
                    coverage_complete=False,
                    notes=[f"Repository root `{repo_root}` is not a directory; SQL DDL truth coverage is incomplete."],
                )
            _check_dir_accessible(real_root)
        except OSError as exc:
            return TruthExtractionResult(
                nodes=[],
                table_symbol_map={},
                function_symbol_map={},
                coverage_complete=False,
                notes=[f"Repository root `{repo_root}` is unreadable ({exc}); SQL DDL truth coverage is incomplete."],
            )
        function_symbol_map: dict[str, str] = {}
        findings: list[RawCandidateFinding] = []
        notes: list[str] = []
        coverage_complete = True

        scan_roots: list[Path] = []
        safe_be_ok = False
        if backend_subdir not in ("", "."):
            sub_p = Path(backend_subdir)
            if sub_p.is_absolute() or ".." in sub_p.parts or "\x00" in backend_subdir:
                coverage_complete = False
                notes.append("SQL DDL backend root is absent, symlinked, or outside the repository; skipping backend_subdir.")
            else:
                safe_be = safe_resolve_contained_path(sub_p, real_root)
                be_ok = False
                if safe_be is not None:
                    try:
                        if safe_be.is_dir():
                            _check_dir_accessible(safe_be)
                            be_ok = True
                    except OSError as exc:
                        coverage_complete = False
                        notes.append(f"SQL DDL backend root `{backend_subdir}` is unreadable ({exc}); skipping backend_subdir.")
                        be_ok = False
                        safe_be = None
                if be_ok and safe_be is not None:
                    safe_be_ok = True
                    scan_roots.append(safe_be)
                elif safe_be is not None or not notes:
                    coverage_complete = False
                    notes.append("SQL DDL backend root is absent, symlinked, or outside the repository; skipping backend_subdir.")
                else:
                    coverage_complete = False
        scan_roots.append(real_root)

        ddl_tables: dict[str, tuple[str, int, list[str], str]] = {}
        extra_sqlite_sql: list[InlineStoreObject] = []
        sql_guards: dict[str, tuple[str, int]] = {}
        sql_files: list[Path] = []

        def _on_sql_walk_err(exc: OSError) -> None:
            nonlocal coverage_complete
            coverage_complete = False
            notes.append(f"Unreadable directory during SQL DDL walk `{exc.filename or real_root}` ({exc}); SQL DDL truth coverage is incomplete.")

        for root in dict.fromkeys(scan_roots):
            try:
                if not root.is_dir():
                    continue
                _check_dir_accessible(root)
            except OSError as exc:
                coverage_complete = False
                notes.append(f"Unreadable SQL DDL scan root `{root}` ({exc}); SQL DDL truth coverage is incomplete.")
                continue
            for parent, dirs, names in os.walk(root, followlinks=False, onerror=_on_sql_walk_err):
                parent_p = Path(parent)
                if _has_pyvenv_cfg(parent_p):
                    dirs[:] = []
                    continue
                kept_dirs: list[str] = []
                for d in sorted(dirs):
                    if d in _SQL_WALK_SKIP_DIRS or d.startswith("."):
                        continue
                    dp = parent_p / d
                    try:
                        dst = dp.lstat()
                    except OSError as exc:
                        coverage_complete = False
                        notes.append(f"Unreadable SQL directory `{dp}` ({exc}); SQL DDL truth coverage is incomplete.")
                        continue
                    if stat.S_ISLNK(dst.st_mode):
                        coverage_complete = False
                        notes.append(f"Skipped symlink SQL directory `{dp}`; SQL DDL truth coverage is incomplete.")
                        continue
                    if stat.S_ISDIR(dst.st_mode):
                        if not os.access(dp, os.R_OK | os.X_OK):
                            coverage_complete = False
                            notes.append(f"Unreadable SQL directory `{dp}`; SQL DDL truth coverage is incomplete.")
                            continue
                        if _has_pyvenv_cfg(dp):
                            continue
                        kept_dirs.append(d)
                dirs[:] = kept_dirs

                for name in sorted(names):
                    if not name.endswith(".sql") or name.endswith(".down.sql"):
                        continue
                    sf = Path(parent) / name
                    try:
                        sf_st = sf.lstat()
                    except OSError as exc:
                        coverage_complete = False
                        notes.append(f"Unreadable SQL file `{sf}` ({exc}); SQL DDL truth coverage is incomplete.")
                        continue
                    if stat.S_ISLNK(sf_st.st_mode):
                        coverage_complete = False
                        notes.append(f"Skipped symlink SQL file `{sf}`; SQL DDL truth coverage is incomplete.")
                        continue
                    if not stat.S_ISREG(sf_st.st_mode):
                        coverage_complete = False
                        notes.append(f"Skipped non-regular SQL file `{sf}`; SQL DDL truth coverage is incomplete.")
                        continue
                    sf_real = safe_resolve_contained_path(sf, real_root)
                    if sf_real is None:
                        coverage_complete = False
                        notes.append(f"Rejected out-of-repo SQL file `{sf}`; SQL DDL truth coverage is incomplete.")
                        continue
                    if sf_real not in sql_files:
                        sql_files.append(sf_real)

        sql_files.sort()
        sql_texts: dict[Path, str] = {}
        for sf in sql_files:
            rel_s = sf.relative_to(real_root).as_posix()
            try:
                raw_bytes = safe_read_repo_bytes(sf, real_root)
            except OSError as exc:
                coverage_complete = False
                notes.append(f"Unreadable SQL file `{rel_s}` ({exc}); SQL DDL truth coverage is incomplete.")
                continue
            try:
                text = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                coverage_complete = False
                notes.append(f"Invalid UTF-8 in SQL file `{rel_s}` ({exc}); SQL DDL truth coverage is incomplete.")
                text = raw_bytes.decode("utf-8", errors="replace")
            sql_texts[sf] = text
            f_eng = infer_sql_file_engine(rel_s, text)
            t_objs, g_objs = parse_sql_ddl_objects(text)
            balanced = parse_inline_create_tables(text)
            for (raw_sch, b_tbl), (b_off, b_cols) in balanced.items():
                b_key = b_tbl if raw_sch in ("", "public", "main", "dbo") else f"{raw_sch}.{b_tbl}"
                if b_key not in t_objs or (b_cols and not t_objs[b_key][1]):
                    t_objs[b_key] = (b_off + 1, b_cols)

            for tk, (tline, tcols) in t_objs.items():
                if tk in ddl_tables and ddl_tables[tk][3] != f_eng and "sqlite" in {ddl_tables[tk][3], f_eng}:
                    if f_eng == "sqlite":
                        db_st = _sanitize_stem(PurePosixPath(rel_s).stem) or "main"
                        extra_sqlite_sql.append(
                            InlineStoreObject("sqlite", db_st, tk.split(".", 1)[-1], rel_s, tline, tcols)
                        )
                    else:
                        prev_src, prev_ln, prev_cols, _ = ddl_tables[tk]
                        db_st = _sanitize_stem(PurePosixPath(prev_src).stem) or "main"
                        extra_sqlite_sql.append(
                            InlineStoreObject("sqlite", db_st, tk.split(".", 1)[-1], prev_src, prev_ln, prev_cols)
                        )
                        ddl_tables[tk] = (rel_s, tline, tcols, f_eng)
                elif tk not in ddl_tables or tcols:
                    prev_cols = ddl_tables[tk][2] if tk in ddl_tables else []
                    merged_cols = list(dict.fromkeys([*prev_cols, *tcols]))[:40]
                    ddl_tables[tk] = (rel_s, tline, merged_cols, f_eng)
            for gk, gline in g_objs.items():
                sql_guards[gk] = (rel_s, gline)

        inline_subdir = backend_subdir if (backend_subdir in ("", ".") or safe_be_ok) else "."
        try:
            scanned_inline = scan_inline_stores(real_root, inline_subdir)
        except OSError as exc:
            scanned_inline = []
            coverage_complete = False
            notes.append(f"Inline store scan failed ({exc}); SQL DDL truth coverage is incomplete.")
        supp_pg_stores, pg_override_keys, failed_py_files, skipped_py_symlinks = (
            _scan_supplemental_inline_pg_stores(real_root, backend_subdir)
        )
        if failed_py_files:
            coverage_complete = False
            notes.append(
                f"Unreadable or unparseable Python source(s) during inline store scan: {', '.join(failed_py_files[:8])}."
            )
        if skipped_py_symlinks:
            coverage_complete = False
            notes.append(
                f"Skipped symlink/non-regular Python source(s) during inline store scan: {', '.join(skipped_py_symlinks[:8])}; SQL DDL truth coverage is incomplete."
            )
        filtered_inline = [
            s
            for s in scanned_inline
            if not (s.engine == "sqlite" and (s.source_file, s.table_name) in pg_override_keys)
        ]
        inline_stores = [*extra_sqlite_sql, *filtered_inline, *supp_pg_stores]
        nodes, table_symbol_map, ambiguous_bare, ddl_node_ids = reconcile_sql_and_inline_stores(
            ddl_tables, inline_stores
        )
        supp_pg_nids = {
            f"t:postgres:{item.qualifier}.{item.table_name}" for item in supp_pg_stores
        }
        for node in nodes:
            if node.id in supp_pg_nids and node.verification_note is None:
                node.verification_note = "declared (inline_python_ddl)"
        if ambiguous_bare:
            pairs_txt = ", ".join(f"`{k}` -> {v}" for k, v in sorted(ambiguous_bare.items()))
            notes.append(f"Disambiguated colliding bare store names across engines: {pairs_txt}.")

        reg_cov: list[bool] = []
        try:
            reg_res = extract_registry_truth_nodes(
                real_root,
                notes_out=notes,
                coverage_out=reg_cov,
            )
            reg_nodes, reg_sym_map = reg_res
            if not getattr(reg_res, "coverage_complete", True) or any(not c for c in reg_cov):
                coverage_complete = False
                for reg_note in getattr(reg_res, "notes", ()):
                    if reg_note not in notes:
                        notes.append(reg_note)
        except OSError as exc:
            reg_nodes, reg_sym_map = [], {}
            coverage_complete = False
            notes.append(f"Registry truth scan failed ({exc}); SQL DDL truth coverage is incomplete.")
        existing_ids = {n.id for n in nodes}
        for rnode in reg_nodes:
            if rnode.id not in existing_ids:
                nodes.append(rnode)
                existing_ids.add(rnode.id)
        for rk, rv in reg_sym_map.items():
            table_symbol_map.setdefault(rk, rv)

        # Extract sqlc `-- name: QueryName :one|:many|:exec` bindings into table_symbol_map
        for sf in sql_files:
            text = sql_texts.get(sf)
            if not text or "-- name:" not in text:
                continue
            for m in _SQLC_BLOCK_RE.finditer(text):
                qname = m.group("qname")
                sql_body = m.group("sql")
                write_refs = [_norm_sql_ref(w.group("t")) for w in _SQL_WRITE_TBL_RE.finditer(sql_body)]
                read_refs = [_norm_sql_ref(r.group("t")) for r in _SQL_READ_TBL_RE.finditer(sql_body)]
                for wref in write_refs:
                    if wref in table_symbol_map:
                        table_symbol_map[f"sqlc:write:{qname}"] = table_symbol_map[wref]
                for rref in read_refs:
                    if rref not in write_refs and rref in table_symbol_map:
                        table_symbol_map[f"sqlc:read:{qname}"] = table_symbol_map[rref]

        for gk, (gsrc, gline) in sorted(sql_guards.items()):
            fn_id = f"fn:{gk}"
            function_symbol_map[gk] = fn_id
            nodes.append(
                AtlasNode(
                    id=fn_id,
                    tier="truth",
                    subkind="sql_function",
                    label=f"{gk}()",
                    source_file=gsrc,
                    line=gline,
                    status="clean",
                    role="mechanism",
                    cluster="db_guard",
                    summary=f"SQL stored function / trigger `{gk}`.",
                )
            )

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            is_sqlite_dsn = pg_dsn.lower().startswith("sqlite:")
            for tbl_key, (src_file, lineno, _, sql_eng) in sorted(ddl_tables.items()):
                if is_migration_meta_table(tbl_key):
                    continue
                if is_sqlite_dsn and sql_eng == "postgres":
                    continue
                if not is_sqlite_dsn and sql_eng == "sqlite":
                    continue
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=ddl_node_ids.get(tbl_key, f"t:{tbl_key}"),
                            source_file=src_file,
                            line=lineno,
                            title=f"SQL DDL table `{tbl_key}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tbl_key}`.",
                            remediation="Apply pending SQL migrations on the target database.",
                        )
                    )
            for live_tbl in sorted(live_tables):
                ddl_entry = ddl_tables.get(live_tbl)
                ddl_matches_engine = ddl_entry is not None and not (
                    (is_sqlite_dsn and ddl_entry[3] == "postgres")
                    or (not is_sqlite_dsn and ddl_entry[3] == "sqlite")
                )
                if is_migration_meta_table(live_tbl) or ddl_matches_engine:
                    continue
                if is_sqlite_dsn:
                    live_nid = table_symbol_map.get(f"sqlite:{live_tbl}") or table_symbol_map.get(live_tbl)
                else:
                    live_nid = (
                        table_symbol_map.get(f"postgres:{live_tbl}")
                        or table_symbol_map.get(f"postgres:public.{live_tbl}")
                        or table_symbol_map.get(live_tbl)
                    )
                if live_nid is not None and live_nid.startswith(("t:jsonl:", "t:registry:")):
                    live_nid = None
                if live_nid is None:
                    live_nid = f"t:live:{live_tbl}"
                    if live_nid not in existing_ids:
                        nodes.append(
                            AtlasNode(
                                id=live_nid,
                                tier="truth",
                                subkind="table",
                                label=live_tbl,
                                source_file="<live_catalog>",
                                line=1,
                                status="gray_zone",
                                role="unmanaged_live",
                                cluster="live_catalog",
                                summary=(
                                    f"Live database table `{live_tbl}` observed via `{obs_source}` "
                                    "without a matching SQL DDL declaration."
                                ),
                            )
                        )
                        existing_ids.add(live_nid)
                    table_symbol_map.setdefault(live_tbl, live_nid)
                live_node = next((n for n in nodes if n.id == live_nid), None)
                if live_node is not None and live_node.status == "clean":
                    live_node.status = "gray_zone"
                findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-005",
                        node_id=live_nid,
                        source_file=live_node.source_file if live_node is not None else "<live_catalog>",
                        line=live_node.line if live_node is not None else 1,
                        title=f"Live database table `{live_tbl}` has no CREATE TABLE in SQL DDL",
                        detail=(
                            f"Read-only catalog probe ({obs_source}) found `{live_tbl}` in the live "
                            "database catalog, but no repository SQL DDL file declares it."
                        ),
                        remediation=(
                            f"Add the SQL migration or schema DDL that creates `{live_tbl}` "
                            "(or retire unmanaged live tables) so the schema can be rebuilt from source."
                        ),
                    )
                )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
            coverage_complete=coverage_complete,
            notes=notes,
        )
