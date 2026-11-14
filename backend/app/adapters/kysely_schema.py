"""Tier 1 Adapter: Kysely Schema Migrations + SQL Guards + Optional Live Catalog Probe."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    clean_sql_ident,
    infer_table_role,
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.adapters.treesitter_engine import _get_parser, has_treesitter
from app.schemas.atlas import AtlasNode

_SKIP_PARTS = frozenset({"node_modules", ".next", ".svelte-kit", "dist", "build", "__pycache__", ".git"})
_MIG_EXTS = frozenset({".ts", ".mts", ".js", ".mjs"})
_IDENT_SQL = r'(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)'
_SQL_DROP_TABLE_RE = re.compile(
    rf"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?P<schema>{_IDENT_SQL})\.)?(?P<table>{_IDENT_SQL})",
    re.IGNORECASE,
)
_SQL_RENAME_TABLE_RE = re.compile(
    rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?P<schema>{_IDENT_SQL})\.)?(?P<old>{_IDENT_SQL})\s+RENAME\s+TO\s+(?:(?P<nschema>{_IDENT_SQL})\.)?(?P<new>{_IDENT_SQL})",
    re.IGNORECASE,
)
_KYSELY_MIGRATION_TABLE_SET = frozenset({"kysely_migration", "kysely_migration_lock"})
_CAMEL_PLUGIN_RE = re.compile(r"\bCamelCasePlugin\b")
_UP_DEF_RE = re.compile(r"\bexport\s+(?:async\s+)?function\s+up\s*\(|\bexport\s+const\s+up\s*=")
_MIG_MARKER_RE = re.compile(r"createTable|alterTable|dropTable|\.schema\b|\bsql\s*`")


@dataclass
class _KyselyTableState:
    source_file: str
    line: int
    columns: list[str] = field(default_factory=list)
    fks: set[str] = field(default_factory=set)


def _snake_to_camel(name: str) -> str:
    parts = [p for p in name.split("_") if p]
    if len(parts) <= 1:
        return name
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def _qualify_table_key(raw_name: str, active_schema: str = "public") -> str:
    cleaned = raw_name.strip().strip('"`').lower()
    if "." in cleaned:
        sch, tbl = cleaned.split(".", 1)
        sch = sch.strip().strip('"`') or "public"
        tbl = tbl.strip().strip('"`')
    else:
        sch, tbl = (active_schema or "public").lower(), cleaned
    return tbl if sch == "public" else f"{sch}.{tbl}"


def _node_text(raw: bytes, node: Any) -> str:
    return raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _static_str_arg(raw: bytes, arg: Any | None, consts: dict[str, str]) -> str | None:
    if arg is None:
        return None
    while arg.type in ("parenthesized_expression", "as_expression", "type_assertion") and arg.named_children:
        arg = arg.named_children[0]
    if arg.type in ("string", "template_string"):
        txt = _node_text(raw, arg).strip()
        if arg.type == "template_string" and "${" in txt:
            return None
        if len(txt) >= 2 and txt[0] in ("'", '"', "`") and txt[-1] == txt[0]:
            return txt[1:-1]
    if arg.type == "identifier":
        return consts.get(_node_text(raw, arg))
    return None


def _template_sql_literal(raw: bytes, node: Any | None) -> str | None:
    if node is None:
        return None
    txt = _node_text(raw, node).strip()
    if len(txt) >= 2 and txt[0] in ("`", "'", '"') and txt[-1] == txt[0]:
        inner = txt[1:-1]
        if "${" not in inner:
            return inner
    return None


def _collect_migration_scopes_cst(raw: bytes, root: Any) -> tuple[dict[str, str], list[Any], dict[str, Any]]:
    """Collect module const strings, `up` function node(s), and helper function map."""
    consts: dict[str, str] = {}
    ups: list[Any] = []
    helpers: dict[str, Any] = {}

    def scan_top(node: Any) -> None:
        if node.type == "export_statement":
            for ch in node.named_children:
                scan_top(ch)
            return
        if node.type == "function_declaration":
            nm = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if nm is not None and body is not None:
                fname = _node_text(raw, nm)
                if fname == "up":
                    ups.append(body)
                elif fname != "down":
                    helpers[fname] = body
            return
        if node.type == "lexical_declaration":
            for ch in node.named_children:
                if ch.type != "variable_declarator":
                    continue
                nm = ch.child_by_field_name("name")
                val = ch.child_by_field_name("value")
                if nm is None or val is None:
                    continue
                vname = _node_text(raw, nm)
                if val.type in ("arrow_function", "function_expression", "function"):
                    body = val.child_by_field_name("body")
                    if body is not None:
                        if vname == "up":
                            ups.append(body)
                        elif vname != "down":
                            helpers[vname] = body
                else:
                    sval = _static_str_arg(raw, val, consts)
                    if sval is not None:
                        consts[vname] = sval

    for child in root.named_children:
        scan_top(child)
    return consts, ups, helpers


def _call_chain(raw: bytes, call_node: Any) -> list[tuple[str, list[Any], int, Any]]:
    """Flatten a fluent `.withSchema().createTable().addColumn()` call into outer-ordered steps."""
    steps: list[tuple[str, list[Any], int, Any]] = []
    cur: Any | None = call_node
    while cur is not None:
        while cur.type in ("await_expression", "parenthesized_expression") and cur.named_children:
            cur = cur.named_children[0]
        if cur.type != "call_expression":
            break
        fn = cur.child_by_field_name("function")
        args_n = cur.child_by_field_name("arguments")
        args = [c for c in args_n.named_children] if args_n is not None else []
        lineno = cur.start_point[0] + 1
        if fn is not None and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            mname = _node_text(raw, prop) if prop is not None else ""
            steps.append((mname, args, lineno, cur))
            cur = obj
        else:
            break
    steps.reverse()
    return steps


def _exec_ddl_sql(
    sql_text: str,
    rel_file: str,
    lineno: int,
    tables: dict[str, _KyselyTableState],
    sql_guards: dict[str, tuple[str, int]],
) -> None:
    t_objs, g_objs = parse_sql_ddl_objects(sql_text)
    for tk, (off_line, tcols) in t_objs.items():
        if is_migration_meta_table(tk) or tk in _KYSELY_MIGRATION_TABLE_SET:
            continue
        tables[tk] = _KyselyTableState(source_file=rel_file, line=lineno + max(0, off_line - 1), columns=tcols)
    for gk, off_line in g_objs.items():
        sql_guards[gk] = (rel_file, lineno + max(0, off_line - 1))
    for dm in _SQL_DROP_TABLE_RE.finditer(sql_text):
        sch = clean_sql_ident(dm.group("schema")) or "public"
        tbl = clean_sql_ident(dm.group("table"))
        key = tbl if sch == "public" else f"{sch}.{tbl}"
        tables.pop(key, None)
    for rm in _SQL_RENAME_TABLE_RE.finditer(sql_text):
        sch = clean_sql_ident(rm.group("schema")) or "public"
        old_k = clean_sql_ident(rm.group("old")) if sch == "public" else f"{sch}.{clean_sql_ident(rm.group('old'))}"
        nsch = clean_sql_ident(rm.group("nschema")) or sch
        new_k = clean_sql_ident(rm.group("new")) if nsch == "public" else f"{nsch}.{clean_sql_ident(rm.group('new'))}"
        if old_k in tables:
            st = tables.pop(old_k)
            st.source_file = rel_file
            st.line = lineno
            tables[new_k] = st


def _collect_refs_in_subtree(raw: bytes, node: Any, consts: dict[str, str]) -> set[str]:
    refs: set[str] = set()
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "call_expression":
            fn = cur.child_by_field_name("function")
            args_n = cur.child_by_field_name("arguments")
            if fn is not None and fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                if prop is not None and _node_text(raw, prop) == "references" and args_n is not None:
                    args = [c for c in args_n.named_children]
                    if args:
                        s = _static_str_arg(raw, args[0], consts)
                        if s and "." in s:
                            refs.add(_qualify_table_key(s.split(".", 1)[0]))
        stack.extend(cur.children)
    return refs


def _process_chain_cst(
    raw: bytes,
    call_node: Any,
    rel_file: str,
    consts: dict[str, str],
    schema_vars: dict[str, str],
    tables: dict[str, _KyselyTableState],
    sql_guards: dict[str, tuple[str, int]],
    notes: list[str],
) -> bool:
    """Process one call chain inside `up`; return True if valid/resolved, False on unresolved DDL."""
    steps = _call_chain(raw, call_node)
    if not steps:
        return True
    active_schema = "public"
    first_fn = steps[0][3].child_by_field_name("function")
    if first_fn is not None and first_fn.type == "member_expression":
        root_obj = first_fn.child_by_field_name("object")
        if root_obj is not None and root_obj.type == "identifier":
            active_schema = schema_vars.get(_node_text(raw, root_obj), "public")

    current_tbl: str | None = None
    mode: str | None = None
    unresolved = False

    for mname, args, lineno, step_node in steps:
        if mname == "withSchema" and args:
            s = _static_str_arg(raw, args[0], consts)
            if s:
                active_schema = s.lower()
        elif mname == "createTable":
            mode = "create"
            tname = _static_str_arg(raw, args[0] if args else None, consts)
            if not tname:
                notes.append(f"Unresolved dynamic Kysely createTable in {rel_file}:{lineno}.")
                unresolved = True
                current_tbl = None
                continue
            current_tbl = _qualify_table_key(tname, active_schema)
            if is_migration_meta_table(current_tbl) or current_tbl in _KYSELY_MIGRATION_TABLE_SET:
                current_tbl = None
                continue
            tables[current_tbl] = _KyselyTableState(
                source_file=rel_file,
                line=lineno,
                columns=[],
                fks=_collect_refs_in_subtree(raw, call_node, consts),
            )
        elif mname == "alterTable":
            mode = "alter"
            tname = _static_str_arg(raw, args[0] if args else None, consts)
            if not tname:
                notes.append(f"Unresolved dynamic Kysely alterTable in {rel_file}:{lineno}.")
                unresolved = True
                current_tbl = None
                continue
            current_tbl = _qualify_table_key(tname, active_schema)
            if current_tbl in tables:
                tables[current_tbl].fks.update(_collect_refs_in_subtree(raw, call_node, consts))
        elif mname == "dropTable":
            mode = "drop"
            tname = _static_str_arg(raw, args[0] if args else None, consts)
            if not tname:
                notes.append(f"Unresolved dynamic Kysely dropTable in {rel_file}:{lineno}.")
                unresolved = True
                continue
            tables.pop(_qualify_table_key(tname, active_schema), None)
        elif mname == "addColumn" and current_tbl and current_tbl in tables and args:
            col = _static_str_arg(raw, args[0], consts)
            if col and col not in tables[current_tbl].columns:
                tables[current_tbl].columns.append(col)
        elif mname == "dropColumn" and current_tbl and current_tbl in tables and args:
            col = _static_str_arg(raw, args[0], consts)
            if col and col in tables[current_tbl].columns:
                tables[current_tbl].columns.remove(col)
        elif mname == "renameColumn" and current_tbl and current_tbl in tables and len(args) >= 2:
            old_c = _static_str_arg(raw, args[0], consts)
            new_c = _static_str_arg(raw, args[1], consts)
            if old_c and new_c:
                cols = tables[current_tbl].columns
                if old_c in cols:
                    cols[cols.index(old_c)] = new_c
                elif new_c not in cols:
                    cols.append(new_c)
        elif mname == "addForeignKeyConstraint" and current_tbl and current_tbl in tables and len(args) >= 3:
            ref_tbl = _static_str_arg(raw, args[2], consts)
            if ref_tbl:
                tables[current_tbl].fks.add(_qualify_table_key(ref_tbl, active_schema))
        elif mname == "renameTo" and mode == "alter" and current_tbl and args:
            new_name = _static_str_arg(raw, args[0], consts)
            if not new_name:
                notes.append(f"Unresolved dynamic Kysely renameTo in {rel_file}:{lineno}.")
                unresolved = True
                continue
            new_key = _qualify_table_key(new_name, active_schema)
            if current_tbl in tables:
                st = tables.pop(current_tbl)
                st.source_file = rel_file
                st.line = lineno
                tables[new_key] = st
            else:
                tables[new_key] = _KyselyTableState(source_file=rel_file, line=lineno)
            current_tbl = new_key

    # Execute `sql` template tags attached to `.execute(db)` or `db.executeQuery(...)`
    sql_fn = steps[-1][3].child_by_field_name("function")
    if steps[-1][0] in ("execute", "compile") and sql_fn is not None:
        obj = sql_fn.child_by_field_name("object")
        if obj is not None and obj.type == "call_expression":
            inner_fn = obj.child_by_field_name("function")
            if inner_fn is not None and _node_text(raw, inner_fn).startswith("sql"):
                tmpl_n = next((c for c in obj.children if c.type == "template_string"), None)
                sql_lit = _template_sql_literal(raw, tmpl_n or obj.child_by_field_name("arguments"))
                if sql_lit:
                    _exec_ddl_sql(sql_lit, rel_file, steps[-1][2], tables, sql_guards)
        elif obj is not None and obj.type == "template_string":
            sql_lit = _template_sql_literal(raw, obj)
            if sql_lit:
                _exec_ddl_sql(sql_lit, rel_file, steps[-1][2], tables, sql_guards)
    return not unresolved


def _walk_up_scope_cst(
    raw: bytes,
    scope: Any,
    rel_file: str,
    consts: dict[str, str],
    helpers: dict[str, Any],
    visited_helpers: set[str],
    tables: dict[str, _KyselyTableState],
    sql_guards: dict[str, tuple[str, int]],
    notes: list[str],
) -> bool:
    ok = True
    schema_vars: dict[str, str] = {}

    def walk(node: Any) -> None:
        nonlocal ok
        if node.type == "variable_declarator":
            nm = node.child_by_field_name("name")
            val = node.child_by_field_name("value")
            if nm is not None and val is not None:
                vname = _node_text(raw, nm)
                txt = _node_text(raw, val)
                wm = re.search(r"\.withSchema\(\s*(['\"`])([^'\"`]+)\1\s*\)", txt)
                if wm:
                    schema_vars[vname] = wm.group(2).lower()
                elif ".schema" in txt:
                    schema_vars[vname] = "public"
                sval = _static_str_arg(raw, val, consts)
                if sval is not None:
                    consts[vname] = sval
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "identifier":
                fname = _node_text(raw, fn)
                if fname == "sql":
                    # Handled by enclosing `.execute(...)` or standalone sql``? Only treat executed sql``.
                    pass
                elif fname in helpers and fname not in visited_helpers:
                    visited_helpers.add(fname)
                    if not _walk_up_scope_cst(
                        raw, helpers[fname], rel_file, consts, helpers, visited_helpers, tables, sql_guards, notes
                    ):
                        ok = False
            steps = _call_chain(raw, node)
            if any(
                m in ("createTable", "alterTable", "dropTable", "renameTo", "execute")
                for m, _, _, _ in steps
            ):
                if not _process_chain_cst(raw, node, rel_file, consts, schema_vars, tables, sql_guards, notes):
                    ok = False
                return
        for ch in node.children:
            walk(ch)

    walk(scope)
    return ok


def _extract_brace_block(text: str, start_idx: int) -> str:
    open_idx = text.find("{", start_idx)
    if open_idx == -1:
        return ""
    depth = 0
    in_str: str | None = None
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"', "`"):
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[open_idx : i + 1]
        i += 1
    return text[open_idx:]


def _replay_up_regex_fallback(
    text: str,
    rel_file: str,
    tables: dict[str, _KyselyTableState],
    sql_guards: dict[str, tuple[str, int]],
) -> None:
    up_m = _UP_DEF_RE.search(text)
    if not up_m:
        return
    up_text = _extract_brace_block(text, up_m.end()) or text[up_m.start() :]
    if not up_text:
        return
    # Inline same-file helper functions invoked by up() so regex fallback matches CST helper coverage.
    extra_helpers: list[str] = []
    for hm in re.finditer(r"(?:^|\n)[ \t]*(?:export\s+)?(?:async\s+)?function\s+(?P<fn>[A-Za-z_$][\w$]*)\s*\(", text):
        fname = hm.group("fn")
        if fname not in ("up", "down") and re.search(rf"\b{re.escape(fname)}\s*\(", up_text):
            body = _extract_brace_block(text, hm.end())
            if body:
                extra_helpers.append(body)
    replay_text = "\n".join([*extra_helpers, up_text])
    for cm in re.finditer(
        r"""(?:withSchema\(\s*['"](?P<sch>[^'"]+)['"]\s*\)\s*)?\.createTable\(\s*['"](?P<tbl>[^'"]+)['"]\s*\)""",
        replay_text,
    ):
        key = _qualify_table_key(cm.group("tbl"), cm.group("sch") or "public")
        if is_migration_meta_table(key) or key in _KYSELY_MIGRATION_TABLE_SET:
            continue
        lineno = replay_text.count("\n", 0, cm.start()) + 1
        chain_body = replay_text[cm.end() : cm.end() + 2400].split(".execute(", 1)[0]
        cols = [
            am.group("col")
            for am in re.finditer(r"""\.addColumn\(\s*['"](?P<col>[^'"]+)['"]""", chain_body)
        ]
        fks = {
            _qualify_table_key(rf.group("ref").split(".", 1)[0])
            for rf in re.finditer(r"""\.references\(\s*['"](?P<ref>[^'"]+\.[^'"]+)['"]""", chain_body)
        }
        tables[key] = _KyselyTableState(source_file=rel_file, line=lineno, columns=cols[:40], fks=fks)
    for alt in re.finditer(
        r"""\.alterTable\(\s*['"](?P<tbl>[^'"]+)['"]\s*\)(?P<chain>[\s\S]{0,1800}?)\.execute\(""",
        replay_text,
    ):
        cur_k = _qualify_table_key(alt.group("tbl"))
        chain = alt.group("chain")
        lineno = replay_text.count("\n", 0, alt.start()) + 1
        for op in re.finditer(
            r"""\.(?P<kind>addColumn|dropColumn|renameColumn|renameTo)\(\s*(?P<args>[^)]*)\)""",
            chain,
        ):
            kind = op.group("kind")
            lits = re.findall(r"""['"]([^'"]+)['"]""", op.group("args"))
            if kind == "addColumn" and lits and cur_k in tables and lits[0] not in tables[cur_k].columns:
                tables[cur_k].columns.append(lits[0])
            elif kind == "dropColumn" and lits and cur_k in tables and lits[0] in tables[cur_k].columns:
                tables[cur_k].columns.remove(lits[0])
            elif kind == "renameColumn" and len(lits) >= 2 and cur_k in tables:
                cols = tables[cur_k].columns
                if lits[0] in cols:
                    cols[cols.index(lits[0])] = lits[1]
                elif lits[1] not in cols:
                    cols.append(lits[1])
            elif kind == "renameTo" and lits:
                new_k = _qualify_table_key(lits[0])
                if cur_k in tables:
                    st = tables.pop(cur_k)
                    st.source_file = rel_file
                    st.line = lineno
                    tables[new_k] = st
                else:
                    tables[new_k] = _KyselyTableState(source_file=rel_file, line=lineno)
                cur_k = new_k
    for dm in re.finditer(r"""\.dropTable\(\s*['"](?P<tbl>[^'"]+)['"]\s*\)""", replay_text):
        tables.pop(_qualify_table_key(dm.group("tbl")), None)
    for sm in re.finditer(r"""sql`(?P<sql>[\s\S]*?)`\s*\.execute\(""", replay_text):
        lineno = replay_text.count("\n", 0, sm.start()) + 1
        _exec_ddl_sql(sm.group("sql"), rel_file, lineno, tables, sql_guards)


def discover_kysely_migrations(repo_root: Path, backend_subdir: str) -> list[Path]:
    """Return sorted Kysely migration files under `migrations` directories."""
    base_dir = (repo_root / backend_subdir).resolve() if backend_subdir not in ("", ".") else repo_root.resolve()
    roots = [base_dir] if base_dir == repo_root.resolve() else [base_dir, repo_root.resolve()]
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file() or p.suffix not in _MIG_EXTS:
                continue
            if any(part in _SKIP_PARTS for part in p.parts):
                continue
            if p.name.endswith((".d.ts", ".test.ts", ".spec.ts", ".e2e-spec.ts")):
                continue
            if "migrations" not in p.parts:
                continue
            try:
                head_txt = p.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            if not (_UP_DEF_RE.search(head_txt) and _MIG_MARKER_RE.search(head_txt)):
                continue
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                found.append(rp)
    found.sort(key=lambda p: (p.name, str(p)))
    return found


def detect_kysely_camel_case_plugin(repo_root: Path, backend_subdir: str) -> bool:
    """Return True only when backend non-test sources configure Kysely `CamelCasePlugin`."""
    base_dir = (repo_root / backend_subdir).resolve() if backend_subdir not in ("", ".") else repo_root.resolve()
    if not base_dir.is_dir():
        return False
    for p in base_dir.rglob("*"):
        if not p.is_file() or p.suffix not in _MIG_EXTS:
            continue
        if any(part in _SKIP_PARTS for part in p.parts):
            continue
        if p.name.endswith((".d.ts", ".test.ts", ".spec.ts", ".e2e-spec.ts")):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        if _CAMEL_PLUGIN_RE.search(txt) and ("new CamelCasePlugin" in txt or "kysely" in txt):
            return True
    return False


def _build_kysely_table_symbol_map(tbl_keys: list[str], uses_camel_case: bool) -> dict[str, str]:
    sym_map: dict[str, str] = {}
    for tk in tbl_keys:
        nid = f"t:{tk}"
        sym_map[tk] = nid
        base = tk.split(".", 1)[1] if "." in tk else tk
        sym_map.setdefault(base, nid)
        if uses_camel_case:
            camel_base = _snake_to_camel(base)
            if camel_base != base:
                sym_map.setdefault(camel_base, nid)
                if "." in tk:
                    sch = tk.split(".", 1)[0]
                    sym_map.setdefault(f"{sch}.{camel_base}", nid)
    return sym_map


class KyselySchemaAdapter:
    """Extracts physical tables & guards from executed Kysely `up()` migrations."""

    name = "kysely-migrations"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        root = repo_root.resolve()
        mig_files = discover_kysely_migrations(root, backend_subdir)
        uses_camel_case = detect_kysely_camel_case_plugin(root, backend_subdir)

        tables: dict[str, _KyselyTableState] = {}
        sql_guards: dict[str, tuple[str, int]] = {}
        notes: list[str] = []
        findings: list[RawCandidateFinding] = []
        coverage_complete = True

        parser = _get_parser("ts") if has_treesitter() else None
        for mfile in mig_files:
            rel_file = mfile.relative_to(root).as_posix()
            try:
                text = mfile.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            if parser is not None:
                raw = text.encode("utf-8")
                tree = parser.parse(raw)
                consts, ups, helpers = _collect_migration_scopes_cst(raw, tree.root_node)
                visited_helpers: set[str] = set()
                for up_body in ups:
                    ok = _walk_up_scope_cst(
                        raw,
                        up_body,
                        rel_file,
                        dict(consts),
                        helpers,
                        visited_helpers,
                        tables,
                        sql_guards,
                        notes,
                    )
                    if not ok:
                        coverage_complete = False
            else:
                _replay_up_regex_fallback(text, rel_file, tables, sql_guards)

        sorted_keys = sorted(tables.keys())
        table_symbol_map = _build_kysely_table_symbol_map(sorted_keys, uses_camel_case)
        nodes: list[AtlasNode] = []
        for tk in sorted_keys:
            st = tables[tk]
            nid = f"t:{tk}"
            fk_note = (
                f" FKs: {', '.join(sorted(st.fks))}."
                if st.fks
                else ""
            )
            nodes.append(
                AtlasNode(
                    id=nid,
                    tier="truth",
                    subkind="table",
                    label=tk,
                    source_file=st.source_file,
                    line=st.line,
                    status="clean",
                    role=infer_table_role(tk),
                    cluster=tk.split("_", 1)[0] if "_" in tk else "core",
                    summary=f"Kysely migration table `{tk}`.{fk_note}",
                    columns=st.columns[:40],
                )
            )

        function_symbol_map: dict[str, str] = {}
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
                    summary=f"Kysely SQL migration function / trigger `{gk}`.",
                )
            )

        if uses_camel_case:
            notes.append("Kysely CamelCasePlugin detected: snake_case physical tables mapped to camelCase query names.")
        else:
            notes.append("Kysely CamelCasePlugin not detected: only exact physical table names are mapped.")

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            for tk, st in sorted(tables.items()):
                if tk not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tk}",
                            source_file=st.source_file,
                            line=st.line,
                            title=f"Kysely table `{tk}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tk}`.",
                            remediation="Run pending Kysely migrations on the target database.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            notes=notes,
            observation_source=obs_source,
            coverage_complete=coverage_complete,
        )
