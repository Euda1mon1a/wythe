"""Tier 1 Adapter: `@immich/sql-tools` Decorator Schema & Registered SQL Functions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import infer_table_role, probe_live_catalog_tables
from app.adapters.kysely_schema import (
    _build_kysely_table_symbol_map,
    _qualify_table_key,
    detect_kysely_camel_case_plugin,
)
from app.adapters.treesitter_engine import _get_parser, has_treesitter
from app.adapters.ts_workspace import WorkspaceResolver, resolve_string_expr
from app.schemas.atlas import AtlasNode

_SKIP_PARTS = frozenset(
    {"node_modules", ".git", ".next", ".svelte-kit", "dist", "build", "__pycache__", "machine-learning", "web", "frontend", "mobile", "open-api", "e2e", "test", "tests"}
)
_SRC_EXTS = frozenset({".ts", ".mts"})
_COLUMN_DECS = frozenset(
    {"Column", "PrimaryColumn", "PrimaryGeneratedColumn", "PrimaryGeneratedUuidV7Column", "CreateDateColumn", "UpdateDateColumn", "DeleteDateColumn", "CreateIdColumn", "UpdateIdColumn", "ForeignKeyColumn"}
)
_TRIGGER_DECS = frozenset(
    {"UpdatedAtTrigger", "AfterInsertTrigger", "AfterUpdateTrigger", "AfterDeleteTrigger", "BeforeUpdateTrigger", "TriggerFunction"}
)
_CONSTRAINT_DECS = frozenset({"Index", "Unique", "Check"})
_LIT_STR_RE = re.compile(r"""^(?P<q>['"`])(?P<val>[^'"`\\]*)(?P=q)$""")
_OBJ_NAME_RE = re.compile(r"""\bname\s*:\s*(?P<expr>'[^'\\]*'|"[^"\\]*"|`[^`$\\]*`|[A-Za-z_$][\w$.]*)""")
_OBJ_SCHEMA_RE = re.compile(r"""\bschema\s*:\s*(?P<expr>'[^'\\]*'|"[^"\\]*"|`[^`$\\]*`|[A-Za-z_$][\w$.]*)""")
_OBJ_EXPR_RE = re.compile(r"""\bexpression\s*:\s*(?P<expr>'[^'\\]*'|"[^"\\]*"|`[^`$\\]*`|[A-Za-z_$][\w$.]*)""")
_FK_ARROW_RE = re.compile(r"""\(\s*\)\s*=>\s*(?P<cls>[A-Za-z_$][\w$]*)""")
_FK_REF_TBL_RE = re.compile(r"""\breferenceTable\s*:\s*\(\s*\)\s*=>\s*(?P<cls>[A-Za-z_$][\w$]*)""")
_TRIG_FN_RE = re.compile(r"""\bfunction\s*:\s*(?P<fn>[A-Za-z_$][\w$]*)""")
_REG_FN_RE = re.compile(
    r"""(?:export\s+(?:const|let|var)\s+(?P<ident>[A-Za-z_$][\w$]*)\s*=\s*)?registerFunction\s*\(\s*\{(?P<body>[\s\S]{0,600}?)\bname\s*:\s*['"](?P<name>[A-Za-z_]\w*)['"]"""
)
_DEC_HEAD_RE = re.compile(r"""@(?P<name>[A-Za-z_$][\w$]*)\s*\(""")
_CLASS_HEAD_RE = re.compile(r"""\bclass\s+(?P<name>[A-Za-z_$][\w$]*)[^{;]*\{""")
_PROP_DECL_RE = re.compile(r"""^\s*(?:readonly\s+)?(?P<prop>[A-Za-z_$][\w$]*)\s*[!?]?\s*:""", re.MULTILINE)


@dataclass
class _SqlToolsTableState:
    table_key: str
    class_name: str
    source_file: str
    line: int
    columns: list[str] = field(default_factory=list)
    fk_classes: list[tuple[str, str, int]] = field(default_factory=list)
    indexes: int = 0
    uniques: int = 0
    checks: int = 0
    triggers: list[tuple[str, str | None, int]] = field(default_factory=list)


def discover_sql_tools_schema_files(repo_root: Path, backend_subdir: str) -> tuple[list[Path], list[Path]]:
    """Return `(table_files, function_files)` for `@immich/sql-tools` decorator declarations."""
    root = repo_root.resolve()
    be_dir = root if backend_subdir in ("", ".") else (root / backend_subdir).resolve()
    roots = [be_dir] if be_dir.is_dir() else []
    if root != be_dir:
        roots.append(root)
    table_files: list[Path] = []
    fn_files: list[Path] = []
    seen_t: set[Path] = set()
    seen_f: set[Path] = set()
    for base in roots:
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.suffix not in _SRC_EXTS:
                continue
            rel_parts = p.relative_to(root).parts
            if any(part in _SKIP_PARTS for part in rel_parts):
                continue
            if p.name.endswith((".d.ts", ".test.ts", ".spec.ts", ".e2e-spec.ts")):
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            rp = p.resolve()
            rel_str = rp.relative_to(root).as_posix()
            has_pkg = "@immich/sql-tools" in txt or "schema/tables" in rel_str
            if "@Table(" in txt and has_pkg and rp not in seen_t:
                seen_t.add(rp)
                table_files.append(rp)
            if "registerFunction(" in txt and "@immich/sql-tools" in txt and rp not in seen_f:
                seen_f.add(rp)
                fn_files.append(rp)
    return table_files, fn_files


def _find_matching_delim(txt: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    quote: str | None = None
    i, n = open_idx, len(txt)
    while i < n:
        ch = txt[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if quote == "`" and ch == "$" and i + 1 < n and txt[i + 1] == "{":
                i = _find_matching_delim(txt, i + 1, "{", "}")
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _resolve_expr(expr: str, fpath: Path, resolver: WorkspaceResolver) -> str | None:
    s = expr.strip()
    m = _LIT_STR_RE.match(s)
    if m:
        return m.group("val")
    return resolve_string_expr(s, fpath, resolver)


def _apply_class_decorators(
    decs: list[tuple[str, str, int]],
    cls_name: str,
    cls_line: int,
    fpath: Path,
    rel_file: str,
    resolver: WorkspaceResolver,
    notes: list[str],
) -> tuple[_SqlToolsTableState | None, bool]:
    """Parse stacked class decorators; returns `(table_state_or_None, table_unresolved)`."""
    table_arg: tuple[str, int] | None = None
    fk_classes: list[tuple[str, str, int]] = []
    triggers: list[tuple[str, str | None, int]] = []
    indexes = uniques = checks = 0
    for dname, raw_arg, dline in decs:
        arg = raw_arg.strip()
        if dname == "Table":
            table_arg = (arg, dline)
        elif dname == "ForeignKeyConstraint":
            rm = _FK_REF_TBL_RE.search(arg)
            if rm:
                fk_classes.append((rm.group("cls"), rel_file, dline))
            else:
                notes.append(f"Unsupported @ForeignKeyConstraint argument `{arg[:80]}` in {rel_file}:{dline} (partial evidence).")
        elif dname in _TRIGGER_DECS:
            fm = _TRIG_FN_RE.search(arg)
            triggers.append((dname, fm.group("fn") if fm else None, dline))
        elif dname in _CONSTRAINT_DECS:
            if dname == "Index":
                indexes += 1
            elif dname == "Unique":
                uniques += 1
            else:
                checks += 1
            if not arg.startswith("{"):
                if not (_LIT_STR_RE.match(arg) or (arg and _resolve_expr(arg, fpath, resolver) is not None)):
                    notes.append(f"Unresolved @{dname} decorator argument `{arg[:80]}` in {rel_file}:{dline} (partial evidence).")
            else:
                nm = _OBJ_NAME_RE.search(arg)
                if nm and _resolve_expr(nm.group("expr"), fpath, resolver) is None:
                    notes.append(f"Unresolved @{dname} name expression `{nm.group('expr')}` in {rel_file}:{dline} (partial evidence).")
                if dname == "Check":
                    em = _OBJ_EXPR_RE.search(arg)
                    if em and _resolve_expr(em.group("expr"), fpath, resolver) is None:
                        notes.append(f"Unresolved @Check expression `{em.group('expr')}` in {rel_file}:{dline} (partial evidence).")
    if table_arg is None:
        return None, False
    t_arg, t_line = table_arg
    raw_name: str | None = None
    schema_name = "public"
    if t_arg.startswith("{"):
        nm = _OBJ_NAME_RE.search(t_arg)
        if nm:
            raw_name = _resolve_expr(nm.group("expr"), fpath, resolver)
        sm = _OBJ_SCHEMA_RE.search(t_arg)
        if sm:
            resolved_s = _resolve_expr(sm.group("expr"), fpath, resolver)
            if resolved_s:
                schema_name = resolved_s
    elif t_arg:
        raw_name = _resolve_expr(t_arg, fpath, resolver)
    if not raw_name:
        notes.append(f"Unresolved @Table argument `{t_arg[:80]}` on class `{cls_name}` in {rel_file}:{t_line} (partial evidence).")
        return None, True
    tk = _qualify_table_key(raw_name, schema_name)
    return _SqlToolsTableState(
        table_key=tk,
        class_name=cls_name,
        source_file=rel_file,
        line=cls_line,
        fk_classes=fk_classes,
        indexes=indexes,
        uniques=uniques,
        checks=checks,
        triggers=triggers,
    ), False


def _parse_dec_header(raw_txt: str, start_line: int) -> tuple[str, str, int] | None:
    m = _DEC_HEAD_RE.match(raw_txt.lstrip())
    if not m:
        return None
    s = raw_txt.lstrip()
    open_p = s.find("(", m.end("name") - m.start())
    if open_p < 0:
        return None
    close_p = _find_matching_delim(s, open_p, "(", ")")
    return m.group("name"), s[open_p + 1 : max(open_p + 1, close_p - 1)], start_line


def _record_prop_decorators(
    decs: list[tuple[str, str, int]],
    prop_name: str,
    state: _SqlToolsTableState,
    fpath: Path,
    rel_file: str,
    resolver: WorkspaceResolver,
    notes: list[str],
) -> None:
    col_name: str | None = None
    for dname, raw_arg, dline in decs:
        if dname in _COLUMN_DECS:
            col_name = prop_name
            arg = raw_arg.strip()
            if arg.startswith("{"):
                nm = _OBJ_NAME_RE.search(arg)
                if nm:
                    resolved = _resolve_expr(nm.group("expr"), fpath, resolver)
                    if resolved:
                        col_name = resolved
            if dname == "ForeignKeyColumn":
                fm = _FK_ARROW_RE.search(arg)
                if fm:
                    state.fk_classes.append((fm.group("cls"), rel_file, dline))
                else:
                    notes.append(f"Unsupported @ForeignKeyColumn target `{arg[:80]}` on `{state.class_name}.{prop_name}` in {rel_file}:{dline} (partial evidence).")
    if col_name and col_name not in state.columns:
        state.columns.append(col_name)


def _parse_table_file_cst(
    raw: bytes,
    root_node: Any,
    fpath: Path,
    rel_file: str,
    resolver: WorkspaceResolver,
    notes: list[str],
) -> tuple[list[_SqlToolsTableState], bool]:
    results: list[_SqlToolsTableState] = []
    unresolved = False

    def _txt(n: Any) -> str:
        return raw[n.start_byte : n.end_byte].decode("utf-8", errors="replace")

    def _node_decs(node: Any) -> list[tuple[str, str, int]]:
        decs: list[tuple[str, str, int]] = []
        for ch in node.children:
            if ch.type == "decorator":
                parsed = _parse_dec_header(_txt(ch), ch.start_point[0] + 1)
                if parsed is not None:
                    decs.append(parsed)
        return decs

    def _handle_class(cls_node: Any, outer_decs: list[tuple[str, str, int]]) -> None:
        nonlocal unresolved
        nm = cls_node.child_by_field_name("name")
        body = cls_node.child_by_field_name("body")
        if nm is None or body is None:
            return
        all_decs = [*outer_decs, *_node_decs(cls_node)]
        st, had_unres = _apply_class_decorators(all_decs, _txt(nm), cls_node.start_point[0] + 1, fpath, rel_file, resolver, notes)
        if had_unres:
            unresolved = True
        if st is None:
            return
        pending: list[tuple[str, str, int]] = []
        for ch in body.named_children:
            if ch.type == "decorator":
                parsed = _parse_dec_header(_txt(ch), ch.start_point[0] + 1)
                if parsed is not None:
                    pending.append(parsed)
                continue
            if ch.type in ("public_field_definition", "property_declaration", "field_definition"):
                pdecs = [*pending, *_node_decs(ch)]
                pending = []
                pnm = ch.child_by_field_name("name")
                if pnm is not None and pdecs:
                    _record_prop_decorators(pdecs, _txt(pnm).strip("\"'"), st, fpath, rel_file, resolver, notes)
            else:
                pending = []
        results.append(st)

    for ch in root_node.named_children:
        if ch.type == "class_declaration":
            _handle_class(ch, [])
        elif ch.type == "export_statement":
            edecs = _node_decs(ch)
            for sub in ch.named_children:
                if sub.type == "class_declaration":
                    _handle_class(sub, edecs)
    return results, unresolved


def _parse_table_file_fallback(
    txt: str,
    fpath: Path,
    rel_file: str,
    resolver: WorkspaceResolver,
    notes: list[str],
) -> tuple[list[_SqlToolsTableState], bool]:
    results: list[_SqlToolsTableState] = []
    unresolved = False
    n = len(txt)
    pos = 0
    while pos < n:
        cm = _CLASS_HEAD_RE.search(txt, pos)
        if not cm:
            break
        cls_name = cm.group("name")
        cls_line = txt.count("\n", 0, cm.start()) + 1
        head_chunk = txt[pos : cm.start()]
        decs: list[tuple[str, str, int]] = []
        scan_i = 0
        while scan_i < len(head_chunk):
            dm = _DEC_HEAD_RE.search(head_chunk, scan_i)
            if not dm:
                break
            open_p = dm.end() - 1
            close_p = _find_matching_delim(head_chunk, open_p, "(", ")")
            decs.append((dm.group("name"), head_chunk[open_p + 1 : max(open_p + 1, close_p - 1)], txt.count("\n", 0, pos + dm.start()) + 1))
            scan_i = close_p
        body_open = cm.end() - 1
        body_close = _find_matching_delim(txt, body_open, "{", "}")
        st, had_unres = _apply_class_decorators(decs, cls_name, cls_line, fpath, rel_file, resolver, notes)
        if had_unres:
            unresolved = True
        if st is not None:
            body_txt = txt[body_open + 1 : max(body_open + 1, body_close - 1)]
            pending: list[tuple[str, str, int]] = []
            bpos = 0
            while bpos < len(body_txt):
                dm = _DEC_HEAD_RE.search(body_txt, bpos)
                if not dm:
                    break
                op = dm.end() - 1
                cl = _find_matching_delim(body_txt, op, "(", ")")
                pending.append((dm.group("name"), body_txt[op + 1 : max(op + 1, cl - 1)], txt.count("\n", 0, body_open + 1 + dm.start()) + 1))
                rest = body_txt[cl:]
                if not rest.lstrip().startswith("@"):
                    pm = _PROP_DECL_RE.match(rest.lstrip())
                    if pm:
                        _record_prop_decorators(pending, pm.group("prop"), st, fpath, rel_file, resolver, notes)
                    pending = []
                bpos = cl
            results.append(st)
        pos = body_close
    return results, unresolved


class SqlToolsSchemaAdapter:
    """Extracts physical tables, columns, FKs, and registered SQL functions from `@immich/sql-tools`."""

    name = "sql-tools"

    def extract(self, repo_root: Path, backend_subdir: str, pg_dsn: str | None = None) -> TruthExtractionResult:
        root = repo_root.resolve()
        be_dir = root if backend_subdir in ("", ".") else (root / backend_subdir).resolve()
        resolver = WorkspaceResolver.build(root, (be_dir,))
        uses_camel_case = detect_kysely_camel_case_plugin(root, backend_subdir)
        table_files, fn_files = discover_sql_tools_schema_files(root, backend_subdir)
        parser = _get_parser("ts") if has_treesitter() else None

        tables: dict[str, _SqlToolsTableState] = {}
        class_to_tk: dict[str, str] = {}
        notes: list[str] = []
        findings: list[RawCandidateFinding] = []
        coverage_complete = True

        for tfile in table_files:
            rel_file = tfile.relative_to(root).as_posix()
            try:
                text = tfile.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            if parser is not None:
                raw = text.encode("utf-8")
                extracted, unres = _parse_table_file_cst(raw, parser.parse(raw).root_node, tfile, rel_file, resolver, notes)
            else:
                extracted, unres = _parse_table_file_fallback(text, tfile, rel_file, resolver, notes)
            if unres:
                coverage_complete = False
            for st in extracted:
                tables.setdefault(st.table_key, st)
                class_to_tk[st.class_name] = st.table_key

        fn_ident_to_key: dict[str, str] = {}
        sql_funcs: dict[str, tuple[str, int]] = {}
        for ffile in fn_files:
            rel_file = ffile.relative_to(root).as_posix()
            try:
                text = ffile.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            for fm in _REG_FN_RE.finditer(text):
                fn_name = fm.group("name").lower()
                sql_funcs.setdefault(fn_name, (rel_file, text.count("\n", 0, fm.start()) + 1))
                if fm.group("ident"):
                    fn_ident_to_key[fm.group("ident")] = fn_name

        db_readers: dict[str, dict[str, tuple[str, str, str]]] = {}
        nodes: list[AtlasNode] = []
        sorted_keys = sorted(tables.keys())
        table_symbol_map = _build_kysely_table_symbol_map(sorted_keys, uses_camel_case)
        for cls_name, tk in sorted(class_to_tk.items()):
            table_symbol_map.setdefault(cls_name, f"t:{tk}")

        for tk in sorted_keys:
            st = tables[tk]
            nid = f"t:{tk}"
            fk_names: list[str] = []
            for target_cls, ev_file, _ev_line in st.fk_classes:
                target_tk = class_to_tk.get(target_cls)
                if target_tk and target_tk != tk:
                    fk_names.append(target_tk)
                    db_readers.setdefault(f"t:{target_tk}", {}).setdefault(
                        nid, (ev_file, "guards_truth", f"Foreign key from `{tk}` references `{target_tk}`.")
                    )
            for _trig_kind, trig_fn_ident, _tline in st.triggers:
                if trig_fn_ident and trig_fn_ident in fn_ident_to_key:
                    fn_key = fn_ident_to_key[trig_fn_ident]
                    db_readers.setdefault(nid, {}).setdefault(
                        f"fn:{fn_key}", (st.source_file, "guards_truth", f"Trigger on `{tk}` invokes `{fn_key}()`.")
                    )
            meta_parts: list[str] = []
            if fk_names:
                meta_parts.append(f"FKs: {', '.join(sorted(set(fk_names)))}.")
            if st.indexes or st.uniques or st.checks or st.triggers:
                meta_parts.append(f"Indexes: {st.indexes}, Unique: {st.uniques}, Checks: {st.checks}, Triggers: {len(st.triggers)}.")
            extra = (" " + " ".join(meta_parts)) if meta_parts else ""
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
                    summary=f"@immich/sql-tools table `{tk}`.{extra}",
                    columns=st.columns[:40],
                )
            )

        function_symbol_map: dict[str, str] = {}
        for fn_key, (fsrc, fline) in sorted(sql_funcs.items()):
            fn_id = f"fn:{fn_key}"
            function_symbol_map[fn_key] = fn_id
            nodes.append(
                AtlasNode(
                    id=fn_id,
                    tier="truth",
                    subkind="sql_function",
                    label=f"{fn_key}()",
                    source_file=fsrc,
                    line=fline,
                    status="clean",
                    role="mechanism",
                    cluster="db_guard",
                    summary=f"@immich/sql-tools registered SQL function `{fn_key}`.",
                )
            )

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
                            title=f"@immich/sql-tools table `{tk}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tk}`.",
                            remediation="Run pending database migrations or sync schema declarations.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            notes=notes,
            db_readers=db_readers,
            observation_source=obs_source,
            coverage_complete=coverage_complete,
        )
