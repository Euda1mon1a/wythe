"""TypeScript Kysely query lineage extractor (Tree-sitter CST + regex fallback)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.adapters.base import TruthExtractionResult
from app.adapters.treesitter_engine import _get_parser, has_treesitter
from app.adapters.ts_workspace import WorkspaceResolver, resolve_string_expr

_KYSELY_FILE_RE = re.compile(
    r"""\b(?:from\s+['"]kysely(?:/[^'"]*)?['"]|nestjs-kysely|@InjectKysely|KyselyDB|KyselyTransaction|ExpressionBuilder|dbOrTx|executeTx)\b"""
)
_DB_HANDLE_RE = re.compile(r"^(?:this\.)?(?:db|trx|tx|eb|qb|qc|kysely|kyselyDb|dbOrTx)$")
_FLUENT_METHODS = frozenset({
    "select", "selectAll", "where", "whereRef", "values", "set", "returning", "returningAll",
    "execute", "executeTakeFirst", "executeTakeFirstOrThrow", "compile", "$if", "onConflict",
    "innerJoin", "leftJoin", "rightJoin", "fullJoin", "crossJoin", "withSchema", "with", "withRecursive",
})
_READ_METHODS = frozenset({
    "selectFrom", "innerJoin", "leftJoin", "rightJoin", "fullJoin",
    "innerJoinLateral", "leftJoinLateral", "crossJoin", "crossJoinLateral", "using",
})
_WRITE_METHODS = frozenset({"insertInto", "updateTable", "deleteFrom", "mergeInto"})
_CTE_METHODS = frozenset({"with", "withRecursive"})
_REGEX_OP_RE = re.compile(
    r"""(?P<recv>[A-Za-z_$][\w$.]*)\s*\.\s*(?P<method>selectFrom|insertInto|updateTable|deleteFrom|mergeInto|innerJoin|leftJoin|rightJoin|fullJoin|crossJoin)\(\s*(?P<arg>[^)]+)\)"""
)
_REGEX_CTE_RE = re.compile(r"""\.(?:with|withRecursive)\(\s*['"`](?P<cte>[^'"`(\s]+)""" )
_REGEX_SCHEMA_RE = re.compile(r"""\.withSchema\(\s*['"`](?P<sch>[^'"`]+)['"`]\s*\)""")
_FLUENT_FB_RE = re.compile(r"""\.\s*(?:select|selectAll|where|whereRef|values|set|returning|execute|executeTakeFirst|compile|\$if)\s*\(""")


def _nt(raw: bytes, node: Any) -> str:
    return raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _unwrap(node: Any) -> Any:
    while node.type in ("parenthesized_expression", "as_expression", "type_assertion") and node.named_children:
        node = node.named_children[0]
    return node


def _split_table_alias(spec: str) -> str:
    cleaned = spec.strip().strip('"`').lower()
    if " as " in cleaned:
        cleaned = cleaned.split(" as ", 1)[0].strip()
    elif " " in cleaned:
        cleaned = cleaned.split(None, 1)[0].strip()
    return cleaned.strip('"`')


def _lookup_table_id(raw_spec: str, schema: str, table_symbol_map: dict[str, str]) -> str | None:
    cleaned = raw_spec.strip().strip('"`')
    if " as " in cleaned.lower():
        cleaned = re.split(r"\s+as\s+", cleaned, maxsplit=1, flags=re.IGNORECASE)[0].strip()
    elif " " in cleaned:
        cleaned = cleaned.split(None, 1)[0].strip()
    cleaned = cleaned.strip('"`')
    if not cleaned:
        return None
    if "." in cleaned:
        sch, tbl = cleaned.split(".", 1)
        sch_l, tbl_l = sch.strip().lower(), tbl.strip().lower()
        cands = (f"{sch_l}.{tbl.strip()}", f"{sch_l}.{tbl_l}", tbl.strip(), tbl_l) if sch_l != "public" else (tbl.strip(), tbl_l)
    else:
        sch_l = (schema or "public").lower()
        cands = (f"{sch_l}.{cleaned}", f"{sch_l}.{cleaned.lower()}", cleaned, cleaned.lower()) if sch_l != "public" else (cleaned, cleaned.lower())
    for c in cands:
        if c in table_symbol_map:
            return table_symbol_map[c]
    return None


def _resolve_kysely_table_arg(
    expr_txt: str, file_path: Path, resolver: WorkspaceResolver
) -> tuple[list[str], bool]:
    """Return `(resolved_table_strings, had_unresolved_dynamic)` for a Kysely table argument."""
    raw = expr_txt.strip()
    if not raw:
        return [], False
    if raw.startswith("(") or "=>" in raw or re.match(r"^(?:async\s+)?function\b", raw):
        return [], False
    if raw.startswith("[") and raw.endswith("]"):
        items = [p.strip() for p in raw[1:-1].split(",") if p.strip()]
        out: list[str] = []
        unres = False
        for item in items:
            sub_res, sub_unres = _resolve_kysely_table_arg(item, file_path, resolver)
            out.extend(sub_res)
            unres = unres or sub_unres
        return out, unres
    sqlt = re.fullmatch(r"sql\.table\(\s*(.+)\s*\)", raw)
    if sqlt:
        raw = sqlt.group(1).strip()
    resolved = resolve_string_expr(raw, file_path, resolver)
    if resolved is not None:
        return [resolved], False
    return [], True


def _chain_steps_cst(raw: bytes, call_node: Any) -> tuple[str, list[tuple[str, list[Any], int, Any]]]:
    steps: list[tuple[str, list[Any], int, Any]] = []
    cur: Any | None = call_node
    root_expr: Any | None = None
    while cur is not None:
        while cur.type in ("await_expression", "parenthesized_expression") and cur.named_children:
            cur = cur.named_children[0]
        if cur.type != "call_expression":
            root_expr = cur
            break
        fn = cur.child_by_field_name("function")
        args_n = cur.child_by_field_name("arguments")
        args = [c for c in args_n.named_children] if args_n is not None else []
        lineno = cur.start_point[0] + 1
        if fn is not None and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            steps.append((_nt(raw, prop) if prop is not None else "", args, lineno, cur))
            cur = obj
            root_expr = obj
        else:
            root_expr = cur
            break
    steps.reverse()
    root_txt = _nt(raw, root_expr).strip() if root_expr is not None else ""
    return root_txt, steps


def extract_kysely_table_ops(
    source: str,
    rel_repo: str,
    truth: TruthExtractionResult,
    file_path: Path,
    resolver: WorkspaceResolver,
) -> tuple[set[str], set[str], list[str]]:
    """Extract Kysely table reads/writes and explicit unresolved-table notes."""
    reads: set[str] = set()
    writes: set[str] = set()
    notes: list[str] = []
    if not truth.table_symbol_map and not any(m in source for m in ("selectFrom", "insertInto", "updateTable", "deleteFrom")):
        return reads, writes, notes

    has_file_sig = bool(_KYSELY_FILE_RE.search(source))
    ctes: set[str] = set()
    schema_vars: dict[str, str] = {}
    kysely_vars: set[str] = set()

    if has_treesitter():
        parser = _get_parser("tsx" if file_path.suffix == ".tsx" else "ts")
        if parser is not None:
            raw = source.encode("utf-8")
            tree = parser.parse(raw)
            seen_calls: set[tuple[int, int]] = set()

            def walk(node: Any) -> None:
                if node.type == "variable_declarator":
                    nm_n = node.child_by_field_name("name")
                    val_n = node.child_by_field_name("value")
                    if nm_n is not None and val_n is not None and nm_n.type == "identifier":
                        vname = _nt(raw, nm_n)
                        vtxt = _nt(raw, val_n)
                        wm = _REGEX_SCHEMA_RE.search(vtxt)
                        if wm:
                            schema_vars[vname] = wm.group("sch").lower()
                        if any(m in vtxt for m in ("selectFrom", "insertInto", "updateTable", "deleteFrom", "dbOrTx", "withSchema")):
                            kysely_vars.add(vname)
                if node.type == "call_expression":
                    span = (node.start_byte, node.end_byte)
                    if span not in seen_calls:
                        root_txt, steps = _chain_steps_cst(raw, node)
                        for _, _, _, snode in steps:
                            seen_calls.add((snode.start_byte, snode.end_byte))
                        methods = [m for m, _, _, _ in steps]
                        if any(m in _READ_METHODS or m in _WRITE_METHODS for m in methods):
                            root_clean = root_txt.removeprefix("await ").strip()
                            is_kysely = (
                                bool(_DB_HANDLE_RE.match(root_clean))
                                or root_clean in kysely_vars
                                or root_clean.startswith("dbOrTx(")
                                or (has_file_sig and any(m in _FLUENT_METHODS for m in methods))
                            )
                            if is_kysely:
                                schema = schema_vars.get(root_clean, "public")
                                for mname, args, lineno, _ in steps:
                                    if mname in _CTE_METHODS and args:
                                        cte_s = resolve_string_expr(_nt(raw, _unwrap(args[0])), file_path, resolver)
                                        if cte_s:
                                            ctes.add(cte_s.split("(", 1)[0].strip().lower())
                                    elif mname == "withSchema" and args:
                                        sch_s = resolve_string_expr(_nt(raw, _unwrap(args[0])), file_path, resolver)
                                        if sch_s:
                                            schema = sch_s.lower()
                                    elif (mname in _READ_METHODS or mname in _WRITE_METHODS) and args:
                                        resolved_list, unres = _resolve_kysely_table_arg(
                                            _nt(raw, _unwrap(args[0])), file_path, resolver
                                        )
                                        if unres:
                                            notes.append(f"Unresolved dynamic Kysely table expression in {rel_repo}:{lineno}.")
                                        for tbl_spec in resolved_list:
                                            base_lc = _split_table_alias(tbl_spec)
                                            if base_lc in ctes:
                                                continue
                                            tid = _lookup_table_id(tbl_spec, schema, truth.table_symbol_map)
                                            if tid:
                                                if mname in _WRITE_METHODS:
                                                    writes.add(tid)
                                                else:
                                                    reads.add(tid)
                for ch in node.children:
                    walk(ch)

            walk(tree.root_node)
            return reads, writes, notes

    # Regex fallback when Tree-sitter is disabled
    for cm in _REGEX_CTE_RE.finditer(source):
        ctes.add(cm.group("cte").strip().lower())
    for om in _REGEX_OP_RE.finditer(source):
        recv = om.group("recv").strip()
        tail_slice = source[om.end() : om.end() + 200]
        is_kysely = bool(_DB_HANDLE_RE.match(recv)) or (has_file_sig and bool(_FLUENT_FB_RE.search(tail_slice)))
        if not is_kysely:
            continue
        lineno = source.count("\n", 0, om.start()) + 1
        win = source[max(0, om.start() - 120) : om.start()]
        sm = _REGEX_SCHEMA_RE.search(win)
        schema = sm.group("sch").lower() if sm else "public"
        first_arg = om.group("arg").split(",", 1)[0].strip()
        resolved_list, unres = _resolve_kysely_table_arg(first_arg, file_path, resolver)
        if unres:
            notes.append(f"Unresolved dynamic Kysely table expression in {rel_repo}:{lineno}.")
        for tbl_spec in resolved_list:
            if _split_table_alias(tbl_spec) in ctes:
                continue
            tid = _lookup_table_id(tbl_spec, schema, truth.table_symbol_map)
            if tid:
                if om.group("method") in _WRITE_METHODS:
                    writes.add(tid)
                else:
                    reads.add(tid)
    return reads, writes, notes
