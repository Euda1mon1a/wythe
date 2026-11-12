"""Optional Tree-sitter Concrete Syntax Tree (CST) grammar engine for non-Python adapters.

When `wythe[treesitter]` is installed (`tree-sitter` + official `tree-sitter-typescript`,
`tree-sitter-javascript`, `tree-sitter-rust`, and `tree-sitter-go` wheels), adapters upgrade
from regex/character scanners to true CST traversal:
  - Preserves `"https://..."` URLs, regex literals, raw strings, and template strings without
    false `//` comment truncation.
  - Resolves TypeScript 5 generic route/HTTP calls (`app.post<Dto>('/orders', ...)`,
    `api.get<Order[]>('/api/orders')`), chained Hono/Express `.basePath()`/`.route()`, and
    distinguishes `import type` from runtime module edges.
  - Resolves multi-scope Rust `axum::Router::nest(...)` subtrees and multi-attribute handlers
    (`#[tracing::instrument]` + `#[post("/orders")]` / `#[tauri::command]`).
  - Resolves nested Go `chi`/`echo` `r.Route("/v1", func(r chi.Router) { ... })` closures.

Set `WYTHE_DISABLE_TREESITTER=1` (or omit the optional extra) to exercise the pure-Python
scanner fallback deterministically.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Any

try:
    import tree_sitter as _ts
    import tree_sitter_go as _ts_go
    import tree_sitter_javascript as _ts_js
    import tree_sitter_rust as _ts_rust
    import tree_sitter_typescript as _ts_typescript

    _TS_IMPORT_OK = True
except ImportError:  # pragma: no cover
    _ts = None  # type: ignore[assignment]
    _ts_go = None  # type: ignore[assignment]
    _ts_js = None  # type: ignore[assignment]
    _ts_rust = None  # type: ignore[assignment]
    _ts_typescript = None  # type: ignore[assignment]
    _TS_IMPORT_OK = False

_HTTP_VERBS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_FETCH_HELPERS = frozenset({"fetch", "ofetch", "$fetch", "useFetch", "useLazyFetch", "apiRequest", "request", "httpClient"})
_CALLEE_WRAPPERS = frozenset({"await_expression", "parenthesized_expression", "non_null_expression"})
_METHOD_RE = re.compile(r"""method\s*:\s*['"](?P<m>GET|POST|PUT|PATCH|DELETE)['"]""", re.IGNORECASE)
_TAURI_READ_PREFIXES = ("get_", "list_", "fetch_", "load_", "find_", "query_", "read_", "detect_", "estimate_", "scope_")


def has_treesitter() -> bool:
    """Return True if official tree-sitter grammar wheels are installed and enabled."""
    if os.environ.get("WYTHE_DISABLE_TREESITTER") == "1" or os.environ.get("TRUTH_ATLAS_DISABLE_TREESITTER") == "1":
        return False
    return _TS_IMPORT_OK


@lru_cache(maxsize=8)
def _get_parser(lang_key: str) -> Any:
    if not _TS_IMPORT_OK:
        return None
    lang_fn = {
        "ts": _ts_typescript.language_typescript,
        "tsx": _ts_typescript.language_tsx,
        "js": _ts_js.language,
        "rust": _ts_rust.language,
        "go": _ts_go.language,
    }[lang_key]
    return _ts.Parser(_ts.Language(lang_fn()))


def blank_comments_cst(source: str, lang_key: str) -> str | None:
    """Blank ONLY real CST comment nodes while preserving exact byte offsets & line numbers."""
    if not has_treesitter():
        return None
    parser = _get_parser(lang_key)
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    buf = bytearray(raw)
    comment_types = {"comment", "line_comment", "block_comment"}

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in comment_types:
            for idx in range(node.start_byte, node.end_byte):
                if buf[idx] != 0x0A:  # preserve '\n'
                    buf[idx] = 0x20
        else:
            stack.extend(node.children)
    return buf.decode("utf-8", errors="replace")


def _unquote_node(raw: bytes, node: Any) -> str:
    txt = raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace").strip()
    if len(txt) >= 2 and txt[0] in ("'", '"', "`") and txt[-1] == txt[0]:
        return txt[1:-1]
    if txt.startswith('r#"') and txt.endswith('"#') and len(txt) >= 5:
        return txt[3:-2]
    return txt


def extract_ts_imports_cst(source: str, *, is_tsx: bool = False) -> tuple[list[str], list[str]] | None:
    """Return `(runtime_import_specs, all_import_specs_including_type_only)` via TS/TSX CST."""
    if not has_treesitter():
        return None
    parser = _get_parser("tsx" if is_tsx else "ts")
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    runtime_specs: list[str] = []
    all_specs: list[str] = []

    for child in tree.root_node.children:
        if child.type in ("import_statement", "export_statement"):
            is_type_only = any(c.type == "type" for c in child.children)
            str_node = next((c for c in child.children if c.type == "string"), None)
            if str_node is not None:
                spec = _unquote_node(raw, str_node)
                if spec:
                    all_specs.append(spec)
                    if not is_type_only:
                        runtime_specs.append(spec)
    return runtime_specs, all_specs


def _resolve_ts_chain_prefix(raw: bytes, expr: Any, var_prefixes: dict[str, str]) -> str:
    if expr.type == "identifier":
        ident = raw[expr.start_byte : expr.end_byte].decode("utf-8", errors="replace")
        return var_prefixes.get(ident, "")
    if expr.type == "call_expression":
        fn_node = expr.children[0] if expr.children else None
        args_node = next((c for c in expr.children if c.type == "arguments"), None)
        if fn_node is not None and fn_node.type == "member_expression" and len(fn_node.children) >= 3:
            obj_node = fn_node.children[0]
            prop_node = fn_node.children[-1]
            prop = raw[prop_node.start_byte : prop_node.end_byte].decode("utf-8", errors="replace")
            parent_pref = _resolve_ts_chain_prefix(raw, obj_node, var_prefixes)
            if prop in ("basePath", "route") and args_node is not None:
                first_str = next((c for c in args_node.children if c.type in ("string", "template_string")), None)
                if first_str is not None:
                    sub = _unquote_node(raw, first_str)
                    return f"{parent_pref.rstrip('/')}/{sub.lstrip('/')}" if sub else parent_pref
            return parent_pref
    return ""


def extract_ts_backend_routes_cst(source: str, mount_prefix: str = "") -> list[tuple[str, str, int]] | None:
    """Extract `(http_method, raw_path, lineno)` for generic/chained Express, Hono, & Fastify CSTs."""
    if not has_treesitter():
        return None
    parser = _get_parser("ts")
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    var_prefixes: dict[str, str] = {}
    found: list[tuple[str, str, int]] = []

    def walk(node: Any) -> None:
        if node.type == "variable_declarator" and len(node.children) >= 3:
            id_node = node.children[0]
            val_node = node.children[-1]
            if id_node.type == "identifier":
                pref = _resolve_ts_chain_prefix(raw, val_node, var_prefixes)
                if pref:
                    vname = raw[id_node.start_byte : id_node.end_byte].decode("utf-8", errors="replace")
                    var_prefixes[vname] = pref
        elif node.type == "call_expression" and node.children:
            fn_node = node.children[0]
            args_node = next((c for c in node.children if c.type == "arguments"), None)
            if fn_node.type == "member_expression" and len(fn_node.children) >= 3 and args_node is not None:
                obj_node = fn_node.children[0]
                prop_node = fn_node.children[-1]
                prop = raw[prop_node.start_byte : prop_node.end_byte].decode("utf-8", errors="replace")
                verb = "DELETE" if prop.lower() == "del" else prop.upper()
                if verb in _HTTP_VERBS:
                    chain_pref = _resolve_ts_chain_prefix(raw, obj_node, var_prefixes)
                    arg_items = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                    first_arg = arg_items[0] if arg_items else None
                    if first_arg is not None and first_arg.type in ("string", "template_string"):
                        sub_p = _unquote_node(raw, first_arg)
                        if sub_p.startswith("/"):
                            full_p = "/".join(p.strip("/") for p in (mount_prefix, chain_pref, sub_p) if p and p.strip("/"))
                            found.append((verb, "/" + full_p, prop_node.start_point[0] + 1))
                    elif chain_pref.startswith("/"):
                        # `router.route('/orders').get(listOrders).post(createOrder)`
                        full_p = "/".join(p.strip("/") for p in (mount_prefix, chain_pref) if p and p.strip("/"))
                        found.append((verb, "/" + full_p, prop_node.start_point[0] + 1))
        for ch in node.children:
            walk(ch)

    walk(tree.root_node)
    return found


_TEMPLATE_HEAD_CONST_RE = re.compile(r"^\$\{\s*(?P<name>[A-Za-z_$][\w$]*)\s*\}")


def resolve_url_const_head(url_val: str, url_consts: dict[str, str] | None) -> str:
    """Expand a leading `${NAME}` when NAME is a same-file string constant holding a path."""
    if not url_consts or not url_val.startswith("${"):
        return url_val
    m = _TEMPLATE_HEAD_CONST_RE.match(url_val)
    if m and m.group("name") in url_consts:
        return url_consts[m.group("name")] + url_val[m.end() :]
    return url_val


_PARAM_CONTAINERS = frozenset(
    {
        "formal_parameters",
        "required_parameter",
        "optional_parameter",
        "rest_pattern",
        "object_pattern",
        "array_pattern",
    }
)


def _collect_cst_pattern_idents(raw: bytes, node: Any, out: set[str]) -> None:
    """Collect identifiers bound by a parameter or destructuring pattern (ignoring types/defaults)."""
    ntype = node.type
    if ntype in ("identifier", "shorthand_property_identifier_pattern"):
        out.add(raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace"))
        return
    if ntype in ("type_annotation", "opting_type_annotation"):
        return
    if ntype == "assignment_pattern":
        left = node.child_by_field_name("left") or (node.named_children[0] if node.named_children else None)
        if left is not None:
            _collect_cst_pattern_idents(raw, left, out)
        return
    if ntype == "pair_pattern":
        val = node.child_by_field_name("value") or (node.named_children[-1] if node.named_children else None)
        if val is not None:
            _collect_cst_pattern_idents(raw, val, out)
        return
    if ntype in ("required_parameter", "optional_parameter"):
        pat = node.child_by_field_name("pattern") or (node.named_children[0] if node.named_children else None)
        if pat is not None:
            _collect_cst_pattern_idents(raw, pat, out)
        return
    if ntype in _PARAM_CONTAINERS:
        for ch in node.named_children:
            _collect_cst_pattern_idents(raw, ch, out)


def extract_ts_http_calls_cst(
    source: str,
    *,
    is_tsx: bool = True,
    url_consts: dict[str, str] | None = None,
) -> list[tuple[str, str, int]] | None:
    """Extract `(http_method, raw_url, lineno)` from TS/TSX CST `call_expression` nodes.

    `url_consts` maps same-file string constants (`const BASE = '/things'`) to their values so
    `` get(`${BASE}/${id}`) `` and `get(BASE)` resolve to a path unless shadowed in a local scope.
    """
    if not has_treesitter():
        return None
    parser = _get_parser("tsx" if is_tsx else "ts")
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    has_tauri_import = b"@tauri-apps" in raw or b"__TAURI__" in raw
    found: list[tuple[str, str, int]] = []
    root_consts = dict(url_consts or {})

    def walk(node: Any, scope_consts: dict[str, str]) -> None:
        ntype = node.type
        if scope_consts and ntype in (
            "function_declaration",
            "generator_function_declaration",
            "function",
            "function_expression",
            "arrow_function",
            "method_definition",
        ):
            bound: set[str] = set()
            params = node.child_by_field_name("parameters")
            if params is not None:
                _collect_cst_pattern_idents(raw, params, bound)
            else:
                single = node.child_by_field_name("parameter")
                if single is not None:
                    _collect_cst_pattern_idents(raw, single, bound)
            if bound:
                scope_consts = {k: v for k, v in scope_consts.items() if k not in bound}
        elif scope_consts and ntype == "statement_block":
            bound_blk: set[str] = set()
            for ch in node.named_children:
                if ch.type in ("lexical_declaration", "variable_declaration"):
                    for decl in ch.named_children:
                        if decl.type == "variable_declarator":
                            lhs = decl.child_by_field_name("name") or (decl.named_children[0] if decl.named_children else None)
                            if lhs is not None:
                                _collect_cst_pattern_idents(raw, lhs, bound_blk)
                elif ch.type == "function_declaration":
                    fn_id = ch.child_by_field_name("name")
                    if fn_id is not None:
                        _collect_cst_pattern_idents(raw, fn_id, bound_blk)
            if bound_blk:
                scope_consts = {k: v for k, v in scope_consts.items() if k not in bound_blk}

        if ntype == "call_expression" and node.children:
            fn_node = node.children[0]
            # tree-sitter-typescript parses `await post<T>(url)` as a call whose function is
            # `await post`; unwrap await/parens/non-null so generic calls are not missed.
            while fn_node.type in _CALLEE_WRAPPERS and fn_node.named_children:
                fn_node = fn_node.named_children[-1]
            args_node = next((c for c in node.children if c.type == "arguments"), None)
            if args_node is not None:
                arg_items = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                callee_name = ""
                if fn_node.type == "identifier":
                    callee_name = raw[fn_node.start_byte : fn_node.end_byte].decode("utf-8", errors="replace")
                elif fn_node.type == "member_expression" and fn_node.children:
                    prop_n = fn_node.children[-1]
                    callee_name = raw[prop_n.start_byte : prop_n.end_byte].decode("utf-8", errors="replace")

                first_arg = arg_items[0] if arg_items else None
                if callee_name == "invoke" and has_tauri_import and first_arg is not None and first_arg.type == "string":
                    cmd = _unquote_node(raw, first_arg)
                    if cmd:
                        tverb = "GET" if cmd.startswith(_TAURI_READ_PREFIXES) else "POST"
                        found.append((tverb, f"/tauri/{cmd}", fn_node.start_point[0] + 1))
                elif first_arg is not None and first_arg.type in ("string", "template_string", "identifier"):
                    if first_arg.type == "identifier":
                        ident = raw[first_arg.start_byte : first_arg.end_byte].decode("utf-8", errors="replace")
                        url_val = scope_consts.get(ident, "")
                    else:
                        url_val = resolve_url_const_head(_unquote_node(raw, first_arg), scope_consts)
                    if url_val.startswith("/"):
                        upper_c = "DELETE" if callee_name.lower() == "del" else callee_name.upper()
                        if upper_c in _HTTP_VERBS:
                            found.append((upper_c, url_val, fn_node.start_point[0] + 1))
                        elif callee_name in _FETCH_HELPERS:
                            verb = "GET"
                            if len(arg_items) >= 2:
                                opt_txt = raw[arg_items[1].start_byte : arg_items[1].end_byte].decode("utf-8", errors="replace")
                                mm = _METHOD_RE.search(opt_txt)
                                if mm:
                                    verb = mm.group("m").upper()
                            found.append((verb, url_val, fn_node.start_point[0] + 1))
        for ch in node.children:
            walk(ch, scope_consts)

    walk(tree.root_node, root_consts)
    return found


_RUST_AXUM_VERB_RE = re.compile(r"\b(?P<verb>get|post|put|patch|delete)\s*\(\s*(?P<fn>[A-Za-z_][\w:]*)")
_RUST_ATTR_VERB_RE = re.compile(
    r"""^\s*#\[\s*(?:actix_web::|rocket::)?(?P<verb>get|post|put|patch|delete)\s*\(\s*"(?P<path>/[^"]*)" """.strip()
)


def extract_rust_routes_cst(
    source: str,
    normalize_fn: Any,
) -> list[tuple[str, str, int, set[str]]] | None:
    """Extract Rust `axum` (including multi-scope `.nest`), `actix`/`rocket`, & `Tauri` routes via CST."""
    if not has_treesitter():
        return None
    parser = _get_parser("rust")
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    found: list[tuple[str, str, int, set[str]]] = []

    # 1. Attribute-attached `function_item` nodes (handles stacked `#[instrument]` + `#[post(...)]` / `#[tauri::command]`)
    def scan_items(parent: Any, scope_prefix: str = "") -> None:
        pending_attrs: list[str] = []
        pending_lines: list[int] = []
        for ch in parent.children:
            if ch.type == "attribute_item":
                pending_attrs.append(raw[ch.start_byte : ch.end_byte].decode("utf-8", errors="replace"))
                pending_lines.append(ch.start_point[0] + 1)
                continue
            if ch.type == "function_item" and pending_attrs:
                fn_id_node = next((c for c in ch.children if c.type == "identifier"), None)
                fn_name = (
                    raw[fn_id_node.start_byte : fn_id_node.end_byte].decode("utf-8", errors="replace")
                    if fn_id_node is not None
                    else ""
                )
                for attr_txt, attr_line in zip(pending_attrs, pending_lines, strict=False):
                    if "tauri::command" in attr_txt and fn_name:
                        tverb = "GET" if fn_name.startswith(_TAURI_READ_PREFIXES) else "POST"
                        found.append((tverb, f"/tauri/{fn_name}", attr_line, {fn_name}))
                    else:
                        am = _RUST_ATTR_VERB_RE.search(attr_txt)
                        if am:
                            verb = am.group("verb").upper()
                            sub_p = am.group("path")
                            full_p = normalize_fn(sub_p) if sub_p.startswith("/api") else normalize_fn(scope_prefix, sub_p)
                            syms = {fn_name} if fn_name else set()
                            found.append((verb, full_p, attr_line, syms))
            pending_attrs.clear()
            pending_lines.clear()
            if ch.type in ("mod_item", "declaration_list"):
                scan_items(ch, scope_prefix)

    # 2. Scoped `axum::Router` `.nest(prefix, inner)` & `actix_web` `web::scope(prefix)` CST walk
    visited_calls: set[int] = set()

    def walk_expr(node: Any, active_prefix: str = "") -> None:
        if node.type == "call_expression" and node.id not in visited_calls and node.children:
            fn_node = node.children[0]
            args_node = next((c for c in node.children if c.type == "arguments"), None)
            if args_node is not None:
                arg_items = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                fn_txt = raw[fn_node.start_byte : fn_node.end_byte].decode("utf-8", errors="replace")
                if fn_node.type == "field_expression" and fn_node.children:
                    recv_node = fn_node.children[0]
                    field_node = fn_node.children[-1]
                    method_name = raw[field_node.start_byte : field_node.end_byte].decode("utf-8", errors="replace")
                    if method_name == "nest" and len(arg_items) >= 2 and arg_items[0].type == "string_literal":
                        visited_calls.add(node.id)
                        walk_expr(recv_node, active_prefix)
                        nested_pref = normalize_fn(active_prefix, _unquote_node(raw, arg_items[0]))
                        walk_expr(arg_items[1], nested_pref)
                        return
                    if method_name == "route" and len(arg_items) >= 2 and arg_items[0].type == "string_literal":
                        visited_calls.add(node.id)
                        walk_expr(recv_node, active_prefix)
                        sub_p = _unquote_node(raw, arg_items[0])
                        full_p = normalize_fn(sub_p) if sub_p.startswith("/api") else normalize_fn(active_prefix, sub_p)
                        arg2_txt = raw[arg_items[1].start_byte : arg_items[1].end_byte].decode("utf-8", errors="replace")
                        for vm in _RUST_AXUM_VERB_RE.finditer(arg2_txt):
                            found.append((vm.group("verb").upper(), full_p, field_node.start_point[0] + 1, {vm.group("fn").split("::")[-1]}))
                        return
                elif fn_txt.endswith("web::scope") and arg_items and arg_items[0].type == "string_literal":
                    visited_calls.add(node.id)
                    scoped_pref = normalize_fn(active_prefix, _unquote_node(raw, arg_items[0]))
                    for ch in node.parent.children if node.parent else ():
                        if ch.id != node.id:
                            walk_expr(ch, scoped_pref)
                    return
        for ch in node.children:
            walk_expr(ch, active_prefix)

    actix_scopes = re.findall(r'web::scope\(\s*"(/[^"]*)"', source)
    attr_default_scope = actix_scopes[0] if len(actix_scopes) == 1 else ""
    scan_items(tree.root_node, attr_default_scope)
    walk_expr(tree.root_node, "")
    return found


def extract_go_routes_cst(source: str, norm_fn: Any) -> list[tuple[str, str, int]] | None:
    """Extract Go `net/http`, `chi`, `gin`, & `echo` routes with nested `r.Route` closure prefixes via CST."""
    if not has_treesitter():
        return None
    parser = _get_parser("go")
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    group_vars: dict[str, str] = {}
    found: list[tuple[str, str, int]] = []

    def walk(node: Any, closure_prefix: str = "") -> None:
        if node.type == "short_var_declaration" and len(node.children) >= 3:
            lhs = raw[node.children[0].start_byte : node.children[0].end_byte].decode("utf-8", errors="replace").strip()
            rhs = node.children[-1]
            if rhs.type == "call_expression" and rhs.children:
                sel = rhs.children[0]
                args = next((c for c in rhs.children if c.type == "argument_list"), None)
                if sel.type == "selector_expression" and args is not None and len(sel.children) >= 2:
                    parent_var = raw[sel.children[0].start_byte : sel.children[0].end_byte].decode("utf-8", errors="replace")
                    mname = raw[sel.children[-1].start_byte : sel.children[-1].end_byte].decode("utf-8", errors="replace")
                    str_arg = next((c for c in args.children if "string_literal" in c.type), None)
                    if mname in ("Group", "Route") and str_arg is not None:
                        base_p = group_vars.get(parent_var, closure_prefix)
                        group_vars[lhs] = norm_fn(base_p, _unquote_node(raw, str_arg))
        elif node.type == "call_expression" and node.children:
            sel = node.children[0]
            args = next((c for c in node.children if c.type == "argument_list"), None)
            if sel.type == "selector_expression" and args is not None and len(sel.children) >= 2:
                recv = raw[sel.children[0].start_byte : sel.children[0].end_byte].decode("utf-8", errors="replace")
                mname = raw[sel.children[-1].start_byte : sel.children[-1].end_byte].decode("utf-8", errors="replace")
                arg_items = [c for c in args.children if c.type not in ("(", ")", ",")]
                first_str = arg_items[0] if arg_items and "string_literal" in arg_items[0].type else None
                if mname in ("Route", "Group") and first_str is not None:
                    base_p = group_vars.get(recv, closure_prefix)
                    sub_pref = norm_fn(base_p, _unquote_node(raw, first_str))
                    for extra in arg_items[1:]:
                        walk(extra, sub_pref)
                    return
                if mname in ("HandleFunc", "Handle") and first_str is not None:
                    lit = _unquote_node(raw, first_str)
                    parts = lit.split(None, 1)
                    if len(parts) == 2 and parts[0].upper() in _HTTP_VERBS:
                        found.append((parts[0].upper(), norm_fn(closure_prefix, parts[1]), sel.children[-1].start_point[0] + 1))
                elif mname.upper() in _HTTP_VERBS and first_str is not None:
                    base_p = group_vars.get(recv, closure_prefix)
                    found.append((mname.upper(), norm_fn(base_p, _unquote_node(raw, first_str)), sel.children[-1].start_point[0] + 1))
        for ch in node.children:
            walk(ch, closure_prefix)

    walk(tree.root_node, "")
    return found
