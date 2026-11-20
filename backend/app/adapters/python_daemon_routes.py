"""Stdlib HTTPServer/BaseHTTPRequestHandler, MCP tool routes, and static subprocess edges."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.adapters.base import ManipulatorExtractionResult, RouteDescriptor
from app.adapters.deployment_sources import normalize_home
from app.adapters.inline_store_truth import _collect_str_bindings, _eval_str_expr
from app.adapters.launchd_sources import shell_references
from app.adapters.service_sources import script_id, source_files, source_reference
from app.schemas.atlas import AtlasEdge, AtlasNode

_DO_METHODS: dict[str, str] = {
    "do_GET": "GET",
    "do_POST": "POST",
    "do_PUT": "PUT",
    "do_DELETE": "DELETE",
    "do_PATCH": "PATCH",
}
_VERSION_HEAD_RE = re.compile(r"^/api/v\d+(?=/)")
_SUBPROC_FUNCS = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "create_subprocess_exec",
        "create_subprocess_shell",
    }
)


def _norm_http_path(raw: str) -> str:
    base = raw.strip().split("?", 1)[0].split("#", 1)[0].strip()
    if not base.startswith("/"):
        base = "/" + base
    return base.rstrip("/") or "/"


def _compile_daemon_route_regex(full_path: str, *, is_prefix: bool = False) -> str:
    norm = full_path.rstrip("/") or "/"
    if norm == "/" and is_prefix:
        return r"^/.*$"
    version = r"/api/v\d+"
    head = _VERSION_HEAD_RE.match(norm)
    if head:
        version = re.escape(head.group(0))
        norm = norm[head.end() :] or "/"
    if is_prefix and norm.endswith("/{param}"):
        prefix_base = norm[: -len("/{param}")]
        esc_base = re.sub(r"\\\{[^/{}]+\\\}", r"[^/?#]+", re.escape(prefix_base))
        return rf"^(?:{version})?{esc_base}/[^?#]+$"
    escaped = re.sub(r"\\\{[^/{}]+\\\}", r"[^/?#]+", re.escape(norm))
    if is_prefix and "{param}" not in full_path:
        return rf"^(?:{version})?{escaped}(?:/[^?#]*)?/?$"
    return rf"^(?:{version})?{escaped}/?$"


def _regex_pattern_to_route_path(pat: str) -> str | None:
    cleaned = pat.strip().removeprefix("^").removesuffix("$")
    cleaned = re.sub(r"\(\?P<\w+>[^)]+\)", "{param}", cleaned)
    cleaned = re.sub(r"\([^)]+\)", "{param}", cleaned)
    cleaned = cleaned.replace(r"\/", "/").rstrip("?").rstrip("/")
    if not cleaned.startswith("/"):
        return None
    if any(ch in cleaned for ch in "*+[]|\\"):
        return None
    return cleaned or "/"


def _has_external_display_sources(repo_root: Path) -> bool:
    for cand in ("frontend", "web", "client", "ui"):
        d = repo_root / cand
        if not d.is_dir() or d.is_symlink():
            continue
        found, _ = source_files(d, {".tsx", ".jsx", ".vue", ".svelte"})
        if found:
            return True
    apps_dir = repo_root / "apps"
    if apps_dir.is_dir() and not apps_dir.is_symlink():
        apps_found, _ = source_files(apps_dir, {".tsx", ".jsx", ".vue", ".svelte"})
        if len(apps_found) >= 8:
            return True
    root_ui = [
        p
        for p in repo_root.glob("src/**/*")
        if p.is_file() and p.suffix in {".tsx", ".jsx", ".vue", ".svelte"}
    ]
    return bool(root_ui)


def _collect_scalar_consts(stmts: list[ast.stmt]) -> dict[str, str | int]:
    out: dict[str, str | int] = {}
    for stmt in stmts:
        name: str | None = None
        val: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            name, val = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            name, val = stmt.target.id, stmt.value
        if name and isinstance(val, ast.Constant) and isinstance(val.value, (str, int)):
            out[name] = val.value
    return out


def _collect_dict_route_keys(stmts: list[ast.stmt]) -> dict[str, list[str]]:
    tables: dict[str, list[str]] = {}
    for stmt in stmts:
        name: str | None = None
        val: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            name, val = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            name, val = stmt.target.id, stmt.value
        if not name or val is None:
            continue
        if isinstance(val, ast.Dict):
            keys = [
                k.value
                for k in val.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.startswith("/")
            ]
            if keys:
                tables[name] = keys
        elif isinstance(val, (ast.Set, ast.Tuple, ast.List)):
            elts = [
                e.value
                for e in val.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value.startswith("/")
            ]
            if elts:
                tables[name] = elts
        elif (
            isinstance(val, ast.Call)
            and isinstance(val.func, ast.Name)
            and val.func.id in {"frozenset", "set", "tuple", "list"}
            and val.args
            and isinstance(val.args[0], (ast.Set, ast.Tuple, ast.List))
        ):
            elts = [
                e.value
                for e in val.args[0].elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value.startswith("/")
            ]
            if elts:
                tables[name] = elts
    return tables


def _called_func_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name):
                names.add(sub.func.id)
            elif isinstance(sub.func, ast.Attribute):
                names.add(sub.func.attr)
    return names


@dataclass
class _ExtractedEndpoint:
    method: str
    full_path: str
    is_prefix: bool
    lineno: int
    handler_symbol: str
    called_symbols: set[str] = field(default_factory=set)
    serves_html: bool = False
    html_ref: str | None = None


def _is_urlparse_of_self_path(
    expr: ast.AST, path_vars: set[str], path_helpers: set[str] | None = None
) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    fn_name = (
        expr.func.id
        if isinstance(expr.func, ast.Name)
        else expr.func.attr
        if isinstance(expr.func, ast.Attribute)
        else ""
    )
    return fn_name in {"urlparse", "urlsplit"} and bool(expr.args) and _is_path_expr(
        expr.args[0], path_vars, set(), path_helpers
    )


def _is_path_expr(
    expr: ast.AST | None,
    path_vars: set[str],
    parsed_vars: set[str],
    path_helpers: set[str] | None = None,
) -> bool:
    if expr is None:
        return False
    if isinstance(expr, ast.Name):
        return expr.id in path_vars
    if isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name) and expr.value.id == "self" and expr.attr in {"path", "raw_path"}:
            return True
        if expr.attr == "path" and (
            (isinstance(expr.value, ast.Name) and expr.value.id in parsed_vars)
            or _is_urlparse_of_self_path(expr.value, path_vars, path_helpers)
        ):
            return True
    if (
        path_helpers
        and isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and isinstance(expr.func.value, ast.Name)
        and expr.func.value.id == "self"
        and expr.func.attr in path_helpers
    ):
        return True
    if (
        isinstance(expr, ast.Subscript)
        and isinstance(expr.slice, ast.Constant)
        and expr.slice.value == 0
        and isinstance(expr.value, ast.Call)
        and isinstance(expr.value.func, ast.Attribute)
        and expr.value.func.attr in {"split", "partition"}
        and _is_path_expr(expr.value.func.value, path_vars, parsed_vars, path_helpers)
    ):
        return True
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in {"rstrip", "strip", "removeprefix"}
        and _is_path_expr(expr.func.value, path_vars, parsed_vars, path_helpers)
    ):
        return True
    if isinstance(expr, ast.IfExp):
        return _is_path_expr(expr.body, path_vars, parsed_vars, path_helpers) or _is_path_expr(
            expr.orelse, path_vars, parsed_vars, path_helpers
        )
    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or) and expr.values:
        return _is_path_expr(expr.values[0], path_vars, parsed_vars, path_helpers)
    return False


def _discover_class_path_helpers(
    class_methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> set[str]:
    helpers: set[str] = set()
    for _ in range(3):
        before = len(helpers)
        for m_name, m_def in class_methods.items():
            if m_name in _DO_METHODS or m_name in helpers:
                continue
            m_pvars: set[str] = set()
            m_parsed: set[str] = set()
            for arg in m_def.args.args[1:]:
                if "path" in arg.arg.lower() or "route" in arg.arg.lower():
                    m_pvars.add(arg.arg)
            for _pass in range(2):
                for sub in ast.walk(m_def):
                    lhs_name: str | None = None
                    rhs_val: ast.AST | None = None
                    if (
                        isinstance(sub, ast.Assign)
                        and len(sub.targets) == 1
                        and isinstance(sub.targets[0], ast.Name)
                    ):
                        lhs_name, rhs_val = sub.targets[0].id, sub.value
                    elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                        lhs_name, rhs_val = sub.target.id, sub.value
                    if lhs_name and rhs_val is not None:
                        if _is_urlparse_of_self_path(rhs_val, m_pvars, helpers):
                            m_parsed.add(lhs_name)
                        elif _is_path_expr(rhs_val, m_pvars, m_parsed, helpers):
                            m_pvars.add(lhs_name)
            if any(
                isinstance(sub, ast.Return)
                and _is_path_expr(sub.value, m_pvars, m_parsed, helpers)
                for sub in ast.walk(m_def)
            ):
                helpers.add(m_name)
        if len(helpers) == before:
            break
    return helpers


def _scan_html_markers(node: ast.AST, str_env: dict[str, str]) -> tuple[bool, str | None]:
    serves_html = False
    html_ref: str | None = None
    for sub in ast.walk(node):
        if isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name)):
            val = _eval_str_expr(sub, str_env) if not isinstance(sub, ast.Name) or sub.id in str_env else None
            if not val:
                continue
            low = val.lower()
            if "text/html" in low or "<!doctype html" in low or "<html" in low:
                serves_html = True
            if low.endswith((".html", ".htm")) and "__dyn__" not in low and "\n" not in val:
                serves_html = True
                if html_ref is None:
                    html_ref = val.strip()
    return serves_html, html_ref


def _extract_handler_method_endpoints(
    fn_def: ast.FunctionDef | ast.AsyncFunctionDef,
    verb: str,
    class_methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    dict_routes: dict[str, list[str]],
    str_env: dict[str, str],
) -> list[_ExtractedEndpoint]:
    bodies: list[ast.FunctionDef | ast.AsyncFunctionDef] = [fn_def]
    for sub in ast.walk(fn_def):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "self"
            and sub.func.attr in class_methods
            and class_methods[sub.func.attr] not in bodies
        ):
            bodies.append(class_methods[sub.func.attr])

    path_helpers = _discover_class_path_helpers(class_methods)
    path_vars: set[str] = set()
    parsed_vars: set[str] = set()
    local_routes = dict(dict_routes)
    local_str_env = dict(str_env)
    # Parameter names like `path` / `route_path` in 1-hop helper methods
    for idx, helper_fn in enumerate(bodies):
        local_routes.update(_collect_dict_route_keys(helper_fn.body))
        local_str_env = _collect_str_bindings(helper_fn.body, local_str_env)
        if idx > 0:
            for arg in helper_fn.args.args[1:]:
                if "path" in arg.arg.lower() or "route" in arg.arg.lower():
                    path_vars.add(arg.arg)
        for _pass in range(2):
            for sub in ast.walk(helper_fn):
                tname: str | None = None
                rhs: ast.AST | None = None
                if (
                    isinstance(sub, ast.Assign)
                    and len(sub.targets) == 1
                    and isinstance(sub.targets[0], ast.Name)
                ):
                    tname, rhs = sub.targets[0].id, sub.value
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    tname, rhs = sub.target.id, sub.value
                if tname and rhs is not None:
                    if _is_urlparse_of_self_path(rhs, path_vars, path_helpers):
                        parsed_vars.add(tname)
                    elif _is_path_expr(rhs, path_vars, parsed_vars, path_helpers):
                        path_vars.add(tname)

    all_called: set[str] = set()
    serves_html = False
    html_ref: str | None = None
    for b_fn in bodies:
        all_called |= _called_func_names(b_fn)
        sh, hr = _scan_html_markers(b_fn, str_env)
        serves_html = serves_html or sh
        html_ref = html_ref or hr

    found: list[_ExtractedEndpoint] = []
    seen: set[tuple[str, bool]] = set()

    def _add(raw_p: str, is_pfx: bool, ln: int, branch_node: ast.AST | None = None) -> None:
        if not raw_p or not raw_p.startswith("/"):
            return
        if is_pfx and raw_p != "/" and raw_p.endswith("/"):
            norm_p = _norm_http_path(raw_p) + "/{param}"
        else:
            norm_p = _norm_http_path(raw_p)
        if (norm_p, is_pfx) in seen:
            return
        seen.add((norm_p, is_pfx))
        b_called = _called_func_names(branch_node) if branch_node is not None else set(all_called)
        for m_name in list(b_called):
            if m_name in class_methods:
                b_called |= _called_func_names(class_methods[m_name])
        b_sh, b_hr = (
            _scan_html_markers(branch_node, str_env) if branch_node is not None else (serves_html, html_ref)
        )
        found.append(
            _ExtractedEndpoint(
                method=verb,
                full_path=norm_p,
                is_prefix=is_pfx,
                lineno=ln,
                handler_symbol=fn_def.name,
                called_symbols=b_called | {fn_def.name},
                serves_html=b_sh or (serves_html and norm_p in {"/", "/index.html"}),
                html_ref=b_hr or html_ref,
            )
        )

    def _static_route_str(node_e: ast.AST) -> str | None:
        if isinstance(node_e, ast.Constant) and isinstance(node_e.value, str):
            return node_e.value
        if isinstance(node_e, (ast.Name, ast.BinOp, ast.JoinedStr)):
            if isinstance(node_e, ast.Name) and node_e.id not in local_str_env:
                return None
            ev = _eval_str_expr(node_e, local_str_env)
            if ev and ev.startswith("/"):
                return ev.replace("__dyn__", "{param}")
        return None

    def _extract_guard_test(test_expr: ast.AST, ln: int, guard_branch: ast.AST | None) -> None:
        if isinstance(test_expr, ast.BoolOp) and isinstance(test_expr.op, ast.And):
            for v in test_expr.values:
                _extract_guard_test(v, ln, guard_branch)
            return
        if isinstance(test_expr, ast.UnaryOp) and isinstance(test_expr.op, ast.Not):
            inner = test_expr.operand
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "startswith"
                and _is_path_expr(inner.func.value, path_vars, parsed_vars, path_helpers)
                and inner.args
            ):
                arg0 = inner.args[0]
                s0 = _static_route_str(arg0)
                if s0:
                    _add(s0, True, ln, guard_branch)
                elif isinstance(arg0, ast.Tuple):
                    for elt in arg0.elts:
                        se = _static_route_str(elt)
                        if se:
                            _add(se, True, ln, guard_branch)
            return
        if isinstance(test_expr, ast.Compare) and len(test_expr.ops) == 1 and len(test_expr.comparators) == 1:
            op, left, right = test_expr.ops[0], test_expr.left, test_expr.comparators[0]
            if isinstance(op, ast.NotEq):
                if _is_path_expr(left, path_vars, parsed_vars, path_helpers):
                    sr = _static_route_str(right)
                    if sr:
                        _add(sr, False, ln, guard_branch)
                elif _is_path_expr(right, path_vars, parsed_vars, path_helpers):
                    sl = _static_route_str(left)
                    if sl:
                        _add(sl, False, ln, guard_branch)
            elif isinstance(op, ast.NotIn) and _is_path_expr(left, path_vars, parsed_vars, path_helpers):
                if isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                    for elt in right.elts:
                        se = _static_route_str(elt)
                        if se:
                            _add(se, False, ln, guard_branch)
                elif isinstance(right, ast.Name) and right.id in local_routes:
                    for r_key in local_routes[right.id]:
                        _add(r_key, False, ln, guard_branch)

    for b_fn in bodies:
        for sub in ast.walk(b_fn):
            if isinstance(sub, ast.If):
                if_body = ast.Module(body=sub.body, type_ignores=[])
                terminates_early = bool(sub.body) and isinstance(
                    sub.body[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break)
                )
                if terminates_early:
                    else_branch = (
                        ast.Module(body=sub.orelse, type_ignores=[]) if sub.orelse else None
                    )
                    _extract_guard_test(sub.test, sub.lineno, else_branch)
                # Associate branch body for surgical called_symbols when test matches a path branch
                for cmp in ast.walk(sub.test):
                    if isinstance(cmp, ast.Compare) and len(cmp.ops) == 1 and len(cmp.comparators) == 1:
                        op, left, right = cmp.ops[0], cmp.left, cmp.comparators[0]
                        if isinstance(op, ast.Eq):
                            if _is_path_expr(left, path_vars, parsed_vars, path_helpers):
                                sr = _static_route_str(right)
                                if sr:
                                    _add(sr, False, sub.lineno, if_body)
                            elif _is_path_expr(right, path_vars, parsed_vars, path_helpers):
                                sl = _static_route_str(left)
                                if sl:
                                    _add(sl, False, sub.lineno, if_body)
                        elif isinstance(op, ast.In) and _is_path_expr(left, path_vars, parsed_vars, path_helpers):
                            if isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                                for elt in right.elts:
                                    se = _static_route_str(elt)
                                    if se:
                                        _add(se, False, sub.lineno, if_body)
                            elif isinstance(right, ast.Name) and right.id in local_routes:
                                for r_key in local_routes[right.id]:
                                    _add(r_key, False, sub.lineno, if_body)
                    elif (
                        isinstance(cmp, ast.Call)
                        and isinstance(cmp.func, ast.Attribute)
                        and cmp.func.attr == "startswith"
                        and _is_path_expr(cmp.func.value, path_vars, parsed_vars, path_helpers)
                        and cmp.args
                    ):
                        arg0 = cmp.args[0]
                        s0 = _static_route_str(arg0)
                        if s0:
                            _add(s0, True, sub.lineno, if_body)
                        elif isinstance(arg0, ast.Tuple):
                            for elt in arg0.elts:
                                se = _static_route_str(elt)
                                if se:
                                    _add(se, True, sub.lineno, if_body)
                    elif (
                        isinstance(cmp, ast.Call)
                        and isinstance(cmp.func, ast.Attribute)
                        and cmp.func.attr in {"match", "fullmatch"}
                        and len(cmp.args) >= 2
                        and isinstance(cmp.args[0], ast.Constant)
                        and isinstance(cmp.args[0].value, str)
                        and _is_path_expr(cmp.args[1], path_vars, parsed_vars, path_helpers)
                    ):
                        rx_p = _regex_pattern_to_route_path(cmp.args[0].value)
                        if rx_p:
                            _add(rx_p, False, sub.lineno, if_body)
            elif isinstance(sub, ast.Match) and _is_path_expr(sub.subject, path_vars, parsed_vars, path_helpers):
                for case in sub.cases:
                    pats = list(case.pattern.patterns) if isinstance(case.pattern, ast.MatchOr) else [case.pattern]
                    for p_item in pats:
                        if (
                            isinstance(p_item, ast.MatchValue)
                            and isinstance(p_item.value, ast.Constant)
                            and isinstance(p_item.value.value, str)
                        ):
                            _add(p_item.value.value, False, getattr(p_item, "lineno", sub.lineno), ast.Module(body=case.body, type_ignores=[]))
            elif (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "get"
                and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id in local_routes
                and sub.args
                and _is_path_expr(sub.args[0], path_vars, parsed_vars, path_helpers)
            ):
                for r_key in local_routes[sub.func.value.id]:
                    _add(r_key, False, sub.lineno, None)

    return found


def _discover_repo_server_and_handler_classes(
    trees: dict[str, ast.Module],
) -> tuple[set[str], set[str]]:
    server_classes = {
        "HTTPServer",
        "ThreadingHTTPServer",
        "TCPServer",
        "ThreadingTCPServer",
        "DualStackServer",
    }
    handler_classes: set[str] = set()
    all_class_defs = [
        n for tree in trees.values() for n in ast.walk(tree) if isinstance(n, ast.ClassDef)
    ]
    for _ in range(4):
        before = (len(server_classes), len(handler_classes))
        for cls in all_class_defs:
            base_names = {
                b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
                for b in cls.bases
            }
            if base_names & server_classes:
                server_classes.add(cls.name)
            cls_methods = {
                m.name for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if (
                any(bn.endswith("RequestHandler") for bn in base_names)
                or (base_names & handler_classes)
                or (any(bn for bn in base_names) and (cls_methods & set(_DO_METHODS)))
            ):
                handler_classes.add(cls.name)
        if (len(server_classes), len(handler_classes)) == before:
            break
    # Also resolve imported aliases (`from server_lib import CustomHTTPServer as MySrv`)
    for _ in range(2):
        for tree in trees.values():
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    for al in n.names:
                        if al.asname and al.name in server_classes:
                            server_classes.add(al.asname)
                        if al.asname and al.name in handler_classes:
                            handler_classes.add(al.asname)
    return server_classes, handler_classes


def _extract_http_server_bindings(
    tree: ast.Module,
    consts: dict[str, str | int],
    repo_server_classes: set[str] | None = None,
    repo_handler_classes: set[str] | None = None,
) -> dict[str, list[tuple[str, str]]]:
    """Return `{HandlerClassName: [(binding_label, caller_scope)]}` for HTTPServer/ThreadingHTTPServer."""
    server_classes = set(
        repo_server_classes
        or {"HTTPServer", "ThreadingHTTPServer", "TCPServer", "ThreadingTCPServer"}
    )
    known_handlers = set(repo_handler_classes or ())
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.ClassDef):
            base_names = {
                b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
                for b in stmt.bases
            }
            if base_names & server_classes:
                server_classes.add(stmt.name)

    bindings: dict[str, list[tuple[str, str]]] = {}
    factory_returns: dict[str, str] = {}
    for top_s in tree.body:
        if isinstance(top_s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nested_classes = [c.name for c in ast.walk(top_s) if isinstance(c, ast.ClassDef)]
            if nested_classes:
                returned_names = {
                    r.value.id
                    for r in ast.walk(top_s)
                    if isinstance(r, ast.Return) and isinstance(r.value, ast.Name)
                }
                matched = [cn for cn in nested_classes if cn in returned_names]
                factory_returns[top_s.name] = matched[0] if matched else nested_classes[0]

    def _handler_name_from_arg(h_arg: ast.AST | None) -> str:
        if h_arg is None:
            return ""
        h_name = (
            h_arg.id
            if isinstance(h_arg, ast.Name)
            else h_arg.attr
            if isinstance(h_arg, ast.Attribute)
            else ""
        )
        if not h_name and isinstance(h_arg, ast.Call):
            cfn = (
                h_arg.func.id
                if isinstance(h_arg.func, ast.Name)
                else h_arg.func.attr
                if isinstance(h_arg.func, ast.Attribute)
                else ""
            )
            h_name = factory_returns.get(cfn, "")
        return h_name

    def _scan_stmts(stmts: list[ast.stmt], scope_name: str) -> None:
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _scan_stmts(s.body, s.name)
                continue
            if isinstance(s, ast.ClassDef):
                for m in s.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        _scan_stmts(m.body, m.name)
                continue
            for node in ast.walk(s):
                if not isinstance(node, ast.Call):
                    continue
                cls_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if cls_name not in server_classes:
                    continue
                h_arg: ast.AST | None = None
                addr_arg: ast.AST | None = None
                if len(node.args) >= 2:
                    addr_arg, h_arg = node.args[0], node.args[1]
                else:
                    for kw in node.keywords:
                        if kw.arg in {"RequestHandlerClass", "handler", "handler_class", "handler_cls"}:
                            h_arg = kw.value
                        elif kw.arg in {"server_address", "addr", "address"}:
                            addr_arg = kw.value
                    if h_arg is None and len(node.args) == 1:
                        cand_h = _handler_name_from_arg(node.args[0])
                        if cand_h and (cand_h in known_handlers or cand_h.endswith("Handler")):
                            h_arg = node.args[0]
                h_name = _handler_name_from_arg(h_arg)
                if not h_name:
                    continue
                addr_str = cls_name
                if isinstance(addr_arg, (ast.Tuple, ast.List)) and len(addr_arg.elts) == 2:
                    h_el, p_el = addr_arg.elts
                    host_v = (
                        h_el.value
                        if isinstance(h_el, ast.Constant)
                        else consts.get(h_el.id)
                        if isinstance(h_el, ast.Name)
                        else None
                    )
                    port_v = (
                        p_el.value
                        if isinstance(p_el, ast.Constant)
                        else consts.get(p_el.id)
                        if isinstance(p_el, ast.Name)
                        else None
                    )
                    host_lbl = str(host_v) if host_v not in (None, "") else "*"
                    port_lbl = str(port_v) if port_v is not None else "*"
                    addr_str = f"{cls_name}({host_lbl}:{port_lbl})"
                bindings.setdefault(h_name, []).append((addr_str, scope_name))

    _scan_stmts(tree.body, "*")
    return bindings


_FASTAPI_DECORATOR_VERBS: dict[str, str] = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "websocket": "GET",
}


def _collect_cross_module_router_mounts(trees: dict[str, ast.Module]) -> dict[tuple[str, str], list[str]]:
    """Return `{(target_rel, router_var): [mount_prefix]}` from `app.include_router(...)` calls."""
    by_stem: dict[str, list[str]] = {}
    for r in trees:
        p = PurePosixPath(r)
        mod_dot = ".".join(p.with_suffix("").parts)
        by_stem.setdefault(mod_dot, []).append(r)
        if p.name == "__init__.py" and len(p.parts) > 1:
            by_stem.setdefault(".".join(p.parent.parts), []).append(r)

    mounts: dict[tuple[str, str], list[str]] = {}
    for rel, tree in sorted(trees.items()):
        mod_env = _collect_str_bindings(tree.body, {})
        imp_router_src: dict[str, tuple[str, str]] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module:
                cand_rels = [
                    r
                    for m_key, rels in by_stem.items()
                    if m_key == n.module or m_key.endswith("." + n.module)
                    for r in rels
                ]
                if len(cand_rels) == 1:
                    for al in n.names:
                        imp_router_src[al.asname or al.name] = (cand_rels[0], al.name)
            elif isinstance(n, ast.Import):
                for al in n.names:
                    cand_rels = [
                        r
                        for m_key, rels in by_stem.items()
                        if m_key == al.name or m_key.endswith("." + al.name)
                        for r in rels
                    ]
                    if len(cand_rels) == 1:
                        imp_router_src[al.asname or al.name] = (cand_rels[0], "router")

        scopes = [(tree.body, mod_env)] + [
            (s.body, _collect_str_bindings(s.body, mod_env))
            for s in tree.body
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for stmts, sc_env in scopes:
            for n in ast.walk(ast.Module(body=stmts, type_ignores=[])):
                if (
                    isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "include_router"
                    and n.args
                ):
                    r_arg = n.args[0]
                    target_pair: tuple[str, str] | None = None
                    if isinstance(r_arg, ast.Name) and r_arg.id in imp_router_src:
                        target_pair = imp_router_src[r_arg.id]
                    elif (
                        isinstance(r_arg, ast.Attribute)
                        and isinstance(r_arg.value, ast.Name)
                        and r_arg.value.id in imp_router_src
                    ):
                        target_pair = (imp_router_src[r_arg.value.id][0], r_arg.attr)
                    elif isinstance(r_arg, ast.Name):
                        target_pair = (rel, r_arg.id)
                    if target_pair is None:
                        continue
                    pref = ""
                    for kw in n.keywords:
                        if kw.arg == "prefix":
                            ev = _eval_str_expr(kw.value, sc_env)
                            if ev:
                                pref = ev.replace("__dyn__", "{param}")
                    mounts.setdefault(target_pair, []).append(pref)
    return mounts


def _extract_fastapi_starlette_endpoints(
    rel: str,
    tree: ast.Module,
    mod_str_env: dict[str, str],
    router_mounts: dict[tuple[str, str], list[str]],
) -> list[_ExtractedEndpoint]:
    """Extract FastAPI/Starlette `@app.<verb>`, `APIRouter`, `create_app()`, and `Route(...)`."""
    has_web_import = False
    receivers: dict[str, str] = {}
    for n in ast.walk(tree):
        if (
            isinstance(n, ast.Import)
            and any(a.name.split(".", 1)[0] in {"fastapi", "starlette"} for a in n.names)
        ) or (
            isinstance(n, ast.ImportFrom)
            and n.module
            and n.module.split(".", 1)[0] in {"fastapi", "starlette"}
        ):
            has_web_import = True

    def _join_route(p1: str, p2: str, p3: str) -> str:
        segs = [s.strip("/") for s in (p1, p2, p3) if s and s.strip("/")]
        return _norm_http_path("/" + "/".join(segs))

    endpoints: list[_ExtractedEndpoint] = []
    seen_ep: set[tuple[str, str, str]] = set()

    def _scan_scope(stmts: list[ast.stmt], sc_env: dict[str, str], local_recvs: dict[str, str]) -> None:
        recvs = dict(local_recvs)
        for s in stmts:
            lhs_id: str | None = None
            rhs_val: ast.AST | None = None
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                lhs_id, rhs_val = s.targets[0].id, s.value
            elif isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                lhs_id, rhs_val = s.target.id, s.value
            if lhs_id and isinstance(rhs_val, ast.Call):
                cname = (
                    rhs_val.func.id
                    if isinstance(rhs_val.func, ast.Name)
                    else rhs_val.func.attr
                    if isinstance(rhs_val.func, ast.Attribute)
                    else ""
                )
                if cname in {"FastAPI", "APIRouter", "Starlette"}:
                    has_pref = ""
                    for kw in rhs_val.keywords:
                        if kw.arg == "prefix":
                            ev = _eval_str_expr(kw.value, sc_env)
                            if ev:
                                has_pref = ev.replace("__dyn__", "{param}")
                    recvs[lhs_id] = has_pref
        if not has_web_import and not recvs:
            return

        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Recurse into factory functions (`create_app`, `build_app`, etc.)
                inner_env = _collect_str_bindings(s.body, sc_env)
                _scan_scope(s.body, inner_env, recvs)
                for dec in s.decorator_list:
                    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                        continue
                    if not isinstance(dec.func.value, ast.Name):
                        continue
                    r_var = dec.func.value.id
                    if r_var not in recvs and not has_web_import:
                        continue
                    attr = dec.func.attr
                    verbs: list[str] = []
                    if attr in _FASTAPI_DECORATOR_VERBS:
                        verbs = [_FASTAPI_DECORATOR_VERBS[attr]]
                    elif attr in {"api_route", "route"}:
                        for kw in dec.keywords:
                            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                                verbs = [
                                    el.value.upper()
                                    for el in kw.value.elts
                                    if isinstance(el, ast.Constant) and isinstance(el.value, str)
                                ]
                        if not verbs:
                            verbs = ["GET"]
                    if not verbs:
                        continue
                    p_expr = dec.args[0] if dec.args else next(
                        (kw.value for kw in dec.keywords if kw.arg == "path"), None
                    )
                    raw_p = _eval_str_expr(p_expr, sc_env) if p_expr is not None else "/"
                    if raw_p is None:
                        continue
                    sub_p = raw_p.replace("__dyn__", "{param}")
                    r_pref = recvs.get(r_var, "")
                    mount_prefs = router_mounts.get((rel, r_var)) or [""]
                    sh, hr = _scan_html_markers(s, inner_env)
                    if not sh:
                        for call_n in ast.walk(s):
                            if isinstance(call_n, ast.Call):
                                cfn = (
                                    call_n.func.id
                                    if isinstance(call_n.func, ast.Name)
                                    else call_n.func.attr
                                    if isinstance(call_n.func, ast.Attribute)
                                    else ""
                                )
                                if cfn == "HTMLResponse":
                                    sh = True
                    called = _called_func_names(s) | {s.name}
                    for mp in mount_prefs:
                        full_p = _join_route(mp, r_pref, sub_p)
                        for vb in verbs:
                            if (vb, full_p, s.name) not in seen_ep:
                                seen_ep.add((vb, full_p, s.name))
                                endpoints.append(
                                    _ExtractedEndpoint(
                                        method=vb,
                                        full_path=full_p,
                                        is_prefix=False,
                                        lineno=s.lineno,
                                        handler_symbol=s.name,
                                        called_symbols=set(called),
                                        serves_html=sh,
                                        html_ref=hr,
                                    )
                                )
            elif has_web_import:
                for call_n in ast.walk(s):
                    if not isinstance(call_n, ast.Call):
                        continue
                    cfn = (
                        call_n.func.id
                        if isinstance(call_n.func, ast.Name)
                        else call_n.func.attr
                        if isinstance(call_n.func, ast.Attribute)
                        else ""
                    )
                    if cfn == "Route" and len(call_n.args) >= 2:
                        raw_rp = _eval_str_expr(call_n.args[0], sc_env)
                        ep_arg = call_n.args[1]
                        ep_sym = ep_arg.id if isinstance(ep_arg, ast.Name) else (
                            ep_arg.attr if isinstance(ep_arg, ast.Attribute) else "endpoint"
                        )
                        if raw_rp:
                            full_rp = _norm_http_path(raw_rp.replace("__dyn__", "{param}"))
                            r_verbs = ["GET"]
                            for kw in call_n.keywords:
                                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                                    cand_vs = [
                                        el.value.upper()
                                        for el in kw.value.elts
                                        if isinstance(el, ast.Constant) and isinstance(el.value, str)
                                    ]
                                    if cand_vs:
                                        r_verbs = cand_vs
                            for vb in r_verbs:
                                if (vb, full_rp, ep_sym) not in seen_ep:
                                    seen_ep.add((vb, full_rp, ep_sym))
                                    endpoints.append(
                                        _ExtractedEndpoint(
                                            method=vb,
                                            full_path=full_rp,
                                            is_prefix=False,
                                            lineno=getattr(call_n, "lineno", 1),
                                            handler_symbol=ep_sym,
                                            called_symbols={ep_sym},
                                        )
                                    )

    _scan_scope(tree.body, mod_str_env, receivers)
    return endpoints


def _extract_mcp_endpoints(tree: ast.Module) -> list[_ExtractedEndpoint]:
    """Extract `@mcp.tool` / `@server.tool` and `@server.list_tools` + `@server.call_tool` endpoints."""
    mcp_receivers = {"mcp", "server", "mcp_server", "fastmcp"}
    has_mcp_import = False
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Import)
            and any(a.name == "mcp" or a.name.startswith("mcp.") for a in node.names)
        ) or (
            isinstance(node, ast.ImportFrom)
            and node.module
            and (
                node.module == "mcp"
                or node.module.startswith("mcp.")
                or "fastmcp" in node.module.lower()
            )
        ):
            has_mcp_import = True
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            cname = (
                node.value.func.id
                if isinstance(node.value.func, ast.Name)
                else node.value.func.attr
                if isinstance(node.value.func, ast.Attribute)
                else ""
            )
            if cname in {"FastMCP", "MCPServer", "Server"}:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        mcp_receivers.add(tgt.id)

    endpoints: list[_ExtractedEndpoint] = []
    call_tool_branches: dict[str, set[str]] = {}
    call_tool_fn_name: str | None = None
    call_tool_all_syms: set[str] = set()

    # Pass 1: inspect `@server.call_tool` if present so `@server.list_tools` gets branch callees
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in stmt.decorator_list:
            dec_t = dec.func if isinstance(dec, ast.Call) else dec
            if (
                isinstance(dec_t, ast.Attribute)
                and dec_t.attr == "call_tool"
                and isinstance(dec_t.value, ast.Name)
                and (dec_t.value.id in mcp_receivers or has_mcp_import)
            ):
                call_tool_fn_name = stmt.name
                call_tool_all_syms = _called_func_names(stmt) | {stmt.name}
                name_param = stmt.args.args[0].arg if stmt.args.args else "name"
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.If):
                        for cmp in ast.walk(sub.test):
                            if (
                                isinstance(cmp, ast.Compare)
                                and len(cmp.ops) == 1
                                and isinstance(cmp.ops[0], ast.Eq)
                                and len(cmp.comparators) == 1
                            ):
                                l_n, r_n = cmp.left, cmp.comparators[0]
                                t_str: str | None = None
                                if isinstance(l_n, ast.Name) and l_n.id == name_param and isinstance(r_n, ast.Constant) and isinstance(r_n.value, str):
                                    t_str = r_n.value
                                elif isinstance(r_n, ast.Name) and r_n.id == name_param and isinstance(l_n, ast.Constant) and isinstance(l_n.value, str):
                                    t_str = l_n.value
                                if t_str:
                                    b_mod = ast.Module(body=sub.body, type_ignores=[])
                                    call_tool_branches.setdefault(t_str, set()).update(
                                        _called_func_names(b_mod) | {stmt.name}
                                    )

    # Pass 2: `@mcp.tool` and `@server.list_tools`
    seen_tools: set[str] = set()
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in stmt.decorator_list:
            dec_call = dec if isinstance(dec, ast.Call) else None
            dec_t = dec_call.func if dec_call is not None else dec
            if not isinstance(dec_t, ast.Attribute) or not isinstance(dec_t.value, ast.Name):
                continue
            recv = dec_t.value.id
            if recv not in mcp_receivers and not has_mcp_import:
                continue
            if dec_t.attr == "tool":
                tname = stmt.name
                if dec_call is not None:
                    if dec_call.args and isinstance(dec_call.args[0], ast.Constant) and isinstance(dec_call.args[0].value, str):
                        tname = dec_call.args[0].value
                    for kw in dec_call.keywords:
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            tname = kw.value.value
                if tname not in seen_tools:
                    seen_tools.add(tname)
                    endpoints.append(
                        _ExtractedEndpoint(
                            method="POST",
                            full_path=f"/mcp/tools/{tname.strip('/')}",
                            is_prefix=False,
                            lineno=stmt.lineno,
                            handler_symbol=stmt.name,
                            called_symbols=_called_func_names(stmt) | {stmt.name},
                        )
                    )
            elif dec_t.attr == "list_tools":
                listed: list[tuple[str, int]] = []
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call):
                        fn_n = sub.func.id if isinstance(sub.func, ast.Name) else sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
                        if fn_n == "Tool":
                            for kw in sub.keywords:
                                if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                    listed.append((kw.value.value, getattr(sub, "lineno", stmt.lineno)))
                    elif isinstance(sub, ast.Dict):
                        for k_n, v_n in zip(sub.keys, sub.values, strict=False):
                            if (
                                isinstance(k_n, ast.Constant)
                                and k_n.value == "name"
                                and isinstance(v_n, ast.Constant)
                                and isinstance(v_n.value, str)
                            ):
                                listed.append((v_n.value, getattr(sub, "lineno", stmt.lineno)))
                for tname, tline in listed:
                    if tname in seen_tools:
                        continue
                    seen_tools.add(tname)
                    syms = call_tool_branches.get(tname) or call_tool_all_syms or ({stmt.name} | _called_func_names(stmt))
                    h_sym = call_tool_fn_name or stmt.name
                    endpoints.append(
                        _ExtractedEndpoint(
                            method="POST",
                            full_path=f"/mcp/tools/{tname.strip('/')}",
                            is_prefix=False,
                            lineno=tline,
                            handler_symbol=h_sym,
                            called_symbols=set(syms) | {stmt.name},
                        )
                    )
                if not listed and "__list_tools__" not in seen_tools:
                    seen_tools.add("__list_tools__")
                    endpoints.append(
                        _ExtractedEndpoint(
                            method="POST",
                            full_path="/mcp/tools",
                            is_prefix=True,
                            lineno=stmt.lineno,
                            handler_symbol=call_tool_fn_name or stmt.name,
                            called_symbols=call_tool_all_syms | _called_func_names(stmt) | {stmt.name},
                        )
                    )
    return endpoints


def _resolve_candidate_script(
    raw: str,
    rel: str,
    paths: set[str],
    deployments: dict[str, set[str]],
) -> set[str]:
    if not raw or "__dyn__" in raw.rsplit("/", 1)[-1]:
        return set()
    cleaned = raw.replace("__dyn__/", "")
    hits: set[str] = set()
    for cand in {raw, cleaned, *shell_references(raw)}:
        mapped = deployments.get(normalize_home(cand), set())
        if mapped:
            hits.update(mapped & paths)
        else:
            target = source_reference(cand, rel, paths)
            if target:
                hits.add(target)
    hits.discard(rel)
    return hits


def _extract_subprocess_targets(
    rel: str,
    tree: ast.Module,
    paths: set[str],
    py_paths: set[str],
    roots: list[list[str]],
    deployments: dict[str, set[str]],
) -> dict[str, tuple[int, list[str]]]:
    """Return `{target_rel: (lineno, caller_scopes)}` for static `subprocess.*` script calls."""
    subproc_mods = {"subprocess", "asyncio"}
    direct_funcs: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for al in n.names:
                if al.name in {"subprocess", "asyncio"} and al.asname:
                    subproc_mods.add(al.asname)
        elif isinstance(n, ast.ImportFrom) and n.module in {"subprocess", "asyncio"}:
            for al in n.names:
                if al.name in _SUBPROC_FUNCS:
                    direct_funcs.add(al.asname or al.name)

    mod_env = _collect_str_bindings(tree.body, {})
    found: dict[str, tuple[int, list[str]]] = {}

    def _record(target: str, ln: int, scope: str) -> None:
        if target not in found:
            found[target] = (ln, [scope])
        elif scope not in found[target][1]:
            found[target][1].append(scope)

    def _scan_stmts(stmts: list[ast.stmt], scope_name: str, outer_env: dict[str, str]) -> None:
        env = _collect_str_bindings(stmts, outer_env)
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _scan_stmts(s.body, s.name, env)
                continue
            if isinstance(s, ast.ClassDef):
                cls_env = _collect_str_bindings(s.body, env)
                for m in s.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        _scan_stmts(m.body, m.name, cls_env)
                continue
            for node in ast.walk(s):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                is_subproc = (
                    isinstance(fn, ast.Attribute)
                    and fn.attr in _SUBPROC_FUNCS
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id in subproc_mods
                ) or (isinstance(fn, ast.Name) and fn.id in direct_funcs)
                if not is_subproc:
                    continue
                is_exec = isinstance(fn, ast.Attribute) and fn.attr == "create_subprocess_exec"
                cmd_expr: ast.AST | None = None
                if is_exec:
                    tokens = [_eval_str_expr(a, env) for a in node.args]
                else:
                    cmd_expr = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"args", "cmd"}), None)
                    if isinstance(cmd_expr, (ast.List, ast.Tuple)):
                        tokens = [_eval_str_expr(el, env) for el in cmd_expr.elts]
                    else:
                        s_cmd = _eval_str_expr(cmd_expr, env)
                        tokens = [s_cmd] if s_cmd else []

                ln = getattr(node, "lineno", 1)
                for idx, tok in enumerate(tokens):
                    if not tok:
                        continue
                    if tok == "-m" and idx + 1 < len(tokens) and tokens[idx + 1]:
                        mod_ref = tokens[idx + 1] or ""
                        if "__dyn__" not in mod_ref:
                            parent = list(PurePosixPath(rel).parent.parts)
                            for base in [*roots, parent]:
                                prefix = "/".join([*base, *mod_ref.split(".")])
                                for cand_py in (f"{prefix}.py", f"{prefix}/__init__.py"):
                                    if cand_py in py_paths and cand_py != rel:
                                        _record(cand_py, ln, scope_name)
                        continue
                    for hit in sorted(_resolve_candidate_script(tok, rel, paths, deployments)):
                        _record(hit, ln, scope_name)

    _scan_stmts(tree.body, "*", mod_env)
    return found


def add_daemon_routes_and_subprocesses(
    repo_root: Path,
    trees: dict[str, ast.Module],
    paths: set[str],
    py_paths: set[str],
    roots: list[list[str]],
    deployments: dict[str, set[str]],
    result: ManipulatorExtractionResult,
) -> dict[str, dict[str, list[str]]]:
    """Extract stdlib HTTP/MCP routes (`m:route:*`) and static `subprocess` edges."""
    has_ext_display = _has_external_display_sources(repo_root)
    route_keys_by_rel: dict[str, dict[str, list[str]]] = {}
    emitted_html_pages: set[str] = set()

    repo_server_classes, repo_handler_classes = _discover_repo_server_and_handler_classes(trees)
    router_mounts = _collect_cross_module_router_mounts(trees)

    # Cross-module HTTPServer binding lookup if server is instantiated in another module
    global_bindings: dict[str, list[tuple[str, str, str]]] = {}
    for rel, tree in sorted(trees.items()):
        consts = _collect_scalar_consts(tree.body)
        for h_cls, items in _extract_http_server_bindings(
            tree, consts, repo_server_classes, repo_handler_classes
        ).items():
            for addr_lbl, sc_name in items:
                global_bindings.setdefault(h_cls, []).append((rel, addr_lbl, sc_name))

    def _emit_route_group(
        rel: str,
        group_slug: str,
        label: str,
        cluster: str,
        lineno: int,
        endpoints: list[_ExtractedEndpoint],
        binding_notes: list[tuple[str, str, str]],
    ) -> None:
        if not endpoints:
            return
        route_nid = f"m:route:{rel}:{group_slug}"
        host_script_nid = script_id(rel)
        methods: list[str] = []
        http_paths: list[str] = []
        html_tags: list[str] = []
        slinks_to_host: list[str] = []
        rel_map = route_keys_by_rel.setdefault(rel, {})

        for ep in endpoints:
            if ep.method not in methods:
                methods.append(ep.method)
            if ep.full_path not in http_paths:
                http_paths.append(ep.full_path)
            rkey = f"{ep.method} {ep.full_path}"
            for sym in sorted(ep.called_symbols | {ep.handler_symbol}):
                rel_map.setdefault(sym, [])
                if rkey not in rel_map[sym]:
                    rel_map[sym].append(rkey)
                pair = f"{rkey}->{sym}"
                if pair not in slinks_to_host:
                    slinks_to_host.append(pair)
            if ep.serves_html:
                tag = ep.html_ref or "inline text/html"
                if tag not in html_tags:
                    html_tags.append(tag)
                if not has_ext_display and ep.method == "GET":
                    page_slug = f"{rel}:{ep.full_path}".replace("/", ".").strip(".")
                    page_nid = f"d:page:{page_slug}"
                    if page_nid not in emitted_html_pages:
                        emitted_html_pages.add(page_nid)
                        safe_html_src = rel
                        if ep.html_ref and not Path(ep.html_ref).is_absolute() and ".." not in PurePosixPath(ep.html_ref).parts:
                            real_root = repo_root.resolve()
                            cand_html = real_root / ep.html_ref
                            cur = real_root
                            has_symlink = False
                            for part in PurePosixPath(ep.html_ref).parts:
                                cur = cur / part
                                if cur.is_symlink():
                                    has_symlink = True
                                    break
                            if not has_symlink and cand_html.is_file() and cand_html.resolve().is_relative_to(real_root):
                                safe_html_src = cand_html.resolve().relative_to(real_root).as_posix()
                        result.nodes.append(
                            AtlasNode(
                                id=page_nid,
                                tier="display",
                                subkind="page",
                                label=ep.html_ref or ep.full_path,
                                source_file=safe_html_src,
                                line=ep.lineno,
                                role="surface",
                                cluster="embedded_html",
                                summary=f"Embedded HTML view served by `{label}` on `GET {ep.full_path}` ({tag}).",
                            )
                        )
                        result.edges.append(
                            AtlasEdge(
                                id=f"e:{page_nid}->{route_nid}:queries_endpoint",
                                source_id=page_nid,
                                target_id=route_nid,
                                kind="queries_endpoint",
                                verification="declared",
                                evidence_path=f"{rel}:{ep.lineno}",
                                evidence_note=f"Stdlib HTTP handler serves `{tag}` at `GET {ep.full_path}`.",
                                symbol_links=[f"*->{rkey}"],
                            )
                        )

            result.routes.append(
                RouteDescriptor(
                    node_id=route_nid,
                    http_method=ep.method,
                    full_path=ep.full_path,
                    path_regex=_compile_daemon_route_regex(ep.full_path, is_prefix=ep.is_prefix),
                    source_file=rel,
                    line=ep.lineno,
                    called_symbols=frozenset(ep.called_symbols | {ep.handler_symbol}),
                    imported_modules=frozenset(),
                )
            )

        path_cap_note = (
            f" ({len(http_paths)} total paths; {len(http_paths) - 25} omitted beyond 25-path cap)"
            if len(http_paths) > 25
            else ""
        )
        summary_parts = [
            f"Daemon route surface `{label}` ({', '.join(methods)} {', '.join(http_paths[:6])}){path_cap_note}."
        ]
        if binding_notes:
            summary_parts.append(
                "Bound via " + ", ".join(dict.fromkeys(b[1] for b in binding_notes)) + "."
            )
        if html_tags:
            summary_parts.append(f"Serves HTML view (text/html: {', '.join(html_tags)}).")

        result.nodes.append(
            AtlasNode(
                id=route_nid,
                tier="manipulate",
                subkind="route",
                label=label,
                source_file=rel,
                line=lineno,
                cluster=cluster,
                summary=" ".join(summary_parts),
                http_methods=methods,
                http_paths=http_paths[:25],
            )
        )
        result.edges.append(
            AtlasEdge(
                id=f"e:route:{route_nid}->{host_script_nid}",
                source_id=route_nid,
                target_id=host_script_nid,
                kind="calls_helper",
                verification="verified",
                evidence_path=f"{rel}:{lineno}",
                evidence_note=f"AST-verified daemon route handler `{label}` in `{rel}`.",
                symbol_links=slinks_to_host,
            )
        )
        for bind_rel, bind_lbl, bind_sc in binding_notes:
            launcher_nid = script_id(bind_rel)
            result.edges.append(
                AtlasEdge(
                    id=f"e:httpserver:{bind_rel}:{bind_sc}->{route_nid}",
                    source_id=launcher_nid,
                    target_id=route_nid,
                    kind="calls_helper",
                    verification="declared",
                    evidence_path=f"{bind_rel}:1",
                    evidence_note=f"Static `{bind_lbl}` binding mounting `{label}`.",
                    symbol_links=[f"{bind_sc}->*"],
                )
            )

    for rel, tree in sorted(trees.items()):
        mod_str_env = _collect_str_bindings(tree.body, {})
        mod_dict_routes = _collect_dict_route_keys(tree.body)
        handler_classes: set[str] = set()
        emitted_slugs: set[str] = set()

        def _collect_class_defs(
            stmts: list[ast.stmt],
            parent_env: dict[str, str],
            parent_dict_routes: dict[str, list[tuple[str, int, set[str]]]],
            enclosing_fn: str | None = None,
        ) -> list[tuple[ast.ClassDef, dict[str, str], dict[str, list[tuple[str, int, set[str]]]], str | None]]:
            found_cls: list[
                tuple[ast.ClassDef, dict[str, str], dict[str, list[tuple[str, int, set[str]]]], str | None]
            ] = []
            for s in stmts:
                if isinstance(s, ast.If) and (
                    (isinstance(s.test, ast.Name) and s.test.id == "TYPE_CHECKING")
                    or (isinstance(s.test, ast.Attribute) and s.test.attr == "TYPE_CHECKING")
                ):
                    continue
                if isinstance(s, ast.ClassDef):
                    found_cls.append((s, parent_env, parent_dict_routes, enclosing_fn))
                    found_cls.extend(_collect_class_defs(s.body, parent_env, parent_dict_routes, enclosing_fn))
                elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_env = _collect_str_bindings(s.body, parent_env)
                    fn_dict_routes = {**parent_dict_routes, **_collect_dict_route_keys(s.body)}
                    found_cls.extend(_collect_class_defs(s.body, fn_env, fn_dict_routes, s.name))
                else:
                    for attr_name in ("body", "orelse", "finalbody"):
                        sub_body = getattr(s, attr_name, None)
                        if isinstance(sub_body, list):
                            found_cls.extend(
                                _collect_class_defs(sub_body, parent_env, parent_dict_routes, enclosing_fn)
                            )
                    for handler in getattr(s, "handlers", []):
                        if isinstance(handler, ast.ExceptHandler):
                            found_cls.extend(
                                _collect_class_defs(handler.body, parent_env, parent_dict_routes, enclosing_fn)
                            )
            return found_cls

        for stmt, outer_env, outer_dict_routes, enclosing_fn in _collect_class_defs(
            tree.body, mod_str_env, mod_dict_routes
        ):
            base_names = {
                b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
                for b in stmt.bases
            }
            cls_methods = {
                m.name: m
                for m in stmt.body
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            is_http_handler = bool(
                any(bn.endswith("RequestHandler") for bn in base_names)
                or (base_names & handler_classes)
                or (any(bn for bn in base_names) and (set(cls_methods) & set(_DO_METHODS)))
            )
            if not is_http_handler:
                continue
            handler_classes.add(stmt.name)
            cls_str_env = _collect_str_bindings(stmt.body, outer_env)
            cls_dict_routes = {**outer_dict_routes, **_collect_dict_route_keys(stmt.body)}
            cls_eps: list[_ExtractedEndpoint] = []
            for do_name, verb in _DO_METHODS.items():
                if do_name in cls_methods:
                    extracted_do = _extract_handler_method_endpoints(
                        cls_methods[do_name], verb, cls_methods, cls_dict_routes, cls_str_env
                    )
                    if extracted_do:
                        cls_eps.extend(extracted_do)
                    else:
                        result.notes.append(
                            f"Stdlib HTTP handler `{rel}:{stmt.name}.{do_name}` defines no static path branches; catch-all route matching omitted."
                        )
            if cls_eps:
                slug = (
                    f"{enclosing_fn}.{stmt.name}"
                    if (enclosing_fn and stmt.name in emitted_slugs)
                    else stmt.name
                )
                emitted_slugs.add(slug)
                _emit_route_group(
                    rel,
                    slug,
                    f"{PurePosixPath(rel).stem}.{slug}",
                    "daemon_http",
                    stmt.lineno,
                    cls_eps,
                    global_bindings.get(stmt.name, []),
                )

        mcp_eps = _extract_mcp_endpoints(tree)
        if mcp_eps:
            _emit_route_group(
                rel,
                "mcp",
                f"{PurePosixPath(rel).stem}.mcp",
                "mcp_tools",
                mcp_eps[0].lineno,
                mcp_eps,
                [],
            )

        fastapi_eps = _extract_fastapi_starlette_endpoints(rel, tree, mod_str_env, router_mounts)
        if fastapi_eps:
            _emit_route_group(
                rel,
                "fastapi",
                f"{PurePosixPath(rel).stem}.fastapi",
                "fastapi_http",
                fastapi_eps[0].lineno,
                fastapi_eps,
                [],
            )

    # Extract static subprocess script invocations across all parsed Python modules
    for rel, tree in sorted(trees.items()):
        sub_targets = _extract_subprocess_targets(rel, tree, paths, py_paths, roots, deployments)
        rel_rkeys = route_keys_by_rel.get(rel, {})
        for target_rel, (ln, scopes) in sorted(sub_targets.items()):
            slinks: list[str] = []
            for sc in scopes:
                slinks.append(f"{sc}->*")
                for rk in rel_rkeys.get(sc, ()):
                    if f"{rk}->*" not in slinks:
                        slinks.append(f"{rk}->*")
            result.edges.append(
                AtlasEdge(
                    id=f"e:subprocess:{rel}:{target_rel}",
                    source_id=script_id(rel),
                    target_id=script_id(target_rel),
                    kind="calls_helper",
                    verification="declared",
                    evidence_path=f"{rel}:{ln}",
                    evidence_note=(
                        f"Static subprocess invocation in `{', '.join(scopes)}` targeting `{target_rel}`; "
                        "runtime arguments and execution state are not inferred."
                    ),
                    symbol_links=slinks,
                )
            )
    return route_keys_by_rel
