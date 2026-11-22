"""Stdlib HTTPServer/BaseHTTPRequestHandler, MCP tool routes, and static subprocess edges."""

from __future__ import annotations

import ast
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.adapters.base import ManipulatorExtractionResult, RouteDescriptor
from app.adapters.deployment_sources import normalize_home
from app.adapters.inline_store_truth import _collect_str_bindings, _eval_str_expr
from app.adapters.launchd_sources import shell_references
from app.adapters.service_sources import script_id, source_files, source_reference
from app.adapters.ts_workspace import safe_read_repo_text, safe_resolve_contained_path
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
    if is_prefix and norm != "/" and "{param}" not in full_path:
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


_UI_SOURCE_SUFFIXES = frozenset({".tsx", ".jsx", ".vue", ".svelte"})
_DEMO_PATH_SEGMENTS = frozenset({"examples", "example", "demos", "demo", "samples", "sample"})
_ROOT_HTML_DIRS = ("ui", "static", "public", "templates", "views", "web")
_DAEMON_HTML_MARKERS = ("text/html", "htmlresponse", "<!doctype html", "<html")


def _is_isolated_demo_path(path: Path, repo_root: Path) -> bool:
    try:
        rel_parts = path.relative_to(repo_root).parts[:-1]
    except ValueError:
        return False
    return any(part.lower() in _DEMO_PATH_SEGMENTS for part in rel_parts)


def _has_root_html_ui(repo_root: Path) -> bool:
    try:
        if repo_root.is_symlink():
            return False
        entries = list(repo_root.iterdir())
    except OSError:
        return False
    for p in entries:
        if p.name == "node_modules" or p.name.startswith("."):
            continue
        try:
            if not p.is_symlink() and p.is_file() and p.suffix.lower() in {".html", ".htm"}:
                return True
        except OSError:
            continue
    for dname in _ROOT_HTML_DIRS:
        d = repo_root / dname
        try:
            if not d.is_dir() or d.is_symlink():
                continue
            html_files, _ = source_files(d, {".html", ".htm"})
        except OSError:
            continue
        if any(not _is_isolated_demo_path(p, repo_root) for p in html_files):
            return True
    return False


def _detect_python_daemon_context(
    repo_root: Path,
    apps_ui_count: int,
    *,
    py_count: int | None,
    has_daemon_html: bool | None,
) -> tuple[bool, bool]:
    """Return `(has_daemon_html_ui, predominantly_python_services)` for `apps/**` gating."""
    try:
        if repo_root.is_symlink():
            return False, False
    except OSError:
        return False, False
    daemon_html = bool(has_daemon_html)
    try:
        has_svc_units = bool(source_files(repo_root, {".plist", ".service"})[0])
    except OSError:
        has_svc_units = False
    eff_py = py_count
    if eff_py is None or has_daemon_html is None:
        try:
            all_py, _ = source_files(repo_root, {".py"})
        except OSError:
            all_py = []
        apps_root = repo_root / "apps"
        try:
            has_apps_dir = apps_root.is_dir()
        except OSError:
            has_apps_dir = False
        non_demo_py = [
            p
            for p in all_py
            if not _is_isolated_demo_path(p, repo_root)
            and not (has_apps_dir and p.is_relative_to(apps_root))
        ]
        if eff_py is None:
            eff_py = len(non_demo_py)
        if has_daemon_html is None:
            for py_f in non_demo_py[:200]:
                try:
                    st = py_f.lstat()
                    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                        continue
                    low = safe_read_repo_text(py_f, repo_root, encoding="utf-8", errors="replace").lower()
                except (OSError, ValueError):
                    continue
                if any(marker in low for marker in _DAEMON_HTML_MARKERS):
                    daemon_html = True
                    break
    predominantly_py = has_svc_units or eff_py >= 8 or (eff_py >= 3 and eff_py > apps_ui_count)
    return daemon_html, predominantly_py


def _has_external_display_sources(
    repo_root: Path,
    *,
    py_count: int | None = None,
    has_daemon_html: bool | None = None,
) -> bool:
    try:
        if repo_root.is_symlink():
            return False
    except OSError:
        return False
    for cand in ("frontend", "web", "client", "ui"):
        d = repo_root / cand
        try:
            if not d.is_dir() or d.is_symlink():
                continue
            found, _ = source_files(d, set(_UI_SOURCE_SUFFIXES))
        except OSError:
            continue
        if any(not _is_isolated_demo_path(p, repo_root) for p in found):
            return True
    src_dir = repo_root / "src"
    try:
        src_ok = src_dir.is_dir() and not src_dir.is_symlink()
        root_ui = source_files(src_dir, set(_UI_SOURCE_SUFFIXES))[0] if src_ok else []
    except OSError:
        root_ui = []
    if any(not _is_isolated_demo_path(p, repo_root) for p in root_ui):
        return True
    apps_dir = repo_root / "apps"
    try:
        apps_ok = apps_dir.is_dir() and not apps_dir.is_symlink()
        raw_apps = source_files(apps_dir, set(_UI_SOURCE_SUFFIXES))[0] if apps_ok else []
    except OSError:
        raw_apps = []
    if raw_apps:
        apps_found = [p for p in raw_apps if not _is_isolated_demo_path(p, repo_root)]
        if len(apps_found) >= 8:
            if _has_root_html_ui(repo_root):
                return False
            daemon_html, predominantly_py = _detect_python_daemon_context(
                repo_root,
                len(apps_found),
                py_count=py_count,
                has_daemon_html=has_daemon_html,
            )
            return not (daemon_html or predominantly_py)
    return False


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


def _dotted_attr(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _called_qualified_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name):
                names.add(sub.func.id)
            elif isinstance(sub.func, ast.Attribute):
                q = _dotted_attr(sub.func)
                if q is not None:
                    names.add(q)
    return names


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
    called_qualified: set[str] = field(default_factory=set)
    serves_html: bool = False
    html_ref: str | None = None


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _self_call_arg0(expr: ast.Call) -> ast.AST | None:
    if expr.args:
        return expr.args[0]
    if expr.keywords:
        return expr.keywords[0].value
    return None


def _is_urlparse_of_self_path(
    expr: ast.AST,
    path_vars: set[str],
    path_helpers: set[str] | None = None,
    tuple_helpers: dict[str, set[int]] | None = None,
    arg0_helpers: set[str] | None = None,
    tuple_vars: dict[str, set[int]] | None = None,
) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    return _call_name(expr) in {"urlparse", "urlsplit"} and bool(expr.args) and _is_path_expr(
        expr.args[0],
        path_vars,
        set(),
        path_helpers,
        tuple_helpers,
        arg0_helpers,
        tuple_vars,
    )


def _is_path_expr(
    expr: ast.AST | None,
    path_vars: set[str],
    parsed_vars: set[str],
    path_helpers: set[str] | None = None,
    tuple_helpers: dict[str, set[int]] | None = None,
    arg0_helpers: set[str] | None = None,
    tuple_vars: dict[str, set[int]] | None = None,
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
            or _is_urlparse_of_self_path(
                expr.value, path_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
            )
        ):
            return True
    if isinstance(expr, ast.Call):
        if (
            isinstance(expr.func, ast.Attribute)
            and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id == "self"
        ):
            m_name = expr.func.attr
            if path_helpers and m_name in path_helpers:
                return True
            if arg0_helpers and m_name in arg0_helpers:
                a0 = _self_call_arg0(expr)
                if a0 is not None and _is_path_expr(
                    a0, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
                ):
                    return True
        fn_name = _call_name(expr)
        if fn_name in {"unquote", "unquote_plus", "normpath"} and expr.args:
            return _is_path_expr(
                expr.args[0],
                path_vars,
                parsed_vars,
                path_helpers,
                tuple_helpers,
                arg0_helpers,
                tuple_vars,
            )
        if (
            isinstance(expr.func, ast.Attribute)
            and expr.func.attr in {"rstrip", "strip", "lstrip", "removeprefix", "removesuffix", "replace"}
            and _is_path_expr(
                expr.func.value,
                path_vars,
                parsed_vars,
                path_helpers,
                tuple_helpers,
                arg0_helpers,
                tuple_vars,
            )
        ):
            return True
    if isinstance(expr, ast.Subscript):
        if isinstance(expr.slice, ast.Slice) and _is_path_expr(
            expr.value, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
        ):
            return True
        if (
            isinstance(expr.slice, ast.Constant)
            and isinstance(expr.slice.value, int)
            and not isinstance(expr.slice.value, bool)
        ):
            idx = expr.slice.value
            if (
                idx == 0
                and isinstance(expr.value, ast.Call)
                and isinstance(expr.value.func, ast.Attribute)
                and expr.value.func.attr in {"split", "partition"}
                and _is_path_expr(
                    expr.value.func.value,
                    path_vars,
                    parsed_vars,
                    path_helpers,
                    tuple_helpers,
                    arg0_helpers,
                    tuple_vars,
                )
            ):
                return True
            if (
                tuple_helpers
                and isinstance(expr.value, ast.Call)
                and isinstance(expr.value.func, ast.Attribute)
                and isinstance(expr.value.func.value, ast.Name)
                and expr.value.func.value.id == "self"
                and expr.value.func.attr in tuple_helpers
                and idx in tuple_helpers[expr.value.func.attr]
            ):
                return True
            if (
                tuple_vars
                and isinstance(expr.value, ast.Name)
                and expr.value.id in tuple_vars
                and idx in tuple_vars[expr.value.id]
            ):
                return True
    if isinstance(expr, ast.IfExp):
        return _is_path_expr(
            expr.body, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
        ) or _is_path_expr(
            expr.orelse, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
        )
    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or) and expr.values:
        return _is_path_expr(
            expr.values[0], path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
        )
    return False


def _propagate_path_vars_in_fn(
    fn_def: ast.FunctionDef | ast.AsyncFunctionDef,
    path_vars: set[str],
    parsed_vars: set[str],
    tuple_vars: dict[str, set[int]],
    path_helpers: set[str],
    tuple_helpers: dict[str, set[int]],
    arg0_helpers: set[str],
    arg0_tuple_helpers: dict[str, set[int]],
) -> None:
    def _tuple_path_indices(rhs: ast.AST) -> set[int]:
        if (
            isinstance(rhs, ast.Call)
            and isinstance(rhs.func, ast.Attribute)
            and isinstance(rhs.func.value, ast.Name)
            and rhs.func.value.id == "self"
        ):
            m_name = rhs.func.attr
            if m_name in tuple_helpers:
                return set(tuple_helpers[m_name])
            if m_name in arg0_tuple_helpers:
                a0 = _self_call_arg0(rhs)
                if a0 is not None and _is_path_expr(
                    a0, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
                ):
                    return set(arg0_tuple_helpers[m_name])
        if (
            isinstance(rhs, ast.Call)
            and isinstance(rhs.func, ast.Attribute)
            and rhs.func.attr in {"split", "partition"}
            and _is_path_expr(
                rhs.func.value, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
            )
        ):
            return {0}
        if isinstance(rhs, (ast.Tuple, ast.List)):
            return {
                idx
                for idx, elt in enumerate(rhs.elts)
                if _is_path_expr(
                    elt, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
                )
            }
        if isinstance(rhs, ast.Name) and rhs.id in tuple_vars:
            return set(tuple_vars[rhs.id])
        return set()

    for sub in ast.walk(fn_def):
        targets: list[ast.AST] = []
        rhs: ast.AST | None = None
        if isinstance(sub, ast.Assign):
            targets, rhs = list(sub.targets), sub.value
        elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
            targets, rhs = [sub.target], sub.value
        if rhs is None:
            continue
        for tgt in targets:
            if isinstance(tgt, ast.Name):
                if _is_urlparse_of_self_path(
                    rhs, path_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
                ):
                    parsed_vars.add(tgt.id)
                elif _is_path_expr(
                    rhs, path_vars, parsed_vars, path_helpers, tuple_helpers, arg0_helpers, tuple_vars
                ):
                    path_vars.add(tgt.id)
                elif idxs := _tuple_path_indices(rhs):
                    tuple_vars[tgt.id] = idxs
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                idxs = _tuple_path_indices(rhs)
                for idx, elt in enumerate(tgt.elts):
                    if isinstance(elt, ast.Name) and idx in idxs:
                        path_vars.add(elt.id)


def _discover_class_path_helpers(
    class_methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[set[str], dict[str, set[int]], set[str], dict[str, set[int]]]:
    helpers: set[str] = set()
    tuple_helpers: dict[str, set[int]] = {}
    arg0_helpers: set[str] = set()
    arg0_tuple_helpers: dict[str, set[int]] = {}
    for _ in range(4):
        before = (len(helpers), len(tuple_helpers), len(arg0_helpers), len(arg0_tuple_helpers))
        for m_name, m_def in class_methods.items():
            if m_name in _DO_METHODS:
                continue
            m_pvars = {
                arg.arg
                for arg in m_def.args.args[1:]
                if any(tok in arg.arg.lower() for tok in ("path", "route", "url", "uri"))
            }
            m_parsed: set[str] = set()
            m_tvars: dict[str, set[int]] = {}
            for _pass in range(2):
                _propagate_path_vars_in_fn(
                    m_def,
                    m_pvars,
                    m_parsed,
                    m_tvars,
                    helpers,
                    tuple_helpers,
                    arg0_helpers,
                    arg0_tuple_helpers,
                )
            for sub in ast.walk(m_def):
                if not isinstance(sub, ast.Return) or sub.value is None:
                    continue
                if _is_path_expr(
                    sub.value, m_pvars, m_parsed, helpers, tuple_helpers, arg0_helpers, m_tvars
                ):
                    helpers.add(m_name)
                elif isinstance(sub.value, (ast.Tuple, ast.List)):
                    ret_idxs = {
                        idx
                        for idx, elt in enumerate(sub.value.elts)
                        if _is_path_expr(
                            elt, m_pvars, m_parsed, helpers, tuple_helpers, arg0_helpers, m_tvars
                        )
                    }
                    if ret_idxs:
                        tuple_helpers.setdefault(m_name, set()).update(ret_idxs)
            if m_name not in helpers and len(m_def.args.args) >= 2:
                a0_pvars = set(m_pvars) | {m_def.args.args[1].arg}
                a0_parsed: set[str] = set(m_parsed)
                a0_tvars: dict[str, set[int]] = dict(m_tvars)
                for _pass in range(2):
                    _propagate_path_vars_in_fn(
                        m_def,
                        a0_pvars,
                        a0_parsed,
                        a0_tvars,
                        helpers,
                        tuple_helpers,
                        arg0_helpers,
                        arg0_tuple_helpers,
                    )
                for sub in ast.walk(m_def):
                    if not isinstance(sub, ast.Return) or sub.value is None:
                        continue
                    if _is_path_expr(
                        sub.value, a0_pvars, a0_parsed, helpers, tuple_helpers, arg0_helpers, a0_tvars
                    ):
                        arg0_helpers.add(m_name)
                    elif m_name not in tuple_helpers and isinstance(sub.value, (ast.Tuple, ast.List)):
                        ret_idxs = {
                            idx
                            for idx, elt in enumerate(sub.value.elts)
                            if _is_path_expr(
                                elt, a0_pvars, a0_parsed, helpers, tuple_helpers, arg0_helpers, a0_tvars
                            )
                        }
                        if ret_idxs:
                            arg0_tuple_helpers.setdefault(m_name, set()).update(ret_idxs)
        if (len(helpers), len(tuple_helpers), len(arg0_helpers), len(arg0_tuple_helpers)) == before:
            break
    return helpers, tuple_helpers, arg0_helpers, arg0_tuple_helpers


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
    idx_b = 0
    while idx_b < len(bodies):
        cur_fn = bodies[idx_b]
        idx_b += 1
        for sub in ast.walk(cur_fn):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id == "self"
                and sub.func.attr in class_methods
                and class_methods[sub.func.attr] not in bodies
            ):
                bodies.append(class_methods[sub.func.attr])

    path_helpers, tuple_helpers, arg0_helpers, arg0_tuple_helpers = _discover_class_path_helpers(
        class_methods
    )
    path_vars: set[str] = set()
    parsed_vars: set[str] = set()
    tuple_vars: dict[str, set[int]] = {}
    local_routes = dict(dict_routes)
    local_str_env = dict(str_env)
    for idx, helper_fn in enumerate(bodies):
        local_routes.update(_collect_dict_route_keys(helper_fn.body))
        local_str_env = _collect_str_bindings(helper_fn.body, local_str_env)
        if idx > 0:
            for arg in helper_fn.args.args[1:]:
                if any(tok in arg.arg.lower() for tok in ("path", "route", "url", "uri")):
                    path_vars.add(arg.arg)
    for _pass in range(4):
        before_pv = (len(path_vars), len(parsed_vars), len(tuple_vars))
        for helper_fn in bodies:
            _propagate_path_vars_in_fn(
                helper_fn,
                path_vars,
                parsed_vars,
                tuple_vars,
                path_helpers,
                tuple_helpers,
                arg0_helpers,
                arg0_tuple_helpers,
            )
            for sub in ast.walk(helper_fn):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and isinstance(sub.func.value, ast.Name)
                    and sub.func.value.id == "self"
                    and sub.func.attr in class_methods
                ):
                    callee = class_methods[sub.func.attr]
                    callee_params = callee.args.args[1:]
                    for pos_i, arg_node in enumerate(sub.args):
                        if pos_i < len(callee_params) and _is_path_expr(
                            arg_node,
                            path_vars,
                            parsed_vars,
                            path_helpers,
                            tuple_helpers,
                            arg0_helpers,
                            tuple_vars,
                        ):
                            path_vars.add(callee_params[pos_i].arg)
                    for kw in sub.keywords:
                        if kw.arg and _is_path_expr(
                            kw.value,
                            path_vars,
                            parsed_vars,
                            path_helpers,
                            tuple_helpers,
                            arg0_helpers,
                            tuple_vars,
                        ):
                            path_vars.add(kw.arg)
        if (len(path_vars), len(parsed_vars), len(tuple_vars)) == before_pv:
            break

    all_called: set[str] = set()
    all_qualified: set[str] = set()
    serves_html = False
    html_ref: str | None = None
    for b_fn in bodies:
        all_called |= _called_func_names(b_fn)
        all_qualified |= _called_qualified_names(b_fn)
        sh, hr = _scan_html_markers(b_fn, local_str_env)
        serves_html = serves_html or sh
        html_ref = html_ref or hr

    found: list[_ExtractedEndpoint] = []
    seen: set[tuple[str, bool]] = set()

    def _is_pexpr(node_e: ast.AST | None) -> bool:
        return _is_path_expr(
            node_e,
            path_vars,
            parsed_vars,
            path_helpers,
            tuple_helpers,
            arg0_helpers,
            tuple_vars,
        )

    def _add(raw_p: str, is_pfx: bool, ln: int, branch_node: ast.AST | None = None) -> None:
        if not raw_p or not raw_p.startswith("/"):
            return
        base_norm = _norm_http_path(raw_p)
        if is_pfx and base_norm == "/":
            return
        if is_pfx and raw_p.endswith("/"):
            norm_p = base_norm + "/{param}"
        else:
            norm_p = base_norm
        if (norm_p, is_pfx) in seen:
            return
        seen.add((norm_p, is_pfx))
        b_called = _called_func_names(branch_node) if branch_node is not None else set(all_called)
        b_qualified = _called_qualified_names(branch_node) if branch_node is not None else set(all_qualified)
        expand_q = [m for m in b_called if m in class_methods]
        seen_methods = set(expand_q)
        while expand_q:
            m_name = expand_q.pop()
            sub_calls = _called_func_names(class_methods[m_name])
            b_called |= sub_calls
            b_qualified |= _called_qualified_names(class_methods[m_name])
            for nxt in sub_calls:
                if nxt in class_methods and nxt not in seen_methods:
                    seen_methods.add(nxt)
                    expand_q.append(nxt)
        if branch_node is not None:
            b_sh, b_hr = _scan_html_markers(branch_node, local_str_env)
            for m_name in seen_methods:
                m_sh, m_hr = _scan_html_markers(class_methods[m_name], local_str_env)
                b_sh = b_sh or m_sh
                b_hr = b_hr or m_hr
        else:
            b_sh, b_hr = serves_html, html_ref
        found.append(
            _ExtractedEndpoint(
                method=verb,
                full_path=norm_p,
                is_prefix=is_pfx,
                lineno=ln,
                handler_symbol=fn_def.name,
                called_symbols=b_called | {fn_def.name},
                called_qualified=b_qualified | {fn_def.name},
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

    def _extract_route_elts(node_e: ast.AST) -> list[str]:
        if isinstance(node_e, (ast.Tuple, ast.List, ast.Set)):
            return [s for elt in node_e.elts if (s := _static_route_str(elt))]
        if (
            isinstance(node_e, ast.Call)
            and isinstance(node_e.func, ast.Name)
            and node_e.func.id in {"frozenset", "set", "tuple", "list"}
            and node_e.args
            and isinstance(node_e.args[0], (ast.Tuple, ast.List, ast.Set))
        ):
            return [s for elt in node_e.args[0].elts if (s := _static_route_str(elt))]
        if isinstance(node_e, ast.Name) and node_e.id in local_routes:
            return list(local_routes[node_e.id])
        return []

    def _extract_positive_cond(expr: ast.AST, ln: int, branch: ast.AST | None) -> None:
        if isinstance(expr, ast.BoolOp) and isinstance(expr.op, (ast.Or, ast.And)):
            for v in expr.values:
                _extract_positive_cond(v, ln, branch)
            return
        if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and len(expr.comparators) == 1:
            op, left, right = expr.ops[0], expr.left, expr.comparators[0]
            if isinstance(op, ast.Eq):
                if _is_pexpr(left) and (sr := _static_route_str(right)):
                    _add(sr, False, ln, branch)
                elif _is_pexpr(right) and (sl := _static_route_str(left)):
                    _add(sl, False, ln, branch)
            elif isinstance(op, ast.In) and _is_pexpr(left):
                for se in _extract_route_elts(right):
                    _add(se, False, ln, branch)
        elif isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if expr.func.attr == "startswith" and _is_pexpr(expr.func.value) and expr.args:
                arg0 = expr.args[0]
                if s0 := _static_route_str(arg0):
                    _add(s0, True, ln, branch)
                elif isinstance(arg0, ast.Tuple):
                    for elt in arg0.elts:
                        if se := _static_route_str(elt):
                            _add(se, True, ln, branch)
            elif (
                expr.func.attr in {"match", "fullmatch"}
                and len(expr.args) >= 2
                and isinstance(expr.args[0], ast.Constant)
                and isinstance(expr.args[0].value, str)
                and _is_pexpr(expr.args[1])
                and (rx_p := _regex_pattern_to_route_path(expr.args[0].value))
            ):
                _add(rx_p, False, ln, branch)

    def _extract_guard_test(test_expr: ast.AST, ln: int, guard_branch: ast.AST | None) -> None:
        if isinstance(test_expr, ast.BoolOp) and isinstance(test_expr.op, (ast.And, ast.Or)):
            for v in test_expr.values:
                _extract_guard_test(v, ln, guard_branch)
            return
        if isinstance(test_expr, ast.UnaryOp) and isinstance(test_expr.op, ast.Not):
            _extract_positive_cond(test_expr.operand, ln, guard_branch)
            return
        if isinstance(test_expr, ast.Compare) and len(test_expr.ops) == 1 and len(test_expr.comparators) == 1:
            op, left, right = test_expr.ops[0], test_expr.left, test_expr.comparators[0]
            if isinstance(op, ast.NotEq):
                if _is_pexpr(left) and (sr := _static_route_str(right)):
                    _add(sr, False, ln, guard_branch)
                elif _is_pexpr(right) and (sl := _static_route_str(left)):
                    _add(sl, False, ln, guard_branch)
            elif isinstance(op, ast.NotIn) and _is_pexpr(left):
                for se in _extract_route_elts(right):
                    _add(se, False, ln, guard_branch)

    def _extract_positive_if_test(test_expr: ast.AST, ln: int, if_body: ast.AST) -> None:
        if isinstance(test_expr, ast.UnaryOp) and isinstance(test_expr.op, ast.Not):
            return
        if isinstance(test_expr, ast.BoolOp):
            for v in test_expr.values:
                _extract_positive_if_test(v, ln, if_body)
            return
        _extract_positive_cond(test_expr, ln, if_body)

    def _branch_terminates_early(stmts: list[ast.stmt]) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.If) and last.orelse:
            return _branch_terminates_early(last.body) and _branch_terminates_early(last.orelse)
        return False

    def _walk_stmt_list(stmts: list[ast.stmt], trailing_stmts: list[ast.stmt]) -> None:
        for idx, sub in enumerate(stmts):
            rest = [*stmts[idx + 1 :], *trailing_stmts]
            if isinstance(sub, ast.If):
                if_body = ast.Module(body=sub.body, type_ignores=[])
                terminates_early = _branch_terminates_early(sub.body)
                if terminates_early or sub.orelse:
                    cont_stmts = [*sub.orelse, *rest] if terminates_early else list(sub.orelse)
                    guard_branch = ast.Module(body=cont_stmts, type_ignores=[]) if cont_stmts else None
                    _extract_guard_test(sub.test, sub.lineno, guard_branch)
                _extract_positive_if_test(sub.test, sub.lineno, if_body)
                _walk_stmt_list(sub.body, [] if terminates_early else rest)
                _walk_stmt_list(sub.orelse, rest)
            elif isinstance(sub, ast.Match) and _is_pexpr(sub.subject):
                for case in sub.cases:
                    pats = (
                        list(case.pattern.patterns)
                        if isinstance(case.pattern, ast.MatchOr)
                        else [case.pattern]
                    )
                    for p_item in pats:
                        if (
                            isinstance(p_item, ast.MatchValue)
                            and isinstance(p_item.value, ast.Constant)
                            and isinstance(p_item.value.value, str)
                        ):
                            _add(
                                p_item.value.value,
                                False,
                                getattr(p_item, "lineno", sub.lineno),
                                ast.Module(body=case.body, type_ignores=[]),
                            )
                    _walk_stmt_list(case.body, rest)
            else:
                for attr_name in ("body", "orelse", "finalbody"):
                    sub_body = getattr(sub, attr_name, None)
                    if isinstance(sub_body, list):
                        _walk_stmt_list(sub_body, rest)
                for handler in getattr(sub, "handlers", []):
                    if isinstance(handler, ast.ExceptHandler):
                        _walk_stmt_list(handler.body, rest)
                for call_n in ast.walk(sub):
                    if (
                        isinstance(call_n, ast.Call)
                        and isinstance(call_n.func, ast.Attribute)
                        and call_n.func.attr == "get"
                        and isinstance(call_n.func.value, ast.Name)
                        and call_n.func.value.id in local_routes
                        and call_n.args
                        and _is_pexpr(call_n.args[0])
                    ):
                        for r_key in local_routes[call_n.func.value.id]:
                            _add(r_key, False, call_n.lineno, None)

    for b_fn in bodies:
        _walk_stmt_list(b_fn.body, [])

    return found


def _build_module_stem_index(trees: dict[str, ast.Module]) -> dict[str, list[str]]:
    by_stem: dict[str, list[str]] = {}
    for r in trees:
        p = PurePosixPath(r)
        mod_dot = ".".join(p.with_suffix("").parts)
        by_stem.setdefault(mod_dot, []).append(r)
        if p.name == "__init__.py" and len(p.parts) > 1:
            by_stem.setdefault(".".join(p.parent.parts), []).append(r)
    return by_stem


def _resolve_import_target(
    rel: str, module: str | None, level: int, by_stem: dict[str, list[str]]
) -> list[str]:
    if level > 0:
        parts = PurePosixPath(rel).parent.parts
        if level - 1 <= len(parts):
            base_parts = parts[: len(parts) - level + 1]
            dotted = ".".join([*base_parts, *(module.split(".") if module else [])])
            if dotted in by_stem:
                return list(by_stem[dotted])
    if module:
        return [
            r
            for m_key, rels in by_stem.items()
            if m_key == module or m_key.endswith("." + module)
            for r in rels
        ]
    return []


def _resolve_module_imports(
    rel: str, tree: ast.Module, by_stem: dict[str, list[str]]
) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    """Return `(imp_symbols: {alias: (target_rel, orig)}, imp_modules: {alias: target_rel})`."""
    imp_symbols: dict[str, tuple[str, str]] = {}
    imp_modules: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            if n.module:
                cand = _resolve_import_target(rel, n.module, n.level, by_stem)
                if len(cand) == 1:
                    for al in n.names:
                        imp_symbols[al.asname or al.name] = (cand[0], al.name)
            elif n.level > 0:
                for al in n.names:
                    cand = _resolve_import_target(rel, al.name, n.level, by_stem)
                    if len(cand) == 1:
                        imp_modules[al.asname or al.name] = cand[0]
        elif isinstance(n, ast.Import):
            for al in n.names:
                cand = _resolve_import_target(rel, al.name, 0, by_stem)
                if len(cand) == 1:
                    imp_modules[al.asname or al.name] = cand[0]
    return imp_symbols, imp_modules


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
    all_imports = [
        n for tree in trees.values() for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
    ]
    for _ in range(5):
        before = (len(server_classes), len(handler_classes))
        for n in all_imports:
            for al in n.names:
                if al.asname and al.name in server_classes:
                    server_classes.add(al.asname)
                if al.asname and al.name in handler_classes:
                    handler_classes.add(al.asname)
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
    return server_classes, handler_classes


def _extract_factory_returns(tree: ast.Module) -> dict[str, str]:
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
    return factory_returns


def _resolve_handler_arg_name(
    h_arg: ast.AST | None, factory_returns: dict[str, str]
) -> str:
    if h_arg is None:
        return ""
    if isinstance(h_arg, ast.Name):
        return h_arg.id
    if isinstance(h_arg, ast.Attribute):
        return h_arg.attr
    if isinstance(h_arg, ast.Call):
        return factory_returns.get(_call_name(h_arg), "")
    return ""


def _parse_server_call_args(
    node: ast.Call,
    known_handlers: set[str],
    factory_returns: dict[str, str],
) -> tuple[ast.AST | None, ast.AST | None]:
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
            cand_h = _resolve_handler_arg_name(node.args[0], factory_returns)
            if cand_h and (cand_h in known_handlers or cand_h.endswith("Handler")):
                h_arg = node.args[0]
    return addr_arg, h_arg


def _format_server_addr(
    cls_name: str,
    addr_arg: ast.AST | None,
    consts: dict[str, str | int],
    param_exprs: dict[str, ast.AST] | None = None,
    fallback_consts: dict[str, str | int] | None = None,
) -> str:
    def _eval_scalar(el: ast.AST) -> str | int | None:
        if isinstance(el, ast.Constant) and isinstance(el.value, (str, int)):
            return el.value
        if isinstance(el, ast.Name):
            if param_exprs and el.id in param_exprs and param_exprs[el.id] is not el:
                bound_el = param_exprs[el.id]
                if isinstance(bound_el, ast.Constant) and isinstance(bound_el.value, (str, int)):
                    return bound_el.value
                if isinstance(bound_el, ast.Name):
                    if bound_el.id in consts:
                        return consts[bound_el.id]
                    if fallback_consts and bound_el.id in fallback_consts:
                        return fallback_consts[bound_el.id]
            if el.id in consts:
                return consts[el.id]
            if fallback_consts and el.id in fallback_consts:
                return fallback_consts[el.id]
        return None

    resolved_addr = addr_arg
    if isinstance(resolved_addr, ast.Name) and param_exprs and resolved_addr.id in param_exprs:
        resolved_addr = param_exprs[resolved_addr.id]
    if isinstance(resolved_addr, (ast.Tuple, ast.List)) and len(resolved_addr.elts) == 2:
        host_v = _eval_scalar(resolved_addr.elts[0])
        port_v = _eval_scalar(resolved_addr.elts[1])
        host_lbl = str(host_v) if host_v not in (None, "") else "*"
        port_lbl = str(port_v) if port_v is not None else "*"
        return f"{cls_name}({host_lbl}:{port_lbl})"
    return cls_name


@dataclass(frozen=True)
class _ServerFactorySpec:
    def_rel: str
    fn_name: str
    srv_cls: str
    pos_params: tuple[str, ...]
    kw_params: tuple[str, ...]
    defaults: dict[str, ast.AST]
    handler_param: str
    addr_arg: ast.AST | None
    def_consts: dict[str, str | int]


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
    factory_returns = _extract_factory_returns(tree)

    def _scan_stmts(
        stmts: list[ast.stmt],
        scope_name: str,
        scope_consts: dict[str, str | int],
        param_names: set[str],
    ) -> None:
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_consts = {**scope_consts, **_collect_scalar_consts(s.body)}
                fn_params = {a.arg for a in (*s.args.posonlyargs, *s.args.args, *s.args.kwonlyargs)}
                _scan_stmts(s.body, s.name, fn_consts, fn_params)
                continue
            if isinstance(s, ast.ClassDef):
                cls_consts = {**scope_consts, **_collect_scalar_consts(s.body)}
                for m in s.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fn_consts = {**cls_consts, **_collect_scalar_consts(m.body)}
                        fn_params = {
                            a.arg for a in (*m.args.posonlyargs, *m.args.args, *m.args.kwonlyargs)
                        }
                        _scan_stmts(m.body, m.name, fn_consts, fn_params)
                continue
            for node in ast.walk(s):
                if not isinstance(node, ast.Call):
                    continue
                cls_name = _call_name(node)
                if cls_name not in server_classes:
                    continue
                addr_arg, h_arg = _parse_server_call_args(node, known_handlers, factory_returns)
                h_name = _resolve_handler_arg_name(h_arg, factory_returns)
                if not h_name or (h_name in param_names and h_name not in known_handlers):
                    continue
                addr_str = _format_server_addr(cls_name, addr_arg, scope_consts)
                bindings.setdefault(h_name, []).append((addr_str, scope_name))

    _scan_stmts(tree.body, "*", consts, set())
    return bindings


def _scan_module_factory_calls(
    caller_rel: str,
    tree: ast.Module,
    by_stem: dict[str, list[str]],
    specs_by_key: dict[tuple[str, str], _ServerFactorySpec],
    specs_by_name: dict[str, list[_ServerFactorySpec]],
    handler_aliases: dict[tuple[str, str], str],
    repo_handler_classes: set[str],
    factory_bindings: dict[str, list[tuple[str, str, str]]],
) -> None:
    imp_syms, imp_mods = _resolve_module_imports(caller_rel, tree, by_stem)
    mod_consts = _collect_scalar_consts(tree.body)
    factory_returns = _extract_factory_returns(tree)

    def _scan_caller(
        stmts: list[ast.stmt], scope_name: str, sc_consts: dict[str, str | int]
    ) -> None:
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _scan_caller(st.body, st.name, {**sc_consts, **_collect_scalar_consts(st.body)})
                continue
            if isinstance(st, ast.ClassDef):
                cls_consts = {**sc_consts, **_collect_scalar_consts(st.body)}
                for m in st.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        _scan_caller(m.body, m.name, {**cls_consts, **_collect_scalar_consts(m.body)})
                continue
            for node in ast.walk(st):
                if not isinstance(node, ast.Call):
                    continue
                spec: _ServerFactorySpec | None = None
                if isinstance(node.func, ast.Name):
                    fn_id = node.func.id
                    if fn_id in imp_syms:
                        t_rel, orig_fn = imp_syms[fn_id]
                        spec = specs_by_key.get((t_rel, orig_fn))
                    elif (caller_rel, fn_id) in specs_by_key:
                        spec = specs_by_key[(caller_rel, fn_id)]
                    elif len(specs_by_name.get(fn_id, ())) == 1:
                        spec = specs_by_name[fn_id][0]
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    m_id = node.func.value.id
                    if m_id in imp_mods:
                        spec = specs_by_key.get((imp_mods[m_id], node.func.attr))
                    elif len(specs_by_name.get(node.func.attr, ())) == 1:
                        spec = specs_by_name[node.func.attr][0]
                if spec is None:
                    continue
                bound = dict(spec.defaults)
                for idx, arg_v in enumerate(node.args):
                    if idx < len(spec.pos_params):
                        bound[spec.pos_params[idx]] = arg_v
                for kw in node.keywords:
                    if kw.arg and (kw.arg in spec.pos_params or kw.arg in spec.kw_params):
                        bound[kw.arg] = kw.value
                h_expr = bound.get(spec.handler_param)
                h_name = _resolve_handler_arg_name(h_expr, factory_returns)
                h_name = handler_aliases.get((caller_rel, h_name), h_name)
                if not h_name or (h_name not in repo_handler_classes and not h_name.endswith("Handler")):
                    continue
                addr_str = _format_server_addr(
                    spec.srv_cls, spec.addr_arg, sc_consts, bound, spec.def_consts
                )
                factory_bindings.setdefault(h_name, []).append((caller_rel, addr_str, scope_name))

    _scan_caller(tree.body, "*", mod_consts)


def _discover_server_factory_bindings(
    trees: dict[str, ast.Module],
    repo_server_classes: set[str],
    repo_handler_classes: set[str],
) -> dict[str, list[tuple[str, str, str]]]:
    """Resolve 1-hop cross-module server factory functions `make_server(HandlerCls, ...)`."""
    by_stem = _build_module_stem_index(trees)
    handler_aliases: dict[tuple[str, str], str] = {}
    for rel, tree in trees.items():
        imp_syms, _ = _resolve_module_imports(rel, tree, by_stem)
        for local_name, (_t_rel, orig_name) in imp_syms.items():
            if orig_name in repo_handler_classes or local_name in repo_handler_classes:
                handler_aliases[(rel, local_name)] = orig_name

    specs_by_key: dict[tuple[str, str], _ServerFactorySpec] = {}
    specs_by_name: dict[str, list[_ServerFactorySpec]] = {}

    def _collect_fn_spec(
        rel: str,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        mod_consts: dict[str, str | int],
        factory_returns: dict[str, str],
        is_method: bool,
    ) -> None:
        raw_pos = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args)]
        defaults: dict[str, ast.AST] = {}
        if fn.args.defaults:
            offset = len(raw_pos) - len(fn.args.defaults)
            for idx, d_val in enumerate(fn.args.defaults):
                defaults[raw_pos[offset + idx]] = d_val
        for kw_a, kw_d in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=False):
            if kw_d is not None:
                defaults[kw_a.arg] = kw_d
        pos_params = tuple(
            raw_pos[1:] if is_method and raw_pos and raw_pos[0] in {"self", "cls"} else raw_pos
        )
        kw_params = tuple(a.arg for a in fn.args.kwonlyargs)
        all_params = set(pos_params) | set(kw_params)
        if not all_params:
            return
        fn_consts = {**mod_consts, **_collect_scalar_consts(fn.body)}
        local_param_map: dict[str, str] = {}
        for st in fn.body:
            if (
                isinstance(st, ast.Assign)
                and len(st.targets) == 1
                and isinstance(st.targets[0], ast.Name)
                and isinstance(st.value, ast.Name)
            ):
                src_p = local_param_map.get(st.value.id, st.value.id)
                if src_p in all_params:
                    local_param_map[st.targets[0].id] = src_p

        def _walk_body(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(child, ast.Call) and _call_name(child) in repo_server_classes:
                    addr_arg, h_arg = _parse_server_call_args(
                        child, repo_handler_classes, factory_returns
                    )
                    if isinstance(h_arg, ast.Name):
                        h_param = local_param_map.get(h_arg.id, h_arg.id)
                        if h_param in all_params:
                            spec = _ServerFactorySpec(
                                def_rel=rel,
                                fn_name=fn.name,
                                srv_cls=_call_name(child),
                                pos_params=pos_params,
                                kw_params=kw_params,
                                defaults=defaults,
                                handler_param=h_param,
                                addr_arg=addr_arg,
                                def_consts=fn_consts,
                            )
                            specs_by_key.setdefault((rel, fn.name), spec)
                            specs_by_name.setdefault(fn.name, []).append(spec)
                _walk_body(child)

        _walk_body(ast.Module(body=fn.body, type_ignores=[]))

    for rel, tree in sorted(trees.items()):
        mod_consts = _collect_scalar_consts(tree.body)
        factory_returns = _extract_factory_returns(tree)
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _collect_fn_spec(rel, stmt, mod_consts, factory_returns, False)
            elif isinstance(stmt, ast.ClassDef):
                cls_consts = {**mod_consts, **_collect_scalar_consts(stmt.body)}
                for m in stmt.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        _collect_fn_spec(rel, m, cls_consts, factory_returns, True)

    if not specs_by_key:
        return {}

    factory_bindings: dict[str, list[tuple[str, str, str]]] = {}
    for caller_rel, tree in sorted(trees.items()):
        _scan_module_factory_calls(
            caller_rel,
            tree,
            by_stem,
            specs_by_key,
            specs_by_name,
            handler_aliases,
            repo_handler_classes,
            factory_bindings,
        )
    return factory_bindings


_FASTAPI_DECORATOR_VERBS: dict[str, str] = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "head": "HEAD",
    "options": "OPTIONS",
    "websocket": "GET",
}


def _eval_route_str_expr(
    node: ast.AST | None,
    str_env: dict[str, str],
    scalar_consts: dict[str, str | int] | None = None,
    depth: int = 0,
) -> str | None:
    if node is None or depth > 8:
        return None
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, int) and not isinstance(node.value, bool) and depth > 0:
            return str(node.value)
        return None
    if isinstance(node, ast.Name):
        if node.id in str_env:
            return str_env[node.id]
        if scalar_consts and node.id in scalar_consts and depth > 0:
            return str(scalar_consts[node.id])
        return None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                resolved = _eval_route_str_expr(val.value, str_env, scalar_consts, depth + 1)
                parts.append(resolved if resolved is not None else "__dyn__")
            else:
                parts.append("__dyn__")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_route_str_expr(node.left, str_env, scalar_consts, depth + 1)
        right = _eval_route_str_expr(node.right, str_env, scalar_consts, depth + 1)
        if left is not None and right is not None:
            return left + right
        if left is not None:
            return left + "__dyn__"
        if right is not None:
            return "__dyn__" + right
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        attr = node.func.attr
        base_s = _eval_route_str_expr(node.func.value, str_env, scalar_consts, depth + 1)
        if base_s is not None and attr in {"strip", "rstrip", "lstrip"}:
            arg_s = (
                _eval_route_str_expr(node.args[0], str_env, scalar_consts, depth + 1)
                if node.args
                else None
            )
            if not node.args or arg_s is not None:
                return getattr(base_s, attr)(arg_s)
        if base_s is not None and attr in {"removeprefix", "removesuffix"} and node.args:
            arg_s = _eval_route_str_expr(node.args[0], str_env, scalar_consts, depth + 1)
            if arg_s is not None:
                return getattr(base_s, attr)(arg_s)
    return _eval_str_expr(node, str_env, depth)


def _fn_arg_str_defaults(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    outer_env: dict[str, str],
    scalar_consts: dict[str, str | int],
) -> dict[str, str]:
    out = dict(outer_env)
    pos = [*fn.args.posonlyargs, *fn.args.args]
    if fn.args.defaults:
        offset = len(pos) - len(fn.args.defaults)
        for i, d_val in enumerate(fn.args.defaults):
            ev = _eval_route_str_expr(d_val, outer_env, scalar_consts)
            if ev is not None:
                out[pos[offset + i].arg] = ev
    for kw_a, kw_d in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=False):
        if kw_d is not None:
            ev = _eval_route_str_expr(kw_d, outer_env, scalar_consts)
            if ev is not None:
                out[kw_a.arg] = ev
    return out


def _scan_module_mounts(
    rel: str,
    tree: ast.Module,
    by_stem: dict[str, list[str]],
    mounts: dict[tuple[str, str], list[str]],
    nested_edges: list[tuple[tuple[str, str], tuple[str, str], str]],
    api_router_prefixes: dict[tuple[str, str], str],
) -> None:
    imp_syms, imp_mods = _resolve_module_imports(rel, tree, by_stem)
    mod_consts = _collect_scalar_consts(tree.body)

    def _add_mount(pair: tuple[str, str], pref: str) -> None:
        bucket = mounts.setdefault(pair, [])
        if pref not in bucket:
            bucket.append(pref)

    def _record_router_prefixes(
        stmts: list[ast.stmt], env: dict[str, str], c_env: dict[str, str | int]
    ) -> None:
        for s in stmts:
            lhs: str | None = None
            rhs: ast.AST | None = None
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                lhs, rhs = s.targets[0].id, s.value
            elif isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                lhs, rhs = s.target.id, s.value
            if lhs and isinstance(rhs, ast.Call) and _call_name(rhs) == "APIRouter":
                r_pref = ""
                for kw in rhs.keywords:
                    if kw.arg == "prefix":
                        ev = _eval_route_str_expr(kw.value, env, c_env)
                        if ev:
                            r_pref = ev.replace("__dyn__", "{param}")
                api_router_prefixes[(rel, lhs)] = r_pref

    def _scan_mount_stmts(
        stmts: list[ast.stmt], outer_env: dict[str, str], outer_consts: dict[str, str | int]
    ) -> None:
        sc_env = _collect_str_bindings(stmts, outer_env)
        sc_consts = {**outer_consts, **_collect_scalar_consts(stmts)}
        _record_router_prefixes(stmts, sc_env, sc_consts)
        nested_defs: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []

        def _walk_non_defs(node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                nested_defs.append(node)
                return
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "include_router"
            ):
                r_arg = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg == "router"), None
                )
                target_pair: tuple[str, str] | None = None
                if isinstance(r_arg, ast.Name) and r_arg.id in imp_syms:
                    target_pair = imp_syms[r_arg.id]
                elif (
                    isinstance(r_arg, ast.Attribute)
                    and isinstance(r_arg.value, ast.Name)
                    and r_arg.value.id in imp_mods
                ):
                    target_pair = (imp_mods[r_arg.value.id], r_arg.attr)
                elif (
                    isinstance(r_arg, ast.Attribute)
                    and isinstance(r_arg.value, ast.Name)
                    and r_arg.value.id in imp_syms
                ):
                    target_pair = (imp_syms[r_arg.value.id][0], r_arg.attr)
                elif isinstance(r_arg, ast.Name):
                    target_pair = (rel, r_arg.id)
                if target_pair is not None:
                    pref = ""
                    for kw in node.keywords:
                        if kw.arg == "prefix":
                            ev = _eval_route_str_expr(kw.value, sc_env, sc_consts)
                            if ev:
                                pref = ev.replace("__dyn__", "{param}")
                    recv_name = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                    recv_pair = (rel, recv_name)
                    if recv_name and recv_pair in api_router_prefixes:
                        nested_edges.append((recv_pair, target_pair, pref))
                    else:
                        _add_mount(target_pair, pref)
            for child in ast.iter_child_nodes(node):
                _walk_non_defs(child)

        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                nested_defs.append(stmt)
                continue
            if isinstance(stmt, (ast.If, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While, ast.Try)):
                for attr_name in ("body", "orelse", "finalbody"):
                    sub_body = getattr(stmt, attr_name, None)
                    if isinstance(sub_body, list):
                        _scan_mount_stmts(sub_body, sc_env, sc_consts)
                for h in getattr(stmt, "handlers", []):
                    if isinstance(h, ast.ExceptHandler):
                        _scan_mount_stmts(h.body, sc_env, sc_consts)
            else:
                _walk_non_defs(stmt)

        for nd in nested_defs:
            if isinstance(nd, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_outer = _fn_arg_str_defaults(nd, sc_env, sc_consts)
                _scan_mount_stmts(nd.body, fn_outer, sc_consts)
            else:
                _scan_mount_stmts(nd.body, sc_env, sc_consts)

    _scan_mount_stmts(tree.body, {}, mod_consts)


def _collect_cross_module_router_mounts(trees: dict[str, ast.Module]) -> dict[tuple[str, str], list[str]]:
    """Return `{(target_rel, router_var): [mount_prefix]}` from `app.include_router(...)` calls."""
    by_stem = _build_module_stem_index(trees)
    mounts: dict[tuple[str, str], list[str]] = {}
    nested_edges: list[tuple[tuple[str, str], tuple[str, str], str]] = []
    api_router_prefixes: dict[tuple[str, str], str] = {}

    for rel, tree in sorted(trees.items()):
        _scan_module_mounts(rel, tree, by_stem, mounts, nested_edges, api_router_prefixes)

    for _ in range(8):
        changed = False
        for parent_pair, child_pair, via_pref in nested_edges:
            parent_own = api_router_prefixes.get(parent_pair, "")
            for p_mount in list(mounts.get(parent_pair) or [""]):
                segs = [s.strip("/") for s in (p_mount, parent_own, via_pref) if s and s.strip("/")]
                full = "/" + "/".join(segs) if segs else ""
                bucket = mounts.setdefault(child_pair, [])
                if full not in bucket:
                    bucket.append(full)
                    changed = True
        if not changed:
            break
    return mounts


def _extract_fastapi_starlette_endpoints(
    rel: str,
    tree: ast.Module,
    mod_str_env: dict[str, str],
    router_mounts: dict[tuple[str, str], list[str]],
) -> list[_ExtractedEndpoint]:
    """Extract FastAPI/Starlette `@app.<verb>`, `APIRouter`, `add_api_route`, `create_app()`, and `Route(...)`."""
    has_web_import = any(
        (
            isinstance(n, ast.Import)
            and any(a.name.split(".", 1)[0] in {"fastapi", "starlette"} for a in n.names)
        )
        or (
            isinstance(n, ast.ImportFrom)
            and n.module
            and n.module.split(".", 1)[0] in {"fastapi", "starlette"}
        )
        for n in ast.walk(tree)
    )

    def _join_route(p1: str, p2: str, p3: str) -> str:
        segs = [s.strip("/") for s in (p1, p2, p3) if s and s.strip("/")]
        return _norm_http_path("/" + "/".join(segs))

    def _extract_methods_kw(call_node: ast.Call) -> list[str]:
        for kw in call_node.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                cand = [
                    el.value.upper()
                    for el in kw.value.elts
                    if isinstance(el, ast.Constant) and isinstance(el.value, str)
                ]
                if cand:
                    return cand
        return ["GET"]

    def _fn_html_and_calls(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef, env: dict[str, str]
    ) -> tuple[bool, str | None, set[str], set[str]]:
        sh, hr = _scan_html_markers(fn_node, env)
        if not sh:
            for call_n in ast.walk(fn_node):
                if isinstance(call_n, ast.Call) and _call_name(call_n) == "HTMLResponse":
                    sh = True
                    break
        return (
            sh,
            hr,
            _called_func_names(fn_node) | {fn_node.name},
            _called_qualified_names(fn_node) | {fn_node.name},
        )

    endpoints: list[_ExtractedEndpoint] = []
    seen_ep: set[tuple[str, str, str]] = set()
    mod_consts = _collect_scalar_consts(tree.body)

    def _scan_scope(
        stmts: list[ast.stmt],
        sc_env: dict[str, str],
        sc_consts: dict[str, str | int],
        local_recvs: dict[str, str],
        local_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    ) -> None:
        recvs = dict(local_recvs)
        fn_defs = dict(local_fns)
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_defs[s.name] = s
                continue
            lhs_id: str | None = None
            rhs_val: ast.AST | None = None
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                lhs_id, rhs_val = s.targets[0].id, s.value
            elif isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                lhs_id, rhs_val = s.target.id, s.value
            if lhs_id and isinstance(rhs_val, ast.Call) and _call_name(rhs_val) in {
                "FastAPI",
                "APIRouter",
                "Starlette",
            }:
                has_pref = ""
                for kw in rhs_val.keywords:
                    if kw.arg == "prefix":
                        ev = _eval_route_str_expr(kw.value, sc_env, sc_consts)
                        if ev:
                            has_pref = ev.replace("__dyn__", "{param}")
                recvs[lhs_id] = has_pref
        if not has_web_import and not recvs:
            return

        def _record_ep(
            r_var: str,
            verbs: list[str],
            p_expr: ast.AST | None,
            ep_sym: str,
            lineno: int,
            called_syms: set[str],
            sh: bool,
            hr: str | None,
            called_qualified: set[str] | None = None,
        ) -> None:
            raw_p = _eval_route_str_expr(p_expr, sc_env, sc_consts) if p_expr is not None else "/"
            if raw_p is None:
                return
            sub_p = raw_p.replace("__dyn__", "{param}")
            r_pref = recvs.get(r_var, "") if r_var else ""
            mount_prefs = (router_mounts.get((rel, r_var)) or [""]) if r_var else [""]
            for mp in mount_prefs:
                full_p = _join_route(mp, r_pref, sub_p)
                for vb in verbs:
                    if (vb, full_p, ep_sym) not in seen_ep:
                        seen_ep.add((vb, full_p, ep_sym))
                        endpoints.append(
                            _ExtractedEndpoint(
                                method=vb,
                                full_path=full_p,
                                is_prefix=False,
                                lineno=lineno,
                                handler_symbol=ep_sym,
                                called_symbols=set(called_syms),
                                called_qualified=set(called_qualified) if called_qualified is not None else set(),
                                serves_html=sh,
                                html_ref=hr,
                            )
                        )

        def _scan_non_def_calls(node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return
            if isinstance(node, ast.Call):
                cfn = _call_name(node)
                if cfn == "Route" and len(node.args) >= 2 and has_web_import:
                    ep_arg = node.args[1]
                    ep_sym = (
                        ep_arg.id
                        if isinstance(ep_arg, ast.Name)
                        else ep_arg.attr
                        if isinstance(ep_arg, ast.Attribute)
                        else "endpoint"
                    )
                    ep_fn = fn_defs.get(ep_sym) if isinstance(ep_arg, ast.Name) else None
                    if ep_fn is not None:
                        sh, hr, c_syms, c_qual = _fn_html_and_calls(ep_fn, sc_env)
                    else:
                        sh, hr, c_syms, c_qual = False, None, {ep_sym}, {ep_sym}
                    _record_ep(
                        "",
                        _extract_methods_kw(node),
                        node.args[0],
                        ep_sym,
                        getattr(node, "lineno", 1),
                        c_syms,
                        sh,
                        hr,
                        c_qual,
                    )
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"add_api_route", "add_route", "add_websocket_route"}
                ):
                    recv_expr = node.func.value
                    r_var = (
                        recv_expr.id
                        if isinstance(recv_expr, ast.Name)
                        else recv_expr.attr
                        if isinstance(recv_expr, ast.Attribute)
                        else ""
                    )
                    if r_var and r_var in recvs:
                        p_expr = node.args[0] if node.args else next(
                            (kw.value for kw in node.keywords if kw.arg == "path"), None
                        )
                        ep_arg = node.args[1] if len(node.args) >= 2 else next(
                            (kw.value for kw in node.keywords if kw.arg == "endpoint"), None
                        )
                        if p_expr is not None:
                            ep_sym = (
                                ep_arg.id
                                if isinstance(ep_arg, ast.Name)
                                else ep_arg.attr
                                if isinstance(ep_arg, ast.Attribute)
                                else "endpoint"
                            )
                            ep_fn = fn_defs.get(ep_sym) if isinstance(ep_arg, ast.Name) else None
                            if ep_fn is not None:
                                sh, hr, c_syms, c_qual = _fn_html_and_calls(ep_fn, sc_env)
                            else:
                                sh, hr, c_syms, c_qual = False, None, {ep_sym}, {ep_sym}
                            verbs = (
                                ["GET"]
                                if node.func.attr == "add_websocket_route"
                                else _extract_methods_kw(node)
                            )
                            _record_ep(
                                r_var,
                                verbs,
                                p_expr,
                                ep_sym,
                                getattr(node, "lineno", 1),
                                c_syms,
                                sh,
                                hr,
                                c_qual,
                            )
            for child in ast.iter_child_nodes(node):
                _scan_non_def_calls(child)

        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner_env = _collect_str_bindings(s.body, _fn_arg_str_defaults(s, sc_env, sc_consts))
                inner_consts = {**sc_consts, **_collect_scalar_consts(s.body)}
                _scan_scope(s.body, inner_env, inner_consts, recvs, fn_defs)
                for dec in s.decorator_list:
                    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                        continue
                    if not isinstance(dec.func.value, ast.Name):
                        continue
                    r_var = dec.func.value.id
                    if r_var not in recvs:
                        continue
                    attr = dec.func.attr
                    verbs = (
                        [_FASTAPI_DECORATOR_VERBS[attr]]
                        if attr in _FASTAPI_DECORATOR_VERBS
                        else _extract_methods_kw(dec)
                        if attr in {"api_route", "route"}
                        else []
                    )
                    if not verbs:
                        continue
                    p_expr = dec.args[0] if dec.args else next(
                        (kw.value for kw in dec.keywords if kw.arg == "path"), None
                    )
                    sh, hr, called, called_qual = _fn_html_and_calls(s, inner_env)
                    _record_ep(r_var, verbs, p_expr, s.name, s.lineno, called, sh, hr, called_qual)
            elif isinstance(s, ast.ClassDef):
                _scan_scope(s.body, sc_env, sc_consts, recvs, fn_defs)
            elif isinstance(s, (ast.If, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While, ast.Try)):
                for attr_name in ("body", "orelse", "finalbody"):
                    sub_body = getattr(s, attr_name, None)
                    if isinstance(sub_body, list):
                        _scan_scope(sub_body, sc_env, sc_consts, recvs, fn_defs)
                for h in getattr(s, "handlers", []):
                    if isinstance(h, ast.ExceptHandler):
                        _scan_scope(h.body, sc_env, sc_consts, recvs, fn_defs)
            elif has_web_import or recvs:
                _scan_non_def_calls(s)

    _scan_scope(tree.body, mod_str_env, mod_consts, {}, {})
    return endpoints


def _extract_mcp_endpoints(tree: ast.Module) -> list[_ExtractedEndpoint]:
    """Extract `@mcp.tool` / `@server.tool` and `@server.list_tools` + `@server.call_tool` endpoints."""
    mcp_receivers = {"mcp", "server", "mcp_server", "fastmcp"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
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
    call_tool_qual_branches: dict[str, set[str]] = {}
    call_tool_fn_name: str | None = None
    call_tool_all_syms: set[str] = set()
    call_tool_all_qual: set[str] = set()

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
                and dec_t.value.id in mcp_receivers
            ):
                call_tool_fn_name = stmt.name
                call_tool_all_syms = _called_func_names(stmt) | {stmt.name}
                call_tool_all_qual = _called_qualified_names(stmt) | {stmt.name}
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
                                    call_tool_qual_branches.setdefault(t_str, set()).update(
                                        _called_qualified_names(b_mod) | {stmt.name}
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
            if recv not in mcp_receivers:
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
                            called_qualified=_called_qualified_names(stmt) | {stmt.name},
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
                    q_syms = call_tool_qual_branches.get(tname) or call_tool_all_qual or ({stmt.name} | _called_qualified_names(stmt))
                    h_sym = call_tool_fn_name or stmt.name
                    endpoints.append(
                        _ExtractedEndpoint(
                            method="POST",
                            full_path=f"/mcp/tools/{tname.strip('/')}",
                            is_prefix=False,
                            lineno=tline,
                            handler_symbol=h_sym,
                            called_symbols=set(syms) | {stmt.name},
                            called_qualified=set(q_syms) | {stmt.name},
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
                            called_qualified=call_tool_all_qual | _called_qualified_names(stmt) | {stmt.name},
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
    *,
    route_qualified_calls_out: dict[tuple[str, str, str], set[str]] | None = None,
) -> dict[str, dict[str, list[str]]]:
    """Extract stdlib HTTP/MCP routes (`m:route:*`) and static `subprocess` edges."""
    try:
        if repo_root.is_symlink():
            return {}
    except OSError:
        return {}
    non_demo_py_count = sum(
        1
        for p in py_paths
        if not p.startswith("apps/")
        and not any(part.lower() in _DEMO_PATH_SEGMENTS for part in PurePosixPath(p).parts[:-1])
    )
    has_daemon_html = any(
        _scan_html_markers(t, _collect_str_bindings(t.body, {}))[0]
        or any(isinstance(n, ast.Call) and _call_name(n) == "HTMLResponse" for n in ast.walk(t))
        for t in trees.values()
    )
    has_ext_display = _has_external_display_sources(
        repo_root, py_count=non_demo_py_count, has_daemon_html=has_daemon_html
    )
    route_keys_by_rel: dict[str, dict[str, list[str]]] = {}
    emitted_html_pages: set[str] = set()

    repo_server_classes, repo_handler_classes = _discover_repo_server_and_handler_classes(trees)
    router_mounts = _collect_cross_module_router_mounts(trees)

    # Cross-module HTTPServer binding lookup (direct instantiation + 1-hop factory functions)
    by_stem = _build_module_stem_index(trees)
    global_bindings: dict[str, list[tuple[str, str, str]]] = {}
    for rel, tree in sorted(trees.items()):
        consts = _collect_scalar_consts(tree.body)
        imp_syms, _ = _resolve_module_imports(rel, tree, by_stem)
        for h_cls, items in _extract_http_server_bindings(
            tree, consts, repo_server_classes, repo_handler_classes
        ).items():
            canon_h = imp_syms[h_cls][1] if h_cls in imp_syms else h_cls
            for addr_lbl, sc_name in items:
                bucket = global_bindings.setdefault(canon_h, [])
                if (rel, addr_lbl, sc_name) not in bucket:
                    bucket.append((rel, addr_lbl, sc_name))
    for h_cls, items in _discover_server_factory_bindings(
        trees, repo_server_classes, repo_handler_classes
    ).items():
        bucket = global_bindings.setdefault(h_cls, [])
        for item in items:
            if item not in bucket:
                bucket.append(item)

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
                            try:
                                safe_html = safe_resolve_contained_path(Path(ep.html_ref), repo_root)
                                if safe_html is not None:
                                    html_st = safe_html.lstat()
                                    if not stat.S_ISLNK(html_st.st_mode) and stat.S_ISREG(html_st.st_mode):
                                        safe_html_src = safe_html.relative_to(repo_root.resolve()).as_posix()
                            except (OSError, ValueError):
                                pass
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
            if route_qualified_calls_out is not None:
                route_qualified_calls_out.setdefault(
                    (route_nid, ep.method, ep.full_path), set()
                ).update(set(ep.called_qualified) | {ep.handler_symbol})

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
        seen_bind_edges: set[str] = set()
        for bind_rel, bind_lbl, bind_sc in binding_notes:
            bind_eid = f"e:httpserver:{bind_rel}:{bind_sc}->{route_nid}"
            if bind_eid in seen_bind_edges:
                continue
            seen_bind_edges.add(bind_eid)
            launcher_nid = script_id(bind_rel)
            result.edges.append(
                AtlasEdge(
                    id=bind_eid,
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
