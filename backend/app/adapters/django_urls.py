"""Django URLConf package/list resolution, include prefix propagation, and CBV inspection."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

_PARAM_BRACED_RE = re.compile(r"(\{[^/{}]+\})")
_DJANGO_PARAM_RE = re.compile(r"<(?:[a-zA-Z_]\w*:)?(?P<p>[a-zA-Z_]\w*)>")
_DJANGO_REGEX_NAMED_RE = re.compile(r"\(\?P<(?P<p>[a-zA-Z_]\w*)>[^)]+\)")

HTTP_VERBS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")
_HTTP_VERB_SET = frozenset(HTTP_VERBS)
_DRF_GENERIC_METHODS: dict[str, tuple[str, ...]] = {
    "ListAPIView": ("GET",),
    "RetrieveAPIView": ("GET",),
    "CreateAPIView": ("POST",),
    "UpdateAPIView": ("PUT", "PATCH"),
    "DestroyAPIView": ("DELETE",),
    "ListCreateAPIView": ("GET", "POST"),
    "RetrieveUpdateAPIView": ("GET", "PUT", "PATCH"),
    "RetrieveDestroyAPIView": ("GET", "DELETE"),
    "RetrieveUpdateDestroyAPIView": ("GET", "PUT", "PATCH", "DELETE"),
    "TemplateView": ("GET",),
    "RedirectView": ("GET",),
}
_OPTIONAL_GUARD_ATTRS = frozenset({"DEBUG", "ENABLE_DRF_SPECTACULAR", "TESTING"})


def norm_django_path(*parts: str) -> str:
    cleaned_parts: list[str] = []
    for p in parts:
        s = re.sub(r"^\^|(?:/\?)?\$$", "", p.strip()).strip("/")
        if s:
            cleaned_parts.append(s)
    joined = "/" + "/".join(cleaned_parts) if cleaned_parts else "/"
    converted = _DJANGO_REGEX_NAMED_RE.sub(r"{\g<p>}", joined)
    return _DJANGO_PARAM_RE.sub(r"{\g<p>}", converted) or "/"


def django_route_regex(full_path: str) -> str:
    norm = full_path.rstrip("/") or "/"
    if norm == "/":
        return r"^(?:/api/v\d+)?/?$"
    pieces: list[str] = []
    for chunk in _PARAM_BRACED_RE.split(norm):
        if _PARAM_BRACED_RE.fullmatch(chunk):
            pieces.append(r"[^/?#]+")
        else:
            pieces.append(re.escape(chunk))
    return rf"^(?:/api/v\d+)?{''.join(pieces)}/?$"


def _dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def extract_module_imports(tree: ast.AST, mod_name: str, is_init: bool) -> dict[str, tuple[str, str | None]]:
    """Map local names (and root package names) -> `(target_module, attr_name_or_None)`."""
    pkg = mod_name if is_init else mod_name.rpartition(".")[0]
    imports: dict[str, tuple[str, str | None]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            base = pkg if node.level else (node.module or "")
            if node.level > 1:
                for _ in range(node.level - 1):
                    base = base.rpartition(".")[0]
            src_mod = ".".join(p for p in (base, node.module) if p) if node.level else (node.module or "")
            if not src_mod:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                if node.module is None and node.level >= 1:
                    imports[local] = (f"{src_mod}.{alias.name}", None)
                else:
                    imports[local] = (src_mod, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = (alias.name, None)
                else:
                    root = alias.name.split(".", 1)[0]
                    imports.setdefault(root, (root, None))
                    imports[alias.name] = (alias.name, None)
    return imports


def extract_pkg_reexports(tree: ast.AST, pkg_mod: str) -> dict[tuple[str, str], tuple[str, str | None]]:
    """Extract top-level re-exports in a package `__init__.py`."""
    reexports: dict[tuple[str, str], tuple[str, str | None]] = {}
    for local, target in extract_module_imports(tree, pkg_mod, is_init=True).items():
        reexports[(pkg_mod, local)] = target
    return reexports


@dataclass(frozen=True)
class ViewModuleMeta:
    imports: dict[str, tuple[str, str | None]]
    class_bases: dict[str, list[str]]
    class_methods: dict[str, frozenset[str]]
    class_allowed_methods: dict[str, frozenset[str] | None]
    fn_methods: dict[str, frozenset[str]]


def _literal_http_methods(expr: ast.AST | None) -> frozenset[str]:
    if not isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return frozenset()
    out: set[str] = set()
    for elt in expr.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            upper = elt.value.upper()
            if upper in _HTTP_VERB_SET:
                out.add(upper)
    return frozenset(out)


def extract_view_module_meta(tree: ast.AST, mod_name: str, is_init: bool = False) -> ViewModuleMeta:
    """Collect class bases/HTTP methods and decorated view HTTP verbs for one module."""
    imports = extract_module_imports(tree, mod_name, is_init=is_init)
    class_bases: dict[str, list[str]] = {}
    class_methods: dict[str, frozenset[str]] = {}
    class_allowed: dict[str, frozenset[str] | None] = {}
    fn_methods: dict[str, frozenset[str]] = {}

    for stmt in getattr(tree, "body", ()):
        if isinstance(stmt, ast.ClassDef):
            bases: list[str] = []
            for base in stmt.bases:
                b_node = base.value if isinstance(base, ast.Subscript) else base
                bdotted = _dotted(b_node)
                if bdotted:
                    bases.append(bdotted)
            class_bases[stmt.name] = bases
            methods: set[str] = set()
            allowed: frozenset[str] | None = None
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    up = member.name.upper()
                    if up in _HTTP_VERB_SET:
                        methods.add(up)
                elif isinstance(member, ast.Assign):
                    for tgt in member.targets:
                        if isinstance(tgt, ast.Name) and tgt.id == "http_method_names":
                            parsed = _literal_http_methods(member.value)
                            if parsed:
                                allowed = parsed
            class_methods[stmt.name] = frozenset(methods)
            class_allowed[stmt.name] = allowed
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            dec_verbs: set[str] = set()
            for dec in stmt.decorator_list:
                d_name = _dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
                short = d_name.rsplit(".", 1)[-1]
                if short == "require_GET":
                    dec_verbs.add("GET")
                elif short == "require_POST":
                    dec_verbs.add("POST")
                elif short == "require_safe":
                    dec_verbs.add("GET")
                elif short in ("api_view", "require_http_methods") and isinstance(dec, ast.Call) and dec.args:
                    dec_verbs.update(_literal_http_methods(dec.args[0]))
            if dec_verbs:
                fn_methods[stmt.name] = frozenset(dec_verbs)
    return ViewModuleMeta(
        imports=imports,
        class_bases=class_bases,
        class_methods=class_methods,
        class_allowed_methods=class_allowed,
        fn_methods=fn_methods,
    )


def resolve_dotted_symbol(
    origin_mod: str,
    dotted: str,
    imports_by_mod: dict[str, dict[str, tuple[str, str | None]]],
    known_modules: set[str],
    pkg_reexports: dict[tuple[str, str], tuple[str, str | None]],
) -> tuple[str | None, str | None, bool]:
    """Resolve `dotted` in `origin_mod` -> `(target_mod, symbol_or_None, is_explicit_external)`.

    `is_explicit_external` is True when an import explicitly points outside `known_modules`.
    """
    head, _, tail = dotted.partition(".")
    imp_map = imports_by_mod.get(origin_mod, {})
    cur_mod: str | None = None
    cur_attr: str | None = None
    if dotted in imp_map:
        tgt_mod, tgt_attr = imp_map[dotted]
        cur_mod, cur_attr = tgt_mod, tgt_attr
    elif head in imp_map:
        tgt_mod, tgt_attr = imp_map[head]
        if tgt_attr is None:
            combined = f"{tgt_mod}.{tail}" if tail else tgt_mod
            if combined in known_modules:
                return combined, None, False
            if tail:
                parts = combined.split(".")
                for split in range(len(parts) - 1, 0, -1):
                    cand_mod = ".".join(parts[:split])
                    if cand_mod in known_modules:
                        return cand_mod, ".".join(parts[split:]), False
                return tgt_mod, tail, tgt_mod not in known_modules
            return tgt_mod, None, tgt_mod not in known_modules
        submod = f"{tgt_mod}.{tgt_attr}"
        if submod in known_modules and tail:
            cur_mod, cur_attr = submod, tail
        elif submod in known_modules and not tail:
            return submod, None, False
        else:
            cur_mod = tgt_mod
            cur_attr = f"{tgt_attr}.{tail}" if tail else tgt_attr
    else:
        return origin_mod, dotted, False

    seen: set[tuple[str, str | None]] = set()
    while cur_mod is not None and cur_attr is not None and (cur_mod, cur_attr) in pkg_reexports:
        if (cur_mod, cur_attr) in seen:
            break
        seen.add((cur_mod, cur_attr))
        next_mod, next_attr = pkg_reexports[(cur_mod, cur_attr)]
        cur_mod, cur_attr = next_mod, next_attr

    is_external = cur_mod is not None and cur_mod not in known_modules
    return cur_mod, cur_attr, is_external


@dataclass(frozen=True)
class StaticCallItem:
    origin_mod: str
    call: ast.Call
    in_optional_guard: bool = False


@dataclass(frozen=True)
class RefPatternItem:
    origin_mod: str
    dotted: str
    lineno: int


@dataclass(frozen=True)
class RouterUrlsItem:
    origin_mod: str
    router_name: str


@dataclass(frozen=True)
class DynamicPatternItem:
    origin_mod: str
    lineno: int
    desc: str
    in_optional_guard: bool = False


PatternItem = StaticCallItem | RefPatternItem | RouterUrlsItem | DynamicPatternItem


@dataclass
class UrlModuleAst:
    mod_name: str
    rel_repo: str
    is_init: bool
    imports: dict[str, tuple[str, str | None]]
    vars: dict[str, list[PatternItem]] = field(default_factory=dict)
    routers: dict[str, list[tuple[str, ast.AST | None, int]]] = field(default_factory=dict)
    extra_notes: list[str] = field(default_factory=list)
    extra_dynamic: bool = False


def _is_optional_guard(test: ast.AST) -> bool:
    for node in ast.walk(test):
        if isinstance(node, ast.Attribute) and node.attr in _OPTIONAL_GUARD_ATTRS:
            return True
        if isinstance(node, ast.Name) and node.id in _OPTIONAL_GUARD_ATTRS:
            return True
    return False


def _is_route_call(node: ast.Call) -> bool:
    dotted = _dotted(node.func) or ""
    return dotted.rsplit(".", 1)[-1] in ("path", "re_path", "url")


def _eval_pattern_expr(
    expr: ast.AST,
    env: dict[str, list[PatternItem]],
    routers: dict[str, list[tuple[str, ast.AST | None, int]]],
    imports: dict[str, tuple[str, str | None]],
    mod_name: str,
    *,
    in_optional_guard: bool = False,
) -> list[PatternItem]:
    if isinstance(expr, (ast.List, ast.Tuple)):
        items: list[PatternItem] = []
        for elt in expr.elts:
            if isinstance(elt, ast.Starred):
                items.extend(
                    _eval_pattern_expr(
                        elt.value, env, routers, imports, mod_name, in_optional_guard=in_optional_guard
                    )
                )
            elif isinstance(elt, ast.Call) and _is_route_call(elt):
                items.append(StaticCallItem(origin_mod=mod_name, call=elt, in_optional_guard=in_optional_guard))
            else:
                items.append(
                    DynamicPatternItem(
                        origin_mod=mod_name,
                        lineno=getattr(elt, "lineno", 1),
                        desc=ast.unparse(elt)[:80],
                        in_optional_guard=in_optional_guard,
                    )
                )
        return items
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _eval_pattern_expr(expr.left, env, routers, imports, mod_name, in_optional_guard=in_optional_guard)
        right = _eval_pattern_expr(expr.right, env, routers, imports, mod_name, in_optional_guard=in_optional_guard)
        return [*left, *right]
    if isinstance(expr, ast.Name):
        if expr.id in env:
            return list(env[expr.id])
        if expr.id in imports:
            return [RefPatternItem(origin_mod=mod_name, dotted=expr.id, lineno=expr.lineno)]
    elif isinstance(expr, ast.Attribute):
        dotted = _dotted(expr)
        if dotted:
            rname, _, tail = dotted.partition(".")
            if tail == "urls" and rname in routers:
                return [RouterUrlsItem(origin_mod=mod_name, router_name=rname)]
            head = dotted.split(".", 1)[0]
            if head in imports or dotted in imports:
                return [RefPatternItem(origin_mod=mod_name, dotted=dotted, lineno=expr.lineno)]
    return [
        DynamicPatternItem(
            origin_mod=mod_name,
            lineno=getattr(expr, "lineno", 1),
            desc=ast.unparse(expr)[:80],
            in_optional_guard=in_optional_guard,
        )
    ]


def _looks_static_pattern_rhs(expr: ast.AST) -> bool:
    if isinstance(expr, (ast.List, ast.Tuple, ast.BinOp, ast.ListComp, ast.Call)):
        return True
    dotted = _dotted(expr)
    return bool(dotted and (dotted.endswith(("urls", "patterns")) or "urlpatterns" in dotted))


def _walk_url_stmts(
    stmts: list[ast.stmt],
    url_ast: UrlModuleAst,
    env: dict[str, list[PatternItem]],
    *,
    in_optional_guard: bool = False,
) -> None:
    for stmt in stmts:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            tname = stmt.targets[0].id
            rhs = stmt.value
            rhs_dotted = _dotted(rhs.func) if isinstance(rhs, ast.Call) else None
            if rhs_dotted and rhs_dotted.rsplit(".", 1)[-1].endswith("Router"):
                url_ast.routers.setdefault(tname, [])
                continue
            if tname == "urlpatterns" or _looks_static_pattern_rhs(rhs):
                env[tname] = _eval_pattern_expr(
                    rhs, env, url_ast.routers, url_ast.imports, url_ast.mod_name, in_optional_guard=in_optional_guard
                )
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            tname = stmt.target.id
            if tname == "urlpatterns" or _looks_static_pattern_rhs(stmt.value):
                env[tname] = _eval_pattern_expr(
                    stmt.value, env, url_ast.routers, url_ast.imports, url_ast.mod_name, in_optional_guard=in_optional_guard
                )
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add) and isinstance(stmt.target, ast.Name):
            tname = stmt.target.id
            if tname == "urlpatterns" or tname in env or _looks_static_pattern_rhs(stmt.value):
                existing = list(env.get(tname, []))
                existing.extend(
                    _eval_pattern_expr(
                        stmt.value, env, url_ast.routers, url_ast.imports, url_ast.mod_name, in_optional_guard=in_optional_guard
                    )
                )
                env[tname] = existing
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
            call = stmt.value
            attr = call.func.attr
            recv = _dotted(call.func.value)
            if not recv:
                continue
            if attr == "register" and len(call.args) >= 2 and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                url_ast.routers.setdefault(recv, []).append((call.args[0].value, call.args[1], call.lineno))
            elif attr == "extend" and call.args and (recv == "urlpatterns" or recv in env):
                existing = list(env.get(recv, []))
                existing.extend(
                    _eval_pattern_expr(
                        call.args[0], env, url_ast.routers, url_ast.imports, url_ast.mod_name, in_optional_guard=in_optional_guard
                    )
                )
                env[recv] = existing
            elif attr == "append" and call.args and (recv == "urlpatterns" or recv in env):
                existing = list(env.get(recv, []))
                existing.extend(
                    _eval_pattern_expr(
                        ast.List(elts=[call.args[0]], ctx=ast.Load()),
                        env,
                        url_ast.routers,
                        url_ast.imports,
                        url_ast.mod_name,
                        in_optional_guard=in_optional_guard,
                    )
                )
                env[recv] = existing
        elif isinstance(stmt, ast.If):
            opt = in_optional_guard or _is_optional_guard(stmt.test)
            _walk_url_stmts(stmt.body, url_ast, env, in_optional_guard=opt)
            if stmt.orelse:
                _walk_url_stmts(stmt.orelse, url_ast, env, in_optional_guard=opt)
        elif isinstance(stmt, (ast.Try, ast.TryStar)):
            has_imp_err = any(
                h.type is None or (_dotted(h.type) or "").endswith(("ImportError", "ModuleNotFoundError"))
                for h in stmt.handlers
            )
            opt = in_optional_guard or has_imp_err
            _walk_url_stmts(stmt.body, url_ast, env, in_optional_guard=opt)
            _walk_url_stmts(stmt.orelse, url_ast, env, in_optional_guard=opt)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)) and any(
            isinstance(sub, (ast.Name, ast.Attribute)) and (_dotted(sub) or "") == "urlpatterns"
            for sub in ast.walk(stmt)
        ):
            # Dynamically building urlpatterns in a top-level loop
            url_ast.extra_dynamic = True
            url_ast.extra_notes.append(
                f"Dynamic loop constructs Django URL patterns in `{url_ast.rel_repo}:{stmt.lineno}`; route coverage may be incomplete."
            )


def parse_url_module(py_file: Path, rel_repo: str, mod_name: str) -> UrlModuleAst | None:
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return None
    is_init = py_file.name == "__init__.py"
    url_ast = UrlModuleAst(
        mod_name=mod_name,
        rel_repo=rel_repo,
        is_init=is_init,
        imports=extract_module_imports(tree, mod_name, is_init=is_init),
    )
    env: dict[str, list[PatternItem]] = {}
    _walk_url_stmts(list(tree.body), url_ast, env)
    url_ast.vars = env
    return url_ast


_VIEW_WRAPPERS = frozenset(
    {
        "login_required",
        "csrf_exempt",
        "never_cache",
        "staff_member_required",
        "permission_required",
        "user_passes_test",
        "gzip_page",
    }
)


@dataclass(frozen=True)
class ResolvedUrlRoute:
    full_path: str
    origin_mod: str
    target_expr: ast.AST
    lineno: int


@dataclass(frozen=True)
class ResolvedDrfReg:
    collection_path: str
    item_path: str
    origin_mod: str
    viewset_expr: ast.AST
    lineno: int


@dataclass
class UrlExpansionResult:
    routes: list[ResolvedUrlRoute]
    drf_regs: list[ResolvedDrfReg]
    notes: list[str]
    coverage_complete: bool
    promoted_modules: set[str]


def _unwrap_view_expr(expr: ast.AST) -> ast.AST:
    cur = expr
    for _ in range(4):
        if isinstance(cur, ast.Call) and cur.args:
            fn_name = (_dotted(cur.func) or "").rsplit(".", 1)[-1]
            if fn_name in _VIEW_WRAPPERS:
                cur = cur.args[0]
                continue
            if isinstance(cur.func, ast.Call):
                outer_name = (_dotted(cur.func.func) or "").rsplit(".", 1)[-1]
                if outer_name in _VIEW_WRAPPERS or outer_name == "cache_page":
                    cur = cur.args[0]
                    continue
        break
    return cur


def _extract_call_str_arg(call: ast.Call, pos: int, kw_name: str) -> str | None:
    node: ast.AST | None = call.args[pos] if len(call.args) > pos else None
    if node is None:
        for kw in call.keywords:
            if kw.arg == kw_name:
                node = kw.value
                break
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_call_expr_arg(call: ast.Call, pos: int, kw_name: str) -> ast.AST | None:
    if len(call.args) > pos:
        return call.args[pos]
    for kw in call.keywords:
        if kw.arg == kw_name:
            return kw.value
    return None


def expand_url_modules(
    url_modules: dict[str, UrlModuleAst],
    mod_files: dict[str, tuple[Path, str]],
    pkg_reexports: dict[tuple[str, str], tuple[str, str | None]],
) -> UrlExpansionResult:
    """Resolve URLConf packages, starred lists, `+`/`.extend`, and multi-hop `include()` prefixes."""
    known_mods: set[str] = set(mod_files) | set(url_modules) | {m for m, _ in pkg_reexports}
    imports_by_mod: dict[str, dict[str, tuple[str, str | None]]] = {
        m: u.imports for m, u in url_modules.items()
    }
    promoted: set[str] = set()
    notes: list[str] = []
    seen_notes: set[str] = set()
    coverage_complete = True

    def add_note(msg: str, *, incomplete: bool = False) -> None:
        nonlocal coverage_complete
        if incomplete:
            coverage_complete = False
        if msg not in seen_notes:
            seen_notes.add(msg)
            notes.append(msg)

    for um in url_modules.values():
        if um.extra_dynamic:
            for msg in um.extra_notes:
                add_note(msg, incomplete=True)

    def ensure_url_mod(mod_name: str) -> bool:
        if mod_name in url_modules:
            return True
        if mod_name in mod_files:
            pf, rel_repo = mod_files[mod_name]
            parsed = parse_url_module(pf, rel_repo, mod_name)
            if parsed is not None:
                url_modules[mod_name] = parsed
                imports_by_mod[mod_name] = parsed.imports
                promoted.add(mod_name)
                if parsed.extra_dynamic:
                    for msg in parsed.extra_notes:
                        add_note(msg, incomplete=True)
                return True
        return False

    included_targets: set[tuple[str, str]] = set()
    starred_targets: set[tuple[str, str]] = set()
    mounted_routers: set[tuple[str, str]] = set()

    def expand_var(
        mod_name: str,
        var_name: str,
        visiting: frozenset[tuple[str, str]],
    ) -> list[tuple[str, str, ast.AST | None, int, str] | RouterUrlsItem | DynamicPatternItem]:
        """Expand `(mod_name, var_name)` -> flat sequence of calls/router-refs/dynamic items."""
        key = (mod_name, var_name)
        if key in visiting:
            rel = url_modules[mod_name].rel_repo if mod_name in url_modules else mod_name
            add_note(
                f"Cyclic Django URL pattern reference involving `{mod_name}.{var_name}` in `{rel}`.",
                incomplete=False,
            )
            return []
        if not ensure_url_mod(mod_name):
            return []
        um = url_modules[mod_name]
        items = um.vars.get(var_name, [])
        next_visiting = visiting | {key}
        out: list[tuple[str, str, ast.AST | None, int, str] | RouterUrlsItem | DynamicPatternItem] = []
        for it in items:
            if isinstance(it, StaticCallItem):
                raw_route = _extract_call_str_arg(it.call, 0, "route")
                tgt = _extract_call_expr_arg(it.call, 1, "view")
                if raw_route is None or tgt is None:
                    add_note(
                        f"Dynamic or non-literal Django route argument in `{um.rel_repo}:{it.call.lineno}`; route coverage may be incomplete.",
                        incomplete=not it.in_optional_guard,
                    )
                    continue
                out.append((it.origin_mod, raw_route, tgt, it.call.lineno, um.rel_repo))
            elif isinstance(it, RouterUrlsItem):
                mounted_routers.add((it.origin_mod, it.router_name))
                out.append(it)
            elif isinstance(it, DynamicPatternItem):
                rel_i = url_modules[it.origin_mod].rel_repo if it.origin_mod in url_modules else it.origin_mod
                add_note(
                    f"Unresolved dynamic Django URL pattern `{it.desc}` in `{rel_i}:{it.lineno}`; route coverage may be incomplete.",
                    incomplete=not it.in_optional_guard,
                )
            elif isinstance(it, RefPatternItem):
                t_mod, t_attr, is_ext = resolve_dotted_symbol(
                    it.origin_mod, it.dotted, imports_by_mod, known_mods, pkg_reexports
                )
                if t_mod and not is_ext and ensure_url_mod(t_mod):
                    target_var = t_attr or "urlpatterns"
                    starred_targets.add((t_mod, target_var))
                    out.extend(expand_var(t_mod, target_var, next_visiting))
                else:
                    rel_i = url_modules[it.origin_mod].rel_repo if it.origin_mod in url_modules else it.origin_mod
                    add_note(
                        f"Unresolved Django pattern reference `{it.dotted}` in `{rel_i}:{it.lineno}`; route coverage may be incomplete.",
                        incomplete=True,
                    )
        return out

    # Pass A: expand every module's `urlpatterns` and any included pattern variables recursively
    expanded_by_var: dict[
        tuple[str, str],
        list[tuple[str, str, ast.AST | None, int, str] | RouterUrlsItem | DynamicPatternItem],
    ] = {}
    vars_queue: list[tuple[str, str]] = [
        (m, "urlpatterns") for m in list(url_modules.keys()) if "urlpatterns" in url_modules[m].vars
    ]
    v_idx = 0
    while v_idx < len(vars_queue):
        m, vname = vars_queue[v_idx]
        v_idx += 1
        if (m, vname) in expanded_by_var:
            continue
        exp = expand_var(m, vname, frozenset())
        expanded_by_var[(m, vname)] = exp
        for entry in exp:
            if not isinstance(entry, tuple):
                continue
            origin_mod, _raw, tgt, _ln, _rel = entry
            if not isinstance(tgt, ast.Call):
                continue
            tfn = (_dotted(tgt.func) or "").rsplit(".", 1)[-1]
            if tfn != "include":
                continue
            inc_arg = _extract_call_expr_arg(tgt, 0, "arg")
            t_ref = _resolve_include_target(
                inc_arg, origin_mod, url_modules, imports_by_mod, known_mods, pkg_reexports
            )
            if t_ref is not None and not t_ref[2]:
                inc_mod, inc_var, _ = t_ref
                included_targets.add((inc_mod, inc_var))
                if ensure_url_mod(inc_mod):
                    if (inc_mod, inc_var) not in expanded_by_var:
                        vars_queue.append((inc_mod, inc_var))
                    if inc_var != "urlpatterns" and "urlpatterns" in url_modules[inc_mod].vars and (inc_mod, "urlpatterns") not in expanded_by_var:
                        vars_queue.append((inc_mod, "urlpatterns"))

    # Identify roots (top-level URL modules not included or starred by another URL module)
    roots: list[str] = [
        m
        for m in sorted(url_modules)
        if ("urlpatterns" in url_modules[m].vars or url_modules[m].routers)
        and (m, "urlpatterns") not in included_targets
        and (m, "urlpatterns") not in starred_targets
    ]
    if not roots and url_modules:
        roots = [min(url_modules)]

    # Pass B: multi-hop BFS prefix propagation
    resolved_routes: list[ResolvedUrlRoute] = []
    resolved_regs: list[ResolvedDrfReg] = []
    visited_mounts: set[tuple[str, str, str]] = set()
    bfs: list[tuple[str, str, str, frozenset[tuple[str, str]]]] = [
        (r, "urlpatterns", "", frozenset()) for r in roots
    ]
    b_idx = 0
    while b_idx < len(bfs):
        cur_mod, cur_var, pref, active_chain = bfs[b_idx]
        b_idx += 1
        mount_key = (cur_mod, cur_var, pref)
        if mount_key in visited_mounts or cur_mod not in url_modules:
            continue
        if (cur_mod, cur_var) in active_chain:
            add_note(
                f"Cyclic Django `include()` chain involving `{cur_mod}.{cur_var}`.",
                incomplete=False,
            )
            continue
        visited_mounts.add(mount_key)
        next_chain = active_chain | {(cur_mod, cur_var)}
        um = url_modules[cur_mod]
        entries = expanded_by_var.get((cur_mod, cur_var))
        if entries is None:
            entries = expand_var(cur_mod, cur_var, frozenset())
            expanded_by_var[(cur_mod, cur_var)] = entries

        seen_submods: set[str] = {cur_mod}
        for entry in entries:
            if isinstance(entry, RouterUrlsItem):
                for reg_pref, vs_expr, rline in url_modules[entry.origin_mod].routers.get(entry.router_name, ()):
                    coll_p = norm_django_path(pref, reg_pref)
                    resolved_regs.append(
                        ResolvedDrfReg(coll_p, norm_django_path(coll_p, "{id}"), entry.origin_mod, vs_expr, rline)
                    )
                continue
            if isinstance(entry, DynamicPatternItem):
                continue
            origin_mod, raw_route, tgt, lineno, rel = entry
            seen_submods.add(origin_mod)
            if isinstance(tgt, ast.Call) and ((_dotted(tgt.func) or "").rsplit(".", 1)[-1] == "include"):
                inc_arg = _extract_call_expr_arg(tgt, 0, "arg")
                child_pref = norm_django_path(pref, raw_route)
                inline_seq: ast.List | ast.Tuple | None = None
                if (
                    isinstance(inc_arg, ast.Tuple)
                    and len(inc_arg.elts) >= 2
                    and isinstance(inc_arg.elts[0], (ast.List, ast.Tuple))
                    and isinstance(inc_arg.elts[1], ast.Constant)
                    and isinstance(inc_arg.elts[1].value, str)
                ):
                    inline_seq = inc_arg.elts[0]
                elif isinstance(inc_arg, (ast.List, ast.Tuple)) and not (
                    len(inc_arg.elts) >= 1 and isinstance(inc_arg.elts[0], ast.Constant) and isinstance(inc_arg.elts[0].value, str)
                ):
                    inline_seq = inc_arg
                if inline_seq is not None and origin_mod in url_modules:
                    origin_um = url_modules[origin_mod]
                    inline_items = _eval_pattern_expr(
                        inline_seq, origin_um.vars, origin_um.routers, origin_um.imports, origin_mod
                    )
                    tmp_key = f"__inline_{lineno}"
                    origin_um.vars[tmp_key] = inline_items
                    bfs.append((origin_mod, tmp_key, child_pref, next_chain))
                    continue
                if isinstance(inc_arg, ast.Attribute) and inc_arg.attr == "urls":
                    rd = _dotted(inc_arg.value)
                    if rd and rd in url_modules[origin_mod].routers:
                        mounted_routers.add((origin_mod, rd))
                        for reg_pref, vs_expr, rline in url_modules[origin_mod].routers[rd]:
                            coll_p = norm_django_path(child_pref, reg_pref)
                            resolved_regs.append(
                                ResolvedDrfReg(coll_p, norm_django_path(coll_p, "{id}"), origin_mod, vs_expr, rline)
                            )
                        continue
                t_ref = _resolve_include_target(inc_arg, origin_mod, url_modules, imports_by_mod, known_mods, pkg_reexports)
                if t_ref is None:
                    add_note(
                        f"Unresolved dynamic `include()` target in `{rel}:{lineno}`; route coverage may be incomplete.",
                        incomplete=True,
                    )
                    continue
                tgt_mod, tgt_var, is_ext = t_ref
                if not is_ext and tgt_mod in url_modules:
                    bfs.append((tgt_mod, tgt_var, child_pref, next_chain))
                else:
                    # Optional third-party urlconfs (e.g. debug_toolbar.urls)
                    add_note(
                        f"External Django `include()` target `{tgt_mod}.{tgt_var}` in `{rel}:{lineno}` is outside repository coverage.",
                        incomplete=False,
                    )
                continue
            if tgt is not None:
                resolved_routes.append(
                    ResolvedUrlRoute(norm_django_path(pref, raw_route), origin_mod, tgt, lineno)
                )

        # Emit unmounted router.register(...) routes at the defining module's mount prefix
        if cur_var == "urlpatterns":
            for sm in sorted(seen_submods):
                for rname, regs in url_modules[sm].routers.items():
                    if (sm, rname) not in mounted_routers:
                        for reg_pref, vs_expr, rline in regs:
                            coll_p = norm_django_path(pref, reg_pref)
                            resolved_regs.append(
                                ResolvedDrfReg(coll_p, norm_django_path(coll_p, "{id}"), sm, vs_expr, rline)
                            )

    return UrlExpansionResult(
        routes=resolved_routes,
        drf_regs=resolved_regs,
        notes=notes,
        coverage_complete=coverage_complete,
        promoted_modules=promoted,
    )


def _resolve_include_target(
    inc_arg: ast.AST | None,
    origin_mod: str,
    url_modules: dict[str, UrlModuleAst],
    imports_by_mod: dict[str, dict[str, tuple[str, str | None]]],
    known_mods: set[str],
    pkg_reexports: dict[tuple[str, str], tuple[str, str | None]],
) -> tuple[str, str, bool] | None:
    if inc_arg is None:
        return None
    if isinstance(inc_arg, ast.Constant) and isinstance(inc_arg.value, str):
        tgt = inc_arg.value.strip()
        return tgt, "urlpatterns", tgt not in known_mods
    if (
        isinstance(inc_arg, ast.Tuple)
        and inc_arg.elts
        and isinstance(inc_arg.elts[0], ast.Constant)
        and isinstance(inc_arg.elts[0].value, str)
    ):
        tgt = inc_arg.elts[0].value.strip()
        return tgt, "urlpatterns", tgt not in known_mods
    dotted = _dotted(inc_arg)
    if dotted:
        t_mod, t_attr, is_ext = resolve_dotted_symbol(origin_mod, dotted, imports_by_mod, known_mods, pkg_reexports)
        if t_mod:
            if t_attr == "urls" and f"{t_mod}.urls" in known_mods:
                return f"{t_mod}.urls", "urlpatterns", False
            if t_attr == "urls":
                return t_mod, "urlpatterns", is_ext
            if t_mod in url_modules and t_attr and t_attr in url_modules[t_mod].vars:
                return t_mod, t_attr, False
            return t_mod, t_attr or "urlpatterns", is_ext
    return None


def _collect_cbv_methods(
    mod_name: str,
    cls_name: str,
    view_metas: dict[str, ViewModuleMeta],
    imports_by_mod: dict[str, dict[str, tuple[str, str | None]]],
    known_mods: set[str],
    pkg_reexports: dict[tuple[str, str], tuple[str, str | None]],
    seen: set[tuple[str, str]],
) -> tuple[set[str], list[str]]:
    if (mod_name, cls_name) in seen:
        return set(), []
    seen.add((mod_name, cls_name))
    meta = view_metas.get(mod_name)
    if meta is None:
        return set(), []
    methods = set(meta.class_methods.get(cls_name, ()))
    ext_bases: list[str] = []
    for base_dotted in meta.class_bases.get(cls_name, ()):
        b_mod, b_sym, is_ext = resolve_dotted_symbol(
            mod_name, base_dotted, imports_by_mod, known_mods, pkg_reexports
        )
        if b_mod and b_sym and not is_ext and b_mod in view_metas:
            sub_methods, sub_ext = _collect_cbv_methods(
                b_mod, b_sym, view_metas, imports_by_mod, known_mods, pkg_reexports, seen
            )
            methods |= sub_methods
            ext_bases.extend(sub_ext)
        else:
            ext_bases.append((b_sym or base_dotted).rsplit(".", 1)[-1])
    return methods, ext_bases


def resolve_view_target_and_methods(
    target_expr: ast.AST,
    origin_mod: str,
    url_imports: dict[str, dict[str, tuple[str, str | None]]],
    view_metas: dict[str, ViewModuleMeta],
    pkg_reexports: dict[tuple[str, str], tuple[str, str | None]],
    symbol_to_mod: dict[str, str],
) -> tuple[str | None, str, tuple[str, ...]]:
    """Return `(view_mod_or_None, view_symbol_label, http_methods_tuple)`."""
    unwrapped = _unwrap_view_expr(target_expr)
    all_imports = {**{m: meta.imports for m, meta in view_metas.items()}, **url_imports}
    known_mods = set(view_metas) | set(url_imports) | {m for m, _ in pkg_reexports}

    if (
        isinstance(unwrapped, ast.Call)
        and isinstance(unwrapped.func, ast.Attribute)
        and unwrapped.func.attr == "as_view"
    ):
        view_dotted = _dotted(unwrapped.func.value) or ""
        short_sym = view_dotted.rsplit(".", 1)[-1]
        v_mod, v_sym, is_ext = (
            resolve_dotted_symbol(origin_mod, view_dotted, all_imports, known_mods, pkg_reexports)
            if view_dotted
            else (None, None, False)
        )
        if not v_mod or (v_mod not in view_metas and not is_ext):
            v_mod = symbol_to_mod.get(short_sym)
            v_sym = short_sym
        cls_name = (v_sym or short_sym).rsplit(".", 1)[-1]

        # Explicit ViewSet actions mapping: `ViewSet.as_view({"get": "list", "post": "create"})`
        actions_verbs: list[str] = []
        if unwrapped.args and isinstance(unwrapped.args[0], ast.Dict):
            for k in unwrapped.args[0].keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    up = k.value.upper()
                    if up in _HTTP_VERB_SET and up not in actions_verbs:
                        actions_verbs.append(up)

        has_allowed_kw = False
        allowed_kw: frozenset[str] = frozenset()
        for kw in unwrapped.keywords:
            if kw.arg == "http_method_names" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                has_allowed_kw = True
                allowed_kw = _literal_http_methods(kw.value)

        if actions_verbs:
            if has_allowed_kw:
                filtered = [v for v in actions_verbs if v in allowed_kw]
                return (None if is_ext else v_mod), cls_name or short_sym, tuple(filtered)
            return (None if is_ext else v_mod), cls_name or short_sym, tuple(actions_verbs)

        if v_mod and v_mod in view_metas and cls_name:
            cbv_methods, ext_bases = _collect_cbv_methods(
                v_mod, cls_name, view_metas, all_imports, known_mods, pkg_reexports, set()
            )
            cls_allowed = view_metas[v_mod].class_allowed_methods.get(cls_name)
            if has_allowed_kw:
                effective_allowed: frozenset[str] | None = allowed_kw
            else:
                effective_allowed = cls_allowed
            if cbv_methods:
                ordered = tuple(v for v in HTTP_VERBS if v in cbv_methods and (effective_allowed is None or v in effective_allowed))
                return v_mod, cls_name, ordered
            for base_name in ext_bases:
                if base_name in _DRF_GENERIC_METHODS:
                    g_verbs = tuple(v for v in _DRF_GENERIC_METHODS[base_name] if effective_allowed is None or v in effective_allowed)
                    return v_mod, cls_name, g_verbs
            if effective_allowed is not None:
                return v_mod, cls_name, tuple(v for v in HTTP_VERBS if v in effective_allowed)
            return v_mod, cls_name, ("GET", "POST")
        if has_allowed_kw:
            return (None if is_ext else v_mod), cls_name or short_sym, tuple(v for v in HTTP_VERBS if v in allowed_kw)
        return (None if is_ext else v_mod), cls_name or short_sym, ("GET", "POST")

    view_dotted = _dotted(unwrapped) or ""
    short_sym = view_dotted.rsplit(".", 1)[-1]
    if view_dotted:
        v_mod, v_sym, is_ext = resolve_dotted_symbol(origin_mod, view_dotted, all_imports, known_mods, pkg_reexports)
        if is_ext:
            return None, (v_sym or short_sym), ("GET", "POST")
        if v_mod not in view_metas:
            v_mod = symbol_to_mod.get(short_sym)
            v_sym = short_sym
        fn_name = (v_sym or short_sym).rsplit(".", 1)[-1]
        if v_mod and v_mod in view_metas and fn_name in view_metas[v_mod].fn_methods:
            verbs = tuple(v for v in HTTP_VERBS if v in view_metas[v_mod].fn_methods[fn_name])
            if verbs:
                return v_mod, fn_name, verbs
        return v_mod, fn_name or short_sym, ("GET", "POST")
    return None, "", ("GET", "POST")


