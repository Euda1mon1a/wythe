"""Syntax-tree analyzer for Python manipulation modules (ORM, SQL, FastAPI, and hygiene)."""

from __future__ import annotations

import ast
import builtins
import re
from dataclasses import dataclass, field

from app.core.policy_context import get_active_policy_tokens, name_has_policy_token

_SQL_IDENT = r'(?:"?[A-Za-z_][A-Za-z0-9_]*"?\.)?"?[A-Za-z_][A-Za-z0-9_]*"?'
_SQL_VERBS = ("select", "insert", "update", "delete", "with")
_SESSION_WRITES = frozenset(
    {
        "add",
        "add_all",
        "delete",
        "merge",
        "update",
        "bulk_save_objects",
        "bulk_insert_mappings",
        "bulk_update_mappings",
    }
)
_CONSTRUCT_WRITES = frozenset({"insert", "update", "delete"})
_HTTP_DECORATORS = frozenset({"get", "post", "put", "patch", "delete"})
_GENERIC_ATTR_METHODS = frozenset(
    {
        "add",
        "all",
        "append",
        "as_posix",
        "clear",
        "close",
        "commit",
        "compile",
        "copy",
        "count",
        "decode",
        "delete",
        "dict",
        "dumps",
        "encode",
        "endswith",
        "execute",
        "exists",
        "extend",
        "filter",
        "findall",
        "finditer",
        "first",
        "flush",
        "format",
        "fullmatch",
        "get",
        "glob",
        "group",
        "group_by",
        "index",
        "insert",
        "is_dir",
        "is_file",
        "is_relative_to",
        "items",
        "join",
        "json",
        "keys",
        "limit",
        "loads",
        "lower",
        "lstrip",
        "match",
        "merge",
        "model_copy",
        "model_dump",
        "model_validate",
        "offset",
        "one",
        "one_or_none",
        "open",
        "order_by",
        "parse",
        "pop",
        "read",
        "read_bytes",
        "read_text",
        "refresh",
        "relative_to",
        "remove",
        "removeprefix",
        "removesuffix",
        "replace",
        "resolve",
        "rglob",
        "rollback",
        "rsplit",
        "rstrip",
        "run",
        "scalar",
        "scalar_one",
        "scalar_one_or_none",
        "scalars",
        "search",
        "select",
        "set",
        "setdefault",
        "sort",
        "split",
        "splitlines",
        "startswith",
        "strip",
        "sub",
        "update",
        "upper",
        "values",
        "walk",
        "where",
        "with_suffix",
        "write",
        "write_bytes",
        "write_text",
    }
)

_POLICY_NUMERIC_TOKENS = (
    "WEIGHT",
    "CAPACITY",
    "PENALTY",
    "RATIO",
    "DUTY_HOUR",
    "WORK_HOUR",
    "WORKLOAD",
    "SHIFT_CAP",
    "HOUR_LIMIT",
    "HOURS_LIMIT",
    "CLINIC_MAX",
    "CLINIC_MIN",
    "WEEKLY_MAX",
    "WEEKLY_MIN",
    "CALL_CAP",
    "SUPERVISION",
    "CADENCE",
    "CUTOFF_DAYS",
)
_POLICY_COLLECTION_TOKENS = (
    "_CODE_MAP",
    "_CODES",
    "_PREFIXES",
    "_WEIGHTS",
    "_PENALTIES",
    "_EXEMPTIONS",
)


_CLOCK_CLASSES = frozenset({"date", "datetime"})


def _clock_ref(node: ast.AST, classes: dict[str, str], modules: set[str]) -> tuple[str, str] | None:
    """Resolve `date.today` / `d.today` / `dt.datetime.now` to (class, attr) via the module's imports."""
    if not isinstance(node, ast.Attribute):
        return None
    base = node.value
    if isinstance(base, ast.Name) and base.id in classes:
        return classes[base.id], node.attr
    if (
        isinstance(base, ast.Attribute)
        and base.attr in _CLOCK_CLASSES
        and isinstance(base.value, ast.Name)
        and base.value.id in modules
    ):
        return base.attr, node.attr
    return None


def _is_none(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _naive_clock_call(call: ast.Call, cls: str, attr: str) -> bool:
    """True when the call reads the host clock without a time zone."""
    tz_kw = next((kw.value for kw in call.keywords if kw.arg == "tz"), None)
    has_tz_kw = any(kw.arg == "tz" for kw in call.keywords)
    if cls == "date":
        return attr in ("today", "fromtimestamp")
    if attr in ("today", "utcnow", "utcfromtimestamp"):
        return True
    if attr == "now":
        if call.args:
            return _is_none(call.args[0])
        return not has_tz_kw or _is_none(tz_kw)
    if attr == "fromtimestamp":
        if len(call.args) >= 2:
            return _is_none(call.args[1])
        return not has_tz_kw or _is_none(tz_kw)
    return False


@dataclass(frozen=True)
class ParsedRouteHandler:
    func_name: str
    http_method: str
    subpath: str
    lineno: int
    called_symbols: frozenset[str]


@dataclass(frozen=True)
class ParsedPythonModule:
    rel_path: str
    module_name: str
    summary: str
    reads: frozenset[str]
    writes: frozenset[str]
    called: frozenset[str]
    defined: frozenset[str]
    sql_reads: frozenset[str]
    sql_writes: frozenset[str]
    sql_calls: frozenset[str]
    imported_modules: frozenset[str]
    router_prefix: str
    router_includes: tuple[tuple[str, str], ...]  # (included module stem, prefix)
    route_handlers: tuple[ParsedRouteHandler, ...]
    policy_literals: tuple[tuple[str, int, str], ...]  # (const_name, lineno, sample)
    raw_clock_calls: tuple[tuple[str, int], ...]  # (expr, lineno)
    method_calls: frozenset[str] = frozenset()  # `param.method()` on an injected, unannotated parameter
    param_method_calls: tuple[tuple[str, frozenset[str]], ...] = ()  # (method, all attrs accessed on param)
    class_attrs: dict[str, frozenset[str]] = field(default_factory=dict)  # ClassName -> defined methods/attrs
    class_bases: dict[str, tuple[str, ...]] = field(default_factory=dict)  # ClassName -> base names
    top_level_defs: frozenset[str] = frozenset()
    method_defs: frozenset[str] = frozenset()
    # Package `__init__` only: (exported name, absolute "module.name" source, the initializer's own top-level
    # definitions that use it; "*" = module-level code, which runs on import)
    package_exports: tuple[tuple[str, str, frozenset[str]], ...] = ()
    symbol_calls: frozenset[str] = frozenset()
    # Precision fields (all are subsets/annotations of the coarse sets above):
    # `constructed` = names called like constructors; `persisted` = names that reach a session
    # write, an insert/update/delete construct, or a mutation of a row loaded from the session.
    constructed: frozenset[str] = frozenset()
    persisted: frozenset[str] = frozenset()
    # True when the module itself calls a session write/flush/commit or emits write SQL.
    has_session_writes: bool = False
    # Original imported name -> absolute modules it is imported from (`from M import name`).
    imported_names: dict[str, frozenset[str]] = field(default_factory=dict)
    # First line of write evidence per symbol (constructors, session writes, SQL write targets).
    write_lines: dict[str, int] = field(default_factory=dict)
    # Includes made into this module's own `APIRouter` (`router.include_router(sub)`): the
    # included routes live under wherever this module's router is mounted.
    nested_router_includes: tuple[tuple[str, str], ...] = ()


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _included_router_module(
    inc_target: str,
    aliases: dict[str, str],
    import_sources: dict[str, str],
    router_vars: set[str],
) -> str | None:
    """Stem of the module whose router `include_router(<inc_target>)` mounts, or None.

    `users.router` / `pkg.users.router` -> `users`; `users_router` imported with
    `from app.api.users import router as users_router` -> `users` (the defining module,
    not the imported attribute name); a router defined in this same module -> None.
    """
    if not inc_target:
        return None
    if "." in inc_target:
        owner = inc_target.rsplit(".", 1)[0]
        head, _, rest = owner.partition(".")
        resolved = aliases.get(head, head)
        full = f"{resolved}.{rest}" if rest else resolved
        return full.rsplit(".", 1)[-1]
    if inc_target in router_vars:
        return None
    source = import_sources.get(inc_target)
    if source:
        return source.rsplit(".", 1)[-1]
    return aliases.get(inc_target, inc_target)


def _excluded_ids(tree: ast.AST) -> set[int]:
    excluded: set[int] = set()

    def mark(sub: ast.AST | None) -> None:
        if sub is not None:
            excluded.update(id(c) for c in ast.walk(sub))

    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            t = node.test
            if (isinstance(t, ast.Name) and t.id == "TYPE_CHECKING") or (
                isinstance(t, ast.Attribute) and t.attr == "TYPE_CHECKING"
            ):
                for s in node.body:
                    mark(s)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            mark(node.returns)
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, node.args.vararg, node.args.kwarg):
                if arg is not None:
                    mark(arg.annotation)
        elif isinstance(node, ast.AnnAssign):
            mark(node.annotation)
        elif isinstance(node, ast.ClassDef):
            for b in (*node.bases, *node.keywords):
                mark(b)
    return excluded


_BUILTIN_NAMES = frozenset(dir(builtins))


def _absolute_import_bindings(
    tree: ast.AST, module_name: str, rel_path: str, excluded: set[int] | None = None
) -> list[tuple[str, str, str, str, int]]:
    """(local_name, absolute 'module.orig', orig_name, src_mod, level) for runtime `from ... import`."""
    skip = excluded or set()
    own_pkg = module_name.removesuffix(".__init__")
    if not rel_path.endswith("__init__.py"):
        own_pkg = own_pkg.rpartition(".")[0]
    out: list[tuple[str, str, str, str, int]] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.ImportFrom) or id(n) in skip:
            continue
        src_mod = n.module or ""
        if n.level:
            base = own_pkg
            for _ in range(n.level - 1):
                base = base.rpartition(".")[0]
            src_mod = ".".join(p for p in (base, n.module) if p)
        if src_mod:
            out.extend(
                (alias.asname or alias.name, f"{src_mod}.{alias.name}", alias.name, src_mod, n.level)
                for alias in n.names
            )
    return out


def _comp_bound_names(comp: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp) -> set[str]:
    return {
        t.id
        for g in comp.generators
        for t in ast.walk(g.target)
        if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)
    }


def _fn_local_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    bound = _arg_names(fn.args)
    nonlocals: set[str] = set()
    queue: list[ast.AST] = list(fn.body)
    idx = 0
    while idx < len(queue):
        cur = queue[idx]
        idx += 1
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(cur.name)
            continue
        if isinstance(cur, ast.Lambda):
            continue
        if isinstance(cur, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            if cur.generators:
                queue.append(cur.generators[0].iter)
            for sub in _expr_nodes_shallow(cur, set()):
                if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                    bound.add(sub.target.id)
            continue
        if isinstance(cur, ast.Name) and isinstance(cur.ctx, ast.Store):
            bound.add(cur.id)
        elif isinstance(cur, ast.ExceptHandler) and cur.name:
            bound.add(cur.name)
        elif isinstance(cur, (ast.Import, ast.ImportFrom)):
            for alias in cur.names:
                if alias.name != "*":
                    bound.add((alias.asname or alias.name).split(".", 1)[0])
        elif isinstance(cur, (ast.MatchAs, ast.MatchStar)) and cur.name:
            bound.add(cur.name)
        elif isinstance(cur, ast.MatchMapping) and cur.rest:
            bound.add(cur.rest)
        elif isinstance(cur, ast.Nonlocal):
            nonlocals.update(cur.names)
        elif isinstance(cur, ast.Global):
            bound.update(cur.names)
        queue.extend(ast.iter_child_nodes(cur))
    return bound - nonlocals


DefsMap = dict[str, set[ast.FunctionDef | ast.AsyncFunctionDef]]


def _copy_defs(defs: DefsMap) -> DefsMap:
    return {k: set(v) for k, v in defs.items() if v}


def _merge_defs(*maps: DefsMap) -> DefsMap:
    merged: DefsMap = {}
    for mp in maps:
        for k, vals in mp.items():
            if vals:
                merged.setdefault(k, set()).update(vals)
    return merged


def _is_nonempty_iter_literal(expr: ast.AST) -> bool:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return any(not isinstance(e, ast.Starred) for e in expr.elts)
    if isinstance(expr, ast.Dict):
        return any(k is not None for k in expr.keys)
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (str, bytes)):
        return len(expr.value) > 0
    return False


def _live_param_expr_nodes(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda, nm: str
) -> list[ast.AST]:
    """Collect AST expression nodes reachable while `nm` may still hold `fn`'s initial parameter."""
    out: list[ast.AST] = []
    activated_states: set[tuple[int, frozenset[tuple[str, frozenset[int]]]]] = set()
    active_fn_stack: set[int] = set()

    def run_scope(
        body: list[ast.stmt] | ast.expr,
        outer_defs: DefsMap | None = None,
    ) -> None:
        init_defs: DefsMap = _copy_defs(outer_defs or {})
        dead_refs: set[int] = set()

        def activate_defs(name: str, cur_defs: DefsMap) -> None:
            for fn_def in list(cur_defs.get(name, ())):
                if id(fn_def) in active_fn_stack:
                    continue
                fn_locals = _fn_local_names(fn_def)
                if nm in fn_locals:
                    continue
                scoped_defs = {k: set(v) for k, v in cur_defs.items() if k not in fn_locals and v}
                sig = frozenset((k, frozenset(id(x) for x in v)) for k, v in scoped_defs.items())
                state_key = (id(fn_def), sig)
                if state_key in activated_states:
                    continue
                activated_states.add(state_key)
                active_fn_stack.add(id(fn_def))
                try:
                    run_scope(fn_def.body, scoped_defs)
                finally:
                    active_fn_stack.discard(id(fn_def))

        def walk_target(tgt: ast.AST, live: bool, defs: DefsMap) -> tuple[bool, DefsMap]:
            if isinstance(tgt, ast.Name):
                defs.pop(tgt.id, None)
                if tgt.id == nm:
                    return False, defs
                return live, defs
            if isinstance(tgt, (ast.Tuple, ast.List)):
                for elt in tgt.elts:
                    live, defs = walk_target(elt, live, defs)
                return live, defs
            if isinstance(tgt, ast.Starred):
                return walk_target(tgt.value, live, defs)
            if isinstance(tgt, ast.Attribute):
                if live:
                    out.append(tgt)
                return walk_expr(tgt.value, live, defs)
            if isinstance(tgt, ast.Subscript):
                if live:
                    out.append(tgt)
                live, defs = walk_expr(tgt.value, live, defs)
                return walk_expr(tgt.slice, live, defs)
            return live, defs

        def walk_expr(expr: ast.AST | None, live: bool, defs: DefsMap) -> tuple[bool, DefsMap]:
            if expr is None:
                return live, defs
            if isinstance(expr, ast.NamedExpr):
                rhs_defs = set(defs.get(expr.value.id, ())) if isinstance(expr.value, ast.Name) else set()
                live, defs = walk_expr(expr.value, live, defs)
                if live:
                    out.append(expr)
                live, defs = walk_target(expr.target, live, defs)
                if rhs_defs and isinstance(expr.target, ast.Name) and expr.target.id != nm:
                    defs[expr.target.id] = rhs_defs
                return live, defs
            if isinstance(expr, ast.Lambda):
                if live:
                    out.append(expr)
                for dflt in (*expr.args.defaults, *(d for d in expr.args.kw_defaults if d is not None)):
                    live, defs = walk_expr(dflt, live, defs)
                lam_bound = _arg_names(expr.args) | {
                    sub.target.id
                    for sub in _expr_nodes_shallow(expr.body, set())
                    if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name)
                }
                if live and nm not in lam_bound:
                    lam_defs = {k: set(v) for k, v in defs.items() if k not in lam_bound and v}
                    run_scope(expr.body, lam_defs)
                return live, defs
            if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                if live:
                    out.append(expr)
                if expr.generators:
                    live, defs = walk_expr(expr.generators[0].iter, live, defs)
                cbound = _comp_bound_names(expr)
                eager_nonempty = (
                    not isinstance(expr, ast.GeneratorExp)
                    and bool(expr.generators)
                    and _is_nonempty_iter_literal(expr.generators[0].iter)
                )
                if live and nm not in cbound:
                    clive = live
                    cdefs = {k: set(v) for k, v in defs.items() if k not in cbound and v}
                    must_live = live
                    must_defs: DefsMap | None = None
                    if expr.generators:
                        for idx_if, ifs_e in enumerate(expr.generators[0].ifs):
                            clive, cdefs = walk_expr(ifs_e, clive, cdefs)
                            if eager_nonempty and idx_if == 0:
                                must_live = clive
                                must_defs = _copy_defs(cdefs)
                        for gen in expr.generators[1:]:
                            clive, cdefs = walk_expr(gen.iter, clive, cdefs)
                            for ifs_e in gen.ifs:
                                clive, cdefs = walk_expr(ifs_e, clive, cdefs)
                    if isinstance(expr, ast.DictComp):
                        clive, cdefs = walk_expr(expr.key, clive, cdefs)
                        clive, cdefs = walk_expr(expr.value, clive, cdefs)
                    else:
                        clive, cdefs = walk_expr(expr.elt, clive, cdefs)
                    if eager_nonempty and len(expr.generators) == 1 and not expr.generators[0].ifs:
                        must_live = clive
                        must_defs = _copy_defs(cdefs)
                    kept_cbound = {k: set(v) for k, v in defs.items() if k in cbound and v}
                    if must_defs is not None:
                        live = must_live
                        defs = _merge_defs(kept_cbound, must_defs, cdefs)
                    else:
                        defs = _merge_defs(defs, cdefs)
                return live, defs
            if isinstance(expr, ast.IfExp):
                if live:
                    out.append(expr)
                lt, dt = walk_expr(expr.test, live, defs)
                lb, db = walk_expr(expr.body, lt, _copy_defs(dt))
                le, de = walk_expr(expr.orelse, lt, _copy_defs(dt))
                return (lb or le), _merge_defs(db, de)
            if isinstance(expr, ast.BoolOp):
                if live:
                    out.append(expr)
                cur_l, cur_d = walk_expr(expr.values[0], live, defs)
                any_sc = cur_l
                snaps = [_copy_defs(cur_d)]
                for val in expr.values[1:]:
                    cur_l, cur_d = walk_expr(val, cur_l, _copy_defs(cur_d))
                    any_sc = any_sc or cur_l
                    snaps.append(_copy_defs(cur_d))
                return any_sc, _merge_defs(*snaps)
            if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
                if live:
                    out.append(expr)
                    if expr.id in defs:
                        activate_defs(expr.id, defs)
                elif expr.id in defs:
                    for fn_node in defs[expr.id]:
                        dead_refs.add(id(fn_node))
                return live, defs
            if isinstance(expr, ast.Call):
                if live:
                    out.append(expr)
                live, defs = walk_expr(expr.func, live, defs)
                for arg_e in expr.args:
                    live, defs = walk_expr(arg_e, live, defs)
                for kw in expr.keywords:
                    live, defs = walk_expr(kw.value, live, defs)
                return live, defs
            if isinstance(expr, ast.Dict):
                if live:
                    out.append(expr)
                for k_e, v_e in zip(expr.keys, expr.values, strict=False):
                    live, defs = walk_expr(k_e, live, defs)
                    live, defs = walk_expr(v_e, live, defs)
                return live, defs
            if live:
                out.append(expr)
            for ch in ast.iter_child_nodes(expr):
                if isinstance(ch, ast.expr):
                    live, defs = walk_expr(ch, live, defs)
            return live, defs

        def walk_stmts(
            stmts: list[ast.stmt],
            live: bool,
            defs: DefsMap,
            loop_breaks: list[tuple[bool, DefsMap]] | None = None,
            loop_continues: list[tuple[bool, DefsMap]] | None = None,
        ) -> tuple[bool, DefsMap, bool]:
            for s in stmts:
                if isinstance(s, ast.Return):
                    live, defs = walk_expr(s.value, live, defs)
                    return live, defs, False
                if isinstance(s, ast.Raise):
                    live, defs = walk_expr(s.exc, live, defs)
                    live, defs = walk_expr(s.cause, live, defs)
                    return live, defs, False
                if isinstance(s, ast.Break):
                    if loop_breaks is not None:
                        loop_breaks.append((live, _copy_defs(defs)))
                    return live, defs, False
                if isinstance(s, ast.Continue):
                    if loop_continues is not None:
                        loop_continues.append((live, _copy_defs(defs)))
                    return live, defs, False
                if isinstance(s, ast.Assign):
                    rhs_defs = set(defs.get(s.value.id, ())) if isinstance(s.value, ast.Name) else set()
                    live, defs = walk_expr(s.value, live, defs)
                    for tgt in s.targets:
                        live, defs = walk_target(tgt, live, defs)
                    if rhs_defs and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and s.targets[0].id != nm:
                        defs[s.targets[0].id] = rhs_defs
                elif isinstance(s, ast.AnnAssign):
                    if s.value is not None:
                        rhs_defs = set(defs.get(s.value.id, ())) if isinstance(s.value, ast.Name) else set()
                        live, defs = walk_expr(s.value, live, defs)
                        live, defs = walk_target(s.target, live, defs)
                        if rhs_defs and isinstance(s.target, ast.Name) and s.target.id != nm:
                            defs[s.target.id] = rhs_defs
                elif isinstance(s, ast.AugAssign):
                    if isinstance(s.target, ast.Name):
                        live, defs = walk_expr(s.value, live, defs)
                        live, defs = walk_target(s.target, live, defs)
                    else:
                        live, defs = walk_target(s.target, live, defs)
                        live, defs = walk_expr(s.value, live, defs)
                elif isinstance(s, ast.Delete):
                    for tgt in s.targets:
                        live, defs = walk_target(tgt, live, defs)
                elif isinstance(s, ast.Expr):
                    live, defs = walk_expr(s.value, live, defs)
                elif isinstance(s, ast.Assert):
                    live, defs = walk_expr(s.test, live, defs)
                    live, defs = walk_expr(s.msg, live, defs)
                elif isinstance(s, (ast.Import, ast.ImportFrom)):
                    for alias in s.names:
                        if alias.name != "*":
                            bound_nm = (alias.asname or alias.name).split(".", 1)[0]
                            defs.pop(bound_nm, None)
                            if bound_nm == nm:
                                live = False
                elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in s.decorator_list:
                        live, defs = walk_expr(dec, live, defs)
                    for dflt in (*s.args.defaults, *(d for d in s.args.kw_defaults if d is not None)):
                        live, defs = walk_expr(dflt, live, defs)
                    if s.decorator_list:
                        defs.pop(s.name, None)
                        s_locals = _fn_local_names(s)
                        if live and nm not in s_locals:
                            run_scope(s.body, {k: set(v) for k, v in defs.items() if k not in s_locals and v})
                    else:
                        defs[s.name] = {s}
                    if s.name == nm:
                        defs.pop(nm, None)
                        live = False
                elif isinstance(s, ast.ClassDef):
                    for dec in s.decorator_list:
                        live, defs = walk_expr(dec, live, defs)
                    defs.pop(s.name, None)
                    if s.name == nm:
                        live = False
                elif isinstance(s, ast.TypeAlias):
                    if isinstance(s.name, ast.Name):
                        defs.pop(s.name.id, None)
                        if s.name.id == nm:
                            live = False
                elif isinstance(s, ast.If):
                    live, defs = walk_expr(s.test, live, defs)
                    lb, db, fb = walk_stmts(s.body, live, _copy_defs(defs), loop_breaks, loop_continues)
                    le, de, fe = walk_stmts(s.orelse, live, _copy_defs(defs), loop_breaks, loop_continues)
                    if not fb and not fe:
                        return (lb or le), _merge_defs(db, de), False
                    live = (lb if fb else False) or (le if fe else False)
                    defs = _merge_defs(*(([db] if fb else []) + ([de] if fe else [])))
                elif isinstance(s, (ast.For, ast.AsyncFor)):
                    live, defs = walk_expr(s.iter, live, defs)
                    nonempty_iter = _is_nonempty_iter_literal(s.iter)
                    body_in, body_defs = walk_target(s.target, live, _copy_defs(defs))
                    brk: list[tuple[bool, DefsMap]] = []
                    cnt: list[tuple[bool, DefsMap]] = []
                    lb, db, fb = walk_stmts(s.body, body_in, body_defs, brk, cnt)
                    iter_end_l = (lb if fb else False) or any(cl for cl, _ in cnt)
                    iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd in cnt]))
                    if fb or cnt:
                        body2_in, body2_defs = walk_target(s.target, iter_end_l, _copy_defs(iter_end_d))
                        merged_body_defs = _merge_defs(body_defs, body2_defs)
                        if merged_body_defs != body_defs:
                            brk = []
                            cnt = []
                            lb, db, fb = walk_stmts(s.body, body_in or body2_in, merged_body_defs, brk, cnt)
                            iter_end_l = (lb if fb else False) or any(cl for cl, _ in cnt)
                            iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd in cnt]))
                    zero_iter = False if nonempty_iter else live
                    if nonempty_iter and not fb and not cnt:
                        le, de, fe = False, {}, False
                    else:
                        else_in_l = zero_iter or iter_end_l
                        else_in_d = (
                            iter_end_d
                            if nonempty_iter
                            else (_merge_defs(defs, iter_end_d) if (fb or cnt) else _copy_defs(defs))
                        )
                        le, de, fe = walk_stmts(s.orelse, else_in_l, else_in_d, loop_breaks, loop_continues)
                    if not fe and not brk:
                        return le, de, False
                    live = (le if fe else False) or any(bl for bl, _ in brk)
                    defs = _merge_defs(*(([de] if fe else []) + [bd for _, bd in brk]))
                elif isinstance(s, ast.While):
                    live, defs = walk_expr(s.test, live, defs)
                    always_true = isinstance(s.test, ast.Constant) and bool(s.test.value) is True
                    brk = []
                    cnt = []
                    lb, db, fb = walk_stmts(s.body, live, _copy_defs(defs), brk, cnt)
                    iter_end_l = (lb if fb else False) or any(cl for cl, _ in cnt)
                    iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd in cnt]))
                    zero_iter = False if always_true else live
                    if not zero_iter and not fb and not cnt:
                        le, de, fe = False, {}, False
                    else:
                        else_in_d = iter_end_d if always_true else _merge_defs(defs, iter_end_d)
                        le, de, fe = walk_stmts(s.orelse, zero_iter or iter_end_l, else_in_d, loop_breaks, loop_continues)
                    if not fe and not brk:
                        return le, de, False
                    live = (le if fe else False) or any(bl for bl, _ in brk)
                    defs = _merge_defs(*(([de] if fe else []) + [bd for _, bd in brk]))
                elif isinstance(s, (ast.With, ast.AsyncWith)):
                    for item in s.items:
                        live, defs = walk_expr(item.context_expr, live, defs)
                        if item.optional_vars is not None:
                            live, defs = walk_target(item.optional_vars, live, defs)
                    live, defs, fw = walk_stmts(s.body, live, defs, loop_breaks, loop_continues)
                    if not fw:
                        return live, defs, False
                elif isinstance(s, (ast.Try, ast.TryStar)):
                    entry_live = live
                    entry_defs = _copy_defs(defs)
                    lt, dt, ft = walk_stmts(s.body, entry_live, _copy_defs(entry_defs), loop_breaks, loop_continues)
                    le, de, fe = (
                        walk_stmts(s.orelse, lt, _copy_defs(dt), loop_breaks, loop_continues)
                        if ft
                        else (False, {}, False)
                    )
                    h_lives: list[bool] = [le] if fe else []
                    h_defs: list[DefsMap] = [de] if fe else []
                    any_fall = fe
                    exc_base_defs = _merge_defs(entry_defs, dt)
                    for h in s.handlers:
                        if h.type is not None:
                            walk_expr(h.type, entry_live or lt, _copy_defs(exc_base_defs))
                        hd = _copy_defs(exc_base_defs)
                        if h.name:
                            hd.pop(h.name, None)
                        h_in = False if h.name == nm else (entry_live or lt)
                        lh, dh, fh = walk_stmts(h.body, h_in, hd, loop_breaks, loop_continues)
                        if fh:
                            any_fall = True
                            h_lives.append(lh)
                            h_defs.append(dh)
                    fin_in_l = any(h_lives) if any_fall else (entry_live or lt)
                    fin_in_d = _merge_defs(*h_defs) if any_fall else exc_base_defs
                    lf, df, ff = walk_stmts(s.finalbody, fin_in_l, fin_in_d, loop_breaks, loop_continues)
                    if not ff or not any_fall:
                        return lf, df, False
                    live, defs = lf, df
                elif isinstance(s, ast.Match):
                    live, defs = walk_expr(s.subject, live, defs)
                    c_lives: list[bool] = []
                    c_defs: list[DefsMap] = []
                    exit_lives: list[bool] = []
                    exit_defs: list[DefsMap] = []
                    any_fall = False
                    has_wild = False
                    for case in s.cases:
                        pat_names = {
                            p.name for p in ast.walk(case.pattern) if isinstance(p, (ast.MatchAs, ast.MatchStar)) and p.name
                        } | {
                            p.rest for p in ast.walk(case.pattern) if isinstance(p, ast.MatchMapping) and p.rest
                        }
                        cd = _copy_defs(defs)
                        for pn in pat_names:
                            cd.pop(pn, None)
                        cin = False if nm in pat_names else live
                        if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                            has_wild = True
                        cin, cd = walk_expr(case.guard, cin, cd)
                        lc, dc, fc = walk_stmts(case.body, cin, cd, loop_breaks, loop_continues)
                        exit_lives.append(lc)
                        exit_defs.append(dc)
                        if fc:
                            any_fall = True
                            c_lives.append(lc)
                            c_defs.append(dc)
                    if not has_wild:
                        any_fall = True
                        c_lives.append(live)
                        c_defs.append(_copy_defs(defs))
                    if not any_fall:
                        return any(exit_lives), _merge_defs(*exit_defs), False
                    live = any(c_lives)
                    defs = _merge_defs(*c_defs)
                else:
                    for ch in ast.iter_child_nodes(s):
                        if isinstance(ch, ast.expr):
                            live, defs = walk_expr(ch, live, defs)
                        elif isinstance(ch, ast.stmt):
                            live, defs, fs = walk_stmts([ch], live, defs, loop_breaks, loop_continues)
                            if not fs:
                                return live, defs, False
            return live, defs, True

        if isinstance(body, list):
            end_live, end_defs, _ = walk_stmts(body, True, init_defs)
            if end_live:
                for fn_name, fn_nodes in list(end_defs.items()):
                    if any(id(fn_node) not in dead_refs for fn_node in fn_nodes):
                        activate_defs(fn_name, end_defs)
        else:
            walk_expr(body, True, init_defs)

    run_scope(fn.body)
    return out


def _injected_param_profiles(tree: ast.AST, excluded: set[int]) -> dict[int, dict[str, frozenset[str]]]:
    """Map each call `id(call)` to `{unannotated_param: frozenset(attrs accessed on param in that fn)}`."""
    out: dict[int, dict[str, frozenset[str]]] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) or id(fn) in excluded:
            continue
        a = fn.args
        names = frozenset(
            p.arg
            for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)
            if p.annotation is None and p.arg not in ("self", "cls")
        )
        if not names:
            continue
        for nm in names:
            subnodes = [s for s in _live_param_expr_nodes(fn, nm) if id(s) not in excluded]
            atts = {
                sub.attr
                for sub in subnodes
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == nm
            }
            if not atts:
                continue
            frozen_atts = frozenset(atts)
            for sub in subnodes:
                if isinstance(sub, ast.Call):
                    merged = dict(out.get(id(sub), {}))
                    merged[nm] = frozen_atts
                    out[id(sub)] = merged
    return out


def _sql_targets(text: str) -> tuple[set[str], set[str], set[str]]:
    stripped = text.lstrip().lstrip("(").lstrip()
    m = re.match(r"[A-Za-z]+", stripped)
    if m is None or m.group(0).lower() not in _SQL_VERBS:
        return set(), set(), set()
    word = m.group(0)
    if word not in (word.upper(), word.lower()):
        return set(), set(), set()
    flags = 0 if word.isupper() else re.IGNORECASE
    v = (
        {k: k.upper() for k in ("from", "join", "insert", "into", "update", "set", "delete")}
        if word.isupper()
        else {k: k for k in ("from", "join", "insert", "into", "update", "set", "delete")}
    )

    def grab(pat: str) -> set[str]:
        return {hit.group("t").replace('"', "").lower() for hit in re.finditer(pat, stripped, flags)}

    reads = grab(rf"\b(?:{v['from']}|{v['join']})\s+(?P<t>{_SQL_IDENT})")
    writes = grab(rf"\b{v['insert']}\s+{v['into']}\s+(?P<t>{_SQL_IDENT})")
    writes |= grab(rf"\b{v['update']}\s+(?P<t>{_SQL_IDENT})\s+(?:AS\s+\w+\s+)?{v['set']}\b")
    del_targets = grab(rf"\b{v['delete']}\s+{v['from']}\s+(?P<t>{_SQL_IDENT})")
    writes |= del_targets
    reads -= del_targets
    calls = {hit.group(1).lower() for hit in re.finditer(r"\b([A-Za-z_]\w*\.[A-Za-z_]\w*)\s*\(", stripped)}
    return reads, writes, calls


def _is_session_receiver(node: ast.AST) -> bool:
    d = _dotted(node) or ""
    tokens = [p for p in d.split(".") if p != "self"]
    return any(p == "db" or p.endswith("_db") or "session" in p.lower() for p in tokens[:1])


_ROW_LOAD_TERMINALS = frozenset({"first", "one", "one_or_none", "scalar", "scalar_one", "scalar_one_or_none"})
_ROW_SOURCES = frozenset({"query", "select"})
_MUTATING_SESSION_CALLS = _SESSION_WRITES | {"flush", "commit"}


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _model_arg(call: ast.Call) -> str | None:
    """`query(Model)`, `select(Model)`, `session.get(Model, pk)` -> 'Model' or 'pkg.Model'."""
    if not call.args:
        return None
    arg = call.args[0]
    if isinstance(arg, ast.Name) and arg.id[:1].isupper():
        return arg.id
    if isinstance(arg, ast.Attribute) and arg.attr[:1].isupper():
        return _dotted(arg)
    return None


def _model_in_row_source(expr: ast.AST) -> str | None:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call) and _call_name(sub) in _ROW_SOURCES:
            model = _model_arg(sub)
            if model:
                return model
    return None


def _loaded_row_model(expr: ast.AST | None) -> str | None:
    """Model of ONE row loaded through the session (`db.get(M, pk)`, `db.query(M)...first()`)."""
    if isinstance(expr, ast.Await):
        expr = expr.value
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
        return None
    if expr.func.attr == "get" and _is_session_receiver(expr.func.value):
        return _model_arg(expr)
    if expr.func.attr in _ROW_LOAD_TERMINALS:
        return _model_in_row_source(expr)
    return None


def _constructed_model(expr: ast.AST | None) -> str | None:
    """`Model(...)`, `pkg.Model(...)`, or classmethod factory `Model.create(...)`."""
    if isinstance(expr, ast.Await):
        expr = expr.value
    if not isinstance(expr, ast.Call):
        return None
    func = expr.func
    if isinstance(func, ast.Name) and func.id[:1].isupper():
        return func.id
    if isinstance(func, ast.Attribute):
        if func.attr[:1].isupper():
            return _dotted(func)
        if isinstance(func.value, ast.Name) and func.value.id[:1].isupper():
            return func.value.id
        if isinstance(func.value, ast.Attribute) and func.value.attr[:1].isupper():
            return _dotted(func.value)
    return None


def _expr_nodes_shallow(stmt_expr: ast.AST | None, excluded: set[int]) -> list[ast.AST]:
    """Walk an expression without descending into nested function/lambda/class definitions."""
    if stmt_expr is None or id(stmt_expr) in excluded:
        return []
    out: list[ast.AST] = [stmt_expr]
    idx = 0
    while idx < len(out):
        cur = out[idx]
        idx += 1
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        for ch in ast.iter_child_nodes(cur):
            if id(ch) not in excluded:
                out.append(ch)
    return out


def _merge_binding_maps(*maps: dict[str, set[str]]) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for mp in maps:
        for k, vals in mp.items():
            if vals:
                merged.setdefault(k, set()).update(vals)
    return merged


def _loaded_row_writes(tree: ast.Module, excluded: set[int]) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Statement-ordered writes to rows loaded from (or added to) the session, per lexical scope."""
    session_writes: list[tuple[str, int]] = []
    mutations: list[tuple[str, int]] = []

    def inspect_expr(expr: ast.AST | None, rows: dict[str, set[str]], made: dict[str, set[str]]) -> None:
        if expr is None or id(expr) in excluded:
            return
        if isinstance(expr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(expr, ast.Lambda):
            for dflt in (*expr.args.defaults, *(d for d in expr.args.kw_defaults if d is not None)):
                inspect_expr(dflt, rows, made)
            return
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            if expr.generators:
                inspect_expr(expr.generators[0].iter, rows, made)
            cbound = _comp_bound_names(expr)
            crows = {k: v for k, v in rows.items() if k not in cbound}
            cmade = {k: v for k, v in made.items() if k not in cbound}
            if expr.generators:
                for ifs_e in expr.generators[0].ifs:
                    inspect_expr(ifs_e, crows, cmade)
                for gen in expr.generators[1:]:
                    inspect_expr(gen.iter, crows, cmade)
                    for ifs_e in gen.ifs:
                        inspect_expr(ifs_e, crows, cmade)
            if isinstance(expr, ast.DictComp):
                inspect_expr(expr.key, crows, cmade)
                inspect_expr(expr.value, crows, cmade)
            else:
                inspect_expr(expr.elt, crows, cmade)
            return
        if isinstance(expr, ast.Call):
            name = _call_name(expr)
            if isinstance(expr.func, ast.Attribute) and name in _SESSION_WRITES and _is_session_receiver(expr.func.value):
                for arg in expr.args:
                    elts = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
                    for elt in elts:
                        if isinstance(elt, ast.Name) and elt.id in rows:
                            for m in rows[elt.id]:
                                session_writes.append((m, expr.lineno))
                        elif isinstance(elt, ast.Name) and elt.id in made and name != "delete":
                            for m in made[elt.id]:
                                session_writes.append((m, expr.lineno))
            elif name == "setattr" and isinstance(expr.func, ast.Name) and expr.args:
                first = expr.args[0]
                if isinstance(first, ast.Name) and first.id in rows:
                    for m in rows[first.id]:
                        mutations.append((m, expr.lineno))
            inspect_expr(expr.func, rows, made)
            for arg_e in expr.args:
                inspect_expr(arg_e, rows, made)
            for kw in expr.keywords:
                inspect_expr(kw.value, rows, made)
            return
        for ch in ast.iter_child_nodes(expr):
            if isinstance(ch, ast.expr):
                inspect_expr(ch, rows, made)

    def bind_var(
        var: str, rhs: ast.AST | None, rows: dict[str, set[str]], made: dict[str, set[str]]
    ) -> None:
        model = _loaded_row_model(rhs)
        if model:
            rows[var] = {model}
            made.pop(var, None)
            return
        maker = _constructed_model(rhs)
        if maker:
            made[var] = {maker}
            rows.pop(var, None)
            return
        rows.pop(var, None)
        made.pop(var, None)

    def record_target_mutations(tgt: ast.AST, lineno: int, rows: dict[str, set[str]]) -> None:
        for t in ast.walk(tgt):
            if (
                isinstance(t, ast.Attribute)
                and isinstance(t.ctx, ast.Store)
                and isinstance(t.value, ast.Name)
                and t.value.id in rows
            ):
                for m in rows[t.value.id]:
                    mutations.append((m, lineno))

    def walk_block(
        stmts: list[ast.stmt], rows: dict[str, set[str]], made: dict[str, set[str]]
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        for s in stmts:
            if id(s) in excluded:
                continue
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in s.decorator_list:
                    inspect_expr(dec, rows, made)
                for dflt in (*s.args.defaults, *(d for d in s.args.kw_defaults if d is not None)):
                    inspect_expr(dflt, rows, made)
                rows.pop(s.name, None)
                made.pop(s.name, None)
                continue
            if isinstance(s, ast.ClassDef):
                for dec in s.decorator_list:
                    inspect_expr(dec, rows, made)
                rows.pop(s.name, None)
                made.pop(s.name, None)
                continue
            if isinstance(s, (ast.Import, ast.ImportFrom)):
                for alias in s.names:
                    if alias.name != "*":
                        bnm = (alias.asname or alias.name).split(".", 1)[0]
                        rows.pop(bnm, None)
                        made.pop(bnm, None)
                continue
            if isinstance(s, ast.Assign):
                inspect_expr(s.value, rows, made)
                for tgt in s.targets:
                    record_target_mutations(tgt, s.lineno, rows)
                if len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                    bind_var(s.targets[0].id, s.value, rows, made)
                else:
                    for tgt in s.targets:
                        for sub in ast.walk(tgt):
                            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                                rows.pop(sub.id, None)
                                made.pop(sub.id, None)
            elif isinstance(s, ast.AnnAssign):
                inspect_expr(s.value, rows, made)
                record_target_mutations(s.target, s.lineno, rows)
                if isinstance(s.target, ast.Name) and s.value is not None:
                    bind_var(s.target.id, s.value, rows, made)
            elif isinstance(s, ast.AugAssign):
                inspect_expr(s.value, rows, made)
                record_target_mutations(s.target, s.lineno, rows)
            elif isinstance(s, (ast.For, ast.AsyncFor)):
                inspect_expr(s.iter, rows, made)
                r_loop_in = {k: set(v) for k, v in rows.items()}
                m_loop_in = {k: set(v) for k, v in made.items()}
                if isinstance(s.target, ast.Name):
                    m = _model_in_row_source(s.iter)
                    if m:
                        r_loop_in[s.target.id] = {m}
                        m_loop_in.pop(s.target.id, None)
                    else:
                        r_loop_in.pop(s.target.id, None)
                        m_loop_in.pop(s.target.id, None)
                r_body, m_body = walk_block(s.body, r_loop_in, m_loop_in)
                r_else, m_else = walk_block(
                    s.orelse,
                    _merge_binding_maps(rows, r_body),
                    _merge_binding_maps(made, m_body),
                )
                rows = _merge_binding_maps(rows, r_body, r_else)
                made = _merge_binding_maps(made, m_body, m_else)
            elif isinstance(s, ast.While):
                inspect_expr(s.test, rows, made)
                r_body, m_body = walk_block(
                    s.body, {k: set(v) for k, v in rows.items()}, {k: set(v) for k, v in made.items()}
                )
                r_else, m_else = walk_block(
                    s.orelse,
                    _merge_binding_maps(rows, r_body),
                    _merge_binding_maps(made, m_body),
                )
                rows = _merge_binding_maps(rows, r_body, r_else)
                made = _merge_binding_maps(made, m_body, m_else)
            elif isinstance(s, ast.If):
                inspect_expr(s.test, rows, made)
                r_body, m_body = walk_block(s.body, {k: set(v) for k, v in rows.items()}, {k: set(v) for k, v in made.items()})
                r_else, m_else = walk_block(s.orelse, {k: set(v) for k, v in rows.items()}, {k: set(v) for k, v in made.items()})
                rows = _merge_binding_maps(r_body, r_else)
                made = _merge_binding_maps(m_body, m_else)
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                for item in s.items:
                    inspect_expr(item.context_expr, rows, made)
                    if isinstance(item.optional_vars, ast.Name):
                        bind_var(item.optional_vars.id, item.context_expr, rows, made)
                rows, made = walk_block(s.body, rows, made)
            elif isinstance(s, (ast.Try, ast.TryStar)):
                branches_r: list[dict[str, set[str]]] = []
                branches_m: list[dict[str, set[str]]] = []
                r_try, m_try = walk_block(
                    s.body, {k: set(v) for k, v in rows.items()}, {k: set(v) for k, v in made.items()}
                )
                rb, mb = walk_block(
                    s.orelse, {k: set(v) for k, v in r_try.items()}, {k: set(v) for k, v in m_try.items()}
                )
                branches_r.append(rb)
                branches_m.append(mb)
                h_in_r = _merge_binding_maps(rows, r_try)
                h_in_m = _merge_binding_maps(made, m_try)
                for h in s.handlers:
                    hr = {k: set(v) for k, v in h_in_r.items()}
                    hm = {k: set(v) for k, v in h_in_m.items()}
                    if h.name:
                        hr.pop(h.name, None)
                        hm.pop(h.name, None)
                    rh, mh = walk_block(h.body, hr, hm)
                    branches_r.append(rh)
                    branches_m.append(mh)
                rows = _merge_binding_maps(*branches_r)
                made = _merge_binding_maps(*branches_m)
                rows, made = walk_block(s.finalbody, rows, made)
            elif isinstance(s, ast.Match):
                inspect_expr(s.subject, rows, made)
                case_r: list[dict[str, set[str]]] = []
                case_m: list[dict[str, set[str]]] = []
                has_wildcard = False
                for case in s.cases:
                    cr = {k: set(v) for k, v in rows.items()}
                    cm = {k: set(v) for k, v in made.items()}
                    for pat_node in ast.walk(case.pattern):
                        bound_name = (
                            pat_node.name
                            if isinstance(pat_node, (ast.MatchAs, ast.MatchStar))
                            else pat_node.rest
                            if isinstance(pat_node, ast.MatchMapping)
                            else None
                        )
                        if bound_name:
                            cr.pop(bound_name, None)
                            cm.pop(bound_name, None)
                    if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                        has_wildcard = True
                    inspect_expr(case.guard, cr, cm)
                    cr, cm = walk_block(case.body, cr, cm)
                    case_r.append(cr)
                    case_m.append(cm)
                if not has_wildcard:
                    case_r.append(rows)
                    case_m.append(made)
                rows = _merge_binding_maps(*case_r)
                made = _merge_binding_maps(*case_m)
            else:
                for ch in ast.iter_child_nodes(s):
                    if isinstance(ch, ast.expr):
                        inspect_expr(ch, rows, made)
                    elif isinstance(ch, ast.stmt):
                        rows, made = walk_block([ch], rows, made)
        return rows, made

    walk_block(tree.body, {}, {})
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(n) not in excluded:
            walk_block(n.body, {}, {})
    return session_writes, mutations


_CLOCK_FACTORY_KWARGS = frozenset({"default", "default_factory", "onupdate", "insert_default", "factory"})
_CLOCK_ZERO_ARG_CALLS = frozenset({"defaultdict", "Factory", "LazyFunction"})


def _arg_names(args: ast.arguments) -> set[str]:
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _collect_raw_clocks(tree: ast.Module, excluded: set[int]) -> list[tuple[str, int]]:
    """Find naive clock reads/factories while keeping import bindings scoped per function/class."""
    found: list[tuple[str, int]] = []

    def check_factory_val(val: ast.AST, classes: dict[str, str], modules: set[str]) -> None:
        ref = _clock_ref(val, classes, modules)
        if ref and ref[1] in ("now", "utcnow", "today"):
            found.append((f"{_dotted(val)} (passed uncalled)", getattr(val, "lineno", 1)))

    def inspect_expr(
        expr: ast.AST | None,
        classes: dict[str, str],
        modules: set[str],
        deferred_lams: list[ast.Lambda] | None = None,
    ) -> None:
        if isinstance(expr, ast.Lambda):
            for dflt in (*expr.args.defaults, *(d for d in expr.args.kw_defaults if d is not None)):
                inspect_expr(dflt, classes, modules, deferred_lams)
            if deferred_lams is not None:
                deferred_lams.append(expr)
            else:
                lam_params = _arg_names(expr.args)
                lam_classes = {k: v for k, v in classes.items() if k not in lam_params}
                inspect_expr(expr.body, lam_classes, modules - lam_params, None)
            return
        for n in _expr_nodes_shallow(expr, excluded):
            if isinstance(n, ast.Lambda):
                inspect_expr(n, classes, modules, deferred_lams)
                continue
            if not isinstance(n, ast.Call):
                continue
            target = n.func
            dotted = _dotted(target) or ""
            short = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
            clock = _clock_ref(target, classes, modules)
            if clock and _naive_clock_call(n, *clock):
                found.append((f"{dotted}()", n.lineno))
            for kw in n.keywords:
                if kw.arg in _CLOCK_FACTORY_KWARGS:
                    check_factory_val(kw.value, classes, modules)
            is_tzless_partial = (
                short == "partial"
                and len(n.args) == 1
                and not any(kw.arg == "tz" and not _is_none(kw.value) for kw in n.keywords)
            )
            if (short in _CLOCK_ZERO_ARG_CALLS and n.args) or is_tzless_partial:
                check_factory_val(n.args[0], classes, modules)

    def walk_stmts(
        stmts: list[ast.stmt],
        classes: dict[str, str],
        modules: set[str],
        deferred_fns: list[ast.FunctionDef | ast.AsyncFunctionDef],
        deferred_lams: list[ast.Lambda],
    ) -> None:
        for stmt in stmts:
            if id(stmt) in excluded:
                continue
            if isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    local_name = alias.asname or alias.name
                    if stmt.module == "datetime" and stmt.level == 0 and alias.name in _CLOCK_CLASSES:
                        classes[local_name] = alias.name
                    else:
                        classes.pop(local_name, None)
                        modules.discard(local_name)
                continue
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.name == "datetime":
                        bound = alias.asname or "datetime"
                        modules.add(bound)
                        if alias.asname:
                            classes.pop(alias.asname, None)
                    else:
                        bound = alias.asname or alias.name.split(".", 1)[0]
                        classes.pop(bound, None)
                        modules.discard(bound)
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in stmt.decorator_list:
                    inspect_expr(dec, classes, modules, deferred_lams)
                for dflt in (*stmt.args.defaults, *(d for d in stmt.args.kw_defaults if d is not None)):
                    inspect_expr(dflt, classes, modules, deferred_lams)
                deferred_fns.append(stmt)
                continue
            if isinstance(stmt, ast.ClassDef):
                for dec in stmt.decorator_list:
                    inspect_expr(dec, classes, modules, deferred_lams)
                for base_expr in (*stmt.bases, *(kw.value for kw in stmt.keywords)):
                    inspect_expr(base_expr, classes, modules, deferred_lams)
                walk_stmts(stmt.body, dict(classes), set(modules), deferred_fns, deferred_lams)
                continue
            for ch in ast.iter_child_nodes(stmt):
                if isinstance(ch, ast.expr):
                    inspect_expr(ch, classes, modules, deferred_lams)
                elif isinstance(ch, ast.stmt):
                    walk_stmts([ch], classes, modules, deferred_fns, deferred_lams)
                else:
                    for sub in ast.iter_child_nodes(ch):
                        if isinstance(sub, ast.expr):
                            inspect_expr(sub, classes, modules, deferred_lams)
                        elif isinstance(sub, ast.stmt):
                            walk_stmts([sub], classes, modules, deferred_fns, deferred_lams)

    def run_lexical_scope(stmts: list[ast.stmt], classes: dict[str, str], modules: set[str]) -> None:
        fns: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        lams: list[ast.Lambda] = []
        walk_stmts(stmts, classes, modules, fns, lams)
        for lam in lams:
            lam_params = _arg_names(lam.args)
            lam_classes = {k: v for k, v in classes.items() if k not in lam_params}
            inspect_expr(lam.body, lam_classes, modules - lam_params, None)
        for fn in fns:
            sub_classes = dict(classes)
            sub_modules = set(modules)
            for pname in _arg_names(fn.args):
                sub_classes.pop(pname, None)
                sub_modules.discard(pname)
            run_lexical_scope(fn.body, sub_classes, sub_modules)

    run_lexical_scope(tree.body, {"date": "date", "datetime": "datetime"}, {"datetime"})
    return found


def parse_python_module(source: str, rel_path: str, module_name: str) -> ParsedPythonModule | None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None

    excluded = _excluded_ids(tree)
    docstring_ids: set[int] = set()
    for n in ast.walk(tree):
        body = getattr(n, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstring_ids.add(id(first.value))

    local_pkg = module_name.split(".", 1)[0]
    aliases: dict[str, str] = {}
    import_sources: dict[str, str] = {}  # local name -> module it came from
    imported_modules: set[str] = set()
    external_roots: set[str] = set()
    imported_names: dict[str, set[str]] = {}
    for n in ast.walk(tree):
        if id(n) in excluded:
            continue
        if isinstance(n, ast.ImportFrom) and n.module:
            imported_modules.add(n.module)
            is_ext = n.level == 0 and n.module.split(".", 1)[0] != local_pkg
            for alias in n.names:
                imported_modules.add(f"{n.module}.{alias.name}")
                local_name = alias.asname or alias.name
                aliases[local_name] = alias.name
                import_sources[local_name] = n.module
                if is_ext:
                    external_roots.add(local_name)
        elif isinstance(n, ast.Import):
            for alias in n.names:
                imported_modules.add(alias.name)
                if alias.asname:
                    aliases[alias.asname] = alias.name
                if alias.name.split(".", 1)[0] != local_pkg:
                    external_roots.add(alias.asname or alias.name.split(".", 1)[0])
    # All runtime `from ... import` bindings (including `pkg/__init__.py` relative & `from . import x`).
    bindings = _absolute_import_bindings(tree, module_name, rel_path, excluded)
    for local_name, target, orig_name, src_mod, level in bindings:
        imported_names.setdefault(orig_name, set()).add(src_mod)
        if level:
            imported_modules.update((src_mod, target))
            aliases[local_name] = orig_name
            import_sources.setdefault(local_name, target)

    def resolve(sym: str) -> str:
        return aliases.get(sym, sym)

    def resolve_qual(sym: str) -> str:
        h, _, t = sym.partition(".")
        return f"{resolve(h)}.{t}" if t else resolve(sym)

    writes: set[str] = set()
    constructed: set[str] = set()
    persisted: set[str] = set()
    write_lines: dict[str, int] = {}
    has_session_writes = False
    called: set[str] = set()
    symbol_calls: set[str] = set()
    method_calls: set[str] = set()
    param_method_calls: set[tuple[str, frozenset[str]]] = set()
    param_profiles = _injected_param_profiles(tree, excluded)
    write_only: set[int] = set()

    def note_write(sym: str, lineno: int) -> None:
        if sym not in write_lines or lineno < write_lines[sym]:
            write_lines[sym] = lineno

    raw_clocks = _collect_raw_clocks(tree, excluded)
    router_prefix = ""
    router_includes: list[tuple[str, str]] = []
    nested_router_includes: list[tuple[str, str]] = []
    router_vars: set[str] = set()

    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            fn = _dotted(stmt.value.func) or ""
            if fn.endswith("APIRouter"):
                router_vars.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
                for kw in stmt.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        router_prefix = kw.value.value

    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or id(n) in excluded:
            continue
        target = n.func
        dotted = _dotted(target) or ""
        short = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""

        if dotted.endswith(".include_router") and n.args:
            inc_target = _dotted(n.args[0]) or ""
            inc_prefix = ""
            for kw in n.keywords:
                if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    inc_prefix = kw.value.value
            child = _included_router_module(inc_target, aliases, import_sources, router_vars)
            if child:
                router_includes.append((child, inc_prefix))
                if dotted.rsplit(".", 1)[0] in router_vars:
                    nested_router_includes.append((child, inc_prefix))

        if short:
            resolved_short = resolve(short)
            called.add(resolved_short)
            if isinstance(target, ast.Name):
                # Imported names resolve through their import edge; builtins never cross modules.
                if target.id not in external_roots and target.id not in aliases and target.id not in _BUILTIN_NAMES:
                    symbol_calls.add(resolved_short)
            elif isinstance(target, ast.Attribute):
                # Only an injected, unannotated parameter hides its class from the imports.
                recv = target.value
                prof = param_profiles.get(id(n), {})
                if isinstance(recv, ast.Name) and recv.id in prof and short not in _GENERIC_ATTR_METHODS:
                    method_calls.add(short)
                    param_method_calls.add((short, prof[recv.id]))
            if dotted:
                qual = resolve_qual(dotted)
                called.add(qual)
                writes.add(qual)
                constructed.add(qual)
                note_write(qual, n.lineno)
            writes.add(resolved_short)
            constructed.add(resolved_short)
            note_write(resolved_short, n.lineno)
            write_only.add(id(target))

        is_construct = isinstance(target, ast.Name) and short in _CONSTRUCT_WRITES
        is_sess = isinstance(target, ast.Attribute) and short in _SESSION_WRITES and _is_session_receiver(target.value)
        if is_construct or (
            isinstance(target, ast.Attribute)
            and short in _MUTATING_SESSION_CALLS
            and _is_session_receiver(target.value)
        ):
            has_session_writes = True
        if is_construct or is_sess:
            for sub in [*n.args, *(kw.value for kw in n.keywords)]:
                for child in ast.walk(sub):
                    syms: list[str] = []
                    if isinstance(child, ast.Name):
                        syms.append(resolve(child.id))
                    elif isinstance(child, ast.Attribute):
                        syms.append(child.attr)
                        d = _dotted(child)
                        if d:
                            syms.append(resolve_qual(d))
                    for sym in syms:
                        writes.add(sym)
                        persisted.add(sym)
                        note_write(sym, n.lineno)
                write_only.update(id(c) for c in ast.walk(sub))

    reads: set[str] = set()
    sql_reads: set[str] = set()
    sql_writes: set[str] = set()
    sql_calls: set[str] = set()
    for n in ast.walk(tree):
        if id(n) in excluded:
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and id(n) not in write_only:
            reads.add(resolve(n.id))
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and id(n) not in write_only:
            reads.add(n.attr)
            d = _dotted(n)
            if d:
                h, _, t = d.partition(".")
                reads.add(f"{resolve(h)}.{t}" if t else resolve(h))
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstring_ids:
            sr, sw, sc = _sql_targets(n.value)
            sql_reads |= sr
            sql_writes |= sw
            sql_calls |= sc
            for sym in sw:
                note_write(sym, n.lineno)

    if sql_writes:
        has_session_writes = True
    row_session_writes, row_mutations = _loaded_row_writes(tree, excluded)
    for model, lineno in row_session_writes:
        sym = resolve_qual(model)
        writes.add(sym)
        persisted.add(sym)
        note_write(sym, lineno)
    if has_session_writes:
        # A loaded row's attribute change is only an UPDATE if this module flushes/commits.
        for model, lineno in row_mutations:
            sym = resolve_qual(model)
            writes.add(sym)
            persisted.add(sym)
            note_write(sym, lineno)

    handlers: list[ParsedRouteHandler] = []
    defined: set[str] = set()
    top_level_defs: set[str] = set()
    method_defs: set[str] = set()
    class_attrs: dict[str, frozenset[str]] = {}
    class_bases: dict[str, tuple[str, ...]] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(stmt.name)
            top_level_defs.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef):
            defined.add(stmt.name)
            top_level_defs.add(stmt.name)
            cattrs: set[str] = set()
            bases: list[str] = []
            for b in stmt.bases:
                bname = b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
                if bname:
                    bases.append(resolve(bname))
            class_bases[stmt.name] = tuple(bases)
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    cattrs.add(member.name)
                    if not member.name.startswith("_"):
                        defined.add(member.name)
                        method_defs.add(member.name)
                    for sub in ast.walk(member):
                        if (
                            isinstance(sub, ast.Attribute)
                            and isinstance(sub.ctx, ast.Store)
                            and isinstance(sub.value, ast.Name)
                            and sub.value.id == "self"
                        ):
                            cattrs.add(sub.attr)
                elif isinstance(member, ast.Assign):
                    for t in member.targets:
                        if isinstance(t, ast.Name):
                            cattrs.add(t.id)
                elif isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                    cattrs.add(member.target.id)
            class_attrs[stmt.name] = frozenset(cattrs)

    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in n.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in _HTTP_DECORATORS:
                    subpath = ""
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        subpath = dec.args[0].value
                    fn_calls: set[str] = set()
                    for sub in ast.walk(n):
                        if isinstance(sub, ast.Call):
                            s = sub.func.id if isinstance(sub.func, ast.Name) else sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
                            if s:
                                fn_calls.add(resolve(s))
                    handlers.append(
                        ParsedRouteHandler(
                            func_name=n.name,
                            http_method=dec.func.attr.upper(),
                            subpath=subpath,
                            lineno=n.lineno,
                            called_symbols=frozenset(fn_calls),
                        )
                    )

    active_policy_tokens = get_active_policy_tokens()
    policy_literals: list[tuple[str, int, str]] = []
    for stmt in tree.body:
        target_name: str | None = None
        val: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target_name, val = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            target_name, val = stmt.target.id, stmt.value
        if not target_name or val is None or not target_name.isupper() or target_name.startswith("_"):
            continue
        if isinstance(val, ast.Constant) and isinstance(val.value, (int, float)) and not isinstance(val.value, bool):
            if name_has_policy_token(target_name, active_policy_tokens):
                policy_literals.append((target_name, stmt.lineno, repr(val.value)))
        elif isinstance(val, (ast.Dict, ast.Set, ast.List, ast.Tuple)):
            size = len(val.keys) if isinstance(val, ast.Dict) else len(val.elts)
            if size >= 3 and name_has_policy_token(target_name, _POLICY_COLLECTION_TOKENS):
                policy_literals.append((target_name, stmt.lineno, f"collection[{size}]"))

    is_package = rel_path.endswith("__init__.py")
    package_exports = _package_exports(tree, [b[:2] for b in bindings], excluded, local_pkg) if is_package else ()

    doc = (ast.get_docstring(tree) or "").strip().splitlines()
    summary = doc[0].strip() if doc else f"Python module `{module_name}`."
    return ParsedPythonModule(
        rel_path=rel_path,
        module_name=module_name,
        summary=summary,
        reads=frozenset(reads),
        writes=frozenset(writes),
        called=frozenset(called),
        defined=frozenset(defined),
        sql_reads=frozenset(sql_reads),
        sql_writes=frozenset(sql_writes),
        sql_calls=frozenset(sql_calls),
        imported_modules=frozenset(imported_modules),
        router_prefix=router_prefix,
        router_includes=tuple(router_includes),
        nested_router_includes=tuple(nested_router_includes),
        route_handlers=tuple(handlers),
        policy_literals=tuple(policy_literals),
        raw_clock_calls=tuple(raw_clocks),
        method_calls=frozenset(method_calls),
        param_method_calls=tuple(sorted(param_method_calls, key=lambda x: (x[0], tuple(sorted(x[1]))))),
        class_attrs=class_attrs,
        class_bases=class_bases,
        top_level_defs=frozenset(top_level_defs),
        method_defs=frozenset(method_defs),
        package_exports=package_exports,
        symbol_calls=frozenset(symbol_calls),
        constructed=frozenset(constructed),
        persisted=frozenset(persisted),
        has_session_writes=has_session_writes,
        imported_names={k: frozenset(v) for k, v in imported_names.items()},
        write_lines=write_lines,
    )


def _package_exports(
    tree: ast.Module, bindings: list[tuple[str, str]], excluded: set[int], local_pkg: str
) -> tuple[tuple[str, str, frozenset[str]], ...]:
    """What a package `__init__` exports: its `from ... import` bindings, plus PEP 562 lazy tables.

    A lazy table is a module-level dict such as `{"Name": "pkg.mod"}` or `{"Name": ("pkg.mod", "attr")}`
    in an `__init__` that defines `__getattr__`. Each binding carries which of the initializer's own
    top-level definitions use it, so a caller is credited only with what the name it imports needs.
    """
    users: dict[str, set[str]] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        owner = stmt.name if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else "*"
        for n in ast.walk(stmt):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and id(n) not in excluded:
                users.setdefault(n.id, set()).add(owner)
    out = [(local, target, frozenset(users.get(local, ()))) for local, target in bindings]
    if not any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name == "__getattr__" for s in tree.body):
        return tuple(out)
    for stmt in tree.body:
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        if not isinstance(value, ast.Dict):
            continue
        for key, val in zip(value.keys, value.values):
            attr = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None
            if attr is None:
                continue
            if isinstance(val, ast.Tuple) and len(val.elts) == 2 and all(isinstance(e, ast.Constant) for e in val.elts):
                mod, attr = val.elts[0].value, val.elts[1].value
            else:
                mod = val.value if isinstance(val, ast.Constant) else None
            if isinstance(mod, str) and isinstance(attr, str) and mod.startswith(f"{local_pkg}."):
                out.append((key.value, f"{mod}.{attr}", frozenset()))
    return tuple(out)
