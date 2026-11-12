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


_OBJECT_ATTRS = frozenset(dir(object)) | frozenset(
    {"__dict__", "__weakref__", "__module__", "__annotations__", "__name__", "__qualname__"}
)


def _merge_stored(branches: list[tuple[bool, frozenset[str]]]) -> frozenset[str]:
    live_sets = [st for lv, st in branches if lv]
    if not live_sets:
        return frozenset()
    acc = set(live_sets[0])
    for st in live_sets[1:]:
        acc &= st
    return frozenset(acc)


def _hasattr_guarded(
    test: ast.AST | None, nm: str, defs: DefsMap
) -> tuple[frozenset[str], frozenset[str]]:
    if test is None or "hasattr" in defs:
        return frozenset(), frozenset()
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Name)
        and test.func.id == "hasattr"
        and len(test.args) == 2
        and not test.keywords
        and isinstance(test.args[0], ast.Name)
        and test.args[0].id == nm
        and isinstance(test.args[1], ast.Constant)
        and isinstance(test.args[1].value, str)
    ):
        return frozenset({test.args[1].value}), frozenset()
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        wt, wf = _hasattr_guarded(test.operand, nm, defs)
        return wf, wt
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        wt_all: set[str] = set()
        for v in test.values:
            wt_v, _ = _hasattr_guarded(v, nm, defs)
            wt_all.update(wt_v)
        return frozenset(wt_all), frozenset()
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or) and test.values:
        wf_all: set[str] = set()
        wt_common: set[str] | None = None
        for v in test.values:
            wt_v, wf_v = _hasattr_guarded(v, nm, defs)
            wf_all.update(wf_v)
            wt_common = set(wt_v) if wt_common is None else (wt_common & set(wt_v))
        return frozenset(wt_common or ()), frozenset(wf_all)
    return frozenset(), frozenset()


StateTriple = tuple[bool, DefsMap, frozenset[str]]


def _live_param_expr_nodes(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    nm: str,
    excluded: set[int] | None = None,
) -> tuple[dict[int, str], frozenset[str]]:
    """Return `(live_method_calls, required_attrs)` for `fn`'s initial parameter `nm`."""
    skip = excluded or set()
    live_calls: dict[int, str] = {}
    required_attrs: set[str] = set()
    activated_states: dict[
        tuple[int, frozenset[tuple[str, frozenset[int]]], frozenset[str], frozenset[str]],
        frozenset[str],
    ] = {}
    active_fn_stack: set[int] = set()

    def run_scope(
        body: list[ast.stmt] | ast.expr,
        outer_defs: DefsMap | None = None,
        init_stored: frozenset[str] = frozenset(),
        init_guarded: frozenset[str] = frozenset(),
    ) -> frozenset[str]:
        init_defs: DefsMap = _copy_defs(outer_defs or {})
        dead_refs: set[int] = set()

        def activate_defs(
            name: str,
            cur_defs: DefsMap,
            cur_stored: frozenset[str],
            cur_guarded: frozenset[str],
        ) -> frozenset[str] | None:
            fn_list = list(cur_defs.get(name, ()))
            exit_sets: list[frozenset[str]] = []
            for fn_def in fn_list:
                if id(fn_def) in active_fn_stack:
                    continue
                fn_locals = _fn_local_names(fn_def)
                if nm in fn_locals:
                    exit_sets.append(cur_stored)
                    continue
                scoped_defs = {k: set(v) for k, v in cur_defs.items() if k not in fn_locals and v}
                sig = frozenset((k, frozenset(id(x) for x in v)) for k, v in scoped_defs.items())
                state_key = (id(fn_def), sig, cur_stored, cur_guarded)
                if state_key in activated_states:
                    exit_sets.append(activated_states[state_key])
                    continue
                activated_states[state_key] = cur_stored
                active_fn_stack.add(id(fn_def))
                try:
                    res_st = run_scope(fn_def.body, scoped_defs, cur_stored, cur_guarded)
                finally:
                    active_fn_stack.discard(id(fn_def))
                activated_states[state_key] = res_st
                exit_sets.append(res_st)
            if not exit_sets:
                return None
            acc = set(exit_sets[0])
            for st in exit_sets[1:]:
                acc &= st
            return frozenset(acc)

        def walk_target(
            tgt: ast.AST,
            live: bool,
            defs: DefsMap,
            stored: frozenset[str],
            guarded: frozenset[str],
            *,
            is_delete: bool = False,
        ) -> StateTriple:
            if isinstance(tgt, ast.Name):
                defs.pop(tgt.id, None)
                if tgt.id == nm:
                    return False, defs, frozenset()
                return live, defs, stored
            if isinstance(tgt, (ast.Tuple, ast.List)):
                for elt in tgt.elts:
                    live, defs, stored = walk_target(elt, live, defs, stored, guarded, is_delete=is_delete)
                return live, defs, stored
            if isinstance(tgt, ast.Starred):
                return walk_target(tgt.value, live, defs, stored, guarded, is_delete=is_delete)
            if isinstance(tgt, ast.Attribute):
                is_direct = isinstance(tgt.value, ast.Name) and tgt.value.id == nm
                live, defs, stored = walk_expr(tgt.value, live, defs, stored, guarded)
                if live and is_direct:
                    stored = (stored - {tgt.attr}) if is_delete else (stored | {tgt.attr})
                return live, defs, stored
            if isinstance(tgt, ast.Subscript):
                live, defs, stored = walk_expr(tgt.value, live, defs, stored, guarded)
                return walk_expr(tgt.slice, live, defs, stored, guarded)
            return live, defs, stored

        def walk_expr(
            expr: ast.AST | None,
            live: bool,
            defs: DefsMap,
            stored: frozenset[str],
            guarded: frozenset[str],
        ) -> StateTriple:
            if expr is None or id(expr) in skip:
                return live, defs, stored
            if isinstance(expr, ast.NamedExpr):
                rhs_defs = set(defs.get(expr.value.id, ())) if isinstance(expr.value, ast.Name) else set()
                live, defs, stored = walk_expr(expr.value, live, defs, stored, guarded)
                live, defs, stored = walk_target(expr.target, live, defs, stored, guarded)
                if rhs_defs and isinstance(expr.target, ast.Name) and expr.target.id != nm:
                    defs[expr.target.id] = rhs_defs
                return live, defs, stored
            if isinstance(expr, ast.Lambda):
                for dflt in (*expr.args.defaults, *(d for d in expr.args.kw_defaults if d is not None)):
                    live, defs, stored = walk_expr(dflt, live, defs, stored, guarded)
                lam_bound = _arg_names(expr.args) | {
                    sub.target.id
                    for sub in _expr_nodes_shallow(expr.body, skip)
                    if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name)
                }
                if live and nm not in lam_bound:
                    lam_defs = {k: set(v) for k, v in defs.items() if k not in lam_bound and v}
                    run_scope(expr.body, lam_defs, stored, guarded)
                return live, defs, stored
            if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                if expr.generators:
                    live, defs, stored = walk_expr(expr.generators[0].iter, live, defs, stored, guarded)
                cbound = _comp_bound_names(expr)
                eager_nonempty = (
                    not isinstance(expr, ast.GeneratorExp)
                    and bool(expr.generators)
                    and _is_nonempty_iter_literal(expr.generators[0].iter)
                )
                if live and nm not in cbound:
                    clive = live
                    cdefs = {k: set(v) for k, v in defs.items() if k not in cbound and v}
                    cstored = stored
                    must_live = live
                    must_defs: DefsMap | None = None
                    must_stored: frozenset[str] | None = None
                    if expr.generators:
                        for idx_if, ifs_e in enumerate(expr.generators[0].ifs):
                            clive, cdefs, cstored = walk_expr(ifs_e, clive, cdefs, cstored, guarded)
                            if eager_nonempty and idx_if == 0:
                                must_live = clive
                                must_defs = _copy_defs(cdefs)
                                must_stored = cstored
                        for gen in expr.generators[1:]:
                            clive, cdefs, cstored = walk_expr(gen.iter, clive, cdefs, cstored, guarded)
                            for ifs_e in gen.ifs:
                                clive, cdefs, cstored = walk_expr(ifs_e, clive, cdefs, cstored, guarded)
                    if isinstance(expr, ast.DictComp):
                        clive, cdefs, cstored = walk_expr(expr.key, clive, cdefs, cstored, guarded)
                        clive, cdefs, cstored = walk_expr(expr.value, clive, cdefs, cstored, guarded)
                    else:
                        clive, cdefs, cstored = walk_expr(expr.elt, clive, cdefs, cstored, guarded)
                    if eager_nonempty and len(expr.generators) == 1 and not expr.generators[0].ifs:
                        must_live = clive
                        must_defs = _copy_defs(cdefs)
                        must_stored = cstored
                    kept_cbound = {k: set(v) for k, v in defs.items() if k in cbound and v}
                    if must_defs is not None and must_stored is not None:
                        live = must_live
                        defs = _merge_defs(kept_cbound, must_defs, cdefs)
                        stored = _merge_stored([(must_live, must_stored), (clive, cstored)])
                    else:
                        defs = _merge_defs(defs, cdefs)
                        stored = _merge_stored([(live, stored), (clive, cstored)])
                return live, defs, stored
            if isinstance(expr, ast.IfExp):
                lt, dt, st = walk_expr(expr.test, live, defs, stored, guarded)
                wt, wf = _hasattr_guarded(expr.test, nm, dt)
                lb, db, sb = walk_expr(expr.body, lt, _copy_defs(dt), st, guarded | wt)
                le, de, se = walk_expr(expr.orelse, lt, _copy_defs(dt), st, guarded | wf)
                return (lb or le), _merge_defs(db, de), _merge_stored([(lb, sb), (le, se)])
            if isinstance(expr, ast.BoolOp):
                cur_l, cur_d, cur_s = walk_expr(expr.values[0], live, defs, stored, guarded)
                wt0, wf0 = _hasattr_guarded(expr.values[0], nm, cur_d)
                cur_g = guarded | (wt0 if isinstance(expr.op, ast.And) else wf0)
                any_sc = cur_l
                snaps = [_copy_defs(cur_d)]
                st_branches: list[tuple[bool, frozenset[str]]] = [(cur_l, cur_s)]
                for val in expr.values[1:]:
                    cur_l, cur_d, cur_s = walk_expr(val, cur_l, _copy_defs(cur_d), cur_s, cur_g)
                    wt_v, wf_v = _hasattr_guarded(val, nm, cur_d)
                    cur_g = cur_g | (wt_v if isinstance(expr.op, ast.And) else wf_v)
                    any_sc = any_sc or cur_l
                    snaps.append(_copy_defs(cur_d))
                    st_branches.append((cur_l, cur_s))
                return any_sc, _merge_defs(*snaps), _merge_stored(st_branches)
            if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
                if live:
                    if expr.id in defs:
                        activate_defs(expr.id, defs, stored, guarded)
                elif expr.id in defs:
                    for fn_node in defs[expr.id]:
                        dead_refs.add(id(fn_node))
                return live, defs, stored
            if isinstance(expr, ast.Attribute) and isinstance(expr.ctx, ast.Load):
                if (
                    live
                    and isinstance(expr.value, ast.Name)
                    and expr.value.id == nm
                    and expr.attr not in stored
                    and expr.attr not in guarded
                    and expr.attr not in _OBJECT_ATTRS
                ):
                    required_attrs.add(expr.attr)
                return walk_expr(expr.value, live, defs, stored, guarded)
            if isinstance(expr, ast.Call):
                if (
                    live
                    and isinstance(expr.func, ast.Attribute)
                    and isinstance(expr.func.value, ast.Name)
                    and expr.func.value.id == nm
                    and expr.func.attr not in stored
                ):
                    live_calls[id(expr)] = expr.func.attr
                is_direct_helper_call = isinstance(expr.func, ast.Name) and expr.func.id in defs
                helper_name = expr.func.id if isinstance(expr.func, ast.Name) else ""
                live, defs, stored = walk_expr(expr.func, live, defs, stored, guarded)
                for arg_e in expr.args:
                    live, defs, stored = walk_expr(arg_e, live, defs, stored, guarded)
                for kw in expr.keywords:
                    live, defs, stored = walk_expr(kw.value, live, defs, stored, guarded)
                if live and is_direct_helper_call and helper_name in defs:
                    post_st = activate_defs(helper_name, defs, stored, guarded)
                    if post_st is not None:
                        stored = post_st
                if (
                    live
                    and isinstance(expr.func, ast.Name)
                    and expr.func.id == "setattr"
                    and "setattr" not in defs
                    and len(expr.args) == 3
                    and not expr.keywords
                    and isinstance(expr.args[0], ast.Name)
                    and expr.args[0].id == nm
                    and isinstance(expr.args[1], ast.Constant)
                    and isinstance(expr.args[1].value, str)
                ):
                    stored = stored | {expr.args[1].value}
                if (
                    live
                    and isinstance(expr.func, ast.Name)
                    and expr.func.id == "delattr"
                    and "delattr" not in defs
                    and len(expr.args) == 2
                    and not expr.keywords
                    and isinstance(expr.args[0], ast.Name)
                    and expr.args[0].id == nm
                    and isinstance(expr.args[1], ast.Constant)
                    and isinstance(expr.args[1].value, str)
                ):
                    stored = stored - {expr.args[1].value}
                return live, defs, stored
            if isinstance(expr, ast.Dict):
                for k_e, v_e in zip(expr.keys, expr.values, strict=False):
                    live, defs, stored = walk_expr(k_e, live, defs, stored, guarded)
                    live, defs, stored = walk_expr(v_e, live, defs, stored, guarded)
                return live, defs, stored
            for ch in ast.iter_child_nodes(expr):
                if isinstance(ch, ast.expr):
                    live, defs, stored = walk_expr(ch, live, defs, stored, guarded)
            return live, defs, stored

        def walk_stmts(
            stmts: list[ast.stmt],
            live: bool,
            defs: DefsMap,
            stored: frozenset[str],
            guarded: frozenset[str],
            loop_breaks: list[StateTriple] | None = None,
            loop_continues: list[StateTriple] | None = None,
            abrupt_returns: list[StateTriple] | None = None,
            abrupt_raises: list[StateTriple] | None = None,
        ) -> tuple[bool, DefsMap, frozenset[str], bool]:
            for s in stmts:
                if id(s) in skip:
                    continue
                if isinstance(s, ast.Return):
                    live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                    if abrupt_returns is not None:
                        abrupt_returns.append((live, _copy_defs(defs), stored))
                    return live, defs, stored, False
                if isinstance(s, ast.Raise):
                    live, defs, stored = walk_expr(s.exc, live, defs, stored, guarded)
                    live, defs, stored = walk_expr(s.cause, live, defs, stored, guarded)
                    if abrupt_raises is not None:
                        abrupt_raises.append((live, _copy_defs(defs), stored))
                    return live, defs, stored, False
                if isinstance(s, ast.Break):
                    if loop_breaks is not None:
                        loop_breaks.append((live, _copy_defs(defs), stored))
                    return live, defs, stored, False
                if isinstance(s, ast.Continue):
                    if loop_continues is not None:
                        loop_continues.append((live, _copy_defs(defs), stored))
                    return live, defs, stored, False
                if isinstance(s, ast.Assign):
                    rhs_defs = set(defs.get(s.value.id, ())) if isinstance(s.value, ast.Name) else set()
                    live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                    for tgt in s.targets:
                        live, defs, stored = walk_target(tgt, live, defs, stored, guarded)
                    if rhs_defs and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and s.targets[0].id != nm:
                        defs[s.targets[0].id] = rhs_defs
                elif isinstance(s, ast.AnnAssign):
                    if s.value is not None:
                        rhs_defs = set(defs.get(s.value.id, ())) if isinstance(s.value, ast.Name) else set()
                        live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                        live, defs, stored = walk_target(s.target, live, defs, stored, guarded)
                        if rhs_defs and isinstance(s.target, ast.Name) and s.target.id != nm:
                            defs[s.target.id] = rhs_defs
                elif isinstance(s, ast.AugAssign):
                    if isinstance(s.target, ast.Name):
                        live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                        live, defs, stored = walk_target(s.target, live, defs, stored, guarded)
                    elif (
                        isinstance(s.target, ast.Attribute)
                        and isinstance(s.target.value, ast.Name)
                        and s.target.value.id == nm
                    ):
                        if (
                            live
                            and s.target.attr not in stored
                            and s.target.attr not in guarded
                            and s.target.attr not in _OBJECT_ATTRS
                        ):
                            required_attrs.add(s.target.attr)
                        live, defs, stored = walk_expr(s.target.value, live, defs, stored, guarded)
                        live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                        if live:
                            stored = stored | {s.target.attr}
                    else:
                        live, defs, stored = walk_target(s.target, live, defs, stored, guarded)
                        live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                elif isinstance(s, ast.Delete):
                    for tgt in s.targets:
                        live, defs, stored = walk_target(tgt, live, defs, stored, guarded, is_delete=True)
                elif isinstance(s, ast.Expr):
                    live, defs, stored = walk_expr(s.value, live, defs, stored, guarded)
                elif isinstance(s, ast.Assert):
                    live, defs, stored = walk_expr(s.test, live, defs, stored, guarded)
                    wt_a, _ = _hasattr_guarded(s.test, nm, defs)
                    live, defs, stored = walk_expr(s.msg, live, defs, stored, guarded)
                    guarded = guarded | wt_a
                elif isinstance(s, (ast.Import, ast.ImportFrom)):
                    for alias in s.names:
                        if alias.name != "*":
                            bound_nm = (alias.asname or alias.name).split(".", 1)[0]
                            defs.pop(bound_nm, None)
                            if bound_nm == nm:
                                live = False
                                stored = frozenset()
                elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in s.decorator_list:
                        live, defs, stored = walk_expr(dec, live, defs, stored, guarded)
                    for dflt in (*s.args.defaults, *(d for d in s.args.kw_defaults if d is not None)):
                        live, defs, stored = walk_expr(dflt, live, defs, stored, guarded)
                    if s.decorator_list:
                        defs.pop(s.name, None)
                        s_locals = _fn_local_names(s)
                        if live and nm not in s_locals:
                            run_scope(
                                s.body,
                                {k: set(v) for k, v in defs.items() if k not in s_locals and v},
                                stored,
                                guarded,
                            )
                    else:
                        defs[s.name] = {s}
                    if s.name == nm:
                        defs.pop(nm, None)
                        live = False
                        stored = frozenset()
                elif isinstance(s, ast.ClassDef):
                    for dec in s.decorator_list:
                        live, defs, stored = walk_expr(dec, live, defs, stored, guarded)
                    defs.pop(s.name, None)
                    if s.name == nm:
                        live = False
                        stored = frozenset()
                elif isinstance(s, ast.TypeAlias):
                    if isinstance(s.name, ast.Name):
                        defs.pop(s.name.id, None)
                        if s.name.id == nm:
                            live = False
                            stored = frozenset()
                elif isinstance(s, ast.If):
                    live, defs, stored = walk_expr(s.test, live, defs, stored, guarded)
                    wt_i, wf_i = _hasattr_guarded(s.test, nm, defs)
                    lb, db, sb, fb = walk_stmts(
                        s.body,
                        live,
                        _copy_defs(defs),
                        stored,
                        guarded | wt_i,
                        loop_breaks,
                        loop_continues,
                        abrupt_returns,
                        abrupt_raises,
                    )
                    le, de, se, fe = walk_stmts(
                        s.orelse,
                        live,
                        _copy_defs(defs),
                        stored,
                        guarded | wf_i,
                        loop_breaks,
                        loop_continues,
                        abrupt_returns,
                        abrupt_raises,
                    )
                    if not fb and not fe:
                        return (lb or le), _merge_defs(db, de), _merge_stored([(lb, sb), (le, se)]), False
                    live = (lb if fb else False) or (le if fe else False)
                    defs = _merge_defs(*(([db] if fb else []) + ([de] if fe else [])))
                    stored = _merge_stored(([(lb, sb)] if fb else []) + ([(le, se)] if fe else []))
                elif isinstance(s, (ast.For, ast.AsyncFor)):
                    live, defs, stored = walk_expr(s.iter, live, defs, stored, guarded)
                    nonempty_iter = _is_nonempty_iter_literal(s.iter)
                    body_in, body_defs, body_st = walk_target(s.target, live, _copy_defs(defs), stored, guarded)
                    brk: list[StateTriple] = []
                    cnt: list[StateTriple] = []
                    lb, db, sb, fb = walk_stmts(
                        s.body, body_in, body_defs, body_st, guarded, brk, cnt, abrupt_returns, abrupt_raises
                    )
                    iter_branches = ([(lb, sb)] if fb else []) + [(cl, cs) for cl, _, cs in cnt]
                    iter_end_l = any(bl for bl, _ in iter_branches)
                    iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd, _ in cnt]))
                    iter_end_s = _merge_stored(iter_branches)
                    if fb or cnt:
                        body2_in, body2_defs, body2_st = walk_target(
                            s.target, iter_end_l, _copy_defs(iter_end_d), iter_end_s, guarded
                        )
                        merged_body_defs = _merge_defs(body_defs, body2_defs)
                        merged_body_st = _merge_stored([(body_in, body_st), (body2_in, body2_st)])
                        if merged_body_defs != body_defs or merged_body_st != body_st:
                            brk = []
                            cnt = []
                            lb, db, sb, fb = walk_stmts(
                                s.body,
                                body_in or body2_in,
                                merged_body_defs,
                                merged_body_st,
                                guarded,
                                brk,
                                cnt,
                                abrupt_returns,
                                abrupt_raises,
                            )
                            iter_branches = ([(lb, sb)] if fb else []) + [(cl, cs) for cl, _, cs in cnt]
                            iter_end_l = any(bl for bl, _ in iter_branches)
                            iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd, _ in cnt]))
                            iter_end_s = _merge_stored(iter_branches)
                    zero_iter = False if nonempty_iter else live
                    if nonempty_iter and not fb and not cnt:
                        le, de, se, fe = False, {}, frozenset(), False
                    else:
                        else_in_l = zero_iter or iter_end_l
                        else_in_d = (
                            iter_end_d
                            if nonempty_iter
                            else (_merge_defs(defs, iter_end_d) if (fb or cnt) else _copy_defs(defs))
                        )
                        else_in_s = (
                            iter_end_s
                            if nonempty_iter
                            else (
                                _merge_stored([(live, stored), (iter_end_l, iter_end_s)])
                                if (fb or cnt)
                                else stored
                            )
                        )
                        le, de, se, fe = walk_stmts(
                            s.orelse,
                            else_in_l,
                            else_in_d,
                            else_in_s,
                            guarded,
                            loop_breaks,
                            loop_continues,
                            abrupt_returns,
                            abrupt_raises,
                        )
                    if not fe and not brk:
                        return le, de, se, False
                    live = (le if fe else False) or any(bl for bl, _, _ in brk)
                    defs = _merge_defs(*(([de] if fe else []) + [bd for _, bd, _ in brk]))
                    stored = _merge_stored(([(le, se)] if fe else []) + [(bl, bs) for bl, _, bs in brk])
                elif isinstance(s, ast.While):
                    w_entry_l, w_entry_d, w_entry_s = live, _copy_defs(defs), stored
                    live, defs, stored = walk_expr(s.test, w_entry_l, _copy_defs(w_entry_d), w_entry_s, guarded)
                    wt_w, wf_w = _hasattr_guarded(s.test, nm, defs)
                    always_true = isinstance(s.test, ast.Constant) and bool(s.test.value) is True
                    brk = []
                    cnt = []
                    lb, db, sb, fb = walk_stmts(
                        s.body, live, _copy_defs(defs), stored, guarded | wt_w, brk, cnt, abrupt_returns, abrupt_raises
                    )
                    iter_branches = ([(lb, sb)] if fb else []) + [(cl, cs) for cl, _, cs in cnt]
                    iter_end_l = any(bl for bl, _ in iter_branches)
                    iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd, _ in cnt]))
                    iter_end_s = _merge_stored(iter_branches)
                    if fb or cnt:
                        merged_w_d = _merge_defs(w_entry_d, iter_end_d)
                        merged_w_s = _merge_stored([(w_entry_l, w_entry_s), (iter_end_l, iter_end_s)])
                        if merged_w_d != w_entry_d or merged_w_s != w_entry_s:
                            brk = []
                            cnt = []
                            live2, defs2, stored2 = walk_expr(
                                s.test, w_entry_l or iter_end_l, _copy_defs(merged_w_d), merged_w_s, guarded
                            )
                            lb, db, sb, fb = walk_stmts(
                                s.body,
                                live2,
                                _copy_defs(defs2),
                                stored2,
                                guarded | wt_w,
                                brk,
                                cnt,
                                abrupt_returns,
                                abrupt_raises,
                            )
                            live, defs, stored = live2, defs2, stored2
                            iter_branches = ([(lb, sb)] if fb else []) + [(cl, cs) for cl, _, cs in cnt]
                            iter_end_l = any(bl for bl, _ in iter_branches)
                            iter_end_d = _merge_defs(*(([db] if fb else []) + [cd for _, cd, _ in cnt]))
                            iter_end_s = _merge_stored(iter_branches)
                    zero_iter = False if always_true else live
                    if not zero_iter and not fb and not cnt:
                        le, de, se, fe = False, {}, frozenset(), False
                    else:
                        else_in_d = iter_end_d if always_true else _merge_defs(defs, iter_end_d)
                        else_in_s = (
                            iter_end_s
                            if always_true
                            else _merge_stored([(live, stored), (iter_end_l, iter_end_s)])
                        )
                        le, de, se, fe = walk_stmts(
                            s.orelse,
                            zero_iter or iter_end_l,
                            else_in_d,
                            else_in_s,
                            guarded | wf_w,
                            loop_breaks,
                            loop_continues,
                            abrupt_returns,
                            abrupt_raises,
                        )
                    if not fe and not brk:
                        return le, de, se, False
                    live = (le if fe else False) or any(bl for bl, _, _ in brk)
                    defs = _merge_defs(*(([de] if fe else []) + [bd for _, bd, _ in brk]))
                    stored = _merge_stored(([(le, se)] if fe else []) + [(bl, bs) for bl, _, bs in brk])
                elif isinstance(s, (ast.With, ast.AsyncWith)):
                    for item in s.items:
                        live, defs, stored = walk_expr(item.context_expr, live, defs, stored, guarded)
                        if item.optional_vars is not None:
                            live, defs, stored = walk_target(item.optional_vars, live, defs, stored, guarded)
                    live, defs, stored, fw = walk_stmts(
                        s.body, live, defs, stored, guarded, loop_breaks, loop_continues, abrupt_returns, abrupt_raises
                    )
                    if not fw:
                        return live, defs, stored, False
                elif isinstance(s, (ast.Try, ast.TryStar)):
                    entry_live = live
                    entry_defs = _copy_defs(defs)
                    entry_stored = stored
                    body_returns: list[StateTriple] = []
                    body_raises: list[StateTriple] = []
                    post_returns: list[StateTriple] = []
                    post_raises: list[StateTriple] = []
                    try_breaks: list[StateTriple] = []
                    try_continues: list[StateTriple] = []
                    lt, dt, st_t, ft = walk_stmts(
                        s.body,
                        entry_live,
                        _copy_defs(entry_defs),
                        entry_stored,
                        guarded,
                        try_breaks,
                        try_continues,
                        body_returns,
                        body_raises,
                    )
                    le, de, se, fe = (
                        walk_stmts(
                            s.orelse,
                            lt,
                            _copy_defs(dt),
                            st_t,
                            guarded,
                            try_breaks,
                            try_continues,
                            post_returns,
                            post_raises,
                        )
                        if ft
                        else (False, {}, frozenset(), False)
                    )
                    h_branches: list[StateTriple] = [(le, de, se)] if fe else []
                    any_fall = fe
                    exc_base_defs = _merge_defs(entry_defs, dt)
                    exc_base_st = _merge_stored([(entry_live, entry_stored), (lt, st_t)])
                    for h in s.handlers:
                        if h.type is not None:
                            walk_expr(h.type, entry_live or lt, _copy_defs(exc_base_defs), exc_base_st, guarded)
                        hd = _copy_defs(exc_base_defs)
                        if h.name:
                            hd.pop(h.name, None)
                        h_in = False if h.name == nm else (entry_live or lt)
                        h_st_in = frozenset() if h.name == nm else exc_base_st
                        lh, dh, sh, fh = walk_stmts(
                            h.body,
                            h_in,
                            hd,
                            h_st_in,
                            guarded,
                            try_breaks,
                            try_continues,
                            post_returns,
                            post_raises,
                        )
                        if fh:
                            any_fall = True
                            h_branches.append((lh, dh, sh))
                    has_bare_except = isinstance(s, ast.Try) and any(h.type is None for h in s.handlers)
                    all_returns = body_returns + post_returns
                    uncaught_raises = post_raises if has_bare_except else (body_raises + post_raises)
                    fall_in_l = any(hl for hl, _, _ in h_branches) if any_fall else False
                    fall_in_d = _merge_defs(*(hd for _, hd, _ in h_branches)) if any_fall else {}
                    fall_in_s = _merge_stored([(hl, hs) for hl, _, hs in h_branches]) if any_fall else frozenset()
                    if not s.finalbody:
                        if abrupt_returns is not None:
                            abrupt_returns.extend(all_returns)
                        if abrupt_raises is not None:
                            abrupt_raises.extend(uncaught_raises)
                        if loop_breaks is not None:
                            loop_breaks.extend(try_breaks)
                        if loop_continues is not None:
                            loop_continues.extend(try_continues)
                        if not any_fall:
                            return False, {}, frozenset(), False
                        live, defs, stored = fall_in_l, fall_in_d, fall_in_s
                    else:
                        fin_states: list[StateTriple] = []
                        if any_fall:
                            fin_states.append((fall_in_l, fall_in_d, fall_in_s))
                        fin_states.extend(all_returns)
                        fin_states.extend(uncaught_raises)
                        if loop_breaks is not None:
                            fin_states.extend(try_breaks)
                        if loop_continues is not None:
                            fin_states.extend(try_continues)
                        if not fin_states:
                            fin_states.append((entry_live or lt, exc_base_defs, exc_base_st))
                        fin_union_l = any(l for l, _, _ in fin_states)
                        fin_union_d = _merge_defs(*(d for _, d, _ in fin_states))
                        fin_union_s = _merge_stored([(l, st) for l, _, st in fin_states])
                        walk_stmts(
                            s.finalbody,
                            fin_union_l,
                            _copy_defs(fin_union_d),
                            fin_union_s,
                            guarded,
                            loop_breaks,
                            loop_continues,
                            abrupt_returns,
                            abrupt_raises,
                        )

                        def eval_finalizer(
                            in_l: bool,
                            in_d: DefsMap,
                            in_s: frozenset[str],
                            cur_g: frozenset[str] = guarded,
                            final_stmts: list[ast.stmt] = s.finalbody,
                        ) -> tuple[bool, DefsMap, frozenset[str], bool]:
                            calls_snap = dict(live_calls)
                            req_snap = set(required_attrs)
                            dead_snap = set(dead_refs)
                            rl, rd, rs, rf = walk_stmts(final_stmts, in_l, _copy_defs(in_d), in_s, cur_g)
                            live_calls.clear()
                            live_calls.update(calls_snap)
                            required_attrs.clear()
                            required_attrs.update(req_snap)
                            dead_refs.clear()
                            dead_refs.update(dead_snap)
                            return rl, rd, rs, rf

                        if all_returns and abrupt_returns is not None:
                            rl, rd, rs, rf = eval_finalizer(
                                any(l for l, _, _ in all_returns),
                                _merge_defs(*(d for _, d, _ in all_returns)),
                                _merge_stored([(l, st) for l, _, st in all_returns]),
                            )
                            if rf:
                                abrupt_returns.append((rl, rd, rs))
                        if uncaught_raises and abrupt_raises is not None:
                            rl, rd, rs, rf = eval_finalizer(
                                any(l for l, _, _ in uncaught_raises),
                                _merge_defs(*(d for _, d, _ in uncaught_raises)),
                                _merge_stored([(l, st) for l, _, st in uncaught_raises]),
                            )
                            if rf:
                                abrupt_raises.append((rl, rd, rs))
                        if try_breaks and loop_breaks is not None:
                            rl, rd, rs, rf = eval_finalizer(
                                any(l for l, _, _ in try_breaks),
                                _merge_defs(*(d for _, d, _ in try_breaks)),
                                _merge_stored([(l, st) for l, _, st in try_breaks]),
                            )
                            if rf:
                                loop_breaks.append((rl, rd, rs))
                        if try_continues and loop_continues is not None:
                            rl, rd, rs, rf = eval_finalizer(
                                any(l for l, _, _ in try_continues),
                                _merge_defs(*(d for _, d, _ in try_continues)),
                                _merge_stored([(l, st) for l, _, st in try_continues]),
                            )
                            if rf:
                                loop_continues.append((rl, rd, rs))
                        if not any_fall:
                            return False, {}, frozenset(), False
                        lf, df, sf, ff = eval_finalizer(fall_in_l, fall_in_d, fall_in_s)
                        if not ff:
                            return lf, df, sf, False
                        live, defs, stored = lf, df, sf
                elif isinstance(s, ast.Match):
                    live, defs, stored = walk_expr(s.subject, live, defs, stored, guarded)
                    c_branches: list[StateTriple] = []
                    exit_branches: list[StateTriple] = []
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
                        cst = frozenset() if nm in pat_names else stored
                        if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                            has_wild = True
                        cin, cd, cst = walk_expr(case.guard, cin, cd, cst, guarded)
                        wt_m, _ = _hasattr_guarded(case.guard, nm, cd)
                        lc, dc, sc, fc = walk_stmts(
                            case.body,
                            cin,
                            cd,
                            cst,
                            guarded | wt_m,
                            loop_breaks,
                            loop_continues,
                            abrupt_returns,
                            abrupt_raises,
                        )
                        exit_branches.append((lc, dc, sc))
                        if fc:
                            any_fall = True
                            c_branches.append((lc, dc, sc))
                    if not has_wild:
                        any_fall = True
                        c_branches.append((live, _copy_defs(defs), stored))
                    if not any_fall:
                        return (
                            any(el for el, _, _ in exit_branches),
                            _merge_defs(*(ed for _, ed, _ in exit_branches)),
                            _merge_stored([(el, es) for el, _, es in exit_branches]),
                            False,
                        )
                    live = any(cl for cl, _, _ in c_branches)
                    defs = _merge_defs(*(cd_i for _, cd_i, _ in c_branches))
                    stored = _merge_stored([(cl, cs) for cl, _, cs in c_branches])
                else:
                    for ch in ast.iter_child_nodes(s):
                        if isinstance(ch, ast.expr):
                            live, defs, stored = walk_expr(ch, live, defs, stored, guarded)
                        elif isinstance(ch, ast.stmt):
                            live, defs, stored, fs = walk_stmts(
                                [ch],
                                live,
                                defs,
                                stored,
                                guarded,
                                loop_breaks,
                                loop_continues,
                                abrupt_returns,
                                abrupt_raises,
                            )
                            if not fs:
                                return live, defs, stored, False
            return live, defs, stored, True

        if isinstance(body, list):
            top_returns: list[StateTriple] = []
            end_live, end_defs, end_st, end_fall = walk_stmts(
                body, True, init_defs, init_stored, init_guarded, None, None, top_returns, None
            )
            exit_states = ([(end_live, end_defs, end_st)] if end_fall else []) + top_returns
            exit_stored = _merge_stored([(l, st) for l, _, st in exit_states])
            if any(l for l, _, _ in exit_states):
                live_exit_defs = _merge_defs(*(d for l, d, _ in exit_states if l))
                for fn_name, fn_nodes in list(live_exit_defs.items()):
                    if any(id(fn_node) not in dead_refs for fn_node in fn_nodes):
                        activate_defs(fn_name, live_exit_defs, exit_stored, init_guarded)
            return exit_stored
        _, _, expr_st = walk_expr(body, True, init_defs, init_stored, init_guarded)
        return expr_st

    run_scope(fn.body)
    return live_calls, frozenset(required_attrs)


def _injected_param_profiles(tree: ast.AST, excluded: set[int]) -> dict[int, dict[str, frozenset[str]]]:
    """Map each call `id(call)` to `{unannotated_param: frozenset(attrs required on param in that fn)}`."""
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
            live_calls, req_attrs = _live_param_expr_nodes(fn, nm, excluded)
            if not live_calls:
                continue
            for call_id, mname in live_calls.items():
                if call_id in excluded:
                    continue
                merged = dict(out.get(call_id, {}))
                merged[nm] = req_attrs if mname in _OBJECT_ATTRS else (req_attrs | {mname})
                out[call_id] = merged
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
                            and sub.value.id in ("self", "cls")
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
