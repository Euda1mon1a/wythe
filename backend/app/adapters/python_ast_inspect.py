"""Syntax-tree analyzer for Python manipulation modules (ORM, SQL, FastAPI, and hygiene)."""

from __future__ import annotations

import ast
import builtins
import re
from dataclasses import dataclass

from app.core.policy_context import get_active_policy_tokens

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
    router_includes: tuple[tuple[str, str], ...]  # (module_attr, prefix)
    route_handlers: tuple[ParsedRouteHandler, ...]
    policy_literals: tuple[tuple[str, int, str], ...]  # (const_name, lineno, sample)
    raw_clock_calls: tuple[tuple[str, int], ...]  # (expr, lineno)
    method_calls: frozenset[str] = frozenset()  # `param.method()` on an injected, unannotated parameter
    top_level_defs: frozenset[str] = frozenset()
    method_defs: frozenset[str] = frozenset()
    # Package `__init__` only: (exported name, absolute "module.name" source, the initializer's own top-level
    # definitions that use it; "*" = module-level code, which runs on import)
    package_exports: tuple[tuple[str, str, frozenset[str]], ...] = ()
    symbol_calls: frozenset[str] = frozenset()


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


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


def _absolute_import_bindings(tree: ast.AST, module_name: str, rel_path: str) -> list[tuple[str, str, int]]:
    """(local name, absolute "module.name", level) for every `from ... import`, relative ones resolved.

    A package `__init__` is its own package; any other module resolves against its parent.
    """
    own_pkg = module_name.removesuffix(".__init__")
    if not rel_path.endswith("__init__.py"):
        own_pkg = own_pkg.rpartition(".")[0]
    out: list[tuple[str, str, int]] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.ImportFrom):
            continue
        src_mod = n.module or ""
        if n.level:
            base = own_pkg
            for _ in range(n.level - 1):
                base = base.rpartition(".")[0]
            src_mod = ".".join(p for p in (base, n.module) if p)
        if src_mod:
            out.extend((alias.asname or alias.name, f"{src_mod}.{alias.name}", n.level) for alias in n.names)
    return out


def _injected_params_by_call(tree: ast.AST) -> dict[int, frozenset[str]]:
    """Map each call to the unannotated parameters (bar `self`/`cls`) of the functions enclosing it."""
    out: dict[int, frozenset[str]] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = fn.args
            names = frozenset(
                p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs) if p.annotation is None and p.arg not in ("self", "cls")
            )
            if names:
                for sub in ast.walk(fn):
                    if isinstance(sub, ast.Call):
                        out[id(sub)] = out.get(id(sub), frozenset()) | names
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
    imported_modules: set[str] = set()
    external_roots: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            imported_modules.add(n.module)
            is_ext = n.level == 0 and n.module.split(".", 1)[0] != local_pkg
            for alias in n.names:
                imported_modules.add(f"{n.module}.{alias.name}")
                local_name = alias.asname or alias.name
                aliases[local_name] = alias.name
                if is_ext:
                    external_roots.add(local_name)
        elif isinstance(n, ast.Import):
            for alias in n.names:
                imported_modules.add(alias.name)
                if alias.asname:
                    aliases[alias.asname] = alias.name
                if alias.name.split(".", 1)[0] != local_pkg:
                    external_roots.add(alias.asname or alias.name.split(".", 1)[0])
    # Relative imports (`from .x import y`, `from . import x`) by their absolute module path.
    bindings = _absolute_import_bindings(tree, module_name, rel_path)
    for local_name, target, level in bindings:
        if level:
            imported_modules.update((target.rpartition(".")[0], target))
            aliases[local_name] = target.rpartition(".")[2]

    def resolve(sym: str) -> str:
        return aliases.get(sym, sym)

    writes: set[str] = set()
    called: set[str] = set()
    symbol_calls: set[str] = set()
    method_calls: set[str] = set()
    injected_params = _injected_params_by_call(tree)
    write_only: set[int] = set()
    raw_clocks: list[tuple[str, int]] = []
    router_prefix = ""
    router_includes: list[tuple[str, str]] = []

    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            fn = _dotted(stmt.value.func) or ""
            if fn.endswith("APIRouter"):
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
            if inc_target:
                router_includes.append((resolve(inc_target.split(".")[0]), inc_prefix))

        if dotted in ("date.today", "datetime.date.today", "datetime.utcnow", "datetime.datetime.utcnow") or dotted in ("datetime.now", "datetime.datetime.now") and not n.args and not n.keywords:
            raw_clocks.append((f"{dotted}()", n.lineno))

        if short:
            resolved_short = resolve(short)
            called.add(resolved_short)
            if isinstance(target, ast.Name):
                # Imported names resolve through their import edge; builtins never cross modules.
                if target.id not in external_roots and target.id not in aliases and target.id not in _BUILTIN_NAMES:
                    symbol_calls.add(resolved_short)
            elif isinstance(target, ast.Attribute):
                # Only an injected, unannotated parameter hides its class from the imports. Any
                # other receiver resolves through an import edge or is a library object
                # (`logger.error()`, `session.query()`), so a name match there is a coincidence.
                recv = target.value
                if isinstance(recv, ast.Name) and recv.id in injected_params.get(id(n), ()) and short not in _GENERIC_ATTR_METHODS:
                    method_calls.add(short)
            if dotted:
                head, _, tail = dotted.partition(".")
                called.add(f"{resolve(head)}.{tail}" if tail else resolve(head))
            writes.add(resolved_short)
            write_only.add(id(target))

        is_construct = isinstance(target, ast.Name) and short in _CONSTRUCT_WRITES
        is_sess = isinstance(target, ast.Attribute) and short in _SESSION_WRITES and _is_session_receiver(target.value)
        if is_construct or is_sess:
            for sub in [*n.args, *(kw.value for kw in n.keywords)]:
                for child in ast.walk(sub):
                    if isinstance(child, ast.Name):
                        writes.add(resolve(child.id))
                    elif isinstance(child, ast.Attribute):
                        writes.add(child.attr)
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

    handlers: list[ParsedRouteHandler] = []
    defined: set[str] = set()
    top_level_defs: set[str] = set()
    method_defs: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(stmt.name)
            top_level_defs.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef):
            defined.add(stmt.name)
            top_level_defs.add(stmt.name)
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and not member.name.startswith("_"):
                    defined.add(member.name)
                    method_defs.add(member.name)

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
            if any(tok in target_name for tok in active_policy_tokens):
                policy_literals.append((target_name, stmt.lineno, repr(val.value)))
        elif isinstance(val, (ast.Dict, ast.Set, ast.List, ast.Tuple)):
            size = len(val.keys) if isinstance(val, ast.Dict) else len(val.elts)
            if size >= 3 and any(tok in target_name for tok in _POLICY_COLLECTION_TOKENS):
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
        route_handlers=tuple(handlers),
        policy_literals=tuple(policy_literals),
        raw_clock_calls=tuple(raw_clocks),
        method_calls=frozenset(method_calls),
        top_level_defs=frozenset(top_level_defs),
        method_defs=frozenset(method_defs),
        package_exports=package_exports,
        symbol_calls=frozenset(symbol_calls),
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
