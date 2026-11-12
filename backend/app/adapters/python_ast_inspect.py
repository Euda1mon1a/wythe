"""Syntax-tree analyzer for Python manipulation modules (ORM, SQL, FastAPI, and hygiene)."""

from __future__ import annotations

import ast
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
    """`query(Model)`, `select(Model)`, `session.get(Model, pk)` -> "Model" (capitalized names only)."""
    if call.args and isinstance(call.args[0], ast.Name) and call.args[0].id[:1].isupper():
        return call.args[0].id
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
    """`Model(...)` or a classmethod factory `Model.create(...)` -> "Model" (capitalized names)."""
    if isinstance(expr, ast.Await):
        expr = expr.value
    if not isinstance(expr, ast.Call):
        return None
    func = expr.func
    if isinstance(func, ast.Name) and func.id[:1].isupper():
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id[:1].isupper():
        return func.value.id
    return None


def _scope_nodes(root: ast.AST) -> list[ast.AST]:
    """Nodes of one function (or module) scope, without descending into nested defs."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(root))
    while stack:
        node = stack.pop()
        out.append(node)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))
    return out


def _loaded_row_writes(tree: ast.Module, excluded: set[int]) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Writes to rows loaded from the session, per scope.

    Returns (session_writes, mutations): `db.delete(row)` / `db.add(row)` / `db.merge(row)` on a
    loaded row, and attribute stores / `setattr(row, ...)` on a loaded row, as (model, lineno).
    """
    session_writes: list[tuple[str, int]] = []
    mutations: list[tuple[str, int]] = []
    scopes: list[ast.AST] = [tree, *(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))]
    for scope in scopes:
        nodes = [n for n in _scope_nodes(scope) if id(n) not in excluded]
        rows: dict[str, str] = {}
        made: dict[str, str] = {}  # `v = Model(...)` / `v = Model.factory(...)`: only a write once added
        for n in nodes:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                model = _loaded_row_model(n.value)
                if model:
                    rows[n.targets[0].id] = model
                maker = _constructed_model(n.value)
                if maker:
                    made[n.targets[0].id] = maker
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                model = _loaded_row_model(n.value)
                if model:
                    rows[n.target.id] = model
            elif isinstance(n, (ast.For, ast.AsyncFor)) and isinstance(n.target, ast.Name):
                model = _model_in_row_source(n.iter)
                if model:
                    rows[n.target.id] = model
        if not rows and not made:
            continue
        for n in nodes:
            if isinstance(n, ast.Call):
                name = _call_name(n)
                if (
                    isinstance(n.func, ast.Attribute)
                    and name in _SESSION_WRITES
                    and _is_session_receiver(n.func.value)
                ):
                    for arg in n.args:
                        elts = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
                        for elt in elts:
                            if isinstance(elt, ast.Name) and elt.id in rows:
                                session_writes.append((rows[elt.id], n.lineno))
                            elif isinstance(elt, ast.Name) and elt.id in made and name != "delete":
                                session_writes.append((made[elt.id], n.lineno))
                elif name == "setattr" and isinstance(n.func, ast.Name) and n.args:
                    first = n.args[0]
                    if isinstance(first, ast.Name) and first.id in rows:
                        mutations.append((rows[first.id], n.lineno))
            elif isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for tgt in targets:
                    for t in ast.walk(tgt):
                        if (
                            isinstance(t, ast.Attribute)
                            and isinstance(t.ctx, ast.Store)
                            and isinstance(t.value, ast.Name)
                            and t.value.id in rows
                        ):
                            mutations.append((rows[t.value.id], n.lineno))
    return session_writes, mutations


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
    mod_parts = module_name.split(".")
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            imported_modules.add(n.module)
            is_ext = n.level == 0 and n.module.split(".", 1)[0] != local_pkg
            abs_module = (
                ".".join([*mod_parts[: max(0, len(mod_parts) - n.level)], n.module])
                if n.level
                else n.module
            )
            for alias in n.names:
                imported_modules.add(f"{n.module}.{alias.name}")
                imported_names.setdefault(alias.name, set()).add(abs_module)
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

    def resolve(sym: str) -> str:
        return aliases.get(sym, sym)

    # Names bound to the stdlib clock classes and module (`from datetime import date as d`,
    # `import datetime as dt`). Bare `date`/`datetime` keep counting unless another module
    # supplies that name.
    clock_classes: dict[str, str] = {"date": "date", "datetime": "datetime"}
    clock_modules: set[str] = {"datetime"}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            for alias in n.names:
                local_name = alias.asname or alias.name
                if n.module == "datetime" and n.level == 0 and alias.name in _CLOCK_CLASSES:
                    clock_classes[local_name] = alias.name
                elif local_name in _CLOCK_CLASSES:
                    clock_classes.pop(local_name, None)
        elif isinstance(n, ast.Import):
            for alias in n.names:
                if alias.name == "datetime":
                    clock_modules.add(alias.asname or "datetime")

    writes: set[str] = set()
    constructed: set[str] = set()
    persisted: set[str] = set()
    write_lines: dict[str, int] = {}
    has_session_writes = False
    called: set[str] = set()
    symbol_calls: set[str] = set()
    write_only: set[int] = set()

    def note_write(sym: str, lineno: int) -> None:
        if sym not in write_lines or lineno < write_lines[sym]:
            write_lines[sym] = lineno
    raw_clocks: list[tuple[str, int]] = []
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

        clock = _clock_ref(target, clock_classes, clock_modules)
        if clock and _naive_clock_call(n, *clock):
            raw_clocks.append((f"{dotted}()", n.lineno))
        # An uncalled clock passed as a value (`default_factory=datetime.now`,
        # `Column(default=date.today)`) runs later with no time zone; `partial(datetime.now, tz)`
        # binds one and is left alone.
        if short != "partial":
            for value in (*n.args, *(kw.value for kw in n.keywords)):
                ref = _clock_ref(value, clock_classes, clock_modules)
                if ref and ref[1] in ("now", "utcnow", "today"):
                    raw_clocks.append((f"{_dotted(value)} (passed uncalled)", value.lineno))

        if short:
            resolved_short = resolve(short)
            called.add(resolved_short)
            if isinstance(target, ast.Name):
                if target.id not in external_roots:
                    symbol_calls.add(resolved_short)
            elif isinstance(target, ast.Attribute):
                recv_root = dotted.split(".", 1)[0] if dotted else ""
                if recv_root not in external_roots and short not in _GENERIC_ATTR_METHODS:
                    symbol_calls.add(resolved_short)
            if dotted:
                head, _, tail = dotted.partition(".")
                called.add(f"{resolve(head)}.{tail}" if tail else resolve(head))
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
                    sym = (
                        resolve(child.id)
                        if isinstance(child, ast.Name)
                        else child.attr
                        if isinstance(child, ast.Attribute)
                        else None
                    )
                    if sym:
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
        sym = resolve(model)
        writes.add(sym)
        persisted.add(sym)
        note_write(sym, lineno)
    if has_session_writes:
        # A loaded row's attribute change is only an UPDATE if this module flushes/commits.
        for model, lineno in row_mutations:
            sym = resolve(model)
            writes.add(sym)
            persisted.add(sym)
            note_write(sym, lineno)

    handlers: list[ParsedRouteHandler] = []
    defined: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef):
            defined.add(stmt.name)
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and not member.name.startswith("_"):
                    defined.add(member.name)

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
        symbol_calls=frozenset(symbol_calls),
        constructed=frozenset(constructed),
        persisted=frozenset(persisted),
        has_session_writes=has_session_writes,
        imported_names={k: frozenset(v) for k, v in imported_names.items()},
        write_lines=write_lines,
    )
