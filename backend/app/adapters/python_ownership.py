"""Single-handler source observations, never an authorization verdict or taint proof."""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Iterator

from app.schemas.security import OwnershipEvidence, OwnershipReport


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""


def _imports(tree: ast.Module) -> dict[str, str]:
    names: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and not node.level:
            for item in node.names:
                names[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, ast.Import):
            for item in node.names:
                names[item.asname or item.name.split('.')[0]] = (
                    item.name if item.asname else item.name.split('.')[0]
                )
    return names


def _qualified(node: ast.AST | None, imports: dict[str, str]) -> str:
    name = _name(node)
    first, dot, rest = name.partition(".")
    return imports.get(first, first) + (dot + rest if dot else "")


def _walk(node: ast.AST, placement: str = "direct") -> Iterator[tuple[ast.AST, str]]:
    """Retain literal dead branches, label conditional code, exclude nested definitions."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    yield node, placement
    if isinstance(node, (ast.If, ast.While)):
        yield from _walk(node.test, placement)
        constant = isinstance(node.test, ast.Constant)
        for active, block in ((True, node.body), (False, node.orelse)):
            branch = "inactive" if placement == "inactive" else "conditional"
            if constant and bool(node.test.value) != active:
                branch = "inactive"
            for child in block:
                yield from _walk(child, branch)
        return
    child_placement = placement
    if isinstance(node, (ast.For, ast.AsyncFor, ast.Try, ast.TryStar, ast.Match, ast.IfExp)):
        child_placement = "inactive" if placement == "inactive" else "conditional"
    for child in ast.iter_child_nodes(node):
        yield from _walk(child, child_placement)


def _owner_comparison(node: ast.AST, record: str, principal: str, owner: str) -> bool:
    return (
        isinstance(node, ast.Compare) and len(node.ops) == 1
        and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
        and {_name(node.left), _name(node.comparators[0])} == {f"{record}.{owner}", principal}
    )


def _rejects(node: ast.If, imports: dict[str, str]) -> bool:
    if not isinstance(node.test, ast.Compare) or not isinstance(node.test.ops[0], ast.NotEq):
        return False
    if len(node.body) != 1 or not isinstance(node.body[0], ast.Raise):
        return False
    call = node.body[0].exc
    if not isinstance(call, ast.Call) or _qualified(call.func, imports) != "fastapi.HTTPException":
        return False
    status = next((k.value for k in call.keywords if k.arg == "status_code"), None)
    if status is None and call.args:
        status = call.args[0]
    return isinstance(status, ast.Constant) and status.value in (403, 404)


def inspect_ownership_source(
    source: str, *, source_file: str, handler: str, record: str, principal: str,
    owner_field: str, source_sha256: str | None = None,
) -> OwnershipReport:
    """Inspect explicit caller-supplied symbols; their security meaning is not inferred."""
    for value in (handler, record, owner_field):
        if not value.isidentifier():
            raise ValueError("Handler, record and owner field must be Python identifiers")
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", principal):
        raise ValueError("Principal must be a name or dotted attribute, not an expression")
    if principal == f"{record}.{owner_field}":
        raise ValueError("Principal and record ownership expressions must differ")
    tree = ast.parse(source, filename=source_file)
    matches = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == handler]
    if len(matches) != 1:
        raise ValueError("Select exactly one top-level function; nested/duplicate handlers are unsupported")
    function = matches[0]
    imports = _imports(tree)
    evidence: list[OwnershipEvidence] = []

    def add(kind: str, node: ast.AST, detail: str, placement: str = "direct") -> None:
        evidence.append(OwnershipEvidence(
            kind=kind, line=node.lineno, end_line=node.end_lineno or node.lineno,
            expression=ast.unparse(node), placement=placement, detail=detail,
        ))

    receivers = set()
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and _qualified(node.value.func, imports) in ("fastapi.FastAPI", "fastapi.APIRouter")):
            receivers.update(t.id for t in node.targets if isinstance(t, ast.Name))
    for decorator in function.decorator_list:
        if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                and _name(decorator.func.value) in receivers
                and decorator.func.attr in ("get", "post", "put", "patch", "delete", "api_route")):
            add("route", decorator, "Local route declaration; mount path and live registration unverified.")

    parameters = function.args.posonlyargs + function.args.args + function.args.kwonlyargs
    sessions = set()
    for parameter in parameters:
        annotation = parameter.annotation
        if (isinstance(annotation, ast.Subscript)
                and _qualified(annotation.value, imports) in ("typing.Annotated", "typing_extensions.Annotated")
                and isinstance(annotation.slice, ast.Tuple)):
            annotation = annotation.slice.elts[0]
        if _qualified(annotation, imports) in ("sqlalchemy.orm.Session", "sqlalchemy.ext.asyncio.AsyncSession"):
            sessions.add(parameter.arg)
    for node in ast.walk(function.args):
        if isinstance(node, ast.Call) and _qualified(node.func, imports) == "fastapi.Depends":
            add("dependency", node, "Dependency declaration only; authentication/authorization behavior unverified.")

    nodes = [pair for statement in function.body for pair in _walk(statement)]
    for node, placement in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            if any(isinstance(t, ast.Attribute) and _name(t.value) == record for t in targets):
                add("record_write", node, "Attribute mutation on the selected variable; object identity unverified.", placement)
            value = getattr(node, "value", None)
            if isinstance(value, ast.Await):
                value = value.value
            if (any(isinstance(t, ast.Name) and t.id == record for t in targets)
                    and isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                    and _name(value.func.value) in sessions and value.func.attr == "get"):
                add("record_lookup", node, "Session.get on an annotated SQLAlchemy parameter; model/table binding unverified.", placement)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and _name(node.func.value) in sessions
                and node.func.attr in ("add", "add_all", "delete", "execute", "flush", "commit")):
            add("persistence_call", node, "Session operation declaration; effect and transaction outcome unverified.", placement)
        if _owner_comparison(node, record, principal, owner_field):
            add("owner_comparison", node, "Comparison of the selected ownership and principal expressions.", placement)
        if (isinstance(node, ast.If) and _owner_comparison(node.test, record, principal, owner_field)
                and _rejects(node, imports)):
            add("ownership_rejection", node, "Mismatch branch raises a declared HTTPException(403/404); not proof it protects any write.", placement)

    evidence.sort(key=lambda e: (e.line, e.kind))
    unknowns = [
        "Caller-selected symbols express the hypothesis; their identity and trust are unverified.",
        "Imports, helpers, dependencies, decorators, middleware and database policies are not followed.",
        "Aliases, rebinding, dynamic writes and query predicates are not resolved; this is not taint analysis.",
        "Placement is lexical: direct/conditional/inactive does not prove reachability or guard dominance.",
        "Model-to-table mapping, mounted URL, database effects and runtime authorization are unverified.",
        "No target code was executed and no target database or endpoint was contacted.",
    ]
    for kind, label in (("route", "FastAPI route declaration"), ("record_lookup", "Session.get lookup"),
                        ("record_write", "record attribute write"), ("ownership_rejection", "ownership rejection")):
        if not any(e.kind == kind and e.placement != "inactive" for e in evidence):
            unknowns.append(f"No supported active {label} observed; absence is not proof of a defect or safety.")
    return OwnershipReport(
        source_file=source_file, source_sha256=source_sha256 or hashlib.sha256(source.encode()).hexdigest(),
        handler=handler, record=record, principal=principal, owner_field=owner_field,
        evidence=evidence, unknowns=unknowns,
    )
