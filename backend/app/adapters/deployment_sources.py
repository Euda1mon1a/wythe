"""Read literal source/deployment declarations without importing an installer."""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.service_sources import script_id
from app.schemas.atlas import AtlasEdge

_REPO_PARENT_RE = re.compile(r"^<repo_parent(?::(\d+))?>$")


def _step_parent(base: str) -> str | None:
    """Advance one directory parent above `base`, representing climbs past repo root symbolically."""
    if not base or base in ("/", "~"):
        return None
    if base == ".":
        return "<repo_parent>"
    if base == "<repo_parent>":
        return "<repo_parent:2>"
    m = _REPO_PARENT_RE.match(base)
    if m and m.group(1):
        return f"<repo_parent:{int(m.group(1)) + 1}>"
    p = PurePosixPath(base)
    if ".." in p.parts:
        return None
    parent = str(p.parent)
    if not parent or parent == base or ".." in PurePosixPath(parent).parts:
        return None
    return parent


def _clean_repo_source(raw: str | None) -> str | None:
    """Return a normalized in-repo relative path or None if `raw` escapes or cannot be repo-tracked."""
    if raw is None:
        return None
    cleaned = raw.strip()
    if cleaned.startswith("./"):
        cleaned = cleaned.removeprefix("./")
    if not cleaned or cleaned in (".", "~") or cleaned.startswith("~/"):
        return None
    p = PurePosixPath(cleaned)
    if p.is_absolute() or ".." in p.parts:
        return None
    if any(part.startswith("<repo_parent") for part in p.parts):
        return None
    return cleaned


def symbolic_path(
    node: ast.AST,
    names: dict[str, str],
    owner: str | None = None,
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        if node.id == "__file__" and owner:
            return owner
        return names.get(node.id)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base = symbolic_path(node.value, names, owner)
        return _step_parent(base) if base is not None else None
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "parents"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, int)
        and not isinstance(node.slice.value, bool)
        and 0 <= node.slice.value <= 64
    ):
        cur = symbolic_path(node.value.value, names, owner)
        for _ in range(node.slice.value + 1):
            if cur is None:
                return None
            cur = _step_parent(cur)
        return cur
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = symbolic_path(node.left, names, owner)
        right = symbolic_path(node.right, names, owner)
        if left is not None and right is not None:
            return str(PurePosixPath(left) / right)
    if isinstance(node, ast.Call) and not node.keywords:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "Path"
            and node.func.attr == "home"
            and not node.args
        ):
            return "~"  # symbolic only: never inspect the operator's home
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"resolve", "expanduser", "absolute"}
            and not node.args
        ):
            return symbolic_path(node.func.value, names, owner)
        if isinstance(node.func, ast.Name) and node.func.id == "str" and len(node.args) == 1:
            return symbolic_path(node.args[0], names, owner)
        if isinstance(node.func, ast.Name) and node.func.id in {"Path", "PurePosixPath"}:
            values = [symbolic_path(arg, names, owner) for arg in node.args]
            if values and all(v is not None for v in values):
                return str(PurePosixPath(*values))
    return None


def normalize_home(value: str) -> str:
    value = re.sub(r"^(?:/Users|/home)/[^/]+(?=/)", "~", value)
    return re.sub(r"^\$(?:HOME|\{HOME\})(?=/)", "~", value)


def _scan_module_deployments(
    repo_root: Path,
    owner: str,
    tree: ast.Module,
    constructors: set[str],
    mappings: dict[str, set[str]],
    references: list[tuple[str, str, int]],
    result: ManipulatorExtractionResult,
) -> int:
    unresolved = 0

    def _record_call(node: ast.Call, env: dict[str, str]) -> None:
        nonlocal unresolved
        kwargs = {k.arg: k.value for k in node.keywords}
        src = node.args[0] if node.args else kwargs.get("repo_path")
        dst = node.args[1] if len(node.args) > 1 else kwargs.get("live_path")
        source = _clean_repo_source(symbolic_path(src, env, owner)) if src is not None else None
        dest = symbolic_path(dst, env, owner) if dst is not None else None
        if source is None or dest is None:
            unresolved += 1
            return
        mappings.setdefault(normalize_home(dest), set()).add(source)
        references.append((owner, source, node.lineno))
        if not (repo_root / source).is_file():
            result.findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-005",
                    node_id=script_id(owner),
                    source_file=owner,
                    line=node.lineno,
                    title="Deployment declaration names an absent source file",
                    detail=f"The literal repo_path `{source}` does not exist in this source tree. The declaration may be conditional or retained; runtime impact is unproven.",
                    remediation="Verify the declaration's owning group, then restore its source or retire the stale declaration with recovery evidence.",
                )
            )

    def _walk_calls_no_defs(node: ast.AST, env: dict[str, str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in constructors
        ):
            _record_call(node, env)
        for child in ast.iter_child_nodes(node):
            _walk_calls_no_defs(child, env)

    def _scan_stmts(stmts: list[ast.stmt], base_names: dict[str, str]) -> None:
        names = dict(base_names)
        for statement in stmts:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                _scan_stmts(statement.body, names)
                continue
            if isinstance(statement, ast.Assign):
                value = symbolic_path(statement.value, names, owner)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        names.pop(target.id, None)
                        if value is not None:
                            names[target.id] = value
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                names.pop(statement.target.id, None)
                if statement.value is not None:
                    value = symbolic_path(statement.value, names, owner)
                    if value is not None:
                        names[statement.target.id] = value
            _walk_calls_no_defs(statement, names)

    _scan_stmts(tree.body, {})
    return unresolved


def deployment_mappings(
    repo_root: Path,
    trees: dict[str, ast.Module],
    result: ManipulatorExtractionResult,
) -> tuple[dict[str, set[str]], list[tuple[str, str, int]]]:
    """Recognize constructors whose first fields are repo_path and live_path.

    This is a narrow declaration convention, not arbitrary Python evaluation.
    Conditional lists, host groups and subclass overrides do not establish admission.
    """
    mappings: dict[str, set[str]] = {}
    references: list[tuple[str, str, int]] = []
    unresolved = 0
    for owner, tree in trees.items():
        constructors = set()
        for cls in tree.body:
            if not isinstance(cls, ast.ClassDef):
                continue
            fields = [
                n.target.id
                for n in cls.body
                if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
            ]
            if fields[:2] == ["repo_path", "live_path"]:
                constructors.add(cls.name)
        if not constructors:
            continue
        unresolved += _scan_module_deployments(
            repo_root, owner, tree, constructors, mappings, references, result
        )
    result.notes.append(
        f"Deployment source coverage: {len(references)} literal repo_path/live_path declarations, "
        f"{unresolved} unresolved declarations. Constructor fields, Path literals and symbolic home paths "
        "are recognized; installer execution, group selection and installed content are not observed."
    )
    return mappings, references


def add_deployment_edges(
    result: ManipulatorExtractionResult, references: list[tuple[str, str, int]]
) -> None:
    by_path = {n.source_file: n.id for n in result.nodes}
    seen = set()
    for owner, source, line in references:
        if source not in by_path or owner == source or (owner, source) in seen:
            continue
        seen.add((owner, source))
        result.edges.append(
            AtlasEdge(
                id=f"e:deployment:{owner}:{source}",
                source_id=script_id(owner),
                target_id=by_path[source],
                kind="calls_helper",
                verification="declared",
                evidence_path=f"{owner}:{line}",
                evidence_note="Installer source declaration references this file; no deployment or execution is established.",
            )
        )
