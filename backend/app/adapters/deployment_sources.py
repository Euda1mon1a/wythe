"""Read literal source/deployment declarations without importing an installer."""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.service_sources import script_id
from app.schemas.atlas import AtlasEdge


def symbolic_path(node: ast.AST, names: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left, right = symbolic_path(node.left, names), symbolic_path(node.right, names)
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
        if isinstance(node.func, ast.Name) and node.func.id in {"Path", "PurePosixPath"}:
            values = [symbolic_path(arg, names) for arg in node.args]
            if values and all(v is not None for v in values):
                return str(PurePosixPath(*values))
    return None


def normalize_home(value: str) -> str:
    value = re.sub(r"^(?:/Users|/home)/[^/]+(?=/)", "~", value)
    return re.sub(r"^\$(?:HOME|\{HOME\})(?=/)", "~", value)


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
        names: dict[str, str] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                value = symbolic_path(statement.value, names)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        names.pop(target.id, None)
                        if value is not None:
                            names[target.id] = value
            for node in ast.walk(statement):
                if (
                    not isinstance(node, ast.Call)
                    or not isinstance(node.func, ast.Name)
                    or node.func.id not in constructors
                ):
                    continue
                kwargs = {k.arg: k.value for k in node.keywords}
                src = node.args[0] if node.args else kwargs.get("repo_path")
                dst = node.args[1] if len(node.args) > 1 else kwargs.get("live_path")
                source = symbolic_path(src, names) if src is not None else None
                dest = symbolic_path(dst, names) if dst is not None else None
                if (
                    source is None
                    or dest is None
                    or PurePosixPath(source).is_absolute()
                    or ".." in PurePosixPath(source).parts
                ):
                    unresolved += 1
                    continue
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
