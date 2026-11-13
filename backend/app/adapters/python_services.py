"""Experimental module graph for Python services outside the FastAPI app/ layout."""

from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath

from app.adapters.base import (
    DisplayExtractionResult,
    ManipulatorExtractionResult,
    TruthExtractionResult,
)
from app.adapters.deployment_sources import (
    add_deployment_edges,
    deployment_mappings,
    normalize_home,
)
from app.adapters.launchd_sources import add_launchd_sources, shell_references
from app.adapters.python_ast_inspect import parse_python_module
from app.adapters.registry_sources import add_registry_sources
from app.adapters.service_sources import EXCLUDED_PARTS, script_id, source_files, source_reference
from app.schemas.atlas import AtlasEdge, AtlasNode


def _module_paths(parts: list[str], paths: set[str]) -> set[str]:
    """Include every package initializer that evaluating an import may execute."""
    prefix = "/".join(parts)
    candidates = {prefix + ".py", prefix + "/__init__.py"}
    candidates.update("/".join(parts[:i]) + "/__init__.py" for i in range(1, len(parts)))
    return candidates & paths


def _imports(tree: ast.Module, rel: str, paths: set[str], roots: list[list[str]]) -> set[str]:
    hits: set[str] = set()
    parent = list(PurePosixPath(rel).parent.parts)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
            bases = [
                *roots,
                parent,
            ]  # script-directory imports are possible; all edges are declared
        elif isinstance(node, ast.ImportFrom):
            # Even `from . import *` evaluates the relative package initializer.
            names = [node.module or ""]
            names += [
                ".".join(filter(None, (node.module, a.name))) for a in node.names if a.name != "*"
            ]
            if node.level:
                if node.level > len(parent):
                    continue
                bases = [parent[: len(parent) - node.level + 1]]
            else:
                bases = [*roots, parent]
        else:
            continue
        for base in bases:
            for name in names:
                hits.update(_module_paths([*base, *(name.split(".") if name else [])], paths))
    hits.discard(rel)
    return hits


def _has_main(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
        for node in tree.body
    )


def _dynamic_imports(
    tree: ast.Module, rel: str, paths: set[str], roots: list[list[str]]
) -> tuple[set[str], int]:
    modules = {
        a.asname or a.name
        for n in ast.walk(tree)
        if isinstance(n, ast.Import)
        for a in n.names
        if a.name == "importlib"
    }
    functions = {
        a.asname or a.name
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module == "importlib"
        for a in n.names
        if a.name == "import_module"
    }
    hits: set[str] = set()
    unresolved = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        possible = (
            isinstance(func, ast.Attribute)
            and func.attr in {"import_module", "spec_from_file_location"}
            or isinstance(func, ast.Name)
            and func.id in functions | {"__import__"}
        )
        if not possible:
            continue
        known = (
            isinstance(func, ast.Name)
            and func.id in functions | {"__import__"}
            or isinstance(func, ast.Attribute)
            and func.attr == "import_module"
            and isinstance(func.value, ast.Name)
            and func.value.id in modules
        )
        targets: set[str] = set()
        if (
            known
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            name = node.args[0].value
            if name and not name.startswith("."):
                for base in [*roots, list(PurePosixPath(rel).parent.parts)]:
                    targets.update(_module_paths([*base, *name.split(".")], paths))
        if not targets:
            unresolved += 1
        hits.update(targets)
    return hits - {rel}, unresolved


class NoDisplayAdapter:
    name = "no-display"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        return DisplayExtractionResult(
            nodes=[],
            edges=[],
            http_calls=[],
            notes=[
                (
                    "The python-services profile does not inspect UI or HTTP routing; embedded HTML, "
                    "native clients and custom HTTP servers remain outside this profile's coverage."
                )
            ],
        )


class PythonServicesAdapter:
    name = "python-services"

    def extract(
        self, repo_root: Path, backend_subdir: str, truth: TruthExtractionResult
    ) -> ManipulatorExtractionResult:
        result = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        base = (repo_root / backend_subdir).resolve()
        if not base.is_relative_to(repo_root.resolve()) or not base.is_dir():
            result.notes.append(
                "Python services backend root is absent or outside the repository; no modules inspected."
            )
            return result
        files, excluded = source_files(base, {".py", ".sh"})
        paths = {f.relative_to(repo_root).as_posix() for f in files}
        py_paths = {p for p in paths if p.endswith(".py")}
        trees: dict[str, ast.Module] = {}
        shell: dict[str, str] = {}
        failed: list[str] = []
        for path in files:
            rel = path.relative_to(repo_root).as_posix()
            try:
                text = path.read_text(encoding="utf-8-sig")
                tree = ast.parse(text) if path.suffix == ".py" else None
            except (OSError, UnicodeError, SyntaxError, ValueError):
                failed.append(rel)
                continue
            if tree is not None:
                trees[rel] = tree
                entry = _has_main(tree)
            else:
                shell[rel] = text
                entry = True
            result.nodes.append(
                AtlasNode(
                    id=script_id(rel),
                    tier="manipulate",
                    subkind="cli" if entry else "service",
                    label=rel,
                    source_file=rel,
                    cluster="python_scripts" if tree else "shell_scripts",
                    summary=(
                        "Explicit Python __main__ guard. "
                        if tree and entry
                        else "Shell script source. "
                        if tree is None
                        else "Python module source. "
                    )
                    + "Static source evidence only; external entry points and runtime state are unknown.",
                )
            )
            if tree is not None:
                parsed = parse_python_module(text, rel, rel.removesuffix(".py").replace("/", "."))
                if parsed:
                    for kind, refs in (
                        ("reads_truth", parsed.sql_reads),
                        ("writes_truth", parsed.sql_writes),
                    ):
                        for ref in sorted(refs):
                            target = truth.table_symbol_map.get(ref) or truth.table_symbol_map.get(
                                ref.removeprefix("public.")
                            )
                            if target:
                                result.edges.append(
                                    AtlasEdge(
                                        id=f"e:script:{rel}:{kind}:{target}",
                                        source_id=script_id(rel),
                                        target_id=target,
                                        kind=kind,
                                        verification="declared",
                                        evidence_path=f"{rel}:1",
                                        evidence_note="Static SQL reference; reachability and database identity are not established.",
                                    )
                                )
        # Retain unreadable modules as unknown dependency nodes, never as absent files.
        for rel in failed:
            result.nodes.append(
                AtlasNode(
                    id=script_id(rel),
                    tier="manipulate",
                    subkind="service",
                    label=rel,
                    source_file=rel,
                    status="gray_zone",
                    cluster="unparsed",
                    summary="Source could not be parsed; outgoing dependency evidence is unavailable.",
                )
            )
        roots = [list(base.relative_to(repo_root).parts)]
        if (base / "src").is_dir():
            roots.append([*roots[0], "src"])
        dynamic = 0
        for rel, tree in trees.items():
            hits = _imports(tree, rel, py_paths, roots)
            dynamic_hits, unresolved = _dynamic_imports(tree, rel, py_paths, roots)
            hits.update(dynamic_hits)
            dynamic += unresolved
            for target in sorted(hits):
                result.edges.append(
                    AtlasEdge(
                        id=f"e:import:{rel}:{target}",
                        source_id=script_id(rel),
                        target_id=script_id(target),
                        kind="calls_helper",
                        verification="declared",
                        evidence_path=f"{rel}:1",
                        evidence_note="Static Python import or literal importlib target, including possible package initialization; conditional imports and search-path precedence are not evaluated.",
                    )
                )
        deployments, references = deployment_mappings(repo_root, trees, result)
        for rel, text in shell.items():
            targets = set()
            for ref in shell_references(text):
                mapped = deployments.get(normalize_home(ref), set())
                if mapped:
                    targets.update(mapped & paths)
                else:
                    target = source_reference(ref, rel, paths)
                    if target:
                        targets.add(target)
            targets.discard(rel)
            for target in sorted(targets):
                result.edges.append(
                    AtlasEdge(
                        id=f"e:shell:{rel}:{target}",
                        source_id=script_id(rel),
                        target_id=script_id(target),
                        kind="calls_helper",
                        verification="declared",
                        evidence_path=f"{rel}:1",
                        evidence_note="Shell source contains a script reference; this does not prove invocation or resolve variable values.",
                    )
                )
        add_launchd_sources(repo_root, result, deployments)
        add_registry_sources(repo_root, result, deployments)
        add_deployment_edges(result, references)
        result.edges[:] = {edge.id: edge for edge in result.edges}.values()
        incoming = {edge.target_id for edge in result.edges}
        callers = {
            edge.target_id for edge in result.edges if not edge.id.startswith("e:deployment:")
        }
        for node in result.nodes:
            if not node.id.startswith("m:script:"):
                continue
            if node.id in callers:
                node.summary += " Declared source caller/reference found."
            elif node.id in incoming:
                node.summary += " Deployment references only; no execution caller discovered."
            else:
                node.summary += (
                    " No source caller/reference discovered; external entry points remain unknown."
                )
        result.notes.extend(
            [
                (
                    f"Python services source coverage: {len(trees)}/{len(py_paths)} Python files parsed, "
                    f"{len(shell)} shell files inspected, {len(failed)} unreadable/unparseable files; "
                    f"{excluded} directories or links excluded. Excluded names: {', '.join(sorted(EXCLUDED_PARTS))}; hidden directories and symlinks also excluded."
                ),
                (
                    f"{dynamic} dynamic import call sites are unresolved. Import edges retain possible dependencies; "
                    "sys.path mutations, entry-point plugins and custom job admission remain unobserved. "
                    "No missing-caller finding or small blast radius is removal approval."
                ),
                (
                    "SQL coverage is limited to standalone DDL and recognized Python SQL references; "
                    "inline CREATE statements, runtime database selection and live schemas are not fully resolved."
                ),
            ]
        )
        result.notes.extend(f"Unparsed source: {rel}" for rel in failed)
        return result
