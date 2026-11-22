"""Experimental module graph for Python services outside the FastAPI app/ layout."""

from __future__ import annotations

import ast
import os
import stat
from dataclasses import replace
from pathlib import Path, PurePosixPath

from app.adapters.base import (
    DisplayExtractionResult,
    ManipulatorExtractionResult,
    RawCandidateFinding,
    TruthExtractionResult,
)
from app.adapters.deployment_sources import (
    add_deployment_edges,
    deployment_mappings,
    normalize_home,
)
from app.adapters.inline_store_truth import (
    ModuleStoreIo,
    extract_module_store_io,
    resolve_store_target_id,
)
from app.adapters.launchd_sources import add_launchd_sources, shell_references
from app.adapters.python_ast_inspect import ParsedPythonModule, parse_python_module
from app.adapters.python_daemon_routes import (
    _called_qualified_names,
    add_daemon_routes_and_subprocesses,
)
from app.adapters.python_policy_consumption import (
    analyze_module_policy_table_read,
    classify_table_policy_columns,
    merge_policy_consumptions,
    summarize_edge_policy_consumption,
)
from app.adapters.registry_sources import add_registry_sources
from app.adapters.service_sources import EXCLUDED_PARTS, script_id, source_files, source_reference
from app.adapters.ts_workspace import safe_read_repo_text, safe_resolve_contained_path
from app.schemas.atlas import AtlasEdge, AtlasNode, PolicyFieldConsumption


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


def _is_test_module(rel: str) -> bool:
    posix = PurePosixPath(rel)
    bname = posix.name
    parts_low = {p.lower() for p in posix.parts[:-1]}
    return (
        bname == "conftest.py"
        or bname.startswith("test_")
        or bname.endswith("_test.py")
        or bool(parts_low & {"tests", "test", "testing", "fixtures"})
    )


def _is_type_checking_if(stmt: ast.If) -> bool:
    test = stmt.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _is_pure_constant_module(
    tree: ast.Module, io: ModuleStoreIo, parsed: ParsedPythonModule
) -> bool:
    """Return True when a Python module declares only constants/types/imports with no runtime logic."""
    if (
        parsed.raw_clock_calls
        or parsed.route_handlers
        or io.sql_reads
        or io.sql_writes
        or io.jsonl_reads
        or io.jsonl_writes
    ):
        return False
    type_alias_cls = getattr(ast, "TypeAlias", None)
    seen_stmt = False
    for stmt in tree.body:
        if isinstance(stmt, ast.If) and _is_type_checking_if(stmt):
            continue
        seen_stmt = True
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.Pass)):
            continue
        if type_alias_cls is not None and isinstance(stmt, type_alias_cls):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if isinstance(stmt.value.value, str) or stmt.value.value is Ellipsis:
                continue
            return False
        if isinstance(stmt, ast.ClassDef):
            for member in stmt.body:
                if isinstance(member, (ast.Assign, ast.AnnAssign, ast.Pass)):
                    continue
                if (
                    isinstance(member, ast.Expr)
                    and isinstance(member.value, ast.Constant)
                    and (isinstance(member.value.value, str) or member.value.value is Ellipsis)
                ):
                    continue
                return False
            continue
        return False
    return seen_stmt


def _target_import_bindings(
    tree: ast.Module,
    rel: str,
    target: str,
    roots: list[list[str]],
) -> tuple[dict[str, str], set[str], bool]:
    """Resolve imports in `rel` targeting `target` into `(direct_alias_to_orig, mod_prefixes, has_star)`."""
    parent = list(PurePosixPath(rel).parent.parts)
    direct_alias_to_orig: dict[str, str] = {}
    mod_prefixes: set[str] = set()
    has_star = False
    target_set = {target}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                hits_mod = any(
                    _module_paths([*base, *parts], target_set) for base in [*roots, parent]
                )
                if hits_mod:
                    mod_prefixes.add(alias.asname or alias.name)
                if (
                    not alias.asname
                    and len(parts) > 1
                    and any(_module_paths([*base, parts[0]], target_set) for base in [*roots, parent])
                ):
                    mod_prefixes.add(parts[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > len(parent):
                    continue
                bases = [parent[: len(parent) - node.level + 1]]
            else:
                bases = [*roots, parent]
            mod_parts = node.module.split(".") if node.module else []
            mod_hits_target = bool(node.module) and any(
                _module_paths([*base, *mod_parts], target_set) for base in bases
            )
            for alias in node.names:
                if alias.name == "*":
                    if mod_hits_target:
                        has_star = True
                    continue
                sub_hits_target = any(
                    _module_paths([*base, *mod_parts, alias.name], target_set) for base in bases
                )
                if sub_hits_target:
                    mod_prefixes.add(alias.asname or alias.name)
                elif mod_hits_target:
                    direct_alias_to_orig[alias.asname or alias.name] = alias.name
    return direct_alias_to_orig, mod_prefixes, has_star


def _match_qualified_calls(
    qcalls: set[str],
    direct_alias_to_orig: dict[str, str],
    mod_prefixes: set[str],
    has_star: bool,
    src_pm: ParsedPythonModule | None,
    tgt_pm: ParsedPythonModule,
) -> list[str]:
    """Match receiver-qualified calls `qcalls` strictly against bindings imported from `tgt_pm`."""
    t_defs = tgt_pm.defined | set(tgt_pm.class_attrs)
    src_defs = src_pm.top_level_defs if src_pm is not None else frozenset()
    matched: set[str] = set()
    for call_q in qcalls:
        if "." not in call_q:
            if call_q in direct_alias_to_orig:
                orig = direct_alias_to_orig[call_q]
                if orig in t_defs:
                    matched.add(orig)
            elif has_star and call_q in tgt_pm.top_level_defs and call_q not in src_defs:
                matched.add(call_q)
            continue
        for mp in mod_prefixes:
            pref = f"{mp}."
            if call_q.startswith(pref):
                rem = call_q[len(pref) :]
                sym = rem.split(".", 1)[0]
                if sym in t_defs:
                    matched.add(sym)
        head, rest = call_q.split(".", 1)
        if head in direct_alias_to_orig:
            orig_head = direct_alias_to_orig[head]
            if orig_head in tgt_pm.class_attrs:
                attr = rest.split(".", 1)[0]
                if attr in tgt_pm.class_attrs[orig_head]:
                    matched.add(orig_head)
    return sorted(matched)


def _collect_scope_qualified_calls(tree: ast.Module) -> dict[str, set[str]]:
    """Map top-level scope names (and `\"*\"` for module-level code) to receiver-qualified call strings."""
    scope_qcalls: dict[str, set[str]] = {}
    mod_q: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope_qcalls[stmt.name] = _called_qualified_names(stmt)
        elif isinstance(stmt, ast.ClassDef):
            cls_q: set[str] = set()
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mq = _called_qualified_names(member)
                    scope_qcalls[f"{stmt.name}.{member.name}"] = mq
                    scope_qcalls.setdefault(member.name, set()).update(mq)
                    cls_q.update(mq)
                else:
                    cls_q.update(_called_qualified_names(member))
            scope_qcalls[stmt.name] = cls_q
        else:
            mod_q.update(_called_qualified_names(stmt))
    if mod_q:
        scope_qcalls["*"] = mod_q
    return scope_qcalls


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


def _find_uninspected_service_links(
    base: Path,
    suffixes: set[str],
    unreadable_dirs: list[Path] | None = None,
) -> tuple[list[Path], list[Path]]:
    """Return `(symlink_paths, non_regular_paths)` skipped by `source_files` under non-excluded dirs."""
    symlinks: list[Path] = []
    non_regular: list[Path] = []

    def _on_walk_err(exc: OSError) -> None:
        if unreadable_dirs is not None:
            unreadable_dirs.append(Path(exc.filename) if exc.filename else base)

    if not os.access(base, os.R_OK | os.X_OK):
        if unreadable_dirs is not None:
            unreadable_dirs.append(base)
        return symlinks, non_regular

    for parent, dirs, names in os.walk(base, followlinks=False, onerror=_on_walk_err):
        kept_dirs: list[str] = []
        for d in sorted(dirs):
            if d in EXCLUDED_PARTS or d.startswith("."):
                continue
            dp = Path(parent) / d
            try:
                st = dp.lstat()
            except OSError:
                if unreadable_dirs is not None:
                    unreadable_dirs.append(dp)
                else:
                    non_regular.append(dp)
                continue
            if stat.S_ISLNK(st.st_mode):
                symlinks.append(dp)
                continue
            if stat.S_ISDIR(st.st_mode):
                if not os.access(dp, os.R_OK | os.X_OK):
                    if unreadable_dirs is not None:
                        unreadable_dirs.append(dp)
                    else:
                        non_regular.append(dp)
                    continue
                kept_dirs.append(d)
        dirs[:] = kept_dirs

        for name in sorted(names):
            p = Path(parent) / name
            if p.suffix not in suffixes:
                continue
            try:
                st = p.lstat()
            except OSError:
                non_regular.append(p)
                continue
            if stat.S_ISLNK(st.st_mode):
                symlinks.append(p)
            elif not stat.S_ISREG(st.st_mode):
                non_regular.append(p)
    return symlinks, non_regular


class PythonServicesAdapter:
    name = "python-services"

    def extract(
        self, repo_root: Path, backend_subdir: str, truth: TruthExtractionResult
    ) -> ManipulatorExtractionResult:
        try:
            if repo_root.is_symlink():
                return ManipulatorExtractionResult(
                    nodes=[],
                    edges=[],
                    routes=[],
                    coverage_complete=False,
                    notes=[
                        f"Repository root `{repo_root}` is a symlink; Python services coverage is incomplete."
                    ],
                )
            repo_res = repo_root.resolve(strict=True)
            if not repo_res.is_dir():
                return ManipulatorExtractionResult(
                    nodes=[],
                    edges=[],
                    routes=[],
                    coverage_complete=False,
                    notes=[
                        f"Repository root `{repo_root}` is not a directory; Python services coverage is incomplete."
                    ],
                )
            if not os.access(repo_res, os.R_OK | os.X_OK):
                raise PermissionError(f"Repository root is not readable/traversable: {repo_res}")
            with os.scandir(repo_res):
                pass
        except OSError as exc:
            return ManipulatorExtractionResult(
                nodes=[],
                edges=[],
                routes=[],
                coverage_complete=False,
                notes=[
                    f"Repository root `{repo_root}` is unreadable ({exc}); Python services coverage is incomplete."
                ],
            )
        base = (
            repo_res
            if backend_subdir in ("", ".")
            else safe_resolve_contained_path(Path(backend_subdir), repo_root)
        )
        try:
            base_ok = base is not None and base.is_relative_to(repo_res) and base.is_dir() and os.access(base, os.R_OK | os.X_OK)
        except OSError:
            base_ok = False
        if not base_ok or base is None:
            return ManipulatorExtractionResult(
                nodes=[],
                edges=[],
                routes=[],
                coverage_complete=False,
                notes=[
                    "Python services backend root is absent or outside the repository; no modules inspected."
                ],
            )
        result = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        coverage_complete = True
        try:
            files, excluded = source_files(base, {".py", ".sh"})
        except OSError as exc:
            files, excluded = [], []
            coverage_complete = False
            result.notes.append(f"Unreadable Python/shell source tree `{base}` ({exc}); Python services coverage is incomplete.")
        unreadable_dirs: list[Path] = []
        sym_paths, nonreg_paths = _find_uninspected_service_links(
            base, {".py", ".sh"}, unreadable_dirs=unreadable_dirs
        )
        if unreadable_dirs:
            coverage_complete = False
            rel_unreadable = ", ".join(
                p.relative_to(repo_res).as_posix() if p.is_relative_to(repo_res) else p.as_posix()
                for p in unreadable_dirs[:8]
            )
            result.notes.append(
                f"Unreadable Python/shell directory(ies): {rel_unreadable}; Python services coverage is incomplete."
            )
        if sym_paths:
            coverage_complete = False
            rel_syms = ", ".join(
                p.relative_to(repo_res).as_posix() if p.is_relative_to(repo_res) else p.as_posix()
                for p in sym_paths[:8]
            )
            result.notes.append(
                f"Skipped symlinked Python/shell source path(s): {rel_syms}; Python services coverage is incomplete."
            )
        if nonreg_paths:
            coverage_complete = False
            rel_nonregs = ", ".join(
                p.relative_to(repo_res).as_posix() if p.is_relative_to(repo_res) else p.as_posix()
                for p in nonreg_paths[:8]
            )
            result.notes.append(
                f"Skipped non-regular Python/shell source path(s): {rel_nonregs}; Python services coverage is incomplete."
            )
        paths = {f.relative_to(repo_res).as_posix() for f in files}
        py_paths = {p for p in paths if p.endswith(".py")}
        trees: dict[str, ast.Module] = {}
        py_sources: dict[str, str] = {}
        parsed_mods: dict[str, ParsedPythonModule] = {}
        store_io_by_rel: dict[str, ModuleStoreIo] = {}
        shell: dict[str, str] = {}
        failed: list[str] = []
        for path in files:
            rel = path.relative_to(repo_res).as_posix()
            try:
                text = safe_read_repo_text(path, repo_res, encoding="utf-8-sig")
                tree = ast.parse(text) if path.suffix == ".py" else None
            except (OSError, UnicodeError, SyntaxError, ValueError):
                failed.append(rel)
                coverage_complete = False
                continue
            if tree is not None:
                trees[rel] = tree
                py_sources[rel] = text
                entry = _has_main(tree)
                parsed = parse_python_module(text, rel, rel.removesuffix(".py").replace("/", "."))
                if parsed is not None:
                    parsed_mods[rel] = parsed
                else:
                    coverage_complete = False
                store_io_by_rel[rel] = extract_module_store_io(tree, rel)
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
        roots = [list(base.relative_to(repo_res).parts)] if base != repo_res else []
        safe_base_src = safe_resolve_contained_path(base / "src", repo_res)
        try:
            if safe_base_src is not None and safe_base_src.is_dir() and os.access(safe_base_src, os.R_OK | os.X_OK):
                roots.append([*(roots[0] if roots else []), "src"])
        except OSError as exc:
            coverage_complete = False
            result.notes.append(f"Unreadable source subdirectory `{base / 'src'}` ({exc}); Python services coverage is incomplete.")

        deployments: dict[str, object] = {}
        references: list[object] = []
        try:
            deployments, references = deployment_mappings(repo_res, trees, result)
            add_launchd_sources(repo_res, result, deployments)
            add_deployment_edges(result, references)
        except OSError as exc:
            coverage_complete = False
            result.notes.append(f"Deployment/launchd source scan failed ({exc}); Python services coverage is incomplete.")
        route_qualified_calls: dict[tuple[str, str, str], set[str]] = {}
        try:
            route_keys_by_rel = add_daemon_routes_and_subprocesses(
                repo_res,
                trees,
                paths,
                py_paths,
                roots,
                deployments,
                result,
                route_qualified_calls_out=route_qualified_calls,
            )
        except OSError as exc:
            route_keys_by_rel = {}
            coverage_complete = False
            result.notes.append(f"Daemon route scan failed ({exc}); Python services coverage is incomplete.")
        try:
            add_registry_sources(
                repo_res,
                result,
                deployments,
                truth=truth,
                trees=trees,
                route_keys_by_rel=route_keys_by_rel,
            )
        except OSError as exc:
            coverage_complete = False
            result.notes.append(f"Registry source scan failed ({exc}); Python services coverage is incomplete.")

        # Ensure truth table policy_columns are hydrated even if truth was constructed inline.
        tnode_by_id: dict[str, AtlasNode] = {}
        for tnode in truth.nodes:
            if tnode.subkind == "table":
                tnode_by_id[tnode.id] = tnode
                if not tnode.policy_columns and tnode.columns:
                    tnode.policy_columns = classify_table_policy_columns(tnode.label, tnode.columns)
        mnode_by_id = {n.id: n for n in result.nodes}
        sql_pfcs_by_tid: dict[str, list[PolicyFieldConsumption]] = {}
        unmapped_sql_refs: dict[str, list[str]] = {}
        clock_allow_modules = ("clock.py", "program_time.py", "sql_clock.py")

        def _ensure_unmapped_table_node(raw_ref: str, first_rel: str) -> str | None:
            bare = raw_ref.split(".", 1)[1] if raw_ref.startswith(("public.", "main.", "dbo.")) else raw_ref
            if (
                not bare
                or len(bare) < 2
                or bare.startswith(("sqlite_", "pg_", "pragma_"))
                or bare in {"temp", "dual", "json_each", "json_tree", "unnest"}
            ):
                return None
            unmapped_tid = f"t:unmapped:{bare}"
            if unmapped_tid not in tnode_by_id:
                utnode = AtlasNode(
                    id=unmapped_tid,
                    tier="truth",
                    subkind="table",
                    label=bare,
                    source_file=first_rel,
                    line=1,
                    status="gray_zone",
                    role="unmapped",
                    cluster="unmapped_sql",
                    summary=(
                        f"Unmapped SQL table `{bare}` referenced in `{first_rel}` "
                        "without a resolved CREATE TABLE or inline store declaration."
                    ),
                    verification_note=(
                        "unmapped_sql_reference: Unmapped SQL table reference; "
                        "no DDL declaration resolved in repository."
                    ),
                )
                truth.nodes.append(utnode)
                tnode_by_id[unmapped_tid] = utnode
            if first_rel not in unmapped_sql_refs.setdefault(bare, []):
                unmapped_sql_refs[bare].append(first_rel)
            return unmapped_tid

        def _resolve_sql_target(raw_ref: str, module_io: ModuleStoreIo) -> str | None:
            resolved_tid = resolve_store_target_id(raw_ref, truth.table_symbol_map, module_io)
            if resolved_tid and resolved_tid.startswith(("t:jsonl:", "t:registry:")):
                return None
            return resolved_tid

        # Emit SQL (direct + helper wrappers + f-strings) and JSONL reads_truth / writes_truth edges.
        for rel in sorted(trees):
            parsed = parsed_mods.get(rel)
            io = store_io_by_rel.get(rel, ModuleStoreIo())
            rkeys = route_keys_by_rel.get(rel, {})
            read_scopes_by_tid: dict[str, set[str]] = {}
            read_sql_refs_by_tid: dict[str, set[str]] = {}
            write_scopes_by_tid: dict[str, set[str]] = {}
            unmapped_read_scopes: dict[str, set[str]] = {}
            unmapped_write_scopes: dict[str, set[str]] = {}

            raw_reads: dict[str, set[str]] = {k: set(v) for k, v in io.sql_reads.items()}
            if parsed is not None:
                for ref in parsed.sql_reads:
                    sc_set = {sc for sc, rsyms in parsed.func_reads.items() if ref in rsyms} or {"*"}
                    raw_reads.setdefault(ref, set()).update(sc_set)
            for ref, sc_set in sorted(raw_reads.items()):
                tid = _resolve_sql_target(ref, io)
                if tid:
                    read_scopes_by_tid.setdefault(tid, set()).update(sc_set)
                    read_sql_refs_by_tid.setdefault(tid, set()).add(ref)
                else:
                    utid = _ensure_unmapped_table_node(ref, rel)
                    if utid:
                        unmapped_read_scopes.setdefault(utid, set()).update(sc_set)

            raw_writes: dict[str, set[str]] = {k: set(v) for k, v in io.sql_writes.items()}
            if parsed is not None:
                for ref in parsed.sql_writes:
                    sc_set = {sc for sc, wsyms in parsed.func_writes.items() if ref in wsyms} or {"*"}
                    raw_writes.setdefault(ref, set()).update(sc_set)
            for ref, sc_set in sorted(raw_writes.items()):
                tid = _resolve_sql_target(ref, io)
                if tid:
                    write_scopes_by_tid.setdefault(tid, set()).update(sc_set)
                else:
                    utid = _ensure_unmapped_table_node(ref, rel)
                    if utid:
                        unmapped_write_scopes.setdefault(utid, set()).update(sc_set)

            for j_stem, sc_set in io.jsonl_reads.items():
                tid = truth.table_symbol_map.get(f"jsonl:{j_stem}") or truth.table_symbol_map.get(f"{j_stem}.jsonl")
                if tid:
                    read_scopes_by_tid.setdefault(tid, set()).update(sc_set)
            for j_stem, sc_set in io.jsonl_writes.items():
                tid = truth.table_symbol_map.get(f"jsonl:{j_stem}") or truth.table_symbol_map.get(f"{j_stem}.jsonl")
                if tid:
                    write_scopes_by_tid.setdefault(tid, set()).update(sc_set)

            def _scope_links(scopes: set[str], _rk: dict[str, list[str]] = rkeys) -> list[str]:
                links: list[str] = []
                for sc in sorted(scopes):
                    links.append(f"{sc}->*")
                    for rk in _rk.get(sc, ()):
                        if f"{rk}->*" not in links:
                            links.append(f"{rk}->*")
                return links

            src_nid = script_id(rel)
            mnode = mnode_by_id.get(src_nid)
            subst_consts_in_mod: dict[str, list[str]] = {}
            fb_consts_in_mod: dict[str, list[str]] = {}
            for tid, sc_set in sorted(read_scopes_by_tid.items()):
                tnode_ref = tnode_by_id.get(tid)
                edge_pfc: PolicyFieldConsumption | None = None
                ev_note = "Static SQL/ledger read reference; reachability and runtime store binding remain static."
                if (
                    tnode_ref is not None
                    and tnode_ref.policy_columns
                    and not tid.startswith(("t:jsonl:", "t:registry:"))
                    and parsed is not None
                ):
                    sa_list = analyze_module_policy_table_read(
                        py_sources.get(rel, ""),
                        table_label=tnode_ref.label,
                        table_columns=tnode_ref.columns,
                        policy_columns=tnode_ref.policy_columns,
                        active_scopes=sorted(sc_set),
                        write_scopes=write_scopes_by_tid.get(tid, set()),
                        func_calls=parsed.func_calls,
                        model_symbols=set(),
                        sql_table_names=read_sql_refs_by_tid.get(tid, set()),
                        declared_policy_consts=[c for c, _, _ in parsed.policy_literals],
                    )
                    summarized = summarize_edge_policy_consumption(
                        tnode_ref.label, tnode_ref.policy_columns, sa_list
                    )
                    if summarized is not None:
                        edge_pfc, ev_note = summarized
                        sql_pfcs_by_tid.setdefault(tid, []).append(edge_pfc)
                        if mnode is not None:
                            mnode.policy_field_consumption = (
                                merge_policy_consumptions([mnode.policy_field_consumption, edge_pfc])
                                if mnode.policy_field_consumption is not None
                                else edge_pfc
                            )
                    for sa in sa_list:
                        if sa.state == "bypassed":
                            for sc_const in sa.substituted_constants:
                                subst_consts_in_mod.setdefault(sc_const, []).append(tnode_ref.label)
                        for fb_const in sa.fallback_constants:
                            fb_consts_in_mod.setdefault(fb_const, []).append(tnode_ref.label)
                result.edges.append(
                    AtlasEdge(
                        id=f"e:script:{rel}:reads_truth:{tid}",
                        source_id=src_nid,
                        target_id=tid,
                        kind="reads_truth",
                        verification="verified",
                        evidence_path=f"{rel}:1",
                        evidence_note=ev_note,
                        symbol_links=_scope_links(sc_set),
                        policy_field_consumption=edge_pfc,
                    )
                )
            for utid, sc_set in sorted(unmapped_read_scopes.items()):
                ulabel = utid.removeprefix("t:unmapped:")
                result.edges.append(
                    AtlasEdge(
                        id=f"e:script:{rel}:reads_truth:{utid}",
                        source_id=src_nid,
                        target_id=utid,
                        kind="reads_truth",
                        verification="unverified",
                        evidence_path=f"{rel}:1",
                        evidence_note=f"Unmapped SQL read reference to `{ulabel}`; no repository DDL/store declaration matched.",
                        symbol_links=_scope_links(sc_set),
                    )
                )
            for tid, sc_set in sorted(write_scopes_by_tid.items()):
                result.edges.append(
                    AtlasEdge(
                        id=f"e:script:{rel}:writes_truth:{tid}",
                        source_id=src_nid,
                        target_id=tid,
                        kind="writes_truth",
                        verification="verified",
                        evidence_path=f"{rel}:1",
                        evidence_note="Static SQL/ledger write reference; reachability and runtime store binding remain static.",
                        symbol_links=_scope_links(sc_set),
                    )
                )
            for utid, sc_set in sorted(unmapped_write_scopes.items()):
                ulabel = utid.removeprefix("t:unmapped:")
                result.edges.append(
                    AtlasEdge(
                        id=f"e:script:{rel}:writes_truth:{utid}",
                        source_id=src_nid,
                        target_id=utid,
                        kind="writes_truth",
                        verification="unverified",
                        evidence_path=f"{rel}:1",
                        evidence_note=f"Unmapped SQL write reference to `{ulabel}`; no repository DDL/store declaration matched.",
                        symbol_links=_scope_links(sc_set),
                    )
                )
            for fn_ref, sc_set in sorted(io.sql_calls.items()):
                fn_id = truth.function_symbol_map.get(fn_ref)
                if fn_id:
                    result.edges.append(
                        AtlasEdge(
                            id=f"e:script:{rel}:guards_truth:{fn_id}",
                            source_id=src_nid,
                            target_id=fn_id,
                            kind="guards_truth",
                            verification="declared",
                            evidence_path=f"{rel}:1",
                            evidence_note=f"Static SQL call to `{fn_ref}`.",
                            symbol_links=_scope_links(sc_set),
                        )
                    )
            if parsed is not None and mnode is not None:
                skip_manip1 = (
                    _is_test_module(rel)
                    or _is_pure_constant_module(trees[rel], io, parsed)
                )
                if not skip_manip1:
                    for const_name, lineno, sample in parsed.policy_literals:
                        mnode.status = "policy_in_code"
                        subst_tbls = list(dict.fromkeys(subst_consts_in_mod.get(const_name, ())))
                        fb_tbls = list(dict.fromkeys(fb_consts_in_mod.get(const_name, ())))
                        usage_suffix = ""
                        if subst_tbls:
                            tbl_list = ", ".join(f"`{t}`" for t in subst_tbls)
                            usage_suffix = f" Overrides database policy column(s) on {tbl_list} in reader output."
                        elif fb_tbls:
                            tbl_list = ", ".join(f"`{t}`" for t in fb_tbls)
                            usage_suffix = f" Used as null/falsy fallback alongside {tbl_list} policy read."
                        result.findings.append(
                            RawCandidateFinding(
                                rule_code="MANIP-001",
                                node_id=src_nid,
                                source_file=rel,
                                line=lineno,
                                title=f"Hardcoded policy constant `{const_name}` ({sample})",
                                detail=(
                                    f"{rel}:{lineno} defines mutable domain policy "
                                    f"`{const_name}` in Python code.{usage_suffix}"
                                ),
                                remediation=(
                                    "Move policy threshold/vocabulary into database/registry truth "
                                    "and read via snapshot."
                                ),
                            )
                        )
                if PurePosixPath(rel).name not in clock_allow_modules:
                    for clock_expr, lineno in parsed.raw_clock_calls:
                        if mnode.status == "clean":
                            mnode.status = "gray_zone"
                        result.findings.append(
                            RawCandidateFinding(
                                rule_code="MANIP-002",
                                node_id=src_nid,
                                source_file=rel,
                                line=lineno,
                                title=f"Direct host clock call `{clock_expr}`",
                                detail=f"{rel}:{lineno} calls `{clock_expr}` directly instead of shared DB/program time.",
                                remediation="Read current date/instant from the shared clock authority module.",
                            )
                        )

        dynamic = 0
        for rel, tree in trees.items():
            hits = _imports(tree, rel, py_paths, roots)
            dynamic_hits, unresolved = _dynamic_imports(tree, rel, py_paths, roots)
            hits.update(dynamic_hits)
            dynamic += unresolved
            src_pm = parsed_mods.get(rel)
            rkeys = route_keys_by_rel.get(rel, {})
            scope_qcalls = _collect_scope_qualified_calls(tree)
            for target in sorted(hits):
                tgt_pm = parsed_mods.get(target)
                imp_links: list[str] = []
                direct_alias_to_orig, mod_prefixes, has_star = _target_import_bindings(
                    tree, rel, target, roots
                )
                if src_pm is not None and tgt_pm is not None:
                    for sc, c_syms in sorted(src_pm.func_calls.items()):
                        sc_qcalls = scope_qcalls.get(sc, set())
                        if sc_qcalls:
                            matched = _match_qualified_calls(
                                sc_qcalls,
                                direct_alias_to_orig,
                                mod_prefixes,
                                has_star,
                                src_pm,
                                tgt_pm,
                            )
                        else:
                            matched = []
                        if not matched:
                            continue
                        callers_k = [sc, *rkeys.get(sc, ())]
                        for ck in callers_k:
                            for cal in matched:
                                pair = f"{ck}->{cal}"
                                if pair not in imp_links:
                                    imp_links.append(pair)
                result.edges.append(
                    AtlasEdge(
                        id=f"e:import:{rel}:{target}",
                        source_id=script_id(rel),
                        target_id=script_id(target),
                        kind="calls_helper",
                        verification="declared",
                        evidence_path=f"{rel}:1",
                        evidence_note="Static Python import or literal importlib target, including possible package initialization; conditional imports and search-path precedence are not evaluated.",
                        symbol_links=imp_links,
                    )
                )
                # Connect daemon route nodes directly to imported helper modules invoked inside route handlers.
                for rdesc in result.routes:
                    if rdesc.source_file != rel or tgt_pm is None:
                        continue
                    qcalls = route_qualified_calls.get(
                        (rdesc.node_id, rdesc.http_method, rdesc.full_path), set()
                    )
                    shared = _match_qualified_calls(
                        qcalls,
                        direct_alias_to_orig,
                        mod_prefixes,
                        has_star,
                        src_pm,
                        tgt_pm,
                    )
                    if shared:
                        rk = f"{rdesc.http_method} {rdesc.full_path}"
                        result.edges.append(
                            AtlasEdge(
                                id=f"e:route:{rdesc.node_id}->{script_id(target)}",
                                source_id=rdesc.node_id,
                                target_id=script_id(target),
                                kind="calls_helper",
                                verification="verified",
                                evidence_path=f"{rel}:{rdesc.line}",
                                evidence_note=f"Route handler `{rk}` invokes imported helper `{shared[0]}` in `{target}`.",
                                symbol_links=[f"{rk}->{s}" for s in shared],
                            )
                        )
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
        dedup_edges: dict[str, AtlasEdge] = {}
        for edge in result.edges:
            prev = dedup_edges.get(edge.id)
            if prev is None:
                dedup_edges[edge.id] = edge
            elif edge.symbol_links:
                prev.symbol_links = list(dict.fromkeys([*prev.symbol_links, *edge.symbol_links]))
        result.edges[:] = list(dedup_edges.values())

        # Populate read_by_count, written_by_count, and SQL policy_field_consumption on truth.nodes.
        readers_by_tid: dict[str, set[str]] = {}
        writers_by_tid: dict[str, set[str]] = {}
        for edge in result.edges:
            if edge.kind in ("reads_truth", "guards_truth"):
                readers_by_tid.setdefault(edge.target_id, set()).add(edge.source_id)
            elif edge.kind == "writes_truth":
                writers_by_tid.setdefault(edge.target_id, set()).add(edge.source_id)
        for tid, db_r in truth.db_readers.items():
            readers_by_tid.setdefault(tid, set()).update(db_r.keys())
        for tnode in truth.nodes:
            if tnode.subkind != "table":
                continue
            tnode.read_by_count = len(readers_by_tid.get(tnode.id, set()))
            tnode.written_by_count = len(writers_by_tid.get(tnode.id, set()))
            if sql_pfcs := sql_pfcs_by_tid.get(tnode.id):
                merged_tpfc = merge_policy_consumptions(
                    [*( [tnode.policy_field_consumption] if tnode.policy_field_consumption else [] ), *sql_pfcs]
                )
                if merged_tpfc is not None:
                    tnode.policy_field_consumption = merged_tpfc
                    tnode.verification_note = f"policy_field_consumption={merged_tpfc.state}"
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
                    "SQL and store coverage includes standalone DDL, inline SQLite/PostgreSQL CREATE statements, "
                    "append-only JSONL ledgers, and declarative JSON registries; runtime database selection and live schemas are not fully resolved."
                ),
            ]
        )
        if unmapped_sql_refs:
            samples = ", ".join(
                f"`{tbl}` ({rels[0]})" for tbl, rels in sorted(unmapped_sql_refs.items())[:8]
            )
            result.notes.append(
                f"Unmapped SQL table reference(s) without resolved repository DDL ({len(unmapped_sql_refs)}): {samples}."
            )
        result.notes.extend(f"Unparsed source: {rel}" for rel in failed)
        if not coverage_complete:
            result = replace(result, coverage_complete=False)
        return result
