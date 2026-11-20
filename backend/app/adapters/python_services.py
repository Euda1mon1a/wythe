"""Experimental module graph for Python services outside the FastAPI app/ layout."""

from __future__ import annotations

import ast
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
from app.adapters.python_daemon_routes import add_daemon_routes_and_subprocesses
from app.adapters.python_policy_consumption import (
    analyze_module_policy_table_read,
    classify_table_policy_columns,
    merge_policy_consumptions,
    summarize_edge_policy_consumption,
)
from app.adapters.registry_sources import add_registry_sources
from app.adapters.service_sources import EXCLUDED_PARTS, script_id, source_files, source_reference
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
        py_sources: dict[str, str] = {}
        parsed_mods: dict[str, ParsedPythonModule] = {}
        store_io_by_rel: dict[str, ModuleStoreIo] = {}
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
                py_sources[rel] = text
                entry = _has_main(tree)
                parsed = parse_python_module(text, rel, rel.removesuffix(".py").replace("/", "."))
                if parsed is not None:
                    parsed_mods[rel] = parsed
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
        roots = [list(base.relative_to(repo_root).parts)]
        if (base / "src").is_dir():
            roots.append([*roots[0], "src"])

        deployments, references = deployment_mappings(repo_root, trees, result)
        add_launchd_sources(repo_root, result, deployments)
        add_deployment_edges(result, references)
        route_keys_by_rel = add_daemon_routes_and_subprocesses(
            repo_root, trees, paths, py_paths, roots, deployments, result
        )
        add_registry_sources(
            repo_root,
            result,
            deployments,
            truth=truth,
            trees=trees,
            route_keys_by_rel=route_keys_by_rel,
        )

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
        known_bare_tables: set[str] = {
            k.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
            for k in truth.table_symbol_map
            if not k.startswith(("jsonl:", "registry:", "sqlc:"))
        }
        clock_allow_modules = ("clock.py", "program_time.py", "sql_clock.py")

        def _ensure_unmapped_table_node(raw_ref: str, first_rel: str) -> str | None:
            bare = raw_ref.split(".", 1)[1] if raw_ref.startswith(("public.", "main.", "dbo.")) else raw_ref
            if (
                not bare
                or len(bare) < 2
                or bare in known_bare_tables
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
                    verification_note="Unmapped SQL table reference; no DDL declaration resolved in repository.",
                )
                truth.nodes.append(utnode)
                tnode_by_id[unmapped_tid] = utnode
            if first_rel not in unmapped_sql_refs.setdefault(bare, []):
                unmapped_sql_refs[bare].append(first_rel)
            return unmapped_tid

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
                tid = resolve_store_target_id(ref, truth.table_symbol_map, io)
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
                tid = resolve_store_target_id(ref, truth.table_symbol_map, io)
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
                if not rel.startswith("adapters/") and "/adapters/" not in f"/{rel}":
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
            for target in sorted(hits):
                tgt_pm = parsed_mods.get(target)
                imp_links: list[str] = []
                if src_pm is not None and tgt_pm is not None:
                    t_defs = tgt_pm.defined | set(tgt_pm.class_attrs)
                    for sc, c_syms in sorted(src_pm.func_calls.items()):
                        matched = sorted(c_syms & t_defs)
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
                    shared = sorted(rdesc.called_symbols & (tgt_pm.defined | set(tgt_pm.class_attrs)))
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
        return result
