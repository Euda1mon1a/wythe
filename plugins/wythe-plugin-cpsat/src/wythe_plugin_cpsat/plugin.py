"""Wythe plugin registration and Zoom-1/Zoom-2/post-scan hooks for `wythe-plugin-cpsat`."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar, Literal

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.schemas.atlas import (
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TruthAtlasReport,
)
from wythe_plugin_cpsat.ast_extractor import (
    CpSatModuleModel,
    CpSatRepoExtraction,
    extract_repo_cpsat_models,
)
from wythe_plugin_cpsat.proto_companion import correlate_cpsat_companions


def _collect_static_cpsat_findings(
    extraction: CpSatRepoExtraction,
    node_id_by_file: dict[str, str],
) -> tuple[list[RawCandidateFinding], list[str]]:
    findings: list[RawCandidateFinding] = []
    notes: list[str] = []

    cpsat_mods = [m for m in extraction.modules.values() if m.is_cpsat_module]
    if not cpsat_mods:
        return findings, notes

    if extraction.registration_order:
        notes.append(
            f"CP-SAT constraint registration order: {' -> '.join(extraction.registration_order)}"
        )

    for b in extraction.unregistered_builders:
        nid = node_id_by_file.get(b.source_file)
        findings.append(
            RawCandidateFinding(
                rule_code="MANIP-003",
                node_id=nid,
                source_file=b.source_file,
                line=b.line,
                title=f"Exported CP-SAT constraint builder `{b.symbol}` is never registered in active solver pipelines",
                detail=(
                    f"{b.source_file}:{b.line} defines exported {b.kind} `{b.symbol}`, but no active "
                    "solver assembly function or constraint registry invokes it."
                ),
                remediation=(
                    f"Wire `{b.symbol}` into the solver constraint registration pipeline or retire "
                    "the unused builder."
                ),
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )

    total_hard_cts = 0
    total_assumptions = 0
    has_any_solve = False
    first_hard_anchor: tuple[str | None, str, int, str] | None = None

    for mod in sorted(cpsat_mods, key=lambda m: m.source_file):
        nid = node_id_by_file.get(mod.source_file)
        total_assumptions += len(mod.assumption_vars) + len(mod.assumption_lines)
        if any(r.solve_call_lines for r in mod.solver_runs):
            has_any_solve = True

        for ct in mod.constraints:
            if not ct.enforced_by_vars:
                total_hard_cts += 1
                if first_hard_anchor is None:
                    first_hard_anchor = (nid, ct.source_file, ct.line, ct.method)

        trunc_lines: set[int] = set()
        for tr in mod.truncations:
            trunc_lines.add(tr.line)
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-001",
                    node_id=nid,
                    source_file=tr.source_file,
                    line=tr.line,
                    title=f"Float-to-zero integer truncation `{tr.expr_text}` silently zeroes CP-SAT coefficient",
                    detail=(
                        f"{tr.source_file}:{tr.line} evaluates `{tr.expr_text}` ({tr.evaluated_float}) "
                        f"to integer `{tr.truncated_int}`, silently disabling the weighted soft term."
                    ),
                    remediation=(
                        "Scale integer penalty weights explicitly (e.g. basis-point integers stored in "
                        "persisted policy truth) instead of truncating fractional floats with `int(...)`."
                    ),
                    confidence="confirmed",
                    evidence_strength="ast_exact",
                )
            )

        for obj in mod.objectives:
            hardcoded_terms = [
                t
                for t in obj.terms
                if t.static_weight is not None
                and t.truncated_from_float is None
                and abs(t.static_weight) not in (0, 1)
                and t.line not in trunc_lines
            ]
            if hardcoded_terms:
                weights_desc = ", ".join(
                    f"{t.static_weight} ({t.expr_text})" for t in hardcoded_terms[:5]
                )
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-001",
                        node_id=nid,
                        source_file=obj.source_file,
                        line=hardcoded_terms[0].line,
                        title=f"Hardcoded integer penalty tower in `model.{obj.sense.capitalize()}(...)`",
                        detail=(
                            f"{obj.source_file}:{hardcoded_terms[0].line} embeds hardcoded objective "
                            f"penalty weights [{weights_desc}] directly in manipulation code."
                        ),
                        remediation=(
                            "Load objective penalty weights from persisted Truth policy tables with "
                            "an explicit non-empty table guard."
                        ),
                        confidence="confirmed",
                        evidence_strength="ast_exact",
                    )
                )

        for lp in mod.unguarded_loops:
            findings.append(
                RawCandidateFinding(
                    rule_code="TRUTH-001",
                    node_id=nid,
                    source_file=lp.source_file,
                    line=lp.line,
                    title=f"Dynamic CP-SAT rule loop over `{lp.iterable_expr}` lacks an empty-table guard",
                    detail=(
                        f"{lp.source_file}:{lp.line} (`{lp.function_name}`) iterates over Truth rows "
                        f"`{lp.iterable_expr}` without checking for zero rows; an unseeded table silently "
                        "sheds constraints or objective penalties as a no-op."
                    ),
                    remediation=(
                        f"Guard `{lp.iterable_expr}` (`if not rows:` / `len(rows) == 0`) before "
                        "assembling `CpModel` constraints or objective terms."
                    ),
                    confidence="confirmed",
                    evidence_strength="ast_exact",
                )
            )

        for run in mod.solver_runs:
            if run.status_masked:
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-001",
                        node_id=nid,
                        source_file=run.source_file,
                        line=run.status_mask_line or run.line,
                        title=f"Multi-stage `CpSolver` orchestration in `{run.function_name}` masks `FEASIBLE` status",
                        detail=run.status_mask_detail,
                        remediation=(
                            "Preserve each solver stage's status distinctly and downgrade overall run "
                            "status to `FEASIBLE` whenever the primary stage finishes non-optimally."
                        ),
                        confidence="confirmed",
                        evidence_strength="ast_exact",
                    )
                )
            if run.missing_bound_gap:
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-001",
                        node_id=nid,
                        source_file=run.source_file,
                        line=run.missing_bound_gap_line or run.line,
                        title=f"`FEASIBLE` branch in `{run.function_name}` omits `(ObjectiveValue(), BestObjectiveBound())` gap",
                        detail=(
                            f"{run.source_file}:{run.missing_bound_gap_line or run.line} accepts `FEASIBLE` "
                            "solutions without recording both `solver.ObjectiveValue()` and "
                            "`solver.BestObjectiveBound()` optimality-gap metrics."
                        ),
                        remediation=(
                            "Persist both `solver.ObjectiveValue()` and `solver.BestObjectiveBound()` "
                            "whenever accepting `FEASIBLE` or `OPTIMAL` solver outcomes."
                        ),
                        confidence="confirmed",
                        evidence_strength="ast_exact",
                    )
                )
            if run.unguarded_cpu_workers:
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-001",
                        node_id=nid,
                        source_file=run.source_file,
                        line=run.unguarded_cpu_workers_line or run.line,
                        title=f"Unguarded `os.cpu_count()` worker assignment in `{run.function_name}`",
                        detail=(
                            f"{run.source_file}:{run.unguarded_cpu_workers_line or run.line} sets "
                            "`solver.parameters.num_search_workers` from `cpu_count()` without an "
                            "explicit deterministic cap."
                        ),
                        remediation="Clamp worker parallelism via `min(policy_cap, os.cpu_count() or 1)`.",
                        confidence="confirmed",
                        evidence_strength="ast_exact",
                    )
                )
            if run.missing_max_time:
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-001",
                        node_id=nid,
                        source_file=run.source_file,
                        line=run.solve_call_lines[0] if run.solve_call_lines else run.line,
                        title=f"`CpSolver` invocation in `{run.function_name}` omits `max_time_in_seconds` bound",
                        detail=(
                            f"{run.source_file}:{run.line} executes `CpSolver.Solve(...)` without setting "
                            "`solver.parameters.max_time_in_seconds`."
                        ),
                        remediation="Configure `solver.parameters.max_time_in_seconds` from persisted solver policy.",
                        confidence="confirmed",
                        evidence_strength="ast_exact",
                    )
                )

    if has_any_solve and total_hard_cts > 0 and total_assumptions == 0 and first_hard_anchor is not None:
        h_nid, h_file, h_line, h_method = first_hard_anchor
        findings.append(
            RawCandidateFinding(
                rule_code="MANIP-003",
                node_id=h_nid,
                source_file=h_file,
                line=h_line,
                title=f"Hard `CpModel` constraint group ({total_hard_cts} constraints) has zero assumption literals",
                detail=(
                    f"{h_file}:{h_line} (`{h_method}`) and {total_hard_cts - 1} peer hard constraint(s) "
                    "configure zero `AddAssumptions` or `OnlyEnforceIf` indicator literals for unsat-core diagnosis."
                ),
                remediation=(
                    "Attach named boolean assumption literals via `OnlyEnforceIf` and `model.AddAssumptions(...)` "
                    "to extract `sufficient_assumptions_for_infeasibility` cores on `INFEASIBLE` runs."
                ),
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )

    return findings, notes


def _active_modules_for_node(
    node_id: str,
    report: TruthAtlasReport,
    extraction: CpSatRepoExtraction,
) -> list[CpSatModuleModel]:
    node_by_id = {n.id: n for n in report.nodes}
    parent = node_by_id.get(node_id)
    if parent is None:
        return []
    files: list[str] = [parent.source_file]
    for edge in report.edges:
        if edge.source_id == node_id and edge.kind == "calls_helper":
            tgt = node_by_id.get(edge.target_id)
            if tgt is not None and tgt.source_file not in files:
                files.append(tgt.source_file)
    return [
        extraction.modules[sf]
        for sf in files
        if sf in extraction.modules and extraction.modules[sf].is_cpsat_module
    ]


def _badges_for_modules(mods: list[CpSatModuleModel]) -> list[StratumSummaryBadge]:
    n_vars = sum(len(m.variables) for m in mods)
    n_cts = sum(len(m.constraints) for m in mods)
    n_objs = sum(len(o.terms) for m in mods for o in m.objectives)
    assump_syms = {a for m in mods for a in m.assumption_vars}
    n_assump = max(len(assump_syms), sum(len(m.assumption_lines) for m in mods))
    return [
        StratumSummaryBadge(key="cp_vars", label="CP-SAT Variables", count=n_vars),
        StratumSummaryBadge(key="cp_constraints", label="CP-SAT Constraints", count=n_cts),
        StratumSummaryBadge(key="cp_objective_terms", label="Objective Terms", count=n_objs),
        StratumSummaryBadge(key="cp_assumptions", label="Assumption Literals", count=n_assump),
    ]


def _build_param_alias_map(extraction: CpSatRepoExtraction) -> dict[tuple[str, str], str]:
    builder_params: dict[str, tuple[str, ...]] = {}
    for mod in extraction.modules.values():
        for b in mod.builders:
            if b.param_names:
                builder_params[b.symbol] = b.param_names

    aliases: dict[tuple[str, str], str] = {}
    for mod in extraction.modules.values():
        for run in mod.solver_runs:
            for callee, arg_idx, caller_sym in run.call_arg_var_map:
                p_names = builder_params.get(callee, ())
                if 0 <= arg_idx < len(p_names):
                    aliases[(callee, p_names[arg_idx])] = caller_sym
    return aliases


def _expand_cpsat_zoom2(
    node_id: str,
    report: TruthAtlasReport,
    extraction: CpSatRepoExtraction,
) -> StratumExpansionResult:
    mods = _active_modules_for_node(node_id, report, extraction)
    if not mods:
        return StratumExpansionResult()

    aliases = _build_param_alias_map(extraction)
    repo_var_decls = {
        v.symbol: v
        for m in extraction.modules.values()
        if m.is_cpsat_module
        for v in m.variables
    }
    local_var_decls: dict[str, tuple[str, str, int, str]] = {}
    for m in mods:
        for v in m.variables:
            local_var_decls.setdefault(v.symbol, (v.family, v.source_file, v.line, v.function_name))
        for a_sym in m.assumption_vars:
            if a_sym not in local_var_decls:
                rv = repo_var_decls.get(a_sym)
                if rv is not None:
                    local_var_decls[a_sym] = (rv.family, rv.source_file, rv.line, rv.function_name)
                else:
                    ln = m.assumption_lines[0] if m.assumption_lines else 1
                    local_var_decls[a_sym] = ("bool_var", m.source_file, ln, "assumption")

    def _resolve_sym(fn_name: str, sym: str) -> str | None:
        mapped = aliases.get((fn_name, sym), sym)
        if mapped in local_var_decls:
            return mapped
        if mapped in repo_var_decls:
            rv = repo_var_decls[mapped]
            local_var_decls[mapped] = (rv.family, rv.source_file, rv.line, rv.function_name)
            return mapped
        return None

    micro_nodes: list[StratumMicroNode] = []
    micro_edges: list[StratumMicroEdge] = []

    ct_counter = 0
    for m in mods:
        for ct in m.constraints:
            ct_counter += 1
            ct_id = f"z2:{node_id}:ct:{ct_counter}:{ct.function_name}:{ct.method}"
            micro_nodes.append(
                StratumMicroNode(
                    id=ct_id,
                    label=f"{ct.function_name}:{ct.method}",
                    kind="cp_constraint",
                    zoom=2,
                    source_file=ct.source_file,
                    line=ct.line,
                    verification="verified",
                    summary=f"{ct.constraint_type} constraint in `{ct.function_name}`",
                )
            )
            chan_set = {
                r for s in ct.channel_target_vars if (r := _resolve_sym(ct.function_name, s))
            }
            enf_set = {
                r for s in ct.enforced_by_vars if (r := _resolve_sym(ct.function_name, s))
            }
            ref_list = [
                r for s in ct.referenced_vars if (r := _resolve_sym(ct.function_name, s))
            ]

            for es in sorted(enf_set):
                var_id = f"z2:{node_id}:var:{es}"
                micro_edges.append(
                    StratumMicroEdge(
                        id=f"e:{ct_id}->enforced:{es}",
                        source_id=ct_id,
                        target_id=var_id,
                        label="enforced_by_literal",
                        kind="enforced_by_literal",
                        verification="verified",
                        evidence_note=f"Half-reified enforcement via `{es}`",
                    )
                )

            for rs in dict.fromkeys([*sorted(chan_set), *ref_list]):
                var_id = f"z2:{node_id}:var:{rs}"
                ekind = "channels_var" if ct.is_channeling else "constrains_var"
                micro_edges.append(
                    StratumMicroEdge(
                        id=f"e:{ct_id}->{ekind}:{rs}",
                        source_id=ct_id,
                        target_id=var_id,
                        label=ekind,
                        kind=ekind,
                        verification="verified",
                        evidence_note=f"`{ct.method}` {ekind} `{rs}`",
                    )
                )

        for o_idx, obj in enumerate(m.objectives, start=1):
            obj_id = f"z2:{node_id}:obj:{o_idx}:{obj.sense}"
            micro_nodes.append(
                StratumMicroNode(
                    id=obj_id,
                    label=f"{obj.sense}:{obj.function_name}",
                    kind="cp_objective",
                    zoom=2,
                    source_file=obj.source_file,
                    line=obj.line,
                    verification="verified",
                    summary=f"{obj.sense.capitalize()} objective ({len(obj.terms)} term(s))",
                )
            )
            for s in obj.referenced_vars:
                rs = _resolve_sym(obj.function_name, s)
                if rs:
                    var_id = f"z2:{node_id}:var:{rs}"
                    micro_edges.append(
                        StratumMicroEdge(
                            id=f"e:{obj_id}->constrains_var:{rs}",
                            source_id=obj_id,
                            target_id=var_id,
                            label="constrains_var",
                            kind="constrains_var",
                            verification="verified",
                            evidence_note=f"Objective {obj.sense} term references `{rs}`",
                        )
                    )

    for v_sym, (v_fam, v_sf, v_ln, v_fn) in sorted(local_var_decls.items()):
        micro_nodes.append(
            StratumMicroNode(
                id=f"z2:{node_id}:var:{v_sym}",
                label=v_sym,
                kind="cp_var",
                zoom=2,
                source_file=v_sf,
                line=v_ln,
                verification="verified",
                summary=f"{v_fam} decision variable in `{v_fn}`",
            )
        )

    return StratumExpansionResult(
        summary_badges=_badges_for_modules(mods),
        nodes=micro_nodes,
        edges=micro_edges,
    )



class CpSatLineagePlugin:
    """Multi-hook Wythe plugin for OR-Tools CP-SAT lineage, Zoom-2 strata, and companion protos."""

    name = "cpsat"
    version = "0.1.0"
    description = (
        "Pure-Python OR-Tools CP-SAT domain lineage, Zoom-2 variable-constraint lattice, "
        "and CpModelProto/CpSolverResponse companion correlator."
    )
    supported_zooms: tuple[int, ...] = (2,)
    enabled_by_default: bool = True
    companion_handlers: ClassVar[dict[str, Callable[..., Any]]] = {
        "cpsat": correlate_cpsat_companions,
    }

    def __init__(self) -> None:
        self.__dict__["companion_handlers"] = {"cpsat": correlate_cpsat_companions}

    def augment_manipulator(
        self,
        repo_root: Path,
        backend_subdir: str,
        result: ManipulatorExtractionResult,
    ) -> None:
        extraction = extract_repo_cpsat_models(repo_root, backend_subdir)
        node_by_file = {n.source_file: n.id for n in result.nodes}
        cand_findings, notes = _collect_static_cpsat_findings(extraction, node_by_file)
        existing_keys = {(f.rule_code, f.source_file, f.line) for f in result.findings}
        for cf in cand_findings:
            fkey = (cf.rule_code, cf.source_file, cf.line)
            if fkey not in existing_keys:
                existing_keys.add(fkey)
                result.findings.append(cf)
        for nt in notes:
            if nt not in result.notes:
                result.notes.append(nt)

    def check_report(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
    ) -> dict[str, object]:
        extraction = extract_repo_cpsat_models(repo_root)
        cpsat_mods = [m for m in extraction.modules.values() if m.is_cpsat_module]
        if not cpsat_mods:
            return {
                "cpsat_detected": False,
                "findings": [],
                "notes": [],
            }

        node_by_id = {n.id: n for n in report.nodes}
        node_id_by_file = {n.source_file: n.id for n in report.nodes}
        static_cands, notes = _collect_static_cpsat_findings(extraction, node_id_by_file)

        existing_keys = {(f.rule_code, f.source_file, f.line) for f in report.findings}
        out_findings: list[RawCandidateFinding] = []
        for cf in static_cands:
            fkey = (cf.rule_code, cf.source_file, cf.line)
            if fkey not in existing_keys:
                existing_keys.add(fkey)
                out_findings.append(cf)

        validator_nids = {
            n.id
            for n in report.nodes
            if n.tier == "manipulate"
            and (
                (n.source_file in extraction.modules and extraction.modules[n.source_file].is_validator_module)
                or "validator" in n.source_file.lower()
            )
        }
        solver_nids = {
            n.id
            for n in report.nodes
            if n.tier == "manipulate"
            and n.id not in validator_nids
            and n.source_file in extraction.modules
            and extraction.modules[n.source_file].is_cpsat_module
        }
        for edge in report.edges:
            if (
                edge.kind == "calls_helper"
                and edge.source_id in list(solver_nids)
                and edge.target_id not in validator_nids
            ):
                solver_nids.add(edge.target_id)

        sql_table_ids = {
            n.id for n in report.nodes if n.tier == "truth" and n.subkind == "table"
        }
        builder_only: list[str] = []
        validator_only: list[str] = []

        if solver_nids and validator_nids:
            solver_writes = {
                e.target_id
                for e in report.edges
                if e.kind == "writes_truth" and e.source_id in solver_nids
            }
            solver_reads = {
                e.target_id
                for e in report.edges
                if e.kind in ("reads_truth", "guards_truth")
                and e.source_id in solver_nids
                and e.target_id in sql_table_ids
            } - solver_writes
            validator_reads = {
                e.target_id
                for e in report.edges
                if e.kind in ("reads_truth", "guards_truth")
                and e.source_id in validator_nids
                and e.target_id in sql_table_ids
            } - solver_writes

            builder_only = sorted(solver_reads - validator_reads)
            validator_only = sorted(validator_reads - solver_reads)

            primary_val = node_by_id[min(validator_nids)]
            primary_sol = node_by_id[min(solver_nids)]

            for tbl_id in builder_only:
                tbl_lbl = node_by_id[tbl_id].label if tbl_id in node_by_id else tbl_id
                out_findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-001",
                        node_id=primary_val.id,
                        target_node_id=tbl_id,
                        source_file=primary_val.source_file,
                        line=primary_val.line,
                        title=f"Asymmetric Truth validation: post-solve validator omits `{tbl_lbl}` read by CpModel",
                        detail=(
                            f"CpModel assembly reads Truth table `{tbl_lbl}` (`{tbl_id}`), "
                            f"but post-solve validator `{primary_val.source_file}` never verifies it."
                        ),
                        remediation=(
                            f"Read and enforce `{tbl_lbl}` in `{primary_val.source_file}` so post-solve "
                            "validation mirrors active CpModel constraints."
                        ),
                        confidence="confirmed",
                        evidence_strength="structural_match",
                    )
                )
            for tbl_id in validator_only:
                tbl_lbl = node_by_id[tbl_id].label if tbl_id in node_by_id else tbl_id
                out_findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-001",
                        node_id=primary_sol.id,
                        target_node_id=tbl_id,
                        source_file=primary_sol.source_file,
                        line=primary_sol.line,
                        title=f"Asymmetric Truth validation: CpModel assembly omits `{tbl_lbl}` checked by validator",
                        detail=(
                            f"Post-solve validator checks Truth table `{tbl_lbl}` (`{tbl_id}`), "
                            f"but CpModel assembly `{primary_sol.source_file}` never reads it."
                        ),
                        remediation=(
                            f"Incorporate `{tbl_lbl}` into `{primary_sol.source_file}` constraint assembly "
                            "or align validator rule scope."
                        ),
                        confidence="confirmed",
                        evidence_strength="structural_match",
                    )
                )
            if builder_only or validator_only:
                notes.append(
                    f"CP-SAT Truth asymmetry: builder_only={builder_only}, validator_only={validator_only}"
                )

        return {
            "cpsat_detected": True,
            "findings": out_findings,
            "notes": notes,
            "registration_order": list(extraction.registration_order),
            "unregistered_builders": [b.symbol for b in extraction.unregistered_builders],
            "validator_asymmetry": {
                "builder_only_tables": builder_only,
                "validator_only_tables": validator_only,
            },
        }

    def summarize_zoom1_badges(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
    ) -> dict[str, list[StratumSummaryBadge]]:
        extraction = extract_repo_cpsat_models(repo_root)
        if not any(m.is_cpsat_module for m in extraction.modules.values()):
            return {}

        badges_by_nid: dict[str, list[StratumSummaryBadge]] = {}
        for node in report.nodes:
            if node.tier != "manipulate":
                continue
            mods = _active_modules_for_node(node.id, report, extraction)
            if not mods:
                continue
            if node.subkind == "solver" or (
                node.source_file in extraction.modules
                and extraction.modules[node.source_file].is_cpsat_module
            ):
                badges_by_nid[node.id] = _badges_for_modules(mods)
        return badges_by_nid

    def expand_node_stratum(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
        node_id: str,
        zoom: Literal[2, 3],
    ) -> StratumExpansionResult:
        if zoom != 2:
            return StratumExpansionResult()
        extraction = extract_repo_cpsat_models(repo_root)
        return _expand_cpsat_zoom2(node_id, report, extraction)


WYTHE_PLUGIN = CpSatLineagePlugin()


def register_wythe_plugin() -> CpSatLineagePlugin:
    """Entry-point factory registered under `[project.entry-points.\"wythe.plugins\"]`."""
    return WYTHE_PLUGIN
