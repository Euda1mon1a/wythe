"""Wythe `StratumPlugin`, `PostScanCheckPlugin`, and companion handler for `#85`."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from app.adapters import plugin_registry
from app.adapters.base import RawCandidateFinding
from app.adapters.plugin_registry import PluginRuleSpec, WythePluginSpec
from app.schemas.atlas import (
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TruthAtlasReport,
)
from wythe_plugin_solver_internals.param_lineage import (
    ParamLineageReport,
    trace_sat_parameter_lineage,
)
from wythe_plugin_solver_internals.proto_descriptor import (
    MAX_SOLVER_FILE_BYTES,
    UPSTREAM_ORTOOLS_REF,
    SolverProtoCatalog,
    build_solver_proto_catalog,
)
from wythe_plugin_solver_internals.singleton_graph import (
    SingletonGraphReport,
    build_singleton_zoom2_subgraph,
    extract_singleton_dependency_graph,
)
from wythe_plugin_solver_internals.stage_matrix import (
    EPISTEMIC_STAGE_NOTE,
    PIPELINE_STAGES,
    CppUsrIndex,
    StageMatrixReport,
    build_constraint_stage_matrix,
    load_cpp_usr_index,
    parse_compile_commands_files,
)
from wythe_plugin_solver_internals.wrapper_parity import (
    WrapperParityReport,
    check_host_wrapper_parity,
)

SOLVER_INTERNALS_RULES: tuple[PluginRuleSpec, ...] = (
    PluginRuleSpec(
        rule_code="SAT-INT-001",
        tier="manipulate",
        title="Asymmetric ConstraintProto or enforcement_literal coverage across C++ solver pipeline stages",
        severity="warning",
        blocks_gate=False,
        confidence="confirmed",
        evidence_strength="structural_match",
    ),
    PluginRuleSpec(
        rule_code="SAT-INT-002",
        tier="manipulate",
        title="Hardcoded C++ solver work-limit or clause/domain heuristic threshold bypasses SatParameters",
        severity="warning",
        blocks_gate=False,
        confidence="confirmed",
        evidence_strength="ast_exact",
    ),
    PluginRuleSpec(
        rule_code="SAT-INT-003",
        tier="manipulate",
        title="Hidden cyclic Model::GetOrCreate<T>() singleton constructor dependency",
        severity="warning",
        blocks_gate=False,
        confidence="confirmed",
        evidence_strength="ast_exact",
    ),
    PluginRuleSpec(
        rule_code="SAT-INT-004",
        tier="display",
        title="Host-language solver wrapper omits ConstraintProto case or exposes deprecated SatParameters alias",
        severity="warning",
        blocks_gate=False,
        confidence="confirmed",
        evidence_strength="structural_match",
    ),
)


@dataclass(frozen=True)
class SolverInternalsAnalysis:
    solver_engine_detected: bool
    proto_catalog: SolverProtoCatalog
    usr_index: CppUsrIndex
    compile_command_files: tuple[str, ...]
    stage_matrix: StageMatrixReport
    param_lineage: ParamLineageReport
    singleton_graph: SingletonGraphReport
    wrapper_parity: WrapperParityReport
    findings: tuple[RawCandidateFinding, ...]
    notes: tuple[str, ...]


def _normalize_artifact_list(*raw_inputs: object) -> list[str]:
    out: list[str] = []
    for item in raw_inputs:
        if item is None:
            continue
        if isinstance(item, (str, Path)):
            s = str(item).strip()
            if s and s not in out:
                out.append(s)
        elif isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray)):
            for sub in item:
                if not isinstance(sub, (str, Path)):
                    raise ValueError(f"Invalid artifact path entry: {sub!r}")  # noqa: TRY004
                s = str(sub).strip()
                if s and s not in out:
                    out.append(s)
        else:
            raise ValueError(f"Invalid artifact path argument: {item!r}")  # noqa: TRY004
    return out


def _collect_artifact_inputs(
    *,
    proto_descriptor: object = None,
    index_store: object = None,
    compile_commands: object = None,
) -> tuple[list[str], list[str], list[str]]:
    active_fn = getattr(plugin_registry, "get_active_stratum_artifacts", None)
    active = active_fn() if callable(active_fn) else {}
    if not isinstance(active, dict):
        active = {}
    desc_list = _normalize_artifact_list(proto_descriptor, active.get("proto_descriptor"))
    idx_list = _normalize_artifact_list(index_store, active.get("index_store"))
    cc_list = _normalize_artifact_list(compile_commands, active.get("compile_commands"))
    return desc_list, idx_list, cc_list


def analyze_solver_internals(
    repo_root: Path | str,
    *,
    report: TruthAtlasReport | None = None,
    proto_descriptor: object = None,
    index_store: object = None,
    compile_commands: object = None,
    include_manip_001: bool = False,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> SolverInternalsAnalysis:
    """Run full read-only C++/Protobuf solver-internals extraction on `repo_root`."""
    root_p = Path(repo_root)
    desc_paths, idx_paths, cc_paths = _collect_artifact_inputs(
        proto_descriptor=proto_descriptor,
        index_store=index_store,
        compile_commands=compile_commands,
    )
    node_id_by_file = (
        {n.source_file: n.id for n in report.nodes}
        if report is not None
        else {}
    )

    catalog = build_solver_proto_catalog(root_p, descriptor_paths=desc_paths, max_bytes=max_bytes)
    usr_idx = load_cpp_usr_index(idx_paths, repo_root=root_p, max_bytes=max_bytes) if idx_paths else CppUsrIndex()
    cc_files = (
        parse_compile_commands_files(cc_paths, repo_root=root_p, max_bytes=max_bytes)
        if cc_paths
        else ()
    )

    stage_rep = build_constraint_stage_matrix(
        root_p,
        catalog,
        usr_index=usr_idx,
        compile_command_files=cc_files,
        node_id_by_file=node_id_by_file,
        max_bytes=max_bytes,
    )
    param_rep = trace_sat_parameter_lineage(
        root_p,
        catalog,
        node_id_by_file=node_id_by_file,
        include_manip_001=include_manip_001,
        max_bytes=max_bytes,
    )
    singleton_rep = extract_singleton_dependency_graph(
        root_p,
        usr_index=usr_idx,
        node_id_by_file=node_id_by_file,
        max_bytes=max_bytes,
    )
    wrapper_rep = check_host_wrapper_parity(
        root_p,
        catalog,
        node_id_by_file=node_id_by_file,
        max_bytes=max_bytes,
    )

    detected = bool(
        catalog.constraint_cases
        or catalog.sat_parameters
        or singleton_rep.dependencies
        or (stage_rep.active_stages and param_rep.knobs)
    )
    if not detected:
        return SolverInternalsAnalysis(
            solver_engine_detected=False,
            proto_catalog=catalog,
            usr_index=usr_idx,
            compile_command_files=cc_files,
            stage_matrix=stage_rep,
            param_lineage=param_rep,
            singleton_graph=singleton_rep,
            wrapper_parity=wrapper_rep,
            findings=(),
            notes=(),
        )

    findings = (
        *stage_rep.findings,
        *param_rep.findings,
        *singleton_rep.findings,
        *wrapper_rep.findings,
    )
    notes = (
        EPISTEMIC_STAGE_NOTE,
        (
            f"solver-internals: {len(catalog.constraint_cases)} ConstraintProto cases across "
            f"{len(stage_rep.active_stages)}/7 stages, {len(param_rep.knobs)} SatParameters knobs, "
            f"{len(singleton_rep.singletons)} Model singletons ({len(singleton_rep.cycles)} cycle(s)), "
            f"and {len(wrapper_rep.wrapper_files) + len(wrapper_rep.binding_shim_files)} host wrapper(s)."
        ),
    )
    return SolverInternalsAnalysis(
        solver_engine_detected=True,
        proto_catalog=catalog,
        usr_index=usr_idx,
        compile_command_files=cc_files,
        stage_matrix=stage_rep,
        param_lineage=param_rep,
        singleton_graph=singleton_rep,
        wrapper_parity=wrapper_rep,
        findings=findings,
        notes=notes,
    )


def _summary_badges_for_analysis(analysis: SolverInternalsAnalysis) -> list[StratumSummaryBadge]:
    return [
        StratumSummaryBadge(
            key="proto_constraints",
            label="ConstraintProto Cases",
            count=len(analysis.proto_catalog.constraint_cases),
        ),
        StratumSummaryBadge(
            key="pipeline_stages",
            label="Solver C++ Stages",
            count=len(analysis.stage_matrix.active_stages),
        ),
        StratumSummaryBadge(
            key="sat_param_knobs",
            label="SatParameters Knobs",
            count=len(analysis.param_lineage.knobs),
        ),
        StratumSummaryBadge(
            key="model_singletons",
            label="Model Singletons",
            count=len(analysis.singleton_graph.singletons),
        ),
    ]


def _solver_related_files(analysis: SolverInternalsAnalysis) -> set[str]:
    files: set[str] = set(analysis.proto_catalog.descriptor_sources)
    for st_files in analysis.stage_matrix.stage_files.values():
        files.update(st_files)
    files.update(analysis.param_lineage.consumption_by_file)
    for decl in analysis.singleton_graph.singletons.values():
        files.add(decl.source_file)
    files.update(analysis.wrapper_parity.wrapper_files)
    files.update(analysis.wrapper_parity.binding_shim_files)
    return files


def summarize_solver_internals_badges(
    repo_root: Path,
    report: TruthAtlasReport,
) -> dict[str, list[StratumSummaryBadge]]:
    """Attach compact Zoom-1 badges without mutating `Zoom 1` `content_digest`."""
    analysis = analyze_solver_internals(repo_root, report=report)
    if not analysis.solver_engine_detected:
        return {}
    badges = _summary_badges_for_analysis(analysis)
    solver_files = _solver_related_files(analysis)
    matched = [
        n.id
        for n in report.nodes
        if n.source_file in solver_files or n.subkind == "solver"
    ]
    if not matched:
        matched = [n.id for n in report.nodes if n.tier == "manipulate"]
    return {nid: list(badges) for nid in matched}


def expand_solver_internals_stratum(
    repo_root: Path,
    report: TruthAtlasReport,
    node_id: str,
    zoom: Literal[2, 3],
) -> StratumExpansionResult:
    """Emit Zoom-2 pipeline stage coverage and `Model::GetOrCreate<T>()` singleton subgraphs."""
    if zoom != 2:
        return StratumExpansionResult()
    if report.nodes and all(n.id != node_id for n in report.nodes):
        return StratumExpansionResult()

    analysis = analyze_solver_internals(repo_root, report=report)
    if not analysis.solver_engine_detected:
        return StratumExpansionResult()

    micro_nodes: list[StratumMicroNode] = []
    micro_edges: list[StratumMicroEdge] = []

    for st in PIPELINE_STAGES:
        st_files = analysis.stage_matrix.stage_files.get(st, ())
        if not st_files:
            continue
        micro_nodes.append(
            StratumMicroNode(
                id=f"z2:{node_id}:stage:{st}",
                label=f"Stage:{st}",
                kind="solver_pipeline_stage",
                zoom=2,
                source_file=st_files[0],
                line=1,
                verification="verified",
                summary=f"Solver pipeline stage `{st}` ({', '.join(st_files[:3])})",
            )
        )

    for row in analysis.stage_matrix.rows:
        ct_nid = f"z2:{node_id}:constraint:{row.case_name}"
        src_f, _, ln_s = row.proto_location.partition(":")
        ln_int = int(ln_s) if ln_s.isdigit() else 1
        micro_nodes.append(
            StratumMicroNode(
                id=ct_nid,
                label=f"ConstraintProto.{row.case_name}",
                kind="proto_constraint_case",
                zoom=2,
                source_file=src_f or None,
                line=ln_int,
                verification="unverified" if row.asymmetric else "verified",
                summary=(
                    f"`{row.message_type}` covered in {len(row.covered_stages)}/"
                    f"{len(analysis.stage_matrix.active_stages)} active stages"
                ),
            )
        )
        for st in row.covered_stages:
            cell = row.cells[st]
            st_nid = f"z2:{node_id}:stage:{st}"
            loc_str = ", ".join(cell.symbol_links[:2] or cell.locations[:2])
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{ct_nid}->stage:{st}",
                    source_id=ct_nid,
                    target_id=st_nid,
                    label="handled_in_stage",
                    kind="handled_in_stage",
                    verification="verified",
                    evidence_note=f"`{row.case_name}` handled in `{st}` ({loc_str})",
                )
            )

    sing_nodes, sing_edges = build_singleton_zoom2_subgraph(
        node_id, analysis.singleton_graph, usr_index=analysis.usr_index
    )
    micro_nodes.extend(sing_nodes)
    micro_edges.extend(sing_edges)

    return StratumExpansionResult(
        summary_badges=_summary_badges_for_analysis(analysis),
        nodes=micro_nodes,
        edges=micro_edges,
        notes=[EPISTEMIC_STAGE_NOTE],
    )


def _serialize_analysis_summary(analysis: SolverInternalsAnalysis) -> dict[str, object]:
    return {
        "solver_engine_detected": analysis.solver_engine_detected,
        "epistemic_notice": EPISTEMIC_STAGE_NOTE,
        "proto_catalog": {
            "descriptor_sources": list(analysis.proto_catalog.descriptor_sources),
            "constraint_cases": [c.name for c in analysis.proto_catalog.constraint_cases],
            "has_enforcement_literal": analysis.proto_catalog.has_enforcement_literal,
            "sat_parameter_count": len(analysis.proto_catalog.sat_parameters),
            "deprecated_parameters": sorted(
                k for k, f in analysis.proto_catalog.sat_parameters.items() if f.deprecated
            ),
        },
        "compile_commands": {
            "translation_unit_count": len(analysis.compile_command_files),
            "files": list(analysis.compile_command_files),
        },
        "usr_index": {
            "symbol_count": len(analysis.usr_index.symbols_by_usr),
            "sources": list(analysis.usr_index.sources),
        },
        "stage_matrix": {
            "stages": list(PIPELINE_STAGES),
            "active_stages": list(analysis.stage_matrix.active_stages),
            "rows": [
                {
                    "case_name": r.case_name,
                    "field_number": r.field_number,
                    "message_type": r.message_type,
                    "covered_stages": list(r.covered_stages),
                    "omitted_active_stages": list(r.omitted_active_stages),
                    "asymmetric": r.asymmetric,
                    "symbol_links": {
                        st: list(r.cells[st].symbol_links)
                        for st in r.covered_stages
                    },
                }
                for r in analysis.stage_matrix.rows
            ],
        },
        "param_lineage": {
            "consumed_knobs": [k.name for k in analysis.param_lineage.knobs if k.consumed],
            "unconsumed_knobs": [k.name for k in analysis.param_lineage.knobs if not k.consumed],
            "hardcoded_thresholds": [asdict(t) for t in analysis.param_lineage.hardcoded_thresholds],
            "overall_consumption": (
                analysis.param_lineage.overall_consumption.model_dump()
                if analysis.param_lineage.overall_consumption is not None
                else None
            ),
            "consumption_by_file": {
                sf: pfc.model_dump()
                for sf, pfc in sorted(analysis.param_lineage.consumption_by_file.items())
            },
        },
        "singleton_graph": {
            "singletons": sorted(analysis.singleton_graph.singletons),
            "dependency_count": len(analysis.singleton_graph.dependencies),
            "cycles": [list(c.chain) for c in analysis.singleton_graph.cycles],
        },
        "wrapper_parity": {
            "wrapper_files": list(analysis.wrapper_parity.wrapper_files),
            "binding_shim_files": list(analysis.wrapper_parity.binding_shim_files),
            "exposed_constraints": sorted(analysis.wrapper_parity.exposed_constraints),
            "unexposed_constraints": list(analysis.wrapper_parity.unexposed_constraints),
            "deprecated_aliases": [asdict(a) for a in analysis.wrapper_parity.deprecated_aliases],
        },
    }


def check_solver_internals_report(
    repo_root: Path,
    report: TruthAtlasReport,
) -> dict[str, object]:
    """Post-scan check emitting `SAT-INT-001..004` on solver engines (silent elsewhere)."""
    analysis = analyze_solver_internals(repo_root, report=report)
    if not analysis.solver_engine_detected:
        return {
            "plugin": "solver-internals",
            "solver_engine_detected": False,
            "findings": [],
            "notes": [],
        }
    existing = {(f.rule_code, f.source_file, f.line, f.title) for f in report.findings}
    deduped = [
        cf
        for cf in analysis.findings
        if (cf.rule_code, cf.source_file, cf.line, cf.title) not in existing
    ]
    return {
        "plugin": "solver-internals",
        "solver_engine_detected": True,
        "findings": deduped,
        "notes": list(analysis.notes),
        "summary": _serialize_analysis_summary(analysis),
    }


def correlate_solver_internals_companion(
    repo_root: Path | str,
    report: Any = None,
    *,
    proto_descriptor: object = None,
    proto_descriptor_path: object = None,
    compile_commands: object = None,
    compile_commands_path: object = None,
    index_store: object = None,
    index_store_path: object = None,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
    **extra: Any,
) -> dict[str, object]:
    """Companion handler (`handler_key="solver_internals"`) for `.pb` & `compile_commands.json`."""
    desc_arg = proto_descriptor or proto_descriptor_path or extra.get("proto_descriptors")
    cc_arg = compile_commands or compile_commands_path
    idx_arg = index_store or index_store_path
    typed_report = report if isinstance(report, TruthAtlasReport) else None

    analysis = analyze_solver_internals(
        repo_root,
        report=typed_report,
        proto_descriptor=desc_arg,
        index_store=idx_arg,
        compile_commands=cc_arg,
        max_bytes=max_bytes,
    )
    has_drift = bool(analysis.findings)
    anchor_nids = [
        n.id for n in getattr(report, "nodes", ()) if getattr(n, "tier", "") == "manipulate"
    ]
    primary_nid = anchor_nids[0] if anchor_nids else "m:solver:internals"
    wall_ties = (
        [
            {
                "id": f"wt:solver_internals:z0->z1:{primary_nid}",
                "logical_key": primary_nid,
                "source_node_id": primary_nid,
                "target_node_id": f"z1:{primary_nid}",
                "from_wythe": 0,
                "to_wythe": 1,
                "status": "drift" if has_drift else "intact",
                "kind": "plugin_stratum_mismatch" if has_drift else "plugin_stratum_tie",
                "rule_code": analysis.findings[0].rule_code if analysis.findings else None,
                "label": (
                    f"Z=0->Z=1 Solver Internals ({len(analysis.proto_catalog.constraint_cases)} "
                    f"ConstraintProto cases, {len(analysis.stage_matrix.active_stages)}/7 stages, "
                    f"{len(analysis.findings)} finding(s))"
                ),
            }
        ]
        if analysis.solver_engine_detected
        else []
    )
    return {
        "plugin": "solver-internals",
        "target_slug": getattr(report, "target_slug", "unknown"),
        "source_commit": getattr(report, "source_commit", "unknown"),
        "z0_content_digest": getattr(report, "content_digest", ""),
        "target_code_executed": False,
        "build_system_executed": False,
        "automated_security_audit": False,
        "upstream_benchmark_ref": UPSTREAM_ORTOOLS_REF,
        **_serialize_analysis_summary(analysis),
        "findings": [asdict(f) for f in analysis.findings],
        "wall_ties": wall_ties,
    }


SOLVER_INTERNALS_PLUGIN = WythePluginSpec(
    name="solver-internals",
    kind="stratum_inspector",
    origin="entry_point",
    version="0.1.0",
    description=(
        "Read-only C++/Protobuf solver-engine architecture microscope (`zoom=2`): "
        "ConstraintProto 7-stage matrix, SatParameters knob lineage, Model::GetOrCreate<T>() "
        "singleton graph, and host wrapper parity."
    ),
    enabled_by_default=True,
    supported_zooms=(2,),
    post_scan_hook=check_solver_internals_report,
    stratum_badge_hook=summarize_solver_internals_badges,
    stratum_expand_hook=expand_solver_internals_stratum,
    rules=SOLVER_INTERNALS_RULES,
    companion_handlers={"solver_internals": correlate_solver_internals_companion},
)

WYTHE_PLUGIN = SOLVER_INTERNALS_PLUGIN


def register_wythe_plugin() -> WythePluginSpec:
    """Return the `SOLVER_INTERNALS_PLUGIN` spec for `wythe.plugins` registration."""
    return SOLVER_INTERNALS_PLUGIN
