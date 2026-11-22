"""Six-phase causal 3-tier solver chronicle synthesizer and viewport publisher.

Synthesizes ordered `ChronicleFrame[]` keyframes across `Truth <-> Manipulate <-> Display`
(`[1.Load]` through `[6.Render]`) and publishes `#86` / `#88` `ViewportCommand` payloads.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.schemas import atlas as atlas_schemas
from app.schemas.atlas import (
    ChronicleFrame,
    TruthAtlasReport,
    ViewportCommand,
    ViewportCommandAck,
    sanitize_viewport_plain_text,
    validate_semantic_atlas_id,
)
from app.services.viewport_service import (
    DEFAULT_VIEWPORT_ORIGIN,
    build_viewport_permalink,
    publish_viewport_command,
)
from wythe_plugin_solver_chronicle.forensics import (
    ForensicReport,
    RepoSolverAstProfile,
    classify_solver_forensics,
    inspect_repo_solver_ast,
)
from wythe_plugin_solver_chronicle.log_parser import (
    CpModelProtoSummary,
    CpSolverResponseSummary,
    ParsedSolverSession,
)

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_UNSAFE_MARKUP_RE = re.compile(
    r"<\s*/?\s*(?:script|iframe|object|embed)\b[^<>]*"
    r"|\b(?:javascript|vbscript)\s*:"
    r"|\bdata\s*:\s*text/html"
    r"|\bon[a-zA-Z]+\s*=",
    re.IGNORECASE,
)


def _clean_plain(raw: str, max_len: int) -> str:
    cur = _CTRL_RE.sub("", raw[:4096])
    for _ in range(32):
        nxt = _UNSAFE_MARKUP_RE.sub("[redacted]", cur)
        nxt = atlas_schemas._EXECUTABLE_TEXT_RE.sub("[redacted]", nxt)
        nxt = atlas_schemas._FORBIDDEN_URI_SCHEME_RE.sub("[redacted]", nxt)
        spans = atlas_schemas._iter_html_tag_spans(nxt)
        if spans:
            if any(atlas_schemas._tag_span_is_executable(nxt[s:e]) for s, e in spans):
                parts: list[str] = []
                pos = 0
                for s, e in spans:
                    if s > pos:
                        parts.append(nxt[pos:s])
                    if atlas_schemas._tag_span_is_executable(nxt[s:e]):
                        parts.append("[redacted]")
                    pos = max(pos, e)
                if pos < len(nxt):
                    parts.append(nxt[pos:])
                nxt = "".join(parts)
            else:
                nxt = atlas_schemas._strip_html_spans(nxt, spans)
        nxt = _UNSAFE_MARKUP_RE.sub("[redacted]", nxt)
        nxt = atlas_schemas._EXECUTABLE_TEXT_RE.sub("[redacted]", nxt)
        nxt = atlas_schemas._FORBIDDEN_URI_SCHEME_RE.sub("[redacted]", nxt)
        if nxt == cur:
            break
        cur = nxt
    if atlas_schemas._contains_executable_markup_or_uri(cur):
        cur = re.sub(
            r"(?i)(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t)\s*:|"
            r"d\s*a\s*t\s*a\s*:\s*t\s*e\s*x\s*t\s*/\s*h\s*t\s*m\s*l",
            "[redacted]",
            cur,
        )
        cur = _UNSAFE_MARKUP_RE.sub("[redacted]", cur)
        cur = atlas_schemas._EXECUTABLE_TEXT_RE.sub("[redacted]", cur)
        if atlas_schemas._contains_executable_markup_or_uri(cur):
            cur = "[redacted]"
    cleaned = sanitize_viewport_plain_text(cur, field_name="chronicle_text")
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


def _clean_substeps(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        s = _clean_plain(item, 230)
        if s and s not in out:
            out.append(s)
        if len(out) >= 24:
            break
    return out


def _dedup_ids(ids: list[str], limit: int) -> list[str]:
    seen: list[str] = []
    for raw in ids:
        s = raw.strip()
        if s and s not in seen:
            seen.append(s)
        if len(seen) >= limit:
            break
    return seen


def default_timeline_id(
    target_slug: str,
    session: ParsedSolverSession | None = None,
) -> str:
    seed = f"{target_slug}:{session.model_name if session else 'static'}:{session.line_count if session else 0}:{session.final_status if session else 'none'}"
    digest8 = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    safe_slug = re.sub(r"[^a-z0-9-_]", "-", target_slug.lower()).strip("-")[:28] or "target"
    return f"chron-{safe_slug}-{digest8}"


@dataclass(frozen=True)
class ChronicleSynthesisResult:
    timeline_id: str
    target_slug: str
    title: str
    live_following: bool
    halted_reason: str | None
    active_phase_index: int
    frames: tuple[ChronicleFrame, ...]
    forensics: ForensicReport
    ast_profile: RepoSolverAstProfile
    content_digest: str


def _select_active_phase_index(
    frames: list[ChronicleFrame],
    forensics: ForensicReport,
    session: ParsedSolverSession | None,
    explicit_phase: int | None = None,
) -> int:
    if explicit_phase is not None:
        if isinstance(explicit_phase, bool) or not isinstance(explicit_phase, int):
            raise TypeError("`phase_index` must be an integer, not boolean.")
        if explicit_phase < 0 or explicit_phase >= len(frames):
            raise ValueError(f"`phase_index` must be in 0..{len(frames) - 1}, got {explicit_phase}.")
        return explicit_phase
    if forensics.halted and forensics.halt_phase_index is not None:
        return forensics.halt_phase_index
    if forensics.pathologies:
        return forensics.pathologies[0].phase_index
    if session is not None:
        if session.final_status in ("OPTIMAL", "FEASIBLE"):
            return 5
        if session.search_started or session.incumbents:
            return 3
        if session.presolve_started:
            return 2
        if session.line_count > 0:
            return 1
    return 0


def synthesize_solver_chronicle(
    repo_root: Path,
    report: TruthAtlasReport,
    *,
    session: ParsedSolverSession | None = None,
    proto: CpModelProtoSummary | None = None,
    response: CpSolverResponseSummary | None = None,
    timeline_id: str | None = None,
    phase_index: int | None = None,
    ast_profile: RepoSolverAstProfile | None = None,
) -> ChronicleSynthesisResult:
    """Synthesize the 6-phase 3-tier `ChronicleFrame[]` timeline and forensic classification."""
    resolved_ast = (
        ast_profile if ast_profile is not None else inspect_repo_solver_ast(repo_root, report)
    )
    forensics = classify_solver_forensics(
        report,
        resolved_ast,
        session=session,
        proto=proto,
        response=response,
    )
    raw_tl = (timeline_id or "").strip() or default_timeline_id(report.target_slug, session)
    tl_id = validate_semantic_atlas_id(raw_tl[:64], field_name="timeline_id")

    truth_nodes = [n for n in report.nodes if n.tier == "truth"]
    manip_nodes = [n for n in report.nodes if n.tier == "manipulate"]
    disp_nodes = [n for n in report.nodes if n.tier == "display"]
    route_nodes = [n for n in manip_nodes if n.subkind == "route"]
    solver_ids = list(resolved_ast.solver_node_ids) or [
        n.id for n in manip_nodes if n.subkind == "solver"
    ] or [n.id for n in manip_nodes if n.subkind != "route"][:3]

    read_edges = [e for e in report.edges if e.kind == "reads_truth"]
    write_edges = [e for e in report.edges if e.kind == "writes_truth"]
    call_edges = [e for e in report.edges if e.kind == "calls_helper"]
    disp_edges = [
        e
        for e in report.edges
        if e.kind in ("queries_endpoint", "mutates_endpoint", "uses_hook", "uses_client")
    ]

    frames = _build_six_frames(
        report=report,
        ast_profile=resolved_ast,
        forensics=forensics,
        session=session,
        proto=proto,
        response=response,
        truth_ids=[n.id for n in truth_nodes],
        solver_ids=solver_ids,
        route_ids=[n.id for n in route_nodes],
        disp_ids=[n.id for n in disp_nodes],
        read_edges=read_edges,
        write_edges=write_edges,
        call_edges=call_edges,
        disp_edges=disp_edges,
    )
    active_idx = _select_active_phase_index(frames, forensics, session, explicit_phase=phase_index)
    model_lbl = (
        (session.model_name if session and session.model_name else None)
        or (proto.name if proto and proto.name else None)
        or report.target_slug
    )
    status_lbl = (
        (response.status if response and response.status else None)
        or (session.final_status if session and session.final_status else "STATIC")
    )
    title = _clean_plain(f"Solver Chronicle :: {model_lbl} ({status_lbl})", 150)
    clean_halt = _clean_plain(forensics.halted_reason, 235) if forensics.halted_reason else None
    return ChronicleSynthesisResult(
        timeline_id=tl_id,
        target_slug=report.target_slug,
        title=title,
        live_following=not forensics.halted,
        halted_reason=clean_halt,
        active_phase_index=active_idx,
        frames=tuple(frames),
        forensics=forensics,
        ast_profile=resolved_ast,
        content_digest=report.content_digest,
    )


def _build_six_frames(
    *,
    report: TruthAtlasReport,
    ast_profile: RepoSolverAstProfile,
    forensics: ForensicReport,
    session: ParsedSolverSession | None,
    proto: CpModelProtoSummary | None,
    response: CpSolverResponseSummary | None,
    truth_ids: list[str],
    solver_ids: list[str],
    route_ids: list[str],
    disp_ids: list[str],
    read_edges: list[atlas_schemas.AtlasEdge],
    write_edges: list[atlas_schemas.AtlasEdge],
    call_edges: list[atlas_schemas.AtlasEdge],
    disp_edges: list[atlas_schemas.AtlasEdge],
) -> list[ChronicleFrame]:
    halt_idx = forensics.halt_phase_index if forensics.halted else None
    path_by_phase: dict[int, list[str]] = {}
    for p in forensics.pathologies:
        path_by_phase.setdefault(p.phase_index, []).append(p.summary)

    # Phase 0: [1.Load] Truth -> Manipulate
    consumed_n = 0
    bypassed_items: list[str] = []
    unresolved_n = 0
    for edge in read_edges:
        pfc = edge.policy_field_consumption
        if pfc is None:
            continue
        if pfc.state == "consumed":
            consumed_n += 1
        elif pfc.state == "bypassed":
            consts = ", ".join(pfc.substituted_constants[:2]) or "constant override"
            bypassed_items.append(f"BYPASSED: {edge.source_id} -> {edge.target_id} ({consts})")
        else:
            unresolved_n += 1

    load_steps: list[str] = [
        f"Preload reads_truth edges: {len(read_edges)} across {len(truth_ids)} Truth store(s)",
        f"PolicyFieldConsumption: consumed={consumed_n}, bypassed={len(bypassed_items)}, unresolved={unresolved_n}",
    ]
    load_steps.extend(bypassed_items[:4])
    for risk in ast_profile.empty_table_risks[:4]:
        load_steps.append(f"TRUTH-001 empty-table risk: {risk}")
    load_warn = bool(bypassed_items or ast_profile.empty_table_risks)
    f0 = ChronicleFrame(
        phase_index=0,
        phase_key="1.Load",
        phase_label="[1.Load] Context & Policy Ingestion",
        tier="truth",
        focus_node_ids=_dedup_ids([*truth_ids, *solver_ids[:2]], 80),
        highlight_edge_ids=_dedup_ids([e.id for e in read_edges], 120),
        status="warning" if load_warn else "ok",
        caption=_clean_plain(
            f"Ingested {len(truth_ids)} Truth table(s) via {len(read_edges)} preload edge(s) "
            f"(consumed={consumed_n}, bypassed={len(bypassed_items)}, empty-risk={len(ast_profile.empty_table_risks)}).",
            390,
        ),
        substeps=_clean_substeps(load_steps),
    )

    # Phase 1: [2.Build] Manipulate Model Assembly
    build_steps: list[str] = [
        f"Variables allocated: {len(ast_profile.var_builders)} Z=0 builder site(s)"
        + (f" ({session.initial_variables} runtime vars)" if session and session.initial_variables is not None else "")
    ]
    for idx_c, cs in enumerate(ast_profile.constraint_builders[:6], start=1):
        build_steps.append(
            f"Constraint #{idx_c}: {cs.func_name} ({cs.method}) @ {cs.source_file}:{cs.line}"
        )
    for uw in ast_profile.unwired_builders[:4]:
        build_steps.append(f"UNWIRED [MANIP-003]: {uw.name_hint} @ {uw.source_file}:{uw.line}")
    for f_m3 in (f for f in report.findings if f.rule_code == "MANIP-003"):
        build_steps.append(f"UNWIRED [MANIP-003]: {f_m3.source_file}:{f_m3.line} ({f_m3.title})")
    for tr in ast_profile.objective_truncations[:4]:
        build_steps.append(f"TRUNCATION [MANIP-001]: {tr}")
    for ot in ast_profile.objective_terms[:2]:
        build_steps.append(f"Objective: {ot}")

    build_warn = bool(ast_profile.unwired_builders or ast_profile.objective_truncations or path_by_phase.get(1))
    f1_status = "failed" if halt_idx == 1 else ("warning" if build_warn else "ok")
    f1_caption = (
        forensics.summary
        if halt_idx == 1
        else (
            f"Assembled {len(ast_profile.var_builders)} variable family site(s) and "
            f"{len(ast_profile.constraint_builders)} sequential constraint brick(s) "
            f"(unwired={len(ast_profile.unwired_builders)}, truncations={len(ast_profile.objective_truncations)})."
        )
    )
    if halt_idx == 1:
        for zb in forensics.z0_builders:
            build_steps.insert(0, f"HALT Z=0 builder: {zb.symbol} @ {zb.pointer()} -> Truth {list(zb.truth_table_ids)}")
    f1 = ChronicleFrame(
        phase_index=1,
        phase_key="2.Build",
        phase_label="[2.Build] Model Assembly & Objective Tower",
        tier="manipulate",
        focus_node_ids=_dedup_ids(
            list(forensics.focus_node_ids) if halt_idx == 1 else [*solver_ids, *(uw.node_id for uw in ast_profile.unwired_builders if uw.node_id)],
            80,
        ),
        highlight_edge_ids=_dedup_ids(
            list(forensics.highlight_edge_ids) if halt_idx == 1 else [e.id for e in call_edges],
            120,
        ),
        status=f1_status,  # type: ignore[arg-type]
        caption=_clean_plain(f1_caption, 390),
        substeps=_clean_substeps(build_steps),
    )

    # Phase 2: [3.Presolve] Expand -> Presolve -> Symmetry
    init_v = (
        len(proto.variable_names)
        if proto and proto.variable_names
        else (session.initial_variables if session else None)
    )
    post_v = (session.presolved_variables or session.expanded_variables) if session else None
    init_c = (
        len(proto.constraint_names)
        if proto and proto.constraint_names
        else (session.initial_constraints if session else None)
    )
    post_c = (session.presolved_constraints or session.expanded_constraints) if session else None
    presolve_steps: list[str] = [
        (
            f"Expand/Presolve vars: {init_v if init_v is not None else 'n/a'} -> {post_v if post_v is not None else 'n/a'}; "
            f"constraints: {init_c if init_c is not None else 'n/a'} -> {post_c if post_c is not None else 'n/a'}"
        )
    ]
    if session and session.presolve_rules_applied:
        presolve_steps.append(f"Rules applied: {', '.join(session.presolve_rules_applied[:5])}")
    if session and session.symmetry_summary:
        presolve_steps.append(f"Symmetry: {session.symmetry_summary}")
    for p_msg in path_by_phase.get(2, ()):
        presolve_steps.append(f"PATHOLOGY: {p_msg}")
    if halt_idx == 2:
        for zb in forensics.z0_builders:
            presolve_steps.insert(0, f"HALT Z=0 brick: {zb.symbol} @ {zb.pointer()}")
        if forensics.neighborhood_builders:
            presolve_steps.append(f"1-hop coupled bricks: {', '.join(forensics.neighborhood_builders[:4])}")

    f2_status = (
        "pending"
        if (halt_idx is not None and halt_idx < 2)
        else ("failed" if halt_idx == 2 else ("warning" if path_by_phase.get(2) else "ok"))
    )
    f2_caption = (
        f"Pending upstream halt at {forensics.halt_phase_key}."
        if f2_status == "pending"
        else (
            forensics.summary
            if halt_idx == 2
            else (path_by_phase[2][0] if path_by_phase.get(2) else "Completed Expand -> Presolve -> Symmetry reduction pipeline.")
        )
    )
    f2 = ChronicleFrame(
        phase_index=2,
        phase_key="3.Presolve",
        phase_label="[3.Presolve] Expand, Presolve & Symmetry",
        tier="manipulate",
        focus_node_ids=_dedup_ids(
            list(forensics.focus_node_ids) if halt_idx == 2 else solver_ids,
            80,
        ),
        highlight_edge_ids=_dedup_ids(
            list(forensics.highlight_edge_ids) if halt_idx == 2 else [e.id for e in call_edges],
            120,
        ),
        status=f2_status,  # type: ignore[arg-type]
        caption=_clean_plain(f2_caption, 390),
        substeps=_clean_substeps(presolve_steps),
    )

    return [
        f0,
        f1,
        f2,
        *_build_tail_three_frames(
            ast_profile=ast_profile,
            forensics=forensics,
            session=session,
            response=response,
            halt_idx=halt_idx,
            path_by_phase=path_by_phase,
            truth_ids=truth_ids,
            solver_ids=solver_ids,
            route_ids=route_ids,
            disp_ids=disp_ids,
            write_edges=write_edges,
            disp_edges=disp_edges,
        ),
    ]


def _build_tail_three_frames(
    *,
    ast_profile: RepoSolverAstProfile,
    forensics: ForensicReport,
    session: ParsedSolverSession | None,
    response: CpSolverResponseSummary | None,
    halt_idx: int | None,
    path_by_phase: dict[int, list[str]],
    truth_ids: list[str],
    solver_ids: list[str],
    route_ids: list[str],
    disp_ids: list[str],
    write_edges: list[atlas_schemas.AtlasEdge],
    disp_edges: list[atlas_schemas.AtlasEdge],
) -> list[ChronicleFrame]:
    # Phase 3: [4.Search] Multi-Solver & Portfolio Search
    search_steps: list[str] = []
    run_cnt = len(session.solver_runs) if session else 0
    if run_cnt >= 2 or ast_profile.multi_solver_calls >= 2:
        runs_desc = (
            " -> ".join(f"Solver {r.run_index} ({r.status or 'RUN'})" for r in session.solver_runs)
            if session and len(session.solver_runs) >= 2
            else f"Sequential pipeline ({ast_profile.multi_solver_calls} CpSolver invocations)"
        )
        search_steps.append(f"Multi-solver sequence: {runs_desc}")
    if session and session.portfolio_subsolvers:
        search_steps.append(f"Portfolio workers: {', '.join(session.portfolio_subsolvers[:6])}")
    if session and session.incumbents:
        first_i, last_i = session.incumbents[0], session.incumbents[-1]
        search_steps.append(
            f"Incumbents ({len(session.incumbents)}): #{first_i.step_index} obj={first_i.objective:g} ({first_i.worker}) "
            f"-> #{last_i.step_index} obj={last_i.objective:g}, bound={last_i.best_bound if last_i.best_bound is not None else 'n/a'} ({last_i.worker})"
        )
    else:
        search_steps.append("Incumbents: 0 solutions recorded in current window")
    for p_msg in path_by_phase.get(3, ()):
        search_steps.append(f"PATHOLOGY: {p_msg}")
    if halt_idx == 3:
        for zb in forensics.z0_builders[:4]:
            search_steps.insert(0, f"HALT Z=0 brick: {zb.symbol} @ {zb.pointer()}")
        if forensics.recommended_action:
            search_steps.append(f"Guidance: {forensics.recommended_action}")

    f3_status = (
        "pending"
        if (halt_idx is not None and halt_idx < 3)
        else ("failed" if halt_idx == 3 else ("warning" if path_by_phase.get(3) else "ok"))
    )
    eff_obj = (response.objective_value if response and response.objective_value is not None else (session.final_objective if session else None))
    eff_bnd = (response.best_objective_bound if response and response.best_objective_bound is not None else (session.final_best_bound if session else None))
    f3_caption = (
        f"Pending upstream halt at {forensics.halt_phase_key}."
        if f3_status == "pending"
        else (
            forensics.summary
            if halt_idx == 3
            else (
                path_by_phase[3][0]
                if path_by_phase.get(3)
                else f"Portfolio search converged: objective={eff_obj if eff_obj is not None else 'n/a'}, best_bound={eff_bnd if eff_bnd is not None else 'n/a'}."
            )
        )
    )
    f3 = ChronicleFrame(
        phase_index=3,
        phase_key="4.Search",
        phase_label="[4.Search] Multi-Solver & Portfolio Search",
        tier="manipulate",
        focus_node_ids=_dedup_ids(
            list(forensics.focus_node_ids) if halt_idx == 3 else solver_ids,
            80,
        ),
        highlight_edge_ids=_dedup_ids(
            list(forensics.highlight_edge_ids) if halt_idx == 3 else [],
            120,
        ),
        status=f3_status,  # type: ignore[arg-type]
        caption=_clean_plain(f3_caption, 390),
        substeps=_clean_substeps(search_steps),
    )

    # Phase 4: [5.Persist] Post-Solve Validation & Status Persistence
    runtime_masked = bool(
        session
        and len(session.solver_runs) >= 2
        and any(r.status == "FEASIBLE" for r in session.solver_runs[:-1])
        and session.solver_runs[-1].status == "OPTIMAL"
    )
    persist_steps: list[str] = [
        f"Persistence writes_truth edges: {len(write_edges)}; validators: {len(ast_profile.validator_node_ids)}"
    ]
    if ast_profile.asymmetric_truth_tables:
        persist_steps.append(
            f"ASYMMETRY: Validator vs [2.Build] Truth mismatch on {', '.join(ast_profile.asymmetric_truth_tables[:4])}"
        )
    if ast_profile.masks_primary_feasible or runtime_masked:
        loc = f" @ {ast_profile.masking_site}" if ast_profile.masking_site else ""
        persist_steps.append(
            f"STATUS MASKING: Auxiliary OPTIMAL masks primary FEASIBLE status{loc}"
        )
    if ast_profile.omits_bound_gap_persistence:
        loc = f" @ {ast_profile.gap_omission_site}" if ast_profile.gap_omission_site else ""
        persist_steps.append(
            f"GAP OMISSION: Persists ObjectiveValue without BestObjectiveBound{loc}"
        )

    persist_warn = bool(
        ast_profile.asymmetric_truth_tables
        or ast_profile.masks_primary_feasible
        or runtime_masked
        or ast_profile.omits_bound_gap_persistence
    )
    f4_status = "pending" if halt_idx is not None else ("warning" if persist_warn else "ok")
    f4_caption = (
        f"Pending upstream halt at {forensics.halt_phase_key}."
        if f4_status == "pending"
        else (
            persist_steps[1]
            if persist_warn and len(persist_steps) > 1
            else f"Validated symmetry and persisted run status across {len(write_edges)} writes_truth edge(s)."
        )
    )
    f4 = ChronicleFrame(
        phase_index=4,
        phase_key="5.Persist",
        phase_label="[5.Persist] Validation & Status Persistence",
        tier="truth",
        focus_node_ids=_dedup_ids([*ast_profile.validator_node_ids, *truth_ids, *solver_ids[:1]], 80),
        highlight_edge_ids=_dedup_ids([e.id for e in write_edges], 120),
        status=f4_status,  # type: ignore[arg-type]
        caption=_clean_plain(f4_caption, 390),
        substeps=_clean_substeps(persist_steps),
    )

    # Phase 5: [6.Render] Truth -> Manipulate -> Display Projection
    render_steps: list[str] = [
        f"API -> Display projection: {len(route_ids)} route(s) -> {len(disp_ids)} UI node(s) ({len(disp_edges)} edge(s))"
    ]
    for ui_nid, ui_msg in ast_profile.optimistic_ui_nodes[:4]:
        render_steps.append(f"OPTIMISTIC UI ({ui_nid}): {ui_msg}")

    render_warn = bool(ast_profile.optimistic_ui_nodes)
    f5_status = "pending" if halt_idx is not None else ("warning" if render_warn else "ok")
    f5_caption = (
        f"Pending upstream halt at {forensics.halt_phase_key}."
        if f5_status == "pending"
        else (
            ast_profile.optimistic_ui_nodes[0][1]
            if render_warn
            else f"Projected solver status and optimality gap cleanly to {len(disp_ids)} Display component(s)."
        )
    )
    f5 = ChronicleFrame(
        phase_index=5,
        phase_key="6.Render",
        phase_label="[6.Render] API & UI Status Projection",
        tier="display",
        focus_node_ids=_dedup_ids([*(u[0] for u in ast_profile.optimistic_ui_nodes), *disp_ids, *route_ids], 80),
        highlight_edge_ids=_dedup_ids([e.id for e in disp_edges], 120),
        status=f5_status,  # type: ignore[arg-type]
        caption=_clean_plain(f5_caption, 390),
        substeps=_clean_substeps(render_steps),
    )
    return [f3, f4, f5]


def build_chronicle_viewport_command(
    synthesis: ChronicleSynthesisResult,
    *,
    session_id: str | None = None,
) -> ViewportCommand:
    """Construct a validated `ViewportCommand` compatible with both 860c38d and @w3-core-spine."""
    active_frame = synthesis.frames[synthesis.active_phase_index]
    preset = "corridor_trace" if synthesis.forensics.halted else "wythe_cross_section"
    cmd_kwargs: dict[str, object] = {
        "target_slug": synthesis.target_slug,
        "session_id": session_id,
        "focus_node_ids": list(active_frame.focus_node_ids[:50]),
        "highlight_edge_ids": list(active_frame.highlight_edge_ids[:80]),
        "layout_mode": "lifecycle_z",
        "framing_preset": preset,
        "caption": _clean_plain(active_frame.caption or synthesis.title, 390),
        "chronicle_frames": list(synthesis.frames),
    }
    timeline_cls = getattr(atlas_schemas, "ChronicleTimeline", None)
    if timeline_cls is not None and "chronicle_timeline" in ViewportCommand.model_fields:
        cmd_kwargs["chronicle_timeline"] = timeline_cls(
            timeline_id=synthesis.timeline_id,
            target_slug=synthesis.target_slug,
            title=_clean_plain(synthesis.title, 155),
            live_following=synthesis.live_following,
            halted_reason=_clean_plain(synthesis.halted_reason, 235) if synthesis.halted_reason else None,
            active_phase_index=synthesis.active_phase_index,
            frames=list(synthesis.frames),
        )
    return ViewportCommand(**cmd_kwargs)  # type: ignore[arg-type]


def build_chronicle_permalink(
    cmd: ViewportCommand,
    *,
    timeline_id: str,
    phase_index: int,
    base_origin: str = DEFAULT_VIEWPORT_ORIGIN,
    raw_permalink: str | None = None,
) -> str:
    """Return canonical `#target=...&focus=...&chronicle=<id>&phase=<idx>` permalink."""
    base = raw_permalink or build_viewport_permalink(cmd, base_origin=base_origin)
    q_tl = urllib.parse.quote(timeline_id, safe="")
    if "chronicle=" in base and "phase=" in base:
        return base
    if "chronicle=" not in base:
        base = f"{base}&chronicle={q_tl}"
    if "phase=" not in base:
        base = f"{base}&phase={phase_index}"
    return base


def publish_chronicle_to_viewport(
    synthesis: ChronicleSynthesisResult,
    *,
    session_id: str | None = None,
    base_origin: str = DEFAULT_VIEWPORT_ORIGIN,
    server_url: str | None = None,
    allow_remote: bool = False,
) -> tuple[ViewportCommandAck, str]:
    """Publish `synthesis` to `viewport_service` and return `(ack, canonical_permalink)`."""
    cmd = build_chronicle_viewport_command(synthesis, session_id=session_id)
    ack = publish_viewport_command(
        cmd,
        base_origin=base_origin,
        server_url=server_url,
        allow_remote=allow_remote,
    )
    permalink = build_chronicle_permalink(
        cmd,
        timeline_id=synthesis.timeline_id,
        phase_index=synthesis.active_phase_index,
        base_origin=base_origin,
        raw_permalink=ack.permalink,
    )
    return ack, permalink


def serialize_chronicle_payload(
    synthesis: ChronicleSynthesisResult,
    *,
    permalink: str,
    published_to_viewport: bool,
    viewport_seq: int | None = None,
) -> dict[str, Any]:
    """Serialize `ChronicleSynthesisResult` + forensic provenance into JSON-ready dict."""
    f = synthesis.forensics
    forensics_dict: dict[str, Any] = {
        "forensic_class": f.forensic_class,
        "submode": f.submode,
        "halted": f.halted,
        "halt_phase_index": f.halt_phase_index,
        "halt_phase_key": f.halt_phase_key,
        "summary": f.summary,
        "z0_builders": [
            {
                "symbol": zb.symbol,
                "node_id": zb.node_id,
                "source_file": zb.source_file,
                "line": zb.line,
                "pointer": zb.pointer(),
                "func_name": zb.func_name,
                "truth_table_ids": list(zb.truth_table_ids),
                "truth_columns": list(zb.truth_columns),
            }
            for zb in f.z0_builders
        ],
        "upstream_truth_tables": list(f.upstream_truth_tables),
        "upstream_truth_columns": list(f.upstream_truth_columns),
        "neighborhood_node_ids": list(f.neighborhood_node_ids),
        "neighborhood_builders": list(f.neighborhood_builders),
        "recommended_action": f.recommended_action,
        "pathologies": [
            {
                "kind": p.kind,
                "phase_index": p.phase_index,
                "phase_key": p.phase_key,
                "summary": p.summary,
            }
            for p in f.pathologies
        ],
    }
    if f.unverified_candidates_note:
        forensics_dict["unverified_candidates_note"] = f.unverified_candidates_note
    return {
        "target_slug": synthesis.target_slug,
        "timeline_id": synthesis.timeline_id,
        "title": synthesis.title,
        "live_following": synthesis.live_following,
        "halted_reason": synthesis.halted_reason,
        "active_phase_index": synthesis.active_phase_index,
        "permalink": permalink,
        "published_to_viewport": published_to_viewport,
        "viewport_seq": viewport_seq,
        "content_digest": synthesis.content_digest,
        "forensics": forensics_dict,
        "chronicle_frames": [frame.model_dump() for frame in synthesis.frames],
    }
