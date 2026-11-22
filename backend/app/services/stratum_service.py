"""Progressive LOD microscope (`Zoom 2` IR/AIR & `Zoom 3` binary/heap) compaction service."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from pathlib import Path

from app.adapters.plugin_registry import (
    WythePluginSpec,
    get_active_stratum_artifacts,
    run_stratum_badge_plugins,
    run_stratum_expand_plugins,
)
from app.schemas.atlas import (
    MicroStratumZoom,
    StratumDrilldownRead,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TruthAtlasReport,
    VerificationState,
)

_stdlib_prefixes: tuple[str, ...] = (
    "std::",
    "core::",
    "Swift.",
    "builtins.",
)
_arc_helper_prefixes: tuple[str, ...] = (
    "swift_retain",
    "swift_release",
    "swift_bridgeObjectRetain",
    "swift_bridgeObjectRelease",
    "swift_unknownObjectRetain",
    "swift_unknownObjectRelease",
    "swift_unownedRetain",
    "swift_unownedRelease",
    "objc_retain",
    "objc_release",
    "objc_autorelease",
    "objc_storeStrong",
    "objc_destroyWeak",
    "objc_loadWeakRetained",
)
_thunk_lower_prefixes: tuple[str, ...] = (
    "protocol witness for ",
    "thunk for ",
    "reabstraction thunk ",
    "vtable thunk",
    "non-virtual thunk to ",
)
_sample_preview_size = 8
_epistemic_conservatism: dict[VerificationState, int] = {
    "verified": 0,
    "declared": 1,
    "unverified": 2,
    "broken": 3,
}
_rank_to_verification: dict[int, VerificationState] = {
    0: "verified",
    1: "declared",
    2: "unverified",
    3: "broken",
}


def is_boilerplate_stratum_symbol(symbol: str) -> bool:
    """Return True for language stdlib leaves, Swift/ObjC ARC helpers, and witness/thunk trampolines."""
    cleaned = symbol.strip()
    if not cleaned:
        return False
    if cleaned.startswith(_stdlib_prefixes) or cleaned.startswith(_arc_helper_prefixes):
        return True
    if cleaned.startswith("_") and "TWo" in cleaned:
        return True
    low = cleaned.lower()
    return low.startswith(_thunk_lower_prefixes)


def _is_collapsible_micro_node(node: StratumMicroNode) -> bool:
    if node.verification in ("unverified", "broken"):
        return False
    if is_boilerplate_stratum_symbol(node.label):
        return True
    tail = node.id.rsplit(":", 1)[-1] if ":" in node.id else node.id
    return is_boilerplate_stratum_symbol(tail)


def _conservative_verification(states: Sequence[VerificationState]) -> VerificationState:
    if not states:
        return "declared"
    worst = max(_epistemic_conservatism.get(st, 1) for st in states)
    return _rank_to_verification.get(worst, "declared")


def _merge_badges(badges: Sequence[StratumSummaryBadge]) -> list[StratumSummaryBadge]:
    by_key: dict[str, tuple[str, int]] = {}
    for b in badges:
        prev = by_key.get(b.key)
        if prev is None:
            by_key[b.key] = (b.label, b.count)
        else:
            by_key[b.key] = (prev[0] or b.label, max(prev[1], b.count))
    return [
        StratumSummaryBadge(key=k, label=lbl, count=cnt)
        for k, (lbl, cnt) in sorted(by_key.items())
    ]


def compact_stratum_subgraph(
    parent_node_id: str,
    raw_nodes: Sequence[StratumMicroNode],
    raw_edges: Sequence[StratumMicroEdge],
    *,
    unfiltered_ir: bool = False,
) -> tuple[list[StratumMicroNode], list[StratumMicroEdge], int, int, int]:
    """Deterministically fold stdlib/ARC/witness/thunk noise unless `unfiltered_ir=True`."""
    nodes_by_id: dict[str, StratumMicroNode] = {}
    for n in raw_nodes:
        nodes_by_id.setdefault(n.id, n)
    edges_by_id: dict[str, StratumMicroEdge] = {}
    for e in raw_edges:
        edges_by_id.setdefault(e.id, e)

    ordered_nodes = [nodes_by_id[nid] for nid in sorted(nodes_by_id)]
    ordered_edges = [edges_by_id[eid] for eid in sorted(edges_by_id)]
    raw_count = len(ordered_nodes)

    if unfiltered_ir:
        return ordered_nodes, ordered_edges, raw_count, raw_count, 0

    boilerplate_by_id: dict[str, StratumMicroNode] = {}
    surviving_nodes: list[StratumMicroNode] = []
    for node in ordered_nodes:
        if _is_collapsible_micro_node(node):
            boilerplate_by_id[node.id] = node
        else:
            surviving_nodes.append(node)

    has_external_boiler_edge = any(
        e.target_id not in nodes_by_id
        and is_boilerplate_stratum_symbol(e.target_id)
        and e.verification not in ("unverified", "broken")
        for e in ordered_edges
    )
    if not boilerplate_by_id and not has_external_boiler_edge:
        return ordered_nodes, ordered_edges, raw_count, len(surviving_nodes), 0

    boiler_out: dict[str, list[StratumMicroEdge]] = {}
    for edge in ordered_edges:
        if edge.source_id in boilerplate_by_id:
            boiler_out.setdefault(edge.source_id, []).append(edge)

    # Iterative Tarjan SCC condensation over boilerplate subgraph (zero call-stack recursion).
    index_counter = 0
    disc_index: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    tarjan_stack: list[str] = []
    on_stack: set[str] = set()
    scc_nodes: list[list[str]] = []
    scc_of: dict[str, int] = {}

    for root_bid in boilerplate_by_id:
        if root_bid in disc_index:
            continue
        disc_index[root_bid] = index_counter
        lowlink[root_bid] = index_counter
        index_counter += 1
        tarjan_stack.append(root_bid)
        on_stack.add(root_bid)
        call_stack: list[tuple[str, int]] = [(root_bid, 0)]
        while call_stack:
            cur_id, edge_idx = call_stack[-1]
            outs = boiler_out.get(cur_id, ())
            if edge_idx < len(outs):
                call_stack[-1] = (cur_id, edge_idx + 1)
                nxt_id = outs[edge_idx].target_id
                if nxt_id not in boilerplate_by_id:
                    continue
                if nxt_id not in disc_index:
                    disc_index[nxt_id] = index_counter
                    lowlink[nxt_id] = index_counter
                    index_counter += 1
                    tarjan_stack.append(nxt_id)
                    on_stack.add(nxt_id)
                    call_stack.append((nxt_id, 0))
                elif nxt_id in on_stack and disc_index[nxt_id] < lowlink[cur_id]:
                    lowlink[cur_id] = disc_index[nxt_id]
            else:
                call_stack.pop()
                if call_stack:
                    parent_id = call_stack[-1][0]
                    lowlink[parent_id] = min(lowlink[parent_id], lowlink[cur_id])
                if lowlink[cur_id] == disc_index[cur_id]:
                    scc_idx = len(scc_nodes)
                    comp: list[str] = []
                    while True:
                        member = tarjan_stack.pop()
                        on_stack.discard(member)
                        scc_of[member] = scc_idx
                        comp.append(member)
                        if member == cur_id:
                            break
                    scc_nodes.append(comp)

    num_sccs = len(scc_nodes)
    scc_labels: list[list[str]] = []
    scc_ext_boiler: list[list[str]] = []
    scc_own_rank: list[int] = []
    scc_cycle_edge_rank: list[int] = []
    scc_dag_out: list[dict[int, int]] = [{} for _ in range(num_sccs)]
    scc_dag_rev: list[list[tuple[int, int]]] = [[] for _ in range(num_sccs)]
    scc_direct_hits: list[dict[str, int]] = [{} for _ in range(num_sccs)]
    any_direct_hits = False

    for c_idx, members in enumerate(scc_nodes):
        lbls: list[str] = []
        ext_syms: list[str] = []
        max_own = 0
        max_cyc = -1
        dag_map = scc_dag_out[c_idx]
        hits_map = scc_direct_hits[c_idx]
        for bid in members:
            b_node = boilerplate_by_id[bid]
            lbls.append(b_node.label or bid)
            n_rank = _epistemic_conservatism.get(b_node.verification, 1)
            max_own = max(max_own, n_rank)
            for out_e in boiler_out.get(bid, ()):
                e_rank = _epistemic_conservatism.get(out_e.verification, 1)
                max_own = max(max_own, e_rank)
                tgt = out_e.target_id
                tgt_scc = scc_of.get(tgt)
                if tgt_scc is not None:
                    if tgt_scc == c_idx:
                        max_cyc = max(max_cyc, e_rank)
                    else:
                        prev_r = dag_map.get(tgt_scc)
                        if prev_r is None or e_rank > prev_r:
                            dag_map[tgt_scc] = e_rank
                elif tgt not in nodes_by_id and is_boilerplate_stratum_symbol(tgt):
                    if out_e.verification in ("unverified", "broken"):
                        any_direct_hits = True
                        prev_h = hits_map.get(tgt)
                        if prev_h is None or e_rank > prev_h:
                            hits_map[tgt] = e_rank
                    else:
                        ext_syms.append(tgt)
                else:
                    any_direct_hits = True
                    prev_h = hits_map.get(tgt)
                    if prev_h is None or e_rank > prev_h:
                        hits_map[tgt] = e_rank
        scc_labels.append(lbls)
        scc_ext_boiler.append(ext_syms)
        scc_own_rank.append(max_own)
        scc_cycle_edge_rank.append(max_cyc)

    for u_scc, dag_map in enumerate(scc_dag_out):
        for v_scc, edge_r in dag_map.items():
            scc_dag_rev[v_scc].append((u_scc, edge_r))

    kept_edges: list[StratumMicroEdge] = []
    bridged_map: dict[tuple[str, str, str], tuple[list[VerificationState], set[str]]] = {}
    collapsed_by_caller: dict[str, set[str]] = {}
    collapsed_verifs: dict[str, set[VerificationState]] = {}
    accounted_boiler: set[str] = set()
    caller_boiler_entries: dict[str, list[tuple[int, VerificationState]]] = {}
    bridge_entries: dict[tuple[str, str], dict[int, int]] = {}

    for edge in ordered_edges:
        if edge.source_id in boilerplate_by_id:
            continue
        tgt_scc = scc_of.get(edge.target_id)
        if tgt_scc is None:
            if (
                edge.target_id in nodes_by_id
                or not is_boilerplate_stratum_symbol(edge.target_id)
                or edge.verification in ("unverified", "broken")
            ):
                kept_edges.append(edge)
                continue
            collapsed_by_caller.setdefault(edge.source_id, set()).add(edge.target_id)
            collapsed_verifs.setdefault(edge.source_id, set()).add(edge.verification)
            continue

        caller_boiler_entries.setdefault(edge.source_id, []).append((tgt_scc, edge.verification))
        e_rank = _epistemic_conservatism.get(edge.verification, 1)
        b_ent = bridge_entries.setdefault((edge.source_id, edge.kind), {})
        prev_ent = b_ent.get(tgt_scc)
        if prev_ent is None or e_rank > prev_ent:
            b_ent[tgt_scc] = e_rank

    for caller_id, entries in caller_boiler_entries.items():
        c_set = collapsed_by_caller.setdefault(caller_id, set())
        c_verifs = collapsed_verifs.setdefault(caller_id, set())
        seen_sccs: set[int] = set()
        work: list[int] = []
        for entry_scc, entry_verif in entries:
            c_verifs.add(entry_verif)
            if entry_scc not in seen_sccs:
                seen_sccs.add(entry_scc)
                work.append(entry_scc)
        max_sub_rank = -1
        while work:
            cur_scc = work.pop()
            members = scc_nodes[cur_scc]
            accounted_boiler.update(members)
            c_set.update(members)
            if scc_ext_boiler[cur_scc]:
                c_set.update(scc_ext_boiler[cur_scc])
            max_sub_rank = max(max_sub_rank, scc_own_rank[cur_scc])
            for nxt_scc in scc_dag_out[cur_scc]:
                if nxt_scc not in seen_sccs:
                    seen_sccs.add(nxt_scc)
                    work.append(nxt_scc)
        if max_sub_rank >= 0:
            c_verifs.add(_rank_to_verification.get(max_sub_rank, "declared"))

    if any_direct_hits and bridge_entries:
        for (src_id, kind), ent_map in bridge_entries.items():
            fwd_sccs: set[int] = set(ent_map)
            work = list(ent_map)
            reached_tgts: dict[str, list[int]] = {}
            while work:
                cur_scc = work.pop()
                for end_tgt in scc_direct_hits[cur_scc]:
                    reached_tgts.setdefault(end_tgt, []).append(cur_scc)
                for nxt_scc in scc_dag_out[cur_scc]:
                    if nxt_scc not in fwd_sccs:
                        fwd_sccs.add(nxt_scc)
                        work.append(nxt_scc)
            for end_tgt, terminal_sccs in reached_tgts.items():
                on_path: set[int] = set(terminal_sccs)
                rev_work = list(terminal_sccs)
                while rev_work:
                    cur_scc = rev_work.pop()
                    for prev_scc, _ in scc_dag_rev[cur_scc]:
                        if prev_scc in fwd_sccs and prev_scc not in on_path:
                            on_path.add(prev_scc)
                            rev_work.append(prev_scc)
                max_path_rank = 0
                hop_labels: set[str] = set()
                for s_idx in on_path:
                    hop_labels.update(scc_labels[s_idx])
                    max_path_rank = max(max_path_rank, scc_own_rank[s_idx])
                    if s_idx in ent_map:
                        max_path_rank = max(max_path_rank, ent_map[s_idx])
                    max_path_rank = max(max_path_rank, scc_cycle_edge_rank[s_idx])
                    if end_tgt in scc_direct_hits[s_idx]:
                        max_path_rank = max(max_path_rank, scc_direct_hits[s_idx][end_tgt])
                    for nxt_scc, dag_r in scc_dag_out[s_idx].items():
                        if nxt_scc in on_path:
                            max_path_rank = max(max_path_rank, dag_r)
                bkey = (src_id, end_tgt, kind)
                verifs, labels = bridged_map.setdefault(bkey, ([], set()))
                verifs.append(_rank_to_verification.get(max_path_rank, "declared"))
                labels.update(hop_labels)

    unaccounted = set(boilerplate_by_id) - accounted_boiler
    if unaccounted:
        parent_set = collapsed_by_caller.setdefault(parent_node_id, set())
        parent_verifs = collapsed_verifs.setdefault(parent_node_id, set())
        seen_unacc: set[int] = set()
        work_unacc: list[int] = []
        for bid in sorted(unaccounted):
            u_scc = scc_of[bid]
            if u_scc not in seen_unacc:
                seen_unacc.add(u_scc)
                work_unacc.append(u_scc)
        max_unacc_rank = -1
        while work_unacc:
            cur_scc = work_unacc.pop()
            parent_set.update(scc_nodes[cur_scc])
            if scc_ext_boiler[cur_scc]:
                parent_set.update(scc_ext_boiler[cur_scc])
            max_unacc_rank = max(max_unacc_rank, scc_own_rank[cur_scc])
            for nxt_scc in scc_dag_out[cur_scc]:
                if nxt_scc not in seen_unacc:
                    seen_unacc.add(nxt_scc)
                    work_unacc.append(nxt_scc)
        if max_unacc_rank >= 0:
            parent_verifs.add(_rank_to_verification.get(max_unacc_rank, "declared"))

    for (src_id, tgt_id, kind), (verifs, labels) in sorted(bridged_map.items()):
        samples = sorted(labels)[:_sample_preview_size]
        kept_edges.append(
            StratumMicroEdge(
                id=f"s:bridged:{src_id}->{tgt_id}:{kind}",
                source_id=src_id,
                target_id=tgt_id,
                label=f"bridged via {len(labels)} compiler thunk(s)",
                kind=kind,
                verification=_conservative_verification(verifs),
                collapsed_count=len(labels),
                collapsed_samples=samples,
                evidence_note=f"Bridged across {len(labels)} compiler witness/thunk trampoline(s)",
            )
        )

    for caller_id in sorted(collapsed_by_caller):
        b_ids = collapsed_by_caller[caller_id]
        if not b_ids:
            continue
        n_folded = len(b_ids)
        sample_labels = sorted(
            {
                boilerplate_by_id[bid].label if bid in boilerplate_by_id else bid
                for bid in b_ids
            }
        )[:_sample_preview_size]
        summary_text = f"+{n_folded} runtime/stdlib thunks collapsed"
        kept_edges.append(
            StratumMicroEdge(
                id=f"s:collapsed:{caller_id}:thunks",
                source_id=caller_id,
                target_id=f"s:thunks:{caller_id}",
                label=summary_text,
                kind="collapsed_thunks",
                verification=_conservative_verification(
                    tuple(collapsed_verifs.get(caller_id, ()))
                ),
                collapsed_count=n_folded,
                collapsed_samples=sample_labels,
                evidence_note=summary_text,
            )
        )

    return (
        surviving_nodes,
        kept_edges,
        raw_count,
        len(surviving_nodes),
        len(boilerplate_by_id),
    )


def attach_zoom1_stratum_badges(
    repo_root: Path,
    report: TruthAtlasReport,
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
) -> list[str]:
    """Attach compact Zoom-1 `stratum_badges` onto existing `report.nodes` without altering digest."""
    effective_strict = strict_plugins or bool(get_active_stratum_artifacts())
    exec_res = run_stratum_badge_plugins(
        repo_root,
        report,
        plugins=plugins,
        enabled_names=enabled_names,
        disabled_names=disabled_names,
        allow_local_plugins=allow_local_plugins,
        local_plugin_modules=local_plugin_modules,
        strict_plugins=effective_strict,
    )
    if exec_res.badges_by_node:
        for node in report.nodes:
            incoming = exec_res.badges_by_node.get(node.id)
            if incoming:
                node.stratum_badges = _merge_badges([*node.stratum_badges, *incoming])

    for note in exec_res.notes:
        if note not in report.scan_notes:
            report.scan_notes.append(note)

    return exec_res.executed_plugins


def build_node_stratum_drilldown(
    repo_root: Path,
    report: TruthAtlasReport,
    parent_node_id: str,
    *,
    zoom: MicroStratumZoom = 2,
    unfiltered_ir: bool = False,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
) -> StratumDrilldownRead:
    """Expand and deterministically compact Zoom-2/Zoom-3 microscope strata for `parent_node_id`."""
    parent_node = next((n for n in report.nodes if n.id == parent_node_id), None)
    base_badges = list(parent_node.stratum_badges) if parent_node is not None else []

    effective_strict = strict_plugins or bool(get_active_stratum_artifacts())
    exec_res = run_stratum_expand_plugins(
        repo_root,
        report,
        parent_node_id,
        zoom,
        plugins=plugins,
        enabled_names=enabled_names,
        disabled_names=disabled_names,
        allow_local_plugins=allow_local_plugins,
        local_plugin_modules=local_plugin_modules,
        strict_plugins=effective_strict,
    )

    raw_nodes: list[StratumMicroNode] = []
    raw_edges: list[StratumMicroEdge] = []
    merged_badges: list[StratumSummaryBadge] = list(base_badges)
    notes: list[str] = list(exec_res.notes)

    for exp in exec_res.expansions:
        merged_badges.extend(exp.summary_badges)
        raw_nodes.extend(exp.nodes)
        raw_edges.extend(exp.edges)
        for nt in exp.notes:
            if nt not in notes:
                notes.append(nt)

    if not exec_res.executed_plugins and not notes:
        notes.append(
            f"No active StratumPlugin registered for Zoom {zoom}; install an optional "
            "wythe.plugins stratum inspector to populate microscope strata."
        )

    comp_nodes, comp_edges, raw_cnt, comp_cnt, thunk_cnt = compact_stratum_subgraph(
        parent_node_id,
        raw_nodes,
        raw_edges,
        unfiltered_ir=unfiltered_ir,
    )
    return StratumDrilldownRead(
        target_slug=report.target_slug,
        parent_node_id=parent_node_id,
        zoom=zoom,
        unfiltered_ir=unfiltered_ir,
        summary_badges=_merge_badges(merged_badges),
        nodes=comp_nodes,
        edges=comp_edges,
        raw_node_count=raw_cnt,
        compacted_node_count=comp_cnt,
        collapsed_thunk_count=thunk_cnt,
        active_plugins=exec_res.executed_plugins,
        notes=notes,
    )
