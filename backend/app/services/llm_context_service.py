"""Token-budgeted `llms.txt` pointer maps and surgical 3-tier Lineage Cone slicers for LLMs."""

from __future__ import annotations

import re
from collections import Counter, deque
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from app.schemas.atlas import (
    AskChatTurn,
    AtlasEdge,
    AtlasNode,
    BoundaryFinding,
    ConeCompleteness,
    ConeEdgeSummary,
    ConeSectionCount,
    ContextBudgetSummary,
    EvidenceIdentityRead,
    InvestigationCorrectionRead,
    LlmBriefRead,
    LlmContextConeReport,
    LlmNodePointer,
    StratumDrilldownRead,
    StratumZoom,
    TruthAtlasReport,
    UiFocusExplainRead,
)
from app.services.stratum_service import build_node_stratum_drilldown

DEFAULT_BRIEF_TOKENS = 2200
DEFAULT_CONE_NODES = 40
_verification_rank: dict[str, int] = {
    "verified": 0,
    "declared": 1,
    "unverified": 2,
    "broken": 3,
}


def _scan_identity_line(report: TruthAtlasReport) -> str:
    commit = report.source_commit[:12]
    dirty = (
        f"dirty({report.dirty_path_count or 0} paths)"
        if report.worktree_dirty is True
        else ("clean" if report.worktree_dirty is False else "non-git")
    )
    digest = report.content_digest[:12] if report.content_digest else "none"
    return f"commit=`{commit}`, worktree={dirty}, content_digest=`{digest}`"


def _format_cone_edge(edge: AtlasEdge) -> str:
    ev_path = f" @ {edge.evidence_path}" if edge.evidence_path else ""
    ev_note = f" — {edge.evidence_note}" if edge.evidence_note else ""
    return f"{edge.source_id} --[{edge.kind} | {edge.verification}]--> {edge.target_id}{ev_path}{ev_note}"


def _edge_sort_key(edge: AtlasEdge, neighbor_id: str) -> tuple[int, str, str, str]:
    return (_verification_rank.get(edge.verification, 9), edge.kind, neighbor_id, edge.id)


def _count_section(included: int, eligible: int) -> ConeSectionCount:
    return ConeSectionCount(
        included=included,
        eligible=eligible,
        omitted=max(0, eligible - included),
    )


def _parse_symbol_pairs(links: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for item in links:
        caller, sep, callee = item.partition("->")
        if sep and caller and callee:
            pairs.append((caller, callee))
    return pairs


def _bfs_cone_direction(
    seeds: list[str],
    edges_by_node: dict[str, list[tuple[AtlasEdge, str]]],
    valid_ids: set[str],
    *,
    reverse: bool,
) -> tuple[list[str], set[str]]:
    active_syms: dict[str, set[str]] = {sid: {"*"} for sid in seeds}
    visited: set[str] = set(seeds)
    ordered: list[str] = []
    traversed_edge_ids: set[str] = set()
    q: deque[str] = deque(seeds)
    while q:
        cur = q.popleft()
        cur_syms = active_syms.get(cur, {"*"})
        out_items = edges_by_node.get(cur, ())
        has_scoped = any(_parse_symbol_pairs(e.symbol_links) for e, _ in out_items)
        eff_syms = cur_syms if has_scoped else {"*"}
        for edge, nxt in out_items:
            if nxt not in valid_ids:
                continue
            pairs = _parse_symbol_pairs(edge.symbol_links)
            if pairs:
                if reverse:
                    next_syms = {
                        caller
                        for caller, callee in pairs
                        if "*" in eff_syms or callee == "*" or callee in eff_syms
                    }
                else:
                    next_syms = {
                        callee
                        for caller, callee in pairs
                        if "*" in eff_syms or caller == "*" or caller in eff_syms
                    }
                if not next_syms:
                    continue
            else:
                if "*" not in eff_syms:
                    continue
                next_syms = {"*"}
            traversed_edge_ids.add(edge.id)
            prev_nxt = active_syms.get(nxt)
            if prev_nxt is None:
                active_syms[nxt] = set(next_syms)
                if nxt not in visited:
                    visited.add(nxt)
                    ordered.append(nxt)
                q.append(nxt)
            else:
                added = next_syms - prev_nxt
                if added:
                    prev_nxt.update(added)
                    q.append(nxt)
    return ordered, traversed_edge_ids


def _interleave_cone_nodes(
    seed_ids: list[str],
    down_order: list[str],
    up_order: list[str],
    *,
    budget: int | None,
) -> set[str]:
    """Interleave downstream and upstream BFS queues 1-for-1 when `budget` applies."""
    cone_ids: set[str] = set(seed_ids)
    if budget is None:
        cone_ids.update(down_order)
        cone_ids.update(up_order)
        return cone_ids

    i_down = 0
    i_up = 0
    while len(cone_ids) < budget and (i_down < len(down_order) or i_up < len(up_order)):
        while i_down < len(down_order):
            cand = down_order[i_down]
            i_down += 1
            if cand not in cone_ids:
                cone_ids.add(cand)
                break
        if len(cone_ids) >= budget:
            break
        while i_up < len(up_order):
            cand = up_order[i_up]
            i_up += 1
            if cand not in cone_ids:
                cone_ids.add(cand)
                break
    return cone_ids


def _ptr(node: AtlasNode) -> str:
    return f"{node.source_file}:{node.line}" if node.line else node.source_file


def _to_llm_pointer(node: AtlasNode) -> LlmNodePointer:
    return LlmNodePointer(
        id=node.id,
        tier=node.tier,
        subkind=node.subkind,
        label=node.label,
        pointer=_ptr(node),
        status=node.status,
        columns=list(node.columns[:8]),
        http_paths=list(node.http_paths[:6]),
    )


def build_llms_txt_brief(
    report: TruthAtlasReport,
    *,
    max_tokens: int = DEFAULT_BRIEF_TOKENS,
) -> LlmBriefRead:
    """Render a deterministic, pointer-first `llms.txt` architectural map bounded to `max_tokens`."""
    char_budget = max(1600, max_tokens * 4)
    s = report.summary
    commit_short = report.source_commit[:12]

    in_deg: Counter[str] = Counter()
    out_deg: Counter[str] = Counter()
    for e in report.edges:
        out_deg[e.source_id] += 1
        in_deg[e.target_id] += 1

    tables = sorted(
        (
            n
            for n in report.nodes
            if n.tier == "truth" and n.subkind in ("table", "entity_store", "entitlement_spec")
        ),
        key=lambda n: (-(n.read_by_count + n.written_by_count), -in_deg[n.id], n.label),
    )
    guards = sorted(
        (n for n in report.nodes if n.tier == "truth" and n.subkind == "sql_function"),
        key=lambda n: (-in_deg[n.id], n.label),
    )
    queues = sorted(
        (n for n in report.nodes if n.tier == "truth" and n.subkind == "cache_store"),
        key=lambda n: (-(n.read_by_count + n.written_by_count), n.label),
    )
    routes = sorted(
        (n for n in report.nodes if n.tier == "manipulate" and n.subkind in ("route", "ipc_handler")),
        key=lambda n: (-(in_deg[n.id] + out_deg[n.id]), n.label),
    )
    services = sorted(
        (
            n
            for n in report.nodes
            if n.tier == "manipulate" and n.subkind not in ("route", "ipc_handler")
        ),
        key=lambda n: (-(in_deg[n.id] + out_deg[n.id]), n.label),
    )
    displays = sorted(
        (n for n in report.nodes if n.tier == "display"),
        key=lambda n: (
            0 if n.subkind in ("page", "cli") else 1,
            -(in_deg[n.id] + out_deg[n.id]),
            n.label,
        ),
    )

    scale = 1.0 if max_tokens >= 1800 else max(0.4, max_tokens / 1800.0)
    lim_tbl = max(5, int(14 * scale))
    lim_rt = max(5, int(12 * scale))
    lim_svc = max(5, int(12 * scale))
    lim_disp = max(5, int(10 * scale))
    lim_ch = max(4, int(10 * scale))

    lines: list[str] = [
        f"# {report.target_name} ({report.target_slug}) — Wythe 3-Tier Map",
        "",
        (
            f"> Stack: `{report.stack_profile}` | Commit: `{commit_short}` | "
            f"Digest: `{report.content_digest[:16]}` | Gate: `{report.gate.verdict}` "
            f"(blocking={s.blocking_findings}, warnings={s.warning_findings})"
        ),
        (
            f"> Topology: {s.truth_tables} SQL tables, {s.sql_functions} SQL guards, "
            f"{s.ephemeral_stores} Redis/queue lanes | {s.manipulator_routes} route modules, "
            f"{s.manipulator_services} services/workers | {s.display_pages} pages, "
            f"{s.display_hooks_and_clients} clients/hooks | {s.verified_edges} verified edges, "
            f"{s.end_to_end_chains} E2E chains"
        ),
        "",
        "## Tier 1 — Database Truth & Ephemeral Queue Pointers",
    ]
    for t in tables[:lim_tbl]:
        cols = f" cols=[{', '.join(t.columns[:5])}]" if t.columns else ""
        sk_tag = f"[{t.subkind}] " if t.subkind != "table" else ""
        lines.append(
            f"- {sk_tag}`{t.label}` (`{_ptr(t)}`) — status={t.status}, readers={t.read_by_count}, writers={t.written_by_count}{cols}"
        )
    if len(tables) > lim_tbl:
        lines.append(f"- … +{len(tables) - lim_tbl} more SQL tables (query via `wythe context {report.target_slug} <table>`)")
    for g in guards[:6]:
        lines.append(f"- [sql_guard] `{g.label}` (`{_ptr(g)}`) — inbound={in_deg[g.id]}")
    for q in queues[:8]:
        purpose_tag = (
            f", purpose={q.store_purpose.intended_use}, verify={q.store_purpose.verification_summary or q.verification_note}"
            if q.store_purpose is not None
            else (f", verify={q.verification_note}" if q.verification_note else "")
        )
        lines.append(
            f"- [ephemeral_lane] `{q.label}` (`{_ptr(q)}`) — status={q.status}, "
            f"consumers={q.read_by_count}, producers={q.written_by_count}{purpose_tag}"
        )

    lines.extend(["", "## Tier 2 — Backend Manipulation Entry Doors & Hubs"])
    for r in routes[:lim_rt]:
        fallback_lbl = "ipc" if r.subkind == "ipc_handler" else "router"
        paths = ", ".join(r.http_paths[:3]) if r.http_paths else fallback_lbl
        lines.append(f"- [{r.subkind}] `{r.label}` (`{_ptr(r)}`) — {paths}")
    for sv in services[:lim_svc]:
        lines.append(
            f"- [{sv.subkind}] `{sv.label}` (`{_ptr(sv)}`) — status={sv.status}, in={in_deg[sv.id]}, out={out_deg[sv.id]}"
        )

    lines.extend(["", "## Tier 3 — Frontend Display Surfaces & API Clients"])
    for d in displays[:lim_disp]:
        paths = f" -> {', '.join(d.http_paths[:3])}" if d.http_paths else ""
        lines.append(f"- [{d.subkind}] `{d.label}` (`{_ptr(d)}`){paths}")

    if report.chains:
        nodes_map = {n.id: n for n in report.nodes}
        lines.extend(["", "## Static End-to-End 3-Tier Chains (Sample)"])
        lines.append(
            "> Static verification reflects AST/route matching; it does not prove runtime execution."
        )
        seen_routes: set[str] = set()
        picked = 0
        for ch in report.chains:
            if ch.http_path in seen_routes and len(report.chains) > lim_ch:
                continue
            seen_routes.add(ch.http_path)
            tbls = ", ".join(ch.truth_table_labels[:4])
            d_node = nodes_map.get(ch.display_node_id)
            r_node = nodes_map.get(ch.route_node_id)
            d_ptr = _ptr(d_node) if d_node else ch.display_node_id
            r_ptr = _ptr(r_node) if r_node else ch.route_node_id
            state = "static_verified" if ch.verified else "partial"
            lines.append(
                f"- [{state}] `{ch.display_label}` (`{d_ptr}`) -> `{ch.http_method} {ch.http_path}` (`{r_ptr}`) -> [{tbls}]"
            )
            picked += 1
            if picked >= lim_ch:
                break

    if report.findings:
        lines.extend(["", "## Active Boundary & Accessibility Findings (Grouped)"])
        by_rule: dict[str, list] = {}
        for f in report.findings:
            by_rule.setdefault(f.rule_code, []).append(f)
        for rcode in sorted(by_rule):
            items = by_rule[rcode]
            sample_locs = ", ".join(f"`{it.source_file}:{it.line}`" for it in items[:4])
            more = f" (+{len(items) - 4} more)" if len(items) > 4 else ""
            lines.append(
                f"- **{rcode}** ({items[0].severity}, count={len(items)}): {items[0].title} — e.g. {sample_locs}{more}"
            )

    lines.extend(
        [
            "",
            "## Agent Drill-Down Commands",
            f"- Subgraph cone: `wythe context {report.target_slug} <table_or_file_or_route>`",
            f"- Working-tree blast radius: `wythe diff {report.target_slug} --base WORKING`",
            f"- Strict boundary gate: `wythe gate {report.target_slug}`",
        ]
    )

    body = "\n".join(lines)
    if len(body) > char_budget:
        body = body[: char_budget - 64].rsplit("\n", 1)[0] + "\n- … (truncated to token budget)"
    return LlmBriefRead(
        target_slug=report.target_slug,
        source_commit=report.source_commit,
        approx_tokens=max(1, len(body) // 4),
        markdown=body,
    )


def _resolve_seed_nodes(report: TruthAtlasReport, raw_query: str) -> tuple[list[AtlasNode], list[str]]:
    q = raw_query.strip().lower()
    if not q:
        return [], []

    exact: list[AtlasNode] = []
    partial: list[AtlasNode] = []
    for n in report.nodes:
        nid = n.id.lower()
        lbl = n.label.lower()
        sf = n.source_file.lower()
        base = sf.rsplit("/", 1)[-1]
        base_stem = base.rsplit(".", 1)[0]
        paths_lc = [p.lower() for p in n.http_paths]
        if q in (nid, lbl, sf, base, base_stem) or q in paths_lc:
            exact.append(n)
        elif (
            q in nid
            or q in lbl
            or q in sf
            or any(q in p for p in paths_lc)
        ):
            partial.append(n)

    chosen = exact if exact else partial[:6]
    if chosen:
        return chosen, []

    tokens = [tok for tok in q.replace("/", " ").replace("_", " ").replace("-", " ").split() if len(tok) >= 2]
    scored: list[tuple[int, str]] = []
    for n in report.nodes:
        hay = f"{n.id} {n.label} {n.source_file} {' '.join(n.http_paths)}".lower()
        hits = sum(1 for tok in tokens if tok in hay)
        if hits > 0:
            scored.append((hits, f"{n.id} ({_ptr(n)})"))
    scored.sort(key=lambda item: (-item[0], item[1]))
    suggestions = [s for _, s in scored[:8]]
    return [], suggestions


def _slice_cone_strata(
    report: TruthAtlasReport,
    seed_ids: list[str],
    cone_nodes: list[AtlasNode],
    *,
    zoom: Literal[2, 3],
    unfiltered_ir: bool,
    max_nodes: int,
    full: bool,
    local_plugin_modules: Sequence[str] | None = None,
    allow_local_plugins: bool = False,
) -> tuple[list[StratumDrilldownRead], ConeSectionCount, ConeSectionCount]:
    repo_root = Path(report.repo_path).resolve()
    ordered_parents = (
        list(dict.fromkeys([*seed_ids, *(n.id for n in cone_nodes)]))
        if full
        else list(dict.fromkeys(seed_ids))
    )

    seed_lookup = set(seed_ids)
    raw_drills: list[StratumDrilldownRead] = []
    for idx, pid in enumerate(ordered_parents):
        drill = build_node_stratum_drilldown(
            repo_root,
            report,
            pid,
            zoom=zoom,
            unfiltered_ir=unfiltered_ir,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
        )
        has_payload = bool(drill.nodes or drill.edges or drill.summary_badges)
        if has_payload or (pid in seed_lookup and (idx == 0 or drill.active_plugins)):
            raw_drills.append(drill)

    eligible_nodes = sum(len(d.nodes) for d in raw_drills)
    eligible_edges = sum(len(d.edges) for d in raw_drills)
    if full:
        return (
            raw_drills,
            _count_section(eligible_nodes, eligible_nodes),
            _count_section(eligible_edges, eligible_edges),
        )

    rem_nodes = max(25, max_nodes)
    rem_edges = 60
    bounded_drills: list[StratumDrilldownRead] = []
    inc_nodes = 0
    inc_edges = 0
    for drill in raw_drills:
        ordered_d_edges = sorted(
            drill.edges,
            key=lambda e: (
                0 if e.collapsed_count > 0 else 1,
                0 if e.verification in ("unverified", "broken") else 1,
                _verification_rank.get(e.verification, 9),
                e.id,
            ),
        )
        ordered_d_nodes = sorted(
            drill.nodes,
            key=lambda n: (
                0 if n.verification in ("unverified", "broken") else 1,
                _verification_rank.get(n.verification, 9),
                n.id,
            ),
        )
        kept_n = ordered_d_nodes[:rem_nodes]
        kept_e = ordered_d_edges[:rem_edges]
        rem_nodes = max(0, rem_nodes - len(kept_n))
        rem_edges = max(0, rem_edges - len(kept_e))
        inc_nodes += len(kept_n)
        inc_edges += len(kept_e)
        bounded_drills.append(drill.model_copy(update={"nodes": kept_n, "edges": kept_e}))

    return (
        bounded_drills,
        _count_section(inc_nodes, eligible_nodes),
        _count_section(inc_edges, eligible_edges),
    )


def build_lineage_cone_slice(
    report: TruthAtlasReport,
    query: str,
    *,
    max_nodes: int = DEFAULT_CONE_NODES,
    full: bool = False,
    zoom: StratumZoom = 1,
    unfiltered_ir: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    allow_local_plugins: bool = False,
) -> LlmContextConeReport:
    """Slice the directional upstream/downstream 3-tier Lineage Cone around `query`."""
    zoom_flags = (
        f" --zoom {zoom}" + (" --unfiltered-ir" if unfiltered_ir else "")
        if zoom in (2, 3)
        else ""
    )
    full_hint = f'wythe context {report.target_slug} "{query}"{zoom_flags} --full'
    seeds, suggestions = _resolve_seed_nodes(report, query)
    if not seeds:
        hint = (
            f"No node matched `{query}` in `{report.target_slug}`."
            + (f" Closest candidates: {', '.join(suggestions)}" if suggestions else "")
        )
        return LlmContextConeReport(
            target_slug=report.target_slug,
            query=query,
            source_commit=report.source_commit,
            worktree_dirty=report.worktree_dirty,
            dirty_path_count=report.dirty_path_count,
            content_digest=report.content_digest,
            zoom=zoom,
            suggestions=suggestions,
            completeness=ConeCompleteness(
                is_complete=True,
                full_export=full,
                node_budget=0 if full else max_nodes,
                full_export_hint=full_hint,
            ),
            approx_tokens=max(1, len(hint) // 4),
            markdown=f"# Lineage Cone :: `{query}` ({report.target_slug})\n\n{hint}",
        )

    nodes_by_id = {n.id: n for n in report.nodes}
    valid_ids = set(nodes_by_id)
    seed_ids = [n.id for n in seeds]
    seed_set = set(seed_ids)
    fwd_raw: dict[str, list[tuple[tuple[int, str, str, str], AtlasEdge, str]]] = {}
    rev_raw: dict[str, list[tuple[tuple[int, str, str, str], AtlasEdge, str]]] = {}
    for e in report.edges:
        is_seed_edge = e.source_id in seed_set or e.target_id in seed_set
        if not is_seed_edge and e.verification != "verified":
            continue
        fwd_raw.setdefault(e.source_id, []).append((_edge_sort_key(e, e.target_id), e, e.target_id))
        rev_raw.setdefault(e.target_id, []).append((_edge_sort_key(e, e.source_id), e, e.source_id))
    fwd_edges_by_node = {
        k: [(edge, nid) for _, edge, nid in sorted(v, key=lambda item: item[0])]
        for k, v in fwd_raw.items()
    }
    rev_edges_by_node = {
        k: [(edge, nid) for _, edge, nid in sorted(v, key=lambda item: item[0])]
        for k, v in rev_raw.items()
    }

    down_order, down_edge_ids = _bfs_cone_direction(seed_ids, fwd_edges_by_node, valid_ids, reverse=False)
    up_order, up_edge_ids = _bfs_cone_direction(seed_ids, rev_edges_by_node, valid_ids, reverse=True)
    traversed_edge_ids = down_edge_ids | up_edge_ids
    full_cone_ids = seed_set | set(down_order) | set(up_order)
    budget = None if full else max(max_nodes, len(seed_ids))
    cone_ids = _interleave_cone_nodes(seed_ids, down_order, up_order, budget=budget)

    cone_nodes = [nodes_by_id[nid] for nid in sorted(cone_ids)]
    disp_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "display"]
    manip_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "manipulate"]
    truth_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "truth"]

    eligible_edges = [
        e
        for e in report.edges
        if e.source_id in full_cone_ids
        and e.target_id in full_cone_ids
        and (e.id in traversed_edge_ids or e.source_id in seed_set or e.target_id in seed_set)
    ]
    in_cone_edges = sorted(
        (e for e in eligible_edges if e.source_id in cone_ids and e.target_id in cone_ids),
        key=lambda e: (
            0 if (e.source_id in seed_set or e.target_id in seed_set) else 1,
            _verification_rank.get(e.verification, 9),
            e.source_id,
            e.target_id,
            e.kind,
            e.id,
        ),
    )
    selected_edges = in_cone_edges if full else in_cone_edges[:80]
    md_edges = selected_edges if full else selected_edges[:35]
    cone_edges = [_format_cone_edge(e) for e in selected_edges]
    cone_edge_items = [
        ConeEdgeSummary(
            id=e.id,
            source_id=e.source_id,
            target_id=e.target_id,
            kind=e.kind,
            verification=e.verification,
            evidence_path=e.evidence_path,
            evidence_note=e.evidence_note,
            policy_field_consumption=e.policy_field_consumption,
        )
        for e in selected_edges
    ]

    seed_labels = {n.label for n in seeds}
    seed_paths = {p for n in seeds for p in n.http_paths}
    eligible_chains = [
        ch
        for ch in report.chains
        if ch.display_node_id in seed_set
        or ch.route_node_id in seed_set
        or ch.http_path in seed_paths
        or ch.http_path in seed_labels
        or bool(seed_labels.intersection(ch.truth_table_labels))
        or bool(seed_set.intersection(ch.manipulator_node_ids))
        or bool(seed_set.intersection(ch.truth_table_ids))
        or bool(seed_set.intersection(ch.via_node_ids))
    ]
    selected_chains = eligible_chains if full else eligible_chains[:15]

    def _cone_finding_in_scope(f: BoundaryFinding, scope_ids: set[str]) -> bool:
        if f.node_id in seed_set or f.target_node_id in seed_set:
            return True
        if f.node_id in scope_ids:
            return True
        return bool(f.rule_code.startswith("TRUTH-") and f.target_node_id in scope_ids)

    eligible_findings = [
        f for f in report.findings if _cone_finding_in_scope(f, full_cone_ids)
    ]
    eligible_seed_findings = [
        f for f in eligible_findings if f.node_id in seed_set or f.target_node_id in seed_set
    ]
    seed_finding_ids = {f.id for f in eligible_seed_findings}
    in_cone_non_seed_findings = [
        f
        for f in eligible_findings
        if f.id not in seed_finding_ids and _cone_finding_in_scope(f, cone_ids)
    ]
    ordered_findings: list[BoundaryFinding] = eligible_seed_findings + in_cone_non_seed_findings
    selected_findings = ordered_findings if full else ordered_findings[:25]
    selected_seed_finding_count = sum(1 for f in selected_findings if f.id in seed_finding_ids)

    nodes_cnt = _count_section(len(cone_ids), len(full_cone_ids))
    up_cnt = _count_section(len(cone_ids & set(up_order)), len(up_order))
    down_cnt = _count_section(len(cone_ids & set(down_order)), len(down_order))
    edges_cnt = _count_section(len(selected_edges), len(eligible_edges))
    md_edges_cnt = _count_section(len(md_edges), len(eligible_edges))
    findings_cnt = _count_section(len(selected_findings), len(eligible_findings))
    seed_findings_cnt = _count_section(selected_seed_finding_count, len(eligible_seed_findings))
    chains_cnt = _count_section(len(selected_chains), len(eligible_chains))
    if zoom in (2, 3):
        stratum_drills, s_nodes_cnt, s_edges_cnt = _slice_cone_strata(
            report,
            seed_ids,
            cone_nodes,
            zoom=zoom,
            unfiltered_ir=unfiltered_ir,
            max_nodes=max_nodes,
            full=full,
            local_plugin_modules=local_plugin_modules,
            allow_local_plugins=allow_local_plugins,
        )
    else:
        stratum_drills = []
        s_nodes_cnt = ConeSectionCount()
        s_edges_cnt = ConeSectionCount()

    truncation_reasons: list[str] = []
    if nodes_cnt.omitted > 0:
        truncation_reasons.append(f"node_budget:{nodes_cnt.included}/{nodes_cnt.eligible}")
    if edges_cnt.omitted > 0:
        truncation_reasons.append(f"json_edges_capped:{edges_cnt.included}/{edges_cnt.eligible}")
    if md_edges_cnt.omitted > 0:
        truncation_reasons.append(
            f"markdown_edges_capped:{md_edges_cnt.included}/{md_edges_cnt.eligible}"
        )
    if seed_findings_cnt.omitted > 0:
        truncation_reasons.append(
            f"seed_findings_capped:{seed_findings_cnt.included}/{seed_findings_cnt.eligible}"
        )
    if findings_cnt.omitted > 0:
        truncation_reasons.append(
            f"findings_capped:{findings_cnt.included}/{findings_cnt.eligible}"
        )
    if chains_cnt.omitted > 0:
        truncation_reasons.append(f"chains_capped:{chains_cnt.included}/{chains_cnt.eligible}")
    if s_nodes_cnt.omitted > 0:
        truncation_reasons.append(
            f"stratum_nodes_capped:{s_nodes_cnt.included}/{s_nodes_cnt.eligible}"
        )
    if s_edges_cnt.omitted > 0:
        truncation_reasons.append(
            f"stratum_edges_capped:{s_edges_cnt.included}/{s_edges_cnt.eligible}"
        )

    completeness = ConeCompleteness(
        is_complete=not truncation_reasons,
        full_export=full,
        node_budget=len(full_cone_ids) if full else (budget or len(full_cone_ids)),
        nodes=nodes_cnt,
        upstream_nodes=up_cnt,
        downstream_nodes=down_cnt,
        edges=edges_cnt,
        markdown_edges=md_edges_cnt,
        findings=findings_cnt,
        seed_findings=seed_findings_cnt,
        chains=chains_cnt,
        stratum_nodes=s_nodes_cnt,
        stratum_edges=s_edges_cnt,
        truncation_reasons=truncation_reasons,
        full_export_hint=full_hint,
    )

    md: list[str] = [
        f"# 3-Tier Lineage Cone :: `{query}` ({report.target_slug} | {_scan_identity_line(report)})",
        f"> Matched seeds ({len(seeds)}): {', '.join(f'`{s.id}` (`{_ptr(s)}`)' for s in seeds)}",
        (
            "> Guardrail: Distinguish declared store purpose from verified lifetime/invalidation, "
            "discovery location from causal write `file:line`, and suggested changes from verified fixes."
        ),
    ]
    if completeness.is_complete:
        md.append(
            f"> Completeness: complete slice (nodes={nodes_cnt.included}/{nodes_cnt.eligible}, "
            f"edges={md_edges_cnt.included}/{md_edges_cnt.eligible}, "
            f"findings={findings_cnt.included}/{findings_cnt.eligible})."
        )
    else:
        md.append(
            f"> Completeness: TRUNCATED (nodes={nodes_cnt.included}/{nodes_cnt.eligible} "
            f"[upstream={up_cnt.included}/{up_cnt.eligible}, downstream={down_cnt.included}/{down_cnt.eligible}], "
            f"markdown_edges={md_edges_cnt.included}/{md_edges_cnt.eligible}, "
            f"seed_findings={seed_findings_cnt.included}/{seed_findings_cnt.eligible}, "
            f"findings={findings_cnt.included}/{findings_cnt.eligible}, "
            f"chains={chains_cnt.included}/{chains_cnt.eligible}). "
            f"Retrieve omitted context via `{full_hint}`."
        )
    md.append("")
    if disp_ptrs:
        md.append(f"## Tier 3 — Upstream Display ({len(disp_ptrs)})")
        for p in disp_ptrs:
            hp = f" routes={p.http_paths}" if p.http_paths else ""
            md.append(f"- [{p.subkind}] `{p.label}` (`{p.pointer}`) status={p.status}{hp}")
        md.append("")
    if manip_ptrs:
        manip_by_id = {n.id: n for n in cone_nodes if n.tier == "manipulate"}
        md.append(f"## Tier 2 — Backend Manipulation ({len(manip_ptrs)})")
        for p in manip_ptrs:
            hp = f" routes={p.http_paths}" if p.http_paths else ""
            mn = manip_by_id.get(p.id)
            vnote = f" | verification={mn.verification_note}" if (mn and mn.verification_note) else ""
            md.append(f"- [{p.subkind}] `{p.label}` (`{p.pointer}`) status={p.status}{hp}{vnote}")
        md.append("")
    if truth_ptrs:
        truth_by_id = {n.id: n for n in cone_nodes if n.tier == "truth"}
        md.append(f"## Tier 1 — Downstream Truth & Queues ({len(truth_ptrs)})")
        for p in truth_ptrs:
            cols = f" cols=[{', '.join(p.columns)}]" if p.columns else ""
            tn = truth_by_id.get(p.id)
            pnote = ""
            if tn and tn.store_purpose is not None:
                vsum = tn.store_purpose.verification_summary or tn.verification_note or "unverified"
                pnote = f" | declared_purpose={tn.store_purpose.intended_use} | verification={vsum}"
            elif tn and tn.verification_note:
                pnote = f" | verification={tn.verification_note}"
            md.append(f"- [{p.subkind}] `{p.label}` (discovery=`{p.pointer}`) status={p.status}{cols}{pnote}")
        md.append("")
    if selected_chains:
        ch_suffix = (
            f"showing {len(selected_chains)} of {chains_cnt.eligible}; {chains_cnt.omitted} omitted"
            if chains_cnt.omitted > 0
            else str(len(selected_chains))
        )
        md.append(f"## End-to-End 3-Tier Chains ({ch_suffix})")
        for ch in selected_chains:
            d_node = nodes_by_id.get(ch.display_node_id)
            r_node = nodes_by_id.get(ch.route_node_id)
            d_ptr = _ptr(d_node) if d_node else ch.display_node_id
            r_ptr = _ptr(r_node) if r_node else ch.route_node_id
            state = "static_verified" if ch.verified else "partial"
            md.append(
                f"- [{state}] `{ch.display_label}` (`{d_ptr}`) -> `{ch.http_method} {ch.http_path}` (`{r_ptr}`) -> [{', '.join(ch.truth_table_labels)}]"
            )
        md.append("")
    if md_edges:
        edge_counts = Counter(e.verification for e in eligible_edges)
        md_heading_count = (
            f"showing {len(md_edges)} of {len(eligible_edges)}; {md_edges_cnt.omitted} omitted"
            if md_edges_cnt.omitted > 0
            else str(len(md_edges))
        )
        md.append(f"## Cone Connections ({md_heading_count})")
        md.append(
            "> Static verification scope: edges show static AST/route/import links "
            f"(verified={edge_counts['verified']}, declared={edge_counts['declared']}, "
            f"unverified={edge_counts['unverified']}, broken={edge_counts['broken']}); "
            "static matching does not prove runtime execution or business-logic acceptance."
        )
        for edge in md_edges:
            md.append(f"- `{_format_cone_edge(edge)}`")
        md.append("")
    if selected_findings:
        f_heading = (
            f"showing {len(selected_findings)} of {findings_cnt.eligible}; {findings_cnt.omitted} omitted"
            if findings_cnt.omitted > 0
            else str(len(selected_findings))
        )
        md.append(f"## Findings in Cone (requires evidence review; {f_heading})")
        for cf in selected_findings:
            actor_key = "reader" if cf.rule_code == "MANIP-001" else "writer"
            writer_tag = (
                f" [{actor_key}=`{cf.node_id}` -> target=`{cf.target_node_id}`]"
                if cf.target_node_id and cf.target_node_id != cf.node_id
                else ""
            )
            md.append(
                f"- **{cf.rule_code}** [{cf.severity} | {cf.confidence} | {cf.evidence_strength}] "
                f"`{cf.source_file}:{cf.line}`{writer_tag} — "
                f"{cf.title} | Suggested remediation (unverified): {cf.remediation}"
            )
        md.append("")

    if zoom in (2, 3):
        s_edge_counts = Counter(e.verification for d in stratum_drills for e in d.edges)
        s_mode = "unfiltered" if unfiltered_ir else "compacted"
        md.append(f"## Microscope Strata (Zoom {zoom} | {s_mode})")
        md.append(
            "> Stratum edge epistemics: "
            f"verified={s_edge_counts['verified']}, declared={s_edge_counts['declared']}, "
            f"unverified={s_edge_counts['unverified']}, broken={s_edge_counts['broken']} "
            f"(micro_nodes={s_nodes_cnt.included}/{s_nodes_cnt.eligible}, "
            f"micro_edges={s_edges_cnt.included}/{s_edges_cnt.eligible})."
        )
        for drill in stratum_drills:
            badge_str = (
                ", ".join(f"{b.key}={b.count}" for b in drill.summary_badges)
                if drill.summary_badges
                else "none"
            )
            plugins_str = ", ".join(drill.active_plugins) if drill.active_plugins else "none"
            md.append(
                f"### Parent `{drill.parent_node_id}` "
                f"(plugins=[{plugins_str}], badges=[{badge_str}], "
                f"raw_nodes={drill.raw_node_count}, compacted_nodes={drill.compacted_node_count}, "
                f"collapsed_thunks={drill.collapsed_thunk_count})"
            )
            shown_mn = drill.nodes if full else drill.nodes[:20]
            for mn in shown_mn:
                loc = f" @ `{mn.source_file}:{mn.line or 1}`" if mn.source_file else ""
                md.append(f"- [{mn.kind} | {mn.verification}] `{mn.label}` (`{mn.id}`){loc}")
            shown_me = drill.edges if full else drill.edges[:25]
            for me in shown_me:
                note_part = me.label or me.evidence_note
                suffix = f" — {note_part}" if note_part else ""
                md.append(
                    f"- `{me.source_id} --[{me.kind} | {me.verification}]--> {me.target_id}`{suffix}"
                )
            for nt in drill.notes:
                md.append(f"- Note: {nt}")

    md_text = "\n".join(md).strip()
    return LlmContextConeReport(
        target_slug=report.target_slug,
        query=query,
        source_commit=report.source_commit,
        worktree_dirty=report.worktree_dirty,
        dirty_path_count=report.dirty_path_count,
        content_digest=report.content_digest,
        zoom=zoom,
        matched_seed_ids=seed_ids,
        upstream_display_nodes=disp_ptrs,
        manipulator_nodes=manip_ptrs,
        downstream_truth_nodes=truth_ptrs,
        cone_edges=cone_edges,
        cone_edge_items=cone_edge_items,
        matching_chains=selected_chains,
        cone_findings=selected_findings,
        stratum_drilldowns=stratum_drills,
        completeness=completeness,
        approx_tokens=max(1, len(md_text) // 4),
        markdown=md_text,
    )


def _fit_complete_items(
    items: Sequence[str],
    *,
    remaining_chars: int,
    max_items: int,
) -> tuple[list[str], int]:
    """Include whole markdown items up to `max_items` and `remaining_chars` without mid-line slicing."""
    chosen: list[str] = []
    used = 0
    for item in items:
        if len(chosen) >= max_items:
            break
        cost = len(item) + 1
        if chosen and used + cost > remaining_chars:
            break
        if not chosen and len(item) > remaining_chars:
            lines = item.splitlines()
            head_lines: list[str] = []
            acc = 0
            for ln in lines:
                if acc + len(ln) + 1 > max(180, remaining_chars):
                    break
                head_lines.append(ln)
                acc += len(ln) + 1
            if head_lines:
                chosen.append("\n".join(head_lines))
            break
        chosen.append(item)
        used += cost
    return chosen, max(0, len(items) - len(chosen))


_plain_english_prompt_re = re.compile(
    r"(?:"
    r"\bplain[- ]english\b"
    r"|\blaym[ae]n(?:'?s)?\b"
    r"|\bsimple\s+terms\b"
    r"|\bsimply\b"
    r"|\beli5\b"
    r"|\bnon[- ]technical\b"
    r"|\bin\s+short\b"
    r"|\btl;?dr\b"
    r")",
    re.IGNORECASE,
)


def build_section_budgeted_ask_prompt(
    *,
    question: str,
    focus: UiFocusExplainRead,
    report: TruthAtlasReport | None,
    cone: LlmContextConeReport | None,
    evidence_identity: EvidenceIdentityRead | None,
    corrections: Sequence[InvestigationCorrectionRead] = (),
    live_viewport_brief: str | None = None,
    history: Sequence[AskChatTurn] = (),
    max_prompt_chars: int = 7200,
    plain_english: bool | None = None,
) -> tuple[str, str, ContextBudgetSummary]:
    """Build section-aware prompts (`local_prompt`, `apple_prompt`, `ContextBudgetSummary`)."""
    eff_plain = (
        bool(_plain_english_prompt_re.search(question))
        if plain_english is None
        else bool(plain_english)
    )
    included_counts: dict[str, int] = {}
    omitted_counts: dict[str, int] = {}
    truncated_sections: list[str] = []

    ev_line = (
        f"- Evidence Revision: `{evidence_identity.evidence_revision_id}` | "
        f"Commit: `{evidence_identity.source_commit[:24]}` | "
        f"Digest: `{evidence_identity.content_digest[:16]}` | "
        f"Coverage Complete: `{evidence_identity.coverage_complete}`"
        if evidence_identity is not None
        else f"- Commit: `{focus.source_commit[:24]}`"
    )
    sel_lines = [
        "## 1. Evidence & Selection Identity",
        *(() if eff_plain else (ev_line,)),
        f"- Target: `{focus.target_name}` (`{focus.active_slug}`) | Session: `{focus.session_id or 'default'}` (focus_rev={focus.focus_revision})",
        f"- Headline: {focus.headline}",
        f"- Visual / Lineage Summary: {focus.color_reason}",
    ]
    if focus.focused_node is not None:
        sel_lines.append(
            f"- Selected Node: `{focus.focused_node.id}` (`{focus.focused_node.pointer}`, status=`{focus.focused_node.status}`)"
        )
        if report is not None:
            fn_obj = next((n for n in report.nodes if n.id == focus.focused_node.id), None)
            if fn_obj and fn_obj.verification_note:
                sel_lines.append(f"- Node Verification Note: {fn_obj.verification_note}")
            if fn_obj and fn_obj.policy_field_consumption:
                pfc = fn_obj.policy_field_consumption
                sel_lines.append(
                    f"- Node PolicyFieldConsumption: state=`{pfc.state}` (`{pfc.mechanism}`), "
                    f"consumed={pfc.consumed_columns}, unconsumed={pfc.unconsumed_policy_columns}, "
                    f"substituted={pfc.substituted_constants}, fallbacks={pfc.fallback_constants} — {pfc.note}"
                )
    if focus.selected_edge_id:
        sel_lines.append(f"- Selected Edge: `{focus.selected_edge_id}`")
        if report is not None:
            fe_obj = next((e for e in report.edges if e.id == focus.selected_edge_id), None)
            if fe_obj and fe_obj.policy_field_consumption:
                epfc = fe_obj.policy_field_consumption
                sel_lines.append(
                    f"- Edge PolicyFieldConsumption: state=`{epfc.state}` (`{epfc.mechanism}`), "
                    f"consumed={epfc.consumed_columns}, unconsumed={epfc.unconsumed_policy_columns}, "
                    f"substituted={epfc.substituted_constants}, fallbacks={epfc.fallback_constants} — {epfc.note}"
                )
    if focus.selected_finding_id:
        sel_lines.append(f"- Selected Finding: `{focus.selected_finding_id}`")

    sections: list[str] = ["\n".join(sel_lines)]
    used_chars = len(sections[0]) + len(question) + 80

    # Section 2: Active Human Investigation Corrections (high priority, never dropped silently)
    corr_items = [
        f"- [{c.kind}]"
        + (f" on `{c.target_ref_id}`" if c.target_ref_id else "")
        + f" (`{c.correction_id}`, promoted_to_ruling=False): {c.note}"
        for c in corrections
    ]
    inc_corr, omit_corr = _fit_complete_items(
        corr_items,
        remaining_chars=max(600, max_prompt_chars - used_chars),
        max_items=10,
    )
    included_counts["corrections"] = len(inc_corr)
    omitted_counts["corrections"] = omit_corr
    if omit_corr > 0:
        truncated_sections.append("corrections")
    if inc_corr:
        sec_corr = "## 2. Human Investigation Corrections (Must Respect)\n" + "\n".join(inc_corr)
        sections.append(sec_corr)
        used_chars += len(sec_corr) + 2

    # Section 3: Qualifying Findings
    finding_pool = list(focus.active_findings)
    if cone is not None:
        seen_fids = {f.id for f in finding_pool}
        for cf in cone.cone_findings:
            if cf.id not in seen_fids:
                seen_fids.add(cf.id)
                finding_pool.append(cf)
    finding_items = (
        [
            f"- {f.title} (`{f.source_file}:{f.line}`): {f.detail} What to check before changing/deleting: {f.remediation}"
            for f in finding_pool
        ]
        if eff_plain
        else [
            f"- `{f.id}` **{f.rule_code}** [{f.severity} | {f.confidence} | {f.evidence_strength}] "
            f"`{f.source_file}:{f.line}` (node=`{f.node_id}`) — {f.title} | Detail: {f.detail} | "
            f"Suggested remediation (unverified): {f.remediation}"
            for f in finding_pool
        ]
    )
    inc_f, omit_f = _fit_complete_items(
        finding_items,
        remaining_chars=max(500, (max_prompt_chars - used_chars) // 2),
        max_items=8,
    )
    included_counts["findings"] = len(inc_f)
    omitted_counts["findings"] = omit_f
    if omit_f > 0:
        truncated_sections.append("findings")
    if inc_f:
        sec_f = "## 3. Qualifying Findings & Causal Evidence\n" + "\n".join(inc_f)
        sections.append(sec_f)
        used_chars += len(sec_f) + 2

    # Section 4: Lineage Cone Nodes & Policy-Annotated Edges
    cone_node_items: list[str] = []
    cone_edge_items: list[str] = []
    if cone is not None:
        for ptr in (*cone.downstream_truth_nodes, *cone.manipulator_nodes, *cone.upstream_display_nodes):
            cone_node_items.append(
                f"- [{ptr.tier}/{ptr.subkind}] `{ptr.id}` (`{ptr.pointer}`, label=`{ptr.label}`, status=`{ptr.status}`)"
            )
        for ce in cone.cone_edge_items:
            pfc_tag = ""
            if ce.policy_field_consumption is not None:
                pfc = ce.policy_field_consumption
                pfc_tag = (
                    f" | policy_state=`{pfc.state}` (`{pfc.mechanism}`), "
                    f"consumed={pfc.consumed_columns}, unconsumed={pfc.unconsumed_policy_columns}, "
                    f"substituted={pfc.substituted_constants}, fallbacks={pfc.fallback_constants}"
                )
            cone_edge_items.append(
                f"- `{ce.id}`: `{ce.source_id} --[{ce.kind} | {ce.verification}]--> {ce.target_id}`"
                + (f" @ `{ce.evidence_path}`" if ce.evidence_path else "")
                + (f" — {ce.evidence_note}" if ce.evidence_note else "")
                + pfc_tag
            )
    else:
        cone_edge_items = [f"- `{e_str}`" for e_str in focus.cone_edges]

    inc_cn, omit_cn = _fit_complete_items(
        cone_node_items,
        remaining_chars=max(400, (max_prompt_chars - used_chars) // 2),
        max_items=14,
    )
    included_counts["cone_nodes"] = len(inc_cn)
    omitted_counts["cone_nodes"] = omit_cn
    if omit_cn > 0:
        truncated_sections.append("cone_nodes")
    if inc_cn:
        sec_cn = "## 4. 3-Tier Lineage Neighborhood Nodes\n" + "\n".join(inc_cn)
        sections.append(sec_cn)
        used_chars += len(sec_cn) + 2

    inc_ce, omit_ce = _fit_complete_items(
        cone_edge_items,
        remaining_chars=max(400, max_prompt_chars - used_chars - 500),
        max_items=14,
    )
    included_counts["cone_edges"] = len(inc_ce)
    omitted_counts["cone_edges"] = omit_ce
    if omit_ce > 0:
        truncated_sections.append("cone_edges")
    if inc_ce:
        sec_ce = "## 5. Connected Lineage & Policy Consumption Edges\n" + "\n".join(inc_ce)
        sections.append(sec_ce)
        used_chars += len(sec_ce) + 2

    # Section 5: Live Viewport Frustum Lines
    vp_raw = (live_viewport_brief or "").strip()
    vp_lines = [ln.strip() for ln in vp_raw.splitlines() if ln.strip()] if vp_raw else []
    inc_vp, omit_vp = _fit_complete_items(
        vp_lines,
        remaining_chars=max(200, max_prompt_chars - used_chars - 240),
        max_items=12,
    )
    included_counts["viewport_lines"] = len(inc_vp)
    omitted_counts["viewport_lines"] = omit_vp
    if omit_vp > 0:
        truncated_sections.append("viewport_lines")
    if inc_vp:
        sec_vp = "## 6. Live Viewport Summary\n" + "\n".join(inc_vp)
        sections.append(sec_vp)
        used_chars += len(sec_vp) + 2

    # History count tracking
    hist_list = list(history)
    inc_hist = hist_list[-8:]
    included_counts["history_turns"] = len(inc_hist)
    omitted_counts["history_turns"] = max(0, len(hist_list) - len(inc_hist))
    if omitted_counts["history_turns"] > 0:
        truncated_sections.append("history_turns")

    q_clean = question.strip()
    plain_cue = (
        "\n(Answer directly to 'you' in 2–4 plain everyday sentences without rigid section headers; "
        "explain what this does, why it is highlighted, and what happens in practice if changed or deleted. "
        "Never write 'The user is...'.)"
        if eff_plain
        else ""
    )
    local_prompt = "\n\n".join([*sections, f"## User Question\n{q_clean}{plain_cue}"])

    apple_sections = sections[:3]
    if inc_ce:
        apple_sections.append("## Connected Edges\n" + "\n".join(inc_ce[:6]))
    if inc_hist:
        hist_tail = "\n".join(
            f"{'User' if t.role == 'user' else 'Assistant'}: {t.content.splitlines()[0][:320]}"
            for t in inc_hist[-4:]
        )
        apple_sections.append(f"## Recent Session Turns\n{hist_tail}")
    apple_prompt = "\n\n".join([*apple_sections, f"## Question\n{q_clean}{plain_cue}"])

    seed_q = (
        focus.focused_node.id
        if focus.focused_node is not None
        else (focus.selected_finding_id or focus.active_slug)
    )
    expand_hint = (
        f"Truncated sections: {', '.join(truncated_sections)}. "
        f"Expand with `wythe_lineage_cone(target='{focus.active_slug}', query='{seed_q}', full=True)` "
        f"or `wythe_findings(target='{focus.active_slug}')`."
        if truncated_sections
        else "Complete: 0 items omitted across all context sections."
    )
    budget = ContextBudgetSummary(
        included_counts=included_counts,
        omitted_counts=omitted_counts,
        truncated_sections=truncated_sections,
        prompt_chars=len(local_prompt),
        max_prompt_chars=max_prompt_chars,
        expand_hint=expand_hint,
    )
    return local_prompt, apple_prompt, budget
