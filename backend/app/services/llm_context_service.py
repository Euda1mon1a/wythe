"""Token-budgeted `llms.txt` pointer maps and surgical 3-tier Lineage Cone slicers for LLMs."""

from __future__ import annotations

from collections import Counter, deque

from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    BoundaryFinding,
    ConeCompleteness,
    ConeEdgeSummary,
    ConeSectionCount,
    LlmBriefRead,
    LlmContextConeReport,
    LlmNodePointer,
    TruthAtlasReport,
)

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


def _bfs_ordered_list(seeds: list[str], adj: dict[str, list[str]], valid_ids: set[str]) -> list[str]:
    visited: set[str] = set(seeds)
    ordered: list[str] = []
    q: deque[str] = deque(seeds)
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, ()):
            if nxt in valid_ids and nxt not in visited:
                visited.add(nxt)
                ordered.append(nxt)
                q.append(nxt)
    return ordered


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
        (n for n in report.nodes if n.tier == "truth" and n.subkind == "table"),
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
        (n for n in report.nodes if n.tier == "manipulate" and n.subkind == "route"),
        key=lambda n: (-(in_deg[n.id] + out_deg[n.id]), n.label),
    )
    services = sorted(
        (n for n in report.nodes if n.tier == "manipulate" and n.subkind != "route"),
        key=lambda n: (-(in_deg[n.id] + out_deg[n.id]), n.label),
    )
    displays = sorted(
        (n for n in report.nodes if n.tier == "display"),
        key=lambda n: (0 if n.subkind == "page" else 1, -(in_deg[n.id] + out_deg[n.id]), n.label),
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
        lines.append(
            f"- `{t.label}` (`{_ptr(t)}`) — status={t.status}, readers={t.read_by_count}, writers={t.written_by_count}{cols}"
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
        paths = ", ".join(r.http_paths[:3]) if r.http_paths else "router"
        lines.append(f"- [route] `{r.label}` (`{_ptr(r)}`) — {paths}")
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


def build_lineage_cone_slice(
    report: TruthAtlasReport,
    query: str,
    *,
    max_nodes: int = DEFAULT_CONE_NODES,
    full: bool = False,
) -> LlmContextConeReport:
    """Slice the directional upstream/downstream 3-tier Lineage Cone around `query`."""
    full_hint = f'wythe context {report.target_slug} "{query}" --full'
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
    fwd_raw: dict[str, list[tuple[tuple[int, str, str, str], str]]] = {}
    rev_raw: dict[str, list[tuple[tuple[int, str, str, str], str]]] = {}
    for e in report.edges:
        fwd_raw.setdefault(e.source_id, []).append((_edge_sort_key(e, e.target_id), e.target_id))
        rev_raw.setdefault(e.target_id, []).append((_edge_sort_key(e, e.source_id), e.source_id))
    fwd_adj = {
        k: list(dict.fromkeys(nid for _, nid in sorted(v, key=lambda item: item[0])))
        for k, v in fwd_raw.items()
    }
    rev_adj = {
        k: list(dict.fromkeys(nid for _, nid in sorted(v, key=lambda item: item[0])))
        for k, v in rev_raw.items()
    }

    seed_ids = [n.id for n in seeds]
    seed_set = set(seed_ids)
    down_order = _bfs_ordered_list(seed_ids, fwd_adj, valid_ids)
    up_order = _bfs_ordered_list(seed_ids, rev_adj, valid_ids)
    full_cone_ids = seed_set | set(down_order) | set(up_order)
    budget = None if full else max(max_nodes, len(seed_ids))
    cone_ids = _interleave_cone_nodes(seed_ids, down_order, up_order, budget=budget)

    cone_nodes = [nodes_by_id[nid] for nid in sorted(cone_ids)]
    disp_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "display"]
    manip_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "manipulate"]
    truth_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "truth"]

    eligible_edges = [
        e for e in report.edges if e.source_id in full_cone_ids and e.target_id in full_cone_ids
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
        or bool(seed_labels.intersection(ch.truth_table_labels))
        or bool(seed_set.intersection(ch.manipulator_node_ids))
        or bool(seed_set.intersection(ch.truth_table_ids))
        or bool(seed_set.intersection(ch.via_node_ids))
    ]
    selected_chains = eligible_chains if full else eligible_chains[:15]

    eligible_findings = [
        f for f in report.findings if f.node_id in full_cone_ids or f.target_node_id in full_cone_ids
    ]
    eligible_seed_findings = [
        f for f in eligible_findings if f.node_id in seed_set or f.target_node_id in seed_set
    ]
    seed_finding_ids = {f.id for f in eligible_seed_findings}
    in_cone_non_seed_findings = [
        f
        for f in eligible_findings
        if f.id not in seed_finding_ids and (f.node_id in cone_ids or f.target_node_id in cone_ids)
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
        md.append(f"## Tier 2 — Backend Manipulation ({len(manip_ptrs)})")
        for p in manip_ptrs:
            hp = f" routes={p.http_paths}" if p.http_paths else ""
            md.append(f"- [{p.subkind}] `{p.label}` (`{p.pointer}`) status={p.status}{hp}")
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
            writer_tag = (
                f" [writer=`{cf.node_id}` -> target=`{cf.target_node_id}`]"
                if cf.target_node_id and cf.target_node_id != cf.node_id
                else ""
            )
            md.append(
                f"- **{cf.rule_code}** [{cf.severity} | {cf.confidence} | {cf.evidence_strength}] "
                f"`{cf.source_file}:{cf.line}`{writer_tag} — "
                f"{cf.title} | Suggested remediation (unverified): {cf.remediation}"
            )

    md_text = "\n".join(md).strip()
    return LlmContextConeReport(
        target_slug=report.target_slug,
        query=query,
        source_commit=report.source_commit,
        worktree_dirty=report.worktree_dirty,
        dirty_path_count=report.dirty_path_count,
        content_digest=report.content_digest,
        matched_seed_ids=seed_ids,
        upstream_display_nodes=disp_ptrs,
        manipulator_nodes=manip_ptrs,
        downstream_truth_nodes=truth_ptrs,
        cone_edges=cone_edges,
        cone_edge_items=cone_edge_items,
        matching_chains=selected_chains,
        cone_findings=selected_findings,
        completeness=completeness,
        approx_tokens=max(1, len(md_text) // 4),
        markdown=md_text,
    )
