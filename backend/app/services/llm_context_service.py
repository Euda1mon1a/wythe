"""Token-budgeted `llms.txt` pointer maps and surgical 3-tier Lineage Cone slicers for LLMs."""

from __future__ import annotations

from collections import Counter, deque

from app.schemas.atlas import (
    AtlasNode,
    LlmBriefRead,
    LlmContextConeReport,
    LlmNodePointer,
    TruthAtlasReport,
)

DEFAULT_BRIEF_TOKENS = 2200
DEFAULT_CONE_NODES = 40


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
        lines.extend(["", "## Verified End-to-End 3-Tier Chains (Sample)"])
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
            lines.append(
                f"- `{ch.display_label}` (`{d_ptr}`) -> `{ch.http_method} {ch.http_path}` (`{r_ptr}`) -> [{tbls}]"
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
) -> LlmContextConeReport:
    """Slice the directional upstream/downstream 3-tier Lineage Cone around `query`."""
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
            suggestions=suggestions,
            approx_tokens=max(1, len(hint) // 4),
            markdown=f"# Lineage Cone :: `{query}` ({report.target_slug})\n\n{hint}",
        )

    nodes_by_id = {n.id: n for n in report.nodes}
    fwd: dict[str, list[tuple[str, str]]] = {}
    rev: dict[str, list[tuple[str, str]]] = {}
    for e in report.edges:
        fwd.setdefault(e.source_id, []).append((e.target_id, e.kind))
        rev.setdefault(e.target_id, []).append((e.source_id, e.kind))

    seed_ids = [n.id for n in seeds]
    cone_ids: set[str] = set(seed_ids)

    # Walk downstream (toward Tier 1 SQL tables & Redis queues)
    dq_down: deque[str] = deque(seed_ids)
    while dq_down and len(cone_ids) < max_nodes:
        cur = dq_down.popleft()
        for nxt, _ in fwd.get(cur, ()):
            if nxt not in cone_ids and nxt in nodes_by_id:
                cone_ids.add(nxt)
                dq_down.append(nxt)
                if len(cone_ids) >= max_nodes:
                    break

    # Walk upstream (toward Tier 2 routes & Tier 3 display pages/hooks)
    dq_up: deque[str] = deque(seed_ids)
    while dq_up and len(cone_ids) < max_nodes:
        cur = dq_up.popleft()
        for prv, _ in rev.get(cur, ()):
            if prv not in cone_ids and prv in nodes_by_id:
                cone_ids.add(prv)
                dq_up.append(prv)
                if len(cone_ids) >= max_nodes:
                    break

    cone_nodes = [nodes_by_id[nid] for nid in sorted(cone_ids)]
    disp_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "display"]
    manip_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "manipulate"]
    truth_ptrs = [_to_llm_pointer(n) for n in cone_nodes if n.tier == "truth"]

    cone_edges = [
        f"{e.source_id} --[{e.kind}]--> {e.target_id}"
        for e in report.edges
        if e.source_id in cone_ids and e.target_id in cone_ids
    ][:80]

    seed_set = set(seed_ids)
    seed_labels = {n.label for n in seeds}
    seed_paths = {p for n in seeds for p in n.http_paths}
    matching_chains = [
        ch
        for ch in report.chains
        if ch.display_node_id in seed_set
        or ch.route_node_id in seed_set
        or ch.http_path in seed_paths
        or bool(seed_labels.intersection(ch.truth_table_labels))
        or bool(seed_set.intersection(ch.manipulator_node_ids))
        or bool(seed_set.intersection(ch.truth_table_ids))
        or bool(seed_set.intersection(ch.via_node_ids))
    ][:15]

    cone_findings = [
        f
        for f in report.findings
        if f.node_id in cone_ids or f.target_node_id in cone_ids
    ][:25]

    md: list[str] = [
        f"# 3-Tier Lineage Cone :: `{query}` ({report.target_slug} @ `{report.source_commit[:10]}`)",
        f"> Matched seeds ({len(seeds)}): {', '.join(f'`{s.id}` (`{_ptr(s)}`)' for s in seeds)}",
        (
            "> Guardrail: Distinguish declared store purpose from verified lifetime/invalidation, "
            "discovery location from causal write `file:line`, and suggested changes from verified fixes."
        ),
        "",
    ]
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
    if matching_chains:
        md.append(f"## Verified End-to-End Chains ({len(matching_chains)})")
        for ch in matching_chains:
            d_node = nodes_by_id.get(ch.display_node_id)
            r_node = nodes_by_id.get(ch.route_node_id)
            d_ptr = _ptr(d_node) if d_node else ch.display_node_id
            r_ptr = _ptr(r_node) if r_node else ch.route_node_id
            md.append(
                f"- `{ch.display_label}` (`{d_ptr}`) -> `{ch.http_method} {ch.http_path}` (`{r_ptr}`) -> [{', '.join(ch.truth_table_labels)}]"
            )
        md.append("")
    if cone_edges:
        md.append(f"## Verified Cone Edges ({len(cone_edges)})")
        for ce in cone_edges[:35]:
            md.append(f"- `{ce}`")
        md.append("")
    if cone_findings:
        md.append(f"## Active Findings in Cone ({len(cone_findings)})")
        for cf in cone_findings:
            writer_tag = (
                f" [writer=`{cf.node_id}` -> target=`{cf.target_node_id}`]"
                if cf.target_node_id and cf.target_node_id != cf.node_id
                else ""
            )
            md.append(
                f"- **{cf.rule_code}** [{cf.severity}] `{cf.source_file}:{cf.line}`{writer_tag} — "
                f"{cf.title} | Suggested remediation: {cf.remediation}"
            )

    md_text = "\n".join(md).strip()
    return LlmContextConeReport(
        target_slug=report.target_slug,
        query=query,
        source_commit=report.source_commit,
        matched_seed_ids=seed_ids,
        upstream_display_nodes=disp_ptrs,
        manipulator_nodes=manip_ptrs,
        downstream_truth_nodes=truth_ptrs,
        cone_edges=cone_edges,
        matching_chains=matching_chains,
        cone_findings=cone_findings,
        approx_tokens=max(1, len(md_text) // 4),
        markdown=md_text,
    )
