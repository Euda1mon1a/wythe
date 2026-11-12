"""3-Tier Truth Atlas scanner and cross-tier lineage synthesizer."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters import build_default_registry
from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.legacy_snapshot_bridge import apply_legacy_snapshot_bridge
from app.adapters.redis_ephemeral import augment_redis_ephemeral_lineage
from app.core.clock import utc_now, valid_until_from
from app.core.policy_context import policy_tokens_scope
from app.models import PolicyVocabulary, ScanSnapshot, StackProfile, TargetProject
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AtlasSummaryStats,
    EndToEndChain,
    TruthAtlasReport,
)
from app.services.gate_service import evaluate_findings_and_gate
from app.services.governance_service import list_rulings
from app.services.route_probe_service import apply_live_route_probe

_API_VERSION_PREFIX_RE = re.compile(r"^/api/v\d+(?=/|$)")
_ROUTE_PARAM_SEG_RE = re.compile(r"^(?:\{[^/]*\}|:[\w$]+\??|<[^>]+>|\*.*)$")
_CALL_PARAM_SPLIT_RE = re.compile(r"(\{param\})")


def _strip_api_version_prefix(path: str) -> str:
    return _API_VERSION_PREFIX_RE.sub("", path.rstrip("/")) or "/"


def _call_segment_matches(call_seg: str, route_seg: str) -> bool:
    """Only the call's runtime `{param}` parts are wildcards; its literal words must match literally.

    A literal call segment such as `balance` matching a route parameter `{absence_id}` is
    exactly the comparison that already failed, so it must not make the call "unresolved".
    """
    route_is_param = bool(_ROUTE_PARAM_SEG_RE.match(route_seg))
    if "{param}" in call_seg:
        if call_seg == "{param}":
            return True
        if route_is_param:
            return False
        pattern = "".join(
            "[^/]*" if part == "{param}" else re.escape(part)
            for part in _CALL_PARAM_SPLIT_RE.split(call_seg)
        )
        return re.fullmatch(pattern, route_seg) is not None
    return not route_is_param and call_seg == route_seg


def _wildcard_route_candidates(
    call: FrontendHttpCall, routes: list[RouteDescriptor]
) -> list[RouteDescriptor]:
    """Routes a runtime-built call path could resolve to, treating each `{param}` as a wildcard."""
    if "{param}" not in call.normalized_path:
        return []
    call_segs = _strip_api_version_prefix(call.normalized_path).strip("/").split("/")
    found: list[RouteDescriptor] = []
    for route in routes:
        if route.http_method != call.http_method:
            continue
        route_segs = _strip_api_version_prefix(route.full_path).strip("/").split("/")
        if len(route_segs) == len(call_segs) and all(
            _call_segment_matches(c, r) for c, r in zip(call_segs, route_segs)
        ):
            found.append(route)
    return found


def _git_dirty_path_count(repo_root: Path) -> int | None:
    """Count uncommitted paths (modified, deleted, untracked; renames once), or None outside git."""
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    count = 0
    skip_next = False
    for token in res.stdout.split(b"\x00"):
        if skip_next:
            skip_next = False
            continue
        if not token:
            continue
        count += 1
        if b"R" in token[:2] or b"C" in token[:2]:
            skip_next = True  # rename/copy entries carry the original path as the next token
    return count


def _resolve_git_commit(repo_root: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        return res.stdout.strip() or "uncommitted"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


@dataclass(frozen=True)
class _CachedStaticExtraction:
    commit_sha: str
    obs_source: str
    nodes: list[AtlasNode]
    edges: list[AtlasEdge]
    chains: list[EndToEndChain]
    raw_findings: list[RawCandidateFinding]
    notes: list[str]


_EXTRACTION_CACHE: OrderedDict[tuple[object, ...], _CachedStaticExtraction] = OrderedDict()
_EXTRACTION_CACHE_MAX = 8


def _compute_git_worktree_fingerprint(repo_root: Path) -> tuple[str, str] | None:
    """Return `(head_sha, sha256_worktree_digest)` for git repos, or `None` outside git."""
    try:
        head_res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        status_res = subprocess.run(
            ["git", "status", "-z", "-uall"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    head_sha = head_res.stdout.strip() or "uncommitted"
    h = hashlib.sha256()
    h.update(head_sha.encode("utf-8"))
    h.update(b"\x00")
    h.update(status_res.stdout)
    for token in status_res.stdout.split(b"\x00"):
        if not token:
            continue
        rel_bytes = token[3:] if len(token) > 3 and token[2:3] == b" " else token
        try:
            rel_str = rel_bytes.decode("utf-8", errors="surrogateescape")
            st = os.lstat(repo_root / rel_str)
            h.update(f"|{rel_str}:{st.st_mtime_ns}:{st.st_size}".encode("utf-8", errors="replace"))
        except OSError:
            continue
    return head_sha, h.hexdigest()


def _classify_unbacked_call(
    call: FrontendHttpCall,
    routes: list[RouteDescriptor],
    local_route_res: list[re.Pattern[str]],
) -> list[RawCandidateFinding]:
    """Decide what a frontend call with no matching backend route means.

    - served by the frontend itself (Next.js `route.ts`): not a backend call, no finding;
    - built at runtime and could match real routes: DISP-006 (unresolved, warning);
    - no entry point reaches the calling symbol: DISP-007 (dead code, warning);
    - otherwise: DISP-004 (blocking), with the page path that reaches it when known.
    """
    method_path = f"{call.http_method} {call.normalized_path}"
    if any(rx.match(call.normalized_path) for rx in local_route_res):
        return []

    candidates = _wildcard_route_candidates(call, routes)
    if candidates:
        shown = ", ".join(f"`{c.http_method} {c.full_path}`" for c in candidates[:3])
        more = f" (+{len(candidates) - 3} more)" if len(candidates) > 3 else ""
        return [
            RawCandidateFinding(
                rule_code="DISP-006",
                node_id=call.caller_node_id,
                source_file=call.source_file,
                line=call.line,
                title=f"Frontend `{method_path}` is built at runtime; it may match {len(candidates)} backend route(s)",
                detail=(
                    f"{call.source_file}:{call.line} calls `{call.raw_path}`. With its runtime segment(s) "
                    f"treated as wildcards it could resolve to {shown}{more}. Static analysis cannot tell "
                    "which value is used at runtime."
                ),
                remediation="Confirm the runtime values map to these routes, or build the path from literal segments.",
                http_method=call.http_method,
                http_path=call.normalized_path,
            )
        ]

    where = f"`{call.caller_symbol}`" if call.caller_symbol else "this module"
    if call.reachable is False:
        return [
            RawCandidateFinding(
                rule_code="DISP-007",
                node_id=call.caller_node_id,
                source_file=call.source_file,
                line=call.line,
                title=f"Frontend `{method_path}` has no matching backend route (unreachable code)",
                detail=(
                    f"{call.source_file}:{call.line} calls `{call.raw_path}`, which matched zero backend routes. "
                    f"No page, layout, or code they reach imports {where}, so users cannot trigger it today."
                ),
                remediation="Remove the dead call, or repoint it to a real route before a page starts using it.",
                http_method=call.http_method,
                http_path=call.normalized_path,
            )
        ]

    reached = (
        f" Reached from: {' -> '.join(call.reach_trail)}." if call.reach_trail else ""
    )
    return [
        RawCandidateFinding(
            rule_code="DISP-004",
            node_id=call.caller_node_id,
            source_file=call.source_file,
            line=call.line,
            title=f"Frontend `{method_path}` has no matching backend route",
            detail=f"{call.source_file}:{call.line} calls `{call.raw_path}`, which matched zero registered backend routes.{reached}",
            remediation="Align the frontend API path/method with an active backend route handler.",
            http_method=call.http_method,
            http_path=call.normalized_path,
        )
    ]


def _solve_cross_tier_lineage(
    truth: TruthExtractionResult,
    manip: ManipulatorExtractionResult,
    disp: DisplayExtractionResult,
) -> tuple[list[AtlasEdge], list[EndToEndChain], list[RawCandidateFinding]]:
    """Bridge Display HTTP calls -> Manipulate routes -> Services -> Postgres Truth."""
    cross_edges: list[AtlasEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    extra_findings: list[RawCandidateFinding] = []

    all_nodes: dict[str, AtlasNode] = {
        n.id: n for n in (*truth.nodes, *manip.nodes, *disp.nodes)
    }

    compiled_routes: list[tuple[RouteDescriptor, re.Pattern[str]]] = [
        (r, re.compile(r.path_regex)) for r in manip.routes
    ]

    # Build adjacency inside manipulate tier to find downstream services & tables per route
    manip_adj: dict[str, set[str]] = {}
    manip_reads: dict[str, set[str]] = {}
    manip_writes: dict[str, set[str]] = {}
    for e in manip.edges:
        if e.kind == "calls_helper":
            manip_adj.setdefault(e.source_id, set()).add(e.target_id)
        elif e.kind in ("reads_truth", "guards_truth"):
            manip_reads.setdefault(e.source_id, set()).add(e.target_id)
        elif e.kind == "writes_truth":
            manip_writes.setdefault(e.source_id, set()).add(e.target_id)

    def downstream_from_route(route_nid: str) -> tuple[list[str], list[str], list[str]]:
        visited: list[str] = []
        r_tables: set[str] = set()
        w_tables: set[str] = set()
        q: deque[str] = deque([route_nid])
        seen = {route_nid}
        while q:
            cur = q.popleft()
            if cur != route_nid:
                visited.append(cur)
            r_tables |= manip_reads.get(cur, set())
            w_tables |= manip_writes.get(cur, set())
            for nxt in sorted(manip_adj.get(cur, set())):
                if nxt not in seen and len(seen) < 25:
                    seen.add(nxt)
                    q.append(nxt)
        return visited, sorted(r_tables), sorted(w_tables)

    # Reverse adjacency in display tier: which pages/components consume a hook or api_client?
    disp_rev: dict[str, set[str]] = {}
    for e in disp.edges:
        disp_rev.setdefault(e.target_id, set()).add(e.source_id)

    def upstream_pages(caller_nid: str) -> list[tuple[str, list[str]]]:
        caller_node = all_nodes.get(caller_nid)
        if caller_node and caller_node.subkind == "page":
            return [(caller_nid, [])]
        found_pages: list[tuple[str, list[str]]] = []
        q: deque[tuple[str, list[str]]] = deque([(caller_nid, [caller_nid])])
        seen = {caller_nid}
        while q:
            cur, trail = q.popleft()
            for parent in sorted(disp_rev.get(cur, set())):
                if parent in seen:
                    continue
                seen.add(parent)
                pnode = all_nodes.get(parent)
                if pnode and pnode.subkind == "page":
                    found_pages.append((parent, list(reversed(trail))))
                elif len(trail) < 4:
                    q.append((parent, [*trail, parent]))
        return found_pages or [(caller_nid, [])]

    chains: list[EndToEndChain] = []
    seen_chains: set[tuple[str, str, str, str]] = set()
    local_route_res = [re.compile(p) for p in disp.local_route_patterns]

    for call in disp.http_calls:
        matched_routes = [
            r
            for r, pat in compiled_routes
            if r.http_method == call.http_method and pat.match(call.normalized_path)
        ]
        if not matched_routes:
            extra_findings.extend(_classify_unbacked_call(call, manip.routes, local_route_res))
            continue

        kind = "queries_endpoint" if call.http_method == "GET" else "mutates_endpoint"
        op = "read" if call.http_method == "GET" else "write"
        for rdesc in matched_routes:
            ekey = (call.caller_node_id, rdesc.node_id, kind)
            if ekey not in seen_edges:
                seen_edges.add(ekey)
                cross_edges.append(
                    AtlasEdge(
                        id=f"e:{call.caller_node_id}->{rdesc.node_id}:{kind}",
                        source_id=call.caller_node_id,
                        target_id=rdesc.node_id,
                        kind=kind,  # type: ignore[arg-type]
                        verification="verified",
                        evidence_path=call.source_file,
                        evidence_note=f"`{call.http_method} {call.normalized_path}` -> `{rdesc.full_path}`",
                    )
                )

            svcs, r_tbls, w_tbls = downstream_from_route(rdesc.node_id)
            tbls = sorted(set(r_tbls) | set(w_tbls)) if op == "write" else r_tbls or sorted(set(r_tbls) | set(w_tbls))
            route_node = all_nodes.get(rdesc.node_id)
            for root_disp_id, via_ids in upstream_pages(call.caller_node_id):
                ckey = (root_disp_id, call.http_method, rdesc.full_path, rdesc.node_id)
                if ckey in seen_chains or len(chains) >= 300:
                    continue
                seen_chains.add(ckey)
                dnode = all_nodes.get(root_disp_id)
                chains.append(
                    EndToEndChain(
                        id=f"chain:{len(chains) + 1}",
                        display_node_id=root_disp_id,
                        display_label=dnode.label if dnode else root_disp_id,
                        via_node_ids=via_ids,
                        http_method=call.http_method,
                        http_path=rdesc.full_path,
                        route_node_id=rdesc.node_id,
                        route_label=route_node.label if route_node else rdesc.node_id,
                        manipulator_node_ids=svcs,
                        truth_table_ids=tbls,
                        truth_table_labels=[
                            all_nodes[t].label if t in all_nodes else t for t in tbls
                        ],
                        operation=op,  # type: ignore[arg-type]
                        verified=bool(tbls or svcs),
                    )
                )

    return cross_edges, chains, extra_findings


def run_target_scan(
    session: Session,
    target: TargetProject,
    *,
    pg_dsn: str | None = None,
    redis_dsn: str | None = None,
    strict_gate: bool = False,
    persist_snapshot: bool = True,
    probe_url: str | None = None,
    probe_allow_remote: bool = False,
) -> TruthAtlasReport:
    """Execute a 3-tier Truth Atlas scan for a registered TargetProject.

    `probe_url` opts into one unauthenticated GET per unbacked frontend call against a
    running backend (see `route_probe_service`) to confirm or clear DISP-004/007 findings.
    """
    profile_slug = (
        "fastapi-sqlalchemy-nextjs"
        if target.stack_profile_slug.endswith("-native")
        else target.stack_profile_slug
    )
    profile = session.scalar(
        select(StackProfile).where(StackProfile.slug == profile_slug)
    )
    if profile is None:
        raise ValueError(f"Missing StackProfile '{target.stack_profile_slug}'")

    enabled_tokens = tuple(
        session.scalars(
            select(PolicyVocabulary.token)
            .where(PolicyVocabulary.is_enabled.is_(True))
            .order_by(PolicyVocabulary.id)
        ).all()
    )

    registry = build_default_registry()
    t_adapter = registry.get_truth(profile.truth_adapter)
    m_adapter = registry.get_manipulator(profile.manipulator_adapter)
    d_adapter = registry.get_display(profile.display_adapter)

    repo_root = Path(target.repo_path).resolve()
    git_fp = (
        _compute_git_worktree_fingerprint(repo_root)
        if pg_dsn is None and redis_dsn is None
        else None
    )
    cache_key = (
        (
            str(repo_root),
            target.backend_subdir,
            target.frontend_subdir,
            profile.truth_adapter,
            profile.manipulator_adapter,
            profile.display_adapter,
            enabled_tokens,
            git_fp[1],
        )
        if git_fp is not None
        else None
    )

    cached = _EXTRACTION_CACHE.get(cache_key) if cache_key is not None else None
    if cached is not None and cache_key is not None:
        _EXTRACTION_CACHE.move_to_end(cache_key)
        commit_sha = cached.commit_sha
        obs_source = cached.obs_source
        all_nodes = [n.model_copy(deep=True) for n in cached.nodes]
        all_edges = list(cached.edges)
        chains = list(cached.chains)
        raw_findings = list(cached.raw_findings)
        scan_notes = list(cached.notes)
    else:
        with policy_tokens_scope(enabled_tokens):
            truth_res = t_adapter.extract(repo_root, target.backend_subdir, pg_dsn=pg_dsn)
            manip_res = m_adapter.extract(repo_root, target.backend_subdir, truth_res)
            disp_res = d_adapter.extract(repo_root, target.frontend_subdir)

        obs_source = augment_redis_ephemeral_lineage(
            repo_root,
            target.backend_subdir,
            truth_res,
            manip_res,
            redis_dsn=redis_dsn,
        )

        cross_edges, chains, cross_findings = _solve_cross_tier_lineage(
            truth_res, manip_res, disp_res
        )
        all_nodes = sorted(
            [*truth_res.nodes, *manip_res.nodes, *disp_res.nodes],
            key=lambda n: (n.tier, n.subkind, n.id),
        )
        all_edges = sorted(
            [*manip_res.edges, *disp_res.edges, *cross_edges],
            key=lambda e: e.id,
        )
        raw_findings = [
            *truth_res.findings,
            *manip_res.findings,
            *disp_res.findings,
            *cross_findings,
        ]
        scan_notes = list(truth_res.notes)
        commit_sha = git_fp[0] if git_fp is not None else _resolve_git_commit(repo_root)
        if cache_key is not None:
            _EXTRACTION_CACHE[cache_key] = _CachedStaticExtraction(
                commit_sha=commit_sha,
                obs_source=obs_source,
                nodes=[n.model_copy(deep=True) for n in all_nodes],
                edges=list(all_edges),
                chains=list(chains),
                raw_findings=list(raw_findings),
                notes=list(scan_notes),
            )
            while len(_EXTRACTION_CACHE) > _EXTRACTION_CACHE_MAX:
                _EXTRACTION_CACHE.popitem(last=False)

    if probe_url:
        raw_findings, probe_note = apply_live_route_probe(
            raw_findings, probe_url, allow_remote=probe_allow_remote
        )
        obs_source = f"{obs_source}+http_probe"
        scan_notes.append(probe_note)

    dirty_count = _git_dirty_path_count(repo_root)

    legacy_summary = apply_legacy_snapshot_bridge(
        repo_root, target.legacy_snapshot_relpath, all_nodes
    )

    rulings = list_rulings(session, target.id) if target.id else []
    latest_ruling_by_node = {}
    for r in rulings:
        if r.node_id not in latest_ruling_by_node:
            latest_ruling_by_node[r.node_id] = r
    for node in all_nodes:
        ruling = latest_ruling_by_node.get(node.id)
        if ruling is not None:
            node.ruling_summary = f"[{ruling.disposition}] {ruling.summary}"
            node.ruling_audited_at = ruling.audited_at
            if ruling.cutover_history:
                node.cutover_history = ruling.cutover_history
            if ruling.disposition == "accepted_clean":
                node.status = "clean"

    findings, gate = evaluate_findings_and_gate(
        session, raw_findings, target_id=target.id or None, strict=strict_gate
    )

    observed = utc_now()
    digest_src = json.dumps(
        {
            "commit": commit_sha,
            "nodes": [n.id for n in all_nodes],
            "edges": [e.id for e in all_edges],
            "findings": sorted(f.id for f in findings),
        },
        sort_keys=True,
    )
    digest = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()

    stats = AtlasSummaryStats(
        truth_tables=sum(1 for n in all_nodes if n.tier == "truth" and n.subkind == "table"),
        sql_functions=sum(1 for n in all_nodes if n.tier == "truth" and n.subkind == "sql_function"),
        ephemeral_stores=sum(1 for n in all_nodes if n.tier == "truth" and n.subkind == "cache_store"),
        manipulator_routes=sum(1 for n in all_nodes if n.tier == "manipulate" and n.subkind == "route"),
        manipulator_services=sum(1 for n in all_nodes if n.tier == "manipulate" and n.subkind != "route"),
        display_pages=sum(1 for n in all_nodes if n.tier == "display" and n.subkind == "page"),
        display_hooks_and_clients=sum(1 for n in all_nodes if n.tier == "display" and n.subkind != "page"),
        verified_edges=sum(1 for e in all_edges if e.verification == "verified"),
        end_to_end_chains=len(chains),
        clean_nodes=sum(1 for n in all_nodes if n.status == "clean"),
        flagged_nodes=sum(1 for n in all_nodes if n.status != "clean"),
        blocking_findings=sum(1 for f in findings if f.blocks_gate),
        warning_findings=sum(1 for f in findings if not f.blocks_gate),
    )

    profile_maturity = (
        profile.implementation_status
        if profile.implementation_status in ("implemented", "experimental", "planned")
        else "experimental"
    )
    report = TruthAtlasReport(
        target_slug=target.slug,
        target_name=target.name,
        repo_path=str(repo_root),
        stack_profile=target.stack_profile_slug,
        stack_profile_status=profile_maturity,  # type: ignore[arg-type]
        source_commit=commit_sha,
        worktree_dirty=None if dirty_count is None else dirty_count > 0,
        dirty_path_count=dirty_count,
        observed_at=observed,
        valid_until=valid_until_from(observed),
        observation_source=obs_source,
        content_digest=digest,
        scan_notes=scan_notes,
        summary=stats,
        nodes=all_nodes,
        edges=all_edges,
        chains=chains,
        findings=findings,
        gate=gate,
        legacy_bridge=legacy_summary,
        rulings=rulings,
    )

    if persist_snapshot and target.id:
        snap = ScanSnapshot(
            target_id=target.id,
            source_commit=commit_sha,
            observation_source=obs_source,
            observed_at=observed,
            valid_until=report.valid_until,
            content_digest=digest,
            truth_node_count=sum(1 for n in all_nodes if n.tier == "truth"),
            manipulator_node_count=sum(1 for n in all_nodes if n.tier == "manipulate"),
            display_node_count=sum(1 for n in all_nodes if n.tier == "display"),
            verified_edge_count=stats.verified_edges,
            blocking_finding_count=stats.blocking_findings,
            warning_finding_count=stats.warning_findings,
            payload_json=report.model_dump_json(),
        )
        session.add(snap)
        session.commit()
        session.refresh(snap)
        report.snapshot_id = snap.id

    return report
