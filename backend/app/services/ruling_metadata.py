"""Zero-migration AuditRuling metadata packing, purpose verification, and evidence scoping."""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from app.adapters.base import RawCandidateFinding
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AuditRulingRead,
    StorePurposeDeclaration,
)

_v2_envelope_key = "__wythe_ruling_v2__"
_backtick_re = re.compile(r"`([^`]+)`")
_generic_stems = frozenset(
    {"default", "cache", "state", "data", "temp", "tmp", "redis", "queue"}
)
_derived_uses = frozenset(
    {"derived_cache", "read_replica", "materialized_view", "historical_snapshot"}
)


def pack_ruling_cutover_payload(
    cutover_history: str | None,
    store_purpose: StorePurposeDeclaration | None,
    evidence_scope: list[str] | None = None,
) -> str | None:
    """Serialize optional store_purpose & evidence_scope inside AuditRuling.cutover_history."""
    norm_scope = [s.strip() for s in (evidence_scope or []) if s and s.strip()]
    if store_purpose is None and not norm_scope:
        return cutover_history
    payload = {
        _v2_envelope_key: True,
        "cutover_history": cutover_history,
        "store_purpose": store_purpose.model_dump(mode="json") if store_purpose else None,
        "evidence_scope": norm_scope,
    }
    return json.dumps(payload, sort_keys=True)


def unpack_ruling_cutover_payload(
    raw: str | None,
) -> tuple[str | None, StorePurposeDeclaration | None, list[str]]:
    """Decode `(cutover_history, store_purpose, evidence_scope)` from storage text."""
    if not raw or not raw.lstrip().startswith("{"):
        return raw, None, []
    try:
        parsed = json.loads(raw)
    except ValueError:
        return raw, None, []
    if not isinstance(parsed, dict) or not parsed.get(_v2_envelope_key):
        return raw, None, []
    sp_raw = parsed.get("store_purpose")
    sp_obj: StorePurposeDeclaration | None = None
    if isinstance(sp_raw, dict):
        try:
            sp_obj = StorePurposeDeclaration.model_validate(sp_raw)
        except ValidationError:
            sp_obj = None
    scope = [
        str(item).strip()
        for item in (parsed.get("evidence_scope") or [])
        if str(item).strip()
    ]
    hist = parsed.get("cutover_history")
    return (str(hist) if hist is not None else None), sp_obj, scope


def _domain_stem(raw: str) -> str:
    cleaned = raw.lower()
    for pfx in ("t:redis:", "t:sql:", "t:db:", "t:"):
        cleaned = cleaned.removeprefix(pfx)
    cleaned = cleaned.removeprefix("redis:").removesuffix(":*")
    cleaned = re.sub(r"(_copy|_cache|_replica|_view|_snapshot)$", "", cleaned)
    cleaned = re.sub(r"[^a-z0-9_]", "_", cleaned).strip("_")
    if len(cleaned) > 4 and cleaned.endswith("s"):
        cleaned = cleaned[:-1]
    return cleaned


def _finding_matches_scope(
    finding: RawCandidateFinding,
    evidence_scope: list[str],
    keyspace_scope: str | None,
) -> bool:
    tokens = {
        f"{finding.rule_code}@{finding.source_file}:{finding.line}",
        f"{finding.rule_code}:{finding.source_file}:{finding.line}",
        f"{finding.source_file}:{finding.line}",
    }
    quoted = [m.lower() for m in _backtick_re.findall(f"{finding.title} {finding.detail}")]
    for entry in evidence_scope:
        if entry in tokens:
            return True
        if entry.startswith("keyspace:"):
            ks = entry.removeprefix("keyspace:").strip().rstrip("*").lower()
            if ks and ks not in ("default:", "default") and any(q.startswith(ks) for q in quoted):
                return True
    # keyspace_scope without explicit TRUTH-003 scope only covers TTL/lifetime warnings.
    if keyspace_scope and finding.rule_code == "TRUTH-004":
        ks = keyspace_scope.strip().rstrip("*").lower()
        if ks and ks not in ("default:", "default") and any(q.startswith(ks) for q in quoted):
            return True
    return False


def _build_verification_summary(
    node: AtlasNode,
    sp: StorePurposeDeclaration,
    node_findings: list[RawCandidateFinding],
    source_matched: AtlasNode | None,
) -> tuple[str, str]:
    """Return `(verification_summary, node_verification_note)` strictly from observed evidence."""
    use_label = sp.intended_use.replace("_", " ")
    summary_lc = node.summary.lower()
    has_t4 = any(f.rule_code == "TRUTH-004" for f in node_findings)
    has_t3 = any(f.rule_code == "TRUTH-003" for f in node_findings)

    if sp.authoritative_source:
        src_part = (
            f"source declared ({source_matched.id})"
            if source_matched is not None
            else f"source declared ({sp.authoritative_source}; not matched in local scan)"
        )
    elif sp.intended_use in _derived_uses:
        src_part = "authoritative source not declared"
    else:
        src_part = "independent store role declared"

    if sp.intended_use == "persistent_config":
        rec = (
            f"recovery declared ({sp.recovery_expectation})"
            if sp.recovery_expectation
            else "recovery expectation missing"
        )
        note = (
            "direct route mutation active"
            if has_t3
            else ("no TTL required" if sp.recovery_expectation else rec)
        )
        return f"Intentional {use_label}; {rec}; {note}.", note

    if has_t4:
        ev_part = "invalidation/TTL not verified"
    elif "explicit invalidation observed" in summary_lc:
        ev_part = "explicit invalidation observed"
    elif "ttl expiration observed" in summary_lc or "setex" in summary_lc:
        ev_part = "TTL expiration observed"
    elif sp.refresh_policy:
        ev_part = f"refresh policy declared ({sp.refresh_policy}), not statically verified"
    else:
        ev_part = "invalidation not verified"

    if has_t3:
        ev_part = f"{ev_part}; direct route write observed"
    return f"Intentional {use_label}; {src_part}; {ev_part}.", ev_part


def _recompute_node_status(node: AtlasNode, remaining_findings: list[RawCandidateFinding]) -> None:
    if not remaining_findings:
        if node.status in ("duplicated_truth", "gray_zone", "policy_in_code"):
            node.status = "clean"
        return
    codes = {f.rule_code for f in remaining_findings}
    has_conflict = any(
        "conflicting authoritative" in f.title.lower() or "second authority" in f.detail.lower()
        for f in remaining_findings
    )
    if has_conflict:
        node.status = "duplicated_truth"
    elif "MANIP-001" in codes or "DISP-001" in codes:
        node.status = "policy_in_code"
    else:
        node.status = "gray_zone"


def apply_rulings_and_store_purpose_checks(
    all_nodes: list[AtlasNode],
    all_edges: list[AtlasEdge],
    raw_findings: list[RawCandidateFinding],
    rulings: list[AuditRulingRead],
) -> list[RawCandidateFinding]:
    """Hydrate scoped rulings & store purpose declarations without silencing independent checks."""
    nodes_by_id = {n.id: n for n in all_nodes}
    nodes_by_label = {n.label.lower(): n for n in all_nodes}
    written_table_ids = {e.target_id for e in all_edges if e.kind == "writes_truth"}
    sql_writers_by_stem: dict[str, AtlasNode] = {}
    for n in all_nodes:
        if n.subkind == "table" and (n.written_by_count > 0 or n.id in written_table_ids):
            st = _domain_stem(n.id)
            if st and st not in _generic_stems:
                sql_writers_by_stem[st] = n

    rulings_by_node: dict[str, list[AuditRulingRead]] = {}
    for r in rulings:
        rulings_by_node.setdefault(r.node_id, []).append(r)

    waived_indices: set[int] = set()
    updated_findings = list(raw_findings)

    def resolve_source(src: str | None) -> AtlasNode | None:
        if not src:
            return None
        if src in nodes_by_id:
            return nodes_by_id[src]
        return nodes_by_label.get(src.lower())

    for node in all_nodes:
        node_rulings = rulings_by_node.get(node.id, [])
        if not node_rulings:
            if not node.verification_note and node.subkind == "cache_store":
                node.verification_note = "no declared store purpose"
            continue

        latest = node_rulings[0]
        node.ruling_summary = f"[{latest.disposition}] {latest.summary}"
        node.ruling_audited_at = latest.audited_at
        if latest.cutover_history:
            node.cutover_history = latest.cutover_history

        purpose_ruling = next((r for r in node_rulings if r.store_purpose is not None), None)
        sp = (
            purpose_ruling.store_purpose.model_copy(deep=True)
            if (purpose_ruling and purpose_ruling.store_purpose)
            else None
        )
        matched_src = resolve_source(sp.authoritative_source) if sp else None

        rel_indices = [
            idx
            for idx, f in enumerate(updated_findings)
            if f.node_id == node.id or f.target_node_id == node.id
        ]

        # Derived copy declaring its authoritative SQL source is not a "second authority".
        if sp is not None and sp.intended_use in _derived_uses:
            if sp.authoritative_source:
                src_stem = _domain_stem(sp.authoritative_source)
                for idx in rel_indices:
                    f = updated_findings[idx]
                    if f.rule_code == "TRUTH-004" and "second authority" in f.detail.lower():
                        src_ok = (matched_src is not None and matched_src.id in f.detail) or (
                            src_stem and src_stem in f.detail.lower()
                        )
                        if src_ok:
                            updated_findings[idx] = RawCandidateFinding(
                                rule_code=f.rule_code,
                                node_id=f.node_id,
                                target_node_id=f.target_node_id,
                                source_file=f.source_file,
                                line=f.line,
                                title=f.title,
                                detail=(
                                    f"{f.source_file}:{f.line} writes declared derived copy "
                                    f"`{node.label}` (source `{sp.authoritative_source}`) without "
                                    "verified TTL or explicit invalidation."
                                ),
                                remediation=(
                                    "Add TTL or explicit invalidation (`delete`/`unlink`) to keep "
                                    f"derived copy `{node.label}` fresh."
                                ),
                            )
            elif not rel_indices:
                updated_findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-004",
                        node_id=node.id,
                        target_node_id=node.id,
                        source_file=node.source_file,
                        line=node.line,
                        title=f"Derived store `{node.label}` lacks declared authoritative source",
                        detail=(
                            f"`{node.label}` declares `{sp.intended_use}` without identifying its "
                            "`authoritative_source`."
                        ),
                        remediation="Record `authoritative_source` in store purpose declaration.",
                    )
                )
                rel_indices.append(len(updated_findings) - 1)

        if sp is not None and sp.intended_use == "persistent_config":
            is_default_bucket = node.id == "t:redis:default"
            scope_list = purpose_ruling.evidence_scope if purpose_ruling else []
            has_non_default_ks = bool(
                sp.keyspace_scope and sp.keyspace_scope.rstrip("*:").lower() != "default"
            )
            for idx in rel_indices:
                f = updated_findings[idx]
                if f.rule_code != "TRUTH-004":
                    continue
                if is_default_bucket and not (scope_list or has_non_default_ks):
                    continue
                if (scope_list or sp.keyspace_scope) and not _finding_matches_scope(
                    f, scope_list, sp.keyspace_scope
                ):
                    continue
                if sp.recovery_expectation and sp.recovery_expectation.strip():
                    waived_indices.add(idx)
                else:
                    updated_findings[idx] = RawCandidateFinding(
                        rule_code=f.rule_code,
                        node_id=f.node_id,
                        target_node_id=f.target_node_id,
                        source_file=f.source_file,
                        line=f.line,
                        title=f"Persistent config `{node.label}` lacks recovery expectation",
                        detail=(
                            f"{f.source_file}:{f.line} writes persistent config `{node.label}` "
                            "without TTL; missing TTL is expected for config, but no "
                            "recovery/backup expectation is recorded."
                        ),
                        remediation=(
                            "Record `recovery_expectation` (backup or seed source) in store purpose."
                        ),
                    )

        for r in node_rulings:
            if r.disposition != "accepted_clean":
                continue
            r_ks = r.store_purpose.keyspace_scope if r.store_purpose else None
            has_explicit_scope = bool(r.evidence_scope) or bool(r_ks)
            if (node.subkind == "cache_store" or node.id == "t:redis:default") and not (
                has_explicit_scope
            ):
                continue
            for idx in rel_indices:
                if idx in waived_indices:
                    continue
                f = updated_findings[idx]
                if has_explicit_scope:
                    if _finding_matches_scope(f, r.evidence_scope, r_ks):
                        waived_indices.add(idx)
                elif sp is None:
                    waived_indices.add(idx)

        remaining_for_node = [
            updated_findings[idx] for idx in rel_indices if idx not in waived_indices
        ]

        if sp is not None:
            v_sum, v_note = _build_verification_summary(
                node, sp, remaining_for_node, matched_src
            )
            sp.verification_summary = v_sum
            node.store_purpose = sp
            node.verification_note = v_note

        has_clean_ruling = any(r.disposition == "accepted_clean" for r in node_rulings)
        if remaining_for_node:
            _recompute_node_status(node, remaining_for_node)
        elif (has_clean_ruling and (node.subkind != "cache_store" or sp is None)) or (
            sp is not None
            and sp.intended_use == "persistent_config"
            and sp.recovery_expectation
        ):
            node.status = "clean"

    final_findings = [f for i, f in enumerate(updated_findings) if i not in waived_indices]
    waived_writer_ids = {
        updated_findings[idx].node_id
        for idx in waived_indices
        if updated_findings[idx].node_id
    }
    remaining_writer_ids = {f.node_id for f in final_findings if f.node_id}
    for wid in waived_writer_ids - remaining_writer_ids:
        wnode = nodes_by_id.get(wid)
        if wnode is not None and wnode.status == "gray_zone":
            wnode.status = "clean"

    auth_claims: dict[str, list[AtlasNode]] = {}
    for n in all_nodes:
        if n.store_purpose and n.store_purpose.intended_use == "authoritative_store":
            st = _domain_stem(n.id)
            if st and st not in _generic_stems:
                auth_claims.setdefault(st, []).append(n)
            if n.subkind == "cache_store" and st in sql_writers_by_stem:
                sql_node = sql_writers_by_stem[st]
                n.status = "duplicated_truth"
                sql_node.status = "duplicated_truth"
                final_findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-004",
                        node_id=n.id,
                        target_node_id=sql_node.id,
                        source_file=n.source_file,
                        line=n.line,
                        title=(
                            f"Conflicting authoritative stores `{n.label}` and "
                            f"SQL table `{sql_node.label}`"
                        ),
                        detail=(
                            f"Redis `{n.label}` declares `authoritative_store` while SQL table "
                            f"`{sql_node.label}` ({sql_node.source_file}:{sql_node.line}) also "
                            "receives active writes."
                        ),
                        remediation=(
                            "Consolidate single-writer authority or declare the Redis store as a "
                            "derived cache with an authoritative SQL source."
                        ),
                    )
                )

    for stem, claimants in auth_claims.items():
        if len(claimants) >= 2:
            primary, secondary = claimants[0], claimants[1]
            primary.status = "duplicated_truth"
            secondary.status = "duplicated_truth"
            final_findings.append(
                RawCandidateFinding(
                    rule_code="TRUTH-004",
                    node_id=secondary.id,
                    target_node_id=primary.id,
                    source_file=secondary.source_file,
                    line=secondary.line,
                    title=f"Conflicting authoritative declarations for domain `{stem}`",
                    detail=(
                        f"Both `{primary.label}` and `{secondary.label}` declare "
                        f"`authoritative_store` for `{stem}`."
                    ),
                    remediation=(
                        "Designate one authoritative store and mark downstream copies as "
                        "derived caches or replicas."
                    ),
                )
            )

    return final_findings
