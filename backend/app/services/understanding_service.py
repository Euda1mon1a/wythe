"""Read-only Six-Link Outcome, Authority, Provenance & Preservation Understanding Service.

Connects six links around a concrete human-agent investigation question:
    Intent -> Effective Policy/Context -> Execution -> Committed Result
           -> Human-Visible Result -> Preservation Evidence

All evaluators in this module are strictly read-only, deterministic, and non-executing:
- They preserve original producer identities, canonical issue/decision authority, and
  explicit `missing_joins` without inventing precedence rules, causal joins from temporal
  proximity, or generic "verified" badges when coverage is partial or stale.
- `target_code_executed` and `automated_security_audit` are always `False`.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Collection, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from app.core.clock import utc_now
from app.schemas.atlas import StrictSchema

_MAX_BUNDLE_BYTES = 8 * 1024 * 1024  # 8 MiB ceiling for companion JSON receipts
_MAX_JSON_DEPTH = 64
_BLOCKED_BUNDLE_PARTS = frozenset({".git", "secrets", ".secrets", "node_modules"})
_BLOCKED_BUNDLE_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx", ".sqlite", ".db", ".der"})

UnderstandingClaimKind = Literal[
    "source_inference",
    "recorded_selection",
    "demonstrated_effect",
    "runtime_observation",
    "authoritative_settlement",
    "historical_explanation",
    "unresolved",
]

CoverageState = Literal[
    "complete",
    "partial",
    "stale",
    "expired",
    "unobserved",
    "historical_invalidated",
]

SixLinkStageKey = Literal[
    "intent",
    "effective_policy_context",
    "execution",
    "committed_result",
    "human_visible_result",
    "preservation_evidence",
]

ChainLinkState = Literal[
    "supported",
    "degraded_or_drifted",
    "indeterminate",
    "historical_needs_revalidation",
    "regression_detected",
    "unverified",
    "unresolved",
]


def _check_json_depth(value: Any, *, max_depth: int = _MAX_JSON_DEPTH) -> None:
    """Iterative nesting-depth guard for untrusted JSON payloads."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth}).")
        if isinstance(current, dict):
            for child in current.values():
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))


def _reject_symlink_components(candidate: Path, *, stop_at: Path | None = None) -> None:
    """Reject symlinks on every path component before calling `.resolve()`."""
    expanded = candidate.expanduser()
    if "\x00" in str(expanded):
        raise ValueError("Null byte in bundle path is forbidden.")
    stop_resolved = stop_at.expanduser().resolve(strict=True) if stop_at is not None else None
    cur = Path(expanded.anchor) if expanded.is_absolute() else Path.cwd()
    parts = expanded.parts[1:] if expanded.is_absolute() else expanded.parts
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("Parent directory traversal ('..') is forbidden in bundle path.")
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"Symlink component rejected in bundle path: {cur}")
    resolved = cur.resolve(strict=True)
    if stop_resolved is not None and not resolved.is_relative_to(stop_resolved):
        raise ValueError("Bundle path escapes repository root.")


def read_understanding_bundle_file(
    bundle_path: Path | str,
    *,
    root_dir: Path | None = None,
) -> dict[str, Any]:
    """Safely read a bounded regular `.json` understanding bundle without following symlinks."""
    raw_str = str(bundle_path).strip()
    if not raw_str:
        raise ValueError("Empty bundle_path.")
    target_path = (
        (root_dir / raw_str) if (root_dir is not None and not Path(raw_str).is_absolute()) else Path(raw_str)
    )
    _reject_symlink_components(target_path, stop_at=root_dir)
    resolved = target_path.expanduser().resolve(strict=True)
    if resolved.suffix.lower() != ".json" or resolved.suffix.lower() in _BLOCKED_BUNDLE_SUFFIXES:
        raise ValueError("Understanding bundle must be a regular .json file.")
    rel_parts = resolved.relative_to(root_dir.resolve()).parts if root_dir is not None else resolved.parts
    for part in rel_parts:
        low = part.lower()
        if low in _BLOCKED_BUNDLE_PARTS or low == ".env" or low.startswith(".env."):
            raise ValueError(f"Blocked path segment in bundle path: {part}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(resolved, flags)
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Understanding bundle must be a regular file.")
        if st.st_size > _MAX_BUNDLE_BYTES:
            raise ValueError("Understanding bundle exceeds 8 MiB ceiling.")
        raw_bytes = handle.read(_MAX_BUNDLE_BYTES + 1)
    if len(raw_bytes) > _MAX_BUNDLE_BYTES:
        raise ValueError("Understanding bundle exceeds 8 MiB ceiling.")
    parsed = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise TypeError("Top-level understanding bundle JSON must be an object.")
    _check_json_depth(parsed)
    return parsed


class UnderstandingScope(StrictSchema):
    """Scope coordinates for a policy binding, capability lane, or dated observation."""

    lane: str | None = None
    role: str | None = None
    domain_scope: str | None = None
    effective_from: str | None = None
    effective_until: str | None = None


class UnderstandingReference(StrictSchema):
    """Canonical shared evidence reference retaining original producer identity & limits."""

    ref_id: str
    subject_id: str
    source_revision: str
    evidence_producer: str
    claim_kind: UnderstandingClaimKind
    scope: UnderstandingScope = Field(default_factory=UnderstandingScope)
    observed_at: str | None = None
    expires_at: str | None = None
    coverage_state: CoverageState = "partial"
    result_summary: str
    source_location: str | None = None
    authority_ref: str | None = None
    missing_joins: list[str] = Field(default_factory=list)


class AttachedHumanCorrection(StrictSchema):
    """Human challenge or domain clarification attached to evidence without becoming policy."""

    correction_id: str
    actor: str = "human"
    target_ref_id: str | None = None
    kind: str = "expectation_clarification"
    note: str
    recorded_at: str | None = None
    evidence_revision: str | None = None
    promoted_to_policy: bool = False


# ---------------------------------------------------------------------------
# Section A: Effective-Authority Schemas (Policy Bindings & Capability Lanes)
# ---------------------------------------------------------------------------

EffectiveEvidenceState = Literal[
    "demonstrated_effect",
    "recorded_selection",
    "source_inference",
    "bypassed",
    "unresolved",
]

TemporalInterpretationMode = Literal[
    "current_scope",
    "dated_snapshot_matched",
    "boundary_spanning_snapshots",
    "reinterpreted_under_current_vocabulary_warning",
    "missing_dated_snapshot_unresolved",
]


class DatedVocabularyCellBinding(StrictSchema):
    """Per-cell dated vocabulary interpretation across effective-date boundaries."""

    cell_id: str
    cell_date: str
    raw_token: str
    dated_snapshot_id: str | None = None
    dated_meaning: str | None = None
    current_snapshot_id: str | None = None
    current_meaning: str | None = None
    snapshot_status: Literal["matched_dated_snapshot", "reinterpreted_current_only", "unresolved"]


class TemporalAuthorityInterpretation(StrictSchema):
    """Separates historical dated-vocabulary meaning from current observation-time meaning."""

    artifact_effective_date: str | None = None
    observed_at: str | None = None
    historical_snapshot_id: str | None = None
    historical_meaning: str | None = None
    current_snapshot_id: str | None = None
    current_meaning: str | None = None
    interpretation_mode: TemporalInterpretationMode = "current_scope"
    cell_bindings: list[DatedVocabularyCellBinding] = Field(default_factory=list)
    warning: str | None = None


class PolicyBindingCandidate(StrictSchema):
    """Candidate source binding evaluated by a domain resolver."""

    binding_id: str
    source_kind: str  # e.g. "db_scoped_row", "db_global_row", "registry_json", "python_default"
    scope_label: str
    value: Any = None
    effective_from: str | None = None
    effective_until: str | None = None
    disposition: Literal[
        "selected_winner",
        "skipped_conflicting_scope",
        "overridden_by_narrower_or_winner",
        "excluded_out_of_date",
        "fallback_python_default",
        "refused_conflict",
        "candidate_unresolved",
    ]
    reason: str


class DownstreamConsumerEffect(StrictSchema):
    """Tracks whether a selected binding actually controls a downstream consumer."""

    consumer_id: str
    stage: str  # e.g. "persisted_row", "resolver", "immutable_input", "solver_objective", "export"
    effect_state: EffectiveEvidenceState
    mechanism: str
    reached_compiled_input: bool = False
    source_location: str | None = None
    note: str = ""


class CapabilityLaneEvaluation(StrictSchema):
    """Assistant capability/context lane trace: registry -> admission -> request -> delivery."""

    lane: str
    registered: bool
    admitted_by_policy: bool
    offered_in_request: bool
    selected_by_model: bool | None = None
    executed: bool | None = None
    execution_authority_state: Literal[
        "authorized_and_executed",
        "offered_not_authority_requires_grant",
        "denied_or_excluded",
        "not_invoked",
        "unresolved",
    ] = "not_invoked"
    model_visible_result: Literal["included", "missing", "not_applicable", "not_recorded"] = (
        "not_applicable"
    )
    authored_reply_state: Literal["grounded", "unsupported", "not_recorded", "not_applicable"] = (
        "not_recorded"
    )
    delivery_state: Literal["delivered", "queued_not_rendered", "not_recorded", "excluded"] = (
        "not_recorded"
    )
    exclusion_reason: str | None = None
    lane_verdict: Literal[
        "preserved_and_offered",
        "excluded_by_policy",
        "missing_expected_capability",
        "offered_without_execution_grant",
        "executed_delivery_unrecorded",
        "unresolved",
    ]
    missing_joins: list[str] = Field(default_factory=list)


class EffectiveAuthorityExplanation(StrictSchema):
    """Section A: Explains which truth/context won, what was skipped, and downstream effect."""

    item_id: str
    label: str
    domain_kind: Literal["policy_binding", "capability_context"] = "policy_binding"
    owner: str
    legitimate_editor: str
    authority_reference: str | None = None
    scope: UnderstandingScope = Field(default_factory=UnderstandingScope)
    observed_at: str | None = None
    selection_rule: str
    conflict_status: Literal[
        "none",
        "conflicting_scope_skipped_broader_retained",
        "typed_refusal",
        "unresolved_conflict_no_domain_precedence",
        "db_error_python_default_fallback",
    ] = "none"
    refusal_code: str | None = None
    fallback_activated: bool = False
    fallback_source: str | None = None
    winning_binding: PolicyBindingCandidate | None = None
    skipped_or_overridden_bindings: list[PolicyBindingCandidate] = Field(default_factory=list)
    candidate_bindings: list[PolicyBindingCandidate] = Field(default_factory=list)
    orphan_penalty_channels: list[str] = Field(default_factory=list)
    consumer_effects: list[DownstreamConsumerEffect] = Field(default_factory=list)
    lane_evaluations: list[CapabilityLaneEvaluation] = Field(default_factory=list)
    temporal_interpretation: TemporalAuthorityInterpretation = Field(
        default_factory=TemporalAuthorityInterpretation
    )
    evidence_state: EffectiveEvidenceState
    review_candidate: bool = False
    summary: str
    missing_joins: list[str] = Field(default_factory=list)
    reference: UnderstandingReference


# ---------------------------------------------------------------------------
# Sections B, C, D, Documentation Claims & Top-Level Six-Link Schemas
# ---------------------------------------------------------------------------

RuntimeProvenanceStatus = Literal[
    "aligned_within_observed_scope",
    "stale_running_process",
    "wrong_host",
    "wrong_artifact",
    "schema_client_mismatch",
    "stale_receipt",
    "incomplete_import_coverage",
    "config_or_policy_drift",
    "partial_or_unverified",
]


class ImportClosureSummary(StrictSchema):
    """Startup Python import closure and explicit non-covered dynamic/frontend surfaces."""

    coverage: Literal[
        "complete_python_startup_only",
        "incomplete_post_startup_loads",
        "excludes_frontend_and_dynamic",
        "unobserved",
    ] = "unobserved"
    recorded_modules_count: int = 0
    post_startup_dynamic_loads: list[str] = Field(default_factory=list)
    frontend_assets_covered: bool = False
    note: str = ""


class RuntimeProvenanceEvaluation(StrictSchema):
    """Section B: Explicit source -> artifact -> install -> host -> process -> consumer join."""

    invocation_id: str
    subject_id: str
    overall_status: RuntimeProvenanceStatus
    verification_badge: Literal[
        "aligned_observed_scope_only",
        "mismatch_detected",
        "stale_or_expired",
        "partial_coverage",
        "unverified",
    ]
    repo_revision: str | None = None
    dirty_digest: str | None = None
    artifact_digest: str | None = None
    expected_artifact_digest: str | None = None
    installed_path: str | None = None
    installed_path_hash: str | None = None
    expected_installed_hash: str | None = None
    host: str | None = None
    expected_host: str | None = None
    process_pid: int | None = None
    process_started_at: str | None = None
    process_startup_revision: str | None = None
    import_closure: ImportClosureSummary = Field(default_factory=ImportClosureSummary)
    schema_revision: str | None = None
    client_or_artifact_schema_revision: str | None = None
    config_digest: str | None = None
    expected_config_digest: str | None = None
    observed_at: str | None = None
    receipt_expires_at: str | None = None
    discrepancies: list[str] = Field(default_factory=list)
    missing_dimensions: list[str] = Field(default_factory=list)
    missing_joins: list[str] = Field(default_factory=list)
    summary: str
    reference: UnderstandingReference


OutcomeStage = Literal[
    "declared",
    "granted_not_executed",
    "executed",
    "executed_missing_followup_grounding",
    "supplied_answer_unrecorded",
    "candidate_sealed",
    "committed_unacknowledged",
    "authoritatively_settled",
    "queued_not_rendered",
    "delivered_to_human",
    "rejected",
    "deferred",
    "skipped",
    "unknown",
]


class OutcomeTransitionRecord(StrictSchema):
    """Single observed stage in a cross-boundary outcome lifecycle."""

    stage: OutcomeStage
    producer: str
    observed_at: str | None = None
    request_or_attempt_id: str | None = None
    predecessor_state_digest: str | None = None
    state_digest: str | None = None
    detail: str = ""


class OutcomeLifecycleExplanation(StrictSchema):
    """Section C: Cross-boundary outcome & failure lifecycle preserving unknown boundaries."""

    outcome_id: str
    subject_id: str
    producer_claimed_stage: str | None = None
    last_proven_stage: OutcomeStage
    current_stage: OutcomeStage
    settlement_state: Literal[
        "not_applicable",
        "uncommitted_candidate",
        "indeterminate_requires_settlement",
        "settled_committed",
        "settled_aborted",
        "unknown",
    ] = "not_applicable"
    answer_grounding: Literal[
        "grounded",
        "unsupported_or_omitted",
        "not_recorded",
        "not_applicable",
    ] = "not_applicable"
    delivery_status: Literal[
        "delivered",
        "queued_not_rendered",
        "not_recorded",
        "failed",
        "unknown",
    ] = "unknown"
    blind_retry_prohibited: bool = False
    retry_guidance: str = ""
    predecessor_chain_verified: bool = False
    proximity_join_rejected: bool = False
    authorship_established: bool = False
    owning_system_reason: str
    remaining_uncertainty: list[str] = Field(default_factory=list)
    next_evidence_check: str
    transitions: list[OutcomeTransitionRecord] = Field(default_factory=list)
    missing_joins: list[str] = Field(default_factory=list)
    reference: UnderstandingReference


class LaneCapabilityCellCheck(StrictSchema):
    """Single `(caller_lane, capability)` expectation or exclusion check."""

    lane: str
    capability: str
    expectation: Literal["must_preserve", "must_exclude"]
    baseline_present: bool | None = None
    candidate_present: bool | None = None
    passed: bool
    detail: str


class SolverSemanticComparison(StrictSchema):
    """Semantic multi-solution solver comparison (invariants over raw grid equality)."""

    raw_schedule_equal: bool
    hard_constraints_valid: bool
    admitted_policy_equal: bool
    selected_bindings_equal: bool
    locked_facts_preserved: bool
    candidate_complete: bool
    disconnected_penalty_channels: list[str] = Field(default_factory=list)
    export_meaning_equal: bool
    baseline_objective: float | None = None
    candidate_objective: float | None = None
    verdict: Literal[
        "equivalent_valid_alternatives",
        "identical_valid_solution",
        "semantic_change_verified",
        "disconnected_objective_channel",
        "invariant_violation",
    ]
    note: str = ""


class QualityLatencyComparison(StrictSchema):
    """Multi-dimensional latency vs answer-grounding check refusing 1D speed claims."""

    baseline_latency_ms: float | None = None
    candidate_latency_ms: float | None = None
    baseline_quality_score: float | None = None
    candidate_quality_score: float | None = None
    answer_quality_scored: bool = False
    static_budget_only: bool = False
    status: Literal[
        "not_applicable",
        "quality_maintained_or_improved",
        "faster_but_degraded_quality",
        "latency_only_quality_unscored",
        "degraded_quality",
    ] = "not_applicable"
    note: str = ""


class PreservationContractEvaluation(StrictSchema):
    """Section D: Desired change + preserved capability matrix + semantic before/after."""

    contract_id: str
    desired_change: str
    issue_or_decision_ref: str | None = None
    baseline_revision: str
    candidate_revision: str
    git_code_unchanged: bool = False
    non_git_semantic_drift_detected: bool = False
    changed_non_git_factors: list[str] = Field(default_factory=list)
    lane_checks: list[LaneCapabilityCellCheck] = Field(default_factory=list)
    failed_preserved_capabilities: list[str] = Field(default_factory=list)
    violated_exclusions: list[str] = Field(default_factory=list)
    disconnected_penalty_channels: list[str] = Field(default_factory=list)
    solver_comparison: SolverSemanticComparison | None = None
    quality_latency: QualityLatencyComparison = Field(default_factory=QualityLatencyComparison)
    verdict: Literal[
        "preserved_and_verified",
        "equivalent_valid_alternatives",
        "failed_regression",
        "non_git_drift_requires_review",
        "inconclusive_missing_quality_evidence",
    ]
    summary: str
    missing_joins: list[str] = Field(default_factory=list)
    reference: UnderstandingReference


class DocumentationClaimEvaluation(StrictSchema):
    """Documentation & prior-explanation freshness audit (`historical_needs_revalidation`)."""

    claim_id: str
    document_or_note_path: str
    claim_revision: str
    current_revision: str
    historical_claim: str
    owning_update_ref: str | None = None
    owning_update_summary: str | None = None
    current_code_evidence: str
    implemented_symbols_found: list[str] = Field(default_factory=list)
    unverified_remaining_phases: list[str] = Field(default_factory=list)
    status: Literal[
        "current_and_corroborated",
        "historical_needs_revalidation",
        "unverified_claim",
    ]
    safe_for_current_guidance: bool
    reference: UnderstandingReference


class UnderstandingChainLink(StrictSchema):
    """One link in the six-link human-agent understanding chain."""

    link_key: SixLinkStageKey
    stage_index: int = Field(ge=1, le=6)
    label: str
    state: ChainLinkState
    consequence_summary: str
    evidence_limit: str
    references: list[UnderstandingReference] = Field(default_factory=list)
    missing_joins: list[str] = Field(default_factory=list)


class UnderstandingChainReport(StrictSchema):
    """Complete read-only six-link understanding explanation for UI, CLI, and MCP."""

    schema_version: str = "wythe.understanding.v1"
    target_slug: str | None = None
    example_slug: str | None = None
    session_id: str | None = None
    question: str
    selected_subject_id: str | None = None
    evidence_revision: str
    evaluated_at: str
    consequence_headline: str
    last_supported_cause: str
    overall_missing_joins: list[str] = Field(default_factory=list)
    links: list[UnderstandingChainLink] = Field(default_factory=list)
    effective_authority: list[EffectiveAuthorityExplanation] = Field(default_factory=list)
    runtime_provenance: list[RuntimeProvenanceEvaluation] = Field(default_factory=list)
    outcome_lifecycles: list[OutcomeLifecycleExplanation] = Field(default_factory=list)
    preservation_evaluations: list[PreservationContractEvaluation] = Field(default_factory=list)
    documentation_claims: list[DocumentationClaimEvaluation] = Field(default_factory=list)
    human_corrections: list[AttachedHumanCorrection] = Field(default_factory=list)
    coverage_statement: str
    non_certification_notice: str
    target_code_executed: bool = False
    automated_security_audit: bool = False


class UnderstandingWalkthroughStep(StrictSchema):
    """Guided human/agent interaction step for synthetic example investigations."""

    step_number: int = Field(ge=1)
    actor: Literal["human", "agent", "system"]
    action: str
    expected_observation: str


class UnderstandingExampleSummary(StrictSchema):
    """Catalog metadata for a shipped Wave 6 example investigation."""

    slug: str
    title: str
    domain_package: str
    question: str
    summary: str
    covered_cases: list[str] = Field(default_factory=list)


class UnderstandingExampleRead(StrictSchema):
    """Complete synthetic example investigation bundle, candidate comparison & report."""

    summary: UnderstandingExampleSummary
    synthetic_files: dict[str, str] = Field(default_factory=dict)
    baseline_bundle: dict[str, Any] = Field(default_factory=dict)
    candidate_bundle: dict[str, Any] = Field(default_factory=dict)
    baseline_report: UnderstandingChainReport
    candidate_report: UnderstandingChainReport
    post_change_revalidation_report: UnderstandingChainReport
    walkthrough_steps: list[UnderstandingWalkthroughStep] = Field(default_factory=list)


class UnderstandingAnalyzeRequest(StrictSchema):
    """Request payload for `POST /api/v1/understanding/analyze`."""

    bundle: dict[str, Any] | None = None
    bundle_path: str | None = None
    target_slug: str | None = None
    example_slug: str | None = None
    session_id: str | None = None
    subject_id: str | None = None
    node_id: str | None = None
    finding_id: str | None = None
    edge_id: str | None = None
    question: str | None = None
    observed_at: str | None = None
    prior_explanation_revision: str | None = None
    human_corrections: list[dict[str, Any]] = Field(default_factory=list)


def _pick(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    """Read flexible snake_case / camelCase / producer-receipt alias keys without hardcoding."""
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _parse_iso_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        try:
            d = date.fromisoformat(cleaned[:10])
            return datetime(d.year, d.month, d.day, tzinfo=UTC)
        except ValueError:
            return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _parse_iso_date(value: str | None) -> date | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Section A Implementation: Effective-Authority Explanation
# ---------------------------------------------------------------------------


def _evaluate_temporal_interpretation(
    raw_item: Mapping[str, Any],
    *,
    observed_at: str | None,
) -> tuple[TemporalAuthorityInterpretation, list[str]]:
    missing: list[str] = []
    artifact_date_str = _pick(raw_item, "artifact_effective_date", "effective_date", "workbook_date")
    snapshots = _pick(raw_item, "vocabulary_snapshots", "dated_snapshots", default=[]) or []
    cells = _pick(raw_item, "dated_cells", "cell_bindings", "cells", default=[]) or []
    recorded_snap_id = _pick(raw_item, "recorded_vocabulary_snapshot_id", "historical_snapshot_id")

    obs_date = _parse_iso_date(observed_at)
    art_date = _parse_iso_date(artifact_date_str)

    def _find_snapshot_for_date(target_d: date | None) -> dict[str, Any] | None:
        if target_d is None:
            return None
        for snap in snapshots:
            if not isinstance(snap, Mapping):
                continue
            s_from = _parse_iso_date(_pick(snap, "effective_from", "valid_from"))
            s_until = _parse_iso_date(_pick(snap, "effective_until", "valid_until"))
            if s_from and target_d < s_from:
                continue
            if s_until and target_d > s_until:
                continue
            return dict(snap)
        return None

    current_snap = _find_snapshot_for_date(obs_date)
    if current_snap is None and snapshots and isinstance(snapshots[-1], Mapping):
        current_snap = dict(snapshots[-1])
    current_snap_id = _pick(current_snap or {}, "snapshot_id", "id")

    cell_out: list[DatedVocabularyCellBinding] = []
    distinct_cell_snaps: set[str] = set()
    reinterpreted_any = False
    unresolved_any = False

    for raw_cell in cells:
        if not isinstance(raw_cell, Mapping):
            continue
        cid = str(_pick(raw_cell, "cell_id", "id", default=f"cell-{len(cell_out) + 1}"))
        cdate_str = str(_pick(raw_cell, "cell_date", "date", default=artifact_date_str or ""))
        token = str(_pick(raw_cell, "raw_token", "token", "code", default=""))
        cdate = _parse_iso_date(cdate_str)
        dated_snap = _find_snapshot_for_date(cdate)
        cur_meanings = _pick(current_snap or {}, "meanings", "tokens", default={}) or {}
        cur_meaning = cur_meanings.get(token) if isinstance(cur_meanings, Mapping) else None
        has_dated_attach = bool(_pick(raw_cell, "dated_snapshot_attached", default=True))

        if dated_snap is not None and has_dated_attach:
            ds_id = str(_pick(dated_snap, "snapshot_id", "id", default="dated"))
            d_meanings = _pick(dated_snap, "meanings", "tokens", default={}) or {}
            d_meaning = d_meanings.get(token) if isinstance(d_meanings, Mapping) else None
            distinct_cell_snaps.add(ds_id)
            cell_out.append(
                DatedVocabularyCellBinding(
                    cell_id=cid,
                    cell_date=cdate_str,
                    raw_token=token,
                    dated_snapshot_id=ds_id,
                    dated_meaning=d_meaning,
                    current_snapshot_id=current_snap_id,
                    current_meaning=cur_meaning,
                    snapshot_status="matched_dated_snapshot",
                )
            )
        elif current_snap is not None:
            reinterpreted_any = True
            cell_out.append(
                DatedVocabularyCellBinding(
                    cell_id=cid,
                    cell_date=cdate_str,
                    raw_token=token,
                    dated_snapshot_id=None,
                    dated_meaning=None,
                    current_snapshot_id=current_snap_id,
                    current_meaning=cur_meaning,
                    snapshot_status="reinterpreted_current_only",
                )
            )
        else:
            unresolved_any = True
            cell_out.append(
                DatedVocabularyCellBinding(
                    cell_id=cid,
                    cell_date=cdate_str,
                    raw_token=token,
                    snapshot_status="unresolved",
                )
            )

    hist_snap = _find_snapshot_for_date(art_date)
    hist_snap_id = recorded_snap_id or _pick(hist_snap or {}, "snapshot_id", "id")
    probe_token = str(_pick(raw_item, "vocabulary_token", default=""))
    hist_meaning = _pick(raw_item, "historical_meaning")
    cur_meaning_top = _pick(raw_item, "current_meaning")
    if probe_token and hist_snap and hist_meaning is None:
        hm = _pick(hist_snap, "meanings", "tokens", default={})
        hist_meaning = hm.get(probe_token) if isinstance(hm, Mapping) else None
    if probe_token and current_snap and cur_meaning_top is None:
        cm = _pick(current_snap, "meanings", "tokens", default={})
        cur_meaning_top = cm.get(probe_token) if isinstance(cm, Mapping) else None

    mode: TemporalInterpretationMode = "current_scope"
    warning: str | None = None
    if unresolved_any or (art_date is not None and snapshots and hist_snap is None and not recorded_snap_id):
        mode = "missing_dated_snapshot_unresolved"
        missing.append("dated_vocabulary_snapshot_for_artifact_date")
        warning = (
            "Artifact date has no matching vocabulary snapshot; raw workbook/artifact bytes "
            "alone cannot establish historical cell meaning."
        )
    elif reinterpreted_any or (
        art_date is not None
        and recorded_snap_id is None
        and bool(_pick(raw_item, "artifact_bytes_only", default=False))
    ):
        mode = "reinterpreted_under_current_vocabulary_warning"
        missing.append("pinned_historical_vocabulary_snapshot")
        warning = (
            "Old artifact bytes are being read without a pinned historical snapshot; "
            "current vocabulary interpretation is NOT historical reconstruction."
        )
    elif len(distinct_cell_snaps) >= 2:
        mode = "boundary_spanning_snapshots"
        warning = (
            f"Cells cross an effective-date boundary spanning snapshots {sorted(distinct_cell_snaps)}; "
            "each date must use its own snapshot rather than a single global map."
        )
    elif hist_snap_id and current_snap_id and hist_snap_id != current_snap_id:
        mode = "dated_snapshot_matched"
        warning = (
            f"Historical snapshot '{hist_snap_id}' differs from current observation snapshot "
            f"'{current_snap_id}'; preserve dated interpretation for historical cells."
        )

    return (
        TemporalAuthorityInterpretation(
            artifact_effective_date=artifact_date_str,
            observed_at=observed_at,
            historical_snapshot_id=hist_snap_id,
            historical_meaning=hist_meaning,
            current_snapshot_id=current_snap_id,
            current_meaning=cur_meaning_top,
            interpretation_mode=mode,
            cell_bindings=cell_out,
            warning=warning,
        ),
        missing,
    )


def explain_effective_authority(
    raw_item: Mapping[str, Any],
    *,
    default_revision: str = "unpinned",
    evaluation_time: str | None = None,
) -> EffectiveAuthorityExplanation:
    """Section A: Explain effective policy selection, conflicts, lanes & downstream effect."""
    item_id = str(_pick(raw_item, "item_id", "id", "subject_id", default="authority-item"))
    label = str(_pick(raw_item, "label", "name", "policy_key", "capability_key", default=item_id))
    raw_lanes = _pick(raw_item, "lane_evaluations", "capability_lanes", "lanes", default=[]) or []
    domain_kind: Literal["policy_binding", "capability_context"] = (
        "capability_context"
        if _pick(raw_item, "domain_kind") == "capability_context" or bool(raw_lanes)
        else "policy_binding"
    )
    observed_at = str(_pick(raw_item, "observed_at", default=evaluation_time or "") or "") or None
    source_rev = str(_pick(raw_item, "source_revision", "commit", default=default_revision))
    producer = str(
        _pick(raw_item, "evidence_producer", "producer", default="wythe.effective_authority")
    )
    raw_scope = _pick(raw_item, "scope", default={}) or {}
    scope = UnderstandingScope(
        lane=_pick(raw_scope, "lane") if isinstance(raw_scope, Mapping) else None,
        role=_pick(raw_scope, "role") if isinstance(raw_scope, Mapping) else None,
        domain_scope=(
            _pick(raw_scope, "domain_scope", "scope_label")
            if isinstance(raw_scope, Mapping)
            else str(raw_scope)
        ),
        effective_from=_pick(raw_scope, "effective_from") if isinstance(raw_scope, Mapping) else None,
        effective_until=_pick(raw_scope, "effective_until") if isinstance(raw_scope, Mapping) else None,
    )

    temporal, missing_joins = _evaluate_temporal_interpretation(raw_item, observed_at=observed_at)
    missing_joins.extend(str(m) for m in (_pick(raw_item, "missing_joins", default=[]) or []))

    # Candidate bindings & domain conflict rules (never invent precedence!)
    raw_candidates = _pick(raw_item, "candidate_bindings", "candidates", default=[]) or []
    selection_rule = str(
        _pick(
            raw_item,
            "selection_rule",
            default="domain_recorded_selection_only (Wythe never invents precedence)",
        )
    )
    conflict_mode = str(_pick(raw_item, "conflict_resolution", "conflict_mode", default=""))
    refusal_code = _pick(raw_item, "refusal_code")
    db_sync_error = _pick(raw_item, "db_sync_error", "database_error")
    explicit_winner_id = _pick(raw_item, "winning_binding_id", "selected_binding_id")

    conflict_status: Literal[
        "none",
        "conflicting_scope_skipped_broader_retained",
        "typed_refusal",
        "unresolved_conflict_no_domain_precedence",
        "db_error_python_default_fallback",
    ] = "none"
    fallback_activated = False
    fallback_source: str | None = None
    review_candidate = bool(_pick(raw_item, "review_candidate", default=False))

    # Group narrowest scope conflicts when candidates carry `specificity` or same `scope_label`
    scope_values: dict[str, set[str]] = {}
    for rc in raw_candidates:
        if isinstance(rc, Mapping):
            sl = str(_pick(rc, "scope_label", "scope", default="global"))
            scope_values.setdefault(sl, set()).add(json.dumps(_pick(rc, "value"), sort_keys=True))
    conflicted_scopes = {sl for sl, vals in scope_values.items() if len(vals) > 1 and sl != "default"}

    candidates_out: list[PolicyBindingCandidate] = []
    winning_binding: PolicyBindingCandidate | None = None
    skipped_out: list[PolicyBindingCandidate] = []

    if db_sync_error:
        conflict_status = "db_error_python_default_fallback"
        fallback_activated = True
        fallback_source = str(_pick(raw_item, "fallback_source", default="python_default"))
        review_candidate = True
    elif conflict_mode in ("typed_refusal", "refused") or refusal_code:
        conflict_status = "typed_refusal"
    elif conflicted_scopes and conflict_mode == "skip_conflicting_scope_retain_broader":
        conflict_status = "conflicting_scope_skipped_broader_retained"
        review_candidate = True
    elif conflicted_scopes and not explicit_winner_id:
        conflict_status = "unresolved_conflict_no_domain_precedence"
        review_candidate = True
        missing_joins.append("domain_precedence_selection_record")

    for idx, rc in enumerate(raw_candidates):
        if not isinstance(rc, Mapping):
            continue
        bid = str(_pick(rc, "binding_id", "id", default=f"bind-{idx + 1}"))
        skind = str(_pick(rc, "source_kind", "source", default="db_row"))
        slabel = str(_pick(rc, "scope_label", "scope", default="global"))
        val = _pick(rc, "value")
        ef_from = _pick(rc, "effective_from")
        ef_until = _pick(rc, "effective_until")
        explicit_disp = _pick(rc, "disposition")
        reason = str(_pick(rc, "reason", default=""))

        if explicit_disp in (
            "selected_winner",
            "skipped_conflicting_scope",
            "overridden_by_narrower_or_winner",
            "excluded_out_of_date",
            "fallback_python_default",
            "refused_conflict",
            "candidate_unresolved",
        ):
            disp = explicit_disp
        elif db_sync_error:
            if skind == "python_default":
                disp = "fallback_python_default"
                reason = reason or f"Activated after database sync error: {db_sync_error}"
            else:
                disp = "overridden_by_narrower_or_winner"
                reason = reason or f"Unavailable due to database sync error: {db_sync_error}"
        elif conflict_status == "typed_refusal":
            disp = "refused_conflict"
            reason = reason or f"Rejected by domain policy refusal ({refusal_code or 'conflict'})"
        elif conflict_status == "unresolved_conflict_no_domain_precedence":
            disp = "candidate_unresolved"
            reason = reason or "Competing bindings at scope with no recorded domain precedence"
        elif conflict_status == "conflicting_scope_skipped_broader_retained" and slabel in conflicted_scopes:
            disp = "skipped_conflicting_scope"
            reason = reason or f"Conflicting values at scope '{slabel}' skipped by resolver"
        elif explicit_winner_id and bid == str(explicit_winner_id):
            disp = "selected_winner"
            reason = reason or "Selected by recorded domain resolver"
        elif (
            conflict_status == "conflicting_scope_skipped_broader_retained"
            and winning_binding is None
            and skind != "python_default"
            and slabel not in conflicted_scopes
        ):
            disp = "selected_winner"
            reason = reason or "Broader binding retained after narrower scope conflict"
        elif not explicit_winner_id and len(raw_candidates) == 1:
            disp = "selected_winner"
            reason = reason or "Single active candidate binding"
        else:
            disp = "overridden_by_narrower_or_winner"
            reason = reason or "Superseded by winning binding"

        cand = PolicyBindingCandidate(
            binding_id=bid,
            source_kind=skind,
            scope_label=slabel,
            value=val,
            effective_from=ef_from,
            effective_until=ef_until,
            disposition=disp,
            reason=reason,
        )
        candidates_out.append(cand)
        if disp in ("selected_winner", "fallback_python_default") and winning_binding is None:
            winning_binding = cand
        else:
            skipped_out.append(cand)

    emitted_penalties = [
        str(x) for x in (_pick(raw_item, "emitted_penalty_channels", default=[]) or [])
    ]
    consumed_penalties = {
        str(x) for x in (_pick(raw_item, "consumed_objective_channels", default=[]) or [])
    }
    explicit_orphans = [
        str(x) for x in (_pick(raw_item, "orphan_penalty_channels", default=[]) or [])
    ]
    orphan_channels = sorted(
        set(explicit_orphans)
        | (set(emitted_penalties) - consumed_penalties if emitted_penalties else set())
    )
    if orphan_channels:
        review_candidate = True
        missing_joins.append(f"orphan_penalty_to_objective:{','.join(orphan_channels)}")

    # Downstream consumers & assistant capability lanes
    consumers_out, lanes_out, ev_state = _evaluate_consumers_and_lanes(
        raw_item,
        raw_lanes=raw_lanes,
        conflict_status=conflict_status,
        orphan_channels=orphan_channels,
        temporal_mode=temporal.interpretation_mode,
        missing_joins=missing_joins,
    )
    if any(c.effect_state == "bypassed" for c in consumers_out) or any(
        ln.lane_verdict == "missing_expected_capability" for ln in lanes_out
    ):
        review_candidate = True

    dedup_missing = list(dict.fromkeys(missing_joins))
    claim_kind: UnderstandingClaimKind = (
        "demonstrated_effect"
        if ev_state == "demonstrated_effect"
        else "recorded_selection"
        if ev_state == "recorded_selection"
        else "source_inference"
        if ev_state in ("source_inference", "bypassed")
        else "unresolved"
    )
    cov: CoverageState = "complete" if not dedup_missing and ev_state == "demonstrated_effect" else "partial"
    summary = _build_authority_summary(
        label=label,
        winning_binding=winning_binding,
        conflict_status=conflict_status,
        orphan_channels=orphan_channels,
        consumers=consumers_out,
        lanes=lanes_out,
        temporal=temporal,
        ev_state=ev_state,
    )
    ref = UnderstandingReference(
        ref_id=f"ref:authority:{item_id}",
        subject_id=item_id,
        source_revision=source_rev,
        evidence_producer=producer,
        claim_kind=claim_kind,
        scope=scope,
        observed_at=observed_at,
        coverage_state=cov,
        result_summary=summary,
        source_location=_pick(raw_item, "source_location"),
        authority_ref=_pick(raw_item, "authority_reference", "authority_ref"),
        missing_joins=dedup_missing,
    )
    return EffectiveAuthorityExplanation(
        item_id=item_id,
        label=label,
        domain_kind=domain_kind,
        owner=str(_pick(raw_item, "owner", default="domain_owner")),
        legitimate_editor=str(_pick(raw_item, "legitimate_editor", default="persisted_policy_door")),
        authority_reference=_pick(raw_item, "authority_reference", "authority_ref"),
        scope=scope,
        observed_at=observed_at,
        selection_rule=selection_rule,
        conflict_status=conflict_status,
        refusal_code=refusal_code,
        fallback_activated=fallback_activated,
        fallback_source=fallback_source,
        winning_binding=winning_binding,
        skipped_or_overridden_bindings=skipped_out,
        candidate_bindings=candidates_out,
        orphan_penalty_channels=orphan_channels,
        consumer_effects=consumers_out,
        lane_evaluations=lanes_out,
        temporal_interpretation=temporal,
        evidence_state=ev_state,
        review_candidate=review_candidate,
        summary=summary,
        missing_joins=dedup_missing,
        reference=ref,
    )


def _evaluate_consumers_and_lanes(
    raw_item: Mapping[str, Any],
    *,
    raw_lanes: Sequence[Any],
    conflict_status: str,
    orphan_channels: Sequence[str],
    temporal_mode: TemporalInterpretationMode,
    missing_joins: list[str],
) -> tuple[list[DownstreamConsumerEffect], list[CapabilityLaneEvaluation], EffectiveEvidenceState]:
    raw_consumers = _pick(raw_item, "consumer_effects", "consumers", default=[]) or []
    consumers_out: list[DownstreamConsumerEffect] = []
    for idx, rc in enumerate(raw_consumers):
        if not isinstance(rc, Mapping):
            continue
        cid = str(_pick(rc, "consumer_id", "id", "consumer", default=f"consumer-{idx + 1}"))
        stage = str(_pick(rc, "stage", default="consumer"))
        raw_state = str(_pick(rc, "effect_state", "state", default="source_inference"))
        mech = str(_pick(rc, "mechanism", default="unspecified"))
        reached = bool(_pick(rc, "reached_compiled_input", default=(raw_state == "demonstrated_effect")))
        if mech in ("constant_or_fallback_wins", "field_ignored_after_table_read") or raw_state == "bypassed":
            eff_state: EffectiveEvidenceState = "bypassed"
            reached = False
        elif mech == "dynamic_or_opaque_flow" or raw_state == "unresolved":
            eff_state = "unresolved"
            reached = False
            missing_joins.append(f"opaque_consumer_handoff:{cid}")
        elif stage == "resolver" and not bool(_pick(rc, "verified_downstream_output", default=False)):
            # Audit rule: resolver return-value check alone is never full solve/export proof.
            eff_state = "recorded_selection"
        elif raw_state in ("demonstrated_effect", "recorded_selection", "source_inference"):
            eff_state = raw_state  # type: ignore[assignment]
        else:
            eff_state = "source_inference"
        consumers_out.append(
            DownstreamConsumerEffect(
                consumer_id=cid,
                stage=stage,
                effect_state=eff_state,
                mechanism=mech,
                reached_compiled_input=reached,
                source_location=_pick(rc, "source_location"),
                note=str(_pick(rc, "note", default="")),
            )
        )

    lanes_out: list[CapabilityLaneEvaluation] = []
    for rl in raw_lanes:
        if not isinstance(rl, Mapping):
            continue
        lane_name = str(_pick(rl, "lane", "lane_key", default="unknown_lane"))
        registered = bool(_pick(rl, "registered", default=True))
        admitted = bool(_pick(rl, "admitted_by_policy", "admitted", default=True))
        offered = bool(_pick(rl, "offered_in_request", "offered", default=False))
        selected = _pick(rl, "selected_by_model", "selected")
        executed = _pick(rl, "executed")
        req_grant = bool(_pick(rl, "requires_grant", default=False))
        has_grant = bool(_pick(rl, "grant_present", default=not req_grant))
        m_vis = str(_pick(rl, "model_visible_result", default="not_applicable"))
        a_rep = str(_pick(rl, "authored_reply_state", "answer_grounding", default="not_recorded"))
        d_st = str(_pick(rl, "delivery_state", "delivery_status", default="not_recorded"))
        excl = _pick(rl, "exclusion_reason")
        lane_missing: list[str] = []

        if not admitted and not offered:
            auth_state = "denied_or_excluded"
            verdict = "excluded_by_policy"
            d_st = "excluded"
        elif registered and admitted and not offered:
            auth_state = "not_invoked"
            verdict = "missing_expected_capability"
            lane_missing.append(f"lane:{lane_name}:admission_to_offered_request")
            missing_joins.extend(lane_missing)
        elif offered and req_grant and not has_grant:
            auth_state = "offered_not_authority_requires_grant"
            verdict = "offered_without_execution_grant"
            lane_missing.append(f"lane:{lane_name}:execution_broker_grant")
            missing_joins.extend(lane_missing)
        elif executed is True and (a_rep == "not_recorded" or d_st == "not_recorded"):
            auth_state = "authorized_and_executed"
            verdict = "executed_delivery_unrecorded"
            lane_missing.append(f"lane:{lane_name}:authored_reply_and_delivery")
            missing_joins.extend(lane_missing)
        elif offered:
            auth_state = "authorized_and_executed" if executed else "not_invoked"
            verdict = "preserved_and_offered"
        else:
            auth_state = "unresolved"
            verdict = "unresolved"

        lanes_out.append(
            CapabilityLaneEvaluation(
                lane=lane_name,
                registered=registered,
                admitted_by_policy=admitted,
                offered_in_request=offered,
                selected_by_model=bool(selected) if selected is not None else None,
                executed=bool(executed) if executed is not None else None,
                execution_authority_state=auth_state,  # type: ignore[arg-type]
                model_visible_result=m_vis if m_vis in ("included", "missing", "not_applicable", "not_recorded") else "not_recorded",  # type: ignore[arg-type]
                authored_reply_state=a_rep if a_rep in ("grounded", "unsupported", "not_recorded", "not_applicable") else "not_recorded",  # type: ignore[arg-type]
                delivery_state=d_st if d_st in ("delivered", "queued_not_rendered", "not_recorded", "excluded") else "not_recorded",  # type: ignore[arg-type]
                exclusion_reason=excl,
                lane_verdict=verdict,  # type: ignore[arg-type]
                missing_joins=lane_missing,
            )
        )

    explicit_ev = _pick(raw_item, "evidence_state")
    has_output_stage = any(
        c.stage in ("solver_objective", "terminal_validation", "accepted_output", "export")
        and c.effect_state == "demonstrated_effect"
        for c in consumers_out
    )
    if conflict_status == "unresolved_conflict_no_domain_precedence" or temporal_mode == "missing_dated_snapshot_unresolved":
        ev_state: EffectiveEvidenceState = "unresolved"
    elif conflict_status == "typed_refusal":
        ev_state = "recorded_selection"
    elif (
        (consumers_out and all(c.effect_state == "bypassed" for c in consumers_out))
        or (any(c.effect_state == "bypassed" for c in consumers_out) and not has_output_stage)
        or any(ln.lane_verdict == "missing_expected_capability" for ln in lanes_out)
    ):
        ev_state = "bypassed"
    elif orphan_channels:
        ev_state = "recorded_selection"
    elif consumers_out and all(c.stage == "resolver" for c in consumers_out):
        missing_joins.append("resolver_to_compiled_input_and_output")
        ev_state = "recorded_selection"
    elif any(c.effect_state == "unresolved" for c in consumers_out) and not has_output_stage:
        ev_state = "unresolved"
    elif has_output_stage:
        ev_state = "demonstrated_effect"
    elif explicit_ev in ("demonstrated_effect", "recorded_selection", "source_inference", "bypassed", "unresolved"):
        ev_state = explicit_ev
    elif lanes_out:
        ev_state = "recorded_selection"
    else:
        missing_joins.append("persisted_policy_to_consumer_effect")
        ev_state = "source_inference"

    return consumers_out, lanes_out, ev_state


def _build_authority_summary(
    *,
    label: str,
    winning_binding: PolicyBindingCandidate | None,
    conflict_status: str,
    orphan_channels: Sequence[str],
    consumers: Sequence[DownstreamConsumerEffect],
    lanes: Sequence[CapabilityLaneEvaluation],
    temporal: TemporalAuthorityInterpretation,
    ev_state: EffectiveEvidenceState,
) -> str:
    parts: list[str] = []
    if conflict_status == "unresolved_conflict_no_domain_precedence":
        parts.append(f"'{label}' has conflicting bindings with no domain precedence rule; left unresolved.")
    elif conflict_status == "typed_refusal":
        parts.append(f"'{label}' rejected conflicting bindings with an explicit typed domain refusal.")
    elif conflict_status == "conflicting_scope_skipped_broader_retained" and winning_binding:
        parts.append(
            f"'{label}' skipped conflicting narrow-scope bindings and retained broader binding "
            f"'{winning_binding.binding_id}' (value={winning_binding.value!r})."
        )
    elif conflict_status == "db_error_python_default_fallback" and winning_binding:
        parts.append(
            f"'{label}' fell back to Python default ({winning_binding.value!r}) after DB sync error."
        )
    elif winning_binding is not None:
        parts.append(
            f"'{label}' selected '{winning_binding.binding_id}' (value={winning_binding.value!r})."
        )
    else:
        parts.append(f"'{label}' evaluated across {len(lanes) or len(consumers)} consumer lane(s).")

    bypassed = [c.consumer_id for c in consumers if c.effect_state == "bypassed"]
    if bypassed:
        parts.append(f"Persisted authority read, but field bypassed/ignored in {bypassed}.")
    if orphan_channels:
        parts.append(f"Orphan penalty channel(s) disconnected from objective: {list(orphan_channels)}.")
    missing_lanes = [ln.lane for ln in lanes if ln.lane_verdict == "missing_expected_capability"]
    if missing_lanes:
        parts.append(f"Registered capability missing from expected lane request(s): {missing_lanes}.")
    if temporal.warning:
        parts.append(temporal.warning)
    parts.append(f"Evidence state: {ev_state}.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Section B Implementation: Source-to-Consumer Runtime Provenance Joiner
# ---------------------------------------------------------------------------


def evaluate_runtime_provenance(
    raw_item: Mapping[str, Any],
    *,
    evaluation_time: str | None = None,
) -> RuntimeProvenanceEvaluation:
    """Section B: Join source, artifact, install, host, process, schema, config & consumer."""
    inv_id = str(_pick(raw_item, "invocation_id", "request_id", "run_id", "id", default="inv-1"))
    subj_id = str(_pick(raw_item, "subject_id", "service", "component", default=inv_id))
    producer = str(_pick(raw_item, "evidence_producer", "producer", default="wythe.runtime_provenance"))

    repo_rev = _pick(raw_item, "repo_revision", "source_revision", "git_commit")
    dirty_dig = _pick(raw_item, "dirty_digest", "worktree_digest")
    art_dig = _pick(raw_item, "artifact_digest", "build_digest", "candidate_digest")
    exp_art_dig = _pick(raw_item, "expected_artifact_digest", "trace_artifact_digest")
    inst_path = _pick(raw_item, "installed_path", "live_path")
    inst_hash = _pick(raw_item, "installed_path_hash", "live_file_hash")
    exp_inst_hash = _pick(raw_item, "expected_installed_hash", "source_file_hash")
    host = _pick(raw_item, "host", "observed_host")
    exp_host = _pick(raw_item, "expected_host", "target_host")
    pid_raw = _pick(raw_item, "process_pid", "pid")
    pid = int(pid_raw) if isinstance(pid_raw, int) and not isinstance(pid_raw, bool) else None
    proc_start = _pick(raw_item, "process_started_at", "started_at")
    proc_rev = _pick(raw_item, "process_startup_revision", "running_revision")
    installed_at = _pick(raw_item, "installed_at", "deployed_at")
    schema_rev = _pick(raw_item, "schema_revision", "server_schema_revision")
    client_schema = _pick(
        raw_item, "client_or_artifact_schema_revision", "artifact_schema_revision", "client_schema_revision"
    )
    cfg_dig = _pick(raw_item, "config_digest", "runtime_config_digest")
    exp_cfg_dig = _pick(raw_item, "expected_config_digest", "baseline_config_digest")
    obs_at = _pick(raw_item, "observed_at")
    exp_at = _pick(raw_item, "receipt_expires_at", "expires_at")
    trace_req_id = _pick(raw_item, "trace_request_id")
    consumer_req_id = _pick(raw_item, "consumer_request_id")

    raw_ic = _pick(raw_item, "import_closure", default={}) or {}
    dyn_loads = [
        str(m)
        for m in (
            _pick(raw_ic, "post_startup_dynamic_loads", default=None)
            or _pick(raw_item, "post_startup_dynamic_loads", default=[])
            or []
        )
    ]
    rec_mods = int(_pick(raw_ic, "recorded_modules_count", default=0) or 0)
    fe_covered = bool(_pick(raw_ic, "frontend_assets_covered", default=False))
    fe_in_workflow = bool(_pick(raw_item, "workflow_touches_frontend", default=False))
    ic_mode_raw = _pick(raw_ic, "coverage", default=None) or _pick(raw_item, "import_closure_coverage")

    if ic_mode_raw in (
        "complete_python_startup_only",
        "incomplete_post_startup_loads",
        "excludes_frontend_and_dynamic",
        "unobserved",
    ):
        ic_cov = ic_mode_raw
    elif dyn_loads:
        ic_cov = "incomplete_post_startup_loads"
    elif rec_mods > 0 and (fe_in_workflow and not fe_covered):
        ic_cov = "excludes_frontend_and_dynamic"
    elif rec_mods > 0:
        ic_cov = "complete_python_startup_only"
    else:
        ic_cov = "unobserved"

    ic_note = str(
        _pick(
            raw_ic,
            "note",
            default=(
                "Startup Python import closure excludes modules imported dynamically after startup "
                "and browser/frontend asset bundles."
            ),
        )
    )
    import_closure = ImportClosureSummary(
        coverage=ic_cov,  # type: ignore[arg-type]
        recorded_modules_count=rec_mods,
        post_startup_dynamic_loads=dyn_loads,
        frontend_assets_covered=fe_covered,
        note=ic_note,
    )

    discrepancies: list[str] = []
    missing_dims: list[str] = []
    missing_joins: list[str] = [str(m) for m in (_pick(raw_item, "missing_joins", default=[]) or [])]

    for dim_name, dim_val in (
        ("repo_revision", repo_rev),
        ("installed_path_hash", inst_hash),
        ("host", host),
        ("process_startup_revision", proc_rev),
        ("schema_revision", schema_rev),
        ("config_digest", cfg_dig),
    ):
        if dim_val is None:
            missing_dims.append(dim_name)

    eval_dt = _parse_iso_ts(evaluation_time) or utc_now()
    exp_dt = _parse_iso_ts(exp_at)
    proc_dt = _parse_iso_ts(proc_start)
    inst_dt = _parse_iso_ts(installed_at)

    is_expired = exp_dt is not None and exp_dt < eval_dt
    is_wrong_host = bool(host and exp_host and host != exp_host)
    is_wrong_artifact = bool(
        (art_dig and exp_art_dig and art_dig != exp_art_dig)
        or (trace_req_id and consumer_req_id and trace_req_id != consumer_req_id)
    )
    is_stale_proc = bool(
        (repo_rev and proc_rev and repo_rev != proc_rev)
        or (inst_dt and proc_dt and inst_dt > proc_dt)
        or (inst_hash and exp_inst_hash and inst_hash == exp_inst_hash and proc_rev and repo_rev and proc_rev != repo_rev)
    )
    is_install_hash_mismatch = bool(inst_hash and exp_inst_hash and inst_hash != exp_inst_hash)
    is_schema_mismatch = bool(schema_rev and client_schema and schema_rev != client_schema)
    is_cfg_drift = bool(cfg_dig and exp_cfg_dig and cfg_dig != exp_cfg_dig)
    is_incomplete_ic = bool(
        ic_cov in ("incomplete_post_startup_loads", "excludes_frontend_and_dynamic")
        or dyn_loads
        or (fe_in_workflow and not fe_covered)
    )

    if is_wrong_host:
        discrepancies.append(f"right_file_wrong_host: observed host '{host}' != expected '{exp_host}'")
        missing_joins.append("target_host_runtime_observation")
    if is_wrong_artifact:
        discrepancies.append("fresh_trace_wrong_artifact: trace/invocation does not match consumer artifact")
        missing_joins.append("trace_to_consumer_artifact_digest")
    if is_install_hash_mismatch:
        discrepancies.append("installed_file_hash_mismatch: installed path differs from source tree hash")
    if is_stale_proc:
        discrepancies.append(
            f"new_disk_stale_process: disk revision '{repo_rev}' != running process '{proc_rev}'"
        )
        missing_joins.append("installed_disk_to_running_process_reload")
    if is_schema_mismatch:
        discrepancies.append(
            f"current_schema_old_client_or_artifact: schema '{schema_rev}' != client/artifact '{client_schema}'"
        )
        missing_joins.append("schema_revision_to_client_artifact_compatibility")
    if is_cfg_drift:
        discrepancies.append(
            f"config_or_policy_drift: runtime config digest '{cfg_dig}' != baseline '{exp_cfg_dig}'"
        )
    if is_expired:
        discrepancies.append(f"stale_receipt: receipt expired at {exp_at}")
        missing_joins.append("fresh_unexpired_runtime_receipt")
    if is_incomplete_ic:
        discrepancies.append(
            "incomplete_import_coverage: post-startup dynamic modules or frontend assets outside startup closure"
        )
        missing_joins.append("post_startup_dynamic_and_frontend_asset_provenance")

    # Priority ordering for primary status while retaining ALL discrepancies in `discrepancies`
    if is_wrong_host:
        status: RuntimeProvenanceStatus = "wrong_host"
        badge = "mismatch_detected"
    elif is_wrong_artifact or is_install_hash_mismatch:
        status = "wrong_artifact"
        badge = "mismatch_detected"
    elif is_stale_proc:
        status = "stale_running_process"
        badge = "stale_or_expired"
    elif is_schema_mismatch:
        status = "schema_client_mismatch"
        badge = "mismatch_detected"
    elif is_expired:
        status = "stale_receipt"
        badge = "stale_or_expired"
    elif is_cfg_drift:
        status = "config_or_policy_drift"
        badge = "mismatch_detected"
    elif is_incomplete_ic:
        status = "incomplete_import_coverage"
        badge = "partial_coverage"
    elif missing_dims or ic_cov == "unobserved":
        status = "partial_or_unverified"
        badge = "unverified" if len(missing_dims) >= 3 else "partial_coverage"
        missing_joins.extend(f"missing_provenance:{d}" for d in missing_dims)
    else:
        status = "aligned_within_observed_scope"
        badge = "aligned_observed_scope_only"

    dedup_missing = list(dict.fromkeys(missing_joins))
    cov_state: CoverageState = (
        "expired"
        if is_expired
        else "stale"
        if is_stale_proc
        else "partial"
        if (discrepancies or missing_dims or not fe_covered)
        else "complete"
    )
    summary = (
        f"Runtime provenance for '{subj_id}' is '{status}' ({badge}): "
        + ("; ".join(discrepancies) if discrepancies else "all observed dimensions aligned within startup scope.")
    )
    ref = UnderstandingReference(
        ref_id=f"ref:provenance:{inv_id}",
        subject_id=subj_id,
        source_revision=str(repo_rev or proc_rev or "unpinned"),
        evidence_producer=producer,
        claim_kind="runtime_observation" if (pid or host or inst_hash) else "unresolved",
        scope=UnderstandingScope(domain_scope=host),
        observed_at=obs_at,
        expires_at=exp_at,
        coverage_state=cov_state,
        result_summary=summary,
        authority_ref=_pick(raw_item, "authority_ref"),
        missing_joins=dedup_missing,
    )
    return RuntimeProvenanceEvaluation(
        invocation_id=inv_id,
        subject_id=subj_id,
        overall_status=status,
        verification_badge=badge,  # type: ignore[arg-type]
        repo_revision=repo_rev,
        dirty_digest=dirty_dig,
        artifact_digest=art_dig,
        expected_artifact_digest=exp_art_dig,
        installed_path=inst_path,
        installed_path_hash=inst_hash,
        expected_installed_hash=exp_inst_hash,
        host=host,
        expected_host=exp_host,
        process_pid=pid,
        process_started_at=proc_start,
        process_startup_revision=proc_rev,
        import_closure=import_closure,
        schema_revision=schema_rev,
        client_or_artifact_schema_revision=client_schema,
        config_digest=cfg_dig,
        expected_config_digest=exp_cfg_dig,
        observed_at=obs_at,
        receipt_expires_at=exp_at,
        discrepancies=discrepancies,
        missing_dimensions=missing_dims,
        missing_joins=dedup_missing,
        summary=summary,
        reference=ref,
    )


# ---------------------------------------------------------------------------
# Section C Implementation: Boundary Outcome & Failure Lifecycle
# ---------------------------------------------------------------------------

_VALID_OUTCOME_STAGES: frozenset[str] = frozenset(
    {
        "declared",
        "granted_not_executed",
        "executed",
        "executed_missing_followup_grounding",
        "supplied_answer_unrecorded",
        "candidate_sealed",
        "committed_unacknowledged",
        "authoritatively_settled",
        "queued_not_rendered",
        "delivered_to_human",
        "rejected",
        "deferred",
        "skipped",
        "unknown",
    }
)


_POSITIVE_TERMINAL_STATES: frozenset[str] = frozenset(
    {"committed", "accepted", "settled_committed"}
)
_NEGATIVE_TERMINAL_STATES: frozenset[str] = frozenset(
    {"rejected", "rolled_back", "aborted"}
)
_AUTHORITATIVE_TERMINAL_STATES: frozenset[str] = (
    _POSITIVE_TERMINAL_STATES | _NEGATIVE_TERMINAL_STATES
)
_SETTLEMENT_METADATA_KEYS: tuple[str, ...] = (
    "settlement_receipt",
    "settlement_receipt_id",
    "authoritative_settlement_receipt",
    "lock_settlement_receipt",
    "settlement_evidence",
    "authoritative_receipt",
    "settlement_digest",
    "after_image_digest",
    "terminal_digest",
    "settled_at",
    "settlement_observed_at",
    "settlement_timestamp",
    "settlement_lock_id",
    "publication_lock_id",
    "settlement_producer",
    "reconciled_by",
    "reconciliation_receipt",
)
_EXPLICIT_RECEIPT_BOOL_KEYS: tuple[str, ...] = (
    "settlement_receipt",
    "authoritative_settlement_receipt",
    "lock_settlement_receipt",
    "authoritative_receipt",
    "reconciliation_receipt",
)
_NEGATIVE_SETTLEMENT_VALUES: frozenset[str] = frozenset(
    {
        "not_found",
        "not-found",
        "notfound",
        "missing",
        "none",
        "null",
        "nil",
        "unknown",
        "pending",
        "in_progress",
        "unresolved",
        "indeterminate",
        "unavailable",
        "unreachable",
        "failed",
        "failure",
        "error",
        "timeout",
        "timed_out",
        "lost_reply",
        "unverified",
        "unreconciled",
        "unsettled",
        "unacknowledged",
        "committed_unacknowledged",
        "not_applicable",
        "n/a",
        "na",
        "false",
        "no",
        "0",
    }
)
_POSITIVE_SETTLED_RECEIPT_STATUSES: frozenset[str] = frozenset(
    {
        "settled",
        "committed",
        "accepted",
        "settled_committed",
        "settled_aborted",
        "rolled_back",
        "aborted",
        "reconciled",
        "verified",
        "confirmed",
    }
)
_RECEIPT_MAPPING_KEYS: tuple[str, ...] = (
    "settlement_receipt",
    "authoritative_settlement_receipt",
    "lock_settlement_receipt",
    "lock_receipt",
    "authoritative_receipt",
    "reconciliation_receipt",
    "settlement_evidence",
    "receipt",
)
_RECEIPT_ID_SCALAR_KEYS: tuple[str, ...] = (
    "settlement_receipt_id",
    "settlement_lock_id",
    "publication_lock_id",
)
_INNER_RECEIPT_ID_KEYS: tuple[str, ...] = (
    "receipt_id",
    "settlement_receipt_id",
    "lock_id",
    "settlement_lock_id",
    "publication_lock_id",
    "id",
)
_RECEIPT_BOOL_POSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "found",
        "exists",
        "verified",
        "settled",
        "reconciled",
        "ok",
        "valid",
        "matched",
        "acknowledged",
        "authoritative",
    }
)
_RECEIPT_BOOL_NEGATIVE_KEYS: frozenset[str] = frozenset(
    {
        "not_found",
        "missing",
        "failed",
        "error",
        "timed_out",
        "lost_reply",
        "indeterminate",
        "unverified",
        "conflict",
    }
)
_RECEIPT_STATUS_KEYS: frozenset[str] = frozenset(
    {
        "status",
        "state",
        "outcome",
        "result",
        "verdict",
        "settlement_state",
        "terminal_state",
        "authoritative_terminal_state",
        "final_state",
        "outcome_status",
        "settlement_status",
        "reconciliation_status",
        "receipt_status",
        "lock_status",
    }
)


def _is_valid_settlement_id_value(val: Any) -> str | None:
    if not isinstance(val, str):
        return None
    s = val.strip()
    if not s or s.lower() in _NEGATIVE_SETTLEMENT_VALUES:
        return None
    return s


def _is_nonempty_settlement_value(val: Any) -> bool:
    if val is None or isinstance(val, bool):
        return val is True
    if isinstance(val, (int, float)):
        return False
    if isinstance(val, str):
        return _is_valid_settlement_id_value(val) is not None
    if isinstance(val, Mapping):
        return any(_is_nonempty_settlement_value(v) for v in val.values())
    if isinstance(val, Sequence) and not isinstance(val, (bytes, bytearray)):
        return any(_is_nonempty_settlement_value(v) for v in val)
    return False


def _terminal_polarity(raw_val: Any) -> Literal["positive", "negative"] | None:
    if raw_val is None:
        return None
    low = str(raw_val).strip().lower()
    if low in ("committed", "accepted", "settled_committed", "delivered_to_human"):
        return "positive"
    if low in ("rejected", "rolled_back", "aborted", "settled_aborted", "failed"):
        return "negative"
    return None


_BENIGN_FALSE_RECEIPT_KEYS: frozenset[str] = frozenset(
    {
        "lost_reply",
        "transport_timeout_or_lost_reply",
        "timed_out",
        "blind_retry_prohibited",
        "error",
        "failed",
        "conflict",
        "missing",
        "not_found",
        "indeterminate",
        "unverified",
        "content_equality_only",
        "temporal_proximity_only",
    }
)
_ERROR_LIKE_RECEIPT_KEYS: frozenset[str] = frozenset(
    {
        "error",
        "error_code",
        "err",
        "failure",
        "failure_code",
        "failure_reason",
        "rejection_reason",
        "timeout_reason",
    }
)


def _inspect_receipt_tree(
    node: Any,
    *,
    settled_terminal: str | None,
    structured_maps: list[Mapping[str, Any]],
    receipt_ids: set[str],
    lock_ids: set[str],
    receipt_polarities: set[str],
    allow_positive_capture: bool = True,
) -> bool:
    """Walk a receipt value/mapping recursively; return True if any negative/invalid state is seen."""
    neg = False
    if node is None or node is False:
        if node is False and settled_terminal in _POSITIVE_TERMINAL_STATES:
            receipt_polarities.add("negative")
        return True
    if node is True:
        return False
    if isinstance(node, (int, float)):
        return True
    if isinstance(node, str):
        pol = _terminal_polarity(node)
        if pol is not None:
            receipt_polarities.add(pol)
        return _is_valid_settlement_id_value(node) is None
    if isinstance(node, Sequence) and not isinstance(node, (bytes, bytearray)):
        if len(node) == 0:
            return True
        for elem in node:
            if _inspect_receipt_tree(
                elem,
                settled_terminal=settled_terminal,
                structured_maps=structured_maps,
                receipt_ids=receipt_ids,
                lock_ids=lock_ids,
                receipt_polarities=receipt_polarities,
                allow_positive_capture=allow_positive_capture,
            ):
                neg = True
        return neg
    if isinstance(node, Mapping):
        if len(node) == 0:
            return True
        if allow_positive_capture:
            structured_maps.append(node)
        for raw_k, raw_v in node.items():
            kl = str(raw_k).strip().lower()
            if raw_v is False:
                if kl not in _BENIGN_FALSE_RECEIPT_KEYS:
                    neg = True
                    if kl in _RECEIPT_BOOL_POSITIVE_KEYS and settled_terminal in _POSITIVE_TERMINAL_STATES:
                        receipt_polarities.add("negative")
            elif raw_v is True and (kl in _RECEIPT_BOOL_NEGATIVE_KEYS or kl in _ERROR_LIKE_RECEIPT_KEYS):
                neg = True
            elif isinstance(raw_v, str):
                s_clean = raw_v.strip()
                s_low = s_clean.lower()
                if kl in _RECEIPT_BOOL_POSITIVE_KEYS and s_low in ("false", "0", "no"):
                    neg = True
                    if settled_terminal in _POSITIVE_TERMINAL_STATES:
                        receipt_polarities.add("negative")
                elif (kl in _RECEIPT_BOOL_NEGATIVE_KEYS and s_low in ("true", "1", "yes")) or (
                    kl in _ERROR_LIKE_RECEIPT_KEYS
                    and s_clean
                    and s_low not in ("none", "null", "0", "false", "ok")
                ) or (kl not in _ERROR_LIKE_RECEIPT_KEYS and _is_valid_settlement_id_value(raw_v) is None):
                    neg = True
            if kl == "stage" and raw_v is not None and (
                not isinstance(raw_v, str)
                or raw_v.strip().lower()
                not in (_POSITIVE_SETTLED_RECEIPT_STATUSES | {"authoritatively_settled"})
            ):
                neg = True
            if kl in _RECEIPT_STATUS_KEYS and raw_v is not None:
                pol = _terminal_polarity(raw_v)
                if pol is not None:
                    receipt_polarities.add(pol)
                if (
                    not isinstance(raw_v, str)
                    or raw_v.strip().lower() not in _POSITIVE_SETTLED_RECEIPT_STATUSES
                ):
                    neg = True
            if kl in _INNER_RECEIPT_ID_KEYS and not isinstance(raw_v, Mapping):
                cid = _is_valid_settlement_id_value(raw_v)
                if cid is None:
                    neg = True
                elif allow_positive_capture:
                    if kl in ("lock_id", "settlement_lock_id", "publication_lock_id"):
                        lock_ids.add(cid)
                    else:
                        receipt_ids.add(cid)
            if (
                isinstance(raw_v, Mapping)
                or (isinstance(raw_v, Sequence) and not isinstance(raw_v, (str, bytes, bytearray)))
            ) and _inspect_receipt_tree(
                raw_v,
                settled_terminal=settled_terminal,
                structured_maps=structured_maps,
                receipt_ids=receipt_ids,
                lock_ids=lock_ids,
                receipt_polarities=receipt_polarities,
                allow_positive_capture=allow_positive_capture,
            ):
                neg = True
        return neg
    return True


def _validate_post_loss_settlement(
    raw_item: Mapping[str, Any],
    *,
    raw_transition_maps: Sequence[Mapping[str, Any]],
    raw_transition_stages: Sequence[str],
    transitions: Sequence[OutcomeTransitionRecord],
    last_loss_idx: int,
    settled_terminal: str | None,
    top_term_digests: set[str],
    settlement_commit_digests: set[str],
) -> tuple[bool, bool]:
    """Return `(is_valid_settlement, has_receipt_conflict)` for post-loss write reconciliation."""
    structured_maps: list[Mapping[str, Any]] = []
    receipt_ids: set[str] = set()
    lock_ids: set[str] = set()
    receipt_polarities: set[str] = set()
    has_negative = False

    post_loss_sources: list[Mapping[str, Any]] = [raw_item]
    non_post_loss_transitions: list[Mapping[str, Any]] = []
    for t_idx, (st_l, rt) in enumerate(zip(raw_transition_stages, raw_transition_maps, strict=False)):
        rt_lost = bool(_pick(rt, "transport_timeout_or_lost_reply", "lost_reply", default=False))
        if t_idx > last_loss_idx and not rt_lost and st_l in (
            "authoritatively_settled",
            "settled_committed",
            "settled_aborted",
        ):
            post_loss_sources.append(rt)
        else:
            non_post_loss_transitions.append(rt)

    for src_m in post_loss_sources:
        for rk in _RECEIPT_MAPPING_KEYS:
            if rk in src_m and _inspect_receipt_tree(
                src_m[rk],
                settled_terminal=settled_terminal,
                structured_maps=structured_maps,
                receipt_ids=receipt_ids,
                lock_ids=lock_ids,
                receipt_polarities=receipt_polarities,
                allow_positive_capture=(rk != "receipt"),
            ):
                has_negative = True

    for pre_rt in non_post_loss_transitions:
        for rk in _RECEIPT_MAPPING_KEYS:
            if rk in pre_rt:
                pre_neg = _inspect_receipt_tree(
                    pre_rt[rk],
                    settled_terminal=settled_terminal,
                    structured_maps=structured_maps,
                    receipt_ids=receipt_ids,
                    lock_ids=lock_ids,
                    receipt_polarities=receipt_polarities,
                    allow_positive_capture=False,
                )
                if rk != "receipt" and pre_neg:
                    has_negative = True

    for src_m in post_loss_sources:
        for ik in _RECEIPT_ID_SCALAR_KEYS:
            if ik in src_m:
                cid = _is_valid_settlement_id_value(src_m[ik])
                if cid is None:
                    has_negative = True
                elif ik in ("settlement_lock_id", "publication_lock_id"):
                    lock_ids.add(cid)
                else:
                    receipt_ids.add(cid)
        for bk in _RECEIPT_BOOL_POSITIVE_KEYS:
            if src_m.get(bk) is False or (
                isinstance(src_m.get(bk), str)
                and str(src_m[bk]).strip().lower() in ("false", "0", "no")
            ):
                has_negative = True
                if settled_terminal in _POSITIVE_TERMINAL_STATES:
                    receipt_polarities.add("negative")
        for nk in _RECEIPT_BOOL_NEGATIVE_KEYS:
            if nk in ("lost_reply", "timed_out") and src_m is raw_item:
                continue
            if src_m.get(nk) is True:
                has_negative = True
        for ek in _ERROR_LIKE_RECEIPT_KEYS | {"settlement_error", "reconciliation_error"}:
            ev_err = src_m.get(ek)
            if ev_err is True or (
                isinstance(ev_err, str)
                and ev_err.strip()
                and ev_err.strip().lower() not in ("none", "null", "0", "false", "ok")
            ):
                has_negative = True
        status_keys = _RECEIPT_STATUS_KEYS - ({"state"} if src_m is raw_item else set())
        for sk in status_keys:
            if sk in src_m and src_m[sk] is not None:
                pol = _terminal_polarity(src_m[sk])
                if pol is not None:
                    receipt_polarities.add(pol)
                if (
                    not isinstance(src_m[sk], str)
                    or src_m[sk].strip().lower() not in _POSITIVE_SETTLED_RECEIPT_STATUSES
                ):
                    has_negative = True

    has_scalar_receipt_id = any(
        _is_valid_settlement_id_value(src_m.get(sk)) is not None
        for src_m in post_loss_sources
        for sk in _RECEIPT_ID_SCALAR_KEYS
    )
    if structured_maps and not has_scalar_receipt_id and not any(
        isinstance(rm.get(sk), str)
        and str(rm[sk]).strip().lower() in _POSITIVE_SETTLED_RECEIPT_STATUSES
        for rm in structured_maps
        for sk in _RECEIPT_STATUS_KEYS
    ):
        has_negative = True

    term_pol = _terminal_polarity(settled_terminal)
    has_conflict = bool(
        ("positive" in receipt_polarities and "negative" in receipt_polarities)
        or (term_pol == "positive" and "negative" in receipt_polarities)
        or (term_pol == "negative" and "positive" in receipt_polarities)
    )
    if len(receipt_ids) > 1 or len(lock_ids) > 1:
        has_conflict = True
        has_negative = True

    settled_stages = ("authoritatively_settled", "settled_committed", "settled_aborted", "delivered_to_human")
    anchor_maps: list[Mapping[str, Any]] = [raw_item] + [
        rt
        for idx, (st_l, rt) in enumerate(zip(raw_transition_stages, raw_transition_maps, strict=False))
        if idx <= last_loss_idx or st_l not in settled_stages
    ]
    evidence_maps: list[Mapping[str, Any]] = list(structured_maps) + [
        rt
        for idx, (st_l, rt) in enumerate(zip(raw_transition_stages, raw_transition_maps, strict=False))
        if idx > last_loss_idx and st_l in ("authoritatively_settled", "settled_committed", "settled_aborted")
    ]
    all_maps = [*anchor_maps, *evidence_maps]

    for corr_key in ("operation_id", "request_id", "attempt_id", "idempotency_key"):
        seen_vals: set[str] = set()
        for m in all_maps:
            if corr_key in m and m[corr_key] is not None:
                cv = _is_valid_settlement_id_value(m[corr_key])
                if cv is None:
                    has_negative = True
                else:
                    seen_vals.add(cv)
        if len(seen_vals) > 1:
            has_negative = True

    req_or_att_vals: set[str] = set()
    for m in all_maps:
        if "request_or_attempt_id" in m and m["request_or_attempt_id"] is not None:
            rv = _is_valid_settlement_id_value(m["request_or_attempt_id"])
            if rv is None:
                has_negative = True
            else:
                req_or_att_vals.add(rv)
    if len(req_or_att_vals) > 1:
        has_negative = True
    for m in all_maps:
        for rk_cmp in ("request_id", "attempt_id"):
            rv_cmp = _is_valid_settlement_id_value(m.get(rk_cmp))
            if rv_cmp is not None and req_or_att_vals and rv_cmp not in req_or_att_vals:
                # Allow distinct request_id vs attempt_id only when request_or_attempt_id matches at least one
                sibling = _is_valid_settlement_id_value(
                    m.get("attempt_id" if rk_cmp == "request_id" else "request_id")
                )
                if sibling is None or sibling not in req_or_att_vals:
                    has_negative = True

    explicit_out_id = _is_valid_settlement_id_value(_pick(raw_item, "outcome_id", "id", "journey_id"))
    for em in evidence_maps:
        if "outcome_id" in em and em["outcome_id"] is not None:
            ev_oid = _is_valid_settlement_id_value(em["outcome_id"])
            if ev_oid is None or (explicit_out_id is not None and ev_oid != explicit_out_id):
                has_negative = True

    rcpt_term_digests: set[str] = set()
    for rm in structured_maps:
        for dk in ("settlement_digest", "after_image_digest", "terminal_digest", "state_digest"):
            if dk in rm and rm[dk] is not None:
                dv = _is_valid_settlement_id_value(rm[dk])
                if dv is None:
                    has_negative = True
                else:
                    rcpt_term_digests.add(dv)
    combined_term = top_term_digests | settlement_commit_digests | rcpt_term_digests
    if len(combined_term) > 1:
        has_conflict = True
        has_negative = True

    all_pre_loss_digests = {
        t.state_digest
        for idx, (st_l, t) in enumerate(zip(raw_transition_stages, transitions, strict=False))
        if (idx <= last_loss_idx or st_l not in settled_stages)
        and _is_valid_settlement_id_value(t.state_digest) is not None
        and t.state_digest is not None
    }
    pre_top_dig = _is_valid_settlement_id_value(raw_item.get("pre_loss_state_digest"))
    if pre_top_dig is not None:
        all_pre_loss_digests.add(pre_top_dig)
    if not transitions and not top_term_digests:
        raw_st_dig = _is_valid_settlement_id_value(raw_item.get("state_digest"))
        if raw_st_dig is not None:
            all_pre_loss_digests.add(raw_st_dig)

    for rm in structured_maps:
        rm_state_digs = {
            dv
            for dk in ("settlement_digest", "after_image_digest", "terminal_digest", "state_digest")
            if (dv := _is_valid_settlement_id_value(rm.get(dk))) is not None
        }
        rm_pred_digs: set[str] = set()
        for pk in ("predecessor_state_digest", "predecessor_digest"):
            if pk in rm and rm[pk] is not None:
                pv = _is_valid_settlement_id_value(rm[pk])
                if pv is None or (all_pre_loss_digests and pv not in all_pre_loss_digests):
                    has_negative = True
                elif pv is not None:
                    rm_pred_digs.add(pv)
        if settled_terminal in _POSITIVE_TERMINAL_STATES and (
            rm_state_digs & (rm_pred_digs | all_pre_loss_digests)
        ):
            has_negative = True

    if has_negative or has_conflict or not (receipt_ids or lock_ids):
        return False, has_conflict

    anchor_ops = {
        v for m in anchor_maps if (v := _is_valid_settlement_id_value(m.get("operation_id"))) is not None
    }
    anchor_reqs = {
        v
        for m in anchor_maps
        if (v := _is_valid_settlement_id_value(_pick(m, "request_id", "request_or_attempt_id"))) is not None
    }
    anchor_atts = {
        v
        for m in anchor_maps
        if (v := _is_valid_settlement_id_value(_pick(m, "attempt_id", "request_or_attempt_id"))) is not None
    }
    anchor_idems = {
        v for m in anchor_maps if (v := _is_valid_settlement_id_value(m.get("idempotency_key"))) is not None
    }

    path_a_ok = False
    for t_idx, (st_l, rt, t) in enumerate(
        zip(raw_transition_stages, raw_transition_maps, transitions, strict=False)
    ):
        rt_lost = bool(_pick(rt, "transport_timeout_or_lost_reply", "lost_reply", default=False))
        if (
            t_idx <= last_loss_idx
            or rt_lost
            or st_l not in ("authoritatively_settled", "settled_committed", "settled_aborted")
            or _is_valid_settlement_id_value(t.state_digest) is None
        ):
            continue
        prior_digs = {
            pt.state_digest
            for pt in transitions[:t_idx]
            if _is_valid_settlement_id_value(pt.state_digest) is not None and pt.state_digest is not None
        }
        if pre_top_dig is not None:
            prior_digs.add(pre_top_dig)
        if settled_terminal in _POSITIVE_TERMINAL_STATES and (
            t.state_digest in prior_digs or t.state_digest == t.predecessor_state_digest
        ):
            continue
        pred_ok = (
            _is_valid_settlement_id_value(t.predecessor_state_digest) is not None
            and t.predecessor_state_digest in prior_digs
        )
        id_ok = (
            _is_valid_settlement_id_value(rt.get("operation_id")) in anchor_ops
            or _is_valid_settlement_id_value(_pick(rt, "request_id", "request_or_attempt_id")) in anchor_reqs
            or _is_valid_settlement_id_value(_pick(rt, "attempt_id", "request_or_attempt_id")) in anchor_atts
            or _is_valid_settlement_id_value(rt.get("idempotency_key")) in anchor_idems
        )
        if pred_ok or id_ok:
            path_a_ok = True
            break

    path_b_ok = False
    for rm in structured_maps:
        has_rm_id = bool(
            any(_is_valid_settlement_id_value(rm.get(ik)) is not None for ik in _INNER_RECEIPT_ID_KEYS)
            or any(_is_valid_settlement_id_value(raw_item.get(sk)) is not None for sk in _RECEIPT_ID_SCALAR_KEYS)
        )
        has_pos_status = any(
            isinstance(rm.get(sk), str)
            and str(rm[sk]).strip().lower() in _POSITIVE_SETTLED_RECEIPT_STATUSES
            for sk in _RECEIPT_STATUS_KEYS
        )
        rm_linked = (
            _is_valid_settlement_id_value(rm.get("operation_id")) in anchor_ops
            or _is_valid_settlement_id_value(_pick(rm, "request_id", "request_or_attempt_id")) in anchor_reqs
            or _is_valid_settlement_id_value(_pick(rm, "attempt_id", "request_or_attempt_id")) in anchor_atts
            or _is_valid_settlement_id_value(rm.get("idempotency_key")) in anchor_idems
            or _is_valid_settlement_id_value(_pick(rm, "predecessor_state_digest", "predecessor_digest"))
            in all_pre_loss_digests
        )
        if has_rm_id and has_pos_status and rm_linked:
            path_b_ok = True
            break

    return bool(path_a_ok or path_b_ok), has_conflict


def explain_outcome_lifecycle(
    raw_item: Mapping[str, Any],
    *,
    default_revision: str = "unpinned",
) -> OutcomeLifecycleExplanation:
    """Section C: Explain cross-boundary outcome stages, settlement & unknown limits."""
    outcome_id = str(_pick(raw_item, "outcome_id", "id", "journey_id", default="outcome-1"))
    subj_id = str(_pick(raw_item, "subject_id", "target", default=outcome_id))
    producer = str(_pick(raw_item, "evidence_producer", "producer", default="wythe.outcome_lifecycle"))
    source_rev = str(_pick(raw_item, "source_revision", "commit", default=default_revision))

    raw_transitions = _pick(raw_item, "transitions", "stages", default=[]) or []
    transitions: list[OutcomeTransitionRecord] = []
    raw_transition_maps: list[Mapping[str, Any]] = []
    raw_transition_stages: list[str] = []
    transition_polarities: set[str] = set()
    settlement_commit_digests: set[str] = set()
    delivery_digests: list[tuple[str | None, str]] = []
    last_loss_idx = -1
    seen_settled_transition = False
    terminal_conflict = False
    predecessor_ok = True
    prev_state_digest: str | None = None
    proximity_rejected = bool(_pick(raw_item, "temporal_proximity_only", default=False))
    missing_joins: list[str] = [str(m) for m in (_pick(raw_item, "missing_joins", default=[]) or [])]

    seen_req_ids: set[str] = set()
    for rt in raw_transitions:
        if not isinstance(rt, Mapping):
            continue
        t_idx = len(transitions)
        raw_transition_maps.append(rt)
        st_raw = str(_pick(rt, "stage", default="unknown")).strip()
        st_low = st_raw.lower()
        raw_transition_stages.append(st_low)
        st: OutcomeStage = (
            st_low  # type: ignore[assignment]
            if st_low in _VALID_OUTCOME_STAGES
            else ("authoritatively_settled" if st_low in _POSITIVE_TERMINAL_STATES else ("rejected" if st_low in _NEGATIVE_TERMINAL_STATES else "unknown"))
        )
        rt_lost = bool(_pick(rt, "transport_timeout_or_lost_reply", "lost_reply", default=False))
        if rt_lost or st_low == "committed_unacknowledged":
            last_loss_idx = t_idx
        req_id = _pick(rt, "request_or_attempt_id", "request_id", "attempt_id")
        pred_dig_raw = _pick(rt, "predecessor_state_digest", "predecessor_digest")
        cur_dig_raw = _pick(
            rt, "state_digest", "after_image_digest", "terminal_digest", "settlement_digest"
        )
        pred_dig = str(pred_dig_raw).strip() if pred_dig_raw is not None and str(pred_dig_raw).strip() else None
        cur_dig = str(cur_dig_raw).strip() if cur_dig_raw is not None and str(cur_dig_raw).strip() else None
        rt_dig_vals = [
            str(rt[dk]).strip()
            for dk in ("state_digest", "after_image_digest", "terminal_digest", "settlement_digest")
            if isinstance(rt.get(dk), str) and _is_nonempty_settlement_value(rt.get(dk))
        ]
        if len(set(rt_dig_vals)) > 1:
            terminal_conflict = True
        for pol_cand in (
            _terminal_polarity(st_low),
            _terminal_polarity(_pick(rt, "authoritative_terminal_state", "terminal_state", "settlement_state")),
        ):
            if pol_cand is not None:
                transition_polarities.add(pol_cand)
        if seen_settled_transition and (st_low == "committed_unacknowledged" or rt_lost):
            terminal_conflict = True
        if st_low in (_AUTHORITATIVE_TERMINAL_STATES | {"authoritatively_settled", "delivered_to_human"}):
            seen_settled_transition = True
        is_commit_settlement_step = st_low in (
            _AUTHORITATIVE_TERMINAL_STATES | {"authoritatively_settled"}
        ) or any(_is_nonempty_settlement_value(rt.get(dk)) for dk in ("terminal_digest", "settlement_digest"))
        if is_commit_settlement_step and rt_dig_vals:
            settlement_commit_digests.update(rt_dig_vals)
            if len(settlement_commit_digests) > 1:
                terminal_conflict = True
        elif st_low == "delivered_to_human" and cur_dig is not None:
            if (
                settlement_commit_digests
                and cur_dig not in settlement_commit_digests
                and pred_dig not in settlement_commit_digests
                and pred_dig != prev_state_digest
            ):
                terminal_conflict = True
            if delivery_digests:
                prev_deliv_dig = delivery_digests[-1][1]
                if cur_dig != prev_deliv_dig and pred_dig != prev_deliv_dig:
                    terminal_conflict = True
            delivery_digests.append((pred_dig, cur_dig))
        if bool(_pick(rt, "joined_by_timestamp_only", default=False)):
            proximity_rejected = True
        if t_idx > 0 and prev_state_digest is not None and pred_dig is not None and pred_dig != prev_state_digest:
            predecessor_ok = False
            missing_joins.append(f"broken_predecessor_state_vector_at_step_{t_idx + 1}")
        if req_id:
            seen_req_ids.add(str(req_id))
        if cur_dig is not None:
            prev_state_digest = cur_dig
        transitions.append(
            OutcomeTransitionRecord(
                stage=st,
                producer=str(_pick(rt, "producer", default=producer)),
                observed_at=_pick(rt, "observed_at"),
                request_or_attempt_id=req_id,
                predecessor_state_digest=pred_dig,
                state_digest=cur_dig,
                detail=str(_pick(rt, "detail", "note", default="")),
            )
        )

    if len(seen_req_ids) > 1 and not bool(_pick(raw_item, "explicit_cross_request_link", default=False)):
        proximity_rejected = True
        missing_joins.append("unlinked_request_ids_temporal_proximity_rejected")
    if proximity_rejected:
        missing_joins.append("explicit_request_or_predecessor_join")

    has_pred_vectors = any(t.predecessor_state_digest or t.state_digest for t in transitions)
    predecessor_verified = bool(has_pred_vectors and predecessor_ok and not proximity_rejected)

    # Infer or normalize stage from explicit producer fields while enforcing lost-reply invariants
    raw_claimed_val = _pick(raw_item, "current_stage", "stage")
    producer_claimed_stage = (
        str(raw_claimed_val).strip()
        if raw_claimed_val is not None and str(raw_claimed_val).strip() != ""
        else None
    )
    explicit_stage = producer_claimed_stage or ""
    explicit_stage_low = explicit_stage.lower()
    tool_executed = _pick(raw_item, "tool_executed", "executed")
    followup_included = _pick(raw_item, "tool_result_included_in_followup", "model_visible_data_included")
    ans_ground_raw = str(_pick(raw_item, "answer_grounding", default="not_applicable"))
    deliv_raw = str(_pick(raw_item, "delivery_status", "delivery", default="unknown"))
    lost_reply = bool(
        _pick(raw_item, "transport_timeout_or_lost_reply", "lost_reply", default=False)
        or last_loss_idx >= 0
    )
    sealed_only = bool(_pick(raw_item, "candidate_sealed_only", default=False))
    grant_only = bool(_pick(raw_item, "grant_issued_not_executed", default=False))
    queued_only = bool(_pick(raw_item, "queued_not_rendered", default=False))
    settled_terminal_raw = _pick(raw_item, "authoritative_terminal_state")
    settled_terminal = (
        str(settled_terminal_raw).strip().lower()
        if settled_terminal_raw is not None and str(settled_terminal_raw).strip() != ""
        else None
    )

    polarities = set(transition_polarities)
    for field_val in (
        explicit_stage_low,
        settled_terminal,
        _pick(raw_item, "settlement_state"),
        _pick(raw_item, "terminal_state", "final_state", "outcome_status"),
    ):
        pol = _terminal_polarity(field_val)
        if pol is not None:
            polarities.add(pol)
    if deliv_raw == "delivered" and settled_terminal in _NEGATIVE_TERMINAL_STATES:
        polarities.add("positive")
    if deliv_raw == "failed" and explicit_stage_low == "delivered_to_human":
        polarities.add("negative")
    if (
        any(raw_item.get(k) is False for k in _EXPLICIT_RECEIPT_BOOL_KEYS)
        or any(rt.get(k) is False for rt in raw_transition_maps for k in _EXPLICIT_RECEIPT_BOOL_KEYS)
    ) and (settled_terminal in _POSITIVE_TERMINAL_STATES):
        polarities.add("negative")
    if "positive" in polarities and "negative" in polarities:
        terminal_conflict = True

    top_term_digests = {
        str(raw_item[dk]).strip()
        for dk in ("settlement_digest", "after_image_digest", "terminal_digest")
        if isinstance(raw_item.get(dk), str) and _is_nonempty_settlement_value(raw_item.get(dk))
    }
    if len(top_term_digests) > 1:
        terminal_conflict = True
    if (
        not transitions
        and top_term_digests
        and isinstance(raw_item.get("state_digest"), str)
        and _is_nonempty_settlement_value(raw_item.get("state_digest"))
        and str(raw_item["state_digest"]).strip() not in top_term_digests
    ):
        terminal_conflict = True
    if (
        top_term_digests
        and settlement_commit_digests
        and len(top_term_digests | settlement_commit_digests) > 1
    ):
        terminal_conflict = True
    if not predecessor_ok and (
        settled_terminal is not None
        or seen_settled_transition
        or explicit_stage_low in (_AUTHORITATIVE_TERMINAL_STATES | {"authoritatively_settled", "delivered_to_human"})
    ):
        terminal_conflict = True

    validated_post_loss_settlement, receipt_conflict = _validate_post_loss_settlement(
        raw_item,
        raw_transition_maps=raw_transition_maps,
        raw_transition_stages=raw_transition_stages,
        transitions=transitions,
        last_loss_idx=last_loss_idx,
        settled_terminal=settled_terminal,
        top_term_digests=top_term_digests,
        settlement_commit_digests=settlement_commit_digests,
    )
    if receipt_conflict:
        terminal_conflict = True
    has_settlement_metadata = bool(
        validated_post_loss_settlement
        and not bool(_pick(raw_item, "content_equality_only", default=False))
        and not proximity_rejected
        and predecessor_ok
    )
    authoritative_settlement_valid = bool(
        settled_terminal in _AUTHORITATIVE_TERMINAL_STATES
        and has_settlement_metadata
        and not terminal_conflict
    )
    force_indeterminate_settlement = (
        lost_reply and not authoritative_settlement_valid
    ) or terminal_conflict

    if force_indeterminate_settlement:
        current_stage: OutcomeStage = "committed_unacknowledged"
    elif lost_reply and authoritative_settlement_valid:
        if settled_terminal in _POSITIVE_TERMINAL_STATES and deliv_raw == "delivered":
            current_stage = "delivered_to_human"
        else:
            current_stage = "authoritatively_settled"
    elif explicit_stage_low in _VALID_OUTCOME_STAGES:
        current_stage = explicit_stage_low  # type: ignore[assignment]
    elif explicit_stage_low in _POSITIVE_TERMINAL_STATES:
        current_stage = "delivered_to_human" if deliv_raw == "delivered" else "authoritatively_settled"
    elif explicit_stage_low in _NEGATIVE_TERMINAL_STATES and not settled_terminal:
        current_stage = "rejected"
    elif settled_terminal in _POSITIVE_TERMINAL_STATES and deliv_raw == "delivered":
        current_stage = "delivered_to_human"
    elif settled_terminal in _AUTHORITATIVE_TERMINAL_STATES:
        current_stage = "authoritatively_settled"
    elif sealed_only:
        current_stage = "candidate_sealed"
    elif grant_only:
        current_stage = "granted_not_executed"
    elif queued_only or deliv_raw == "queued_not_rendered":
        current_stage = "queued_not_rendered"
    elif tool_executed is True and followup_included is False:
        current_stage = "executed_missing_followup_grounding"
    elif tool_executed is True and (
        ans_ground_raw in ("not_recorded", "unsupported_or_omitted")
        or deliv_raw in ("not_recorded", "unknown")
    ):
        current_stage = "supplied_answer_unrecorded"
    elif transitions:
        current_stage = transitions[-1].stage
    else:
        current_stage = "unknown"

    if force_indeterminate_settlement:
        pre_loss_stages = ("declared", "granted_not_executed", "executed", "candidate_sealed")
        prior_proven = next(
            (t.stage for t in reversed(transitions) if t.stage in pre_loss_stages),
            None,
        )
        if prior_proven is not None:
            last_proven: OutcomeStage = prior_proven
        elif explicit_stage_low in pre_loss_stages:
            last_proven = explicit_stage_low  # type: ignore[assignment]
        else:
            last_proven = "committed_unacknowledged"
    else:
        last_proven = (
            transitions[-1].stage
            if transitions and transitions[-1].stage != "unknown"
            else (
                "executed"
                if current_stage in ("executed_missing_followup_grounding", "supplied_answer_unrecorded")
                else current_stage
            )
        )

    # Settlement, grounding, delivery & retry safety rules
    settlement_state: Literal[
        "not_applicable",
        "uncommitted_candidate",
        "indeterminate_requires_settlement",
        "settled_committed",
        "settled_aborted",
        "unknown",
    ] = "not_applicable"
    blind_retry_prohibited = False
    retry_guidance = "Read-only inspection; follow domain idempotency contract."
    uncertainty: list[str] = [
        str(u) for u in (_pick(raw_item, "remaining_uncertainty", default=[]) or [])
    ]

    if current_stage == "candidate_sealed":
        settlement_state = "uncommitted_candidate"
        uncertainty.append("Sealed candidate artifact is NOT an accepted or published schedule.")
        missing_joins.append("candidate_acceptance_transaction_and_settlement")
    elif current_stage == "committed_unacknowledged" or force_indeterminate_settlement:
        settlement_state = "indeterminate_requires_settlement"
        blind_retry_prohibited = True
        retry_guidance = (
            "DO NOT blindly retry write after transport timeout, lost reply, or conflicting "
            "terminal evidence; read authoritative terminal state under the "
            "publication/transaction lock before taking action."
        )
        if producer_claimed_stage and producer_claimed_stage != "committed_unacknowledged":
            uncertainty.append(
                f"Producer claimed stage '{producer_claimed_stage}', overridden to "
                "'committed_unacknowledged' because settlement is indeterminate and blind write "
                "retries are prohibited until authoritative terminal state is reconciled."
            )
        if terminal_conflict:
            uncertainty.append(
                "Conflicting terminal state or transition digest evidence detected; settlement is "
                "indeterminate and blind write retries are prohibited until authoritative "
                "terminal state is reconciled."
            )
            missing_joins.append("conflicting_terminal_settlement_evidence_reconciliation")
        else:
            uncertainty.append(
                "Mutation may have committed despite lost reply; settlement is indeterminate and "
                "blind write retries are prohibited until authoritative terminal state is reconciled."
            )
        missing_joins.append("authoritative_lock_settlement_receipt")
        missing_joins.append(
            "indeterminate_settlement_blind_retry_prohibited_until_authoritative_reconciliation"
        )
    elif current_stage == "authoritatively_settled":
        settlement_state = (
            "settled_aborted" if settled_terminal in _NEGATIVE_TERMINAL_STATES else "settled_committed"
        )
        if deliv_raw != "delivered":
            uncertainty.append("Database state settled, but downstream timeline/workbook refresh is separate.")
            missing_joins.append("consumer_timeline_or_workbook_refresh_receipt")
    elif current_stage == "delivered_to_human" and settled_terminal in _POSITIVE_TERMINAL_STATES:
        settlement_state = "settled_committed"
    elif current_stage == "granted_not_executed":
        uncertainty.append("Broker/capability grant was issued, which does not establish execution.")
        missing_joins.append("execution_invocation_receipt")
    elif current_stage == "executed_missing_followup_grounding":
        ans_ground_raw = "unsupported_or_omitted" if ans_ground_raw == "not_applicable" else ans_ground_raw
        uncertainty.append("Tool executed, but output was absent from the follow-up model context.")
        missing_joins.append("tool_output_to_model_followup_request")
    elif current_stage == "supplied_answer_unrecorded":
        if ans_ground_raw == "not_applicable":
            ans_ground_raw = "not_recorded"
        if deliv_raw == "unknown":
            deliv_raw = "not_recorded"
        uncertainty.append(
            "Tool output reached follow-up prompt, but final answer grounding and human delivery are not certified."
        )
        missing_joins.append("authored_answer_grounding_and_human_delivery_receipt")
    elif current_stage == "queued_not_rendered":
        deliv_raw = "queued_not_rendered"
        uncertainty.append("Outbound item is queued; screen/card rendering has not been confirmed.")
        missing_joins.append("client_render_application_receipt")

    ans_ground: Literal["grounded", "unsupported_or_omitted", "not_recorded", "not_applicable"] = (
        ans_ground_raw  # type: ignore[assignment]
        if ans_ground_raw in ("grounded", "unsupported_or_omitted", "not_recorded", "not_applicable")
        else "not_recorded"
    )
    deliv_status: Literal["delivered", "queued_not_rendered", "not_recorded", "failed", "unknown"] = (
        "unknown"
        if (force_indeterminate_settlement and deliv_raw == "delivered")
        else (
            deliv_raw  # type: ignore[assignment]
            if deliv_raw in ("delivered", "queued_not_rendered", "not_recorded", "failed", "unknown")
            else "unknown"
        )
    )
    # Equality of current file/workbook bytes never establishes writer authorship by itself
    authorship = bool(
        _pick(raw_item, "authenticated_writer_receipt", default=False)
        and not bool(_pick(raw_item, "content_equality_only", default=False))
        and not force_indeterminate_settlement
    )
    default_reason = f"Lifecycle reached '{current_stage}' (last proven: '{last_proven}')."
    if force_indeterminate_settlement:
        claimed_note = (
            f" (producer claimed '{producer_claimed_stage}')"
            if producer_claimed_stage and producer_claimed_stage != "committed_unacknowledged"
            else ""
        )
        default_reason = (
            f"Lifecycle forced to 'committed_unacknowledged'{claimed_note} (last proven: "
            f"'{last_proven}'); settlement is indeterminate and blind write retries are "
            "prohibited until authoritative terminal state is reconciled."
        )
    reason = str(_pick(raw_item, "owning_system_reason", "reason", default=default_reason))
    if force_indeterminate_settlement and "blind" not in reason.lower():
        claimed_note = (
            f" Producer claimed '{producer_claimed_stage}'."
            if producer_claimed_stage and producer_claimed_stage != "committed_unacknowledged"
            else ""
        )
        reason = (
            f"{reason.rstrip()}{claimed_note} Settlement is indeterminate and blind write "
            "retries are prohibited until authoritative terminal state is reconciled."
        )
    next_check = str(
        _pick(
            raw_item,
            "next_evidence_check",
            default=(
                "Query authoritative settlement state under publication lock before any retry."
                if blind_retry_prohibited
                else "Inspect downstream consumer receipt for the first missing join."
            ),
        )
    )
    dedup_missing = list(dict.fromkeys(missing_joins))
    claim_kind: UnderstandingClaimKind = (
        "authoritative_settlement"
        if settlement_state in ("settled_committed", "settled_aborted")
        else "unresolved"
        if settlement_state == "indeterminate_requires_settlement"
        else "runtime_observation"
        if current_stage != "declared" and current_stage != "unknown"
        else "source_inference"
        if current_stage == "declared"
        else "unresolved"
    )
    ref = UnderstandingReference(
        ref_id=f"ref:outcome:{outcome_id}",
        subject_id=subj_id,
        source_revision=source_rev,
        evidence_producer=producer,
        claim_kind=claim_kind,
        observed_at=_pick(raw_item, "observed_at"),
        coverage_state="complete" if (current_stage == "delivered_to_human" and not dedup_missing) else "partial",
        result_summary=f"{reason} (grounding={ans_ground}, delivery={deliv_status}, settlement={settlement_state})",
        authority_ref=_pick(raw_item, "authority_ref"),
        missing_joins=dedup_missing,
    )
    return OutcomeLifecycleExplanation(
        outcome_id=outcome_id,
        subject_id=subj_id,
        producer_claimed_stage=producer_claimed_stage,
        last_proven_stage=last_proven,
        current_stage=current_stage,
        settlement_state=settlement_state,
        answer_grounding=ans_ground,
        delivery_status=deliv_status,
        blind_retry_prohibited=blind_retry_prohibited,
        retry_guidance=retry_guidance,
        predecessor_chain_verified=predecessor_verified,
        proximity_join_rejected=proximity_rejected,
        authorship_established=authorship,
        owning_system_reason=reason,
        remaining_uncertainty=list(dict.fromkeys(uncertainty)),
        next_evidence_check=next_check,
        transitions=transitions,
        missing_joins=dedup_missing,
        reference=ref,
    )


# ---------------------------------------------------------------------------
# Section D Implementation: Preservation & Semantic Comparison Contract
# ---------------------------------------------------------------------------


def _lane_cap_present(evidence: Mapping[str, Any], lane: str, cap: str) -> bool | None:
    lanes_map = _pick(evidence, "lane_capabilities", "lanes", default={})
    if not isinstance(lanes_map, Mapping) or lane not in lanes_map:
        return None
    entry = lanes_map[lane]
    if isinstance(entry, Mapping):
        if "offered_capabilities" in entry and isinstance(entry["offered_capabilities"], Sequence):
            return cap in entry["offered_capabilities"]
        return bool(entry[cap]) if cap in entry else False
    if isinstance(entry, Sequence) and not isinstance(entry, (str, bytes)):
        return cap in entry
    return None


def evaluate_preservation_contract(
    raw_item: Mapping[str, Any],
    *,
    default_revision: str = "unpinned",
) -> PreservationContractEvaluation:
    """Section D: Verify preserved caller-lane capabilities, solver invariants & drift."""
    cid = str(_pick(raw_item, "contract_id", "id", default="preservation-1"))
    desired = str(_pick(raw_item, "desired_change", "intent", default="unspecified change"))
    issue_ref = _pick(raw_item, "issue_or_decision_ref", "authority_ref")
    producer = str(
        _pick(raw_item, "evidence_producer", "producer", default="wythe.preservation_contract")
    )

    base_ev = _pick(raw_item, "baseline_evidence", "baseline", default={}) or {}
    cand_ev = _pick(raw_item, "candidate_evidence", "candidate", default={}) or {}
    base_rev = str(_pick(base_ev, "source_commit", "source_revision", default=default_revision))
    cand_rev = str(_pick(cand_ev, "source_commit", "source_revision", default=default_revision))
    git_unchanged = bool(
        _pick(raw_item, "git_code_unchanged", default=(base_rev == cand_rev and base_rev != "unpinned"))
    )

    # Non-Git semantic drift check (Case 10)
    non_git_factors: list[str] = []
    for factor_key in (
        "policy_digest",
        "config_digest",
        "model_id",
        "model_artifact_digest",
        "offered_tools_digest",
        "schema_revision",
        "server_identity",
    ):
        b_val = _pick(base_ev, factor_key)
        c_val = _pick(cand_ev, factor_key)
        if b_val is not None and c_val is not None and b_val != c_val:
            non_git_factors.append(f"{factor_key} ({b_val!r} -> {c_val!r})")
    b_samp = _pick(base_ev, "sampler_settings", default={}) or {}
    c_samp = _pick(cand_ev, "sampler_settings", default={}) or {}
    if isinstance(b_samp, Mapping) and isinstance(c_samp, Mapping):
        for sk in sorted(set(b_samp.keys()) | set(c_samp.keys())):
            if b_samp.get(sk) != c_samp.get(sk):
                non_git_factors.append(f"sampler_settings.{sk} ({b_samp.get(sk)!r} -> {c_samp.get(sk)!r})")
    non_git_drift = bool(git_unchanged and non_git_factors)

    # Caller-lane x capability matrix (Case 9)
    req_by_lane = _pick(raw_item, "required_capabilities_by_lane", "preserved_capabilities", default={}) or {}
    excl_by_lane = _pick(raw_item, "required_exclusions_by_lane", "excluded_capabilities", default={}) or {}
    lane_checks: list[LaneCapabilityCellCheck] = []
    failed_caps: list[str] = []
    violated_excl: list[str] = []
    missing_joins: list[str] = [str(m) for m in (_pick(raw_item, "missing_joins", default=[]) or [])]

    if isinstance(req_by_lane, Mapping):
        for lane, caps in req_by_lane.items():
            for cap in (caps if isinstance(caps, Sequence) and not isinstance(caps, str) else [caps]):
                cap_s = str(cap)
                b_pres = _lane_cap_present(base_ev, str(lane), cap_s)
                c_pres = _lane_cap_present(cand_ev, str(lane), cap_s)
                passed = c_pres is True
                if not passed:
                    failed_caps.append(f"{lane}:{cap_s}")
                    if c_pres is None:
                        missing_joins.append(f"candidate_lane_entrypoint_proof:{lane}:{cap_s}")
                lane_checks.append(
                    LaneCapabilityCellCheck(
                        lane=str(lane),
                        capability=cap_s,
                        expectation="must_preserve",
                        baseline_present=b_pres,
                        candidate_present=c_pres,
                        passed=passed,
                        detail=(
                            f"Preserved on '{lane}'"
                            if passed
                            else f"MISSING required capability '{cap_s}' on lane '{lane}'"
                        ),
                    )
                )

    if isinstance(excl_by_lane, Mapping):
        for lane, caps in excl_by_lane.items():
            for cap in (caps if isinstance(caps, Sequence) and not isinstance(caps, str) else [caps]):
                cap_s = str(cap)
                b_pres = _lane_cap_present(base_ev, str(lane), cap_s)
                c_pres = _lane_cap_present(cand_ev, str(lane), cap_s)
                passed = c_pres is False
                if not passed:
                    violated_excl.append(f"{lane}:{cap_s}")
                lane_checks.append(
                    LaneCapabilityCellCheck(
                        lane=str(lane),
                        capability=cap_s,
                        expectation="must_exclude",
                        baseline_present=b_pres,
                        candidate_present=c_pres,
                        passed=passed,
                        detail=(
                            f"Excluded as required on '{lane}'"
                            if passed
                            else f"VIOLATED exclusion: '{cap_s}' exposed or unverified on '{lane}'"
                        ),
                    )
                )

    # Disconnected objective penalty channels
    exp_channels = {
        str(x)
        for x in (
            _pick(raw_item, "expected_objective_channels", default=None)
            or _pick(base_ev, "consumed_objective_channels", default=[])
            or []
        )
    }
    cand_emitted = {str(x) for x in (_pick(cand_ev, "emitted_penalty_channels", default=[]) or [])}
    cand_consumed_raw = _pick(cand_ev, "consumed_objective_channels")
    disconnected: list[str] = [
        str(x) for x in (_pick(cand_ev, "disconnected_penalty_channels", default=[]) or [])
    ]
    if cand_consumed_raw is not None:
        cand_consumed = {str(x) for x in cand_consumed_raw}
        disconnected = sorted(set(disconnected) | ((exp_channels | cand_emitted) - cand_consumed))

    # Multi-solution solver comparison (Case 11) & Latency-vs-Quality guard
    solver_comp = _evaluate_solver_comparison(base_ev, cand_ev, disconnected)
    if solver_comp is not None and solver_comp.disconnected_penalty_channels:
        disconnected = sorted(set(disconnected) | set(solver_comp.disconnected_penalty_channels))
    ql_comp = _evaluate_quality_latency(base_ev, cand_ev, missing_joins)

    if (
        failed_caps
        or violated_excl
        or disconnected
        or (solver_comp and solver_comp.verdict in ("disconnected_objective_channel", "invariant_violation"))
        or ql_comp.status in ("faster_but_degraded_quality", "degraded_quality")
    ):
        verdict = "failed_regression"
    elif ql_comp.status == "latency_only_quality_unscored":
        verdict = "inconclusive_missing_quality_evidence"
    elif non_git_drift and not bool(_pick(raw_item, "intentional_non_git_change", default=False)):
        verdict = "non_git_drift_requires_review"
    elif solver_comp and solver_comp.verdict == "equivalent_valid_alternatives":
        verdict = "equivalent_valid_alternatives"
    else:
        verdict = "preserved_and_verified"

    dedup_missing = list(dict.fromkeys(missing_joins))
    summary = _build_preservation_summary(
        verdict=verdict,
        failed_caps=failed_caps,
        violated_excl=violated_excl,
        disconnected=disconnected,
        non_git_factors=non_git_factors,
        git_unchanged=git_unchanged,
        solver_comp=solver_comp,
        ql_comp=ql_comp,
    )
    ref = UnderstandingReference(
        ref_id=f"ref:preservation:{cid}",
        subject_id=cid,
        source_revision=cand_rev,
        evidence_producer=producer,
        claim_kind="demonstrated_effect" if verdict in ("preserved_and_verified", "equivalent_valid_alternatives") else "recorded_selection",
        observed_at=_pick(cand_ev, "observed_at"),
        coverage_state="complete" if not dedup_missing and verdict != "inconclusive_missing_quality_evidence" else "partial",
        result_summary=summary,
        authority_ref=issue_ref,
        missing_joins=dedup_missing,
    )
    return PreservationContractEvaluation(
        contract_id=cid,
        desired_change=desired,
        issue_or_decision_ref=issue_ref,
        baseline_revision=base_rev,
        candidate_revision=cand_rev,
        git_code_unchanged=git_unchanged,
        non_git_semantic_drift_detected=non_git_drift,
        changed_non_git_factors=non_git_factors,
        lane_checks=lane_checks,
        failed_preserved_capabilities=failed_caps,
        violated_exclusions=violated_excl,
        disconnected_penalty_channels=disconnected,
        solver_comparison=solver_comp,
        quality_latency=ql_comp,
        verdict=verdict,  # type: ignore[arg-type]
        summary=summary,
        missing_joins=dedup_missing,
        reference=ref,
    )


def _evaluate_solver_comparison(
    base_ev: Mapping[str, Any],
    cand_ev: Mapping[str, Any],
    disconnected: Sequence[str],
) -> SolverSemanticComparison | None:
    b_sol = _pick(base_ev, "solver_run", "solver")
    c_sol = _pick(cand_ev, "solver_run", "solver")
    if not isinstance(b_sol, Mapping) or not isinstance(c_sol, Mapping):
        return None
    raw_eq = bool(
        _pick(
            c_sol,
            "raw_schedule_equal",
            default=(
                _pick(b_sol, "assignments_digest", "raw_assignments")
                == _pick(c_sol, "assignments_digest", "raw_assignments")
            ),
        )
    )
    hard_ok = bool(_pick(b_sol, "hard_constraints_valid", default=True)) and bool(
        _pick(c_sol, "hard_constraints_valid", default=True)
    )
    pol_eq = _pick(b_sol, "admitted_policy_digest") == _pick(c_sol, "admitted_policy_digest")
    bind_eq = _pick(b_sol, "selected_bindings") == _pick(c_sol, "selected_bindings")
    locked_ok = bool(
        _pick(
            c_sol,
            "locked_facts_preserved",
            default=(_pick(b_sol, "locked_facts_digest") == _pick(c_sol, "locked_facts_digest")),
        )
    )
    complete_ok = bool(_pick(c_sol, "candidate_complete", default=True))
    exp_eq = _pick(b_sol, "export_semantic_digest", "export_meaning") == _pick(
        c_sol, "export_semantic_digest", "export_meaning"
    )
    b_obj_raw = _pick(b_sol, "total_objective", "objective_value")
    c_obj_raw = _pick(c_sol, "total_objective", "objective_value")
    b_obj = float(b_obj_raw) if isinstance(b_obj_raw, (int, float)) else None
    c_obj = float(c_obj_raw) if isinstance(c_obj_raw, (int, float)) else None

    b_ch = {str(x) for x in (_pick(b_sol, "active_objective_channels", default=[]) or [])}
    c_ch_raw = _pick(c_sol, "active_objective_channels")
    disc = list(disconnected)
    if c_ch_raw is not None:
        disc = sorted(set(disc) | (b_ch - {str(x) for x in c_ch_raw}))

    if disc:
        verdict = "disconnected_objective_channel"
        note = (
            f"Penalty channel(s) {disc} disconnected from solver objective; a lower raw objective "
            "value does NOT prove a better schedule."
        )
    elif not (hard_ok and locked_ok and complete_ok):
        verdict = "invariant_violation"
        note = "Solver candidate violated hard constraints, locked facts, or completeness."
    elif pol_eq and bind_eq and exp_eq:
        if raw_eq:
            verdict = "identical_valid_solution"
            note = "Identical schedule grid and invariants."
        else:
            verdict = "equivalent_valid_alternatives"
            note = (
                "Raw assignments differ across symmetric valid solutions, while hard rules, "
                "admitted policy, selected bindings, locked facts, and export meaning all hold."
            )
    else:
        verdict = "semantic_change_verified"
        note = "Hard invariants hold with verified policy/binding/export delta."

    return SolverSemanticComparison(
        raw_schedule_equal=raw_eq,
        hard_constraints_valid=hard_ok,
        admitted_policy_equal=pol_eq,
        selected_bindings_equal=bind_eq,
        locked_facts_preserved=locked_ok,
        candidate_complete=complete_ok,
        disconnected_penalty_channels=disc,
        export_meaning_equal=exp_eq,
        baseline_objective=b_obj,
        candidate_objective=c_obj,
        verdict=verdict,  # type: ignore[arg-type]
        note=note,
    )


def _evaluate_quality_latency(
    base_ev: Mapping[str, Any],
    cand_ev: Mapping[str, Any],
    missing_joins: list[str],
) -> QualityLatencyComparison:
    b_lat_r = _pick(base_ev, "latency_ms")
    c_lat_r = _pick(cand_ev, "latency_ms")
    b_q_r = _pick(base_ev, "quality_score", "grounded_answer_score", "accuracy_score")
    c_q_r = _pick(cand_ev, "quality_score", "grounded_answer_score", "accuracy_score")
    b_lat = float(b_lat_r) if isinstance(b_lat_r, (int, float)) else None
    c_lat = float(c_lat_r) if isinstance(c_lat_r, (int, float)) else None
    b_q = float(b_q_r) if isinstance(b_q_r, (int, float)) else None
    c_q = float(c_q_r) if isinstance(c_q_r, (int, float)) else None
    static_only = bool(_pick(cand_ev, "static_schema_budget_only", default=False))
    scored_flag = _pick(cand_ev, "answer_quality_scored")
    scored = bool(scored_flag) if scored_flag is not None else (b_q is not None and c_q is not None)

    if b_lat is None and c_lat is None and b_q is None and c_q is None and not static_only:
        return QualityLatencyComparison()

    faster = b_lat is not None and c_lat is not None and c_lat < b_lat
    if scored and b_q is not None and c_q is not None:
        if c_q < b_q:
            status = "faster_but_degraded_quality" if faster else "degraded_quality"
            note = (
                f"Candidate is faster ({c_lat}ms vs {b_lat}ms) but answer grounding/quality degraded "
                f"({c_q} < {b_q}); 1D speed improvement rejected."
                if faster
                else f"Candidate answer grounding/quality degraded ({c_q} < {b_q})."
            )
        else:
            status = "quality_maintained_or_improved"
            note = f"Grounded answer quality maintained/improved ({b_q} -> {c_q})."
    else:
        status = "latency_only_quality_unscored"
        missing_joins.append("measured_grounded_answer_quality_evaluation")
        note = (
            "Latency or static schema budget was recorded without measured answer-grounding quality; "
            "microbenchmarks and token budgets cannot establish equivalent user experience."
        )
    return QualityLatencyComparison(
        baseline_latency_ms=b_lat,
        candidate_latency_ms=c_lat,
        baseline_quality_score=b_q,
        candidate_quality_score=c_q,
        answer_quality_scored=scored,
        static_budget_only=static_only,
        status=status,  # type: ignore[arg-type]
        note=note,
    )


def _build_preservation_summary(
    *,
    verdict: str,
    failed_caps: Sequence[str],
    violated_excl: Sequence[str],
    disconnected: Sequence[str],
    non_git_factors: Sequence[str],
    git_unchanged: bool,
    solver_comp: SolverSemanticComparison | None,
    ql_comp: QualityLatencyComparison,
) -> str:
    details: list[str] = [f"Preservation verdict: {verdict}."]
    if failed_caps:
        details.append(f"Lost preserved lane capabilities: {list(failed_caps)}.")
    if violated_excl:
        details.append(f"Violated boundary exclusions: {list(violated_excl)}.")
    if disconnected:
        details.append(f"Disconnected objective penalty channels: {list(disconnected)}.")
    if git_unchanged and non_git_factors:
        details.append(f"Unchanged Git commit with non-Git semantic drift: {list(non_git_factors)}.")
    if solver_comp is not None and solver_comp.note:
        details.append(solver_comp.note)
    if ql_comp.note:
        details.append(ql_comp.note)
    return " ".join(details)


def evaluate_documentation_claims(
    raw_items: Sequence[Mapping[str, Any]],
    *,
    current_revision: str,
    current_digest: str | None = None,
    live_defined_symbols: Collection[str] = (),
) -> list[DocumentationClaimEvaluation]:
    """Case 12: Flag stale doc headers & invalidated prior explanations (`historical_needs_revalidation`)."""
    results: list[DocumentationClaimEvaluation] = []
    live_syms = set(live_defined_symbols)
    for idx, item in enumerate(raw_items):
        cid = str(_pick(item, "claim_id", "id", default=f"doc-claim-{idx + 1}"))
        doc_path = str(_pick(item, "document_or_note_path", "path", "source_file", default="unknown_doc"))
        claim_rev = str(_pick(item, "claim_revision", "pinned_revision", default="historical"))
        claim_dig = _pick(item, "claim_digest", "pinned_digest")
        hist_claim = str(_pick(item, "historical_claim", "claim_text", default=""))
        upd_ref = _pick(item, "owning_update_ref", "superseded_by")
        upd_sum = _pick(item, "owning_update_summary")
        expected_syms = [
            str(s) for s in (_pick(item, "implemented_symbols_found", "code_symbols", default=[]) or [])
        ]
        found_syms = sorted(set(expected_syms) | (live_syms & set(_pick(item, "check_symbols", default=[]) or [])))
        rem_phases = [str(p) for p in (_pick(item, "unverified_remaining_phases", default=[]) or [])]
        claims_unimplemented = bool(
            _pick(item, "claims_unimplemented", default=("not implemented" in hist_claim.lower()))
        )
        source_changed = bool(
            _pick(item, "source_or_evidence_changed", default=False)
            or (claim_rev not in ("historical", "unpinned", current_revision) and current_revision != "unpinned")
            or (claim_dig and current_digest and claim_dig != current_digest)
        )
        contradicted = (claims_unimplemented and bool(found_syms)) or bool(upd_ref) or source_changed
        cur_ev = str(
            _pick(
                item,
                "current_code_evidence",
                default=(
                    f"Current revision '{current_revision}' implements {found_syms}."
                    if found_syms
                    else f"Evaluated against current revision '{current_revision}'."
                ),
            )
        )
        if contradicted:
            status: Literal["current_and_corroborated", "historical_needs_revalidation", "unverified_claim"] = (
                "historical_needs_revalidation"
            )
            safe = False
            missing = ["revalidate_explanation_against_current_revision"]
        elif found_syms or bool(_pick(item, "corroborated", default=False)):
            status = "current_and_corroborated"
            safe = True
            missing = []
        else:
            status = "unverified_claim"
            safe = False
            missing = ["code_or_runtime_corroboration_for_doc_claim"]

        ref = UnderstandingReference(
            ref_id=f"ref:doc:{cid}",
            subject_id=doc_path,
            source_revision=claim_rev,
            evidence_producer=str(_pick(item, "evidence_producer", default="wythe.documentation_audit")),
            claim_kind="historical_explanation" if status == "historical_needs_revalidation" else "source_inference",
            observed_at=_pick(item, "observed_at"),
            coverage_state="historical_invalidated" if status == "historical_needs_revalidation" else "partial",
            result_summary=(
                f"{doc_path} ({claim_rev} -> {current_revision}): {status}. "
                f"Historical claim preserved; current evidence: {cur_ev}"
            ),
            source_location=doc_path,
            authority_ref=upd_ref,
            missing_joins=missing,
        )
        results.append(
            DocumentationClaimEvaluation(
                claim_id=cid,
                document_or_note_path=doc_path,
                claim_revision=claim_rev,
                current_revision=current_revision,
                historical_claim=hist_claim,
                owning_update_ref=upd_ref,
                owning_update_summary=upd_sum,
                current_code_evidence=cur_ev,
                implemented_symbols_found=found_syms,
                unverified_remaining_phases=rem_phases,
                status=status,
                safe_for_current_guidance=safe,
                reference=ref,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Six-Link Chain Synthesis, Live Scan Bridge & Example Dispatch
# ---------------------------------------------------------------------------

_NON_CERTIFICATION_NOTICE = (
    "Read-only understanding view over static source and imported producer receipts only — "
    "NOT an automated security audit, policy authority, runtime health controller, or "
    "production deployment certification (target_code_executed=False)."
)


def _load_session_corrections(session_id: str | None) -> list[AttachedHumanCorrection]:
    """Optionally bridge human corrections from Wave 5 `investigation_service` when present."""
    if not session_id:
        return []
    try:
        from app.services import investigation_service  # type: ignore[attr-defined]

        getter = getattr(investigation_service, "get_investigation_session", None)
        if callable(getter):
            sess = getter(session_id)
            raw_corrs = getattr(sess, "corrections", None) or []
            out: list[AttachedHumanCorrection] = []
            for idx, c in enumerate(raw_corrs):
                cid = str(getattr(c, "correction_id", None) or getattr(c, "id", f"corr-{idx + 1}"))
                out.append(
                    AttachedHumanCorrection(
                        correction_id=cid,
                        actor=str(getattr(c, "actor", "human")),
                        target_ref_id=getattr(c, "target_ref_id", None),
                        kind=str(getattr(c, "kind", "expectation_clarification")),
                        note=str(getattr(c, "note", "")),
                        recorded_at=(
                            str(getattr(c, "created_at", "")) if getattr(c, "created_at", None) else None
                        ),
                        evidence_revision=getattr(c, "evidence_revision_id", None),
                        promoted_to_policy=False,
                    )
                )
            return out
    except Exception:  # noqa: BLE001 - optional cross-slice lookup must fail closed/empty
        return []
    return []


def _synthesize_six_links(
    *,
    question: str,
    evidence_revision: str,
    intent_meta: Mapping[str, Any],
    authority_items: Sequence[EffectiveAuthorityExplanation],
    provenance_items: Sequence[RuntimeProvenanceEvaluation],
    outcomes: Sequence[OutcomeLifecycleExplanation],
    preservations: Sequence[PreservationContractEvaluation],
    doc_claims: Sequence[DocumentationClaimEvaluation],
    corrections: Sequence[AttachedHumanCorrection],
) -> tuple[list[UnderstandingChainLink], str, str, list[str]]:
    # 1. Intent
    intent_ref_id = str(_pick(intent_meta, "intent_id", "issue_ref", default="intent:primary"))
    intent_summary = str(
        _pick(
            intent_meta,
            "summary",
            "desired_behavior",
            default=f"Investigate question: {question}",
        )
    )
    if corrections:
        intent_summary += (
            f" ({len(corrections)} attached human correction(s) recorded as working context; "
            "not silently promoted to policy.)"
        )
    intent_ref = UnderstandingReference(
        ref_id=f"ref:{intent_ref_id}",
        subject_id=intent_ref_id,
        source_revision=evidence_revision,
        evidence_producer=str(_pick(intent_meta, "producer", default="wythe.investigation_intent")),
        claim_kind="recorded_selection",
        coverage_state="complete" if _pick(intent_meta, "summary", "desired_behavior") else "partial",
        result_summary=intent_summary,
        authority_ref=_pick(intent_meta, "authority_ref", "issue_ref"),
        missing_joins=[],
    )
    link1 = UnderstandingChainLink(
        link_key="intent",
        stage_index=1,
        label="1. Intent & Expected Invariants",
        state="supported",
        consequence_summary=intent_summary,
        evidence_limit="Human corrections clarify expectations on this investigation without mutating policy.",
        references=[intent_ref],
        missing_joins=[],
    )

    # 2. Effective Policy / Context
    auth_missing = list(dict.fromkeys(m for a in authority_items for m in a.missing_joins))
    if not authority_items:
        auth_state: ChainLinkState = "unresolved"
        auth_sum = "No effective policy or capability-lane selection evidence supplied."
        auth_missing.append("effective_policy_or_capability_selection_evidence")
    elif any(a.evidence_state == "bypassed" or a.orphan_penalty_channels for a in authority_items):
        auth_state = "degraded_or_drifted"
        auth_sum = " ".join(a.summary for a in authority_items)
    elif any(a.evidence_state == "unresolved" for a in authority_items):
        auth_state = "unresolved"
        auth_sum = " ".join(a.summary for a in authority_items)
    elif any(a.evidence_state in ("recorded_selection", "source_inference") for a in authority_items):
        auth_state = "unverified" if all(a.evidence_state == "source_inference" for a in authority_items) else "supported"
        auth_sum = " ".join(a.summary for a in authority_items)
    else:
        auth_state = "supported"
        auth_sum = " ".join(a.summary for a in authority_items)
    link2 = UnderstandingChainLink(
        link_key="effective_policy_context",
        stage_index=2,
        label="2. Effective Policy / Context",
        state=auth_state,
        consequence_summary=auth_sum,
        evidence_limit="Displays domain selection & AST/receipt evidence; Wythe never invents precedence.",
        references=[a.reference for a in authority_items],
        missing_joins=auth_missing,
    )

    # 3. Execution & Runtime Provenance
    prov_missing = list(dict.fromkeys(m for p in provenance_items for m in p.missing_joins))
    if not provenance_items:
        prov_state: ChainLinkState = "unverified"
        prov_sum = "No runtime provenance receipt supplied; source inspection does not establish running process state."
        prov_missing.append("source_to_running_process_provenance_receipt")
    elif any(p.overall_status != "aligned_within_observed_scope" for p in provenance_items):
        prov_state = "degraded_or_drifted"
        prov_sum = " ".join(p.summary for p in provenance_items)
    else:
        prov_state = "supported"
        prov_sum = " ".join(p.summary for p in provenance_items)
    link3 = UnderstandingChainLink(
        link_key="execution",
        stage_index=3,
        label="3. Execution & Runtime Provenance",
        state=prov_state,
        consequence_summary=prov_sum,
        evidence_limit="Startup import closures exclude post-startup dynamic imports and browser assets; never a generic 'verified' badge.",
        references=[p.reference for p in provenance_items],
        missing_joins=prov_missing,
    )

    # 4. Committed Result & 5. Human-Visible Result
    out_missing = list(dict.fromkeys(m for o in outcomes for m in o.missing_joins))
    has_indeterminate_retry_ban = any(
        o.settlement_state == "indeterminate_requires_settlement" or o.blind_retry_prohibited
        for o in outcomes
    )
    if not outcomes:
        comm_state: ChainLinkState = "unverified"
        comm_sum = "No transaction, execution, or acceptance settlement receipt supplied."
        vis_state: ChainLinkState = "unresolved"
        vis_sum = "Human-visible delivery, rendered card, or exported workbook lineage is unrecorded."
        out_missing.append("committed_and_human_visible_outcome_receipts")
    else:
        if has_indeterminate_retry_ban:
            comm_state = "unresolved"
        elif any(o.settlement_state == "settled_aborted" for o in outcomes):
            comm_state = "degraded_or_drifted"
        elif any(o.current_stage in ("declared", "granted_not_executed", "candidate_sealed") for o in outcomes):
            comm_state = "unverified"
        else:
            comm_state = "supported"
        comm_sum = " ".join(
            f"{o.outcome_id}: stage='{o.current_stage}'"
            + (
                f" (producer claimed '{o.producer_claimed_stage}')"
                if o.producer_claimed_stage and o.producer_claimed_stage != o.current_stage
                else ""
            )
            + f", settlement='{o.settlement_state}'."
            + (
                " Settlement is indeterminate and blind write retries are prohibited until "
                f"authoritative terminal state is reconciled. {o.retry_guidance}"
                if o.blind_retry_prohibited
                else ""
            )
            for o in outcomes
        )
        if has_indeterminate_retry_ban:
            vis_state = "unresolved"
        elif all(
            o.current_stage == "delivered_to_human"
            and o.answer_grounding in ("grounded", "not_applicable")
            for o in outcomes
        ):
            vis_state = "supported"
        elif any(
            o.current_stage
            in ("executed_missing_followup_grounding", "supplied_answer_unrecorded", "queued_not_rendered")
            for o in outcomes
        ):
            vis_state = "unverified"
        else:
            vis_state = "unresolved"
        vis_sum = " ".join(
            f"{o.outcome_id}: grounding='{o.answer_grounding}', delivery='{o.delivery_status}'."
            for o in outcomes
        )

    link4 = UnderstandingChainLink(
        link_key="committed_result",
        stage_index=4,
        label="4. Committed Result & Settlement",
        state=comm_state,
        consequence_summary=comm_sum,
        evidence_limit="Sealed candidates are not accepted schedules; lost replies forbid blind write retries before lock settlement.",
        references=[o.reference for o in outcomes],
        missing_joins=[
            m
            for m in out_missing
            if "settlement" in m
            or "acceptance" in m
            or "execution" in m
            or "predecessor" in m
            or "proximity" in m
            or "retry" in m
            or "reconciliation" in m
        ],
    )
    link5 = UnderstandingChainLink(
        link_key="human_visible_result",
        stage_index=5,
        label="5. Human-Visible Result & Delivery",
        state=vis_state,
        consequence_summary=vis_sum,
        evidence_limit="Tool execution and follow-up prompt inclusion do not certify answer grounding, authorship, or screen rendering.",
        references=[o.reference for o in outcomes],
        missing_joins=[m for m in out_missing if m not in link4.missing_joins],
    )

    # 6. Preservation Evidence & Documentation Freshness
    pres_missing = list(
        dict.fromkeys(
            [m for pr in preservations for m in pr.missing_joins]
            + [m for dc in doc_claims for m in dc.reference.missing_joins]
        )
    )
    has_stale_doc = any(dc.status == "historical_needs_revalidation" for dc in doc_claims)
    if any(pr.verdict == "failed_regression" for pr in preservations):
        pres_state: ChainLinkState = "regression_detected"
    elif has_stale_doc:
        pres_state = "historical_needs_revalidation"
    elif any(pr.verdict in ("non_git_drift_requires_review", "inconclusive_missing_quality_evidence") for pr in preservations):
        pres_state = "degraded_or_drifted"
    elif preservations:
        pres_state = "supported"
    else:
        pres_state = "unverified"
        pres_missing.append("caller_lane_and_semantic_preservation_contract")

    pres_parts = [pr.summary for pr in preservations] + [
        f"Doc/note '{dc.document_or_note_path}' is '{dc.status}' (historical claim preserved; unsafe as current guidance)."
        for dc in doc_claims
        if dc.status == "historical_needs_revalidation"
    ]
    link6 = UnderstandingChainLink(
        link_key="preservation_evidence",
        stage_index=6,
        label="6. Preservation & Historical Freshness",
        state=pres_state,
        consequence_summary=" ".join(pres_parts) if pres_parts else "No baseline-vs-candidate preservation evidence supplied.",
        evidence_limit="Compares caller-lane matrices and semantic invariants; stale docs/explanations remain historical.",
        references=[*(pr.reference for pr in preservations), *(dc.reference for dc in doc_claims)],
        missing_joins=pres_missing,
    )

    links = [link1, link2, link3, link4, link5, link6]
    overall_missing = list(dict.fromkeys(m for lnk in links for m in lnk.missing_joins))

    # Determine last supported cause before the first degraded/unverified/unresolved boundary
    last_supported = link1.consequence_summary
    first_gap_link: UnderstandingChainLink | None = None
    for lnk in links:
        if lnk.state == "supported":
            last_supported = f"[{lnk.label}] {lnk.consequence_summary}"
        elif first_gap_link is None:
            first_gap_link = lnk

    if has_indeterminate_retry_ban:
        proven_stages = ", ".join(
            dict.fromkeys(
                o.last_proven_stage
                for o in outcomes
                if o.settlement_state == "indeterminate_requires_settlement" or o.blind_retry_prohibited
            )
        )
        last_supported = (
            f"{last_supported} (Boundary before unresolved commit: last proven outcome "
            f"stage='{proven_stages}'; settlement is indeterminate and blind write retries are "
            "prohibited until authoritative terminal state is reconciled.)"
        )

    headline = (
        f"Chain break/qualification at {first_gap_link.label} ({first_gap_link.state}): "
        f"{first_gap_link.consequence_summary}"
        if first_gap_link is not None
        else f"All six understanding links supported within declared evidence boundaries for: {question}"
    )
    if has_indeterminate_retry_ban and "blind write retries are prohibited" not in headline.lower():
        headline = (
            f"{headline} [{link4.label} ({link4.state})] Settlement is indeterminate "
            "(indeterminate_requires_settlement) and blind write retries are prohibited until "
            "authoritative terminal state is reconciled."
        )
    return links, headline, last_supported, overall_missing


def _extract_report_authority_items(
    scan_report: Any,
    *,
    focus_id: str | None = None,
) -> list[dict[str, Any]]:
    """Derive static `PolicyFieldConsumption` authority items from a live `TruthAtlasReport`."""
    items: list[dict[str, Any]] = []
    node_map = {n.id: n for n in getattr(scan_report, "nodes", ())}
    resolved_focus_ids: set[str] = {focus_id} if focus_id else set()
    for f in getattr(scan_report, "findings", ()):
        if focus_id and getattr(f, "id", None) == focus_id:
            if getattr(f, "node_id", None):
                resolved_focus_ids.add(str(f.node_id))
            if getattr(f, "target_node_id", None):
                resolved_focus_ids.add(str(f.target_node_id))

    for edge in getattr(scan_report, "edges", ()):
        pfc = getattr(edge, "policy_field_consumption", None) or getattr(
            edge, "policy_consumption", None
        )
        if pfc is None:
            continue
        if resolved_focus_ids and not (
            {edge.id, edge.source_id, edge.target_id} & resolved_focus_ids
        ):
            continue
        src_node = node_map.get(edge.source_id)
        tgt_node = node_map.get(edge.target_id)
        eff_state = (
            "bypassed"
            if pfc.state == "bypassed"
            else "unresolved"
            if pfc.state == "unresolved"
            else "source_inference"
        )
        items.append(
            {
                "item_id": f"{edge.source_id}->{edge.target_id}",
                "label": f"{getattr(tgt_node, 'label', edge.target_id)} read by {getattr(src_node, 'label', edge.source_id)}",
                "owner": getattr(tgt_node, "label", edge.target_id),
                "legitimate_editor": "persisted_catalog_table",
                "source_revision": getattr(scan_report, "source_commit", "unpinned"),
                "evidence_producer": "wythe.python_policy_consumption",
                "source_location": getattr(edge, "evidence_path", None),
                "candidate_bindings": [
                    {
                        "binding_id": f"table:{edge.target_id}",
                        "source_kind": "db_table_column",
                        "scope_label": "static_schema",
                        "value": list(pfc.policy_columns),
                        "disposition": "selected_winner",
                        "reason": "Declared on Tier-1 policy table",
                    }
                ],
                "consumer_effects": [
                    {
                        "consumer_id": edge.source_id,
                        "stage": "manipulator_static_ast",
                        "effect_state": eff_state,
                        "mechanism": pfc.mechanism,
                        "reached_compiled_input": pfc.state == "consumed",
                        "source_location": getattr(edge, "evidence_path", None),
                        "note": pfc.note,
                    }
                ],
                "evidence_state": eff_state,
            }
        )
    return items


def analyze_understanding_bundle(
    request: UnderstandingAnalyzeRequest | Mapping[str, Any],
    *,
    db: Any | None = None,
) -> UnderstandingChainReport:
    """Analyze an uploaded/referenced bundle, shipped example, or registered target."""
    req = (
        request
        if isinstance(request, UnderstandingAnalyzeRequest)
        else UnderstandingAnalyzeRequest.model_validate(request)
    )
    eval_ts = req.observed_at or utc_now().isoformat()
    focus_id = req.subject_id or req.node_id or req.finding_id or req.edge_id

    raw_bundle: dict[str, Any] = {}
    live_scan: Any | None = None
    repo_root: Path | None = None

    # 1. Resolve registered target scan & optional `.wythe/understanding_bundle.json`
    if db is not None and req.target_slug:
        from app.services.governance_service import get_target_by_slug
        from app.services.scanner_service import run_target_scan

        target = get_target_by_slug(db, req.target_slug)
        if target is not None:
            repo_root = Path(target.repo_path).resolve()
            live_scan = run_target_scan(db, target, strict_gate=False, persist_snapshot=False)
            default_companion = repo_root / ".wythe" / "understanding_bundle.json"
            if req.bundle is None and req.bundle_path is None and default_companion.is_file():
                raw_bundle = read_understanding_bundle_file(default_companion, root_dir=repo_root)

    # 2. Resolve explicit example_slug (or fallback when target_slug names a shipped example)
    chosen_example = req.example_slug
    if (
        not chosen_example
        and not raw_bundle
        and req.bundle is None
        and req.bundle_path is None
        and req.target_slug in ("schedule-policy-to-export", "assistant-context-to-delivery")
    ):
        chosen_example = req.target_slug
    if chosen_example and not raw_bundle and req.bundle is None and req.bundle_path is None:
        from wythe_examples.understanding_examples import get_example_bundle_dict

        raw_bundle = get_example_bundle_dict(chosen_example)

    # 3. Explicit bundle_path or inline bundle overrides
    if req.bundle_path:
        raw_bundle = read_understanding_bundle_file(req.bundle_path, root_dir=repo_root)
    if req.bundle is not None:
        _check_json_depth(req.bundle)
        raw_bundle = dict(req.bundle)

    live_rev: str | None = None
    live_digest: str | None = None
    if live_scan is not None:
        sc = str(getattr(live_scan, "source_commit", "") or "")
        live_digest = str(getattr(live_scan, "content_digest", "") or "")
        live_rev = (
            f"non_git:{live_digest[:16]}"
            if (not sc or sc in ("unknown", "unavailable", "uncommitted", "non_git")) and live_digest
            else sc
        )

    bundle_rev = str(
        _pick(
            raw_bundle,
            "source_revision",
            "evidence_revision",
            "repo_revision",
            default=live_rev or "unpinned",
        )
    )
    effective_rev = live_rev or bundle_rev
    question = str(
        req.question
        or _pick(raw_bundle, "question", default=None)
        or (f"Explain outcome and authority lineage for '{focus_id}'" if focus_id else "Explain system outcome, authority, and preservation chain")
    )

    raw_auth_list = list(
        _pick(raw_bundle, "effective_authority", "policy_records", "authority_items", default=[]) or []
    )
    if live_scan is not None and not raw_auth_list:
        raw_auth_list = _extract_report_authority_items(live_scan, focus_id=focus_id)

    raw_prov_list = list(
        _pick(raw_bundle, "runtime_provenance", "runtime_records", "running_versions", default=[]) or []
    )
    raw_out_list = list(
        _pick(raw_bundle, "outcome_lifecycles", "lifecycle_records", "outcomes", "request_journeys", default=[])
        or []
    )
    raw_pres_list = list(
        _pick(raw_bundle, "preservation_contracts", "preservation_evaluations", "comparisons", default=[])
        or []
    )
    raw_doc_list = list(
        _pick(raw_bundle, "documentation_claims", "doc_claims", "explanatory_notes", default=[]) or []
    )

    # Detect source/digest evolution invalidating a pinned prior explanation (Case 12)
    pinned_rev = req.prior_explanation_revision or _pick(raw_bundle, "pinned_explanation_revision")
    pinned_dig = _pick(raw_bundle, "pinned_content_digest")
    if (pinned_rev and pinned_rev != effective_rev and effective_rev != "unpinned") or (
        pinned_dig and live_digest and pinned_dig != live_digest
    ):
        raw_doc_list.append(
            {
                "claim_id": "prior-session-explanation",
                "document_or_note_path": f"investigation_explanation@{pinned_rev or pinned_dig[:12]}",
                "claim_revision": str(pinned_rev or bundle_rev),
                "claim_digest": pinned_dig,
                "historical_claim": str(
                    _pick(
                        raw_bundle,
                        "prior_explanation_summary",
                        default="Prior explanation recorded before source/evidence mutation.",
                    )
                ),
                "source_or_evidence_changed": True,
                "current_code_evidence": (
                    f"Repository/evidence advanced to revision '{effective_rev}'"
                    + (f" (digest {live_digest[:12]})" if live_digest else "")
                    + "; prior explanation is preserved as historical context and requires revalidation."
                ),
            }
        )

    authority_evals = [
        explain_effective_authority(item, default_revision=effective_rev, evaluation_time=eval_ts)
        for item in raw_auth_list
        if isinstance(item, Mapping)
    ]
    prov_evals = [
        evaluate_runtime_provenance(item, evaluation_time=eval_ts)
        for item in raw_prov_list
        if isinstance(item, Mapping)
    ]
    out_evals = [
        explain_outcome_lifecycle(item, default_revision=effective_rev)
        for item in raw_out_list
        if isinstance(item, Mapping)
    ]
    pres_evals = [
        evaluate_preservation_contract(item, default_revision=effective_rev)
        for item in raw_pres_list
        if isinstance(item, Mapping)
    ]
    doc_evals = evaluate_documentation_claims(
        [item for item in raw_doc_list if isinstance(item, Mapping)],
        current_revision=effective_rev,
        current_digest=live_digest,
    )

    # Human corrections (never silently promoted to policy!)
    corrections: list[AttachedHumanCorrection] = _load_session_corrections(req.session_id)
    for idx, rc in enumerate(
        [*(_pick(raw_bundle, "human_corrections", default=[]) or []), *req.human_corrections]
    ):
        if isinstance(rc, Mapping) and _pick(rc, "note"):
            corrections.append(
                AttachedHumanCorrection(
                    correction_id=str(_pick(rc, "correction_id", "id", default=f"corr-inline-{idx + 1}")),
                    actor=str(_pick(rc, "actor", default="human")),
                    target_ref_id=_pick(rc, "target_ref_id"),
                    kind=str(_pick(rc, "kind", default="expectation_clarification")),
                    note=str(_pick(rc, "note")),
                    recorded_at=_pick(rc, "recorded_at"),
                    evidence_revision=_pick(rc, "evidence_revision", default=effective_rev),
                    promoted_to_policy=False,
                )
            )

    intent_meta = _pick(raw_bundle, "intent", default={}) or {}
    links, headline, last_supported, overall_missing = _synthesize_six_links(
        question=question,
        evidence_revision=effective_rev,
        intent_meta=intent_meta if isinstance(intent_meta, Mapping) else {},
        authority_items=authority_evals,
        provenance_items=prov_evals,
        outcomes=out_evals,
        preservations=pres_evals,
        doc_claims=doc_evals,
        corrections=corrections,
    )
    cov_statement = (
        f"Evaluated {len(authority_evals)} authority item(s), {len(prov_evals)} provenance record(s), "
        f"{len(out_evals)} outcome lifecycle(s), {len(pres_evals)} preservation contract(s), and "
        f"{len(doc_evals)} documentation/explanation freshness check(s); "
        f"{len(overall_missing)} explicit missing join(s) preserved."
    )
    return UnderstandingChainReport(
        target_slug=req.target_slug,
        example_slug=chosen_example,
        session_id=req.session_id,
        question=question,
        selected_subject_id=focus_id,
        evidence_revision=effective_rev,
        evaluated_at=eval_ts,
        consequence_headline=headline,
        last_supported_cause=last_supported,
        overall_missing_joins=overall_missing,
        links=links,
        effective_authority=authority_evals,
        runtime_provenance=prov_evals,
        outcome_lifecycles=out_evals,
        preservation_evaluations=pres_evals,
        documentation_claims=doc_evals,
        human_corrections=corrections,
        coverage_statement=cov_statement,
        non_certification_notice=_NON_CERTIFICATION_NOTICE,
        target_code_executed=False,
        automated_security_audit=False,
    )


def list_understanding_examples() -> list[UnderstandingExampleSummary]:
    """Return catalog summaries for all shipped Wave 6 example investigations."""
    from wythe_examples.understanding_examples import list_shipped_understanding_examples

    return list_shipped_understanding_examples()


def get_understanding_example(example_slug: str) -> UnderstandingExampleRead:
    """Return a complete evaluated Wave 6 synthetic example investigation by slug."""
    from wythe_examples.understanding_examples import build_shipped_understanding_example

    return build_shipped_understanding_example(example_slug)


def compute_content_sha256(text: str) -> str:
    """Deterministic SHA-256 helper for synthetic fixture & receipt verification."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
