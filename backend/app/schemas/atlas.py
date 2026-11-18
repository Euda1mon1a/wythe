"""Strict response and request contracts for the 3-tier Truth Atlas."""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

TierKind = Literal["truth", "manipulate", "display"]
NodeSubkind = Literal[
    "table",
    "sql_function",
    "cache_store",
    "entity_store",
    "entitlement_spec",
    "route",
    "ipc_handler",
    "service",
    "ffi_shim",
    "solver",
    "cli",
    "page",
    "hook",
    "api_client",
    "component",
]
NodeStatus = Literal[
    "clean",
    "policy_in_code",
    "duplicated_truth",
    "gray_zone",
    "orphaned",
    "in_flight",
    "unwired",
]
EdgeKind = Literal[
    "reads_truth",
    "writes_truth",
    "guards_truth",
    "calls_helper",
    "queries_endpoint",
    "mutates_endpoint",
    "uses_hook",
    "uses_client",
]
VerificationState = Literal["verified", "declared", "unverified", "broken"]
PolicyConsumptionState = Literal["consumed", "bypassed", "unresolved"]
PolicyConsumptionMechanism = Literal[
    "field_controls_result",
    "constant_or_fallback_wins",
    "dynamic_or_opaque_flow",
]
FindingConfidence = Literal["confirmed", "candidate"]
EvidenceStrength = Literal["ast_exact", "structural_match", "heuristic"]
GateVerdict = Literal["PASS", "RATCHET_PASS", "INCOMPLETE", "FAIL"]
StoreIntendedUse = Literal[
    "derived_cache",
    "read_replica",
    "materialized_view",
    "historical_snapshot",
    "persistent_config",
    "ephemeral_state",
    "queue_buffer",
    "authoritative_store",
]


class StrictSchema(BaseModel):
    """Forbid undeclared fields across all API boundaries."""

    model_config = ConfigDict(extra="forbid")


class StorePurposeDeclaration(StrictSchema):
    """Declared copy/storage intent, kept distinct from static verification."""

    intended_use: StoreIntendedUse
    authoritative_source: str | None = None
    copy_reason: str | None = None
    refresh_policy: str | None = None
    recovery_expectation: str | None = None
    keyspace_scope: str | None = None
    verification_summary: str | None = None


class PolicyFieldConsumption(StrictSchema):
    """Per-edge or per-node static policy column consumption lineage."""

    state: PolicyConsumptionState
    mechanism: PolicyConsumptionMechanism
    reader_scopes: list[str] = Field(default_factory=list)
    policy_columns: list[str] = Field(default_factory=list)
    consumed_columns: list[str] = Field(default_factory=list)
    unconsumed_policy_columns: list[str] = Field(default_factory=list)
    substituted_constants: list[str] = Field(default_factory=list)
    fallback_constants: list[str] = Field(default_factory=list)
    note: str = ""


StratumZoom = Literal[1, 2, 3]
MicroStratumZoom = Literal[2, 3]


class StratumSummaryBadge(StrictSchema):
    """Compact Zoom-1 summary badge contributed by an optional `StratumPlugin`."""

    key: str
    label: str
    count: int = Field(default=0, ge=0)


class AtlasNode(StrictSchema):
    id: str
    tier: TierKind
    subkind: NodeSubkind
    label: str
    source_file: str
    line: int = 1
    status: NodeStatus = "clean"
    role: str = "mechanism"
    cluster: str = "core"
    summary: str
    columns: list[str] = Field(default_factory=list)
    policy_columns: list[str] = Field(default_factory=list)
    http_methods: list[str] = Field(default_factory=list)
    http_paths: list[str] = Field(default_factory=list)
    read_by_count: int = 0
    written_by_count: int = 0
    cutover_history: str | None = None
    ruling_summary: str | None = None
    ruling_audited_at: date | None = None
    store_purpose: StorePurposeDeclaration | None = None
    verification_note: str | None = None
    policy_field_consumption: PolicyFieldConsumption | None = None
    stratum_badges: list[StratumSummaryBadge] = Field(default_factory=list)


class AtlasEdge(StrictSchema):
    id: str
    source_id: str
    target_id: str
    kind: EdgeKind
    verification: VerificationState
    evidence_path: str | None = None
    evidence_note: str
    symbol_links: list[str] = Field(default_factory=list)
    policy_field_consumption: PolicyFieldConsumption | None = None


class EndToEndChain(StrictSchema):
    id: str
    display_node_id: str
    display_label: str
    via_node_ids: list[str] = Field(default_factory=list)
    http_method: str
    http_path: str
    route_node_id: str
    route_label: str
    manipulator_node_ids: list[str] = Field(default_factory=list)
    truth_table_ids: list[str] = Field(default_factory=list)
    truth_table_labels: list[str] = Field(default_factory=list)
    operation: Literal["read", "write"]
    verified: bool


class BoundaryFinding(StrictSchema):
    id: str
    rule_code: str
    tier: TierKind
    severity: str
    blocks_gate: bool
    confidence: FindingConfidence = "confirmed"
    evidence_strength: EvidenceStrength = "ast_exact"
    node_id: str | None = None
    target_node_id: str | None = None
    source_file: str
    line: int = 1
    title: str
    detail: str
    remediation: str


class LegacyReceiptItem(StrictSchema):
    node_id: str
    result: Literal["verified_present", "verified_absent", "changed", "error"]
    path: str
    note: str


class LegacyBridgeSummary(StrictSchema):
    present: bool
    snapshot_title: str | None = None
    audited_at: date | None = None
    snapshot_commit: str | None = None
    receipts_checked: int = 0
    receipts_verified: int = 0
    receipts_changed: int = 0
    receipts_error: int = 0
    curated_nodes_matched: int = 0
    cutover_reclassified_count: int = 0
    sample_receipts: list[LegacyReceiptItem] = Field(default_factory=list)


class RuleGateRow(StrictSchema):
    rule_code: str
    tier: TierKind
    title: str
    severity: str
    enabled: bool
    blocks_gate: bool
    observed_count: int
    baseline_max: int | None = None
    status: Literal["pass", "ratcheted", "exceeded", "disabled"]


class GateEvaluation(StrictSchema):
    verdict: GateVerdict
    mode: Literal["strict", "ratchet"]
    blocking_violations: int
    coverage_complete: bool = True
    ratchet_exceeded_rules: list[str] = Field(default_factory=list)
    rule_counts: list[RuleGateRow] = Field(default_factory=list)
    evaluated_at: datetime


class AtlasSummaryStats(StrictSchema):
    truth_tables: int
    sql_functions: int
    ephemeral_stores: int = 0
    manipulator_routes: int
    manipulator_services: int
    display_pages: int
    display_hooks_and_clients: int
    verified_edges: int
    end_to_end_chains: int
    clean_nodes: int
    flagged_nodes: int
    blocking_findings: int
    warning_findings: int


class AuditRulingRead(StrictSchema):
    id: int
    target_id: int
    node_id: str
    disposition: str
    summary: str
    cutover_history: str | None = None
    store_purpose: StorePurposeDeclaration | None = None
    evidence_scope: list[str] = Field(default_factory=list)
    audited_commit: str
    audited_at: date
    effective_from: date
    effective_until: date | None = None
    recorded_by: str
    created_at: datetime


class AuditRulingCreate(StrictSchema):
    node_id: str = Field(min_length=1, max_length=160)
    disposition: str = Field(min_length=1, max_length=48)
    summary: str = Field(min_length=1)
    cutover_history: str | None = None
    store_purpose: StorePurposeDeclaration | None = None
    evidence_scope: list[str] = Field(default_factory=list)
    recorded_by: str = Field(min_length=1, max_length=64)


class TruthAtlasReport(StrictSchema):
    snapshot_id: int | None = None
    target_slug: str
    target_name: str
    repo_path: str
    stack_profile: str
    stack_profile_status: Literal["implemented", "experimental", "planned"] = "implemented"
    coverage_complete: bool = True
    source_commit: str
    # The scan reads files from disk, so a dirty tree means `source_commit` alone does not
    # describe the scanned code. None outside git.
    worktree_dirty: bool | None = None
    dirty_path_count: int | None = None
    observed_at: datetime
    valid_until: datetime
    observation_source: str
    content_digest: str
    # Plain-language notes about what the scan could not check or how it decided.
    scan_notes: list[str] = Field(default_factory=list)
    summary: AtlasSummaryStats
    nodes: list[AtlasNode]
    edges: list[AtlasEdge]
    chains: list[EndToEndChain]
    findings: list[BoundaryFinding]
    gate: GateEvaluation
    legacy_bridge: LegacyBridgeSummary
    rulings: list[AuditRulingRead] = Field(default_factory=list)


class StackProfileRead(StrictSchema):
    slug: str
    label: str
    truth_adapter: str
    manipulator_adapter: str
    display_adapter: str
    implementation_status: str
    is_enabled: bool
    description: str


class AdapterSlotSchema(StrictSchema):
    name: str
    tier: TierKind
    language: str
    frameworks: list[str]
    implementation_status: Literal["implemented", "experimental", "planned"]
    capabilities: list[str]


class StackDetectionResult(StrictSchema):
    repo_path: str
    recommended_profile_slug: str
    truth_adapter: str
    manipulator_adapter: str
    display_adapter: str
    backend_subdir: str
    frontend_subdir: str
    confidence: Literal["high", "medium", "fallback"]
    coverage_complete: bool = True
    detected_signals: list[str] = Field(default_factory=list)


class TargetProjectRead(StrictSchema):
    id: int
    slug: str
    name: str
    repo_path: str
    stack_profile_slug: str
    backend_subdir: str
    frontend_subdir: str
    legacy_snapshot_relpath: str | None = None
    description: str
    is_active: bool


class TargetProjectCreate(StrictSchema):
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-_]*$")
    name: str = Field(min_length=1, max_length=128)
    repo_path: str = Field(min_length=1)
    stack_profile_slug: str = "fastapi-sqlalchemy-nextjs"
    backend_subdir: str = "backend"
    frontend_subdir: str = "frontend"
    legacy_snapshot_relpath: str | None = None
    description: str = ""
    created_by: str = "operator"


class RulePolicyRead(StrictSchema):
    rule_code: str
    tier: str
    category: str
    title: str
    rationale: str
    severity: str
    enabled: bool
    blocks_gate: bool
    effective_from: date
    effective_until: date | None = None
    updated_by: str
    updated_at: datetime


class RulePolicyUpdate(StrictSchema):
    severity: str | None = None
    enabled: bool | None = None
    blocks_gate: bool | None = None
    updated_by: str = Field(min_length=1, max_length=64)


class RatchetBaselineRead(StrictSchema):
    rule_code: str
    max_allowed_count: int
    recorded_commit: str
    recorded_by: str
    recorded_at: datetime
    note: str


class RatchetCaptureRequest(StrictSchema):
    recorded_by: str = Field(min_length=1, max_length=64)
    note: str = "Captured current observed counts as downward-only ratchet ceiling."


class ScanSnapshotSummary(StrictSchema):
    id: int
    source_commit: str
    observation_source: str
    observed_at: datetime
    valid_until: datetime
    content_digest: str
    truth_node_count: int
    manipulator_node_count: int
    display_node_count: int
    verified_edge_count: int
    blocking_finding_count: int
    warning_finding_count: int


class PolicyVocabularyRead(StrictSchema):
    id: int
    domain_pack: str
    token: str
    description: str
    is_enabled: bool
    created_by: str
    created_at: datetime


class PolicyVocabularyCreate(StrictSchema):
    domain_pack: str = Field(
        default="custom", min_length=2, max_length=32, pattern=r"^[a-z0-9][a-z0-9-_]*$"
    )
    token: str = Field(min_length=2, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
    description: str = ""
    is_enabled: bool = True
    created_by: str = Field(default="operator", min_length=1, max_length=64)


class PolicyVocabularyUpdate(StrictSchema):
    description: str | None = None
    is_enabled: bool | None = None


class DiffBlastRadiusReport(StrictSchema):
    target_slug: str
    base_ref: str
    base_commit: str = ""
    base_graph_status: Literal["available", "not_needed", "unavailable"] = "unavailable"
    base_impacted_node_ids: list[str] = Field(default_factory=list)
    removed_nodes: list[AtlasNode] = Field(default_factory=list)
    analysis_notes: list[str] = Field(default_factory=list)
    head_commit: str
    commits_in_range: list[str] = Field(default_factory=list)
    changed_files: list[str] = Field(default_factory=list)
    touched_node_ids: list[str] = Field(default_factory=list)
    impacted_truth_nodes: list[str] = Field(default_factory=list)
    impacted_manipulator_nodes: list[str] = Field(default_factory=list)
    impacted_display_nodes: list[str] = Field(default_factory=list)
    impacted_chains: list[EndToEndChain] = Field(default_factory=list)
    new_findings: list[BoundaryFinding] = Field(default_factory=list)
    blocking_new_findings: int = 0
    diff_verdict: Literal["PASS", "FAIL", "INCOMPLETE"]


class SnapshotComparisonReport(StrictSchema):
    target_slug: str
    base_snapshot_id: int
    head_snapshot_id: int
    base_commit: str
    head_commit: str
    base_observed_at: datetime
    head_observed_at: datetime
    edge_delta: int
    chain_delta: int
    blocking_delta: int
    warning_delta: int
    added_nodes: list[AtlasNode] = Field(default_factory=list)
    removed_nodes: list[AtlasNode] = Field(default_factory=list)
    new_findings: list[BoundaryFinding] = Field(default_factory=list)
    resolved_findings: list[BoundaryFinding] = Field(default_factory=list)


class PortableRuleOverride(StrictSchema):
    rule_code: str
    severity: str
    enabled: bool
    blocks_gate: bool
    updated_by: str


class PortableVocabularyEntry(StrictSchema):
    domain_pack: str
    token: str
    description: str = ""
    is_enabled: bool = True


class PortableRatchetItem(StrictSchema):
    rule_code: str
    max_allowed_count: int
    recorded_commit: str
    recorded_by: str
    note: str = ""


class PortableRulingItem(StrictSchema):
    node_id: str
    disposition: str
    summary: str
    cutover_history: str | None = None
    store_purpose: StorePurposeDeclaration | None = None
    evidence_scope: list[str] = Field(default_factory=list)
    audited_commit: str
    recorded_by: str


class PortableReferenceExemplar(StrictSchema):
    title: str
    node_id: str | None = None
    pointer: str
    applies_to_tiers: list[TierKind] = Field(default_factory=list)
    applies_to_subkinds: list[NodeSubkind] = Field(default_factory=list)
    rationale: str
    approved_by: str | None = None


class PortableGovernanceBundle(StrictSchema):
    schema_version: str = "1.0"
    target_slug: str
    exported_at: datetime
    rule_overrides: list[PortableRuleOverride] = Field(default_factory=list)
    vocabularies: list[PortableVocabularyEntry] = Field(default_factory=list)
    ratchet_baselines: list[PortableRatchetItem] = Field(default_factory=list)
    audit_rulings: list[PortableRulingItem] = Field(default_factory=list)
    reference_exemplars: list[PortableReferenceExemplar] = Field(default_factory=list)


class GovernanceSyncReceipt(StrictSchema):
    target_slug: str
    direction: Literal["export", "import"]
    bundle_path: str
    rules_synced: int
    vocabularies_synced: int
    baselines_synced: int
    rulings_synced: int
    synced_at: datetime


class LlmBriefRead(StrictSchema):
    target_slug: str
    source_commit: str
    approx_tokens: int
    markdown: str


class LlmNodePointer(StrictSchema):
    id: str
    tier: TierKind
    subkind: NodeSubkind
    label: str
    pointer: str
    status: NodeStatus
    columns: list[str] = Field(default_factory=list)
    http_paths: list[str] = Field(default_factory=list)


class ConeEdgeSummary(StrictSchema):
    id: str
    source_id: str
    target_id: str
    kind: EdgeKind
    verification: VerificationState
    evidence_path: str | None = None
    evidence_note: str
    policy_field_consumption: PolicyFieldConsumption | None = None


class StratumMicroNode(StrictSchema):
    """Scoped Zoom-2 (IR/AIR) or Zoom-3 (binary/heap) microscope node."""

    id: str
    label: str
    kind: str
    zoom: MicroStratumZoom
    source_file: str | None = None
    line: int | None = None
    verification: VerificationState = "declared"
    summary: str = ""


class StratumMicroEdge(StrictSchema):
    """Scoped Zoom-2/Zoom-3 microscope edge with deterministic thunk compaction metadata."""

    id: str
    source_id: str
    target_id: str
    label: str = ""
    kind: str = "calls_ir"
    verification: VerificationState = "declared"
    collapsed_count: int = 0
    collapsed_samples: list[str] = Field(default_factory=list)
    evidence_note: str = ""


class StratumExpansionResult(StrictSchema):
    """Read-only Zoom-2/Zoom-3 subgraph emitted by a `StratumPlugin` for one parent node."""

    summary_badges: list[StratumSummaryBadge] = Field(default_factory=list)
    nodes: list[StratumMicroNode] = Field(default_factory=list)
    edges: list[StratumMicroEdge] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class StratumDrilldownRead(StrictSchema):
    """On-demand progressive LOD drill-down payload for a single parent Zoom-1 node."""

    target_slug: str
    parent_node_id: str
    zoom: MicroStratumZoom
    unfiltered_ir: bool = False
    summary_badges: list[StratumSummaryBadge] = Field(default_factory=list)
    nodes: list[StratumMicroNode] = Field(default_factory=list)
    edges: list[StratumMicroEdge] = Field(default_factory=list)
    raw_node_count: int = 0
    compacted_node_count: int = 0
    collapsed_thunk_count: int = 0
    active_plugins: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ConeSectionCount(StrictSchema):
    included: int = 0
    eligible: int = 0
    omitted: int = 0


class ConeCompleteness(StrictSchema):
    is_complete: bool = True
    full_export: bool = False
    node_budget: int = 0
    nodes: ConeSectionCount = Field(default_factory=ConeSectionCount)
    upstream_nodes: ConeSectionCount = Field(default_factory=ConeSectionCount)
    downstream_nodes: ConeSectionCount = Field(default_factory=ConeSectionCount)
    edges: ConeSectionCount = Field(default_factory=ConeSectionCount)
    markdown_edges: ConeSectionCount = Field(default_factory=ConeSectionCount)
    findings: ConeSectionCount = Field(default_factory=ConeSectionCount)
    seed_findings: ConeSectionCount = Field(default_factory=ConeSectionCount)
    chains: ConeSectionCount = Field(default_factory=ConeSectionCount)
    stratum_nodes: ConeSectionCount = Field(default_factory=ConeSectionCount)
    stratum_edges: ConeSectionCount = Field(default_factory=ConeSectionCount)
    truncation_reasons: list[str] = Field(default_factory=list)
    full_export_hint: str = ""


class LlmContextConeReport(StrictSchema):
    target_slug: str
    query: str
    source_commit: str
    worktree_dirty: bool | None = None
    dirty_path_count: int | None = None
    content_digest: str = ""
    zoom: StratumZoom = 1
    matched_seed_ids: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
    upstream_display_nodes: list[LlmNodePointer] = Field(default_factory=list)
    manipulator_nodes: list[LlmNodePointer] = Field(default_factory=list)
    downstream_truth_nodes: list[LlmNodePointer] = Field(default_factory=list)
    cone_edges: list[str] = Field(default_factory=list)
    cone_edge_items: list[ConeEdgeSummary] = Field(default_factory=list)
    matching_chains: list[EndToEndChain] = Field(default_factory=list)
    cone_findings: list[BoundaryFinding] = Field(default_factory=list)
    stratum_drilldowns: list[StratumDrilldownRead] = Field(default_factory=list)
    completeness: ConeCompleteness | None = None
    approx_tokens: int = 0
    markdown: str = ""


LineageConeSlice = LlmContextConeReport


class SourceSnippetLine(StrictSchema):
    line_number: int
    text: str
    is_focus: bool = False


class SourceSnippetRead(StrictSchema):
    target_slug: str
    rel_path: str
    abs_path: str
    focus_line: int
    start_line: int
    end_line: int
    total_lines: int
    language: str
    lines: list[SourceSnippetLine] = Field(default_factory=list)


EvidenceSourceKind = Literal["source_static", "compiled_artifact", "runtime_capture"]
EpistemicKind = Literal[
    "observation",
    "static_inference",
    "compiled_artifact",
    "runtime_capture",
    "model_interpretation",
    "suggested_action",
    "verified_result",
]
ReferenceSubjectKind = Literal["node", "edge", "finding", "snippet", "capture"]
ReferenceValidationState = Literal[
    "validated",
    "text_convenience",
    "vanished_in_current_scan",
    "historical_needs_revalidation",
    "unresolved",
]
InvestigationActor = Literal["human", "agent", "system"]
FollowState = Literal["following", "paused"]


class EvidenceSourceItem(StrictSchema):
    kind: EvidenceSourceKind
    producer: str
    freshness: str
    sampling_note: str = ""


class EvidenceIdentityRead(StrictSchema):
    evidence_revision_id: str
    snapshot_id: int | None = None
    source_commit: str
    content_tree_sha256: str | None = None
    worktree_dirty: bool | None = None
    dirty_path_count: int | None = None
    content_digest: str
    observed_at: datetime
    coverage_complete: bool = True
    stack_profile: str
    active_plugins: list[str] = Field(default_factory=list)
    evidence_sources: list[EvidenceSourceItem] = Field(default_factory=list)


class ValidatedReferenceRead(StrictSchema):
    ref_id: str
    kind: ReferenceSubjectKind
    label: str = ""
    source_file: str | None = None
    line: int | None = None
    evidence_revision_id: str
    validation_state: ReferenceValidationState
    epistemic_kind: EpistemicKind = "static_inference"
    producer: str = "wythe-scanner"
    note: str = ""


class ContextBudgetSummary(StrictSchema):
    included_counts: dict[str, int] = Field(default_factory=dict)
    omitted_counts: dict[str, int] = Field(default_factory=dict)
    truncated_sections: list[str] = Field(default_factory=list)
    prompt_chars: int = 0
    max_prompt_chars: int = 0
    expand_hint: str = ""


class InvestigationCorrectionRead(StrictSchema):
    correction_id: str
    session_id: str
    client_id: str | None = None
    actor: InvestigationActor = "human"
    target_ref_id: str | None = None
    turn_id: str | None = None
    kind: str = "disagreement"
    note: str
    evidence_revision_id: str | None = None
    promoted_to_ruling: bool = False
    created_at: datetime


class UiFocusStatePayload(StrictSchema):
    active_slug: str = Field(min_length=1, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    client_id: str | None = Field(default=None, max_length=128)
    actor: InvestigationActor = "human"
    active_tab: str = Field(default="3d", max_length=24)
    selected_node_id: str | None = Field(default=None, max_length=200)
    selected_edge_id: str | None = Field(default=None, max_length=200)
    selected_finding_id: str | None = Field(default=None, max_length=200)
    hovered_node_id: str | None = Field(default=None, max_length=200)
    focused_district: str | None = Field(default=None, max_length=80)
    follow_state: FollowState | None = None
    focus_revision: int | None = Field(default=None, ge=0)
    evidence_revision_id: str | None = Field(default=None, max_length=96)
    tier_filter: str = Field(default="all", max_length=24)
    subkind_filter: str = Field(default="all", max_length=32)
    edge_filter: str = Field(default="all", max_length=32)
    lens: str = Field(default="status", max_length=32)
    layout_mode: str = Field(default="cluster", max_length=24)
    blast_mode: str = Field(default="off", max_length=24)
    diff_base_ref: str = Field(default="HEAD~1", max_length=128)
    only_flagged: bool = False
    isolate_cone: bool = False
    connected_only: bool = False
    neighborhood_hops: Literal[0, 1, 2] = 0
    search_query: str = Field(default="", max_length=200)
    active_trace_route: str | None = Field(default=None, max_length=200)
    camera_position: str | None = Field(default=None, max_length=96)
    camera_target: str | None = Field(default=None, max_length=96)
    visible_node_count: int = Field(default=0, ge=0, le=50000)
    in_frustum_count: int = Field(default=0, ge=0, le=50000)
    visual_headline: str | None = Field(default=None, max_length=320)
    live_viewport_brief: str | None = Field(default=None, max_length=16000)
    camera_revision: int | None = Field(default=None, ge=0)
    snapshot_data_url: str | None = Field(default=None, max_length=8_500_000)


class UiFocusSyncAck(StrictSchema):
    active_slug: str
    session_id: str | None = None
    client_id: str | None = None
    actor: InvestigationActor = "human"
    follow_state: FollowState = "following"
    focus_revision: int = 0
    evidence_revision_id: str | None = None
    observed_at: datetime
    has_snapshot: bool
    snapshot_path: str | None = None
    snapshot_mime_type: str | None = None
    camera_revision: int | None = None
    snapshot_focus_revision: int | None = None
    snapshot_evidence_revision: str | None = None
    snapshot_stale: bool = False


class DistrictXraySummary(StrictSchema):
    district: str
    node_count: int
    flagged_node_count: int
    crimson_diff_count: int = 0
    top_rule_code: str | None = None
    top_rule_title: str | None = None
    sample_nodes: list[str] = Field(default_factory=list)
    sample_files: list[str] = Field(default_factory=list)


class UiFocusExplainRead(StrictSchema):
    active_slug: str
    target_name: str
    source_commit: str
    observed_at: datetime
    session_id: str | None = None
    client_id: str | None = None
    actor: InvestigationActor = "human"
    follow_state: FollowState = "following"
    focus_revision: int = 0
    evidence_revision_id: str | None = None
    active_tab: str
    lens: str
    layout_mode: str
    blast_mode: str
    diff_base_ref: str
    headline: str
    color_reason: str
    focused_node: LlmNodePointer | None = None
    selected_edge_id: str | None = None
    selected_finding_id: str | None = None
    focused_district: DistrictXraySummary | None = None
    active_findings: list[BoundaryFinding] = Field(default_factory=list)
    cone_edges: list[str] = Field(default_factory=list)
    has_snapshot: bool = False
    snapshot_path: str | None = None
    snapshot_mime_type: str | None = None
    camera_revision: int | None = None
    snapshot_focus_revision: int | None = None
    snapshot_evidence_revision: str | None = None
    snapshot_stale: bool = False
    ambiguous_session_ids: list[str] = Field(default_factory=list)
    corrections: list[InvestigationCorrectionRead] = Field(default_factory=list)
    evidence_identity: EvidenceIdentityRead | None = None
    context_budget: ContextBudgetSummary | None = None
    markdown_brief: str


UiFocusExplainResponse = UiFocusExplainRead


class OnDeviceEngineStatus(StrictSchema):
    engine: Literal["apple", "chrome", "local"]
    label: str
    state: Literal["ready", "downloadable", "downloading", "unavailable", "client_probed"]
    model_id: str | None = None
    base_url: str | None = None
    supports_vision: bool = False
    note: str = ""


class AskEnginesRead(StrictSchema):
    auto_order: list[str] = Field(default_factory=lambda: ["apple", "chrome", "local"])
    recommended_backend_engine: Literal["apple", "local", "none"]
    engines: list[OnDeviceEngineStatus] = Field(default_factory=list)
    mcp_http_path: str = "/api/v1/mcp"
    openapi_path: str = "/openapi.json"


class AskChatTurn(StrictSchema):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=6000)


class AskWytheRequest(StrictSchema):
    question: str = Field(min_length=1, max_length=2000)
    engine: Literal["auto", "apple", "local"] = "auto"
    target_slug: str | None = Field(default=None, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    client_id: str | None = Field(default=None, max_length=128)
    selected_node_id: str | None = Field(default=None, max_length=200)
    selected_finding_id: str | None = Field(default=None, max_length=200)
    selected_edge_id: str | None = Field(default=None, max_length=200)
    local_base_url: str | None = Field(default=None, max_length=256)
    local_model_id: str | None = Field(default=None, max_length=160)
    include_vision_snapshot: bool = True
    history: list[AskChatTurn] = Field(default_factory=list, max_length=16)
    live_viewport_brief: str | None = Field(default=None, max_length=16000)
    snapshot_data_url: str | None = Field(default=None, max_length=4_500_000)


class AskWytheResponse(StrictSchema):
    session_id: str | None = None
    turn_id: str | None = None
    authored_by: Literal["model", "scanner_brief"] = "model"
    engine_used: Literal["apple", "local"]
    model_id: str
    used_vision_snapshot: bool = False
    image_supplied: bool = False
    fallback_reason: str | None = None
    context_headline: str
    answer_markdown: str
    executed_tools: list[str] = Field(default_factory=list)
    referenced_node_ids: list[str] = Field(default_factory=list)
    validated_references: list[ValidatedReferenceRead] = Field(default_factory=list)
    evidence_identity: EvidenceIdentityRead | None = None
    context_budget: ContextBudgetSummary | None = None
    observed_at: datetime


class PluginSpecItem(StrictSchema):
    name: str
    kind: Literal[
        "manipulator_augmenter",
        "post_scan_check",
        "stratum_inspector",
        "stack_adapter",
    ]
    source: str
    origin: Literal["builtin", "entry_point", "local_opt_in"]
    tier: str = "manipulate"
    version: str = "unknown"
    description: str = ""
    enabled_by_default: bool = True
    supported_zooms: list[int] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    mcp_tools: list[str] = Field(default_factory=list)
    cli_subcommands: list[str] = Field(default_factory=list)
    stack_profiles: list[str] = Field(default_factory=list)
    tier_adapters: list[str] = Field(default_factory=list)
    interaction_capabilities: list[str] = Field(default_factory=list)
    unsupported_interaction_capabilities: list[str] = Field(default_factory=list)
    evidence_source_kinds: list[EvidenceSourceKind] = Field(default_factory=list)
    trusted: bool = True


class PluginListResponse(StrictSchema):
    plugins: list[PluginSpecItem] = Field(default_factory=list)
    local_plugins_allowed: bool = False
    load_errors: list[str] = Field(default_factory=list)


class OpenLineageTargetInfo(StrictSchema):
    slug: str
    name: str
    stackProfile: str
    sourceCommit: str
    contentDigest: str
    observationSource: str


class OpenLineageDatasetRef(StrictSchema):
    namespace: str
    name: str


class OpenLineageDatasetItem(StrictSchema):
    namespace: str
    name: str
    facets: dict[str, Any] = Field(default_factory=dict)


class OpenLineageJobItem(StrictSchema):
    namespace: str
    name: str
    inputs: list[OpenLineageDatasetRef] = Field(default_factory=list)
    outputs: list[OpenLineageDatasetRef] = Field(default_factory=list)
    facets: dict[str, Any] = Field(default_factory=dict)


class OpenLineageBundleResponse(StrictSchema):
    producer: str
    schemaURL: str
    bundleType: str
    eventTime: str
    target: OpenLineageTargetInfo
    datasets: list[OpenLineageDatasetItem] = Field(default_factory=list)
    jobs: list[OpenLineageJobItem] = Field(default_factory=list)
    nonCertificationNotice: str


FramingPreset = Literal[
    "iso_overview",
    "tier_elevation",
    "wythe_cross_section",
    "corridor_trace",
]
ViewportLayoutChoice = Literal[
    "cluster",
    "grid",
    "subkind",
    "connected",
    "lifecycle_z",
    "temporal_z",
]
ZWytheSliceChoice = Literal[
    "all",
    "z0_blueprint",
    "z1_built",
    "z2_runtime",
    "z_base",
    "z_head",
]
ViewportLensChoice = Literal[
    "status",
    "contention",
    "gravity",
    "subkind",
    "cluster",
    "containers",
]

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_EXECUTABLE_TEXT_RE = re.compile(
    r"<\s*/?\s*(?:script|iframe|object|embed)\b"
    r"|\b(?:javascript|vbscript)\s*:"
    r"|\bdata\s*:\s*text/html"
    r"|<\s*[a-zA-Z][^>]*\bon[a-zA-Z]+\s*=",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(
    r"<(?:!--[\s\S]*?--|![a-zA-Z][^>]*|\?[^>]*|/\s*[a-zA-Z][a-zA-Z0-9:-]*\s*"
    r"|[a-zA-Z][a-zA-Z0-9:-]*(?:\s[^<>]*)?/?)>"
)
_UNCLOSED_HTML_TAG_RE = re.compile(r"<(?:/\s*)?[a-zA-Z][a-zA-Z0-9:-]*(?:\s[^<>]*)?$")
_NUMERIC_SCALAR_RE = re.compile(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$")
_NUMERIC_TUPLE_RE = re.compile(
    r"^[\[\(\{]?\s*[+-]?(?:\d+\.?\d*|\.\d+)"
    r"(?:\s*[,;\s]\s*[+-]?(?:\d+\.?\d*|\.\d+))+\s*[\]\)\}]?$"
)
_COORD_SMUGGLE_RE = re.compile(
    r"^(?:camera_?(?:pos|position|target|lookat)|pos|position|coords?|coordinates?"
    r"|euler|rot|rotation|quat|quaternion|xyz|azimuth|elevation)\s*[:=]"
    r"|(?:^|[,;\s])[xyz]\s*=\s*[+-]?(?:\d|\.\d)",
    re.IGNORECASE,
)


def sanitize_viewport_plain_text(value: str, *, field_name: str = "text") -> str:
    """Strip HTML tags to plain text and reject script/executable URI payloads."""
    cleaned = _CTRL_CHARS_RE.sub("", value)
    if _EXECUTABLE_TEXT_RE.search(cleaned):
        raise ValueError(
            f"Unsafe executable markup or script URI rejected in `{field_name}`."
        )
    while True:
        nxt = _HTML_TAG_RE.sub("", cleaned)
        nxt = _UNCLOSED_HTML_TAG_RE.sub("", nxt)
        if _EXECUTABLE_TEXT_RE.search(nxt):
            raise ValueError(
                f"Unsafe executable markup or script URI rejected in `{field_name}`."
            )
        if nxt == cleaned:
            break
        cleaned = nxt
    return re.sub(r"\s+", " ", cleaned).strip()


def validate_semantic_atlas_id(raw_id: str, *, field_name: str = "id") -> str:
    """Enforce semantic Atlas IDs and reject raw numeric coordinate smuggling."""
    cleaned = _CTRL_CHARS_RE.sub("", raw_id).strip()
    if not cleaned:
        raise ValueError(f"`{field_name}` entries must be non-empty semantic identifiers.")
    if len(cleaned) > 200:
        raise ValueError(f"`{field_name}` entry exceeds 200 characters.")
    if _EXECUTABLE_TEXT_RE.search(cleaned) or _HTML_TAG_RE.search(cleaned) or _UNCLOSED_HTML_TAG_RE.search(cleaned):
        raise ValueError(f"Markup or script content is forbidden in `{field_name}`.")
    if (
        _NUMERIC_SCALAR_RE.match(cleaned)
        or _NUMERIC_TUPLE_RE.match(cleaned)
        or _COORD_SMUGGLE_RE.search(cleaned)
    ):
        raise ValueError(
            f"Raw numeric coordinates are forbidden in `{field_name}`; "
            "pass semantic Atlas IDs and `framing_preset` instead."
        )
    return cleaned


class TourKeyframe(StrictSchema):
    step_index: int = Field(ge=0, le=64)
    title: str = Field(max_length=120)
    focus_node_ids: list[str] = Field(default_factory=list, max_length=50)
    highlight_edge_ids: list[str] = Field(default_factory=list, max_length=80)
    finding_id: str | None = Field(default=None, max_length=120)
    lens: ViewportLensChoice | None = None
    layout_mode: ViewportLayoutChoice | None = None
    z_wythe_slice: ZWytheSliceChoice | None = None
    zoom_stratum: Literal[1, 2, 3] = 1
    framing_preset: FramingPreset = "iso_overview"
    caption: str = Field(default="", max_length=400)

    @field_validator("title", "caption", mode="before")
    @classmethod
    def _clean_text(cls, value: Any, info: Any) -> Any:
        if not isinstance(value, str):
            return value
        return sanitize_viewport_plain_text(value, field_name=str(info.field_name))

    @field_validator("focus_node_ids", "highlight_edge_ids", mode="before")
    @classmethod
    def _clean_id_list(cls, value: Any, info: Any) -> Any:
        if not isinstance(value, list):
            return value
        fname = str(info.field_name)
        return [
            validate_semantic_atlas_id(item, field_name=fname) if isinstance(item, str) else item
            for item in value
        ]

    @field_validator("finding_id", mode="before")
    @classmethod
    def _clean_finding_id(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return validate_semantic_atlas_id(value, field_name="finding_id")

    @field_validator("step_index", "zoom_stratum", mode="before")
    @classmethod
    def _reject_bool_int(cls, value: Any, info: Any) -> Any:
        if value is True or value is False:
            raise ValueError(f"`{info.field_name}` must be an integer, not boolean.")
        return value


class ChronicleFrame(StrictSchema):
    phase_index: int = Field(ge=0, le=64)
    phase_key: str = Field(min_length=1, max_length=64)
    phase_label: str = Field(min_length=1, max_length=120)
    tier: TierKind
    focus_node_ids: list[str] = Field(default_factory=list, max_length=80)
    highlight_edge_ids: list[str] = Field(default_factory=list, max_length=120)
    status: Literal["ok", "warning", "failed", "pending"] = "ok"
    caption: str = Field(default="", max_length=400)
    substeps: list[str] = Field(default_factory=list, max_length=24)

    @field_validator("phase_key", mode="before")
    @classmethod
    def _clean_phase_key(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return validate_semantic_atlas_id(value, field_name="phase_key")

    @field_validator("phase_index", mode="before")
    @classmethod
    def _reject_bool_phase_idx(cls, value: Any) -> Any:
        if value is True or value is False:
            raise ValueError("`phase_index` must be an integer, not boolean.")
        return value

    @field_validator("phase_label", "caption", mode="before")
    @classmethod
    def _clean_frame_text(cls, value: Any, info: Any) -> Any:
        if not isinstance(value, str):
            return value
        return sanitize_viewport_plain_text(value, field_name=str(info.field_name))

    @field_validator("substeps", mode="before")
    @classmethod
    def _clean_substeps(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value
        cleaned_steps: list[Any] = []
        for item in value:
            if not isinstance(item, str):
                cleaned_steps.append(item)
                continue
            sanitized = sanitize_viewport_plain_text(item, field_name="substeps")
            if len(sanitized) > 240:
                raise ValueError("`substeps` entry exceeds 240 characters.")
            cleaned_steps.append(sanitized)
        return cleaned_steps

    @field_validator("focus_node_ids", "highlight_edge_ids", mode="before")
    @classmethod
    def _clean_frame_ids(cls, value: Any, info: Any) -> Any:
        if not isinstance(value, list):
            return value
        fname = str(info.field_name)
        return [
            validate_semantic_atlas_id(item, field_name=fname) if isinstance(item, str) else item
            for item in value
        ]


class ChronicleTimeline(StrictSchema):
    timeline_id: str = Field(min_length=1, max_length=64)
    target_slug: str = Field(min_length=1, max_length=64)
    title: str = Field(default="", max_length=160)
    live_following: bool = True
    halted_reason: str | None = Field(default=None, max_length=240)
    active_phase_index: int = Field(default=0, ge=0, le=64)
    frames: list[ChronicleFrame] = Field(default_factory=list, max_length=32)

    @field_validator("timeline_id", "target_slug", mode="before")
    @classmethod
    def _clean_timeline_identifiers(cls, value: Any, info: Any) -> Any:
        if not isinstance(value, str):
            return value
        fname = str(info.field_name)
        cleaned = _CTRL_CHARS_RE.sub("", value).strip()
        if not cleaned:
            raise ValueError(f"`{fname}` must be non-empty.")
        if (
            _EXECUTABLE_TEXT_RE.search(cleaned)
            or _HTML_TAG_RE.search(cleaned)
            or _UNCLOSED_HTML_TAG_RE.search(cleaned)
            or _NUMERIC_TUPLE_RE.match(cleaned)
            or _COORD_SMUGGLE_RE.search(cleaned)
        ):
            raise ValueError(f"Markup or coordinate tuples are forbidden in `{fname}`.")
        return cleaned

    @field_validator("title", mode="before")
    @classmethod
    def _clean_timeline_title(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return sanitize_viewport_plain_text(value, field_name="title")

    @field_validator("halted_reason", mode="before")
    @classmethod
    def _clean_halted_reason(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        sanitized = sanitize_viewport_plain_text(value, field_name="halted_reason")
        return sanitized or None

    @field_validator("active_phase_index", mode="before")
    @classmethod
    def _reject_bool_active_phase(cls, value: Any) -> Any:
        if value is True or value is False:
            raise ValueError("`active_phase_index` must be an integer, not boolean.")
        return value


ViewportDeliveryState = Literal[
    "accepted_by_service",
    "waiting_for_follow",
    "applied_by_browser",
    "paused_by_human",
    "rejected",
    "stale",
    "expired",
]
ViewportReceiptOutcome = Literal["applied", "paused_by_human", "rejected", "stale_revision"]


def _new_command_id() -> str:
    return f"cmd_{uuid.uuid4().hex[:12]}"


class ViewportCommand(StrictSchema):
    command_id: str = Field(default_factory=_new_command_id, max_length=64)
    correlation_id: str | None = Field(default=None, max_length=128)
    target_slug: str = Field(min_length=1, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    expected_evidence_revision: str | None = Field(default=None, max_length=96)
    expires_at: datetime | None = None
    delivery_state: ViewportDeliveryState = "accepted_by_service"
    applied_by_client_ids: list[str] = Field(default_factory=list, max_length=64)
    focus_node_ids: list[str] = Field(default_factory=list, max_length=50)
    highlight_edge_ids: list[str] = Field(default_factory=list, max_length=80)
    finding_id: str | None = Field(default=None, max_length=120)
    lens: ViewportLensChoice | None = None
    layout_mode: ViewportLayoutChoice | None = None
    z_wythe_slice: ZWytheSliceChoice | None = None
    zoom_stratum: Literal[1, 2, 3] = 1
    framing_preset: FramingPreset = "iso_overview"
    caption: str = Field(default="", max_length=400)
    tour_keyframes: list[TourKeyframe] = Field(default_factory=list, max_length=32)
    chronicle_frames: list[ChronicleFrame] = Field(default_factory=list, max_length=32)
    chronicle_timeline: ChronicleTimeline | None = None

    @field_validator("command_id", mode="before")
    @classmethod
    def _clean_command_id(cls, value: Any) -> Any:
        if value is None:
            return _new_command_id()
        if not isinstance(value, str):
            return value
        cleaned = _CTRL_CHARS_RE.sub("", value).strip()
        if not cleaned:
            return _new_command_id()
        if _EXECUTABLE_TEXT_RE.search(cleaned) or _HTML_TAG_RE.search(cleaned) or _UNCLOSED_HTML_TAG_RE.search(cleaned):
            raise ValueError("Markup or script content is forbidden in `command_id`.")
        return cleaned

    @field_validator("correlation_id", "expected_evidence_revision", mode="before")
    @classmethod
    def _clean_optional_identifiers(cls, value: Any, info: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        cleaned = _CTRL_CHARS_RE.sub("", value).strip()
        if not cleaned:
            return None
        if _EXECUTABLE_TEXT_RE.search(cleaned) or _HTML_TAG_RE.search(cleaned) or _UNCLOSED_HTML_TAG_RE.search(cleaned):
            raise ValueError(f"Markup or script content is forbidden in `{info.field_name}`.")
        return cleaned

    @field_validator("zoom_stratum", mode="before")
    @classmethod
    def _reject_bool_zoom_stratum(cls, value: Any) -> Any:
        if value is True or value is False:
            raise ValueError("`zoom_stratum` must be integer 1, 2, or 3, not boolean.")
        return value

    @field_validator("target_slug", mode="before")
    @classmethod
    def _clean_target_slug(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        cleaned = _CTRL_CHARS_RE.sub("", value).strip()
        if not cleaned:
            raise ValueError("`target_slug` must be non-empty.")
        if (
            _EXECUTABLE_TEXT_RE.search(cleaned)
            or _HTML_TAG_RE.search(cleaned)
            or _UNCLOSED_HTML_TAG_RE.search(cleaned)
            or _NUMERIC_TUPLE_RE.match(cleaned)
            or _COORD_SMUGGLE_RE.search(cleaned)
        ):
            raise ValueError("Markup or coordinate tuples are forbidden in `target_slug`.")
        return cleaned

    @field_validator("session_id", mode="before")
    @classmethod
    def _clean_session_id(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        cleaned = _CTRL_CHARS_RE.sub("", value).strip()
        if not cleaned:
            return None
        if _EXECUTABLE_TEXT_RE.search(cleaned) or _HTML_TAG_RE.search(cleaned) or _UNCLOSED_HTML_TAG_RE.search(cleaned):
            raise ValueError("Markup or script content is forbidden in `session_id`.")
        return cleaned

    @field_validator("caption", mode="before")
    @classmethod
    def _clean_command_caption(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return sanitize_viewport_plain_text(value, field_name="caption")

    @field_validator("focus_node_ids", "highlight_edge_ids", mode="before")
    @classmethod
    def _clean_command_ids(cls, value: Any, info: Any) -> Any:
        if not isinstance(value, list):
            return value
        fname = str(info.field_name)
        return [
            validate_semantic_atlas_id(item, field_name=fname) if isinstance(item, str) else item
            for item in value
        ]

    @field_validator("finding_id", mode="before")
    @classmethod
    def _clean_command_finding(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return validate_semantic_atlas_id(value, field_name="finding_id")


class ViewportCommandEvent(StrictSchema):
    seq: int = Field(ge=1)
    issued_at: datetime
    permalink: str
    delivery_state: ViewportDeliveryState = "accepted_by_service"
    applied_by_client_ids: list[str] = Field(default_factory=list)
    command: ViewportCommand


class ViewportCommandAck(StrictSchema):
    seq: int = Field(ge=1)
    command_id: str = ""
    correlation_id: str | None = None
    issued_at: datetime
    target_slug: str
    session_id: str | None = None
    permalink: str
    subscriber_count: int = Field(ge=0)
    delivery_state: ViewportDeliveryState = "accepted_by_service"
    applied_by_client_ids: list[str] = Field(default_factory=list)
    idempotent_replay: bool = False
    command: ViewportCommand


class ViewportStateRead(StrictSchema):
    target_slug: str
    session_id: str | None = None
    latest: ViewportCommandEvent | None = None
    history: list[ViewportCommandEvent] = Field(default_factory=list)
    subscriber_count: int = Field(default=0, ge=0)


class ViewportCommandReceiptCreate(StrictSchema):
    command_id: str = Field(min_length=1, max_length=64)
    seq: int | None = Field(default=None, ge=1)
    target_slug: str = Field(min_length=1, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    client_id: str = Field(min_length=1, max_length=128)
    outcome: ViewportReceiptOutcome
    applied_focus_revision: int | None = Field(default=None, ge=0)
    note: str = Field(default="", max_length=400)

    @field_validator("note", mode="before")
    @classmethod
    def _clean_receipt_note(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return sanitize_viewport_plain_text(value, field_name="note")


class ViewportCommandReceiptRead(StrictSchema):
    receipt_id: str
    command_id: str
    seq: int | None = None
    target_slug: str
    session_id: str | None = None
    client_id: str
    outcome: ViewportReceiptOutcome
    delivery_state: ViewportDeliveryState
    applied_by_client_ids: list[str] = Field(default_factory=list)
    applied_focus_revision: int | None = None
    note: str = ""
    recorded_at: datetime


class RetentionPolicyRead(StrictSchema):
    max_sessions: int = 64
    max_turns_per_session: int = 100
    max_events_per_session: int = 200
    storage_backend: str = "sqlite_wal"
    db_filename: str = "viewport_bus.sqlite3"


class InvestigationFocusSnapshot(StrictSchema):
    focus_revision: int = 0
    actor: InvestigationActor = "human"
    client_id: str | None = None
    active_tab: str = "3d"
    selected_node_id: str | None = None
    selected_edge_id: str | None = None
    selected_finding_id: str | None = None
    hovered_node_id: str | None = None
    focused_district: str | None = None
    lens: str = "status"
    layout_mode: str = "cluster"
    blast_mode: str = "off"
    diff_base_ref: str = "HEAD~1"
    has_snapshot: bool = False
    snapshot_path: str | None = None
    snapshot_focus_revision: int | None = None
    snapshot_evidence_revision: str | None = None
    updated_at: datetime


class InvestigationCorrectionCreate(StrictSchema):
    client_id: str | None = Field(default=None, max_length=128)
    actor: InvestigationActor = "human"
    target_ref_id: str | None = Field(default=None, max_length=200)
    turn_id: str | None = Field(default=None, max_length=64)
    kind: str = Field(default="disagreement", max_length=64)
    note: str = Field(min_length=1, max_length=2000)

    @field_validator("note", mode="before")
    @classmethod
    def _clean_correction_note(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        cleaned = sanitize_viewport_plain_text(value, field_name="note")
        if not cleaned:
            raise ValueError("`note` must be non-empty.")
        return cleaned


class InvestigationFollowUpdate(StrictSchema):
    client_id: str | None = Field(default=None, max_length=128)
    actor: InvestigationActor = "human"
    follow_state: FollowState
    reason: str = Field(default="", max_length=400)

    @field_validator("reason", mode="before")
    @classmethod
    def _clean_follow_reason(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return sanitize_viewport_plain_text(value, field_name="reason")


class InvestigationTurnCreate(StrictSchema):
    client_id: str | None = Field(default=None, max_length=128)
    actor: InvestigationActor = "human"
    question: str = Field(min_length=1, max_length=2000)
    answer_markdown: str | None = Field(default=None, max_length=24000)
    engine: str | None = Field(default=None, max_length=64)
    model_id: str | None = Field(default=None, max_length=200)
    used_vision: bool = False
    image_supplied: bool = False
    authored_by: Literal["model", "scanner_brief", "none"] = "model"
    fallback_reason: str | None = Field(default=None, max_length=500)
    failure_reason: str | None = Field(default=None, max_length=500)
    selected_node_id: str | None = Field(default=None, max_length=200)
    selected_edge_id: str | None = Field(default=None, max_length=200)
    selected_finding_id: str | None = Field(default=None, max_length=200)
    referenced_ids: list[str] = Field(default_factory=list, max_length=64)


class InvestigationTurnRead(StrictSchema):
    turn_id: str
    session_id: str
    client_id: str | None = None
    actor: InvestigationActor = "human"
    question: str
    answer_markdown: str | None = None
    status: Literal["answered", "unresolved"] = "answered"
    authored_by: Literal["model", "scanner_brief", "none"] = "model"
    engine: str | None = None
    model_id: str | None = None
    used_vision: bool = False
    image_supplied: bool = False
    fallback_reason: str | None = None
    failure_reason: str | None = None
    evidence_revision_id: str
    focus_revision: int = 0
    selected_node_id: str | None = None
    selected_edge_id: str | None = None
    selected_finding_id: str | None = None
    validated_references: list[ValidatedReferenceRead] = Field(default_factory=list)
    needs_revalidation: bool = False
    created_at: datetime


class InvestigationDeltaEventRead(StrictSchema):
    revision: int
    session_id: str
    event_kind: str
    actor: InvestigationActor = "system"
    client_id: str | None = None
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class InvestigationDeltaEventsResponse(StrictSchema):
    session_id: str
    latest_revision: int
    since_revision: int
    events: list[InvestigationDeltaEventRead] = Field(default_factory=list)


class InvestigationCreateRequest(StrictSchema):
    target_slug: str = Field(min_length=1, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    client_id: str | None = Field(default=None, max_length=128)
    title: str | None = Field(default=None, max_length=200)

    @field_validator("session_id", mode="before")
    @classmethod
    def _clean_create_session_id(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        cleaned = _CTRL_CHARS_RE.sub("", value).strip()
        if not cleaned:
            return None
        if _EXECUTABLE_TEXT_RE.search(cleaned) or _HTML_TAG_RE.search(cleaned) or _UNCLOSED_HTML_TAG_RE.search(cleaned):
            raise ValueError("Markup or script content is forbidden in `session_id`.")
        return cleaned


class InvestigationSummaryRead(StrictSchema):
    session_id: str
    target_slug: str
    title: str
    follow_state: FollowState = "following"
    session_revision: int = 0
    focus_revision: int = 0
    pinned_evidence_revision_id: str
    latest_evidence_revision_id: str
    participating_client_ids: list[str] = Field(default_factory=list)
    turn_count: int = 0
    unresolved_question_count: int = 0
    correction_count: int = 0
    selected_node_id: str | None = None
    selected_edge_id: str | None = None
    selected_finding_id: str | None = None
    created_at: datetime
    updated_at: datetime


class InvestigationListResponse(StrictSchema):
    sessions: list[InvestigationSummaryRead] = Field(default_factory=list)
    retention_policy: RetentionPolicyRead = Field(default_factory=RetentionPolicyRead)


class InvestigationSessionRead(StrictSchema):
    session_id: str
    target_slug: str
    title: str
    follow_state: FollowState = "following"
    follow_reason: str = ""
    session_revision: int = 0
    focus_revision: int = 0
    participating_client_ids: list[str] = Field(default_factory=list)
    pinned_evidence: EvidenceIdentityRead
    latest_evidence: EvidenceIdentityRead
    evidence_drifted: bool = False
    focus: InvestigationFocusSnapshot
    turns: list[InvestigationTurnRead] = Field(default_factory=list)
    unresolved_questions: list[InvestigationTurnRead] = Field(default_factory=list)
    corrections: list[InvestigationCorrectionRead] = Field(default_factory=list)
    recent_receipts: list[ViewportCommandReceiptRead] = Field(default_factory=list)
    recent_events: list[InvestigationDeltaEventRead] = Field(default_factory=list)
    retention_policy: RetentionPolicyRead = Field(default_factory=RetentionPolicyRead)
    permalink: str = ""
    created_at: datetime
    updated_at: datetime


class InvestigationRevisionComparisonRead(StrictSchema):
    session_id: str
    target_slug: str
    pinned_evidence: EvidenceIdentityRead
    current_evidence: EvidenceIdentityRead
    digest_changed: bool
    surviving_refs: list[ValidatedReferenceRead] = Field(default_factory=list)
    vanished_refs: list[ValidatedReferenceRead] = Field(default_factory=list)
    modified_refs: list[ValidatedReferenceRead] = Field(default_factory=list)
    added_finding_ids: list[str] = Field(default_factory=list)
    resolved_finding_ids: list[str] = Field(default_factory=list)
    invalidated_turn_ids: list[str] = Field(default_factory=list)
    summary_markdown: str


class InvestigationExportBundle(StrictSchema):
    schema_version: str = "1.0"
    exported_at: datetime
    session: InvestigationSessionRead
    comparison: InvestigationRevisionComparisonRead | None = None
