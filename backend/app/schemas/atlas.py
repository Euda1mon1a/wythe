"""Strict response and request contracts for the 3-tier Truth Atlas."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TierKind = Literal["truth", "manipulate", "display"]
NodeSubkind = Literal[
    "table",
    "sql_function",
    "cache_store",
    "route",
    "service",
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
    http_methods: list[str] = Field(default_factory=list)
    http_paths: list[str] = Field(default_factory=list)
    read_by_count: int = 0
    written_by_count: int = 0
    cutover_history: str | None = None
    ruling_summary: str | None = None
    ruling_audited_at: date | None = None
    store_purpose: StorePurposeDeclaration | None = None
    verification_note: str | None = None


class AtlasEdge(StrictSchema):
    id: str
    source_id: str
    target_id: str
    kind: EdgeKind
    verification: VerificationState
    evidence_path: str | None = None
    evidence_note: str


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
    truncation_reasons: list[str] = Field(default_factory=list)
    full_export_hint: str = ""


class LlmContextConeReport(StrictSchema):
    target_slug: str
    query: str
    source_commit: str
    worktree_dirty: bool | None = None
    dirty_path_count: int | None = None
    content_digest: str = ""
    matched_seed_ids: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
    upstream_display_nodes: list[LlmNodePointer] = Field(default_factory=list)
    manipulator_nodes: list[LlmNodePointer] = Field(default_factory=list)
    downstream_truth_nodes: list[LlmNodePointer] = Field(default_factory=list)
    cone_edges: list[str] = Field(default_factory=list)
    cone_edge_items: list[ConeEdgeSummary] = Field(default_factory=list)
    matching_chains: list[EndToEndChain] = Field(default_factory=list)
    cone_findings: list[BoundaryFinding] = Field(default_factory=list)
    completeness: ConeCompleteness | None = None
    approx_tokens: int = 0
    markdown: str = ""


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


class UiFocusStatePayload(StrictSchema):
    active_slug: str = Field(min_length=1, max_length=64)
    active_tab: str = Field(default="3d", max_length=24)
    selected_node_id: str | None = Field(default=None, max_length=200)
    hovered_node_id: str | None = Field(default=None, max_length=200)
    focused_district: str | None = Field(default=None, max_length=80)
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
    snapshot_data_url: str | None = Field(default=None, max_length=8_500_000)


class UiFocusSyncAck(StrictSchema):
    active_slug: str
    observed_at: datetime
    has_snapshot: bool
    snapshot_path: str | None = None


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
    active_tab: str
    lens: str
    layout_mode: str
    blast_mode: str
    diff_base_ref: str
    headline: str
    color_reason: str
    focused_node: LlmNodePointer | None = None
    focused_district: DistrictXraySummary | None = None
    active_findings: list[BoundaryFinding] = Field(default_factory=list)
    cone_edges: list[str] = Field(default_factory=list)
    has_snapshot: bool = False
    snapshot_path: str | None = None
    markdown_brief: str


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
    local_base_url: str | None = Field(default=None, max_length=256)
    local_model_id: str | None = Field(default=None, max_length=160)
    include_vision_snapshot: bool = True
    history: list[AskChatTurn] = Field(default_factory=list, max_length=16)
    live_viewport_brief: str | None = Field(default=None, max_length=16000)
    snapshot_data_url: str | None = Field(default=None, max_length=4_500_000)


class AskWytheResponse(StrictSchema):
    engine_used: Literal["apple", "local"]
    model_id: str
    used_vision_snapshot: bool = False
    context_headline: str
    answer_markdown: str
    referenced_node_ids: list[str] = Field(default_factory=list)
    observed_at: datetime
