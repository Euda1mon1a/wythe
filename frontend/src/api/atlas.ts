/**
 * Strictly typed API client bound to OpenAPI-generated contracts (`api-generated.ts`).
 */

import { del, get, patch, post } from '@/lib/api';
import type { components } from '@/types/api-generated';

export type TruthAtlasReport = components['schemas']['TruthAtlasReport'];
export type AtlasNode = components['schemas']['AtlasNode'];
export type StorePurposeDeclaration = components['schemas']['StorePurposeDeclaration'];
export type PolicyFieldConsumption = components['schemas']['PolicyFieldConsumption'];
export type AtlasEdge = components['schemas']['AtlasEdge'];
export type EndToEndChain = components['schemas']['EndToEndChain'];
export type BoundaryFinding = components['schemas']['BoundaryFinding'];
export type TargetProjectRead = components['schemas']['TargetProjectRead'];
export type TargetProjectCreate = components['schemas']['TargetProjectCreate'];
export type RulePolicyRead = components['schemas']['RulePolicyRead'];
export type RulePolicyUpdate = components['schemas']['RulePolicyUpdate'];
export type AuditRulingRead = components['schemas']['AuditRulingRead'];
export type AuditRulingCreate = components['schemas']['AuditRulingCreate'];
export type RatchetBaselineRead = components['schemas']['RatchetBaselineRead'];
export type RatchetCaptureRequest = components['schemas']['RatchetCaptureRequest'];
export type ScanSnapshotSummary = components['schemas']['ScanSnapshotSummary'];
export type AdapterSlotSchema = components['schemas']['AdapterSlotSchema'];
export type StackProfileRead = components['schemas']['StackProfileRead'];
export type StackDetectionResult = components['schemas']['StackDetectionResult'];
export type LegacyBridgeSummary = components['schemas']['LegacyBridgeSummary'];
export type PolicyVocabularyRead = components['schemas']['PolicyVocabularyRead'];
export type PolicyVocabularyCreate = components['schemas']['PolicyVocabularyCreate'];
export type PolicyVocabularyUpdate = components['schemas']['PolicyVocabularyUpdate'];
export type DiffBlastRadiusReport = components['schemas']['DiffBlastRadiusReport'];
export type SnapshotComparisonReport = components['schemas']['SnapshotComparisonReport'];
export type PortableGovernanceBundle = components['schemas']['PortableGovernanceBundle'];
export type PortableReferenceExemplar = components['schemas']['PortableReferenceExemplar'];
export type GovernanceSyncReceipt = components['schemas']['GovernanceSyncReceipt'];
export type LlmBriefRead = components['schemas']['LlmBriefRead'];
export type ConeEdgeSummary = components['schemas']['ConeEdgeSummary'];
export type ConeSectionCount = components['schemas']['ConeSectionCount'];
export type ConeCompleteness = components['schemas']['ConeCompleteness'];
export type LlmContextConeReport = components['schemas']['LlmContextConeReport'];
export type SourceSnippetRead = components['schemas']['SourceSnippetRead'];
export type DistrictXraySummary = components['schemas']['DistrictXraySummary'];
export type OnDeviceEngineStatus = components['schemas']['OnDeviceEngineStatus'];
export type AskEnginesRead = components['schemas']['AskEnginesRead'];
export type AskChatTurn = components['schemas']['AskChatTurn'];
export type PluginSpecItem = components['schemas']['PluginSpecItem'] & {
  interaction_capabilities?: string[];
  unsupported_interaction_capabilities?: string[];
  evidence_source_kinds?: EvidenceSourceKind[];
};
export type PluginListResponse = Omit<components['schemas']['PluginListResponse'], 'plugins'> & {
  plugins?: PluginSpecItem[];
};
export type OpenLineageTargetInfo = components['schemas']['OpenLineageTargetInfo'];
export type OpenLineageDatasetRef = components['schemas']['OpenLineageDatasetRef'];
export type OpenLineageDatasetItem = components['schemas']['OpenLineageDatasetItem'];
export type OpenLineageJobItem = components['schemas']['OpenLineageJobItem'];
export type OpenLineageBundleResponse = components['schemas']['OpenLineageBundleResponse'];
export type StratumSummaryBadge = components['schemas']['StratumSummaryBadge'];
export type StratumMicroNode = components['schemas']['StratumMicroNode'];
export type StratumMicroEdge = components['schemas']['StratumMicroEdge'];
export type StratumDrilldownRead = components['schemas']['StratumDrilldownRead'];
export type TourKeyframe = components['schemas']['TourKeyframe'];
export type ChronicleFrame = components['schemas']['ChronicleFrame'];
export type ChronicleTimeline = components['schemas']['ChronicleTimeline'];

export type EvidenceSourceKind = 'source_static' | 'compiled_artifact' | 'runtime_capture';
export type EpistemicKind =
  | 'observation'
  | 'static_inference'
  | 'compiled_artifact'
  | 'runtime_capture'
  | 'model_interpretation'
  | 'suggested_action'
  | 'verified_result';
export type ReferenceSubjectKind = 'node' | 'edge' | 'finding' | 'snippet' | 'capture';
export type ReferenceValidationState =
  | 'validated'
  | 'text_convenience'
  | 'vanished_in_current_scan'
  | 'historical_needs_revalidation'
  | 'unresolved';
export type InvestigationActor = 'human' | 'agent' | 'system';
export type FollowState = 'following' | 'paused';
export type ViewportDeliveryState =
  | 'accepted_by_service'
  | 'waiting_for_follow'
  | 'applied_by_browser'
  | 'paused_by_human'
  | 'rejected'
  | 'stale'
  | 'expired';
export type ViewportReceiptOutcome =
  | 'applied'
  | 'paused_by_human'
  | 'rejected'
  | 'stale_revision';

export interface EvidenceSourceItem {
  kind: EvidenceSourceKind;
  producer: string;
  freshness: string;
  sampling_note?: string;
}

export interface EvidenceIdentityRead {
  evidence_revision_id: string;
  snapshot_id?: number | null;
  source_commit: string;
  content_tree_sha256?: string | null;
  worktree_dirty?: boolean | null;
  dirty_path_count?: number | null;
  content_digest: string;
  observed_at: string;
  coverage_complete?: boolean;
  stack_profile: string;
  active_plugins?: string[];
  evidence_sources?: EvidenceSourceItem[];
}

export interface ValidatedReferenceRead {
  ref_id: string;
  kind: ReferenceSubjectKind;
  label?: string;
  source_file?: string | null;
  line?: number | null;
  evidence_revision_id: string;
  validation_state: ReferenceValidationState;
  epistemic_kind?: EpistemicKind;
  producer?: string;
  note?: string;
}

export interface ContextBudgetSummary {
  included_counts?: Record<string, number>;
  omitted_counts?: Record<string, number>;
  truncated_sections?: string[];
  prompt_chars?: number;
  max_prompt_chars?: number;
  expand_hint?: string;
}

export interface InvestigationCorrectionCreate {
  client_id?: string | null;
  actor?: InvestigationActor;
  target_ref_id?: string | null;
  turn_id?: string | null;
  kind?: string;
  note: string;
}

export interface InvestigationCorrectionRead {
  correction_id: string;
  session_id: string;
  client_id?: string | null;
  actor?: InvestigationActor;
  target_ref_id?: string | null;
  turn_id?: string | null;
  kind?: string;
  note: string;
  evidence_revision_id?: string | null;
  promoted_to_ruling?: boolean;
  created_at: string;
}

export type UiFocusStatePayload = Omit<
  components['schemas']['UiFocusStatePayload'],
  | 'session_id'
  | 'client_id'
  | 'actor'
  | 'selected_edge_id'
  | 'selected_finding_id'
  | 'follow_state'
  | 'focus_revision'
  | 'evidence_revision_id'
> & {
  session_id?: string | null;
  client_id?: string | null;
  actor?: InvestigationActor;
  selected_edge_id?: string | null;
  selected_finding_id?: string | null;
  follow_state?: FollowState | null;
  focus_revision?: number | null;
  evidence_revision_id?: string | null;
};

export type UiFocusSyncAck = Omit<
  components['schemas']['UiFocusSyncAck'],
  | 'session_id'
  | 'client_id'
  | 'actor'
  | 'follow_state'
  | 'focus_revision'
  | 'evidence_revision_id'
  | 'snapshot_focus_revision'
  | 'snapshot_evidence_revision'
  | 'snapshot_stale'
> & {
  session_id?: string | null;
  client_id?: string | null;
  actor?: InvestigationActor;
  follow_state?: FollowState;
  focus_revision?: number;
  evidence_revision_id?: string | null;
  snapshot_focus_revision?: number | null;
  snapshot_evidence_revision?: string | null;
  snapshot_stale?: boolean;
};

export type UiFocusExplainRead = Omit<
  components['schemas']['UiFocusExplainRead'],
  | 'session_id'
  | 'client_id'
  | 'actor'
  | 'follow_state'
  | 'focus_revision'
  | 'evidence_revision_id'
  | 'selected_edge_id'
  | 'selected_finding_id'
  | 'snapshot_focus_revision'
  | 'snapshot_evidence_revision'
  | 'snapshot_stale'
  | 'ambiguous_session_ids'
  | 'corrections'
  | 'evidence_identity'
  | 'context_budget'
> & {
  session_id?: string | null;
  client_id?: string | null;
  actor?: InvestigationActor;
  follow_state?: FollowState;
  focus_revision?: number;
  evidence_revision_id?: string | null;
  selected_edge_id?: string | null;
  selected_finding_id?: string | null;
  snapshot_focus_revision?: number | null;
  snapshot_evidence_revision?: string | null;
  snapshot_stale?: boolean;
  ambiguous_session_ids?: string[];
  corrections?: InvestigationCorrectionRead[];
  evidence_identity?: EvidenceIdentityRead | null;
  context_budget?: ContextBudgetSummary | null;
};

export type AskWytheRequest = Omit<
  components['schemas']['AskWytheRequest'],
  'session_id' | 'client_id' | 'selected_node_id' | 'selected_finding_id' | 'selected_edge_id'
> & {
  session_id?: string | null;
  client_id?: string | null;
  selected_node_id?: string | null;
  selected_finding_id?: string | null;
  selected_edge_id?: string | null;
};

export type AskWytheResponse = Omit<
  components['schemas']['AskWytheResponse'],
  | 'session_id'
  | 'turn_id'
  | 'authored_by'
  | 'image_supplied'
  | 'fallback_reason'
  | 'validated_references'
  | 'evidence_identity'
  | 'context_budget'
> & {
  session_id?: string | null;
  turn_id?: string | null;
  authored_by?: 'model' | 'scanner_brief';
  image_supplied?: boolean;
  fallback_reason?: string | null;
  validated_references?: ValidatedReferenceRead[];
  evidence_identity?: EvidenceIdentityRead | null;
  context_budget?: ContextBudgetSummary | null;
};

export type BaseViewportCommand = components['schemas']['ViewportCommand'];
export type ViewportCommand = Omit<
  BaseViewportCommand,
  | 'command_id'
  | 'correlation_id'
  | 'session_id'
  | 'expected_evidence_revision'
  | 'expires_at'
  | 'delivery_state'
  | 'applied_by_client_ids'
> & {
  command_id?: string;
  correlation_id?: string | null;
  session_id?: string | null;
  expected_evidence_revision?: string | null;
  expires_at?: string | null;
  delivery_state?: ViewportDeliveryState;
  applied_by_client_ids?: string[];
};

export type ViewportCommandAck = Omit<
  components['schemas']['ViewportCommandAck'],
  | 'command_id'
  | 'correlation_id'
  | 'session_id'
  | 'delivery_state'
  | 'applied_by_client_ids'
  | 'idempotent_replay'
  | 'command'
> & {
  command_id?: string;
  correlation_id?: string | null;
  session_id?: string | null;
  delivery_state?: ViewportDeliveryState;
  applied_by_client_ids?: string[];
  idempotent_replay?: boolean;
  command: ViewportCommand;
};

export type ViewportCommandEvent = Omit<
  components['schemas']['ViewportCommandEvent'],
  'delivery_state' | 'applied_by_client_ids' | 'command'
> & {
  delivery_state?: ViewportDeliveryState;
  applied_by_client_ids?: string[];
  command: ViewportCommand;
};

export type ViewportStateRead = Omit<
  components['schemas']['ViewportStateRead'],
  'session_id' | 'latest' | 'history'
> & {
  session_id?: string | null;
  latest?: ViewportCommandEvent | null;
  history?: ViewportCommandEvent[];
};

export type FramingPreset = BaseViewportCommand['framing_preset'];
export type ViewportLayoutChoice = NonNullable<BaseViewportCommand['layout_mode']>;
export type ZWytheSliceChoice = NonNullable<BaseViewportCommand['z_wythe_slice']>;

export interface ViewportCommandReceiptCreate {
  command_id: string;
  seq?: number | null;
  target_slug: string;
  session_id?: string | null;
  client_id: string;
  outcome: ViewportReceiptOutcome;
  applied_focus_revision?: number | null;
  note?: string;
}

export interface ViewportCommandReceiptRead {
  receipt_id: string;
  command_id: string;
  seq?: number | null;
  target_slug: string;
  session_id?: string | null;
  client_id: string;
  outcome: ViewportReceiptOutcome;
  delivery_state: ViewportDeliveryState;
  applied_by_client_ids?: string[];
  applied_focus_revision?: number | null;
  note?: string;
  recorded_at: string;
}

export interface RetentionPolicyRead {
  max_sessions: number;
  max_turns_per_session: number;
  max_events_per_session: number;
  storage_backend: string;
  db_filename: string;
}

export interface InvestigationFocusSnapshot {
  focus_revision: number;
  actor: InvestigationActor;
  client_id?: string | null;
  active_tab: string;
  selected_node_id?: string | null;
  selected_edge_id?: string | null;
  selected_finding_id?: string | null;
  hovered_node_id?: string | null;
  focused_district?: string | null;
  lens: string;
  layout_mode: string;
  blast_mode: string;
  diff_base_ref: string;
  has_snapshot?: boolean;
  snapshot_path?: string | null;
  snapshot_focus_revision?: number | null;
  snapshot_evidence_revision?: string | null;
  updated_at: string;
}

export interface InvestigationFollowUpdate {
  client_id?: string | null;
  actor?: InvestigationActor;
  follow_state: FollowState;
  reason?: string;
}

export interface InvestigationTurnCreate {
  client_id?: string | null;
  actor?: InvestigationActor;
  question: string;
  answer_markdown?: string | null;
  engine?: string | null;
  model_id?: string | null;
  used_vision?: boolean;
  image_supplied?: boolean;
  authored_by?: 'model' | 'scanner_brief' | 'none';
  fallback_reason?: string | null;
  failure_reason?: string | null;
  selected_node_id?: string | null;
  selected_edge_id?: string | null;
  selected_finding_id?: string | null;
  referenced_ids?: string[];
}

export interface InvestigationTurnRead {
  turn_id: string;
  session_id: string;
  client_id?: string | null;
  actor?: InvestigationActor;
  question: string;
  answer_markdown?: string | null;
  status?: 'answered' | 'unresolved';
  authored_by?: 'model' | 'scanner_brief' | 'none';
  engine?: string | null;
  model_id?: string | null;
  used_vision?: boolean;
  image_supplied?: boolean;
  fallback_reason?: string | null;
  failure_reason?: string | null;
  evidence_revision_id: string;
  focus_revision?: number;
  selected_node_id?: string | null;
  selected_edge_id?: string | null;
  selected_finding_id?: string | null;
  validated_references?: ValidatedReferenceRead[];
  needs_revalidation?: boolean;
  created_at: string;
}

export interface InvestigationDeltaEventRead {
  revision: number;
  session_id: string;
  event_kind: string;
  actor?: InvestigationActor;
  client_id?: string | null;
  summary: string;
  payload?: Record<string, unknown>;
  created_at: string;
}

export interface InvestigationDeltaEventsResponse {
  session_id: string;
  latest_revision: number;
  since_revision: number;
  events: InvestigationDeltaEventRead[];
}

export interface InvestigationCreateRequest {
  target_slug: string;
  session_id?: string | null;
  client_id?: string | null;
  title?: string | null;
}

export interface InvestigationSummaryRead {
  session_id: string;
  target_slug: string;
  title: string;
  follow_state?: FollowState;
  session_revision?: number;
  focus_revision?: number;
  pinned_evidence_revision_id: string;
  latest_evidence_revision_id: string;
  participating_client_ids?: string[];
  turn_count?: number;
  unresolved_question_count?: number;
  correction_count?: number;
  selected_node_id?: string | null;
  selected_edge_id?: string | null;
  selected_finding_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface InvestigationListResponse {
  sessions: InvestigationSummaryRead[];
  retention_policy?: RetentionPolicyRead;
}

export interface InvestigationSessionRead {
  session_id: string;
  target_slug: string;
  title: string;
  follow_state: FollowState;
  follow_reason?: string;
  session_revision: number;
  focus_revision: number;
  participating_client_ids: string[];
  pinned_evidence: EvidenceIdentityRead;
  latest_evidence: EvidenceIdentityRead;
  evidence_drifted: boolean;
  focus: InvestigationFocusSnapshot;
  turns: InvestigationTurnRead[];
  unresolved_questions: InvestigationTurnRead[];
  corrections: InvestigationCorrectionRead[];
  recent_receipts: ViewportCommandReceiptRead[];
  recent_events: InvestigationDeltaEventRead[];
  retention_policy: RetentionPolicyRead;
  permalink: string;
  created_at: string;
  updated_at: string;
}

export interface InvestigationRevisionComparisonRead {
  session_id: string;
  target_slug: string;
  pinned_evidence: EvidenceIdentityRead;
  current_evidence: EvidenceIdentityRead;
  digest_changed: boolean;
  surviving_refs: ValidatedReferenceRead[];
  vanished_refs: ValidatedReferenceRead[];
  modified_refs: ValidatedReferenceRead[];
  added_finding_ids: string[];
  resolved_finding_ids: string[];
  invalidated_turn_ids: string[];
  summary_markdown: string;
}

export interface InvestigationExportBundle {
  schema_version?: string;
  exported_at: string;
  session: InvestigationSessionRead;
  comparison?: InvestigationRevisionComparisonRead | null;
}

const SSE_DEV_UI_PORTS = new Set(['3000', '3180', '3780']);

function resolveSseApiBase(): string {
  if (process.env.NEXT_PUBLIC_WYTHE_API_URL) {
    return process.env.NEXT_PUBLIC_WYTHE_API_URL;
  }
  if (process.env.NEXT_PUBLIC_TRUTH_ATLAS_API_URL) {
    return process.env.NEXT_PUBLIC_TRUTH_ATLAS_API_URL;
  }
  if (typeof window !== 'undefined' && !SSE_DEV_UI_PORTS.has(window.location.port)) {
    return '/api/v1';
  }
  return 'http://127.0.0.1:8780/api/v1';
}

export const atlasApi = {
  listTargets: () => get<TargetProjectRead[]>('/targets'),
  registerTarget: (payload: TargetProjectCreate) =>
    post<TargetProjectRead>('/targets', payload),
  getGovernanceBundle: (targetSlug: string) =>
    get<PortableGovernanceBundle>(`/targets/${targetSlug}/governance-bundle`),
  syncGovernanceBundle: (targetSlug: string, direction: 'export' | 'import') =>
    post<GovernanceSyncReceipt>(
      `/targets/${targetSlug}/governance-sync?direction=${direction}`,
      {},
    ),

  getScan: (targetSlug: string) =>
    get<TruthAtlasReport>(`/scans/${targetSlug}`),
  triggerScan: (targetSlug: string) =>
    post<TruthAtlasReport>(`/scans/${targetSlug}`),
  getScanHistory: (targetSlug: string) =>
    get<ScanSnapshotSummary[]>(`/scans/${targetSlug}/history`),
  compareSnapshots: (targetSlug: string, baseId: number, headId: number) =>
    get<SnapshotComparisonReport>(
      `/scans/${targetSlug}/compare?base_id=${baseId}&head_id=${headId}`,
    ),
  getScanDiff: (targetSlug: string, baseRef: string) =>
    get<DiffBlastRadiusReport>(
      `/scans/${targetSlug}/diff?base_ref=${encodeURIComponent(baseRef)}`,
    ),
  getScanSarif: (targetSlug: string) =>
    get<Record<string, unknown>>(`/scans/${targetSlug}/sarif`),
  getScanOpenLineage: (targetSlug: string) =>
    get<OpenLineageBundleResponse>(`/scans/${targetSlug}/openlineage`),
  getScanLlmsBrief: (targetSlug: string) =>
    get<LlmBriefRead>(`/scans/${targetSlug}/llms`),
  getScanContextCone: (
    targetSlug: string,
    query: string,
    options?: { maxNodes?: number; full?: boolean; zoom?: 1 | 2 | 3; unfilteredIr?: boolean },
  ) => {
    const params = new URLSearchParams({ q: query });
    if (options?.maxNodes !== undefined) {
      params.set('max_nodes', String(options.maxNodes));
    }
    if (options?.full) {
      params.set('full', 'true');
    }
    if (options?.zoom !== undefined && options.zoom !== 1) {
      params.set('zoom', String(options.zoom));
    }
    if (options?.unfilteredIr) {
      params.set('unfiltered_ir', 'true');
    }
    return get<LlmContextConeReport>(`/scans/${targetSlug}/context?${params.toString()}`);
  },
  getNodeStrata: (
    targetSlug: string,
    nodeId: string,
    zoom: 2 | 3 = 2,
    unfilteredIr = false,
  ) =>
    get<StratumDrilldownRead>(
      `/scans/${targetSlug}/nodes/${encodeURIComponent(nodeId)}/strata?zoom=${zoom}&unfiltered_ir=${unfilteredIr}`,
    ),
  getScanSourceSnippet: (targetSlug: string, relPath: string, line = 1, context = 12) =>
    get<SourceSnippetRead>(
      `/scans/${targetSlug}/source?rel_path=${encodeURIComponent(relPath)}&line=${line}&context=${context}`,
    ),

  listBaselines: (targetSlug: string) =>
    get<RatchetBaselineRead[]>(`/scans/${targetSlug}/baselines`),
  captureBaselines: (targetSlug: string, payload: RatchetCaptureRequest) =>
    post<RatchetBaselineRead[]>(`/scans/${targetSlug}/baselines`, payload),

  listRules: () => get<RulePolicyRead[]>('/rules'),
  updateRule: (ruleCode: string, payload: RulePolicyUpdate) =>
    patch<RulePolicyRead>(`/rules/${ruleCode}`, payload),

  listRulings: (targetSlug: string) =>
    get<AuditRulingRead[]>(`/rulings/${targetSlug}`),
  createRuling: (targetSlug: string, payload: AuditRulingCreate) =>
    post<AuditRulingRead>(`/rulings/${targetSlug}`, payload),

  listAdapterSlots: () => get<AdapterSlotSchema[]>('/adapters/slots'),
  listPlugins: () => get<PluginListResponse>('/adapters/plugins'),
  listStackProfiles: () => get<StackProfileRead[]>('/adapters/profiles'),
  detectStack: (repoPath: string) =>
    get<StackDetectionResult>(`/adapters/detect?repo_path=${encodeURIComponent(repoPath)}`),

  listVocabularies: () => get<PolicyVocabularyRead[]>('/vocabularies'),
  createVocabulary: (payload: PolicyVocabularyCreate) =>
    post<PolicyVocabularyRead>('/vocabularies', payload),
  updateVocabulary: (vocabId: number, payload: PolicyVocabularyUpdate) =>
    patch<PolicyVocabularyRead>(`/vocabularies/${vocabId}`, payload),

  syncUiFocus: (payload: UiFocusStatePayload) =>
    post<UiFocusSyncAck>('/ui-focus', payload),
  getUiFocus: (
    targetSlug?: string,
    options?: {
      sessionId?: string | null;
      clientId?: string | null;
      actor?: InvestigationActor;
      selectedEdgeId?: string | null;
      selectedFindingId?: string | null;
      followState?: FollowState | null;
    },
  ) => {
    const params = new URLSearchParams();
    if (targetSlug) params.set('target', targetSlug);
    if (options?.sessionId) params.set('session_id', options.sessionId);
    if (options?.clientId) params.set('client_id', options.clientId);
    if (options?.actor) params.set('actor', options.actor);
    if (options?.selectedEdgeId) params.set('selected_edge_id', options.selectedEdgeId);
    if (options?.selectedFindingId) params.set('selected_finding_id', options.selectedFindingId);
    if (options?.followState) params.set('follow_state', options.followState);
    const qs = params.toString();
    return get<UiFocusExplainRead>(qs ? `/ui-focus?${qs}` : '/ui-focus');
  },

  listInvestigations: (targetSlug?: string) =>
    get<InvestigationListResponse>(
      targetSlug
        ? `/investigations?target_slug=${encodeURIComponent(targetSlug)}`
        : '/investigations',
    ),
  createOrReopenInvestigation: (payload: InvestigationCreateRequest) =>
    post<InvestigationSessionRead>('/investigations', payload),
  getInvestigation: (sessionId: string) =>
    get<InvestigationSessionRead>(`/investigations/${encodeURIComponent(sessionId)}`),
  addInvestigationCorrection: (
    sessionId: string,
    payload: InvestigationCorrectionCreate,
  ) =>
    post<InvestigationCorrectionRead>(
      `/investigations/${encodeURIComponent(sessionId)}/corrections`,
      payload,
    ),
  updateInvestigationFollow: (
    sessionId: string,
    payload: InvestigationFollowUpdate,
  ) =>
    post<InvestigationSessionRead>(
      `/investigations/${encodeURIComponent(sessionId)}/follow`,
      payload,
    ),
  recordInvestigationTurn: (sessionId: string, payload: InvestigationTurnCreate) =>
    post<InvestigationTurnRead>(
      `/investigations/${encodeURIComponent(sessionId)}/turns`,
      payload,
    ),
  getInvestigationEvents: (sessionId: string, sinceRevision = 0) =>
    get<InvestigationDeltaEventsResponse>(
      `/investigations/${encodeURIComponent(sessionId)}/events?since_revision=${sinceRevision}`,
    ),
  compareInvestigationRevisions: (sessionId: string) =>
    get<InvestigationRevisionComparisonRead>(
      `/investigations/${encodeURIComponent(sessionId)}/compare`,
    ),
  exportInvestigation: (sessionId: string) =>
    get<InvestigationExportBundle>(
      `/investigations/${encodeURIComponent(sessionId)}/export`,
    ),
  resetInvestigation: (sessionId: string) =>
    post<InvestigationSessionRead>(
      `/investigations/${encodeURIComponent(sessionId)}/reset`,
    ),
  deleteInvestigation: (sessionId: string) =>
    del<{ session_id: string; deleted: boolean }>(
      `/investigations/${encodeURIComponent(sessionId)}`,
    ),

  listAskEngines: (localBaseUrl?: string) =>
    get<AskEnginesRead>(
      localBaseUrl
        ? `/ask/engines?local_base_url=${encodeURIComponent(localBaseUrl)}`
        : '/ask/engines',
    ),
  askWythe: (payload: AskWytheRequest) =>
    post<AskWytheResponse>('/ask', payload),

  getMcpHttpManifest: () => get<Record<string, unknown>>('/mcp'),
  postMcpHttpRpc: (payload: Record<string, unknown>) =>
    post<Record<string, unknown>>('/mcp', payload),

  postViewportReceipt: (payload: ViewportCommandReceiptCreate) =>
    post<ViewportCommandReceiptRead>('/viewport/receipts', payload),
  listViewportReceipts: (options?: {
    targetSlug?: string;
    sessionId?: string;
    commandId?: string;
    limit?: number;
  }) => {
    const params = new URLSearchParams();
    if (options?.targetSlug) params.set('target_slug', options.targetSlug);
    if (options?.sessionId) params.set('session_id', options.sessionId);
    if (options?.commandId) params.set('command_id', options.commandId);
    if (options?.limit !== undefined) params.set('limit', String(options.limit));
    const qs = params.toString();
    return get<ViewportCommandReceiptRead[]>(
      qs ? `/viewport/receipts?${qs}` : '/viewport/receipts',
    );
  },
  getViewportState: (
    targetSlug: string,
    options?: {
      sessionId?: string;
      clientId?: string;
      actor?: InvestigationActor;
      selectedEdgeId?: string | null;
      selectedFindingId?: string | null;
      followState?: FollowState;
      sinceSeq?: number;
    },
  ) => {
    const params = new URLSearchParams({ target_slug: targetSlug });
    if (options?.sessionId) params.set('session_id', options.sessionId);
    if (options?.clientId) params.set('client_id', options.clientId);
    if (options?.actor) params.set('actor', options.actor);
    if (options?.selectedEdgeId) params.set('selected_edge_id', options.selectedEdgeId);
    if (options?.selectedFindingId) params.set('selected_finding_id', options.selectedFindingId);
    if (options?.followState) params.set('follow_state', options.followState);
    if (options?.sinceSeq !== undefined) params.set('since_seq', String(options.sinceSeq));
    return get<ViewportStateRead>(`/viewport/state?${params.toString()}`);
  },
  buildViewportEventsUrl: (
    targetSlug: string,
    options?: {
      sessionId?: string;
      clientId?: string;
      actor?: InvestigationActor;
      selectedEdgeId?: string | null;
      selectedFindingId?: string | null;
      followState?: FollowState;
      sinceSeq?: number;
    },
  ) => {
    const params = new URLSearchParams({ target_slug: targetSlug });
    if (options?.sessionId) params.set('session_id', options.sessionId);
    if (options?.clientId) params.set('client_id', options.clientId);
    if (options?.actor) params.set('actor', options.actor);
    if (options?.selectedEdgeId) params.set('selected_edge_id', options.selectedEdgeId);
    if (options?.selectedFindingId) params.set('selected_finding_id', options.selectedFindingId);
    if (options?.followState) params.set('follow_state', options.followState);
    if (options?.sinceSeq !== undefined) params.set('since_seq', String(options.sinceSeq));
    return `${resolveSseApiBase()}/viewport/stream?${params.toString()}`;
  },

  getUnderstandingExplain: (params: {
    targetSlug?: string;
    subjectId?: string;
    nodeId?: string;
    findingId?: string;
    edgeId?: string;
    sessionId?: string;
    exampleSlug?: string;
  }) => {
    const q = new URLSearchParams();
    if (params.targetSlug) q.set('target_slug', params.targetSlug);
    if (params.subjectId) q.set('subject_id', params.subjectId);
    if (params.nodeId) q.set('node_id', params.nodeId);
    if (params.findingId) q.set('finding_id', params.findingId);
    if (params.edgeId) q.set('edge_id', params.edgeId);
    if (params.sessionId) q.set('session_id', params.sessionId);
    if (params.exampleSlug) q.set('example_slug', params.exampleSlug);
    const qs = q.toString();
    return get<Record<string, unknown>>(
      qs ? `/understanding/explain?${qs}` : '/understanding/explain',
    );
  },
  listUnderstandingExamples: () =>
    get<Record<string, unknown>>('/understanding/examples'),
  getUnderstandingExample: (exampleSlug: string) =>
    get<Record<string, unknown>>(
      `/understanding/examples/${encodeURIComponent(exampleSlug)}`,
    ),
  analyzeUnderstandingBundle: (payload: Record<string, unknown>) =>
    post<Record<string, unknown>>('/understanding/analyze', payload),
};
