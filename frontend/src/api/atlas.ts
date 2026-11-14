/**
 * Strictly typed API client bound to OpenAPI-generated contracts (`api-generated.ts`).
 */

import { get, patch, post } from '@/lib/api';
import type { components } from '@/types/api-generated';

export type TruthAtlasReport = components['schemas']['TruthAtlasReport'];
export type AtlasNode = components['schemas']['AtlasNode'];
export type StorePurposeDeclaration = components['schemas']['StorePurposeDeclaration'];
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
export type UiFocusStatePayload = components['schemas']['UiFocusStatePayload'];
export type UiFocusSyncAck = components['schemas']['UiFocusSyncAck'];
export type UiFocusExplainRead = components['schemas']['UiFocusExplainRead'];
export type DistrictXraySummary = components['schemas']['DistrictXraySummary'];
export type OnDeviceEngineStatus = components['schemas']['OnDeviceEngineStatus'];
export type AskEnginesRead = components['schemas']['AskEnginesRead'];
export type AskChatTurn = components['schemas']['AskChatTurn'];
export type AskWytheRequest = components['schemas']['AskWytheRequest'];
export type AskWytheResponse = components['schemas']['AskWytheResponse'];

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
  getScanLlmsBrief: (targetSlug: string) =>
    get<LlmBriefRead>(`/scans/${targetSlug}/llms`),
  getScanContextCone: (
    targetSlug: string,
    query: string,
    options?: { maxNodes?: number; full?: boolean },
  ) => {
    const params = new URLSearchParams({ q: query });
    if (options?.maxNodes !== undefined) {
      params.set('max_nodes', String(options.maxNodes));
    }
    if (options?.full) {
      params.set('full', 'true');
    }
    return get<LlmContextConeReport>(`/scans/${targetSlug}/context?${params.toString()}`);
  },
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
  getUiFocus: (targetSlug?: string) =>
    get<UiFocusExplainRead>(
      targetSlug ? `/ui-focus?target=${encodeURIComponent(targetSlug)}` : '/ui-focus',
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
};
