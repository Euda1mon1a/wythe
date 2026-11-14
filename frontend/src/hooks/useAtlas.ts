/**
 * TanStack Query hooks for Truth Atlas read and audited-mutation flows.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  atlasApi,
  type AskWytheRequest,
  type AuditRulingCreate,
  type PolicyVocabularyCreate,
  type PolicyVocabularyUpdate,
  type RatchetCaptureRequest,
  type RulePolicyUpdate,
  type TargetProjectCreate,
  type UiFocusStatePayload,
} from '@/api/atlas';

export const atlasKeys = {
  targets: ['targets'] as const,
  scan: (slug: string) => ['scan', slug] as const,
  history: (slug: string) => ['history', slug] as const,
  compare: (slug: string, baseId: number, headId: number) =>
    ['compare', slug, baseId, headId] as const,
  diff: (slug: string, baseRef: string) => ['diff', slug, baseRef] as const,
  governanceBundle: (slug: string) => ['governance-bundle', slug] as const,
  baselines: (slug: string) => ['baselines', slug] as const,
  rules: ['rules'] as const,
  vocabularies: ['vocabularies'] as const,
  rulings: (slug: string) => ['rulings', slug] as const,
  source: (slug: string, relPath: string, line: number) =>
    ['source', slug, relPath, line] as const,
  slots: ['adapter-slots'] as const,
  profiles: ['stack-profiles'] as const,
};

export function useTargets() {
  return useQuery({
    queryKey: atlasKeys.targets,
    queryFn: () => atlasApi.listTargets(),
  });
}

export function useTargetScan(slug: string) {
  return useQuery({
    queryKey: atlasKeys.scan(slug),
    queryFn: () => atlasApi.getScan(slug),
    enabled: Boolean(slug),
  });
}

export function useScanHistory(slug: string) {
  return useQuery({
    queryKey: atlasKeys.history(slug),
    queryFn: () => atlasApi.getScanHistory(slug),
    enabled: Boolean(slug),
  });
}

export function useRules() {
  return useQuery({
    queryKey: atlasKeys.rules,
    queryFn: () => atlasApi.listRules(),
  });
}

export function useAdapterSlots() {
  return useQuery({
    queryKey: atlasKeys.slots,
    queryFn: () => atlasApi.listAdapterSlots(),
  });
}

export function useStackProfiles() {
  return useQuery({
    queryKey: atlasKeys.profiles,
    queryFn: () => atlasApi.listStackProfiles(),
  });
}

export function useTriggerScan(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => atlasApi.triggerScan(slug),
    onSuccess: (fresh) => {
      qc.setQueryData(atlasKeys.scan(slug), fresh);
      void qc.invalidateQueries({ queryKey: atlasKeys.history(slug) });
    },
  });
}

export function useUpdateRule(activeSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ code, payload }: { code: string; payload: RulePolicyUpdate }) =>
      atlasApi.updateRule(code, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.rules });
      if (activeSlug) {
        void qc.invalidateQueries({ queryKey: atlasKeys.scan(activeSlug) });
      }
    },
  });
}

export function useCreateRuling(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: AuditRulingCreate) => atlasApi.createRuling(slug, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.rulings(slug) });
      void qc.invalidateQueries({ queryKey: atlasKeys.scan(slug) });
    },
  });
}

export function useCaptureRatchet(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: RatchetCaptureRequest) =>
      atlasApi.captureBaselines(slug, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.baselines(slug) });
      void qc.invalidateQueries({ queryKey: atlasKeys.scan(slug) });
    },
  });
}

export function useRegisterTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: TargetProjectCreate) => atlasApi.registerTarget(payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.targets });
    },
  });
}

export function useDetectStack() {
  return useMutation({
    mutationFn: (repoPath: string) => atlasApi.detectStack(repoPath),
  });
}

export function useVocabularies() {
  return useQuery({
    queryKey: atlasKeys.vocabularies,
    queryFn: () => atlasApi.listVocabularies(),
  });
}

export function useCreateVocabulary(activeSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: PolicyVocabularyCreate) => atlasApi.createVocabulary(payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.vocabularies });
      if (activeSlug) {
        void qc.invalidateQueries({ queryKey: atlasKeys.scan(activeSlug) });
      }
    },
  });
}

export function useUpdateVocabulary(activeSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: PolicyVocabularyUpdate }) =>
      atlasApi.updateVocabulary(id, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.vocabularies });
      if (activeSlug) {
        void qc.invalidateQueries({ queryKey: atlasKeys.scan(activeSlug) });
      }
    },
  });
}

export function useScanDiff(slug: string, baseRef: string) {
  return useQuery({
    queryKey: atlasKeys.diff(slug, baseRef),
    queryFn: () => atlasApi.getScanDiff(slug, baseRef),
    enabled: Boolean(slug && baseRef),
  });
}

export function useCompareSnapshots(
  slug: string,
  baseId: number | null,
  headId: number | null,
) {
  return useQuery({
    queryKey: atlasKeys.compare(slug, baseId ?? 0, headId ?? 0),
    queryFn: () => atlasApi.compareSnapshots(slug, baseId!, headId!),
    enabled: Boolean(slug && baseId && headId && baseId !== headId),
  });
}

export function useGovernanceBundle(slug: string) {
  return useQuery({
    queryKey: atlasKeys.governanceBundle(slug),
    queryFn: () => atlasApi.getGovernanceBundle(slug),
    enabled: Boolean(slug),
  });
}

export function useSyncGovernanceBundle(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (direction: 'export' | 'import') =>
      atlasApi.syncGovernanceBundle(slug, direction),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: atlasKeys.governanceBundle(slug) });
      void qc.invalidateQueries({ queryKey: atlasKeys.rules });
      void qc.invalidateQueries({ queryKey: atlasKeys.vocabularies });
      void qc.invalidateQueries({ queryKey: atlasKeys.scan(slug) });
    },
  });
}

export function useDownloadSarif(slug: string) {
  return useMutation({
    mutationFn: () => atlasApi.getScanSarif(slug),
  });
}

export function useFetchLlmsBrief(slug: string) {
  return useMutation({
    mutationFn: () => atlasApi.getScanLlmsBrief(slug),
  });
}

export function useFetchContextCone(slug: string) {
  return useMutation({
    mutationFn: (input: string | { query: string; maxNodes?: number; full?: boolean }) =>
      typeof input === 'string'
        ? atlasApi.getScanContextCone(slug, input)
        : atlasApi.getScanContextCone(slug, input.query, {
            maxNodes: input.maxNodes,
            full: input.full,
          }),
  });
}

export function useSourceSnippet(slug: string, relPath: string, line: number, enabled = true) {
  return useQuery({
    queryKey: atlasKeys.source(slug, relPath, line),
    queryFn: () => atlasApi.getScanSourceSnippet(slug, relPath, line, 12),
    enabled: Boolean(slug && relPath && enabled),
  });
}

export function useSyncUiFocus() {
  return useMutation({
    mutationFn: (payload: UiFocusStatePayload) => atlasApi.syncUiFocus(payload),
  });
}

export function useFetchUiFocus() {
  return useMutation({
    mutationFn: (targetSlug?: string) => atlasApi.getUiFocus(targetSlug),
  });
}

export function useAskEngines(localBaseUrl?: string, enabled = true) {
  return useQuery({
    queryKey: ['ask-engines', localBaseUrl ?? ''] as const,
    queryFn: () => atlasApi.listAskEngines(localBaseUrl || undefined),
    enabled,
  });
}

export function useAskWythe() {
  return useMutation({
    mutationFn: (payload: AskWytheRequest) => atlasApi.askWythe(payload),
  });
}
