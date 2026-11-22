'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Bot, Copy, Cpu, Download, Eye, RefreshCw, Send, Sparkles, Trash2, X } from 'lucide-react';
import {
  atlasApi,
  type AskChatTurn,
  type AskExecutionOrigin,
  type AtlasNode,
  type ContextBudgetSummary,
  type FollowState,
  type InvestigationCorrectionRead,
  type InvestigationRevisionComparisonRead,
  type InvestigationSessionRead,
  type InvestigationTurnRead,
  type UiFocusExplainRead,
  type UiFocusStatePayload,
  type ValidatedReferenceRead,
} from '@/api/atlas';
import {
  ChallengeCorrectionBox,
  RevisionComparisonPanel,
  ValidatedReferencesList,
} from '@/components/InvestigationCollabControls';
import { UnderstandingChainPanel } from '@/components/UnderstandingChainPanel';
import { useAskEngines, useAskWythe } from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import { useDialogFocusTrap } from '@/lib/wytheDialogFocus';
import { resolveTabInvestigationIdentity } from '@/lib/wytheInvestigationSession';
import type { LiveViewportDigest } from '@/lib/wytheVisionBridge';
import {
  bumpViewportCameraRevision,
  isLoopbackClientUrl,
  normalizeClientV1Url,
  probeBrowserLocalOpenAi,
  probeChromeBuiltInModel,
  runBrowserLocalOpenAiAsk,
  runChromeBuiltInAsk,
  triggerChromeModelDownload,
  type BrowserLocalOpenAiProbe,
  type ChromeEngineProbe,
} from '@/lib/wytheBrowserAi';

let monotonicDrawerCameraRevision = 0;

export type SelectedEngineChoice = 'auto' | 'apple' | 'chrome' | 'local';

const MCP_TOOL_INTENT_RE =
  /\b(?:mcp|wythe_[a-z0-9_]+|atlas_[a-z0-9_]+|tools?|camera|viewport|focus|fly|move|steer|pan|orbit|tour|walkthrough|chronicle|lens|layout|filter(?:s|ed|ing)?|flagged|only[-_ ]?flagged|flagged[-_ ]?only|isolat(?:e|ed|ing|ion)|cone|salien(?:ce|t)|tier|subkind|working[-_ ]?set|compact|flatten|flat\s*2d|group[-_ ]?by|reset(?:\s+filters?)?|select|highlight|zoom|strat(?:um|a)|frustum|unshown|off[- ]?screen|outside|blast(?:\s+|[-_])radius|lineage(?:\s+|[-_])cone|plugins?|show\s+me|delet(?:e|ed|ing|ion)|remov(?:e|ed|ing)|affect(?:s|ed)?|break(?:s|ing)?|broken|callers?|who\s+calls|used\s+by)\b/i;

function questionRequestsMcpTools(question: string): boolean {
  return MCP_TOOL_INTENT_RE.test(question.trim());
}

interface QaTurn {
  id: string;
  question: string;
  answerMarkdown: string | null;
  status: 'answered' | 'unresolved';
  authoredBy: 'model' | 'scanner_brief' | 'none';
  engineBadge: string;
  executionOrigin: AskExecutionOrigin | null;
  endpointOrigin: string | null;
  requestedModelId: string | null;
  resolvedModelId: string | null;
  fallbackFrom: string | null;
  executedTools: string[];
  usedVision: boolean;
  imageSupplied: boolean;
  fallbackReason: string | null;
  failureReason: string | null;
  referencedNodeIds: string[];
  validatedReferences: ValidatedReferenceRead[];
  contextBudget: ContextBudgetSummary | null;
  evidenceRevisionId: string | null;
  needsRevalidation: boolean;
}

interface AskWytheDrawerProps {
  open: boolean;
  activeSlug: string;
  sessionId?: string | null;
  clientId?: string | null;
  followState?: FollowState;
  selectedNodeId?: string | null;
  selectedFindingId?: string | null;
  selectedEdgeId?: string | null;
  sessionData?: InvestigationSessionRead | null;
  revisionComparison?: InvestigationRevisionComparisonRead | null;
  explanation: UiFocusExplainRead | null;
  liveDigest?: LiveViewportDigest | null;
  snapshotDataUrl: string | null;
  captureLiveWebp?: () => string | null;
  nodesById: Map<string, AtlasNode>;
  initialQuestion?: string;
  onSessionMutated?: () => void;
  onCorrectionAdded?: (created: InvestigationCorrectionRead) => void;
  onCompareRevisions?: () => Promise<void>;
  onRefreshFocus: () => void;
  onSelectNode: (nodeId: string) => void;
  onClose: () => void;
}

function mapStoredTurnToQaTurn(
  t: InvestigationTurnRead,
  latestEvidenceRevisionId?: string | null,
): QaTurn {
  const isScannerBrief = t.authored_by === 'scanner_brief';
  const isUnresolved = t.status === 'unresolved' || t.authored_by === 'none' || !t.answer_markdown;
  const engineBadge = isScannerBrief
    ? 'Scanner Brief (no model running)'
    : isUnresolved
      ? 'Model Unavailable (question preserved)'
      : `${t.engine ?? 'local'} · ${t.model_id ?? 'model'}`;
  const drifted = Boolean(
    latestEvidenceRevisionId &&
      t.evidence_revision_id &&
      t.evidence_revision_id !== latestEvidenceRevisionId,
  );
  return {
    id: t.turn_id,
    question: t.question,
    answerMarkdown: t.answer_markdown ?? null,
    status: isUnresolved ? 'unresolved' : 'answered',
    authoredBy: t.authored_by ?? (isUnresolved ? 'none' : 'model'),
    engineBadge,
    executionOrigin: null,
    endpointOrigin: null,
    requestedModelId: t.model_id ?? null,
    resolvedModelId: t.model_id ?? null,
    fallbackFrom: null,
    executedTools: [],
    usedVision: Boolean(t.used_vision),
    imageSupplied: Boolean(t.image_supplied),
    fallbackReason: t.fallback_reason ?? null,
    failureReason: t.failure_reason ?? null,
    referencedNodeIds: (t.validated_references ?? [])
      .filter((r) => r.kind === 'node' && r.validation_state !== 'vanished_in_current_scan')
      .map((r) => r.ref_id),
    validatedReferences: t.validated_references ?? [],
    contextBudget: null,
    evidenceRevisionId: t.evidence_revision_id ?? null,
    needsRevalidation: Boolean(t.needs_revalidation || drifted),
  };
}

const PRESET_QUESTIONS = [
  'What is this cluster and why is it colored like this?',
  'What breaks across the 3 tiers if I refactor this?',
  'How do I fix the top boundary finding cleanly?',
  'Summarize upstream routes and downstream SQL tables here.',
];

function renderInlineMarkdown(line: string) {
  const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={idx} className="font-semibold text-teal-200">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={idx}
          className="border border-slate-700 bg-slate-950 px-1 py-0.5 font-mono text-[11px] text-sky-200"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={idx}>{part}</span>;
  });
}

function renderFormattedAnswer(md: string) {
  const lines = md.split('\n');
  return lines.map((raw, idx) => {
    const trimmed = raw.trim();
    if (!trimmed) return <div key={idx} className="h-1.5" />;
    if (/^#{1,4}\s+/.test(trimmed)) {
      const heading = trimmed.replace(/^#{1,4}\s+/, '');
      return (
        <div key={idx} className="pt-1 font-mono text-xs font-semibold text-teal-300">
          {renderInlineMarkdown(heading)}
        </div>
      );
    }
    if (trimmed.startsWith('>')) {
      const quoteText = trimmed.replace(/^>\s*/, '');
      return (
        <div
          key={idx}
          className="border-l-2 border-amber-400/80 bg-amber-950/35 px-2.5 py-1.5 text-amber-100"
        >
          {renderInlineMarkdown(quoteText)}
        </div>
      );
    }
    if (/^[-*]\s+/.test(trimmed)) {
      return (
        <div key={idx} className="pl-3 leading-relaxed text-slate-100">
          <span className="mr-1.5 text-teal-300">•</span>
          {renderInlineMarkdown(trimmed.replace(/^[-*]\s+/, ''))}
        </div>
      );
    }
    return (
      <div key={idx} className="leading-relaxed text-slate-100">
        {renderInlineMarkdown(raw)}
      </div>
    );
  });
}

function matchReferencedNodeIds(
  answerMarkdown: string,
  focusedNodeId: string | null,
  nodesById: Map<string, AtlasNode>,
): string[] {
  const matched: string[] = [];
  if (focusedNodeId) {
    matched.push(focusedNodeId);
  }
  const lowAns = answerMarkdown.toLowerCase();
  for (const node of nodesById.values()) {
    if (matched.length >= 6) break;
    if (matched.includes(node.id)) continue;
    const idLow = node.id.toLowerCase();
    const lblLow = node.label.toLowerCase();
    const isCodeIdentifier =
      lblLow.includes('_') || lblLow.includes('/') || lblLow.includes(':');
    if (
      lowAns.includes(idLow) ||
      lowAns.includes(`\`${lblLow}\``) ||
      (isCodeIdentifier && lblLow.length >= 5 && lowAns.includes(lblLow))
    ) {
      matched.push(node.id);
    }
  }
  return matched;
}

export function AskWytheDrawer({
  open,
  activeSlug,
  sessionId = null,
  clientId = null,
  followState = 'following',
  selectedNodeId = null,
  selectedFindingId = null,
  selectedEdgeId = null,
  sessionData = null,
  revisionComparison = null,
  explanation,
  liveDigest = null,
  snapshotDataUrl,
  captureLiveWebp,
  nodesById,
  initialQuestion = '',
  onSessionMutated,
  onCorrectionAdded,
  onCompareRevisions,
  onRefreshFocus,
  onSelectNode,
  onClose,
}: AskWytheDrawerProps) {
  const [engineChoice, setEngineChoice] = useState<SelectedEngineChoice>('auto');
  const [customLocalUrl, setCustomLocalUrl] = useState('');
  const [showLocalConfig, setShowLocalConfig] = useState(false);
  const [keepSession, setKeepSession] = useState(true);
  const [question, setQuestion] = useState(initialQuestion);
  const [chromeProbe, setChromeProbe] = useState<ChromeEngineProbe>({
    state: 'unavailable',
    supportsVision: false,
    note: 'Probing Chrome LanguageModel…',
  });
  const [browserLocalProbe, setBrowserLocalProbe] = useState<BrowserLocalOpenAiProbe>({
    state: 'unavailable',
    baseUrl: null,
    requestModelId: null,
    displayModel: null,
    supportsVision: false,
    note: 'Probing browser-local /v1…',
  });
  const [chromeDownloadPct, setChromeDownloadPct] = useState<number | null>(null);
  const [turns, setTurns] = useState<QaTurn[]>([]);
  const [activeError, setActiveError] = useState<string | null>(null);
  const [isRunningClientModel, setIsRunningClientModel] = useState(false);
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);
  const containerRef = useRef<HTMLElement>(null);

  useDialogFocusTrap({
    open,
    containerRef,
    onClose,
  });

  const [debouncedCustomUrl, setDebouncedCustomUrl] = useState('');
  useEffect(() => {
    const trimmed = customLocalUrl.trim();
    const t = window.setTimeout(() => setDebouncedCustomUrl(trimmed), 280);
    return () => window.clearTimeout(t);
  }, [customLocalUrl]);

  const { data: backendEngines, refetch: refetchEngines } = useAskEngines(
    debouncedCustomUrl || undefined,
    open,
  );
  const askBackend = useAskWythe();

  useEffect(() => {
    if (initialQuestion) setQuestion(initialQuestion);
  }, [initialQuestion]);

  const fallbackIdentity =
    (!sessionId || !clientId) && activeSlug && typeof window !== 'undefined'
      ? resolveTabInvestigationIdentity({ targetSlug: activeSlug })
      : null;
  const effectiveSessionId = sessionId || fallbackIdentity?.sessionId || null;
  const effectiveClientId = clientId || fallbackIdentity?.clientId || null;

  useEffect(() => {
    setTurns([]);
    setActiveError(null);
  }, [activeSlug, effectiveSessionId]);

  useEffect(() => {
    if (!sessionData) {
      setTurns([]);
      setActiveError(null);
      return;
    }
    if (sessionData.target_slug && activeSlug && sessionData.target_slug !== activeSlug) {
      return;
    }
    const latestRev = sessionData.latest_evidence?.evidence_revision_id ?? null;
    const combined: InvestigationTurnRead[] = [...sessionData.turns];
    const seenIds = new Set(combined.map((t) => t.turn_id));
    for (const unres of sessionData.unresolved_questions ?? []) {
      if (!seenIds.has(unres.turn_id)) {
        combined.push(unres);
        seenIds.add(unres.turn_id);
      }
    }
    setTurns((prev) => {
      const prevById = new Map(prev.map((item) => [item.id, item]));
      return [...combined].reverse().map((t) => {
        const mapped = mapStoredTurnToQaTurn(t, latestRev);
        const existing = prevById.get(t.turn_id);
        if (!existing) return mapped;
        return {
          ...mapped,
          engineBadge: existing.engineBadge || mapped.engineBadge,
          executionOrigin: existing.executionOrigin ?? mapped.executionOrigin,
          endpointOrigin: existing.endpointOrigin ?? mapped.endpointOrigin,
          requestedModelId: existing.requestedModelId ?? mapped.requestedModelId,
          resolvedModelId: existing.resolvedModelId ?? mapped.resolvedModelId,
          fallbackFrom: existing.fallbackFrom ?? mapped.fallbackFrom,
          executedTools:
            existing.executedTools.length > 0 ? existing.executedTools : mapped.executedTools,
          contextBudget: existing.contextBudget ?? mapped.contextBudget,
        };
      });
    });
  }, [sessionData]);

  const syncCapturedWebpToUiFocus = async (webpDataUrl: string | null): Promise<void> => {
    if (!activeSlug || !webpDataUrl || !webpDataUrl.startsWith('data:image/')) return;
    const knownServerRev =
      Number((explanation as { camera_revision?: number | null } | null)?.camera_revision ?? 0) || 0;
    monotonicDrawerCameraRevision = bumpViewportCameraRevision(knownServerRev);
    const syncPayload: Partial<UiFocusStatePayload> & {
      active_slug: string;
      camera_revision: number;
      snapshot_data_url: string;
    } = {
      active_slug: activeSlug,
      session_id: effectiveSessionId,
      client_id: effectiveClientId,
      actor: 'human',
      selected_edge_id: selectedEdgeId,
      selected_finding_id: selectedFindingId,
      follow_state: followState,
      camera_revision: monotonicDrawerCameraRevision,
      snapshot_data_url: webpDataUrl,
      ...(liveDigest?.selectedNodeId !== undefined
        ? { selected_node_id: liveDigest.selectedNodeId }
        : selectedNodeId
          ? { selected_node_id: selectedNodeId }
          : {}),
      ...(liveDigest?.hoveredNodeId !== undefined ? { hovered_node_id: liveDigest.hoveredNodeId } : {}),
      ...(liveDigest?.lens ? { lens: liveDigest.lens } : {}),
      ...(liveDigest?.layoutMode ? { layout_mode: liveDigest.layoutMode } : {}),
      ...(liveDigest?.visibleNodeCount !== undefined ? { visible_node_count: liveDigest.visibleNodeCount } : {}),
      ...(liveDigest?.inFrustumCount !== undefined ? { in_frustum_count: liveDigest.inFrustumCount } : {}),
      ...(liveDigest?.summaryPill ? { visual_headline: liveDigest.summaryPill } : {}),
      ...(liveDigest?.markdownBrief ? { live_viewport_brief: liveDigest.markdownBrief } : {}),
    };
    try {
      await atlasApi.syncUiFocus(syncPayload as UiFocusStatePayload);
    } catch {
      // Keep zero-backend Chrome mode working when server is offline
    }
  };

  useEffect(() => {
    if (!open) return;
    void probeChromeBuiltInModel().then(setChromeProbe);
    const initialWebp = captureLiveWebp?.() ?? null;
    if (initialWebp) {
      void syncCapturedWebpToUiFocus(initialWebp).then(() => onRefreshFocus());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) return;
    void probeBrowserLocalOpenAi(debouncedCustomUrl || undefined, true).then(setBrowserLocalProbe);
  }, [open, debouncedCustomUrl]);

  if (!open) return null;

  const appleSt = (backendEngines?.engines ?? []).find((e) => e.engine === 'apple');
  const localSt = (backendEngines?.engines ?? []).find((e) => e.engine === 'local');
  const anyLocalReady = browserLocalProbe.state === 'ready' || localSt?.state === 'ready';
  const localStatusLabel =
    browserLocalProbe.state === 'ready'
      ? isLoopbackClientUrl(browserLocalProbe.baseUrl)
        ? 'ready · loopback'
        : 'ready · private /v1'
      : localSt?.state === 'ready'
        ? 'ready · server'
        : (localSt?.state ?? '…');
  const isBusy = askBackend.isPending || isRunningClientModel;

  const copyEndpoint = (kind: 'mcp' | 'openapi') => {
    const origin = typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:8780';
    const url = kind === 'mcp' ? `${origin}/api/v1/mcp` : `${origin}/openapi.json`;
    void copyTextToClipboard(url).then((ok) => {
      if (ok) {
        setCopiedEndpoint(kind);
        window.setTimeout(() => setCopiedEndpoint(null), 1800);
      }
    });
  };

  const persistClientTurn = async (payload: {
    question: string;
    answerMarkdown: string | null;
    engine: string | null;
    modelId: string | null;
    usedVision: boolean;
    imageSupplied: boolean;
    authoredBy: 'model' | 'scanner_brief' | 'none';
    failureReason?: string | null;
    referencedIds?: string[];
  }) => {
    if (!effectiveSessionId) return;
    try {
      await atlasApi.recordInvestigationTurn(effectiveSessionId, {
        client_id: effectiveClientId ?? undefined,
        actor: 'human',
        question: payload.question,
        answer_markdown: payload.answerMarkdown,
        engine: payload.engine,
        model_id: payload.modelId,
        used_vision: payload.usedVision,
        image_supplied: payload.imageSupplied,
        authored_by: payload.authoredBy,
        failure_reason: payload.failureReason ?? undefined,
        selected_node_id: selectedNodeId ?? undefined,
        selected_edge_id: selectedEdgeId ?? undefined,
        selected_finding_id: selectedFindingId ?? undefined,
        referenced_ids: payload.referencedIds ?? [],
      });
      onSessionMutated?.();
    } catch {
      // Keep client-side mode resilient when server is offline
    }
  };

  const insertScannerBriefNow = async () => {
    const q = question.trim() || 'Inspect scanner evidence for the current selection';
    const briefMd =
      explanation?.markdown_brief ??
      liveDigest?.markdownBrief ??
      `Target: ${activeSlug} (scanner brief)`;
    const refIds = selectedNodeId ? [selectedNodeId] : [];
    setTurns((prev) => [
      {
        id: `scanner-${Date.now()}`,
        question: q,
        answerMarkdown: briefMd,
        status: 'answered',
        authoredBy: 'scanner_brief',
        engineBadge: 'Scanner Brief (no model running)',
        executionOrigin: 'browser_client',
        endpointOrigin: null,
        requestedModelId: 'wythe-scanner-brief',
        resolvedModelId: 'wythe-scanner-brief',
        fallbackFrom: null,
        executedTools: [],
        usedVision: false,
        imageSupplied: false,
        fallbackReason: 'Generated directly from deterministic scanner facts without a running LLM.',
        failureReason: null,
        referencedNodeIds: refIds,
        validatedReferences: [],
        contextBudget: explanation?.context_budget ?? null,
        evidenceRevisionId: explanation?.evidence_revision_id ?? null,
        needsRevalidation: false,
      },
      ...prev,
    ]);
    await persistClientTurn({
      question: q,
      answerMarkdown: briefMd,
      engine: 'none',
      modelId: 'wythe-scanner-brief',
      usedVision: false,
      imageSupplied: false,
      authoredBy: 'scanner_brief',
      referencedIds: refIds,
    });
  };

  const runQuestion = async (rawQ: string) => {
    const trimmed = rawQ.trim();
    if (!trimmed || isBusy) return;
    setActiveError(null);

    const capturedWebp = captureLiveWebp?.() ?? null;
    if (capturedWebp) {
      await syncCapturedWebpToUiFocus(capturedWebp);
    }
    const liveFrameUrl = capturedWebp ?? snapshotDataUrl;
    const hasAttachedFrame = Boolean(liveFrameUrl);
    const liveBrief = liveDigest
      ? `${liveDigest.markdownBrief}\n\n${explanation?.markdown_brief ?? ''}`.trim()
      : (explanation?.markdown_brief ?? `Target: ${activeSlug}`);
    const focusedNodeId =
      selectedNodeId ??
      explanation?.focused_node?.id ??
      (liveDigest?.referencedNodeIds && liveDigest.referencedNodeIds.length > 0
        ? liveDigest.referencedNodeIds[0]
        : null);
    const sessionHistory: AskChatTurn[] = keepSession
      ? [...turns]
          .filter((t) => t.status === 'answered' && Boolean(t.answerMarkdown))
          .reverse()
          .slice(-6)
          .flatMap((t) => [
            { role: 'user' as const, content: t.question },
            { role: 'assistant' as const, content: t.answerMarkdown! },
          ])
      : [];

    const anyVlmReady =
      (chromeProbe.state === 'ready' && chromeProbe.supportsVision) ||
      (browserLocalProbe.state === 'ready' && browserLocalProbe.supportsVision) ||
      Boolean(localSt?.state === 'ready' && localSt.supports_vision);

    const localServerPinned = Boolean(
      localSt?.state === 'ready' && localSt.model_id && localSt.model_id !== 'default_model',
    );
    const prefersServerMcp =
      Boolean(localSt?.state === 'ready') &&
      (localServerPinned || questionRequestsMcpTools(trimmed));

    const useChrome =
      engineChoice === 'chrome' ||
      (engineChoice === 'auto' &&
        !prefersServerMcp &&
        chromeProbe.state === 'ready' &&
        ((hasAttachedFrame && chromeProbe.supportsVision) ||
          (!anyVlmReady && appleSt?.state !== 'ready')));

    let clientFallbackFrom: string | null = null;
    if (useChrome) {
      setIsRunningClientModel(true);
      try {
        const out = await runChromeBuiltInAsk({
          question: trimmed,
          xrayBrief: liveBrief,
          snapshotDataUrl: liveFrameUrl,
          history: sessionHistory,
        });
        const refs = matchReferencedNodeIds(out.answerMarkdown, focusedNodeId, nodesById);
        const turnUsedVision = Boolean(out.used_vision_snapshot ?? out.usedVision);
        setTurns((prev) => [
          {
            id: `turn-${prev.length + 1}`,
            question: trimmed,
            answerMarkdown: out.answerMarkdown,
            status: 'answered',
            authoredBy: 'model',
            engineBadge: `chrome · ${out.resolved_model_id ?? 'gemini-nano-in-browser'}`,
            executionOrigin: out.execution_origin,
            endpointOrigin: out.endpoint_origin,
            requestedModelId: out.requested_model_id,
            resolvedModelId: out.resolved_model_id,
            fallbackFrom: out.fallback_from,
            executedTools: [],
            usedVision: turnUsedVision,
            imageSupplied: hasAttachedFrame,
            fallbackReason:
              hasAttachedFrame && !turnUsedVision
                ? 'Viewport WebP available, but Chrome model answered in text-only mode.'
                : null,
            failureReason: null,
            referencedNodeIds: refs,
            validatedReferences: [],
            contextBudget: explanation?.context_budget ?? null,
            evidenceRevisionId: explanation?.evidence_revision_id ?? null,
            needsRevalidation: false,
          },
          ...prev,
        ]);
        void persistClientTurn({
          question: trimmed,
          answerMarkdown: out.answerMarkdown,
          engine: 'chrome',
          modelId: out.resolved_model_id ?? 'gemini-nano-in-browser',
          usedVision: turnUsedVision,
          imageSupplied: hasAttachedFrame,
          authoredBy: 'model',
          referencedIds: refs,
        });
        setQuestion('');
        setIsRunningClientModel(false);
        return;
      } catch (err) {
        setIsRunningClientModel(false);
        if (engineChoice === 'chrome') {
          const msg = (err as Error).message;
          setActiveError(msg);
          void persistClientTurn({
            question: trimmed,
            answerMarkdown: null,
            engine: 'chrome',
            modelId: null,
            usedVision: false,
            imageSupplied: hasAttachedFrame,
            authoredBy: 'none',
            failureReason: msg,
          });
          return;
        }
        clientFallbackFrom = 'chrome';
      }
    }

    let normalizedCustomUrl: string | undefined;
    if (customLocalUrl.trim()) {
      try {
        normalizedCustomUrl = normalizeClientV1Url(customLocalUrl);
      } catch (err) {
        if (engineChoice === 'local' || engineChoice === 'auto') {
          setActiveError((err as Error).message);
          return;
        }
      }
    }

    const customMatchesProbe =
      !normalizedCustomUrl || browserLocalProbe.baseUrl === normalizedCustomUrl;
    const useBrowserLocal =
      localSt?.state !== 'ready' &&
      !questionRequestsMcpTools(trimmed) &&
      browserLocalProbe.state === 'ready' &&
      customMatchesProbe &&
      (engineChoice === 'local' ||
        (engineChoice === 'auto' &&
          ((hasAttachedFrame && browserLocalProbe.supportsVision) ||
            (!anyVlmReady && appleSt?.state !== 'ready' && chromeProbe.state !== 'ready'))));

    if (useBrowserLocal) {
      setIsRunningClientModel(true);
      try {
        const out = await runBrowserLocalOpenAiAsk({
          probe: browserLocalProbe,
          question: trimmed,
          xrayBrief: liveBrief,
          snapshotDataUrl: liveFrameUrl,
          history: sessionHistory,
        });
        const dispModel = out.resolved_model_id ?? browserLocalProbe.displayModel ?? 'default_model';
        const refs = matchReferencedNodeIds(out.answerMarkdown, focusedNodeId, nodesById);
        const turnUsedVision = Boolean(out.used_vision_snapshot ?? out.usedVision);
        const turnFallbackFrom = out.fallback_from ?? clientFallbackFrom;
        setTurns((prev) => [
          {
            id: `turn-${prev.length + 1}`,
            question: trimmed,
            answerMarkdown: out.answerMarkdown,
            status: 'answered',
            authoredBy: 'model',
            engineBadge: `local · ${dispModel}`,
            executionOrigin: out.execution_origin,
            endpointOrigin: out.endpoint_origin,
            requestedModelId: out.requested_model_id,
            resolvedModelId: out.resolved_model_id,
            fallbackFrom: turnFallbackFrom,
            executedTools: [],
            usedVision: turnUsedVision,
            imageSupplied: hasAttachedFrame,
            fallbackReason:
              hasAttachedFrame && !turnUsedVision
                ? 'Viewport WebP available, but local /v1 model answered in text-only mode.'
                : null,
            failureReason: null,
            referencedNodeIds: refs,
            validatedReferences: [],
            contextBudget: explanation?.context_budget ?? null,
            evidenceRevisionId: explanation?.evidence_revision_id ?? null,
            needsRevalidation: false,
          },
          ...prev,
        ]);
        void persistClientTurn({
          question: trimmed,
          answerMarkdown: out.answerMarkdown,
          engine: 'local',
          modelId: dispModel,
          usedVision: turnUsedVision,
          imageSupplied: hasAttachedFrame,
          authoredBy: 'model',
          referencedIds: refs,
        });
        setQuestion('');
        setIsRunningClientModel(false);
        return;
      } catch (err) {
        setIsRunningClientModel(false);
        if (localSt?.state !== 'ready') {
          const msg = (err as Error).message;
          setActiveError(msg);
          void persistClientTurn({
            question: trimmed,
            answerMarkdown: null,
            engine: 'local',
            modelId: browserLocalProbe.displayModel,
            usedVision: false,
            imageSupplied: hasAttachedFrame,
            authoredBy: 'none',
            failureReason: msg,
          });
          return;
        }
        clientFallbackFrom = clientFallbackFrom ?? 'browser_local';
      }
    }

    askBackend.mutate(
      {
        question: trimmed,
        engine: engineChoice,
        target_slug: activeSlug || undefined,
        session_id: effectiveSessionId ?? undefined,
        client_id: effectiveClientId ?? undefined,
        selected_node_id: focusedNodeId ?? undefined,
        selected_finding_id: selectedFindingId ?? undefined,
        selected_edge_id: selectedEdgeId ?? undefined,
        local_base_url: normalizedCustomUrl || customLocalUrl.trim() || undefined,
        include_vision_snapshot: true,
        history: sessionHistory,
        live_viewport_brief: liveDigest?.markdownBrief ?? undefined,
        snapshot_data_url: liveFrameUrl ?? undefined,
      },
      {
        onSuccess: (res) => {
          const isScanner = res.authored_by === 'scanner_brief';
          const effectiveModel = res.resolved_model_id || res.model_id;
          setTurns((prev) => [
            {
              id: res.turn_id ?? `turn-${prev.length + 1}`,
              question: trimmed,
              answerMarkdown: res.answer_markdown,
              status: 'answered',
              authoredBy: res.authored_by ?? 'model',
              engineBadge: isScanner
                ? 'Scanner Brief (no model running)'
                : `${res.engine_used} · ${effectiveModel}`,
              executionOrigin: res.execution_origin ?? 'wythe_server',
              endpointOrigin: res.endpoint_origin ?? null,
              requestedModelId: res.requested_model_id ?? null,
              resolvedModelId: res.resolved_model_id ?? res.model_id ?? null,
              fallbackFrom: res.fallback_from ?? clientFallbackFrom ?? null,
              executedTools: res.executed_tools ?? [],
              usedVision: Boolean(res.used_vision_snapshot),
              imageSupplied: Boolean(res.image_supplied ?? hasAttachedFrame),
              fallbackReason: res.fallback_reason ?? null,
              failureReason: null,
              referencedNodeIds: res.referenced_node_ids ?? [],
              validatedReferences: res.validated_references ?? [],
              contextBudget: res.context_budget ?? null,
              evidenceRevisionId: res.evidence_identity?.evidence_revision_id ?? null,
              needsRevalidation: false,
            },
            ...prev,
          ]);
          setQuestion('');
          onSessionMutated?.();
        },
        onError: (err) => {
          // Preserve question in input and refresh stored unresolved_questions
          setActiveError((err as Error).message);
          onSessionMutated?.();
        },
      },
    );
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runQuestion(question);
  };

  return (
    <aside
      ref={containerRef}
      role="dialog"
      aria-modal="true"
      aria-label="Ask Wythe On-Device Architecture Assistant"
      className="fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col border-l border-teal-500/50 bg-slate-950/95 text-xs text-slate-200 shadow-2xl backdrop-blur-md"
    >
      <div className="flex items-start justify-between gap-2 border-b border-slate-800 p-4">
        <div>
          <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-teal-300">
            <Bot className="h-3.5 w-3.5" />
            Ask Wythe · Zero Copy-Paste Bridge ([A] / ⌘J)
          </div>
          <h2 className="mt-0.5 font-mono text-sm font-semibold text-slate-100">
            Zero-Setup On-Device Local Tier + MCP / OpenAPI
          </h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close Ask Wythe drawer"
          className="inline-flex min-h-6 min-w-6 items-center justify-center border border-slate-700 bg-slate-900 p-1 text-slate-300 hover:border-teal-400 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        <div className="space-y-2 border border-slate-800 bg-slate-900/70 p-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-1 font-mono text-[10px] uppercase text-sky-300">
              <Cpu className="h-3 w-3" />
              On-Device Engine Cascade (Apple → Chrome → Local)
            </span>
            <button
              type="button"
              onClick={() => setShowLocalConfig((v) => !v)}
              className="inline-flex min-h-6 min-w-6 items-center font-mono text-[10px] text-teal-300 underline hover:text-teal-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              {showLocalConfig ? 'Hide /v1 URL' : 'Configure /v1 URL'}
            </button>
          </div>
          <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
            {(
              [
                ['auto', 'Auto (Best Local)', appleSt?.state === 'ready' || chromeProbe.state === 'ready' || anyLocalReady],
                ['apple', `Apple FM (${appleSt?.state ?? '…'})`, appleSt?.state === 'ready'],
                ['chrome', `Chrome AI (${chromeProbe.state})`, chromeProbe.state === 'ready'],
                ['local', `Local /v1 (${localStatusLabel})`, anyLocalReady],
              ] as const
            ).map(([key, label, ready]) => (
              <button
                key={key}
                type="button"
                onClick={() => setEngineChoice(key)}
                className={`flex min-h-6 min-w-6 items-center justify-between border px-2 py-1 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                  engineChoice === key
                    ? 'border-teal-400 bg-teal-500/20 text-teal-100'
                    : 'border-slate-800 bg-slate-950 text-slate-300 hover:border-slate-700'
                }`}
              >
                <span className="truncate">{label}</span>
                <span className={ready ? 'text-emerald-300' : 'text-slate-400'}>●</span>
              </button>
            ))}
          </div>

          {(browserLocalProbe.state === 'ready' || localSt?.note) && (
            <div className="truncate font-mono text-[10px] text-slate-300">
              /v1 seat:{' '}
              <span className={anyLocalReady ? 'text-teal-300' : 'text-slate-400'}>
                {browserLocalProbe.state === 'ready' ? browserLocalProbe.note : localSt?.note}
              </span>
            </div>
          )}

          {chromeProbe.state === 'downloadable' && (
            <button
              type="button"
              onClick={() => {
                setChromeDownloadPct(0);
                void triggerChromeModelDownload((pct) => setChromeDownloadPct(pct))
                  .then((next) => {
                    setChromeProbe(next);
                    setChromeDownloadPct(null);
                  })
                  .catch((err) => {
                    setActiveError((err as Error).message);
                    setChromeDownloadPct(null);
                  });
              }}
              className="flex min-h-6 min-w-6 w-full items-center justify-center gap-1.5 border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 font-mono text-[11px] text-sky-200 hover:bg-sky-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              <Download className="h-3 w-3" />
              {chromeDownloadPct !== null
                ? `Downloading Chrome Gemini Nano (${chromeDownloadPct}%)…`
                : 'Download Chrome Built-In Model (One-Time)'}
            </button>
          )}

          {showLocalConfig && (
            <div className="flex items-center gap-1.5 pt-1">
              <input
                type="text"
                aria-label="Custom loopback or Tailnet OpenAI /v1 server URL"
                value={customLocalUrl}
                onChange={(e) => setCustomLocalUrl(e.target.value)}
                placeholder="http://127.0.0.1:8084/v1 or :8080/v1"
                className="min-h-6 flex-1 border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-[11px] text-slate-100 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              />
              <button
                type="button"
                onClick={() => {
                  void refetchEngines();
                  void probeBrowserLocalOpenAi(customLocalUrl.trim() || undefined, true).then(setBrowserLocalProbe);
                }}
                className="inline-flex min-h-6 min-w-6 items-center justify-center border border-teal-500/40 bg-teal-500/15 px-2 py-1 font-mono text-[11px] text-teal-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                Probe
              </button>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-1.5 pt-0.5 font-mono text-[10px] text-slate-300">
            <button
              type="button"
              onClick={() => copyEndpoint('mcp')}
              className="flex min-h-6 min-w-6 items-center gap-1 border border-slate-700 bg-slate-950 px-2 py-0.5 hover:border-teal-400 hover:text-teal-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              <Copy className="h-2.5 w-2.5" />
              {copiedEndpoint === 'mcp' ? 'Copied /api/v1/mcp!' : 'Copy HTTP MCP URL'}
            </button>
            <button
              type="button"
              onClick={() => copyEndpoint('openapi')}
              className="flex min-h-6 min-w-6 items-center gap-1 border border-slate-700 bg-slate-950 px-2 py-0.5 hover:border-teal-400 hover:text-teal-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              <Copy className="h-2.5 w-2.5" />
              {copiedEndpoint === 'openapi' ? 'Copied /openapi.json!' : 'Copy OpenAPI URL'}
            </button>
            <span className="text-emerald-300">· WebMCP `window.wythe` active</span>
          </div>
        </div>

        <div className="border border-teal-500/30 bg-teal-950/20 p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase text-teal-300">
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
              <Eye className="h-3 w-3" />
              Real-Time 3D Camera &amp; Color Sync
            </span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setKeepSession((v) => !v)}
                className={`inline-flex min-h-6 min-w-6 items-center border px-1.5 py-0.5 text-[10px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                  keepSession
                    ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200'
                    : 'border-slate-700 bg-slate-900 text-slate-300'
                }`}
              >
                {keepSession ? `Live Session (${turns.length})` : '1-Shot Mode'}
              </button>
              {turns.length > 0 && (
                <button
                  type="button"
                  onClick={() => setTurns([])}
                  aria-label="Clear conversation history"
                  className="flex min-h-6 min-w-6 items-center gap-1 border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300 hover:border-rose-400 hover:text-rose-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                >
                  <Trash2 className="h-2.5 w-2.5" />
                  Clear
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  const snappedWebp = captureLiveWebp?.() ?? null;
                  if (snappedWebp) {
                    void syncCapturedWebpToUiFocus(snappedWebp).then(() => onRefreshFocus());
                  } else {
                    onRefreshFocus();
                  }
                }}
                className="flex min-h-6 min-w-6 items-center gap-1 border border-teal-500/40 bg-teal-500/15 px-1.5 py-0.5 text-[10px] text-teal-200 hover:bg-teal-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                <RefreshCw className="h-2.5 w-2.5" />
                Snap WebP
              </button>
            </div>
          </div>
          <p className="mt-1 font-mono text-[11px] text-slate-100">
            {liveDigest ? liveDigest.summaryPill : (explanation?.headline ?? `Target: ${activeSlug}`)}
          </p>
          <p className="mt-0.5 text-[10px] text-slate-300">
            Auto-streams live Three.js frustum nodes, exact rendered colors, pinned selection &amp; 1024px WebP frame on every Send.
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {PRESET_QUESTIONS.map((pq) => (
            <button
              key={pq}
              type="button"
              disabled={isBusy}
              onClick={() => void runQuestion(pq)}
              className="min-h-6 min-w-6 border border-slate-800 bg-slate-900 px-2 py-1 text-left font-mono text-[10px] text-slate-200 hover:border-teal-400 hover:text-teal-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 disabled:opacity-50"
            >
              <Sparkles className="mr-1 inline h-2.5 w-2.5 text-teal-300" />
              {pq}
            </button>
          ))}
        </div>

        {activeError && (
          <div className="space-y-2 border border-rose-500/40 bg-rose-950/30 p-2.5 font-mono text-[11px] text-rose-200">
            <div>{activeError}</div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-amber-200">
              <span>Your question is preserved in this session and input box.</span>
              <button
                type="button"
                onClick={() => void insertScannerBriefNow()}
                className="min-h-6 border border-amber-500/50 bg-amber-500/20 px-2 py-0.5 text-amber-100 hover:bg-amber-500/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                Scanner Brief (no model running)
              </button>
            </div>
          </div>
        )}

        <ChallengeCorrectionBox
          sessionId={effectiveSessionId}
          clientId={effectiveClientId}
          targetRefId={selectedFindingId ?? selectedEdgeId ?? selectedNodeId}
          turnId={turns[0]?.id ?? null}
          corrections={sessionData?.corrections ?? explanation?.corrections ?? []}
          compact
          onCorrectionAdded={(created) => {
            onCorrectionAdded?.(created);
            onSessionMutated?.();
          }}
        />

        {onCompareRevisions && (
          <RevisionComparisonPanel
            sessionId={effectiveSessionId}
            evidenceDrifted={Boolean(sessionData?.evidence_drifted)}
            comparison={revisionComparison}
            nodesById={nodesById}
            onRunCompare={onCompareRevisions}
            onSelectNode={onSelectNode}
          />
        )}

        <UnderstandingChainPanel
          activeSlug={activeSlug}
          sessionId={effectiveSessionId}
          subjectId={selectedNodeId ?? explanation?.focused_node?.id ?? null}
          selectedFindingId={selectedFindingId}
          selectedEdgeId={selectedEdgeId}
        />

        <div className="space-y-3">
          {turns.map((t) => {
            const budget = t.contextBudget ?? explanation?.context_budget ?? null;
            const incTotal = budget?.included_counts
              ? Object.values(budget.included_counts).reduce((a, b) => a + b, 0)
              : null;
            const omitTotal = budget?.omitted_counts
              ? Object.values(budget.omitted_counts).reduce((a, b) => a + b, 0)
              : null;
            return (
              <div key={t.id} className="space-y-2 border border-slate-800 bg-slate-900/60 p-3">
                <div className="flex flex-wrap items-center justify-between gap-1.5 border-b border-slate-800 pb-1.5 font-mono text-[10px]">
                  <span className="font-semibold text-teal-300">Q: {t.question}</span>
                  <div className="flex flex-wrap items-center gap-1">
                    <span
                      className={`border px-1.5 py-0.5 ${
                        t.authoredBy === 'scanner_brief'
                          ? 'border-amber-500/45 bg-amber-950/60 text-amber-200'
                          : t.status === 'unresolved'
                            ? 'border-rose-500/45 bg-rose-950/60 text-rose-200'
                            : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                      }`}
                    >
                      {t.engineBadge}
                    </span>
                    {t.executedTools.length > 0 && (
                      <span
                        data-testid="mcp-executed-tools-badge"
                        className="border border-sky-500/40 bg-sky-950/60 px-1.5 py-0.5 text-sky-200"
                      >
                        · MCP: {t.executedTools.join(', ')}
                      </span>
                    )}
                    <span className="border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-slate-200">
                      {t.usedVision ? 'Vision: WebP' : 'Text-only'}
                    </span>
                    {t.executionOrigin && (
                      <span
                        data-testid="ask-provenance-origin"
                        className="border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-slate-200"
                      >
                        {t.executionOrigin}
                        {t.endpointOrigin ? ` @ ${t.endpointOrigin}` : ''}
                      </span>
                    )}
                    {t.requestedModelId && t.resolvedModelId && t.requestedModelId !== t.resolvedModelId && (
                      <span
                        data-testid="ask-provenance-alias"
                        className="border border-sky-500/40 bg-sky-950/60 px-1.5 py-0.5 text-sky-200"
                      >
                        alias: {t.requestedModelId} → {t.resolvedModelId}
                      </span>
                    )}
                    {t.fallbackFrom && (
                      <span
                        data-testid="ask-provenance-fallback"
                        className="border border-amber-500/45 bg-amber-950/60 px-1.5 py-0.5 text-amber-200"
                      >
                        fallback: {t.fallbackFrom}
                      </span>
                    )}
                    {t.needsRevalidation && (
                      <span className="border border-amber-500/50 bg-amber-950/60 px-1.5 py-0.5 text-amber-200">
                        [historical / needs revalidation]
                      </span>
                    )}
                  </div>
                </div>

                {budget && incTotal !== null && (
                  <div className="flex flex-wrap items-center justify-between gap-1 border border-slate-800 bg-slate-950/80 px-2 py-1 font-mono text-[10px] text-slate-300">
                    <span>
                      Context Budget: included <strong>{incTotal}</strong> · omitted{' '}
                      <strong>{omitTotal ?? 0}</strong>
                      {budget.prompt_chars
                        ? ` (${budget.prompt_chars}/${budget.max_prompt_chars || '—'} chars)`
                        : ''}
                    </span>
                    {budget.expand_hint && (
                      <span className="text-sky-300">{budget.expand_hint}</span>
                    )}
                  </div>
                )}

                {t.fallbackReason && (
                  <div className="font-mono text-[10px] text-amber-200">{t.fallbackReason}</div>
                )}

                {t.status === 'unresolved' || !t.answerMarkdown ? (
                  <div className="flex flex-wrap items-center justify-between gap-2 border border-rose-500/30 bg-rose-950/25 p-2 font-mono text-[11px] text-rose-200">
                    <span>
                      Unanswered question preserved ({t.failureReason ?? 'model unavailable'}).
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setQuestion(t.question);
                        void runQuestion(t.question);
                      }}
                      className="min-h-6 border border-teal-500/50 bg-teal-500/20 px-2 py-0.5 text-[10px] text-teal-100 hover:bg-teal-500/30"
                    >
                      Retry Question
                    </button>
                  </div>
                ) : (
                  <div className="space-y-0.5">{renderFormattedAnswer(t.answerMarkdown)}</div>
                )}

                {t.validatedReferences.length > 0 ? (
                  <ValidatedReferencesList
                    references={t.validatedReferences}
                    nodesById={nodesById}
                    needsRevalidation={t.needsRevalidation}
                    onSelectNode={onSelectNode}
                  />
                ) : (
                  t.referencedNodeIds.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="font-mono text-[10px] uppercase text-slate-300">
                        Jump in 3D:
                      </span>
                      {t.referencedNodeIds.map((nid) => {
                        const n = nodesById.get(nid);
                        return (
                          <button
                            key={nid}
                            type="button"
                            onClick={() => onSelectNode(nid)}
                            className="inline-flex min-h-6 min-w-6 items-center border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 font-mono text-[10px] text-sky-200 hover:bg-sky-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            {n ? `${n.tier}:${n.label}` : nid}
                          </button>
                        );
                      })}
                    </div>
                  )
                )}
              </div>
            );
          })}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="border-t border-slate-800 bg-slate-950 p-3">
        <div className="flex items-center gap-2">
          <input
            type="text"
            aria-label="Ask Wythe about the current 3D view, cluster, or node"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder={isBusy ? 'Synthesizing grounded 3-tier answer…' : 'Ask "what is this?" or anything about this view…'}
            disabled={isBusy}
            className="min-h-6 flex-1 border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          />
          <button
            type="submit"
            disabled={isBusy || !question.trim()}
            aria-label="Send architectural question"
            className="flex min-h-6 min-w-6 items-center gap-1.5 border border-teal-500/60 bg-teal-500/20 px-3 py-2 font-mono text-xs font-semibold text-teal-100 hover:bg-teal-500/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 disabled:opacity-50"
          >
            <Send className="h-3.5 w-3.5" />
            {isBusy ? 'Asking…' : 'Ask'}
          </button>
        </div>
      </form>
    </aside>
  );
}
