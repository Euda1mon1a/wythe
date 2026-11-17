'use client';

import { useMemo, useState } from 'react';
import type {
  AdapterSlotSchema,
  AtlasEdge,
  AtlasNode,
  AuditRulingRead,
  BoundaryFinding,
  DiffBlastRadiusReport,
  InvestigationCorrectionRead,
  InvestigationRevisionComparisonRead,
  LegacyBridgeSummary,
  SnapshotComparisonReport,
  StackProfileRead,
  ViewportCommandReceiptRead,
} from '@/api/atlas';
import {
  ChallengeCorrectionBox,
  RevisionComparisonPanel,
} from '@/components/InvestigationCollabControls';
import { UnderstandingChainPanel } from '@/components/UnderstandingChainPanel';
import { formatCalendarDay } from '@/lib/clock';
import {
  normalizeViewportTimeline,
  type AgentCameraFollowState,
} from '@/lib/wytheCameraChoreography';
import {
  ALL_NODE_SUBKINDS,
  computeLifecycleZProjection,
  computeTemporalZProjection,
  deriveDomainCluster,
  type TemporalDiffSummaryRow,
} from '@/lib/wytheSceneLenses';

interface AccessibleIndexViewProps {
  nodes: AtlasNode[];
  edges?: AtlasEdge[];
  findings?: BoundaryFinding[];
  observationSource?: string;
  gitDiffReport?: DiffBlastRadiusReport | null;
  snapCompareReport?: SnapshotComparisonReport | null;
  rulings?: AuditRulingRead[];
  slots: AdapterSlotSchema[];
  profiles: StackProfileRead[];
  legacyBridge: LegacyBridgeSummary;
  scanNotes?: string[];
  agentCameraState?: AgentCameraFollowState;
  activeAgentCaption?: string;
  activeAgentFocusIds?: string[];
  activeSlug?: string;
  sessionId?: string | null;
  clientId?: string | null;
  selectedNodeId?: string | null;
  selectedFindingId?: string | null;
  selectedEdgeId?: string | null;
  corrections?: InvestigationCorrectionRead[];
  evidenceDrifted?: boolean;
  revisionComparison?: InvestigationRevisionComparisonRead | null;
  lastReceipt?: ViewportCommandReceiptRead | null;
  onCorrectionAdded?: (created: InvestigationCorrectionRead) => void;
  onCompareRevisions?: () => Promise<void>;
  onRejectPendingAgentCommand?: () => void;
  onOpenAskAi?: () => void;
  onToggleAgentFollow?: () => void;
  onStepAgentTimeline?: (step: -1 | 1 | { index: number }) => void;
  onToggleAgentPlay?: () => void;
  onExitAgentTimeline?: () => void;
  onHumanNavigateYield?: () => void;
  onSelectNode: (nodeId: string) => void;
}

export function AccessibleIndexView({
  nodes,
  edges = [],
  findings = [],
  observationSource,
  gitDiffReport = null,
  snapCompareReport = null,
  rulings = [],
  slots,
  profiles,
  legacyBridge,
  scanNotes = [],
  agentCameraState,
  activeAgentCaption = '',
  activeAgentFocusIds = [],
  activeSlug = '',
  sessionId = null,
  clientId = null,
  selectedNodeId = null,
  selectedFindingId = null,
  selectedEdgeId = null,
  corrections = [],
  evidenceDrifted = false,
  revisionComparison = null,
  lastReceipt = null,
  onCorrectionAdded,
  onCompareRevisions,
  onRejectPendingAgentCommand,
  onOpenAskAi,
  onToggleAgentFollow,
  onStepAgentTimeline,
  onToggleAgentPlay,
  onExitAgentTimeline,
  onHumanNavigateYield,
  onSelectNode,
}: AccessibleIndexViewProps) {
  const [search, setSearch] = useState('');
  const [tier, setTier] = useState<'all' | 'truth' | 'manipulate' | 'display'>('all');
  const [subkind, setSubkind] = useState<'all' | AtlasNode['subkind']>('all');
  const [wytheFilter, setWytheFilter] = useState<'all' | 'drift' | 'multi_wythe'>('all');
  const [diffFilter, setDiffFilter] = useState<
    'all' | TemporalDiffSummaryRow['transition']
  >('all');
  const [showSubsteps, setShowSubsteps] = useState(false);
  const [pageLimit, setPageLimit] = useState(150);

  const lifecycleProjection = useMemo(
    () => computeLifecycleZProjection(nodes, edges, findings, { observationSource }),
    [nodes, edges, findings, observationSource],
  );
  const temporalProjection = useMemo(
    () =>
      computeTemporalZProjection({
        headNodes: nodes,
        headEdges: edges,
        gitDiffReport,
        snapCompareReport,
      }),
    [nodes, edges, gitDiffReport, snapCompareReport],
  );
  const timelineItems = useMemo(
    () => normalizeViewportTimeline(agentCameraState?.activeEvent?.command),
    [agentCameraState?.activeEvent?.command],
  );
  const currentTimelineItem =
    timelineItems.length > 0
      ? timelineItems[Math.min(agentCameraState?.stepIndex ?? 0, timelineItems.length - 1)]
      : null;

  const exemplars = useMemo(() => {
    const pick = (t: AtlasNode['tier'], preferredSubkind: AtlasNode['subkind']) =>
      nodes.find(
        (n) => n.tier === t && n.subkind === preferredSubkind && n.status === 'clean',
      ) ??
      nodes.find((n) => n.tier === t && n.status === 'clean') ??
      null;
    return {
      truth: pick('truth', 'table'),
      manipulate: pick('manipulate', 'route'),
      display: pick('display', 'page'),
    };
  }, [nodes]);

  const nodesById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return nodes.filter((n) => {
      if (tier !== 'all' && n.tier !== tier) return false;
      if (subkind !== 'all' && n.subkind !== subkind) return false;
      const pres = lifecycleProjection.entityPresence.get(n.id);
      if (wytheFilter === 'drift' && pres?.tieStatus !== 'drift') return false;
      if (wytheFilter === 'multi_wythe' && (pres?.wythes.length ?? 1) < 2) return false;
      if (!q) return true;
      return (
        n.label.toLowerCase().includes(q) ||
        n.source_file.toLowerCase().includes(q) ||
        n.status.toLowerCase().includes(q) ||
        n.subkind.toLowerCase().includes(q) ||
        (n.columns ?? []).some((c) => c.toLowerCase().includes(q)) ||
        (n.stratum_badges ?? []).some(
          (bg) => bg.key.toLowerCase().includes(q) || bg.label.toLowerCase().includes(q),
        ) ||
        (pres?.summary ?? '').toLowerCase().includes(q)
      );
    });
  }, [nodes, search, tier, subkind, wytheFilter, lifecycleProjection.entityPresence]);

  const filteredDiffRows = useMemo(
    () =>
      diffFilter === 'all'
        ? temporalProjection.diffRows
        : temporalProjection.diffRows.filter((r) => r.transition === diffFilter),
    [temporalProjection.diffRows, diffFilter],
  );

  const sampleReceipts = legacyBridge.sample_receipts ?? [];

  return (
    <div
      className="space-y-6"
      onKeyDown={(e) => {
        if (['ArrowDown', 'ArrowUp', 'Home', 'End', 'PageDown', 'PageUp'].includes(e.key)) {
          onHumanNavigateYield?.();
        }
      }}
    >
      {/* WCAG AA Parity (#86/#88): Live Agent Viewport Caption & Tour / Chronicle Stepper */}
      <section
        aria-label="Agent viewport co-navigation and walkthrough stepper"
        className="space-y-2 border border-teal-500/35 bg-slate-950/75 p-4 text-xs"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-mono text-sm font-semibold text-teal-300">
            Agent Co-Navigation &amp; Walkthrough Stepper
          </h2>
          {onToggleAgentFollow && agentCameraState && (
            <div className="flex flex-wrap items-center gap-1.5">
              {(agentCameraState.timelineMode === 'chronicle' ||
                Boolean(agentCameraState.haltedReason)) && (
                <button
                  type="button"
                  aria-pressed={
                    agentCameraState.liveFollowing && agentCameraState.followMode === 'following'
                  }
                  onClick={onToggleAgentFollow}
                  className={`min-h-6 border px-2.5 py-0.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                    agentCameraState.liveFollowing && agentCameraState.followMode === 'following'
                      ? 'border-teal-400/60 bg-teal-500/20 text-teal-200'
                      : 'border-amber-400/60 bg-amber-950/70 text-amber-200'
                  }`}
                >
                  Live Follow:{' '}
                  {agentCameraState.liveFollowing && agentCameraState.followMode === 'following'
                    ? 'Following'
                    : 'Paused — Resume Follow'}
                </button>
              )}
              <button
                type="button"
                aria-pressed={agentCameraState.followMode === 'following'}
                onClick={onToggleAgentFollow}
                className={`min-h-6 border px-2.5 py-0.5 font-mono text-xs font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                  agentCameraState.followMode === 'following'
                    ? 'border-teal-400/60 bg-teal-500/20 text-teal-200'
                    : 'border-amber-400/80 bg-amber-950/90 text-amber-100'
                }`}
              >
                {agentCameraState.followMode === 'following'
                  ? 'Follow Agent Camera: Following'
                  : 'Agent Follow Paused — Resume Follow'}
              </button>
              {agentCameraState.followMode === 'paused' &&
                agentCameraState.pendingEventWhilePaused &&
                onRejectPendingAgentCommand && (
                  <button
                    type="button"
                    onClick={onRejectPendingAgentCommand}
                    className="min-h-6 border border-rose-500/45 bg-rose-950/75 px-2.5 py-0.5 font-mono text-xs text-rose-200 hover:border-rose-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Reject Queued Command
                  </button>
                )}
              {onOpenAskAi && (
                <button
                  type="button"
                  onClick={onOpenAskAi}
                  className="min-h-6 border border-sky-500/50 bg-sky-500/15 px-2.5 py-0.5 font-mono text-xs text-sky-200 hover:bg-sky-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                >
                  Ask AI / Explanation [A]
                </button>
              )}
            </div>
          )}
        </div>
        {lastReceipt && (
          <div
            role="status"
            aria-live="polite"
            className="border border-emerald-500/35 bg-emerald-950/25 px-3 py-1 font-mono text-[11px] text-emerald-200"
          >
            Viewport Receipt: command={lastReceipt.command_id} · outcome={lastReceipt.outcome} · delivery={lastReceipt.delivery_state}
          </div>
        )}
        {agentCameraState?.haltedReason && (
          <div
            role="status"
            aria-live="polite"
            className="border border-rose-500/45 bg-rose-950/45 px-3 py-1.5 font-mono text-xs text-rose-200"
          >
            Live Follow Halted: {agentCameraState.haltedReason}
          </div>
        )}
        <div
          role="status"
          aria-live="polite"
          className="border border-slate-800 bg-slate-900/60 px-3 py-2 font-mono text-xs text-slate-200"
        >
          {activeAgentCaption
            ? `Agent Focus: ${activeAgentCaption}`
            : activeAgentFocusIds.length > 0
              ? `Agent focused ${activeAgentFocusIds.length} node(s): ${activeAgentFocusIds.join(', ')}`
              : 'No active MCP camera command. Standing by for live agent focus or URL permalink.'}
        </div>
        {activeAgentFocusIds.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
            <span className="text-slate-400">Focused entities &amp; Z-wythe / badge attribution:</span>
            {activeAgentFocusIds.slice(0, 12).map((fid) => {
              const fNode = nodesById.get(fid);
              const fPres = lifecycleProjection.entityPresence.get(fid);
              const wytheTag = fPres ? fPres.wythes.map((w) => `Z=${w}`).join('/') : 'Z=0';
              const badgeTag =
                fNode?.stratum_badges && fNode.stratum_badges.length > 0
                  ? ` [${fNode.stratum_badges.map((b) => `${b.label}:${b.count}`).join(', ')}]`
                  : '';
              return (
                <button
                  key={fid}
                  type="button"
                  onClick={() => {
                    onHumanNavigateYield?.();
                    onSelectNode(fid);
                  }}
                  className="min-h-6 border border-sky-500/40 bg-sky-950/35 px-2 py-0.5 text-sky-200 hover:border-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                >
                  {fid} ({wytheTag})
                  {badgeTag}
                </button>
              );
            })}
          </div>
        )}
        {timelineItems.length > 0 && currentTimelineItem && (
          <div className="space-y-2 border-t border-slate-800 pt-2 font-mono text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-slate-200">
                {currentTimelineItem.kind === 'chronicle' ? 'Chronicle Phase' : 'Tour Step'}{' '}
                <strong>
                  {currentTimelineItem.index + 1} / {timelineItems.length}
                </strong>
                : {currentTimelineItem.title}
                {currentTimelineItem.tier ? ` (${currentTimelineItem.tier})` : ''}
                {currentTimelineItem.kind === 'chronicle'
                  ? ` [${currentTimelineItem.status}]`
                  : ''}
              </span>
              <div className="flex flex-wrap items-center gap-1.5">
                {onStepAgentTimeline && (
                  <button
                    type="button"
                    onClick={() => onStepAgentTimeline({ index: 0 })}
                    aria-label="First tour or chronicle step"
                    className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    |&lt; First
                  </button>
                )}
                {onStepAgentTimeline && (
                  <button
                    type="button"
                    onClick={() => onStepAgentTimeline(-1)}
                    aria-label="Previous tour or chronicle step"
                    className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Prev
                  </button>
                )}
                {onToggleAgentPlay && (
                  <button
                    type="button"
                    onClick={onToggleAgentPlay}
                    aria-label={
                      agentCameraState?.isPlaying ? 'Pause walkthrough' : 'Play walkthrough'
                    }
                    className="min-h-6 border border-teal-500/40 bg-teal-950/60 px-2 py-0.5 text-teal-200 hover:border-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    {agentCameraState?.isPlaying ? 'Pause' : 'Play'}
                  </button>
                )}
                {onStepAgentTimeline && (
                  <button
                    type="button"
                    onClick={() => onStepAgentTimeline(1)}
                    aria-label="Next tour or chronicle step"
                    className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Next
                  </button>
                )}
                {onStepAgentTimeline && (
                  <button
                    type="button"
                    onClick={() =>
                      onStepAgentTimeline({ index: Math.max(0, timelineItems.length - 1) })
                    }
                    aria-label="Last tour or chronicle step"
                    className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Last &gt;|
                  </button>
                )}
                {currentTimelineItem.substeps.length > 0 && (
                  <button
                    type="button"
                    aria-expanded={showSubsteps}
                    onClick={() => setShowSubsteps((v) => !v)}
                    className="min-h-6 border border-sky-500/40 bg-sky-950/50 px-2 py-0.5 text-sky-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    {showSubsteps ? 'Hide' : 'Substeps'} ({currentTimelineItem.substeps.length})
                  </button>
                )}
                {onExitAgentTimeline && (
                  <button
                    type="button"
                    onClick={onExitAgentTimeline}
                    aria-label="Exit tour or chronicle walkthrough"
                    className="min-h-6 border border-rose-500/40 bg-rose-950/60 px-2 py-0.5 text-rose-200 hover:border-rose-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Exit
                  </button>
                )}
              </div>
            </div>
            {showSubsteps && currentTimelineItem.substeps.length > 0 && (
              <ol className="list-decimal space-y-0.5 pl-5 text-[11px] text-slate-300">
                {currentTimelineItem.substeps.map((sub, sIdx) => (
                  <li key={sIdx}>{sub}</li>
                ))}
              </ol>
            )}
          </div>
        )}
      </section>

      {/* WCAG AA Parity (DISP-005): Non-WebGL Shared Investigation Corrections, Revision Diff & Understanding Chain */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <ChallengeCorrectionBox
          sessionId={sessionId}
          clientId={clientId}
          targetRefId={selectedFindingId ?? selectedEdgeId ?? selectedNodeId}
          corrections={corrections}
          onCorrectionAdded={onCorrectionAdded}
        />
        {onCompareRevisions ? (
          <RevisionComparisonPanel
            sessionId={sessionId}
            evidenceDrifted={evidenceDrifted}
            comparison={revisionComparison}
            nodesById={nodesById}
            onRunCompare={onCompareRevisions}
            onSelectNode={onSelectNode}
          />
        ) : null}
      </div>

      <UnderstandingChainPanel
        activeSlug={activeSlug}
        sessionId={sessionId}
        subjectId={selectedNodeId}
        selectedFindingId={selectedFindingId}
        selectedEdgeId={selectedEdgeId}
      />

      {/* WCAG AA Parity (#82): Accessible Temporal Z-Diff Snapshot-Slice Summary Table */}
      <section
        aria-label="Temporal Z-Diff base to HEAD snapshot comparison"
        className="space-y-3 border border-slate-800 bg-slate-950/60 p-4 text-xs"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="font-mono text-sm font-semibold text-slate-100">
              Temporal Z-Diff Summary :: {temporalProjection.label}
            </h2>
            <p className="mt-0.5 text-slate-300">
              {temporalProjection.hasDiff
                ? `Canonical (X, Y) domain-and-tier coordinates pinned across Z_base and Z_head (${temporalProjection.diffRows.length} transitions).`
                : 'Single-snapshot fallback active (enable Git Diff or Snapshot Delta in 3D view to compare base -> HEAD slices).'}
            </p>
          </div>
          {temporalProjection.hasDiff && (
            <div
              role="group"
              aria-label="Filter temporal diff transitions"
              className="flex flex-wrap border border-slate-800 bg-slate-950 p-0.5 font-mono text-[11px]"
            >
              {(['all', 'new_finding', 'removed', 'added', 'touched', 'impacted'] as const).map(
                (df) => (
                  <button
                    key={df}
                    type="button"
                    aria-pressed={diffFilter === df}
                    onClick={() => setDiffFilter(df)}
                    className={`min-h-6 px-2 py-0.5 uppercase focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                      diffFilter === df ? 'bg-amber-500/20 text-amber-200' : 'text-slate-300'
                    }`}
                  >
                    {df.replace('_', ' ')}
                  </button>
                ),
              )}
            </div>
          )}
        </div>
        {temporalProjection.hasDiff && filteredDiffRows.length > 0 && (
          <div className="overflow-x-auto border border-slate-800 bg-slate-950/40">
            <table className="w-full text-left text-xs">
              <caption className="sr-only">
                Base to HEAD snapshot transitions including added, removed before-image, impacted, and new-finding nodes
              </caption>
              <thead className="border-b border-slate-800 bg-slate-950 font-mono text-[11px] uppercase text-slate-300">
                <tr>
                  <th scope="col" className="px-3 py-2">Entity</th>
                  <th scope="col" className="px-3 py-2">Transition</th>
                  <th scope="col" className="px-3 py-2">Slices</th>
                  <th scope="col" className="px-3 py-2">Tier · District</th>
                  <th scope="col" className="px-3 py-2">Delta Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 font-mono text-[11px]">
                {filteredDiffRows.slice(0, 80).map((row) => (
                  <tr key={`${row.transition}-${row.nodeId}`} className="hover:bg-slate-900/50">
                    <td className="px-3 py-1.5">
                      {row.presentInHead ? (
                        <button
                          type="button"
                          onClick={() => {
                            onHumanNavigateYield?.();
                            onSelectNode(row.nodeId);
                          }}
                          className="min-h-6 text-left text-teal-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                        >
                          {row.label}
                        </button>
                      ) : (
                        <span className="text-slate-400 line-through">{row.label}</span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 uppercase">
                      <span
                        className={
                          row.transition === 'new_finding'
                            ? 'text-rose-300'
                            : row.transition === 'removed'
                              ? 'text-amber-300'
                              : row.transition === 'added'
                                ? 'text-emerald-300'
                                : 'text-sky-300'
                        }
                      >
                        {row.transition}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-slate-300">
                      {row.presentInBase ? 'Z_base' : '—'} → {row.presentInHead ? 'Z_head' : 'deleted'}
                    </td>
                    <td className="px-3 py-1.5 text-slate-300">
                      {row.tier} · {row.district}
                    </td>
                    <td className="px-3 py-1.5 font-sans text-slate-300">{row.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {scanNotes.length > 0 && (
        <section className="space-y-1 border border-sky-500/30 bg-sky-950/20 p-3 font-mono text-xs text-sky-200">
          <h2 className="font-semibold text-sky-300">Scan Provenance &amp; Probe Notes</h2>
          <ul className="list-disc space-y-0.5 pl-5 text-slate-200">
            {scanNotes.map((note, idx) => (
              <li key={idx}>{note}</li>
            ))}
          </ul>
        </section>
      )}
      {/* Day-1 Newcomer 3-Tier Placement Guide */}
      <section className="space-y-3 border border-slate-800 bg-slate-950/60 p-4 text-xs">
        <div>
          <h2 className="font-mono text-sm font-semibold text-slate-100">
            Day-1 Architecture Guide :: Where Does New Code Belong?
          </h2>
          <p className="mt-0.5 text-slate-300">
            Every feature flows across three strata. Click a sample node below with zero attached scan findings in this snapshot (verify project governance references before treating any file as an architectural pattern):
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <div className="border border-teal-500/30 bg-teal-950/15 p-3">
            <div className="font-mono font-semibold text-teal-300">
              Tier 1 · SQL Bedrock (Truth)
            </div>
            <p className="mt-1 text-slate-300">
              Durable domain schemas, invariants, policies, and SQL guard functions live here—never hardcoded in UI or scattered Python dicts.
            </p>
            {exemplars.truth && (
              <button
                type="button"
                onClick={() => onSelectNode(exemplars.truth!.id)}
                className="mt-2 truncate font-mono text-[11px] text-teal-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                Sample clean node (unvalidated): {exemplars.truth.label} →
              </button>
            )}
          </div>
          <div className="border border-sky-500/30 bg-sky-950/15 p-3">
            <div className="font-mono font-semibold text-sky-300">
              Tier 2 · Backend Manipulation
            </div>
            <p className="mt-1 text-slate-300">
              Typed routes, domain services, solvers, and background workers read/mutate Tier 1 Truth and expose OpenAPI schemas.
            </p>
            {exemplars.manipulate && (
              <button
                type="button"
                onClick={() => onSelectNode(exemplars.manipulate!.id)}
                className="mt-2 truncate font-mono text-[11px] text-sky-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                Sample clean node (unvalidated): {exemplars.manipulate.label} →
              </button>
            )}
          </div>
          <div className="border border-blue-500/30 bg-blue-950/15 p-3">
            <div className="font-mono font-semibold text-blue-300">
              Tier 3 · Frontend Display
            </div>
            <p className="mt-1 text-slate-300">
              Accessible pages, query hooks, and typed API clients render state and dispatch user intent without embedding domain rules.
            </p>
            {exemplars.display && (
              <button
                type="button"
                onClick={() => onSelectNode(exemplars.display!.id)}
                className="mt-2 truncate font-mono text-[11px] text-blue-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                Sample clean node (unvalidated): {exemplars.display.label} →
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Pluggable Multi-Language Adapter Registry */}
      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Pluggable Language &amp; Framework Adapter Registry ({profiles.length} stack profiles)
          </h2>
          <p className="text-xs text-slate-300">
            Core lineage verification is production-dogfooded on{' '}
            <code className="font-mono text-teal-300">fastapi-sqlalchemy-nextjs</code>; secondary polyglot profiles &amp; adapters are marked{' '}
            <span className="font-mono text-amber-300">experimental</span> (use{' '}
            <code className="font-mono">wythe diff</code> or ratchets before strict gating).
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {profiles.map((prof) => (
            <span
              key={prof.slug}
              title={prof.description}
              className={`border px-2 py-0.5 font-mono text-[11px] ${
                prof.implementation_status === 'implemented'
                  ? 'border-teal-500/40 bg-teal-950/30 text-teal-200'
                  : prof.implementation_status === 'experimental'
                    ? 'border-amber-500/35 bg-amber-950/20 text-amber-200'
                    : 'border-slate-800 bg-slate-950/60 text-slate-400'
              }`}
            >
              {prof.slug}{' '}
              <span className="text-[9px] uppercase opacity-80">[{prof.implementation_status}]</span>
            </span>
          ))}
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
          {slots.map((slot) => (
            <div
              key={slot.name}
              className="border border-slate-800 bg-slate-950/60 p-3.5 text-xs"
            >
              <div className="flex items-center justify-between font-mono">
                <span className="font-semibold text-slate-100">{slot.name}</span>
                <span
                  className={`px-1.5 py-0.5 text-[10px] uppercase ${
                    slot.implementation_status === 'implemented'
                      ? 'bg-teal-500/15 text-teal-300'
                      : slot.implementation_status === 'experimental'
                        ? 'bg-amber-500/15 text-amber-300'
                        : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {slot.implementation_status}
                </span>
              </div>
              <div className="mt-1 font-mono text-[11px] text-slate-300">
                Tier: <span className="uppercase text-slate-100">{slot.tier}</span> · {slot.language}
              </div>
              <div className="mt-2 text-[11px] text-slate-300">
                {slot.frameworks.join(' · ')}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Curated Snapshot Receipt Bridge + Mechanical Sample Receipts */}
      {legacyBridge.present && (
        <section className="space-y-3 border border-teal-500/30 bg-teal-950/15 p-4 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-mono font-semibold text-teal-300">
              Curated Snapshot Bridge :: {legacyBridge.snapshot_title}
            </h3>
            <span className="font-mono text-[11px] text-slate-300">
              Base Audit: {formatCalendarDay(legacyBridge.audited_at)} · Commit:{' '}
              {legacyBridge.snapshot_commit?.slice(0, 10) ?? '—'}
            </span>
          </div>
          <p className="text-slate-200">
            Verified <strong className="text-teal-300">{legacyBridge.receipts_verified}</strong> of{' '}
            <strong>{legacyBridge.receipts_checked}</strong> mechanical source signatures (
            {legacyBridge.receipts_changed} changed, {legacyBridge.receipts_error} errors). Matched{' '}
            {legacyBridge.curated_nodes_matched} curated descriptions and normalized{' '}
            <strong className="text-teal-300">{legacyBridge.cutover_reclassified_count}</strong>{' '}
            completed cutover status(es) to <code className="font-mono">clean</code> while preserving provenance in{' '}
            <code className="font-mono">cutover_history</code>.
          </p>
          {sampleReceipts.length > 0 && (
            <div className="grid grid-cols-1 gap-2 pt-1 md:grid-cols-2">
              {sampleReceipts.map((rc, idx) => (
                <div key={`${rc.node_id}-${idx}`} className="border border-slate-800 bg-slate-950/80 p-2 font-mono text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{rc.node_id}</span>
                    <span
                      className={
                        rc.result === 'verified_present'
                          ? 'text-teal-300'
                          : rc.result === 'changed'
                            ? 'text-amber-300'
                            : 'text-rose-300'
                      }
                    >
                      {rc.result}
                    </span>
                  </div>
                  <div className="truncate text-slate-300">{rc.path}</div>
                  {rc.note && <div className="mt-0.5 text-[10px] text-slate-400">{rc.note}</div>}
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Target Ownership Rulings Ledger */}
      {rulings.length > 0 && (
        <section className="space-y-2 border border-slate-800 bg-slate-950/50 p-4 text-xs">
          <h3 className="font-mono font-semibold text-slate-100">
            Recorded Ownership Rulings Ledger ({rulings.length})
          </h3>
          <div className="divide-y divide-slate-800/80">
            {rulings.slice(0, 30).map((r) => (
              <div key={r.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <div>
                  <button
                    type="button"
                    onClick={() => onSelectNode(r.node_id)}
                    className="font-mono font-medium text-teal-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    {r.node_id}
                  </button>
                  <span className="ml-2 border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-200">
                    {r.disposition}
                  </span>
                  <p className="mt-0.5 text-slate-300">{r.summary}</p>
                </div>
                <div className="font-mono text-[10px] text-slate-300">
                  by {r.recorded_by} · {formatCalendarDay(r.audited_at)}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Keyboard-Accessible 3-Tier Node Index */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2">
          <h2 className="text-sm font-semibold text-slate-100">
            Accessible 3-Tier Node Index ({filtered.length} of {nodes.length})
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="search"
              aria-label="Search 3-tier node index"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPageLimit(150);
              }}
              placeholder="Search node, column, or file…"
              className="min-h-6 w-56 border border-slate-800 bg-slate-950 px-2.5 py-1 font-mono text-xs text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            />
            <select
              aria-label="Filter index by subkind"
              value={subkind}
              onChange={(e) => {
                setSubkind(e.target.value as 'all' | AtlasNode['subkind']);
                setPageLimit(150);
              }}
              className="min-h-6 border border-slate-800 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              <option value="all">All {ALL_NODE_SUBKINDS.length} subkinds</option>
              {ALL_NODE_SUBKINDS.map((sk) => (
                <option key={sk} value={sk}>
                  {sk}
                </option>
              ))}
            </select>
            <select
              aria-label="Filter index by lifecycle Z-wythe presence and wall-tie drift"
              value={wytheFilter}
              onChange={(e) => {
                setWytheFilter(e.target.value as 'all' | 'drift' | 'multi_wythe');
                setPageLimit(150);
              }}
              className="min-h-6 border border-slate-800 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              <option value="all">Z-Wythes: All</option>
              <option value="drift">Wall-Tie Drift Only</option>
              <option value="multi_wythe">Multi-Wythe (Z=0/1/2)</option>
            </select>
            <div
              role="group"
              aria-label="Filter index by tier"
              className="flex border border-slate-800 bg-slate-950 p-0.5 font-mono text-xs"
            >
              {(['all', 'truth', 'manipulate', 'display'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  aria-pressed={tier === t}
                  onClick={() => {
                    setTier(t);
                    setPageLimit(150);
                  }}
                  className={`min-h-6 px-2 py-0.5 uppercase focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                    tier === t ? 'bg-teal-500/20 text-teal-300' : 'text-slate-300'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto border border-slate-800 bg-slate-950/40">
          <table className="w-full text-left text-xs">
            <caption className="sr-only">
              3-tier architectural nodes filtered by tier, subkind, and search query
            </caption>
            <thead className="border-b border-slate-800 bg-slate-950 font-mono text-[11px] uppercase text-slate-300">
              <tr>
                <th scope="col" className="px-3 py-2">Node</th>
                <th scope="col" className="px-3 py-2">Tier · Subkind · District</th>
                <th scope="col" className="px-3 py-2">Z-Wythes &amp; Wall-Tie</th>
                <th scope="col" className="px-3 py-2">Coupling</th>
                <th scope="col" className="px-3 py-2">Status</th>
                <th scope="col" className="px-3 py-2">Source Coordinate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.slice(0, pageLimit).map((n) => {
                const pres = lifecycleProjection.entityPresence.get(n.id);
                return (
                <tr key={n.id} className="hover:bg-slate-900/50">
                  <td className="px-3 py-2 font-mono font-medium">
                    <button
                      type="button"
                      onClick={() => {
                        onHumanNavigateYield?.();
                        onSelectNode(n.id);
                      }}
                      className="min-h-6 text-left text-teal-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                    >
                      {n.label}
                    </button>
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-300">
                    {n.tier} · {n.subkind} · <span className="text-slate-400">{deriveDomainCluster(n)}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px]">
                    <div className="flex flex-wrap items-center gap-1">
                      {(pres?.wythes ?? [0]).map((w) => (
                        <span
                          key={w}
                          className="border border-slate-700 bg-slate-900 px-1 py-0.5 text-[10px] text-slate-200"
                        >
                          Z={w}
                        </span>
                      ))}
                      <span
                        className={
                          pres?.tieStatus === 'drift'
                            ? 'text-rose-300'
                            : pres?.tieStatus === 'intact'
                              ? 'text-teal-300'
                              : 'text-slate-400'
                        }
                      >
                        {pres?.tieStatus === 'drift'
                          ? `drift (${pres.driftRuleCodes.join(',') || 'mismatch'})`
                          : pres?.tieStatus === 'intact'
                            ? 'tie intact'
                            : 'blueprint'}
                      </span>
                    </div>
                    {n.stratum_badges && n.stratum_badges.length > 0 && (
                      <div className="mt-0.5 text-[10px] text-sky-300">
                        {n.stratum_badges.map((bg) => `${bg.label}:${bg.count}`).join(' · ')}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-300">
                    {n.tier === 'truth'
                      ? `R:${n.read_by_count ?? 0} W:${n.written_by_count ?? 0} Cols:${n.columns?.length ?? 0}`
                      : n.http_methods?.length
                        ? `${n.http_methods.join('/')} (${n.http_paths?.length ?? 0})`
                        : '—'}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    <span
                      className={
                        n.status === 'clean'
                          ? 'text-teal-300'
                          : n.status === 'policy_in_code' || n.status === 'gray_zone'
                            ? 'text-amber-300'
                            : n.status === 'duplicated_truth'
                              ? 'text-rose-400'
                              : 'text-slate-300'
                      }
                    >
                      {n.status}
                    </span>
                    {n.store_purpose && (
                      <div className="mt-0.5 text-[10px] text-teal-200/80">
                        intent: {n.store_purpose.intended_use}
                      </div>
                    )}
                    {n.verification_note && (
                      <div className="mt-0.5 truncate text-[10px] text-slate-400" title={n.verification_note}>
                        {n.verification_note}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-300">
                    {n.source_file}:{n.line}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {(filtered.length > 150 || filtered.length > pageLimit) && (
          <div
            role="status"
            aria-live="polite"
            className="flex flex-wrap items-center justify-between gap-2 border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-xs text-slate-300"
          >
            <span>
              Showing {Math.min(pageLimit, filtered.length)} of {filtered.length} matching nodes.
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {pageLimit < filtered.length && (
                <>
                  <button
                    type="button"
                    onClick={() => setPageLimit((prev) => prev + 150)}
                    className="min-h-6 border border-slate-700 bg-slate-900 px-2.5 py-0.5 text-slate-200 hover:border-teal-400 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Show 150 more
                  </button>
                  <button
                    type="button"
                    onClick={() => setPageLimit(filtered.length)}
                    className="min-h-6 border border-teal-500/40 bg-teal-500/15 px-2.5 py-0.5 text-teal-300 hover:bg-teal-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    Show all ({filtered.length})
                  </button>
                </>
              )}
              {pageLimit > 150 && (
                <button
                  type="button"
                  onClick={() => setPageLimit(150)}
                  className="min-h-6 border border-slate-700 bg-slate-900 px-2.5 py-0.5 text-slate-200 hover:border-teal-400 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                >
                  Reset to 150
                </button>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
