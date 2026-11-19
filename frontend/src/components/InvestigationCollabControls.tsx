'use client';

import { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  GitCompare,
  History,
  MessageSquareWarning,
  RotateCcw,
  Trash2,
} from 'lucide-react';
import {
  atlasApi,
  type AtlasNode,
  type FollowState,
  type InvestigationCorrectionRead,
  type InvestigationRevisionComparisonRead,
  type InvestigationSessionRead,
  type InvestigationSummaryRead,
  type ReferenceValidationState,
  type ValidatedReferenceRead,
} from '@/api/atlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import { buildSessionShareUrl } from '@/lib/wytheInvestigationSession';

export function formatValidationBadge(
  state: ReferenceValidationState | string | undefined,
  needsRevalidation = false,
): { label: string; className: string } {
  if (state === 'vanished_in_current_scan') {
    return {
      label: '[vanished in current scan]',
      className: 'border-rose-500/50 bg-rose-950/50 text-rose-200',
    };
  }
  if (state === 'historical_needs_revalidation' || needsRevalidation) {
    return {
      label: '[historical / needs revalidation]',
      className: 'border-amber-500/50 bg-amber-950/50 text-amber-200',
    };
  }
  if (state === 'text_convenience') {
    return {
      label: '[text match]',
      className: 'border-sky-500/40 bg-sky-950/40 text-sky-200',
    };
  }
  if (state === 'validated') {
    return {
      label: '[validated]',
      className: 'border-emerald-500/45 bg-emerald-950/40 text-emerald-200',
    };
  }
  return {
    label: '[unresolved]',
    className: 'border-slate-600 bg-slate-900 text-slate-300',
  };
}

export function ValidatedReferencesList({
  references,
  nodesById,
  needsRevalidation = false,
  onSelectNode,
}: {
  references: ValidatedReferenceRead[];
  nodesById?: Map<string, AtlasNode>;
  needsRevalidation?: boolean;
  onSelectNode?: (nodeId: string) => void;
}) {
  if (!references || references.length === 0) return null;
  return (
    <div className="space-y-1.5 border-t border-slate-800/80 pt-2">
      <div className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
        Evidence References ({references.length})
      </div>
      <div className="space-y-1">
        {references.map((ref, idx) => {
          const badge = formatValidationBadge(ref.validation_state, needsRevalidation);
          const vanished = ref.validation_state === 'vanished_in_current_scan';
          let nodeMatch = nodesById?.get(ref.ref_id);
          if (!nodeMatch && ref.source_file && nodesById) {
            let bestDist = Infinity;
            for (const cand of nodesById.values()) {
              if (cand.source_file === ref.source_file) {
                const dist = ref.line ? Math.abs((cand.line ?? 1) - ref.line) : 0;
                if (dist < bestDist) {
                  bestDist = dist;
                  nodeMatch = cand;
                }
              }
            }
          }
          const selectableNodeId = nodeMatch ? nodeMatch.id : ref.kind === 'node' ? ref.ref_id : null;
          const canSelect = Boolean(onSelectNode && !vanished && selectableNodeId);
          const displayLabel =
            ref.label || (nodeMatch ? `${nodeMatch.tier}:${nodeMatch.label}` : ref.ref_id);
          return (
            <div
              key={`${ref.ref_id}-${idx}`}
              className="flex flex-wrap items-center justify-between gap-1.5 border border-slate-800 bg-slate-950/75 px-2 py-1 font-mono text-[10px]"
            >
              <div className="flex flex-wrap items-center gap-1.5">
                {canSelect && selectableNodeId ? (
                  <button
                    type="button"
                    onClick={() => onSelectNode?.(selectableNodeId)}
                    className="min-h-6 text-left font-semibold text-teal-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                  >
                    {displayLabel}
                  </button>
                ) : (
                  <span
                    className={
                      vanished ? 'text-rose-200 line-through' : 'font-semibold text-slate-200'
                    }
                  >
                    {displayLabel}
                  </span>
                )}
                {ref.source_file && (
                  <span className="text-slate-400">
                    {ref.source_file}
                    {ref.line ? `:${ref.line}` : ''}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-1">
                <span className={`border px-1.5 py-0.5 ${badge.className}`}>
                  {badge.label}
                </span>
                <span className="border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-slate-300">
                  {ref.epistemic_kind ?? 'static_inference'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ChallengeCorrectionBox({
  sessionId,
  clientId,
  targetRefId = null,
  turnId = null,
  corrections = [],
  compact = false,
  onCorrectionAdded,
}: {
  sessionId: string | null;
  clientId?: string | null;
  targetRefId?: string | null;
  turnId?: string | null;
  corrections?: InvestigationCorrectionRead[];
  compact?: boolean;
  onCorrectionAdded?: (created: InvestigationCorrectionRead) => void;
}) {
  const [note, setNote] = useState('');
  const [kind, setKind] = useState('disagreement');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  const scopedCorrections = compact
    ? corrections
    : targetRefId
      ? [
          ...corrections.filter((c) => !c.target_ref_id || c.target_ref_id === targetRefId),
          ...corrections.filter((c) => Boolean(c.target_ref_id && c.target_ref_id !== targetRefId)),
        ]
      : corrections;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = note.trim();
    if (!trimmed || !sessionId || submitting) return;
    setSubmitting(true);
    setErrorMsg(null);
    setSavedNotice(null);
    try {
      const created = await atlasApi.addInvestigationCorrection(sessionId, {
        client_id: clientId ?? undefined,
        actor: 'human',
        target_ref_id: targetRefId ?? undefined,
        turn_id: turnId ?? undefined,
        kind,
        note: trimmed,
      });
      setNote('');
      setSavedNotice('Recorded in shared investigation (governance rules unchanged).');
      onCorrectionAdded?.(created);
    } catch (err) {
      setErrorMsg((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section
      aria-label="Challenge explanation or add investigation correction"
      className="space-y-2 border border-amber-500/35 bg-amber-950/15 p-3 text-xs"
    >
      <div className="flex flex-wrap items-center justify-between gap-1 font-mono text-[10px] uppercase tracking-wider text-amber-300">
        <span className="flex items-center gap-1.5">
          <MessageSquareWarning className="h-3.5 w-3.5" />
          Challenge / Add Correction
        </span>
        <span className="text-slate-400">
          {sessionId ? `session:${sessionId.slice(0, 14)}` : 'awaiting session'}
        </span>
      </div>
      {!compact && (
        <p className="text-[11px] text-slate-300">
          Attaches a domain clarification to this shared investigation so subsequent agent turns and MCP reads see your correction. Does <strong>not</strong> silently disable governance rules.
        </p>
      )}
      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-1.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <select
            aria-label="Correction category"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className="min-h-6 border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-[11px] text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <option value="disagreement">disagreement</option>
            <option value="algorithmic_constant">algorithmic_constant (not policy)</option>
            <option value="domain_clarification">domain_clarification</option>
            <option value="scope_note">scope_note</option>
          </select>
          {targetRefId && (
            <span className="truncate border border-slate-800 bg-slate-950 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
              ref: {targetRefId}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <input
            type="text"
            aria-label="Human investigation correction note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder='e.g. "That is an algorithmic tuning value, not domain policy."'
            className="min-h-6 flex-1 border border-slate-700 bg-slate-950 px-2.5 py-1 font-mono text-[11px] text-slate-100 placeholder:text-slate-400 focus:border-amber-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          />
          <button
            type="submit"
            disabled={!sessionId || submitting || !note.trim()}
            className="min-h-6 border border-amber-500/50 bg-amber-500/20 px-2.5 py-1 font-mono text-[11px] font-semibold text-amber-100 hover:bg-amber-500/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 disabled:opacity-50"
          >
            {submitting ? 'Saving…' : 'Record Correction'}
          </button>
        </div>
      </form>
      {savedNotice && (
        <div role="status" className="font-mono text-[10px] text-emerald-300">
          {savedNotice}
        </div>
      )}
      {errorMsg && (
        <div role="alert" className="font-mono text-[10px] text-rose-300">
          {errorMsg}
        </div>
      )}
      {scopedCorrections.length > 0 && (
        <div className="max-h-28 space-y-1 overflow-y-auto border-t border-amber-500/20 pt-1.5">
          {scopedCorrections.slice(-6).map((c) => (
            <div
              key={c.correction_id}
              className="border border-slate-800 bg-slate-950/80 px-2 py-1 font-mono text-[10px] text-slate-200"
            >
              <span className="text-amber-300">[{c.kind}]</span>{' '}
              {c.target_ref_id && (
                <span className="text-teal-300">[{c.target_ref_id}] </span>
              )}
              {c.note}{' '}
              <span className="text-slate-400">
                (ruling:{c.promoted_to_ruling ? 'yes' : 'no'})
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export function RevisionComparisonPanel({
  sessionId,
  evidenceDrifted = false,
  comparison,
  nodesById,
  onRunCompare,
  onSelectNode,
}: {
  sessionId: string | null;
  evidenceDrifted?: boolean;
  comparison: InvestigationRevisionComparisonRead | null;
  nodesById?: Map<string, AtlasNode>;
  onRunCompare: () => Promise<void>;
  onSelectNode?: (nodeId: string) => void;
}) {
  const [loading, setLoading] = useState(false);

  const trigger = async () => {
    if (!sessionId || loading) return;
    setLoading(true);
    try {
      await onRunCompare();
    } finally {
      setLoading(false);
    }
  };

  return (
    <section
      aria-label="Compare pinned investigation evidence against current scan"
      className={`space-y-2 border p-3 text-xs ${
        evidenceDrifted || comparison?.digest_changed
          ? 'border-amber-500/45 bg-amber-950/20'
          : 'border-slate-800 bg-slate-950/60'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-sky-300">
          <GitCompare className="h-3.5 w-3.5" />
          Compare Evidence Revisions
          {evidenceDrifted && (
            <span className="border border-amber-500/50 bg-amber-500/20 px-1.5 py-0.5 text-amber-200">
              source changed since discussion
            </span>
          )}
        </span>
        <button
          type="button"
          disabled={!sessionId || loading}
          onClick={() => void trigger()}
          className="min-h-6 border border-sky-500/45 bg-sky-500/15 px-2.5 py-0.5 font-mono text-[10px] text-sky-200 hover:bg-sky-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 disabled:opacity-50"
        >
          {loading ? 'Comparing…' : 'Compare Evidence Revisions'}
        </button>
      </div>
      {comparison && (
        <div className="space-y-2 border-t border-slate-800 pt-2 font-mono text-[10px] text-slate-200">
          <div className="flex flex-wrap items-center gap-2">
            <span>
              Pinned: <strong>{comparison.pinned_evidence.evidence_revision_id.slice(0, 14)}</strong>{' '}
              ({comparison.pinned_evidence.source_commit.slice(0, 10)})
            </span>
            <span>→</span>
            <span>
              Current:{' '}
              <strong>{comparison.current_evidence.evidence_revision_id.slice(0, 14)}</strong> (
              {comparison.current_evidence.source_commit.slice(0, 10)})
            </span>
            <span
              className={`border px-1.5 py-0.5 ${
                comparison.digest_changed
                  ? 'border-amber-500/50 bg-amber-950/60 text-amber-200'
                  : 'border-emerald-500/40 bg-emerald-950/50 text-emerald-200'
              }`}
            >
              {comparison.digest_changed ? 'digest changed' : 'digest unchanged'}
            </span>
          </div>
          <p className="font-sans text-[11px] text-slate-200">{comparison.summary_markdown}</p>
          <div className="flex flex-wrap gap-2 text-[10px]">
            <span className="text-emerald-300">
              Surviving: {comparison.surviving_refs.length}
            </span>
            <span className="text-amber-300">
              Modified: {comparison.modified_refs.length}
            </span>
            <span className="text-rose-300">
              Vanished (never rebound): {comparison.vanished_refs.length}
            </span>
            <span className="text-sky-300">
              +Findings: {comparison.added_finding_ids.length} / Resolved:{' '}
              {comparison.resolved_finding_ids.length}
            </span>
            {comparison.invalidated_turn_ids.length > 0 && (
              <span className="text-amber-200">
                Historical turns needing revalidation: {comparison.invalidated_turn_ids.length}
              </span>
            )}
          </div>
          {comparison.vanished_refs.length > 0 && (
            <ValidatedReferencesList
              references={comparison.vanished_refs}
              nodesById={nodesById}
              onSelectNode={onSelectNode}
            />
          )}
          {comparison.surviving_refs.length > 0 && (
            <ValidatedReferencesList
              references={comparison.surviving_refs}
              nodesById={nodesById}
              onSelectNode={onSelectNode}
            />
          )}
        </div>
      )}
    </section>
  );
}

export function InvestigationSessionBar({
  activeSlug,
  sessionId,
  clientId,
  followState,
  sessionData,
  priorSessions,
  comparison,
  nodesById,
  onToggleFollow,
  onReopenSession,
  onNewIndependentSession,
  onResetSession,
  onExportSession,
  onDeleteSession,
  onCompareRevisions,
  onSelectNode,
}: {
  activeSlug: string;
  sessionId: string | null;
  clientId: string;
  followState: FollowState;
  sessionData: InvestigationSessionRead | null;
  priorSessions: InvestigationSummaryRead[];
  comparison: InvestigationRevisionComparisonRead | null;
  nodesById?: Map<string, AtlasNode>;
  onToggleFollow: () => void;
  onReopenSession: (nextSessionId: string) => void;
  onNewIndependentSession: () => void;
  onResetSession: () => void;
  onExportSession: () => void;
  onDeleteSession: () => void;
  onCompareRevisions: () => Promise<void>;
  onSelectNode?: (nodeId: string) => void;
}) {
  const [copiedKey, setCopiedKey] = useState<'id' | 'url' | null>(null);
  const [showCompareDrawer, setShowCompareDrawer] = useState(false);

  if (!sessionId) return null;

  const copyId = () => {
    void copyTextToClipboard(sessionId).then((ok) => {
      if (ok) {
        setCopiedKey('id');
        window.setTimeout(() => setCopiedKey(null), 1600);
      }
    });
  };

  const copyShareUrl = () => {
    const base =
      typeof window !== 'undefined'
        ? `${window.location.origin}${window.location.pathname}`
        : 'http://127.0.0.1:8780/';
    const shareUrl = buildSessionShareUrl(base, activeSlug, sessionId);
    void copyTextToClipboard(shareUrl).then((ok) => {
      if (ok) {
        setCopiedKey('url');
        window.setTimeout(() => setCopiedKey(null), 1600);
      }
    });
  };

  const drifted = Boolean(sessionData?.evidence_drifted || comparison?.digest_changed);

  return (
    <div
      role="region"
      aria-label="Shared human-agent investigation session controls"
      className="border-b border-slate-800 bg-slate-950/80 px-5 py-2 font-mono text-[11px] text-slate-200"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex items-center gap-1 text-teal-300">
            <History className="h-3.5 w-3.5" />
            Investigation:
          </span>
          <code
            data-testid="active-investigation-session-id"
            className="border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-slate-100"
          >
            {sessionId}
          </code>
          <span className="text-[10px] text-slate-400">client:{clientId.slice(0, 12)}</span>
          <button
            type="button"
            onClick={copyId}
            aria-label="Copy investigation session ID"
            className="flex min-h-6 items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <Copy className="h-2.5 w-2.5" />
            {copiedKey === 'id' ? 'Copied ID' : 'Copy Session ID'}
          </button>
          <button
            type="button"
            onClick={copyShareUrl}
            aria-label="Copy shared session permalink URL"
            className="flex min-h-6 items-center gap-1 border border-sky-500/40 bg-sky-950/40 px-2 py-0.5 text-[10px] text-sky-200 hover:border-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <Copy className="h-2.5 w-2.5" />
            {copiedKey === 'url' ? 'Copied #session=' : 'Share #session='}
          </button>
          {sessionData?.pinned_evidence && (
            <span className="text-[10px] text-slate-400">
              ev:{sessionData.pinned_evidence.evidence_revision_id.slice(0, 12)}
              {sessionData.pinned_evidence.source_commit === 'non_git' ? ' (non_git)' : ''}
            </span>
          )}
          {drifted ? (
            <span className="flex items-center gap-1 border border-amber-500/50 bg-amber-950/50 px-1.5 py-0.5 text-[10px] text-amber-200">
              <AlertTriangle className="h-3 w-3" />
              Evidence changed
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[10px] text-emerald-300">
              <CheckCircle2 className="h-3 w-3" />
              turns:{sessionData?.turns.length ?? 0} · corrections:
              {sessionData?.corrections.length ?? 0}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            aria-pressed={followState === 'following'}
            onClick={onToggleFollow}
            className={`min-h-6 border px-2.5 py-0.5 text-[11px] font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
              followState === 'following'
                ? 'border-teal-400/60 bg-teal-500/20 text-teal-200'
                : 'border-amber-400/80 bg-amber-950/90 text-amber-100'
            }`}
          >
            {followState === 'following'
              ? 'Agent Follow: Following'
              : 'Agent Follow Paused — Resume Follow'}
          </button>

          {priorSessions.length > 0 && (
            <select
              aria-label="Reopen prior investigation session"
              value={sessionId}
              onChange={(e) => {
                if (e.target.value && e.target.value !== sessionId) {
                  onReopenSession(e.target.value);
                }
              }}
              className="min-h-6 max-w-[13rem] border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
            >
              {!priorSessions.some((s) => s.session_id === sessionId) && (
                <option value={sessionId}>{sessionId} (active)</option>
              )}
              {priorSessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.session_id.slice(0, 14)} · {s.turn_count ?? 0}t/{s.correction_count ?? 0}c
                </option>
              ))}
            </select>
          )}

          <button
            type="button"
            onClick={() => {
              setShowCompareDrawer((v) => !v);
              if (!showCompareDrawer) void onCompareRevisions();
            }}
            className="flex min-h-6 items-center gap-1 border border-sky-500/40 bg-sky-950/40 px-2 py-0.5 text-[10px] text-sky-200 hover:border-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <GitCompare className="h-3 w-3" />
            Compare Revisions
          </button>
          <button
            type="button"
            onClick={onNewIndependentSession}
            className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            New Session
          </button>
          <button
            type="button"
            onClick={onExportSession}
            aria-label="Export investigation session JSON"
            className="flex min-h-6 items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <Download className="h-3 w-3" />
            Export JSON
          </button>
          <button
            type="button"
            onClick={onResetSession}
            aria-label="Reset investigation session"
            className="flex min-h-6 items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-200 hover:border-amber-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <RotateCcw className="h-3 w-3" />
            Reset
          </button>
          <button
            type="button"
            onClick={onDeleteSession}
            aria-label="Delete investigation session"
            className="flex min-h-6 items-center gap-1 border border-rose-500/40 bg-rose-950/40 px-2 py-0.5 text-[10px] text-rose-200 hover:border-rose-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <Trash2 className="h-3 w-3" />
            Delete
          </button>
        </div>
      </div>

      {(showCompareDrawer || drifted) && (
        <div className="mt-2">
          <RevisionComparisonPanel
            sessionId={sessionId}
            evidenceDrifted={drifted}
            comparison={comparison}
            nodesById={nodesById}
            onRunCompare={onCompareRevisions}
            onSelectNode={onSelectNode}
          />
        </div>
      )}
    </div>
  );
}
