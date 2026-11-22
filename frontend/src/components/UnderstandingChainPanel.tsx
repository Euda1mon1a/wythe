'use client';

import { useEffect, useState } from 'react';
import { Link2, RefreshCw, ShieldAlert } from 'lucide-react';
import { atlasApi } from '@/api/atlas';

interface NormalizedChainLink {
  key: string;
  stageIndex: number;
  label: string;
  state: string;
  consequenceSummary: string;
  evidenceLimit: string;
  missingJoins: string[];
}

interface NormalizedVerdictClause {
  clauseId: string;
  text: string;
  state: string;
  evidenceRef: string | null;
  sourceLocation: string | null;
  missingReceipt: string | null;
}

interface NormalizedUnderstandingView {
  question: string;
  evidenceRevision: string;
  consequenceHeadline: string;
  lastSupportedCause: string;
  verdictSentence: string;
  verdictClauses: NormalizedVerdictClause[];
  firstDivergence: Record<string, unknown> | null;
  rulePredictionComparisons: Array<Record<string, unknown>>;
  perturbationMatrix: Array<Record<string, unknown>>;
  overallMissingJoins: string[];
  links: NormalizedChainLink[];
  effectiveAuthority: Array<Record<string, unknown>>;
  runtimeProvenance: Array<Record<string, unknown>>;
  outcomeLifecycles: Array<Record<string, unknown>>;
  preservationEvaluations: Array<Record<string, unknown>>;
  documentationClaims: Array<Record<string, unknown>>;
  coverageStatement: string;
}

const DEFAULT_STAGE_LABELS: Array<[string, string]> = [
  ['intent', '1. Intent'],
  ['effective_policy_context', '2. Effective Policy / Context'],
  ['execution', '3. Execution'],
  ['committed_result', '4. Committed Result'],
  ['human_visible_result', '5. Human-Visible Result'],
  ['preservation_evidence', '6. Preservation Checks'],
];

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function asArrayOfRecords(v: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(v)) return [];
  return v.map(asRecord).filter((x): x is Record<string, unknown> => x !== null);
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string');
}

export function normalizeUnderstandingReport(
  raw: Record<string, unknown> | null | undefined,
): NormalizedUnderstandingView | null {
  const root = asRecord(raw);
  if (!root) return null;
  const nested =
    asRecord(root.report) ?? asRecord(root.baseline_report) ?? root;
  const rawLinks = asArrayOfRecords(nested.links);
  const links: NormalizedChainLink[] =
    rawLinks.length > 0
      ? rawLinks.map((lnk, idx) => ({
          key: String(lnk.link_key ?? `stage_${idx + 1}`),
          stageIndex: Number(lnk.stage_index ?? idx + 1),
          label: String(
            lnk.label ?? DEFAULT_STAGE_LABELS[idx]?.[1] ?? `Stage ${idx + 1}`,
          ),
          state: String(lnk.state ?? 'unresolved'),
          consequenceSummary: String(lnk.consequence_summary ?? lnk.summary ?? ''),
          evidenceLimit: String(lnk.evidence_limit ?? ''),
          missingJoins: asStringArray(lnk.missing_joins),
        }))
      : DEFAULT_STAGE_LABELS.map(([key, label], idx) => ({
          key,
          stageIndex: idx + 1,
          label,
          state: 'unresolved',
          consequenceSummary: 'No recorded evidence for this stage.',
          evidenceLimit: 'Explicit join unavailable.',
          missingJoins: [],
        }));

  const rawClauses = asArrayOfRecords(nested.verdict_clauses);
  const verdictClauses: NormalizedVerdictClause[] = rawClauses.map((cl, idx) => ({
    clauseId: String(cl.clause_id ?? `clause_${idx + 1}`),
    text: String(cl.text ?? ''),
    state: String(cl.state ?? 'unverified'),
    evidenceRef: typeof cl.evidence_ref === 'string' ? cl.evidence_ref : null,
    sourceLocation: typeof cl.source_location === 'string' ? cl.source_location : null,
    missingReceipt: typeof cl.missing_receipt === 'string' ? cl.missing_receipt : null,
  }));

  return {
    question: String(nested.question ?? ''),
    evidenceRevision: String(nested.evidence_revision ?? 'unknown'),
    consequenceHeadline: String(nested.consequence_headline ?? ''),
    lastSupportedCause: String(nested.last_supported_cause ?? ''),
    verdictSentence: String(nested.verdict_sentence ?? ''),
    verdictClauses,
    firstDivergence: asRecord(nested.first_divergence),
    rulePredictionComparisons: asArrayOfRecords(nested.rule_prediction_comparisons),
    perturbationMatrix: asArrayOfRecords(nested.perturbation_matrix),
    overallMissingJoins: asStringArray(nested.overall_missing_joins),
    links,
    effectiveAuthority: asArrayOfRecords(nested.effective_authority),
    runtimeProvenance: asArrayOfRecords(nested.runtime_provenance),
    outcomeLifecycles: asArrayOfRecords(nested.outcome_lifecycles),
    preservationEvaluations: asArrayOfRecords(nested.preservation_evaluations),
    documentationClaims: asArrayOfRecords(nested.documentation_claims),
    coverageStatement: String(nested.coverage_statement ?? ''),
  };
}

function linkTone(state: string): string {
  if (state === 'supported') {
    return 'border-emerald-500/45 bg-emerald-950/35 text-emerald-200';
  }
  if (state === 'regression_detected') {
    return 'border-rose-500/50 bg-rose-950/40 text-rose-200';
  }
  if (
    state === 'historical_needs_revalidation' ||
    state === 'degraded_or_drifted' ||
    state === 'indeterminate'
  ) {
    return 'border-amber-500/50 bg-amber-950/35 text-amber-200';
  }
  return 'border-slate-700 bg-slate-900/80 text-slate-300';
}

export function UnderstandingChainPanel({
  activeSlug,
  sessionId,
  subjectId,
  selectedFindingId = null,
  selectedEdgeId = null,
  defaultOpen = false,
}: {
  activeSlug: string;
  sessionId: string | null;
  subjectId?: string | null;
  selectedFindingId?: string | null;
  selectedEdgeId?: string | null;
  defaultOpen?: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultOpen);
  const [loading, setLoading] = useState(false);
  const [endpointUnavailable, setEndpointUnavailable] = useState(false);
  const [exampleSlugs, setExampleSlugs] = useState<Array<{ slug: string; title: string }>>([]);
  const [selectedExample, setSelectedExample] = useState<string>('');
  const [exampleVariant, setExampleVariant] = useState<
    'baseline_report' | 'candidate_report' | 'post_change_revalidation_report'
  >('baseline_report');
  const [exampleBundle, setExampleBundle] = useState<Record<string, unknown> | null>(null);
  const [liveReport, setLiveReport] = useState<NormalizedUnderstandingView | null>(null);

  const loadUnderstanding = async (explicitExample?: string) => {
    setLoading(true);
    try {
      const exListRaw = await atlasApi.listUnderstandingExamples().catch(() => null);
      if (exListRaw) {
        const items = Array.isArray(exListRaw)
          ? exListRaw
          : Array.isArray((exListRaw as { examples?: unknown }).examples)
            ? ((exListRaw as { examples: unknown[] }).examples)
            : [];
        const parsedEx = items
          .map(asRecord)
          .filter((r): r is Record<string, unknown> => Boolean(r && r.slug))
          .map((r) => ({
            slug: String(r.slug),
            title: String(r.title ?? r.slug),
          }));
        setExampleSlugs(parsedEx);
      }

      const targetEx = explicitExample ?? selectedExample;
      if (targetEx) {
        const exFull = await atlasApi.getUnderstandingExample(targetEx);
        setExampleBundle(exFull);
        setEndpointUnavailable(false);
        setLoading(false);
        return;
      }

      const explained = await atlasApi
        .getUnderstandingExplain({
          targetSlug: activeSlug || undefined,
          subjectId: subjectId ?? undefined,
          nodeId: subjectId ?? undefined,
          findingId: selectedFindingId ?? undefined,
          edgeId: selectedEdgeId ?? undefined,
          sessionId: sessionId ?? undefined,
        })
        .catch(async () =>
          atlasApi.analyzeUnderstandingBundle({
            target_slug: activeSlug || undefined,
            session_id: sessionId ?? undefined,
            subject_id: subjectId ?? undefined,
            node_id: subjectId ?? undefined,
            finding_id: selectedFindingId ?? undefined,
            edge_id: selectedEdgeId ?? undefined,
          }),
        );
      setLiveReport(normalizeUnderstandingReport(explained));
      setEndpointUnavailable(false);
    } catch {
      setEndpointUnavailable(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!expanded) return;
    void loadUnderstanding();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expanded, activeSlug, subjectId, sessionId, selectedExample]);

  const displayedReport: NormalizedUnderstandingView | null = selectedExample
    ? normalizeUnderstandingReport(
        asRecord(exampleBundle?.[exampleVariant]) ?? exampleBundle,
      )
    : liveReport;

  return (
    <section
      aria-label="Six-link outcome, authority, runtime provenance, and preservation chain"
      className="space-y-2 border border-teal-500/30 bg-slate-950/70 p-3 text-xs"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <button
          type="button"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
          className="flex min-h-6 items-center gap-1.5 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-teal-300 hover:text-teal-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
        >
          <Link2 className="h-3.5 w-3.5" />
          <span>
            Understanding Chain (Intent → Policy → Exec → Commit → Visible → Preserved)
          </span>
          <span className="text-slate-400">{expanded ? '[-]' : '[+]'}</span>
        </button>
        {expanded && (
          <button
            type="button"
            disabled={loading}
            onClick={() => void loadUnderstanding()}
            aria-label="Refresh understanding chain"
            className="flex min-h-6 items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
          >
            <RefreshCw className={`h-2.5 w-2.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        )}
      </div>

      {expanded && (
        <div className="space-y-2.5 border-t border-slate-800 pt-2">
          {exampleSlugs.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
              <select
                aria-label="Select understanding investigation source or example"
                value={selectedExample}
                onChange={(e) => {
                  const next = e.target.value;
                  setSelectedExample(next);
                  if (!next) setExampleBundle(null);
                }}
                className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                <option value="">Live Target ({activeSlug || 'current'})</option>
                {exampleSlugs.map((ex) => (
                  <option key={ex.slug} value={ex.slug}>
                    Example: {ex.slug} — {ex.title}
                  </option>
                ))}
              </select>
              {selectedExample && (
                <div role="group" aria-label="Example comparison stage" className="flex gap-1">
                  {(
                    [
                      ['baseline_report', 'Baseline'],
                      ['candidate_report', 'Candidate'],
                      ['post_change_revalidation_report', 'Post-Change'],
                    ] as const
                  ).map(([k, lbl]) => (
                    <button
                      key={k}
                      type="button"
                      aria-pressed={exampleVariant === k}
                      onClick={() => setExampleVariant(k)}
                      className={`min-h-6 border px-1.5 py-0.5 ${
                        exampleVariant === k
                          ? 'border-teal-400/70 bg-teal-500/20 text-teal-200'
                          : 'border-slate-700 bg-slate-950 text-slate-300'
                      }`}
                    >
                      {lbl}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {loading ? (
            <div role="status" className="font-mono text-[11px] text-sky-300">
              Loading 6-link understanding chain…
            </div>
          ) : endpointUnavailable && !displayedReport ? (
            <div className="border border-slate-800 bg-slate-900/60 p-2 font-mono text-[10px] text-slate-400">
              Optional `/api/v1/understanding` chain endpoint is not mounted on this server or has no companion bundle yet.
            </div>
          ) : displayedReport ? (
            <div className="space-y-2 font-mono text-[10px]">
              {/* Evidence-Linked Single-Sentence Verdict (#117) */}
              {displayedReport.verdictClauses.length > 0 && (
                <div
                  aria-label="Evidence-linked verdict summary"
                  className="space-y-1.5 border border-emerald-500/40 bg-slate-900/90 p-2.5 text-slate-100"
                >
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
                    Evidence-Linked Verdict
                  </div>
                  <blockquote className="border-l-2 border-teal-400/70 pl-2 font-sans text-xs leading-relaxed text-slate-100">
                    {displayedReport.verdictClauses.map((cl, idx) => {
                      const isSupported = cl.state === 'supported';
                      const refTarget =
                        cl.sourceLocation ??
                        cl.evidenceRef ??
                        (cl.missingReceipt ? `missing:${cl.missingReceipt}` : 'unverified');
                      return (
                        <span key={cl.clauseId} className="mr-1.5 inline">
                          <span
                            className={
                              isSupported
                                ? 'underline decoration-emerald-400/70 underline-offset-2'
                                : 'text-amber-200 underline decoration-amber-400/80 decoration-dotted underline-offset-2'
                            }
                          >
                            {cl.text}
                          </span>{' '}
                          <span
                            className={`inline-block border px-1 py-0 font-mono text-[9px] ${
                              isSupported
                                ? 'border-emerald-500/45 bg-emerald-950/50 text-emerald-200'
                                : 'border-amber-500/55 bg-amber-950/50 text-amber-200'
                            }`}
                          >
                            [{cl.state}: {refTarget}]
                          </span>
                          {idx < displayedReport.verdictClauses.length - 1 ? ' ' : ''}
                        </span>
                      );
                    })}
                  </blockquote>
                </div>
              )}

              {/* First Point of Divergence & Participant Knowledge at Decision Time (#117 AC2 / #105) */}
              {displayedReport.firstDivergence && (() => {
                const fd = displayedReport.firstDivergence;
                const storage = String(fd.exists_in_storage ?? 'unverified');
                const eligible = String(fd.eligible_for_actor ?? 'unverified');
                const inTurn = String(fd.present_in_turn ?? 'unverified');
                const callerState = String(fd.caller_attribution_state ?? 'unverified');
                const turnEv = asStringArray(fd.evidence_reaching_turn);
                const candCallers = asStringArray(fd.unattributed_candidate_callers);
                return (
                  <div
                    aria-label="First divergence and participant knowledge at decision time"
                    className="space-y-1 border border-amber-500/40 bg-amber-950/20 p-2 text-slate-200"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-1 font-semibold text-amber-200">
                      <span>First Divergence :: {String(fd.stage_label ?? 'Boundary')}</span>
                      <span>[caller: {callerState}]</span>
                    </div>
                    {Boolean(fd.summary) && (
                      <div className="font-sans text-[11px] text-slate-100">
                        {String(fd.summary)}
                      </div>
                    )}
                    <div className="grid grid-cols-1 gap-1 pt-0.5 sm:grid-cols-3">
                      <div className="border border-slate-700 bg-slate-950/80 px-1.5 py-1">
                        <div>1. In Storage: <strong>{storage}</strong></div>
                        {Boolean(fd.storage_source_ref) && (
                          <div className="truncate text-[9px] text-slate-400">
                            {String(fd.storage_source_ref)}
                          </div>
                        )}
                      </div>
                      <div className="border border-slate-700 bg-slate-950/80 px-1.5 py-1">
                        <div>2. Eligible: <strong>{eligible}</strong></div>
                        {Boolean(fd.eligibility_source_ref) && (
                          <div className="truncate text-[9px] text-slate-400">
                            {String(fd.eligibility_source_ref)}
                          </div>
                        )}
                      </div>
                      <div className="border border-slate-700 bg-slate-950/80 px-1.5 py-1">
                        <div>3. In Turn: <strong>{inTurn}</strong></div>
                        {Boolean(fd.turn_context_source_ref) && (
                          <div className="truncate text-[9px] text-slate-400">
                            {String(fd.turn_context_source_ref)}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="text-slate-300">
                      Actor: <strong>{String(fd.actor ?? 'unknown')}</strong> · Channel:{' '}
                      <strong>{String(fd.channel ?? 'unknown')}</strong>
                      {fd.observed_at ? ` · Observed: ${String(fd.observed_at)}` : ''}
                      {fd.observed_hop ? ` · Hop: ${String(fd.observed_hop)}` : ''}
                      {fd.caller_receipt_ref
                        ? ` (${String(fd.caller_receipt_ref)})`
                        : candCallers.length > 0
                          ? ` (unattributed candidates: ${candCallers.join(', ')})`
                          : ''}
                    </div>
                    {turnEv.length > 0 && (
                      <div className="text-slate-300">
                        Evidence in turn: {turnEv.join(', ')}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Rule vs. Implementation Prediction(s) vs. Observed Result (#117 AC1 / #104) */}
              {displayedReport.rulePredictionComparisons.map((rc, rIdx) => {
                const rule = asRecord(rc.owner_rule);
                const preds = asArrayOfRecords(rc.implementation_predictions);
                const obs = asRecord(rc.observed_result);
                const openQs = asStringArray(rc.open_questions);
                return (
                  <div
                    key={`rule-pred-${rIdx}`}
                    className="space-y-1 border border-sky-500/35 bg-sky-950/20 p-2 text-slate-200"
                  >
                    <div className="flex flex-wrap justify-between gap-1 font-semibold text-sky-200">
                      <span>
                        Rule vs. Prediction vs. Observed:{' '}
                        {String(rule?.label ?? rc.comparison_id ?? 'rule')}
                      </span>
                      <span>[{String(rc.state ?? 'unverified')}]</span>
                    </div>
                    {rule && (
                      <div>
                        Owner Rule: {String(rule.statement ?? '')}{' '}
                        <span className="text-sky-300">[{String(rule.source_ref ?? '')}]</span>
                      </div>
                    )}
                    {preds.map((pr, pIdx) => (
                      <div key={pIdx} className="pl-2 text-slate-300">
                        • {String(pr.reading_label)}: {String(pr.predicted_at_boundary)} [
                        {String(pr.match_state)}] ({String(pr.source_ref)})
                      </div>
                    ))}
                    {obs && (
                      <div className="text-emerald-200">
                        Observed: {String(obs.summary)} [{String(obs.source_ref)}] · deliveryVerified=
                        {String(obs.delivery_verified)}
                      </div>
                    )}
                    {Boolean(rc.discriminating_observation) && (
                      <div className="text-slate-300">
                        Distinguished by: {String(rc.discriminating_observation)}
                      </div>
                    )}
                    {openQs.map((oq, qIdx) => (
                      <div key={qIdx} className="text-amber-200">
                        Open: {oq}
                      </div>
                    ))}
                  </div>
                );
              })}

              {/* Single-Variable Perturbation Checks (#117 AC3) */}
              {displayedReport.perturbationMatrix.length > 0 && (
                <div
                  aria-label="Single-variable perturbation checks"
                  className="space-y-1 border border-teal-500/35 bg-teal-950/15 p-2 text-slate-200"
                >
                  <div className="font-semibold text-teal-200">
                    Fresh-Case Perturbation Matrix (Vary One Factor at a Time)
                  </div>
                  {displayedReport.perturbationMatrix.map((pm, pIdx) => (
                    <div
                      key={`pert-${pIdx}`}
                      className={pm.passed ? 'text-emerald-200' : 'text-rose-300'}
                    >
                      [{pm.passed ? 'PASS' : 'FAIL'} · {String(pm.conclusion_state)}]{' '}
                      <strong>{String(pm.varied_factor)}</strong> — {String(pm.observed_outcome)}
                      {pm.decisive_receipt_ref ? ` [${String(pm.decisive_receipt_ref)}]` : ''}
                      {pm.missing_receipt_id
                        ? ` [missing: ${String(pm.missing_receipt_id)}]`
                        : ''}
                    </div>
                  ))}
                </div>
              )}

              {displayedReport.consequenceHeadline && (
                <div className="border border-teal-500/35 bg-teal-950/25 p-2 text-slate-100">
                  <div className="font-semibold text-teal-200">
                    {displayedReport.consequenceHeadline}
                  </div>
                  {displayedReport.lastSupportedCause && (
                    <div className="mt-0.5 text-slate-300">
                      Last supported cause: {displayedReport.lastSupportedCause}
                    </div>
                  )}
                  {displayedReport.overallMissingJoins.length > 0 && (
                    <div className="mt-1 text-amber-300">
                      Missing joins: {displayedReport.overallMissingJoins.join(', ')}
                    </div>
                  )}
                </div>
              )}

              {/* 6-Link Chain */}
              <div className="space-y-1">
                {displayedReport.links.map((lnk) => (
                  <div
                    key={`${lnk.stageIndex}-${lnk.key}`}
                    className={`border px-2 py-1.5 ${linkTone(lnk.state)}`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-1">
                      <span className="font-semibold">{lnk.label}</span>
                      <span className="uppercase opacity-90">[{lnk.state}]</span>
                    </div>
                    {lnk.consequenceSummary && (
                      <div className="mt-0.5 font-sans text-[11px] text-slate-100">
                        {lnk.consequenceSummary}
                      </div>
                    )}
                    {lnk.evidenceLimit && (
                      <div className="mt-0.5 text-[10px] text-slate-300">
                        Limit: {lnk.evidenceLimit}
                      </div>
                    )}
                    {lnk.missingJoins.length > 0 && (
                      <div className="mt-0.5 text-[10px] text-amber-200">
                        Unresolved joins: {lnk.missingJoins.join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Effective Policy / Context Bindings */}
              {displayedReport.effectiveAuthority.map((auth, idx) => {
                const winner = asRecord(auth.winning_binding);
                const skipped = asArrayOfRecords(auth.skipped_or_overridden_bindings);
                const orphans = asStringArray(auth.orphan_penalty_channels);
                const lanes = asArrayOfRecords(auth.lane_evaluations);
                return (
                  <div
                    key={`auth-${idx}`}
                    className="space-y-1 border border-sky-500/30 bg-sky-950/15 p-2 text-slate-200"
                  >
                    <div className="font-semibold text-sky-300">
                      Effective Authority: {String(auth.label ?? auth.item_id ?? 'policy')} [
                      {String(auth.evidence_state ?? 'unresolved')}]
                    </div>
                    {winner && (
                      <div className="text-emerald-200">
                        Winner: {String(winner.scope_label ?? winner.binding_id)} ={' '}
                        {JSON.stringify(winner.value)} ({String(winner.source_kind ?? '')})
                      </div>
                    )}
                    {skipped.length > 0 && (
                      <div className="text-amber-200">
                        Skipped / conflicting ({skipped.length}):{' '}
                        {skipped
                          .map(
                            (s) =>
                              `${String(s.scope_label ?? s.binding_id)} [${String(s.disposition)}]`,
                          )
                          .join('; ')}
                      </div>
                    )}
                    {orphans.length > 0 && (
                      <div className="text-rose-300">
                        Orphan objective penalty channels: {orphans.join(', ')}
                      </div>
                    )}
                    {lanes.length > 0 && (
                      <div className="space-y-0.5 pt-0.5">
                        {lanes.map((ln, lIdx) => (
                          <div key={lIdx} className="text-slate-300">
                            Lane <strong>{String(ln.lane)}</strong>: offered=
                            {String(ln.offered_in_request)} · grounding=
                            {String(ln.authored_reply_state)} · delivery=
                            {String(ln.delivery_state)} [{String(ln.lane_verdict)}]
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Disk vs Running-Process Provenance */}
              {displayedReport.runtimeProvenance.map((prov, idx) => (
                <div
                  key={`prov-${idx}`}
                  className="space-y-0.5 border border-slate-700 bg-slate-900/75 p-2 text-slate-200"
                >
                  <div className="flex flex-wrap justify-between gap-1 font-semibold text-amber-200">
                    <span>Runtime Provenance: {String(prov.subject_id ?? 'process')}</span>
                    <span>[{String(prov.overall_status ?? 'unverified')}]</span>
                  </div>
                  <div>
                    Disk rev: {String(prov.repo_revision ?? '—')} · Running startup rev:{' '}
                    {String(prov.process_startup_revision ?? '—')}
                    {prov.process_pid ? ` (pid ${String(prov.process_pid)})` : ''}
                  </div>
                  {asStringArray(prov.discrepancies).length > 0 && (
                    <div className="text-rose-300">
                      Discrepancies: {asStringArray(prov.discrepancies).join('; ')}
                    </div>
                  )}
                </div>
              ))}

              {/* Outcome Settlement & Delivery Boundaries */}
              {displayedReport.outcomeLifecycles.map((out, idx) => (
                <div
                  key={`out-${idx}`}
                  className="space-y-0.5 border border-amber-500/35 bg-amber-950/20 p-2 text-slate-200"
                >
                  <div className="font-semibold text-amber-300">
                    Outcome Boundary: stage={String(out.current_stage)} · settlement=
                    {String(out.settlement_state)} · grounding=
                    {String(out.answer_grounding)} · delivery={String(out.delivery_status)}
                  </div>
                  {Boolean(out.blind_retry_prohibited) && (
                    <div className="flex items-center gap-1 text-rose-300">
                      <ShieldAlert className="h-3 w-3" />
                      Do NOT blindly retry write before authoritative settlement:{' '}
                      {String(out.retry_guidance ?? '')}
                    </div>
                  )}
                  {out.next_evidence_check ? (
                    <div className="text-slate-300">
                      Next check: {String(out.next_evidence_check)}
                    </div>
                  ) : null}
                </div>
              ))}

              {/* Preservation & Lane-by-Lane Checks */}
              {displayedReport.preservationEvaluations.map((pres, idx) => {
                const laneChecks = asArrayOfRecords(pres.lane_checks);
                const solverComp = asRecord(pres.solver_comparison);
                return (
                  <div
                    key={`pres-${idx}`}
                    className="space-y-1 border border-teal-500/35 bg-teal-950/15 p-2 text-slate-200"
                  >
                    <div className="flex flex-wrap justify-between gap-1 font-semibold text-teal-200">
                      <span>Preservation Contract: {String(pres.desired_change ?? '')}</span>
                      <span>[{String(pres.verdict ?? '')}]</span>
                    </div>
                    {Boolean(pres.non_git_semantic_drift_detected) && (
                      <div className="text-amber-300">
                        Non-Git semantic change detected:{' '}
                        {asStringArray(pres.changed_non_git_factors).join(', ')}
                      </div>
                    )}
                    {laneChecks.map((lc, cIdx) => (
                      <div
                        key={cIdx}
                        className={lc.passed ? 'text-emerald-300' : 'text-rose-300'}
                      >
                        [{lc.passed ? 'PASS' : 'FAIL'}] {String(lc.lane)} ::{' '}
                        {String(lc.capability)} ({String(lc.expectation)}) —{' '}
                        {String(lc.detail ?? '')}
                      </div>
                    ))}
                    {solverComp && (
                      <div className="text-sky-200">
                        Solver semantic comparison: [{String(solverComp.verdict)}] rawEqual=
                        {String(solverComp.raw_schedule_equal)} · hardValid=
                        {String(solverComp.hard_constraints_valid)} · exportEqual=
                        {String(solverComp.export_meaning_equal)}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Historical Doc / Note Freshness */}
              {displayedReport.documentationClaims.map((doc, idx) => (
                <div
                  key={`doc-${idx}`}
                  className="border border-amber-500/35 bg-amber-950/20 p-2 text-amber-100"
                >
                  <div>
                    <strong>{String(doc.document_or_note_path)}</strong>:{' '}
                    {doc.status === 'historical_needs_revalidation'
                      ? '[historical / needs revalidation]'
                      : `[${String(doc.status)}]`}
                  </div>
                  <div className="text-slate-300">
                    Current code evidence: {String(doc.current_code_evidence ?? '')}
                  </div>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}
