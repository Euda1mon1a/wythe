'use client';

import { useMemo, useState, type FormEvent } from 'react';
import { Copy, History, Stamp, X } from 'lucide-react';
import type {
  AtlasEdge,
  AtlasNode,
  BoundaryFinding,
  ConeCompleteness,
  PortableReferenceExemplar,
  StorePurposeDeclaration,
} from '@/api/atlas';
import { NodeSourceAndPromptPanel } from '@/components/NodeSourceAndPromptPanel';
import { useCreateRuling, useFetchContextCone } from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import { formatCalendarDay } from '@/lib/clock';
import {
  deriveDomainCluster,
  type DiffOverlaySet,
} from '@/lib/wytheSceneLenses';

interface NodeInspectorProps {
  activeSlug: string;
  node: AtlasNode | null;
  allNodesById: Map<string, AtlasNode>;
  edges: AtlasEdge[];
  findings: BoundaryFinding[];
  referenceExemplars?: PortableReferenceExemplar[];
  diffOverlay?: DiffOverlaySet | null;
  inWorkingSet?: boolean;
  onToggleWorkingSet?: (nodeId: string) => void;
  onSelectNode: (nodeId: string) => void;
  onClose: () => void;
}

function edgeStateBadge(verification: AtlasEdge['verification']): {
  tone: string;
  text: string;
} {
  if (verification === 'verified') {
    return { tone: 'text-teal-300', text: 'verified · solid' };
  }
  if (verification === 'declared') {
    return { tone: 'text-violet-300', text: 'declared · dashed' };
  }
  if (verification === 'unverified') {
    return { tone: 'text-amber-300', text: 'unverified · dotted' };
  }
  return { tone: 'text-rose-300', text: 'broken · gap' };
}

export function NodeInspector({
  activeSlug,
  node,
  allNodesById,
  edges,
  findings,
  referenceExemplars = [],
  diffOverlay = null,
  inWorkingSet = false,
  onToggleWorkingSet,
  onSelectNode,
  onClose,
}: NodeInspectorProps) {
  const [disposition, setDisposition] = useState('confirmed_owner_intent');
  const [summary, setSummary] = useState('');
  const [cutoverHistory, setCutoverHistory] = useState('');
  const [showPurposeFields, setShowPurposeFields] = useState(false);
  const [intendedUse, setIntendedUse] = useState<StorePurposeDeclaration['intended_use'] | ''>('');
  const [authoritativeSource, setAuthoritativeSource] = useState('');
  const [copyReason, setCopyReason] = useState('');
  const [refreshPolicy, setRefreshPolicy] = useState('');
  const [recoveryExpectation, setRecoveryExpectation] = useState('');
  const [keyspaceScope, setKeyspaceScope] = useState('');
  const [evidenceScopeInput, setEvidenceScopeInput] = useState('');
  const [copiedConeLabel, setCopiedConeLabel] = useState<string | null>(null);
  const [copiedFullLabel, setCopiedFullLabel] = useState<string | null>(null);
  const [coneCompleteness, setConeCompleteness] = useState<ConeCompleteness | null>(null);
  const [showAllColumns, setShowAllColumns] = useState(false);
  const createRuling = useCreateRuling(activeSlug);
  const fetchCone = useFetchContextCone(activeSlug);

  const { inbound, outbound, nodeFindings } = useMemo(() => {
    if (!node) return { inbound: [], outbound: [], nodeFindings: [] };
    return {
      inbound: edges.filter((e) => e.target_id === node.id),
      outbound: edges.filter((e) => e.source_id === node.id),
      nodeFindings: findings.filter(
        (f) => f.node_id === node.id || f.target_node_id === node.id,
      ),
    };
  }, [node, edges, findings]);

  if (!node) {
    return (
      <aside aria-label="Node Inspector" className="border-l border-slate-800 bg-slate-950/60 p-5 text-xs text-slate-300">
        <div className="font-mono uppercase tracking-wider text-slate-400">Node Inspector</div>
        <p className="mt-2 leading-relaxed">
          Click any icosahedron (SQL table), hex-torus (Redis queue/cache), octahedron (backend manipulator), or hex-bipyramid (frontend display surface) in the 3D Wythe lattice—or any row in Lineage/Index—to inspect verified links, provenance, and rulings.
        </p>
      </aside>
    );
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!summary.trim()) return;
    const trimmedEvidenceScope = evidenceScopeInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const storePurpose: StorePurposeDeclaration | null = intendedUse
      ? {
          intended_use: intendedUse,
          authoritative_source: authoritativeSource.trim() || null,
          copy_reason: copyReason.trim() || null,
          refresh_policy: refreshPolicy.trim() || null,
          recovery_expectation: recoveryExpectation.trim() || null,
          keyspace_scope: keyspaceScope.trim() || null,
        }
      : null;
    createRuling.mutate(
      {
        node_id: node.id,
        disposition,
        summary: summary.trim(),
        cutover_history: cutoverHistory.trim() || null,
        store_purpose: storePurpose,
        evidence_scope: trimmedEvidenceScope,
        recorded_by: 'operator',
      },
      {
        onSuccess: () => {
          setSummary('');
          setCutoverHistory('');
          setIntendedUse('');
          setAuthoritativeSource('');
          setCopyReason('');
          setRefreshPolicy('');
          setRecoveryExpectation('');
          setKeyspaceScope('');
          setEvidenceScopeInput('');
        },
      },
    );
  };

  return (
    <aside className="space-y-4 border-l border-slate-800 bg-slate-950/80 p-5 text-xs">
      <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
        <div>
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-teal-400">
            <span>
              {node.tier} · {node.subkind} · {node.status}
            </span>
            {nodeFindings.length > 0 && (
              <span className="border border-rose-500/40 bg-rose-500/20 px-1.5 py-0.5 text-rose-200">
                {nodeFindings.length} finding{nodeFindings.length > 1 ? 's' : ''} ({nodeFindings[0].rule_code})
              </span>
            )}
          </div>
          <h3 className="mt-0.5 break-all font-mono text-sm font-semibold text-slate-100">
            {node.label}
          </h3>
          <div className="mt-1 font-mono text-[11px] text-slate-400">
            {node.source_file}:{node.line} · district:{' '}
            <span className="text-slate-200">{deriveDomainCluster(node)}</span>
            {node.role ? ` · ${node.role}` : ''}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            disabled={fetchCone.isPending}
            onClick={() => {
              fetchCone.mutate(node.id, {
                onSuccess: (res) => {
                  setConeCompleteness(res.completeness ?? null);
                  void copyTextToClipboard(res.markdown).then((ok) => {
                    setCopiedConeLabel(ok ? `Copied ~${res.approx_tokens} tok` : 'Copy failed');
                    window.setTimeout(() => setCopiedConeLabel(null), 2200);
                  });
                },
              });
            }}
            aria-label="Copy 3-tier LLM Lineage Cone Markdown"
            title="Copy budgeted 3-tier Lineage Cone Markdown (~300 tokens) with truncation summary"
            className="flex items-center gap-1 border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 font-mono text-[11px] text-sky-200 hover:bg-sky-500/25"
          >
            <Copy className="h-3 w-3" />
            {copiedConeLabel ?? 'Copy LLM Cone'}
          </button>
          <button
            type="button"
            disabled={fetchCone.isPending}
            onClick={() => {
              fetchCone.mutate(
                { query: node.id, full: true },
                {
                  onSuccess: (res) => {
                    setConeCompleteness(res.completeness ?? null);
                    void copyTextToClipboard(res.markdown).then((ok) => {
                      setCopiedFullLabel(ok ? `Full ~${res.approx_tokens} tok` : 'Copy failed');
                      window.setTimeout(() => setCopiedFullLabel(null), 2200);
                    });
                  },
                },
              );
            }}
            aria-label="Copy complete un-truncated 3-tier LLM Lineage Cone Markdown"
            title="Copy complete un-truncated 3-tier Lineage Cone (all reachable nodes, edges, and findings)"
            className="flex items-center gap-1 border border-teal-500/40 bg-teal-500/15 px-2 py-0.5 font-mono text-[11px] text-teal-200 hover:bg-teal-500/25"
          >
            <Copy className="h-3 w-3" />
            {copiedFullLabel ?? 'Full Cone'}
          </button>
          {onToggleWorkingSet && (
            <button
              type="button"
              onClick={() => onToggleWorkingSet(node.id)}
              aria-label={inWorkingSet ? 'Remove node from working set' : 'Add node to working set'}
              className={`border px-2 py-0.5 font-mono text-[11px] ${
                inWorkingSet
                  ? 'border-teal-400/60 bg-teal-500/20 text-teal-200'
                  : 'border-slate-600 bg-slate-900 text-slate-300 hover:border-teal-400'
              }`}
            >
              {inWorkingSet ? 'In Set ✓' : '+ Set'}
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Clear selection"
            className="text-slate-400 hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {coneCompleteness && (
        <div
          className={`border px-2.5 py-1.5 font-mono text-[10px] ${
            coneCompleteness.is_complete
              ? 'border-teal-500/30 bg-teal-950/20 text-teal-200'
              : 'border-amber-500/40 bg-amber-950/25 text-amber-200'
          }`}
        >
          {coneCompleteness.is_complete
            ? `Cone export complete: nodes ${coneCompleteness.nodes?.included ?? 0}/${coneCompleteness.nodes?.eligible ?? 0}, edges ${coneCompleteness.markdown_edges?.included ?? 0}/${coneCompleteness.edges?.eligible ?? 0}, findings ${coneCompleteness.findings?.included ?? 0}/${coneCompleteness.findings?.eligible ?? 0}.`
            : `Cone truncated: nodes ${coneCompleteness.nodes?.included ?? 0}/${coneCompleteness.nodes?.eligible ?? 0} (up ${coneCompleteness.upstream_nodes?.included ?? 0}/${coneCompleteness.upstream_nodes?.eligible ?? 0}, down ${coneCompleteness.downstream_nodes?.included ?? 0}/${coneCompleteness.downstream_nodes?.eligible ?? 0}), md edges ${coneCompleteness.markdown_edges?.included ?? 0}/${coneCompleteness.edges?.eligible ?? 0}, findings ${coneCompleteness.findings?.included ?? 0}/${coneCompleteness.findings?.eligible ?? 0} (seed ${coneCompleteness.seed_findings?.included ?? 0}/${coneCompleteness.seed_findings?.eligible ?? 0}). Use Full Cone above.`}
        </div>
      )}

      {/* Above-the-fold Why Highlighted & Active Findings Banner */}
      {(nodeFindings.length > 0 ||
        (diffOverlay &&
          (diffOverlay.newFindingNodeIds.has(node.id) ||
            diffOverlay.touchedIds.has(node.id) ||
            diffOverlay.impactedIds.has(node.id)))) && (
        <div className="space-y-1.5 border border-rose-500/35 bg-rose-950/20 p-2.5">
          <div className="font-mono text-[10px] uppercase tracking-wider text-rose-300">
            {diffOverlay?.newFindingNodeIds.has(node.id)
              ? `Crimson in 3D Blast (${diffOverlay.label}) · Active Rule Violation`
              : diffOverlay?.touchedIds.has(node.id)
                ? `Amber in 3D Blast (${diffOverlay.label}) · Touched File`
                : diffOverlay?.impactedIds.has(node.id) && nodeFindings.length === 0
                  ? `Sky-Blue in 3D Blast (${diffOverlay.label}) · Transitive Blast Cone`
                  : `Active Boundary Findings (${nodeFindings.length})`}
          </div>
          {nodeFindings.slice(0, 4).map((f) => {
            const isCausalWriter =
              f.target_node_id === node.id && f.node_id !== node.id;
            return (
              <div key={f.id} className="border border-rose-500/20 bg-slate-950/75 p-2 text-[11px] text-slate-200">
                <div className="flex flex-wrap items-center justify-between gap-1">
                  <strong className="font-mono text-rose-300">{f.rule_code}</strong>
                  <span className="font-mono text-[10px] text-slate-300">
                    {f.severity} · {f.confidence} · {f.evidence_strength}
                  </span>
                </div>
                <div className="mt-0.5">{f.title}</div>
                <div className="mt-0.5 font-mono text-[10px] text-amber-200/90">
                  {isCausalWriter
                    ? `Causal writer: ${f.node_id} @ ${f.source_file}:${f.line}`
                    : `${f.source_file}:${f.line}`}
                </div>
                <div className="mt-0.5 text-[10px] text-slate-300">{f.remediation}</div>
              </div>
            );
          })}
        </div>
      )}

      <p className="leading-relaxed text-slate-300">{node.summary}</p>

      {/* Separate Provenance / Cutover History (never conflated with status!) */}
      {node.cutover_history && (
        <div className="border border-slate-800 bg-slate-900/60 p-3">
          <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase text-sky-300">
            <History className="h-3.5 w-3.5" />
            Transition Provenance (Status remains {node.status})
          </div>
          <p className="mt-1 text-slate-300">{node.cutover_history}</p>
        </div>
      )}

      {/* Declared Store Purpose vs Static Verification (kept distinct!) */}
      {(node.store_purpose || node.verification_note) && (
        <div className="space-y-2 border border-amber-500/30 bg-amber-950/15 p-3">
          <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-amber-300">
            <span>Declared Store Purpose vs Verification</span>
            <span className="text-slate-300">status: {node.status}</span>
          </div>
          {node.store_purpose && (
            <div className="space-y-1 text-[11px] text-slate-200">
              <div>
                <span className="font-mono text-slate-400">Declared Intent (NOT verification): </span>
                <span className="font-mono text-teal-300">{node.store_purpose.intended_use}</span>
              </div>
              {node.store_purpose.authoritative_source && (
                <div>
                  <span className="font-mono text-slate-400">Authoritative Source: </span>
                  <span className="font-mono">{node.store_purpose.authoritative_source}</span>
                </div>
              )}
              {node.store_purpose.copy_reason && (
                <div>
                  <span className="font-mono text-slate-400">Copy Reason: </span>
                  {node.store_purpose.copy_reason}
                </div>
              )}
              {node.store_purpose.refresh_policy && (
                <div>
                  <span className="font-mono text-slate-400">Refresh / Invalidation: </span>
                  {node.store_purpose.refresh_policy}
                </div>
              )}
              {node.store_purpose.recovery_expectation && (
                <div>
                  <span className="font-mono text-slate-400">Recovery Expectation: </span>
                  {node.store_purpose.recovery_expectation}
                </div>
              )}
              {node.store_purpose.keyspace_scope && (
                <div>
                  <span className="font-mono text-slate-400">Keyspace Scope: </span>
                  <span className="font-mono">{node.store_purpose.keyspace_scope}</span>
                </div>
              )}
            </div>
          )}
          {(node.store_purpose?.verification_summary ?? node.verification_note) && (
            <div className="border-t border-amber-500/20 pt-1.5 text-[11px] text-slate-300">
              <span className="font-mono text-[10px] uppercase text-amber-200">Verification: </span>
              {node.store_purpose?.verification_summary ?? node.verification_note}
            </div>
          )}
        </div>
      )}

      {node.ruling_summary && (
        <div className="border border-teal-500/30 bg-teal-950/20 p-3">
          <div className="flex items-center justify-between font-mono text-[10px] uppercase text-teal-300">
            <span>Recorded Ruling</span>
            <span>{formatCalendarDay(node.ruling_audited_at)}</span>
          </div>
          <p className="mt-1 text-slate-200">{node.ruling_summary}</p>
        </div>
      )}

      {node.columns && node.columns.length > 0 && (
        <div>
          <div className="flex items-center justify-between font-mono text-[10px] uppercase text-slate-400">
            <span>
              Columns ({node.columns.length}) · Read by {node.read_by_count} · Written by{' '}
              {node.written_by_count}
            </span>
            {node.columns.length > 18 && (
              <button
                type="button"
                onClick={() => setShowAllColumns((v) => !v)}
                className="text-teal-300 hover:underline"
              >
                {showAllColumns ? 'Collapse' : `Show all ${node.columns.length}`}
              </button>
            )}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {(showAllColumns ? node.columns : node.columns.slice(0, 18)).map((c) => (
              <span
                key={c}
                className="border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-200"
              >
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      {((node.http_paths && node.http_paths.length > 0) ||
        (node.http_methods && node.http_methods.length > 0)) && (
        <div>
          <div className="font-mono text-[10px] uppercase text-slate-400">HTTP Contracts</div>
          {node.http_methods && node.http_methods.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1 font-mono text-[10px]">
              {node.http_methods.map((m) => (
                <span
                  key={m}
                  className={`px-1.5 py-0.5 font-semibold ${
                    m === 'GET'
                      ? 'bg-sky-500/15 text-sky-300'
                      : 'bg-amber-500/15 text-amber-300'
                  }`}
                >
                  {m}
                </span>
              ))}
            </div>
          )}
          {node.http_paths && node.http_paths.length > 0 && (
            <div className="mt-1 max-h-24 space-y-1 overflow-y-auto font-mono text-[11px] text-sky-300">
              {node.http_paths.map((p) => (
                <div key={p}>{p}</div>
              ))}
            </div>
          )}
        </div>
      )}

      <NodeSourceAndPromptPanel
        activeSlug={activeSlug}
        node={node}
        allNodesById={allNodesById}
        inbound={inbound}
        outbound={outbound}
        nodeFindings={nodeFindings}
        referenceExemplars={referenceExemplars}
        onSelectNode={onSelectNode}
      />

      {/* Inbound / Outbound Connection Evidence (4-state static verification) */}
      <div className="space-y-2 border-t border-slate-800 pt-3">
        <div className="font-mono text-[10px] text-slate-400">
          Static link states (`verified · solid`, `declared · dashed`, `unverified · dotted`, `broken · gap`) reflect AST/route inspection, not runtime execution.
        </div>
        <div className="font-mono text-[10px] uppercase text-slate-400">
          Inbound Links ({inbound.length})
        </div>
        <div className="max-h-32 space-y-1.5 overflow-y-auto">
          {inbound.slice(0, 30).map((e) => {
            const peer = allNodesById.get(e.source_id);
            const badge = edgeStateBadge(e.verification);
            return (
              <div key={e.id} className="border-b border-slate-900 pb-1">
                <button
                  type="button"
                  onClick={() => onSelectNode(e.source_id)}
                  className="block w-full truncate text-left font-mono text-[11px] text-slate-200 hover:text-teal-300"
                >
                  ← [{e.kind}] {peer?.label ?? e.source_id}
                </button>
                <div className="flex items-center gap-1.5 truncate font-mono text-[10px] text-slate-400">
                  <span className={badge.tone}>{badge.text}</span>
                  {e.evidence_path && <span title={e.evidence_path}>· {e.evidence_path}</span>}
                  {e.evidence_note && <span title={e.evidence_note}>· {e.evidence_note}</span>}
                </div>
              </div>
            );
          })}
        </div>

        <div className="pt-1 font-mono text-[10px] uppercase text-slate-400">
          Outbound Links ({outbound.length})
        </div>
        <div className="max-h-32 space-y-1.5 overflow-y-auto">
          {outbound.slice(0, 30).map((e) => {
            const peer = allNodesById.get(e.target_id);
            const badge = edgeStateBadge(e.verification);
            return (
              <div key={e.id} className="border-b border-slate-900 pb-1">
                <button
                  type="button"
                  onClick={() => onSelectNode(e.target_id)}
                  className="block w-full truncate text-left font-mono text-[11px] text-slate-200 hover:text-teal-300"
                >
                  → [{e.kind}] {peer?.label ?? e.target_id}
                </button>
                <div className="flex items-center gap-1.5 truncate font-mono text-[10px] text-slate-400">
                  <span className={badge.tone}>{badge.text}</span>
                  {e.evidence_path && <span title={e.evidence_path}>· {e.evidence_path}</span>}
                  {e.evidence_note && <span title={e.evidence_note}>· {e.evidence_note}</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Audited Ruling Write Door */}
      <form onSubmit={handleSubmit} className="space-y-2 border-t border-slate-800 pt-3">
        <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase text-slate-400">
          <Stamp className="h-3.5 w-3.5 text-teal-400" />
          Record Ownership Ruling (DB Truth)
        </div>
        <select
          aria-label="Ownership ruling disposition"
          value={disposition}
          onChange={(e) => {
            const next = e.target.value;
            setDisposition(next);
            if (next === 'intentional_copy') {
              setShowPurposeFields(true);
            }
          }}
          className="w-full border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-xs text-slate-200"
        >
          <option value="confirmed_owner_intent">confirmed_owner_intent</option>
          <option value="accepted_clean">accepted_clean</option>
          <option value="intentional_copy">intentional_copy</option>
          <option value="deferred_cutover">deferred_cutover</option>
        </select>
        <textarea
          aria-label="Ownership ruling summary"
          rows={2}
          value={summary}
          onChange={(e) => setSummary(e.target.value)}
          placeholder="Dated decision or boundary note…"
          className="w-full border border-slate-800 bg-slate-900 p-2 text-xs text-slate-200 placeholder:text-slate-400"
        />
        <input
          type="text"
          aria-label="Cutover provenance note"
          value={cutoverHistory}
          onChange={(e) => setCutoverHistory(e.target.value)}
          placeholder="Optional cutover provenance note…"
          className="w-full border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
        />
        <button
          type="button"
          aria-label="Toggle store purpose and evidence scope fields"
          onClick={() => setShowPurposeFields((v) => !v)}
          className="font-mono text-[10px] text-sky-300 hover:text-sky-200"
        >
          {showPurposeFields ? 'Hide Store Purpose & Scope' : '+ Declare Store Purpose & Evidence Scope'}
        </button>
        {(showPurposeFields || disposition === 'intentional_copy') && (
          <div className="space-y-1.5 border border-slate-800 bg-slate-900/50 p-2">
            <select
              aria-label="Store intended use"
              value={intendedUse}
              onChange={(e) =>
                setIntendedUse(
                  (e.target.value as StorePurposeDeclaration['intended_use']) || '',
                )
              }
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-200"
            >
              <option value="">-- Optional store intended_use --</option>
              <option value="derived_cache">derived_cache</option>
              <option value="read_replica">read_replica</option>
              <option value="materialized_view">materialized_view</option>
              <option value="historical_snapshot">historical_snapshot</option>
              <option value="persistent_config">persistent_config</option>
              <option value="ephemeral_state">ephemeral_state</option>
              <option value="queue_buffer">queue_buffer</option>
              <option value="authoritative_store">authoritative_store</option>
            </select>
            <input
              type="text"
              aria-label="Authoritative source"
              value={authoritativeSource}
              onChange={(e) => setAuthoritativeSource(e.target.value)}
              placeholder="Authoritative source (e.g. pg:orders)"
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
            />
            <input
              type="text"
              aria-label="Copy reason"
              value={copyReason}
              onChange={(e) => setCopyReason(e.target.value)}
              placeholder="Copy reason…"
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
            />
            <input
              type="text"
              aria-label="Refresh or invalidation policy"
              value={refreshPolicy}
              onChange={(e) => setRefreshPolicy(e.target.value)}
              placeholder="Refresh / invalidation policy…"
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
            />
            <input
              type="text"
              aria-label="Recovery expectation"
              value={recoveryExpectation}
              onChange={(e) => setRecoveryExpectation(e.target.value)}
              placeholder="Recovery expectation (e.g. SQL seed / RDB)…"
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
            />
            <input
              type="text"
              aria-label="Keyspace scope"
              value={keyspaceScope}
              onChange={(e) => setKeyspaceScope(e.target.value)}
              placeholder="Keyspace scope (e.g. session:*, catalog:*)"
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
            />
            <input
              type="text"
              aria-label="Evidence scope rules or files"
              value={evidenceScopeInput}
              onChange={(e) => setEvidenceScopeInput(e.target.value)}
              placeholder="Evidence scope (comma-separated rule/file)"
              className="w-full border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-400"
            />
          </div>
        )}
        <button
          type="submit"
          disabled={createRuling.isPending || !summary.trim()}
          className="w-full border border-teal-500/40 bg-teal-500/15 py-1.5 font-mono text-xs font-medium text-teal-300 hover:bg-teal-500/25 disabled:opacity-40"
        >
          {createRuling.isPending ? 'Recording…' : 'Save Ruling to Database'}
        </button>
      </form>
    </aside>
  );
}
