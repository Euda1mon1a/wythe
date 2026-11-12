'use client';

import { useMemo, useState, type FormEvent } from 'react';
import { Copy, History, Stamp, X } from 'lucide-react';
import type { AtlasEdge, AtlasNode, BoundaryFinding } from '@/api/atlas';
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
  diffOverlay?: DiffOverlaySet | null;
  onSelectNode: (nodeId: string) => void;
  onClose: () => void;
}

export function NodeInspector({
  activeSlug,
  node,
  allNodesById,
  edges,
  findings,
  diffOverlay = null,
  onSelectNode,
  onClose,
}: NodeInspectorProps) {
  const [disposition, setDisposition] = useState('confirmed_owner_intent');
  const [summary, setSummary] = useState('');
  const [cutoverHistory, setCutoverHistory] = useState('');
  const [copiedConeLabel, setCopiedConeLabel] = useState<string | null>(null);
  const [showAllColumns, setShowAllColumns] = useState(false);
  const createRuling = useCreateRuling(activeSlug);
  const fetchCone = useFetchContextCone(activeSlug);

  const { inbound, outbound, nodeFindings } = useMemo(() => {
    if (!node) return { inbound: [], outbound: [], nodeFindings: [] };
    return {
      inbound: edges.filter((e) => e.target_id === node.id),
      outbound: edges.filter((e) => e.source_id === node.id),
      nodeFindings: findings.filter((f) => f.node_id === node.id),
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
    createRuling.mutate(
      {
        node_id: node.id,
        disposition,
        summary: summary.trim(),
        cutover_history: cutoverHistory.trim() || null,
        recorded_by: 'operator',
      },
      {
        onSuccess: () => {
          setSummary('');
          setCutoverHistory('');
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
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            disabled={fetchCone.isPending}
            onClick={() => {
              fetchCone.mutate(node.id, {
                onSuccess: (res) => {
                  void copyTextToClipboard(res.markdown).then((ok) => {
                    setCopiedConeLabel(ok ? `Copied ~${res.approx_tokens} tok` : 'Copy failed');
                    window.setTimeout(() => setCopiedConeLabel(null), 2200);
                  });
                },
              });
            }}
            aria-label="Copy 3-tier LLM Lineage Cone Markdown"
            title="Copy surgical 3-tier Lineage Cone Markdown (~300 tokens) for LLMs"
            className="flex items-center gap-1 border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 font-mono text-[11px] text-sky-200 hover:bg-sky-500/25"
          >
            <Copy className="h-3 w-3" />
            {copiedConeLabel ?? 'Copy LLM Cone'}
          </button>
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
          {nodeFindings.slice(0, 4).map((f) => (
            <div key={f.id} className="border border-rose-500/20 bg-slate-950/75 p-2 text-[11px] text-slate-200">
              <strong className="font-mono text-rose-300">{f.rule_code}:</strong> {f.title}
              <div className="mt-0.5 text-[10px] text-slate-300">{f.remediation}</div>
            </div>
          ))}
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
        onSelectNode={onSelectNode}
      />

      {/* Inbound / Outbound Verified Links + Evidence Notes */}
      <div className="space-y-2 border-t border-slate-800 pt-3">
        <div className="font-mono text-[10px] uppercase text-slate-400">
          Inbound Links ({inbound.length})
        </div>
        <div className="max-h-32 space-y-1.5 overflow-y-auto">
          {inbound.slice(0, 30).map((e) => {
            const peer = allNodesById.get(e.source_id);
            const verTone =
              e.verification === 'verified'
                ? 'text-teal-300'
                : e.verification === 'declared'
                  ? 'text-sky-300'
                  : 'text-rose-300';
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
                  <span className={verTone}>{e.verification}</span>
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
            const verTone =
              e.verification === 'verified'
                ? 'text-teal-300'
                : e.verification === 'declared'
                  ? 'text-sky-300'
                  : 'text-rose-300';
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
                  <span className={verTone}>{e.verification}</span>
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
          onChange={(e) => setDisposition(e.target.value)}
          className="w-full border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-xs text-slate-200"
        >
          <option value="confirmed_owner_intent">confirmed_owner_intent</option>
          <option value="accepted_clean">accepted_clean</option>
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
