'use client';

import { useMemo, useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Database,
  FileCode2,
  Globe,
  Play,
  Search,
} from 'lucide-react';
import type { AtlasNode, EndToEndChain } from '@/api/atlas';

interface LineageExplorerProps {
  chains: EndToEndChain[];
  nodesById?: Map<string, AtlasNode>;
  searchQuery?: string;
  onSearchQueryChange?: (value: string) => void;
  onSelectNode: (nodeId: string) => void;
  onTraceChain?: (chain: EndToEndChain) => void;
}

export function LineageExplorer({
  chains,
  nodesById,
  searchQuery,
  onSearchQueryChange,
  onSelectNode,
  onTraceChain,
}: LineageExplorerProps) {
  const [localQuery, setLocalQuery] = useState('');
  const query = searchQuery ?? localQuery;
  const setQuery = onSearchQueryChange ?? setLocalQuery;
  const [opFilter, setOpFilter] = useState<'all' | 'read' | 'write'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return chains.filter((c) => {
      if (opFilter !== 'all' && c.operation !== opFilter) return false;
      if (!q) return true;
      return (
        c.display_label.toLowerCase().includes(q) ||
        c.http_path.toLowerCase().includes(q) ||
        c.route_label.toLowerCase().includes(q) ||
        (c.truth_table_labels ?? []).some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [chains, query, opFilter]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Statically Matched End-to-End 3-Tier Lineage ({filtered.length} of {chains.length})
          </h2>
          <p className="text-xs text-slate-300">
            Static AST/route-matched paths from Display UI through hooks/clients, HTTP endpoints, and backend services down to SQL tables (static matching only; does not prove runtime execution). Expand any row for every intermediate hop or click{' '}
            <strong className="font-mono text-amber-300">Trace 3D</strong> to animate the packet in 3D.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
            <input
              type="search"
              aria-label="Filter end-to-end lineage chains"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter page, /route, or table…"
              className="w-60 border border-slate-800 bg-slate-950 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus:outline-none"
            />
          </div>
          <div className="flex border border-slate-800 bg-slate-950 p-0.5 font-mono text-xs">
            {(['all', 'read', 'write'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setOpFilter(mode)}
                className={`px-2.5 py-1 uppercase ${
                  opFilter === mode ? 'bg-teal-500/20 text-teal-300' : 'text-slate-300 hover:text-slate-100'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="border border-slate-800/80 bg-slate-950/50 p-8 text-center font-mono text-xs text-slate-300">
          No end-to-end chains matched the current filter.
        </div>
      ) : (
        <div className="divide-y divide-slate-800/80 border border-slate-800 bg-slate-950/40">
          {filtered.slice(0, 120).map((chain) => {
            const viaIds = chain.via_node_ids ?? [];
            const manipIds = chain.manipulator_node_ids ?? [];
            const tableIds = chain.truth_table_ids ?? [];
            const tableLabels = chain.truth_table_labels ?? [];
            const isExpanded = expandedId === chain.id;

            return (
              <div key={chain.id} className="px-4 py-3 text-xs hover:bg-slate-900/50">
                <div className="grid grid-cols-1 gap-2 lg:grid-cols-12 lg:items-center">
                  {/* Tier 3: Display */}
                  <div className="flex items-center gap-1.5 lg:col-span-3">
                    <button
                      type="button"
                      onClick={() => setExpandedId(isExpanded ? null : chain.id)}
                      aria-label={isExpanded ? 'Collapse multi-hop chain' : 'Expand multi-hop chain'}
                      className="text-slate-300 hover:text-teal-300"
                    >
                      {isExpanded ? (
                        <ChevronDown className="h-3.5 w-3.5" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5" />
                      )}
                    </button>
                    <Globe className="h-3.5 w-3.5 shrink-0 text-blue-400" />
                    <button
                      type="button"
                      onClick={() => onSelectNode(chain.display_node_id)}
                      className="truncate text-left font-mono font-medium text-blue-300 hover:underline"
                      title={chain.display_label}
                    >
                      {chain.display_label}
                    </button>
                    {viaIds.length > 0 && (
                      <span className="shrink-0 font-mono text-[10px] text-slate-300">
                        (+{viaIds.length} hop)
                      </span>
                    )}
                  </div>

                  {/* HTTP Contract */}
                  <div className="flex items-center gap-1.5 font-mono lg:col-span-3">
                    <ArrowRight className="h-3 w-3 shrink-0 text-slate-400" />
                    <span
                      className={`shrink-0 px-1.5 py-0.5 text-[10px] font-semibold ${
                        chain.operation === 'write'
                          ? 'bg-amber-500/15 text-amber-300'
                          : 'bg-sky-500/15 text-sky-300'
                      }`}
                    >
                      {chain.http_method}
                    </span>
                    <span className="truncate text-slate-200" title={chain.http_path}>
                      {chain.http_path}
                    </span>
                  </div>

                  {/* Tier 2: Route + Services */}
                  <div className="flex items-center gap-1.5 lg:col-span-2">
                    <FileCode2 className="h-3.5 w-3.5 shrink-0 text-sky-400" />
                    <button
                      type="button"
                      onClick={() => onSelectNode(chain.route_node_id)}
                      className="truncate font-mono text-sky-300 hover:underline"
                    >
                      {chain.route_label}
                    </button>
                    {manipIds.length > 0 && (
                      <span className="font-mono text-[10px] text-slate-300">
                        →{manipIds.length} svc
                      </span>
                    )}
                  </div>

                  {/* Tier 1: SQL Tables + 3D Trace Action */}
                  <div className="flex flex-wrap items-center gap-1.5 lg:col-span-4">
                    <Database className="h-3.5 w-3.5 shrink-0 text-teal-400" />
                    {tableIds.length === 0 ? (
                      <span className="font-mono text-[11px] text-slate-300">computed / stateless</span>
                    ) : (
                      tableIds.slice(0, 3).map((tid, i) => (
                        <button
                          key={tid}
                          type="button"
                          onClick={() => onSelectNode(tid)}
                          className="border border-teal-500/30 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[11px] text-teal-300 hover:border-teal-400"
                        >
                          {tableLabels[i] ?? tid}
                        </button>
                      ))
                    )}
                    {tableIds.length > 3 && (
                      <span className="font-mono text-[10px] text-slate-300">
                        +{tableIds.length - 3}
                      </span>
                    )}
                    <div className="ml-auto flex items-center gap-1.5">
                      {onTraceChain && (
                        <button
                          type="button"
                          onClick={() => onTraceChain(chain)}
                          className="flex items-center gap-1 border border-amber-400/40 bg-amber-500/15 px-2 py-0.5 font-mono text-[10px] text-amber-200 hover:bg-amber-500/25"
                        >
                          <Play className="h-2.5 w-2.5 fill-amber-300" />
                          Trace 3D
                        </button>
                      )}
                      {chain.verified ? (
                        <CheckCircle2
                          className="h-3.5 w-3.5 shrink-0 text-teal-400"
                          aria-label="Static match verified"
                        />
                      ) : (
                        <span className="border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-200">
                          partial
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Granular Multi-Hop Chain Breakdown */}
                {isExpanded && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-t border-slate-800/80 pt-2 font-mono text-[11px]">
                    <span className="text-slate-300">Full Hops:</span>
                    <button
                      type="button"
                      onClick={() => onSelectNode(chain.display_node_id)}
                      className="border border-blue-500/40 bg-blue-500/10 px-1.5 py-0.5 text-blue-300 hover:border-blue-400"
                    >
                      UI: {chain.display_label}
                    </button>
                    {viaIds.map((vid) => (
                      <button
                        key={vid}
                        type="button"
                        onClick={() => onSelectNode(vid)}
                        className="border border-cyan-500/40 bg-cyan-500/10 px-1.5 py-0.5 text-cyan-200 hover:border-cyan-400"
                      >
                        via: {nodesById?.get(vid)?.label ?? vid}
                      </button>
                    ))}
                    <button
                      type="button"
                      onClick={() => onSelectNode(chain.route_node_id)}
                      className="border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-sky-300 hover:border-sky-400"
                    >
                      Route: {chain.route_label}
                    </button>
                    {manipIds.map((mid) => (
                      <button
                        key={mid}
                        type="button"
                        onClick={() => onSelectNode(mid)}
                        className="border border-indigo-500/40 bg-indigo-500/10 px-1.5 py-0.5 text-indigo-200 hover:border-indigo-400"
                      >
                        Svc: {nodesById?.get(mid)?.label ?? mid}
                      </button>
                    ))}
                    {tableIds.map((tid, idx) => (
                      <button
                        key={tid}
                        type="button"
                        onClick={() => onSelectNode(tid)}
                        className="border border-teal-500/40 bg-teal-500/10 px-1.5 py-0.5 text-teal-300 hover:border-teal-400"
                      >
                        SQL: {tableLabels[idx] ?? nodesById?.get(tid)?.label ?? tid}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
