'use client';

import { useMemo, useState } from 'react';
import type {
  AdapterSlotSchema,
  AtlasNode,
  AuditRulingRead,
  LegacyBridgeSummary,
  StackProfileRead,
} from '@/api/atlas';
import { formatCalendarDay } from '@/lib/clock';
import { ALL_NODE_SUBKINDS, deriveDomainCluster } from '@/lib/wytheSceneLenses';

interface AccessibleIndexViewProps {
  nodes: AtlasNode[];
  rulings?: AuditRulingRead[];
  slots: AdapterSlotSchema[];
  profiles: StackProfileRead[];
  legacyBridge: LegacyBridgeSummary;
  scanNotes?: string[];
  onSelectNode: (nodeId: string) => void;
}

export function AccessibleIndexView({
  nodes,
  rulings = [],
  slots,
  profiles,
  legacyBridge,
  scanNotes = [],
  onSelectNode,
}: AccessibleIndexViewProps) {
  const [search, setSearch] = useState('');
  const [tier, setTier] = useState<'all' | 'truth' | 'manipulate' | 'display'>('all');
  const [subkind, setSubkind] = useState<'all' | AtlasNode['subkind']>('all');

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

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return nodes.filter((n) => {
      if (tier !== 'all' && n.tier !== tier) return false;
      if (subkind !== 'all' && n.subkind !== subkind) return false;
      if (!q) return true;
      return (
        n.label.toLowerCase().includes(q) ||
        n.source_file.toLowerCase().includes(q) ||
        n.status.toLowerCase().includes(q) ||
        n.subkind.toLowerCase().includes(q) ||
        (n.columns ?? []).some((c) => c.toLowerCase().includes(q))
      );
    });
  }, [nodes, search, tier, subkind]);

  const sampleReceipts = legacyBridge.sample_receipts ?? [];

  return (
    <div className="space-y-6">
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
            Every feature flows strictly across three strata. Click a live clean exemplar from this repository to inspect its pattern:
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
                className="mt-2 truncate font-mono text-[11px] text-teal-300 hover:underline"
              >
                Exemplar: {exemplars.truth.label} →
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
                className="mt-2 truncate font-mono text-[11px] text-sky-300 hover:underline"
              >
                Exemplar: {exemplars.manipulate.label} →
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
                className="mt-2 truncate font-mono text-[11px] text-blue-300 hover:underline"
              >
                Exemplar: {exemplars.display.label} →
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
                    className="font-mono font-medium text-teal-300 hover:underline"
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
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search node, column, or file…"
              className="w-56 border border-slate-800 bg-slate-950 px-2.5 py-1 font-mono text-xs text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus:outline-none"
            />
            <select
              aria-label="Filter index by subkind"
              value={subkind}
              onChange={(e) => setSubkind(e.target.value as 'all' | AtlasNode['subkind'])}
              className="border border-slate-800 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-200"
            >
              <option value="all">All 11 subkinds</option>
              {ALL_NODE_SUBKINDS.map((sk) => (
                <option key={sk} value={sk}>
                  {sk}
                </option>
              ))}
            </select>
            <div className="flex border border-slate-800 bg-slate-950 p-0.5 font-mono text-xs">
              {(['all', 'truth', 'manipulate', 'display'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTier(t)}
                  className={`px-2 py-0.5 uppercase ${
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
            <thead className="border-b border-slate-800 bg-slate-950 font-mono text-[11px] uppercase text-slate-300">
              <tr>
                <th className="px-3 py-2">Node</th>
                <th className="px-3 py-2">Tier · Subkind · District</th>
                <th className="px-3 py-2">Coupling</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Source Coordinate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.slice(0, 150).map((n) => (
                <tr key={n.id} className="hover:bg-slate-900/50">
                  <td className="px-3 py-2 font-mono font-medium">
                    <button
                      type="button"
                      onClick={() => onSelectNode(n.id)}
                      className="text-left text-teal-300 hover:underline"
                    >
                      {n.label}
                    </button>
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-300">
                    {n.tier} · {n.subkind} · <span className="text-slate-400">{deriveDomainCluster(n)}</span>
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
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
