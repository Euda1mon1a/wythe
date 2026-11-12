'use client';

import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Download, FileJson, GitCompare, History, Plus, Tag, Upload } from 'lucide-react';
import type { PolicyVocabularyRead } from '@/api/atlas';
import {
  useCompareSnapshots,
  useCreateVocabulary,
  useDownloadSarif,
  useGovernanceBundle,
  useScanDiff,
  useScanHistory,
  useSyncGovernanceBundle,
  useUpdateVocabulary,
} from '@/hooks/useAtlas';

interface GovernanceAndDiffPanelProps {
  activeSlug: string;
  vocabularies: PolicyVocabularyRead[];
  onSelectNode: (nodeId: string) => void;
}

export function GovernanceAndDiffPanel({
  activeSlug,
  vocabularies,
  onSelectNode,
}: GovernanceAndDiffPanelProps) {
  const [baseRef, setBaseRef] = useState('HEAD~1');
  const [committedBaseRef, setCommittedBaseRef] = useState('');
  const [packFilter, setPackFilter] = useState<string>('ALL');
  const [newPack, setNewPack] = useState('custom');
  const [newToken, setNewToken] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [baseSnapId, setBaseSnapId] = useState<number | null>(null);
  const [headSnapId, setHeadSnapId] = useState<number | null>(null);

  const { data: snapshots = [] } = useScanHistory(activeSlug);
  useEffect(() => {
    if (snapshots.length >= 2) {
      setHeadSnapId((prev) => prev ?? snapshots[0].id);
      setBaseSnapId((prev) => prev ?? snapshots[1].id);
    } else if (snapshots.length === 1) {
      setHeadSnapId(snapshots[0].id);
      setBaseSnapId(null);
    } else {
      setHeadSnapId(null);
      setBaseSnapId(null);
    }
  }, [snapshots]);

  const { data: snapshotDiff, isFetching: loadingSnapDiff } = useCompareSnapshots(
    activeSlug,
    baseSnapId,
    headSnapId,
  );

  const {
    data: diffReport,
    isFetching: loadingDiff,
    refetch: refetchDiff,
  } = useScanDiff(activeSlug, committedBaseRef);
  const { data: bundle } = useGovernanceBundle(activeSlug);
  const syncBundle = useSyncGovernanceBundle(activeSlug);
  const downloadSarif = useDownloadSarif(activeSlug);
  const createVocab = useCreateVocabulary(activeSlug);
  const updateVocab = useUpdateVocabulary(activeSlug);

  const packs = useMemo(() => {
    const unique = new Set(vocabularies.map((v) => v.domain_pack));
    return ['ALL', ...Array.from(unique).sort()];
  }, [vocabularies]);

  const visibleVocabs = useMemo(() => {
    if (packFilter === 'ALL') return vocabularies;
    return vocabularies.filter((v) => v.domain_pack === packFilter);
  }, [vocabularies, packFilter]);

  const handleExportSarif = () => {
    downloadSarif.mutate(undefined, {
      onSuccess: (sarifDoc) => {
        const blob = new Blob([JSON.stringify(sarifDoc, null, 2)], {
          type: 'application/sarif+json',
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${activeSlug}.wythe.sarif.json`;
        a.click();
        URL.revokeObjectURL(url);
      },
    });
  };

  const handleSync = (direction: 'export' | 'import') => {
    syncBundle.mutate(direction, {
      onSuccess: (receipt) => {
        setSyncMessage(
          `${direction === 'export' ? 'Exported to' : 'Synced from'} ${receipt.bundle_path} (${receipt.rules_synced} rules, ${receipt.vocabularies_synced} vocabs)`,
        );
      },
      onError: (err) => {
        setSyncMessage(`Sync error: ${(err as Error).message}`);
      },
    });
  };

  const handleAddVocabulary = (e: FormEvent) => {
    e.preventDefault();
    const cleanToken = newToken.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    if (cleanToken.length < 2) return;
    createVocab.mutate(
      {
        domain_pack: newPack.trim().toLowerCase() || 'custom',
        token: cleanToken,
        description: newDesc.trim(),
        is_enabled: true,
        created_by: 'operator',
      },
      {
        onSuccess: () => {
          setNewToken('');
          setNewDesc('');
        },
      },
    );
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {/* Left Card: PR Diff Blast-Radius & Git-Portable Governance Sync */}
      <div className="space-y-4 border border-slate-800 bg-slate-950/40 p-4 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div className="flex items-center gap-2 font-mono font-semibold text-slate-100">
            <GitCompare className="h-4 w-4 text-sky-400" />
            PR Diff Gate &amp; 3-Tier Blast Radius
          </div>
          <button
            type="button"
            disabled={downloadSarif.isPending}
            onClick={handleExportSarif}
            className="flex items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-200 hover:border-teal-400 hover:text-teal-300"
          >
            <Download className="h-3 w-3" />
            {downloadSarif.isPending ? 'Building…' : 'SARIF 2.1.0'}
          </button>
        </div>

        <div className="flex items-center gap-2 font-mono">
          <input
            type="text"
            aria-label="Git base reference"
            value={baseRef}
            onChange={(e) => setBaseRef(e.target.value)}
            placeholder="HEAD~1 or origin/main"
            className="w-44 border border-slate-800 bg-slate-900 px-2 py-1 text-slate-100"
          />
          <button
            type="button"
            onClick={() => {
              const targetRef = baseRef.trim() || 'HEAD~1';
              if (committedBaseRef === targetRef) {
                void refetchDiff();
              } else {
                setCommittedBaseRef(targetRef);
              }
            }}
            className="border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-sky-300 hover:bg-sky-500/25"
          >
            {loadingDiff ? 'Slicing…' : 'Analyze Diff'}
          </button>
          {diffReport && (
            <span
              className={`ml-auto border px-2 py-0.5 font-semibold ${
                diffReport.diff_verdict === 'FAIL'
                  ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                  : 'border-teal-500/40 bg-teal-500/10 text-teal-300'
              }`}
            >
              DIFF: {diffReport.diff_verdict} ({diffReport.new_findings?.length ?? 0} new)
            </span>
          )}
        </div>

        {diffReport && (
          <div className="grid grid-cols-4 gap-2 border border-slate-800/80 bg-slate-950 p-2.5 font-mono text-[11px]">
            <div>
              <div className="text-slate-400">Truth Slice</div>
              <div className="text-sm font-semibold text-teal-300">
                {diffReport.impacted_truth_nodes?.length ?? 0}
              </div>
            </div>
            <div>
              <div className="text-slate-400">Manipulate</div>
              <div className="text-sm font-semibold text-sky-300">
                {diffReport.impacted_manipulator_nodes?.length ?? 0}
              </div>
            </div>
            <div>
              <div className="text-slate-400">Display UI</div>
              <div className="text-sm font-semibold text-blue-300">
                {diffReport.impacted_display_nodes?.length ?? 0}
              </div>
            </div>
            <div>
              <div className="text-slate-400">E2E Chains</div>
              <div className="text-sm font-semibold text-slate-100">
                {diffReport.impacted_chains?.length ?? 0}
              </div>
            </div>
          </div>
        )}

        {diffReport && (diffReport.touched_node_ids?.length ?? 0) > 0 && (
          <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
            {(diffReport.touched_node_ids ?? []).slice(0, 8).map((nid) => (
              <button
                key={nid}
                type="button"
                onClick={() => onSelectNode(nid)}
                className="border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-teal-300 hover:border-teal-400"
              >
                {nid}
              </button>
            ))}
          </div>
        )}

        {/* Git-Portable Governance Bundle */}
        <div className="space-y-2 border-t border-slate-800 pt-3">
          <div className="flex items-center justify-between font-mono">
            <span className="flex items-center gap-1.5 font-semibold text-slate-200">
              <FileJson className="h-3.5 w-3.5 text-teal-400" />
              Portable Config (<code>.wythe/governance.json</code>)
            </span>
            {bundle && (
              <span className="text-[11px] text-slate-400">
                {bundle.rule_overrides?.length ?? 0} rules · {bundle.vocabularies?.length ?? 0} vocabs
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2 font-mono">
            <button
              type="button"
              disabled={syncBundle.isPending}
              onClick={() => handleSync('export')}
              className="flex items-center gap-1 border border-teal-500/40 bg-teal-500/15 px-2.5 py-1 text-teal-300 hover:bg-teal-500/25"
            >
              <Download className="h-3 w-3" /> Export to Repo
            </button>
            <button
              type="button"
              disabled={syncBundle.isPending}
              onClick={() => handleSync('import')}
              className="flex items-center gap-1 border border-slate-700 bg-slate-900 px-2.5 py-1 text-slate-200 hover:border-teal-400"
            >
              <Upload className="h-3 w-3" /> Hydrate DB from Repo
            </button>
          </div>
          {syncMessage && (
            <div className="font-mono text-[11px] text-slate-400">{syncMessage}</div>
          )}
        </div>

        {/* Recorded Snapshot-to-Snapshot Comparison */}
        <div className="space-y-2 border-t border-slate-800 pt-3">
          <div className="flex items-center justify-between font-mono">
            <span className="flex items-center gap-1.5 font-semibold text-slate-200">
              <History className="h-3.5 w-3.5 text-sky-400" />
              Snapshot-to-Snapshot Comparison ({snapshots.length} sealed)
            </span>
          </div>
          {snapshots.length < 2 ? (
            <p className="font-mono text-[11px] text-slate-400">
              Click <strong>Rescan &amp; Seal Receipt</strong> twice across edits to compare persisted snapshots.
            </p>
          ) : (
            <div className="space-y-2 font-mono text-[11px]">
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Base snapshot"
                  value={baseSnapId ?? ''}
                  onChange={(e) => setBaseSnapId(Number(e.target.value) || null)}
                  className="border border-slate-800 bg-slate-900 px-2 py-1 text-slate-200"
                >
                  {snapshots.map((s) => (
                    <option key={s.id} value={s.id}>
                      Base #{s.id} ({s.source_commit.slice(0, 8)} · {s.verified_edge_count} edges)
                    </option>
                  ))}
                </select>
                <span className="text-slate-400">→</span>
                <select
                  aria-label="Head snapshot"
                  value={headSnapId ?? ''}
                  onChange={(e) => setHeadSnapId(Number(e.target.value) || null)}
                  className="border border-slate-800 bg-slate-900 px-2 py-1 text-slate-200"
                >
                  {snapshots.map((s) => (
                    <option key={s.id} value={s.id}>
                      Head #{s.id} ({s.source_commit.slice(0, 8)} · {s.verified_edge_count} edges)
                    </option>
                  ))}
                </select>
                {loadingSnapDiff && <span className="text-slate-400">Comparing…</span>}
              </div>
              {snapshotDiff && (
                <div className="grid grid-cols-4 gap-2 border border-slate-800/80 bg-slate-950 p-2">
                  <div>
                    <div className="text-slate-400">Edges Δ</div>
                    <div className="font-semibold text-teal-300">
                      {snapshotDiff.edge_delta >= 0 ? `+${snapshotDiff.edge_delta}` : snapshotDiff.edge_delta}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400">Chains Δ</div>
                    <div className="font-semibold text-sky-300">
                      {snapshotDiff.chain_delta >= 0 ? `+${snapshotDiff.chain_delta}` : snapshotDiff.chain_delta}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400">Nodes +/-</div>
                    <div className="font-semibold text-slate-100">
                      +{snapshotDiff.added_nodes?.length ?? 0} / -{snapshotDiff.removed_nodes?.length ?? 0}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400">Findings +/-</div>
                    <div className="font-semibold text-amber-300">
                      +{snapshotDiff.new_findings?.length ?? 0} / -{snapshotDiff.resolved_findings?.length ?? 0}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right Card: DB-Backed Policy Vocabulary Packs */}
      <div className="space-y-3 border border-slate-800 bg-slate-950/40 p-4 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div className="flex items-center gap-2 font-mono font-semibold text-slate-100">
            <Tag className="h-4 w-4 text-teal-400" />
            Domain Policy Vocabularies (MANIP-001 &amp; DISP-001)
          </div>
          <select
            aria-label="Filter domain pack"
            value={packFilter}
            onChange={(e) => setPackFilter(e.target.value)}
            className="border border-slate-800 bg-slate-900 px-2 py-0.5 font-mono text-[11px] text-slate-200"
          >
            {packs.map((p) => (
              <option key={p} value={p}>
                {p === 'ALL' ? `All Packs (${vocabularies.length})` : p}
              </option>
            ))}
          </select>
        </div>

        <form onSubmit={handleAddVocabulary} className="flex flex-wrap items-center gap-1.5 font-mono">
          <input
            type="text"
            aria-label="Domain pack name"
            value={newPack}
            onChange={(e) => setNewPack(e.target.value)}
            placeholder="pack (e.g. custom)"
            className="w-24 border border-slate-800 bg-slate-900 px-2 py-1 text-slate-100"
          />
          <input
            type="text"
            aria-label="Policy vocabulary token"
            required
            value={newToken}
            onChange={(e) => setNewToken(e.target.value)}
            placeholder="TOKEN (e.g. ROYALTY_BPS)"
            className="w-40 border border-slate-800 bg-slate-900 px-2 py-1 text-slate-100"
          />
          <input
            type="text"
            aria-label="Policy token rationale"
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="Rationale"
            className="flex-1 border border-slate-800 bg-slate-900 px-2 py-1 text-slate-100"
          />
          <button
            type="submit"
            disabled={createVocab.isPending}
            className="flex items-center gap-1 border border-teal-500/40 bg-teal-500/15 px-2.5 py-1 text-teal-300 hover:bg-teal-500/25"
          >
            <Plus className="h-3 w-3" /> Add
          </button>
        </form>

        <div className="flex max-h-48 flex-wrap gap-1.5 overflow-y-auto pt-1 font-mono text-[11px]">
          {visibleVocabs.map((v) => (
            <label
              key={v.id}
              title={v.description || v.domain_pack}
              className={`flex cursor-pointer items-center gap-1.5 border px-2 py-0.5 ${
                v.is_enabled
                  ? 'border-teal-500/35 bg-teal-500/10 text-teal-200'
                  : 'border-slate-800 bg-slate-950 text-slate-400'
              }`}
            >
              <input
                type="checkbox"
                checked={v.is_enabled}
                onChange={(e) =>
                  updateVocab.mutate({
                    id: v.id,
                    payload: { is_enabled: e.target.checked },
                  })
                }
                className="accent-teal-400"
              />
              <span className="text-[10px] uppercase text-slate-400">{v.domain_pack}:</span>
              <span>{v.token}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}
