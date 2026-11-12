'use client';

import { useMemo, useState } from 'react';
import { Lock, ShieldAlert, ShieldCheck } from 'lucide-react';
import type {
  BoundaryFinding,
  PolicyVocabularyRead,
  RulePolicyRead,
  TruthAtlasReport,
} from '@/api/atlas';
import { GovernanceAndDiffPanel } from '@/components/GovernanceAndDiffPanel';
import { useCaptureRatchet, useUpdateRule } from '@/hooks/useAtlas';

interface GateAndRulesViewProps {
  activeSlug: string;
  report: TruthAtlasReport;
  rules: RulePolicyRead[];
  vocabularies: PolicyVocabularyRead[];
  onSelectNode: (nodeId: string) => void;
}

export function GateAndRulesView({
  activeSlug,
  report,
  rules,
  vocabularies,
  onSelectNode,
}: GateAndRulesViewProps) {
  const [selectedRule, setSelectedRule] = useState<string>('ALL');
  const updateRule = useUpdateRule(activeSlug);
  const captureRatchet = useCaptureRatchet(activeSlug);

  const countByRule = useMemo(() => {
    const map = new Map<string, { observed: number; baseline: number | null; status: string }>();
    for (const r of report.gate.rule_counts ?? []) {
      map.set(r.rule_code, {
        observed: r.observed_count,
        baseline: r.baseline_max ?? null,
        status: r.status,
      });
    }
    return map;
  }, [report.gate.rule_counts]);

  const filteredFindings: BoundaryFinding[] = useMemo(() => {
    if (selectedRule === 'ALL') return report.findings;
    return report.findings.filter((f) => f.rule_code === selectedRule);
  }, [report.findings, selectedRule]);

  return (
    <div className="space-y-6">
      {/* Gate Header & Ratchet Action */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          {report.gate.verdict === 'FAIL' ? (
            <ShieldAlert className="h-5 w-5 text-rose-400" />
          ) : (
            <ShieldCheck className="h-5 w-5 text-teal-400" />
          )}
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Database-Backed Policy Catalog &amp; Gate ({report.gate.verdict} · {report.gate.mode} mode)
            </h2>
            <p className="text-xs text-slate-400">
              Rule policies live in <code className="font-mono text-teal-300">atlas_rule_policies</code>. Toggling a policy mutates database truth and re-evaluates the gate without editing Python.
            </p>
          </div>
        </div>
        <button
          type="button"
          disabled={captureRatchet.isPending}
          onClick={() =>
            captureRatchet.mutate({
              recorded_by: 'operator',
              note: 'Downward-only ratchet baseline captured from UI.',
            })
          }
          className="flex items-center gap-1.5 border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300 disabled:opacity-50"
        >
          <Lock className="h-3.5 w-3.5" />
          {captureRatchet.isPending ? 'Saving Ceiling…' : 'Capture Ratchet Ceiling'}
        </button>
      </div>

      {(report.scan_notes ?? []).length > 0 && (
        <div className="space-y-1 border border-sky-500/30 bg-sky-950/20 p-3 font-mono text-xs text-sky-200">
          <div className="font-semibold text-sky-300">Scan Provenance &amp; Probe Notes</div>
          <ul className="list-disc space-y-0.5 pl-5 text-slate-200">
            {(report.scan_notes ?? []).map((note, idx) => (
              <li key={idx}>{note}</li>
            ))}
          </ul>
        </div>
      )}

      {/* PR Diff Blast-Radius, SARIF, Portable Config Sync & Domain Vocabularies */}
      <GovernanceAndDiffPanel
        activeSlug={activeSlug}
        vocabularies={vocabularies}
        onSelectNode={onSelectNode}
      />

      {/* Rule Policy Table */}
      <div className="overflow-x-auto border border-slate-800 bg-slate-950/40">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-800 bg-slate-950 font-mono text-[11px] uppercase text-slate-400">
            <tr>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">Tier</th>
              <th className="px-3 py-2">Policy Title</th>
              <th className="px-3 py-2 text-right">Observed</th>
              <th className="px-3 py-2 text-right">Ceiling</th>
              <th className="px-3 py-2">Enabled</th>
              <th className="px-3 py-2">Blocks Gate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {rules.map((r) => {
              const stat = countByRule.get(r.rule_code);
              const isActive = selectedRule === r.rule_code;
              return (
                <tr
                  key={r.rule_code}
                  className={`hover:bg-slate-900/50 ${isActive ? 'bg-slate-900/80' : ''}`}
                >
                  <td className="px-3 py-2 font-mono font-semibold">
                    <button
                      type="button"
                      onClick={() =>
                        setSelectedRule(isActive ? 'ALL' : r.rule_code)
                      }
                      className="text-teal-300 hover:underline"
                    >
                      {r.rule_code}
                    </button>
                  </td>
                  <td className="px-3 py-2 font-mono uppercase text-slate-400">{r.tier}</td>
                  <td className="px-3 py-2 text-slate-200">{r.title}</td>
                  <td className="px-3 py-2 text-right font-mono text-slate-100">
                    {stat?.observed ?? 0}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-slate-400">
                    {stat?.baseline !== null && stat?.baseline !== undefined ? stat.baseline : '—'}
                  </td>
                  <td className="px-3 py-2">
                    <input
                      type="checkbox"
                      aria-label={`Enable ${r.rule_code}`}
                      checked={r.enabled}
                      onChange={(e) =>
                        updateRule.mutate({
                          code: r.rule_code,
                          payload: { enabled: e.target.checked, updated_by: 'operator' },
                        })
                      }
                      className="accent-teal-400"
                    />
                  </td>
                  <td className="px-3 py-2">
                    <input
                      type="checkbox"
                      aria-label={`Block gate on ${r.rule_code}`}
                      checked={r.blocks_gate}
                      onChange={(e) =>
                        updateRule.mutate({
                          code: r.rule_code,
                          payload: { blocks_gate: e.target.checked, updated_by: 'operator' },
                        })
                      }
                      className="accent-amber-400"
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Findings Stream */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="font-mono text-xs uppercase tracking-wider text-slate-300">
            Observed Findings ({filteredFindings.length}
            {selectedRule !== 'ALL' ? ` filtered by ${selectedRule}` : ''})
          </h3>
          {selectedRule !== 'ALL' && (
            <button
              type="button"
              onClick={() => setSelectedRule('ALL')}
              className="font-mono text-xs text-teal-400 hover:underline"
            >
              Clear rule filter
            </button>
          )}
        </div>

        {filteredFindings.length === 0 ? (
          <div className="border border-teal-500/25 bg-teal-500/5 p-6 text-center font-mono text-xs text-teal-300">
            Zero boundary findings under active database policy.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80 border border-slate-800 bg-slate-950/40">
            {filteredFindings.slice(0, 100).map((f) => (
              <div key={f.id} className="space-y-1 px-4 py-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-mono">
                    <span
                      className={`px-1.5 py-0.5 text-[10px] font-semibold ${
                        f.blocks_gate
                          ? 'bg-rose-500/15 text-rose-300'
                          : 'bg-amber-500/15 text-amber-300'
                      }`}
                    >
                      {f.rule_code}
                    </span>
                    <span className="font-semibold text-slate-100">{f.title}</span>
                  </div>
                  {f.node_id && (
                    <button
                      type="button"
                      onClick={() => onSelectNode(f.node_id!)}
                      className="font-mono text-[11px] text-teal-300 hover:underline"
                    >
                      Inspect node →
                    </button>
                  )}
                </div>
                <div className="font-mono text-[11px] text-slate-400">
                  {f.source_file}:{f.line}
                </div>
                <p className="text-slate-300">{f.detail}</p>
                <p className="text-[11px] text-slate-400">Remediation: {f.remediation}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
