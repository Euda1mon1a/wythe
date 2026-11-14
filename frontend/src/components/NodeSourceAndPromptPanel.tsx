'use client';

import { useMemo, useState } from 'react';
import { Code2, Copy, ExternalLink, Sparkles, Wand2 } from 'lucide-react';
import type { AtlasEdge, AtlasNode, BoundaryFinding } from '@/api/atlas';
import { useSourceSnippet } from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';

interface NodeSourceAndPromptPanelProps {
  activeSlug: string;
  node: AtlasNode;
  allNodesById: Map<string, AtlasNode>;
  inbound: AtlasEdge[];
  outbound: AtlasEdge[];
  nodeFindings: BoundaryFinding[];
  onSelectNode: (nodeId: string) => void;
}

export function NodeSourceAndPromptPanel({
  activeSlug,
  node,
  allNodesById,
  inbound,
  outbound,
  nodeFindings,
  onSelectNode,
}: NodeSourceAndPromptPanelProps) {
  const [showCode, setShowCode] = useState(true);
  const [copiedPath, setCopiedPath] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);

  const canFetchSnippet = Boolean(activeSlug && node.source_file && !node.source_file.startsWith('<'));
  const { data: snippet, isLoading } = useSourceSnippet(
    activeSlug,
    node.source_file,
    Math.max(1, node.line || 1),
    canFetchSnippet && showCode,
  );

  const cleanExemplar = useMemo(() => {
    for (const candidate of allNodesById.values()) {
      if (
        candidate.id !== node.id &&
        candidate.tier === node.tier &&
        candidate.subkind === node.subkind &&
        candidate.status === 'clean'
      ) {
        return candidate;
      }
    }
    for (const candidate of allNodesById.values()) {
      if (candidate.id !== node.id && candidate.tier === node.tier && candidate.status === 'clean') {
        return candidate;
      }
    }
    return null;
  }, [allNodesById, node.id, node.tier, node.subkind]);

  const absLineRef = snippet
    ? `${snippet.abs_path}:${snippet.focus_line}`
    : `${node.source_file}:${node.line}`;

  const buildRefactorPrompt = () => {
    const upLabels = inbound
      .slice(0, 6)
      .map((e) => `${e.kind} <- ${allNodesById.get(e.source_id)?.label ?? e.source_id}`);
    const downLabels = outbound
      .slice(0, 6)
      .map((e) => `${e.kind} -> ${allNodesById.get(e.target_id)?.label ?? e.target_id}`);
    const codeLines = (snippet?.lines ?? [])
      .map((l) => `${l.is_focus ? '>' : ' '} ${String(l.line_number).padStart(4, ' ')} | ${l.text}`)
      .join('\n');
    const findingBlocks = nodeFindings
      .map((f) => {
        const causal =
          f.target_node_id === node.id && f.node_id !== node.id
            ? ` [causal writer ${f.node_id} @ ${f.source_file}:${f.line}]`
            : ` @ ${f.source_file}:${f.line}`;
        return `- [${f.rule_code}] (${f.severity}) ${f.title}${causal}\n  Detail: ${f.detail}\n  Remediation: ${f.remediation}`;
      })
      .join('\n');
    const sp = node.store_purpose;
    const purposeBlock = sp
      ? [
          `Declared Store Purpose (intent, NOT verified safety): intended_use=${sp.intended_use}`,
          sp.authoritative_source ? `Authoritative Source: ${sp.authoritative_source}` : '',
          sp.copy_reason ? `Copy Reason: ${sp.copy_reason}` : '',
          sp.refresh_policy ? `Refresh / Invalidation Policy: ${sp.refresh_policy}` : '',
          sp.recovery_expectation ? `Recovery Expectation: ${sp.recovery_expectation}` : '',
          sp.keyspace_scope ? `Keyspace Scope: ${sp.keyspace_scope}` : '',
          sp.verification_summary ? `Static Verification: ${sp.verification_summary}` : '',
        ]
          .filter(Boolean)
          .join('\n')
      : node.verification_note
        ? `Static Verification: ${node.verification_note}`
        : '';

    return [
      `# Wythe 3-Tier Surgical Refactor Brief (${activeSlug})`,
      `Target Node: ${node.label} (${node.tier} :: ${node.subkind}, status=${node.status})`,
      `Discovery Coordinate: ${node.source_file}:${node.line}`,
      upLabels.length > 0 ? `Inbound Links: ${upLabels.join(', ')}` : 'Inbound Links: none',
      downLabels.length > 0 ? `Outbound Links: ${downLabels.join(', ')}` : 'Outbound Links: none',
      purposeBlock,
      cleanExemplar
        ? `Clean Same-Tier Reference Exemplar: ${cleanExemplar.label} (${cleanExemplar.source_file}:${cleanExemplar.line})`
        : '',
      '',
      '## Boundary Violations to Resolve',
      findingBlocks,
      '',
      codeLines ? `## Local Source Context (${node.source_file})\n\`\`\`\n${codeLines}\n\`\`\`` : '',
      '',
      'Task: Investigate the discovery and causal writer coordinates before assuming duplication or deletion safety. Verify refresh/invalidation and authoritative source behavior, and keep domain truth in Tier 1 (Database), computation/orchestration in Tier 2 (Backend Manipulation), and Tier 3 (Display) rendering typed API state without policy leakage.',
    ]
      .filter(Boolean)
      .join('\n');
  };

  return (
    <div className="space-y-3 border-t border-slate-800 pt-3">
      {/* Editor Deep-Links & Source Peek Toggle */}
      <div className="flex flex-wrap items-center justify-between gap-1.5">
        <button
          type="button"
          onClick={() => setShowCode((v) => !v)}
          className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider text-teal-300 hover:text-teal-200"
        >
          <Code2 className="h-3.5 w-3.5" />
          {showCode ? 'Hide Source Peek' : 'Show Source Peek'}
        </button>
        <div className="flex flex-wrap items-center gap-1 font-mono text-[10px]">
          <button
            type="button"
            onClick={() => {
              void copyTextToClipboard(`${node.source_file}:${node.line}`).then((ok) => {
                if (ok) {
                  setCopiedPath(true);
                  window.setTimeout(() => setCopiedPath(false), 1800);
                }
              });
            }}
            className="flex items-center gap-1 border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-slate-200 hover:border-teal-400"
          >
            <Copy className="h-2.5 w-2.5" />
            {copiedPath ? 'Copied!' : 'path:line'}
          </button>
          {snippet?.abs_path && (
            <>
              <a
                href={`vscode://file/${encodeURI(snippet.abs_path)}:${snippet.focus_line}`}
                title={`Open ${absLineRef} in VS Code`}
                className="flex items-center gap-0.5 border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-sky-300 hover:border-sky-400"
              >
                VS Code <ExternalLink className="h-2.5 w-2.5" />
              </a>
              <a
                href={`cursor://file/${encodeURI(snippet.abs_path)}:${snippet.focus_line}`}
                title={`Open ${absLineRef} in Cursor`}
                className="flex items-center gap-0.5 border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-teal-300 hover:border-teal-400"
              >
                Cursor <ExternalLink className="h-2.5 w-2.5" />
              </a>
            </>
          )}
        </div>
      </div>

      {showCode && canFetchSnippet && (
        <div className="max-h-52 overflow-auto border border-slate-800 bg-slate-950 font-mono text-[10.5px] leading-relaxed">
          {isLoading && (
            <div className="p-2.5 text-slate-300">Loading {node.source_file}:{node.line}…</div>
          )}
          {snippet && (
            <div>
              <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/80 px-2 py-1 text-[10px] text-slate-300">
                <span className="truncate">{snippet.rel_path}</span>
                <span className="shrink-0 text-slate-400">
                  L{snippet.start_line}–{snippet.end_line} / {snippet.total_lines}
                </span>
              </div>
              <pre className="p-1.5">
                {(snippet.lines ?? []).map((ln) => (
                  <div
                    key={ln.line_number}
                    className={`flex gap-2 px-1 ${
                      ln.is_focus
                        ? 'border-l-2 border-teal-400 bg-teal-500/15 text-slate-100'
                        : 'text-slate-300'
                    }`}
                  >
                    <span className="w-8 shrink-0 select-none text-right text-slate-400">
                      {ln.line_number}
                    </span>
                    <span className="whitespace-pre">{ln.text || ' '}</span>
                  </div>
                ))}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Surgical Refactor Prompt + Clean Repo Exemplar */}
      {(nodeFindings.length > 0 || node.status !== 'clean') && (
        <div className="space-y-1.5 border border-amber-500/30 bg-amber-950/15 p-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-1 font-mono text-[10px] uppercase text-amber-300">
              <Wand2 className="h-3 w-3" />
              Guided Remediation
            </span>
            {nodeFindings.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  void copyTextToClipboard(buildRefactorPrompt()).then((ok) => {
                    if (ok) {
                      setCopiedPrompt(true);
                      window.setTimeout(() => setCopiedPrompt(false), 2000);
                    }
                  });
                }}
                className="border border-amber-400/50 bg-amber-500/20 px-2 py-0.5 font-mono text-[10px] text-amber-200 hover:bg-amber-500/30"
              >
                {copiedPrompt ? 'Copied Prompt!' : 'Copy Surgical Refactor Prompt'}
              </button>
            )}
          </div>
          {cleanExemplar && (
            <button
              type="button"
              onClick={() => onSelectNode(cleanExemplar.id)}
              className="flex w-full items-center gap-1.5 truncate text-left font-mono text-[11px] text-teal-300 hover:underline"
            >
              <Sparkles className="h-3 w-3 shrink-0" />
              Compare clean {node.subkind} exemplar: {cleanExemplar.label}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
