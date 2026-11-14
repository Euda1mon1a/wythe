'use client';

import { useMemo, useState } from 'react';
import { Code2, Copy, ExternalLink, Sparkles, Wand2 } from 'lucide-react';
import type {
  AtlasEdge,
  AtlasNode,
  BoundaryFinding,
  PortableReferenceExemplar,
} from '@/api/atlas';
import { useSourceSnippet } from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import {
  BRIEF_TASK_INTENT_LABELS,
  buildDiagnosticBrief,
  isRetainOrRetireCandidate,
  selectReferenceExemplar,
  type BriefTaskIntent,
} from '@/lib/wytheBriefBuilder';

interface NodeSourceAndPromptPanelProps {
  activeSlug: string;
  node: AtlasNode;
  allNodesById: Map<string, AtlasNode>;
  inbound: AtlasEdge[];
  outbound: AtlasEdge[];
  nodeFindings: BoundaryFinding[];
  referenceExemplars?: PortableReferenceExemplar[];
  onSelectNode: (nodeId: string) => void;
}

export function NodeSourceAndPromptPanel({
  activeSlug,
  node,
  allNodesById,
  inbound,
  outbound,
  nodeFindings,
  referenceExemplars = [],
  onSelectNode,
}: NodeSourceAndPromptPanelProps) {
  const [showCode, setShowCode] = useState(true);
  const [copiedPath, setCopiedPath] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [taskIntent, setTaskIntent] = useState<BriefTaskIntent>('investigate');

  const canFetchSnippet = Boolean(activeSlug && node.source_file && !node.source_file.startsWith('<'));
  const { data: snippet, isLoading } = useSourceSnippet(
    activeSlug,
    node.source_file,
    Math.max(1, node.line || 1),
    canFetchSnippet && showCode,
  );

  const exemplar = useMemo(
    () => selectReferenceExemplar(node, allNodesById, referenceExemplars),
    [node, allNodesById, referenceExemplars],
  );
  const retainRetireNeeded = useMemo(
    () => isRetainOrRetireCandidate(node, nodeFindings),
    [node, nodeFindings],
  );

  const absLineRef = snippet
    ? `${snippet.abs_path}:${snippet.focus_line}`
    : `${node.source_file}:${node.line}`;

  const buildBrief = () =>
    buildDiagnosticBrief({
      activeSlug,
      node,
      allNodesById,
      inbound,
      outbound,
      nodeFindings,
      exemplar,
      intent: taskIntent,
      snippetLines: snippet?.lines ?? [],
    });

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

      {/* Investigation-Default Diagnostic Brief + Qualified Exemplar */}
      {(nodeFindings.length > 0 || node.status !== 'clean') && (
        <div className="space-y-2 border border-amber-500/30 bg-amber-950/15 p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-1 font-mono text-[10px] uppercase text-amber-300">
              <Wand2 className="h-3 w-3" />
              Diagnostic Brief
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              <select
                aria-label="Copied brief task intent"
                value={taskIntent}
                onChange={(e) => setTaskIntent(e.target.value as BriefTaskIntent)}
                className="border border-slate-700 bg-slate-950 px-1.5 py-0.5 font-mono text-[10px] text-slate-200"
              >
                {(Object.keys(BRIEF_TASK_INTENT_LABELS) as BriefTaskIntent[]).map((mode) => (
                  <option key={mode} value={mode}>
                    {BRIEF_TASK_INTENT_LABELS[mode]}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={() => {
                  void copyTextToClipboard(buildBrief()).then((ok) => {
                    if (ok) {
                      setCopiedPrompt(true);
                      window.setTimeout(() => setCopiedPrompt(false), 2000);
                    }
                  });
                }}
                className="border border-amber-400/50 bg-amber-500/20 px-2 py-0.5 font-mono text-[10px] text-amber-200 hover:bg-amber-500/30"
              >
                {copiedPrompt ? 'Copied Brief!' : 'Copy Diagnostic Brief'}
              </button>
            </div>
          </div>

          {retainRetireNeeded && (
            <div className="border border-sky-500/30 bg-sky-950/20 px-2 py-1 font-mono text-[10px] text-sky-200">
              Retain / Retire Decision Needed: Surface is unwired or candidate-only; confirm retain, wire, or retire before refactoring.
            </div>
          )}

          {exemplar.kind === 'configured' && exemplar.configured && (
            <div className="space-y-0.5 border border-teal-500/30 bg-teal-950/20 p-2 font-mono text-[10px] text-teal-200">
              <div className="flex items-center gap-1 font-semibold text-teal-300">
                <Sparkles className="h-3 w-3 shrink-0" />
                Configured Authority: {exemplar.configured.title} ({exemplar.configured.pointer})
              </div>
              <div className="text-slate-300">{exemplar.rationale}</div>
              {exemplar.configured.node_id && (
                <button
                  type="button"
                  onClick={() => onSelectNode(exemplar.configured!.node_id!)}
                  className="text-teal-300 hover:underline"
                >
                  Inspect configured exemplar →
                </button>
              )}
            </div>
          )}

          {exemplar.kind === 'unvalidated_neighbor' && exemplar.neighborNode && (
            <div className="space-y-0.5 border border-slate-700 bg-slate-900/70 p-2">
              <button
                type="button"
                onClick={() => onSelectNode(exemplar.neighborNode!.id)}
                className="flex w-full items-center gap-1.5 truncate text-left font-mono text-[11px] text-amber-200 hover:underline"
              >
                <Sparkles className="h-3 w-3 shrink-0" />
                Unvalidated clean {node.subkind} neighbor: {exemplar.neighborNode.label}
              </button>
              <div className="font-mono text-[10px] text-slate-400">
                {exemplar.caveat}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
