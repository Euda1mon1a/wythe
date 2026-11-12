'use client';

import { Bot, CheckCircle2, Download, Eye, Sparkles, X } from 'lucide-react';
import type { UiFocusExplainRead } from '@/api/atlas';

interface WhatsThisModalProps {
  open: boolean;
  explanation: UiFocusExplainRead | null;
  snapshotDataUrl: string | null;
  isLoading: boolean;
  imageCopiedToClipboard: boolean;
  onAskAi?: (prefill?: string) => void;
  onClose: () => void;
}

export function WhatsThisModal({
  open,
  explanation,
  snapshotDataUrl,
  isLoading,
  imageCopiedToClipboard,
  onAskAi,
  onClose,
}: WhatsThisModalProps) {
  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Wythe What's This Human-to-LLM X-Ray Bridge"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
    >
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto border border-teal-500/50 bg-slate-950 p-5 text-xs text-slate-200 shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-teal-300">
              <span className="flex items-center gap-1">
                <Sparkles className="h-3.5 w-3.5" />
                Human ↔ Vision / MCP Bridge (`What&apos;s This?` · [W])
              </span>
              <span className="flex items-center gap-1 border border-emerald-500/40 bg-emerald-500/15 px-1.5 py-0.5 text-emerald-200">
                <CheckCircle2 className="h-3 w-3" />
                Live-Synced to MCP (`wythe_what_is_this`) &amp; CLI (`wythe focus`)
              </span>
              {imageCopiedToClipboard && (
                <span className="border border-sky-500/40 bg-sky-500/15 px-1.5 py-0.5 text-sky-200">
                  PNG Image Copied to Clipboard
                </span>
              )}
            </div>
            <h2 className="mt-1 font-mono text-sm font-semibold text-slate-100">
              {isLoading
                ? 'Synthesizing live 3D focus & district X-ray…'
                : explanation?.headline ?? 'Live 3D Viewport X-Ray'}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close What's This X-Ray card"
            className="border border-slate-700 bg-slate-900 p-1 text-slate-300 hover:border-teal-400 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-3 border border-sky-500/30 bg-sky-950/20 p-3 leading-relaxed">
          <div className="font-mono text-[10px] uppercase text-sky-300">
            Zero Copy-Paste Agent Workflow
          </div>
          <p className="mt-1 text-slate-200">
            Ask any connected agent (Codex, Claude Code, Antigravity, Cursor){' '}
            <strong className="font-mono text-teal-200">&ldquo;what is this?&rdquo;</strong> — it
            reads your live 3D node, district, blast-radius lens, and annotated WebGL frame directly
            via <code className="font-mono text-sky-300">wythe_what_is_this</code> /{' '}
            <code className="font-mono text-sky-300">wythe focus</code>. Or ask directly in-browser
            using Apple Intelligence, Chrome Gemini Nano, or Local OpenAI <code className="font-mono text-sky-300">/v1</code>:
          </p>
          {onAskAi && (
            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => onAskAi('What is this cluster and why is it colored like this?')}
                className="flex items-center gap-1.5 border border-teal-400/60 bg-teal-500/20 px-3 py-1 font-mono text-xs font-semibold text-teal-100 hover:bg-teal-500/30"
              >
                <Bot className="h-3.5 w-3.5" />
                Ask On-Device AI Now [A]
              </button>
              <span className="font-mono text-[10px] text-slate-300">
                Auto cascade: Apple FM → Chrome Built-In → Local /v1 · HTTP MCP `/api/v1/mcp`
              </span>
            </div>
          )}
        </div>

        {explanation && (
          <div className="mt-3 space-y-2.5 border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase text-amber-300">
              <Eye className="h-3.5 w-3.5" />
              Instant Architectural Explanation
            </div>
            <p className="font-medium text-slate-100">{explanation.color_reason}</p>
            {explanation.focused_district && (
              <div className="font-mono text-[11px] text-slate-300">
                District <strong className="text-teal-300">{explanation.focused_district.district}</strong>:{' '}
                {explanation.focused_district.node_count} nodes ·{' '}
                {explanation.focused_district.flagged_node_count} flagged
                {explanation.focused_district.crimson_diff_count > 0
                  ? ` · ${explanation.focused_district.crimson_diff_count} crimson in diff`
                  : ''}{' '}
                · files: {(explanation.focused_district.sample_files ?? []).join(', ')}
              </div>
            )}
            {(explanation.active_findings ?? []).length > 0 && (
              <div className="space-y-1 pt-1">
                {(explanation.active_findings ?? []).slice(0, 4).map((f) => (
                  <div
                    key={f.id}
                    className="border border-rose-500/25 bg-rose-950/20 px-2.5 py-1.5 text-[11px]"
                  >
                    <strong className="font-mono text-rose-300">{f.rule_code}</strong> (
                    <span className="font-mono text-slate-300">
                      {f.source_file}:{f.line}
                    </span>
                    ): {f.title}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {snapshotDataUrl && (
          <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between font-mono text-[10px] uppercase text-slate-300">
              <span>Draggable Vision X-Ray Card (drag image directly into any Vision LLM)</span>
              <a
                href={snapshotDataUrl}
                download={`wythe-xray-${explanation?.active_slug ?? 'view'}.png`}
                className="flex items-center gap-1 border border-teal-500/40 bg-teal-500/15 px-2 py-0.5 text-teal-200 hover:bg-teal-500/25"
              >
                <Download className="h-3 w-3" />
                Download PNG
              </a>
            </div>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={snapshotDataUrl}
              alt="Annotated Wythe 3D Architecture X-Ray Card"
              className="max-h-72 w-full border border-slate-700 bg-slate-950 object-contain"
            />
          </div>
        )}
      </div>
    </div>
  );
}
