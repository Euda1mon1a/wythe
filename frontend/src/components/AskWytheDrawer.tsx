'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { Bot, Copy, Cpu, Download, Eye, RefreshCw, Send, Sparkles, Trash2, X } from 'lucide-react';
import type { AskChatTurn, AtlasNode, UiFocusExplainRead } from '@/api/atlas';
import { useAskEngines, useAskWythe } from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import type { LiveViewportDigest } from '@/lib/wytheVisionBridge';
import {
  probeBrowserLocalOpenAi,
  probeChromeBuiltInModel,
  runBrowserLocalOpenAiAsk,
  runChromeBuiltInAsk,
  triggerChromeModelDownload,
  type BrowserLocalOpenAiProbe,
  type ChromeEngineProbe,
} from '@/lib/wytheBrowserAi';

export type SelectedEngineChoice = 'auto' | 'apple' | 'chrome' | 'local';

interface QaTurn {
  id: string;
  question: string;
  answerMarkdown: string;
  engineBadge: string;
  usedVision: boolean;
  referencedNodeIds: string[];
}

interface AskWytheDrawerProps {
  open: boolean;
  activeSlug: string;
  explanation: UiFocusExplainRead | null;
  liveDigest?: LiveViewportDigest | null;
  snapshotDataUrl: string | null;
  captureLiveWebp?: () => string | null;
  nodesById: Map<string, AtlasNode>;
  initialQuestion?: string;
  onRefreshFocus: () => void;
  onSelectNode: (nodeId: string) => void;
  onClose: () => void;
}

const PRESET_QUESTIONS = [
  'What is this cluster and why is it colored like this?',
  'What breaks across the 3 tiers if I refactor this?',
  'How do I fix the top boundary finding cleanly?',
  'Summarize upstream routes and downstream SQL tables here.',
];

function renderInlineMarkdown(line: string) {
  const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={idx} className="font-semibold text-teal-200">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={idx}
          className="border border-slate-700 bg-slate-950 px-1 py-0.5 font-mono text-[11px] text-sky-200"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={idx}>{part}</span>;
  });
}

function renderFormattedAnswer(md: string) {
  const lines = md.split('\n');
  return lines.map((raw, idx) => {
    const trimmed = raw.trim();
    if (!trimmed) return <div key={idx} className="h-1.5" />;
    if (/^#{1,4}\s+/.test(trimmed)) {
      const heading = trimmed.replace(/^#{1,4}\s+/, '');
      return (
        <div key={idx} className="pt-1 font-mono text-xs font-semibold text-teal-300">
          {renderInlineMarkdown(heading)}
        </div>
      );
    }
    if (/^[-*]\s+/.test(trimmed)) {
      return (
        <div key={idx} className="pl-3 leading-relaxed text-slate-100">
          <span className="mr-1.5 text-teal-300">•</span>
          {renderInlineMarkdown(trimmed.replace(/^[-*]\s+/, ''))}
        </div>
      );
    }
    return (
      <div key={idx} className="leading-relaxed text-slate-100">
        {renderInlineMarkdown(raw)}
      </div>
    );
  });
}

export function AskWytheDrawer({
  open,
  activeSlug,
  explanation,
  liveDigest = null,
  snapshotDataUrl,
  captureLiveWebp,
  nodesById,
  initialQuestion = '',
  onRefreshFocus,
  onSelectNode,
  onClose,
}: AskWytheDrawerProps) {
  const [engineChoice, setEngineChoice] = useState<SelectedEngineChoice>('auto');
  const [customLocalUrl, setCustomLocalUrl] = useState('');
  const [showLocalConfig, setShowLocalConfig] = useState(false);
  const [keepSession, setKeepSession] = useState(true);
  const [question, setQuestion] = useState(initialQuestion);
  const [chromeProbe, setChromeProbe] = useState<ChromeEngineProbe>({
    state: 'unavailable',
    supportsVision: false,
    note: 'Probing Chrome LanguageModel…',
  });
  const [browserLocalProbe, setBrowserLocalProbe] = useState<BrowserLocalOpenAiProbe>({
    state: 'unavailable',
    baseUrl: null,
    requestModelId: null,
    displayModel: null,
    supportsVision: false,
    note: 'Probing browser-local /v1…',
  });
  const [chromeDownloadPct, setChromeDownloadPct] = useState<number | null>(null);
  const [turns, setTurns] = useState<QaTurn[]>([]);
  const [activeError, setActiveError] = useState<string | null>(null);
  const [isRunningClientModel, setIsRunningClientModel] = useState(false);
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);

  const { data: backendEngines, refetch: refetchEngines } = useAskEngines(
    customLocalUrl.trim() || undefined,
    open,
  );
  const askBackend = useAskWythe();

  useEffect(() => {
    if (initialQuestion) setQuestion(initialQuestion);
  }, [initialQuestion]);

  useEffect(() => {
    if (!open) return;
    void probeChromeBuiltInModel().then(setChromeProbe);
    void probeBrowserLocalOpenAi(customLocalUrl.trim() || undefined).then(setBrowserLocalProbe);
  }, [open, customLocalUrl]);

  if (!open) return null;

  const appleSt = (backendEngines?.engines ?? []).find((e) => e.engine === 'apple');
  const localSt = (backendEngines?.engines ?? []).find((e) => e.engine === 'local');
  const anyLocalReady = browserLocalProbe.state === 'ready' || localSt?.state === 'ready';
  const localStatusLabel =
    browserLocalProbe.state === 'ready'
      ? 'ready · this Mac'
      : localSt?.state === 'ready'
        ? 'ready · server'
        : (localSt?.state ?? '…');
  const isBusy = askBackend.isPending || isRunningClientModel;

  const copyEndpoint = (kind: 'mcp' | 'openapi') => {
    const origin = typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:8780';
    const url = kind === 'mcp' ? `${origin}/api/v1/mcp` : `${origin}/openapi.json`;
    void copyTextToClipboard(url).then((ok) => {
      if (ok) {
        setCopiedEndpoint(kind);
        window.setTimeout(() => setCopiedEndpoint(null), 1800);
      }
    });
  };

  const runQuestion = async (rawQ: string) => {
    const trimmed = rawQ.trim();
    if (!trimmed || isBusy) return;
    setActiveError(null);

    const liveFrameUrl = captureLiveWebp?.() ?? snapshotDataUrl;
    const liveBrief = liveDigest
      ? `${liveDigest.markdownBrief}\n\n${explanation?.markdown_brief ?? ''}`.trim()
      : (explanation?.markdown_brief ?? `Target: ${activeSlug}`);
    const refNodes =
      liveDigest?.referencedNodeIds && liveDigest.referencedNodeIds.length > 0
        ? liveDigest.referencedNodeIds
        : explanation?.focused_node
          ? [explanation.focused_node.id]
          : [];
    const sessionHistory: AskChatTurn[] = keepSession
      ? [...turns]
          .reverse()
          .slice(-6)
          .flatMap((t) => [
            { role: 'user' as const, content: t.question },
            { role: 'assistant' as const, content: t.answerMarkdown },
          ])
      : [];

    const useChrome =
      engineChoice === 'chrome' ||
      (engineChoice === 'auto' && appleSt?.state !== 'ready' && chromeProbe.state === 'ready');

    if (useChrome) {
      setIsRunningClientModel(true);
      try {
        const out = await runChromeBuiltInAsk({
          question: trimmed,
          xrayBrief: liveBrief,
          snapshotDataUrl: liveFrameUrl,
          history: sessionHistory,
        });
        setTurns((prev) => [
          {
            id: `turn-${prev.length + 1}`,
            question: trimmed,
            answerMarkdown: out.answerMarkdown,
            engineBadge: 'chrome · gemini-nano-in-browser',
            usedVision: out.usedVision,
            referencedNodeIds: refNodes,
          },
          ...prev,
        ]);
        setQuestion('');
        setIsRunningClientModel(false);
        return;
      } catch (err) {
        setIsRunningClientModel(false);
        if (engineChoice === 'chrome') {
          setActiveError((err as Error).message);
          return;
        }
      }
    }

    const useBrowserLocal =
      (engineChoice === 'local' ||
        (engineChoice === 'auto' && appleSt?.state !== 'ready' && chromeProbe.state !== 'ready')) &&
      browserLocalProbe.state === 'ready';

    if (useBrowserLocal) {
      setIsRunningClientModel(true);
      try {
        const out = await runBrowserLocalOpenAiAsk({
          probe: browserLocalProbe,
          question: trimmed,
          xrayBrief: liveBrief,
          snapshotDataUrl: liveFrameUrl,
          history: sessionHistory,
        });
        setTurns((prev) => [
          {
            id: `turn-${prev.length + 1}`,
            question: trimmed,
            answerMarkdown: out.answerMarkdown,
            engineBadge: `local (this Mac) · ${browserLocalProbe.displayModel ?? 'default_model'}`,
            usedVision: out.usedVision,
            referencedNodeIds: refNodes,
          },
          ...prev,
        ]);
        setQuestion('');
        setIsRunningClientModel(false);
        return;
      } catch (err) {
        setIsRunningClientModel(false);
        if (localSt?.state !== 'ready') {
          setActiveError((err as Error).message);
          return;
        }
      }
    }

    askBackend.mutate(
      {
        question: trimmed,
        engine: engineChoice,
        target_slug: activeSlug || undefined,
        local_base_url: customLocalUrl.trim() || undefined,
        include_vision_snapshot: true,
        history: sessionHistory,
        live_viewport_brief: liveDigest?.markdownBrief ?? undefined,
        snapshot_data_url: liveFrameUrl ?? undefined,
      },
      {
        onSuccess: (res) => {
          setTurns((prev) => [
            {
              id: `turn-${prev.length + 1}`,
              question: trimmed,
              answerMarkdown: res.answer_markdown,
              engineBadge: `${res.engine_used} · ${res.model_id}`,
              usedVision: res.used_vision_snapshot,
              referencedNodeIds: res.referenced_node_ids ?? [],
            },
            ...prev,
          ]);
          setQuestion('');
        },
        onError: (err) => setActiveError((err as Error).message),
      },
    );
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runQuestion(question);
  };

  return (
    <aside
      role="dialog"
      aria-label="Ask Wythe On-Device Architecture Assistant"
      className="fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col border-l border-teal-500/50 bg-slate-950/95 text-xs text-slate-200 shadow-2xl backdrop-blur-md"
    >
      <div className="flex items-start justify-between gap-2 border-b border-slate-800 p-4">
        <div>
          <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-teal-300">
            <Bot className="h-3.5 w-3.5" />
            Ask Wythe · Zero Copy-Paste Bridge ([A] / ⌘J)
          </div>
          <h2 className="mt-0.5 font-mono text-sm font-semibold text-slate-100">
            Zero-Setup On-Device Local Tier + MCP / OpenAPI
          </h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close Ask Wythe drawer"
          className="border border-slate-700 bg-slate-900 p-1 text-slate-300 hover:border-teal-400 hover:text-slate-100"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        <div className="space-y-2 border border-slate-800 bg-slate-900/70 p-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-1 font-mono text-[10px] uppercase text-sky-300">
              <Cpu className="h-3 w-3" />
              On-Device Engine Cascade (Apple → Chrome → Local)
            </span>
            <button
              type="button"
              onClick={() => setShowLocalConfig((v) => !v)}
              className="font-mono text-[10px] text-teal-300 underline hover:text-teal-200"
            >
              {showLocalConfig ? 'Hide /v1 URL' : 'Configure /v1 URL'}
            </button>
          </div>
          <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
            {(
              [
                ['auto', 'Auto (Best Local)', appleSt?.state === 'ready' || chromeProbe.state === 'ready' || anyLocalReady],
                ['apple', `Apple FM (${appleSt?.state ?? '…'})`, appleSt?.state === 'ready'],
                ['chrome', `Chrome AI (${chromeProbe.state})`, chromeProbe.state === 'ready'],
                ['local', `Local /v1 (${localStatusLabel})`, anyLocalReady],
              ] as const
            ).map(([key, label, ready]) => (
              <button
                key={key}
                type="button"
                onClick={() => setEngineChoice(key)}
                className={`flex items-center justify-between border px-2 py-1 text-left ${
                  engineChoice === key
                    ? 'border-teal-400 bg-teal-500/20 text-teal-100'
                    : 'border-slate-800 bg-slate-950 text-slate-300 hover:border-slate-700'
                }`}
              >
                <span className="truncate">{label}</span>
                <span className={ready ? 'text-emerald-300' : 'text-slate-400'}>●</span>
              </button>
            ))}
          </div>

          {(browserLocalProbe.state === 'ready' || localSt?.note) && (
            <div className="truncate font-mono text-[10px] text-slate-300">
              /v1 seat:{' '}
              <span className={anyLocalReady ? 'text-teal-300' : 'text-slate-400'}>
                {browserLocalProbe.state === 'ready' ? browserLocalProbe.note : localSt?.note}
              </span>
            </div>
          )}

          {chromeProbe.state === 'downloadable' && (
            <button
              type="button"
              onClick={() => {
                setChromeDownloadPct(0);
                void triggerChromeModelDownload((pct) => setChromeDownloadPct(pct))
                  .then((next) => {
                    setChromeProbe(next);
                    setChromeDownloadPct(null);
                  })
                  .catch((err) => {
                    setActiveError((err as Error).message);
                    setChromeDownloadPct(null);
                  });
              }}
              className="flex w-full items-center justify-center gap-1.5 border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 font-mono text-[11px] text-sky-200 hover:bg-sky-500/25"
            >
              <Download className="h-3 w-3" />
              {chromeDownloadPct !== null
                ? `Downloading Chrome Gemini Nano (${chromeDownloadPct}%)…`
                : 'Download Chrome Built-In Model (One-Time)'}
            </button>
          )}

          {showLocalConfig && (
            <div className="flex items-center gap-1.5 pt-1">
              <input
                type="text"
                aria-label="Custom loopback or Tailnet OpenAI /v1 server URL"
                value={customLocalUrl}
                onChange={(e) => setCustomLocalUrl(e.target.value)}
                placeholder="http://127.0.0.1:8084/v1 or :8080/v1"
                className="flex-1 border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-[11px] text-slate-100 focus:border-teal-400 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => {
                  void refetchEngines();
                  void probeBrowserLocalOpenAi(customLocalUrl.trim() || undefined).then(setBrowserLocalProbe);
                }}
                className="border border-teal-500/40 bg-teal-500/15 px-2 py-1 font-mono text-[11px] text-teal-200"
              >
                Probe
              </button>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-1.5 pt-0.5 font-mono text-[10px] text-slate-300">
            <button
              type="button"
              onClick={() => copyEndpoint('mcp')}
              className="flex items-center gap-1 border border-slate-700 bg-slate-950 px-2 py-0.5 hover:border-teal-400 hover:text-teal-200"
            >
              <Copy className="h-2.5 w-2.5" />
              {copiedEndpoint === 'mcp' ? 'Copied /api/v1/mcp!' : 'Copy HTTP MCP URL'}
            </button>
            <button
              type="button"
              onClick={() => copyEndpoint('openapi')}
              className="flex items-center gap-1 border border-slate-700 bg-slate-950 px-2 py-0.5 hover:border-teal-400 hover:text-teal-200"
            >
              <Copy className="h-2.5 w-2.5" />
              {copiedEndpoint === 'openapi' ? 'Copied /openapi.json!' : 'Copy OpenAPI URL'}
            </button>
            <span className="text-emerald-300">· WebMCP `window.wythe` active</span>
          </div>
        </div>

        <div className="border border-teal-500/30 bg-teal-950/20 p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase text-teal-300">
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
              <Eye className="h-3 w-3" />
              Real-Time 3D Camera &amp; Color Sync
            </span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setKeepSession((v) => !v)}
                className={`border px-1.5 py-0.5 text-[10px] ${
                  keepSession
                    ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200'
                    : 'border-slate-700 bg-slate-900 text-slate-300'
                }`}
              >
                {keepSession ? `Live Session (${turns.length})` : '1-Shot Mode'}
              </button>
              {turns.length > 0 && (
                <button
                  type="button"
                  onClick={() => setTurns([])}
                  aria-label="Clear conversation history"
                  className="flex items-center gap-1 border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300 hover:border-rose-400 hover:text-rose-200"
                >
                  <Trash2 className="h-2.5 w-2.5" />
                  Clear
                </button>
              )}
              <button
                type="button"
                onClick={onRefreshFocus}
                className="flex items-center gap-1 border border-teal-500/40 bg-teal-500/15 px-1.5 py-0.5 text-[10px] text-teal-200 hover:bg-teal-500/25"
              >
                <RefreshCw className="h-2.5 w-2.5" />
                Snap PNG
              </button>
            </div>
          </div>
          <p className="mt-1 font-mono text-[11px] text-slate-100">
            {liveDigest ? liveDigest.summaryPill : (explanation?.headline ?? `Target: ${activeSlug}`)}
          </p>
          <p className="mt-0.5 text-[10px] text-slate-300">
            Auto-streams live Three.js frustum nodes, exact rendered colors, pinned selection &amp; 1024px WebP frame on every Send.
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {PRESET_QUESTIONS.map((pq) => (
            <button
              key={pq}
              type="button"
              disabled={isBusy}
              onClick={() => void runQuestion(pq)}
              className="border border-slate-800 bg-slate-900 px-2 py-1 text-left font-mono text-[10px] text-slate-200 hover:border-teal-400 hover:text-teal-200 disabled:opacity-50"
            >
              <Sparkles className="mr-1 inline h-2.5 w-2.5 text-teal-300" />
              {pq}
            </button>
          ))}
        </div>

        {activeError && (
          <div className="border border-rose-500/40 bg-rose-950/30 p-2.5 font-mono text-[11px] text-rose-200">
            {activeError}
          </div>
        )}

        <div className="space-y-3">
          {turns.map((t) => (
            <div key={t.id} className="space-y-2 border border-slate-800 bg-slate-900/60 p-3">
              <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5 font-mono text-[10px]">
                <span className="font-semibold text-teal-300">Q: {t.question}</span>
                <span className="border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-emerald-200">
                  {t.engineBadge}
                  {t.usedVision ? ' + WebP Vision' : ' + Live Frustum'}
                </span>
              </div>
              <div className="space-y-0.5">{renderFormattedAnswer(t.answerMarkdown)}</div>
              {t.referencedNodeIds.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  <span className="font-mono text-[10px] uppercase text-slate-300">Jump in 3D:</span>
                  {t.referencedNodeIds.map((nid) => {
                    const n = nodesById.get(nid);
                    return (
                      <button
                        key={nid}
                        type="button"
                        onClick={() => onSelectNode(nid)}
                        className="border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 font-mono text-[10px] text-sky-200 hover:bg-sky-500/25"
                      >
                        {n ? `${n.tier}:${n.label}` : nid}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="border-t border-slate-800 bg-slate-950 p-3">
        <div className="flex items-center gap-2">
          <input
            type="text"
            aria-label="Ask Wythe about the current 3D view, cluster, or node"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder={isBusy ? 'Synthesizing grounded 3-tier answer…' : 'Ask "what is this?" or anything about this view…'}
            disabled={isBusy}
            className="flex-1 border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus:outline-none"
          />
          <button
            type="submit"
            disabled={isBusy || !question.trim()}
            aria-label="Send architectural question"
            className="flex items-center gap-1.5 border border-teal-500/60 bg-teal-500/20 px-3 py-2 font-mono text-xs font-semibold text-teal-100 hover:bg-teal-500/30 disabled:opacity-50"
          >
            <Send className="h-3.5 w-3.5" />
            {isBusy ? 'Asking…' : 'Ask'}
          </button>
        </div>
      </form>
    </aside>
  );
}
