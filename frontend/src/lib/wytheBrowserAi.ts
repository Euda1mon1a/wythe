/**
 * Zero-setup Chrome Built-In `LanguageModel` (Prompt API) + `window.wythe` & WebMCP bridge.
 * Runs 100% client-side when Chrome's on-device Gemini Nano model is available, requiring zero
 * backend server, and supports multimodal image input when Chrome's multimodal Prompt API is active.
 */

export type ChromeEngineState = 'ready' | 'downloadable' | 'downloading' | 'unavailable';

export interface ChromeEngineProbe {
  state: ChromeEngineState;
  supportsVision: boolean;
  note: string;
}

interface ChromeLanguageModelSession {
  prompt: (input: unknown, options?: Record<string, unknown>) => Promise<string>;
  destroy: () => void;
}

interface ChromeLanguageModelStatic {
  availability: (opts?: Record<string, unknown>) => Promise<string>;
  create: (opts?: Record<string, unknown>) => Promise<ChromeLanguageModelSession>;
}

const EN_TEXT_OPTS = {
  expectedInputs: [{ type: 'text', languages: ['en'] }],
  expectedOutputs: [{ type: 'text', languages: ['en'] }],
};

const EN_MULTIMODAL_OPTS = {
  expectedInputs: [
    { type: 'text', languages: ['en'] },
    { type: 'image' },
  ],
  expectedOutputs: [{ type: 'text', languages: ['en'] }],
};

function getChromeLanguageModelApi(): ChromeLanguageModelStatic | null {
  if (typeof window === 'undefined') return null;
  const g = window as unknown as {
    LanguageModel?: ChromeLanguageModelStatic;
    ai?: { languageModel?: ChromeLanguageModelStatic };
  };
  return g.LanguageModel ?? g.ai?.languageModel ?? null;
}

function mapAvailability(raw: string): ChromeEngineState {
  if (raw === 'available' || raw === 'readily') return 'ready';
  if (raw === 'downloadable' || raw === 'after-download') return 'downloadable';
  if (raw === 'downloading') return 'downloading';
  return 'unavailable';
}

export async function probeChromeBuiltInModel(): Promise<ChromeEngineProbe> {
  const api = getChromeLanguageModelApi();
  if (!api || typeof api.availability !== 'function') {
    return {
      state: 'unavailable',
      supportsVision: false,
      note: 'Open in Chrome 138+ with Prompt API enabled for in-browser Gemini Nano.',
    };
  }
  try {
    const rawText = await api.availability(EN_TEXT_OPTS);
    const state = mapAvailability(rawText);
    let supportsVision = false;
    if (state === 'ready' || state === 'downloadable') {
      try {
        const rawVision = await api.availability(EN_MULTIMODAL_OPTS);
        supportsVision = mapAvailability(rawVision) === 'ready';
      } catch {
        supportsVision = false;
      }
    }
    const notes: Record<ChromeEngineState, string> = {
      ready: supportsVision
        ? 'Chrome Built-In Gemini Nano ready in-browser (multimodal vision + text).'
        : 'Chrome Built-In Gemini Nano ready in-browser (zero backend required).',
      downloadable: 'Chrome can download its built-in on-device model (1-click below).',
      downloading: 'Chrome is downloading its built-in on-device model…',
      unavailable: 'Chrome built-in model is not enabled on this browser profile.',
    };
    return { state, supportsVision, note: notes[state] };
  } catch {
    return {
      state: 'unavailable',
      supportsVision: false,
      note: 'Could not query Chrome built-in LanguageModel availability.',
    };
  }
}

export async function triggerChromeModelDownload(
  onProgress?: (pct: number) => void,
): Promise<ChromeEngineProbe> {
  const api = getChromeLanguageModelApi();
  if (!api) throw new Error('Chrome LanguageModel API is not present in this browser.');
  const session = await api.create({
    ...EN_TEXT_OPTS,
    monitor(m: EventTarget) {
      m.addEventListener('downloadprogress', (ev: Event) => {
        const loaded = (ev as unknown as { loaded?: number }).loaded;
        if (typeof loaded === 'number' && onProgress) {
          onProgress(Math.max(0, Math.min(100, Math.round(loaded * 100))));
        }
      });
    },
  });
  session.destroy();
  return probeChromeBuiltInModel();
}

async function dataUrlToImageBitmap(dataUrl: string): Promise<ImageBitmap | null> {
  try {
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    return await createImageBitmap(blob);
  } catch {
    return null;
  }
}

export async function runChromeBuiltInAsk(params: {
  question: string;
  xrayBrief: string;
  snapshotDataUrl: string | null;
  history?: Array<{ role: 'user' | 'assistant'; content: string }>;
}): Promise<{ answerMarkdown: string; usedVision: boolean }> {
  const api = getChromeLanguageModelApi();
  if (!api) throw new Error('Chrome built-in LanguageModel API is unavailable.');

  const instructions =
    "You are Wythe's in-browser real-time 3-tier architecture assistant. Ground all repository, node, color, " +
    'rule, and lineage claims strictly in the Live 3D Camera & X-Ray facts (SQL Truth, Backend Manipulate, ' +
    'Frontend Display). Cite exact rule codes, node names, on-screen colors, and file:line pointers, and never ' +
    'invent files or tables. Answer general architecture or Wythe workflow questions directly.';

  const priorTurns = (params.history ?? []).slice(-6);
  const textBody = `## Live 3D Wythe Camera & X-Ray\n${params.xrayBrief.slice(0, 3200)}\n\n## Question\n${params.question.trim()}`;

  if (params.snapshotDataUrl) {
    try {
      const mmAvail = mapAvailability(await api.availability(EN_MULTIMODAL_OPTS));
      if (mmAvail === 'ready') {
        const bmp = await dataUrlToImageBitmap(params.snapshotDataUrl);
        if (bmp) {
          const mmSession = await api.create({
            ...EN_MULTIMODAL_OPTS,
            initialPrompts: [{ role: 'system', content: instructions }, ...priorTurns],
          });
          try {
            const out = await mmSession.prompt([
              {
                role: 'user',
                content: [
                  { type: 'text', value: textBody },
                  { type: 'image', value: bmp },
                ],
              },
            ]);
            bmp.close();
            if (out && out.trim()) {
              return { answerMarkdown: out.trim(), usedVision: true };
            }
          } finally {
            mmSession.destroy();
          }
        }
      }
    } catch {
      // Fall back cleanly to text-only Chrome LanguageModel session
    }
  }

  const session = await api.create({
    ...EN_TEXT_OPTS,
    initialPrompts: [{ role: 'system', content: instructions }, ...priorTurns],
  });
  try {
    const out = await session.prompt(textBody);
    return { answerMarkdown: (out || '').trim(), usedVision: false };
  } finally {
    session.destroy();
  }
}

export interface BrowserLocalOpenAiProbe {
  state: 'ready' | 'unavailable';
  baseUrl: string | null;
  requestModelId: string | null;
  displayModel: string | null;
  supportsVision: boolean;
  note: string;
}

const CLIENT_LOCAL_SEATS = [
  'http://127.0.0.1:8080/v1',
  'http://127.0.0.1:8084/v1',
  'http://127.0.0.1:8081/v1',
  'http://127.0.0.1:8083/v1',
  'http://127.0.0.1:8085/v1',
  'http://127.0.0.1:8093/v1',
  'http://127.0.0.1:1234/v1',
  'http://127.0.0.1:11434/v1',
];

const NON_CHAT_MODEL_TOKENS = ['whisper', 'embed', 'minilm', 'bge-', 'rerank', 'tts', 'piper', 'kokoro', 'ocr', 'flux'];
const VISION_MODEL_TOKENS = ['vl', 'vision', 'gemma-3', 'gemma-4', 'pixtral', 'llava', 'minicpm-v', 'internvl'];

function extractSnapshotSlug(id: string): string | null {
  if (id.includes('models--') && id.includes('/snapshots/')) {
    const tail = id.split('models--')[1]?.split('/snapshots/')[0];
    return tail ? tail.replace(/--/g, '/') : null;
  }
  return null;
}

function normalizeClientV1Url(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, '');
  return trimmed.endsWith('/v1') ? trimmed : `${trimmed}/v1`;
}

export async function probeBrowserLocalOpenAi(customUrl?: string): Promise<BrowserLocalOpenAiProbe> {
  if (typeof window === 'undefined') {
    return { state: 'unavailable', baseUrl: null, requestModelId: null, displayModel: null, supportsVision: false, note: 'SSR' };
  }
  const candidates = customUrl?.trim()
    ? [normalizeClientV1Url(customUrl), ...CLIENT_LOCAL_SEATS]
    : CLIENT_LOCAL_SEATS;

  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/models`, { signal: AbortSignal.timeout(2500) });
      if (!res.ok) continue;
      const body = (await res.json()) as {
        data?: Array<{ id?: string; owned_by?: string; created?: number }>;
      };
      const items = (body.data ?? []).filter((m) => m && typeof m.id === 'string' && m.id.length > 0);
      const chatIds = items
        .map((m) => m.id as string)
        .filter((id) => !NON_CHAT_MODEL_TOKENS.some((bad) => id.toLowerCase().includes(bad)));
      if (chatIds.length === 0) continue;

      let reqModel = chatIds[0];
      let dispModel = extractSnapshotSlug(reqModel) ?? reqModel;
      const isPinnedProxy =
        items.length === 1 || (items[0]?.owned_by ?? '').toLowerCase().includes('pinned');
      const isMlxMulti = items.some((m) => (m.id ?? '').startsWith('mlx-community/') || (m.id ?? '').includes('/models--'));
      if (!isPinnedProxy && isMlxMulti) {
        const srvHdr = (res.headers.get('server') ?? '').toLowerCase();
        const createdSet = new Set(items.map((m) => m.created).filter((c) => typeof c === 'number'));
        const hasOwner = items.some((m) => Boolean(m.owned_by));
        if (srvHdr.includes('mlx_vlm') || (createdSet.size > 1 && !hasOwner)) {
          continue;
        }
        const snap = items.map((m) => extractSnapshotSlug(m.id ?? '')).find(Boolean);
        reqModel = 'default_model';
        dispModel = snap ?? 'default_model (mlx_lm)';
      }
      const supportsVision = VISION_MODEL_TOKENS.some((tok) => dispModel.toLowerCase().includes(tok));
      return {
        state: 'ready',
        baseUrl: base,
        requestModelId: reqModel,
        displayModel: dispModel,
        supportsVision,
        note: `${dispModel} ready on this browser host (${base})`,
      };
    } catch {
      // Try next loopback port on viewer workstation
    }
  }
  return {
    state: 'unavailable',
    baseUrl: null,
    requestModelId: null,
    displayModel: null,
    supportsVision: false,
    note: 'No browser-loopback /v1 seat answered (falls back to Wythe server /v1).',
  };
}

export async function runBrowserLocalOpenAiAsk(params: {
  probe: BrowserLocalOpenAiProbe;
  question: string;
  xrayBrief: string;
  snapshotDataUrl: string | null;
  history?: Array<{ role: 'user' | 'assistant'; content: string }>;
}): Promise<{ answerMarkdown: string; usedVision: boolean }> {
  if (!params.probe.baseUrl || !params.probe.requestModelId) {
    throw new Error('Browser-local /v1 seat is not ready.');
  }
  const instructions =
    "You are Wythe's real-time 3-tier software architecture & lineage verifier assistant. Ground all " +
    'repository, node, on-screen color, rule, and lineage statements strictly in the Live 3D Camera & X-Ray ' +
    'facts below (SQL Truth, Backend Manipulate, Frontend Display). Cite exact rule codes, node names, ' +
    'rendered colors, and file:line pointers, and never invent files or tables. If the user asks a general ' +
    'architecture, workflow, or Wythe UI question, answer it directly and concisely.';
  const textPrompt = `## Live 3D Wythe Camera & X-Ray\n${params.xrayBrief.slice(0, 3400)}\n\n## User Question\n${params.question.trim()}`;
  const priorMsgs = (params.history ?? [])
    .slice(-8)
    .map((t) => ({ role: t.role, content: t.content.slice(0, 2200) }));

  const tryVision = Boolean(params.snapshotDataUrl && params.probe.supportsVision);
  const sendChat = async (contentPayload: unknown) => {
    const body: Record<string, unknown> = {
      model: params.probe.requestModelId,
      temperature: 0.2,
      max_tokens: 900,
      messages: [
        { role: 'system', content: instructions },
        ...priorMsgs,
        { role: 'user', content: contentPayload },
      ],
    };
    if (
      params.probe.requestModelId === 'default_model' ||
      (params.probe.displayModel ?? '').toLowerCase().includes('qwen')
    ) {
      body.chat_template_kwargs = { enable_thinking: false };
    }
    const res = await fetch(`${params.probe.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(90000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const parsed = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const text = (parsed.choices?.[0]?.message?.content ?? '').trim();
    if (!text) throw new Error('Empty completion from browser-local /v1 seat.');
    return text;
  };

  if (tryVision && params.snapshotDataUrl) {
    try {
      const out = await sendChat([
        { type: 'text', text: textPrompt },
        { type: 'image_url', image_url: { url: params.snapshotDataUrl } },
      ]);
      return { answerMarkdown: out, usedVision: true };
    } catch {
      // Retry text-only if VLM payload rejected
    }
  }
  return { answerMarkdown: await sendChat(textPrompt), usedVision: false };
}

export interface WythePageBridgeHandlers {
  getWhatIsThis: () => Promise<unknown>;
  getLineageCone: (query: string) => Promise<unknown>;
  selectNode: (nodeId: string) => void;
  openAskDrawer: (prefill?: string) => void;
}

export function registerWytheWebMcpBridge(handlers: WythePageBridgeHandlers): () => void {
  if (typeof window === 'undefined') return () => {};
  const win = window as unknown as Record<string, unknown>;
  win.wythe = {
    version: '0.1.2',
    mcpHttpEndpoint: `${window.location.origin}/api/v1/mcp`,
    openapiEndpoint: `${window.location.origin}/openapi.json`,
    whatIsThis: () => handlers.getWhatIsThis(),
    getLineageCone: (query: string) => handlers.getLineageCone(query),
    selectNode: (nodeId: string) => handlers.selectNode(nodeId),
    ask: (question?: string) => handlers.openAskDrawer(question),
  };

  const nav = navigator as unknown as {
    modelContext?: {
      registerTool?: (tool: Record<string, unknown>) => void;
      unregisterTool?: (name: string) => void;
    };
  };
  if (nav.modelContext && typeof nav.modelContext.registerTool === 'function') {
    try {
      nav.modelContext.registerTool({
        name: 'wythe_what_is_this',
        description: 'Inspect live 3D Wythe focus node, vertical district, and blast-radius X-ray.',
        inputSchema: { type: 'object', properties: {} },
        execute: async () => handlers.getWhatIsThis(),
      });
      nav.modelContext.registerTool({
        name: 'wythe_select_node',
        description: 'Highlight a 3-tier node in the live 3D Wythe viewport without moving the camera.',
        inputSchema: {
          type: 'object',
          properties: { nodeId: { type: 'string' } },
          required: ['nodeId'],
        },
        execute: async (args: { nodeId?: string }) => {
          if (args?.nodeId) handlers.selectNode(args.nodeId);
          return { ok: true, selectedNodeId: args?.nodeId ?? null };
        },
      });
    } catch {
      // Ignore experimental WebMCP differences across browser builds
    }
  }

  return () => {
    delete win.wythe;
    try {
      nav.modelContext?.unregisterTool?.('wythe_what_is_this');
      nav.modelContext?.unregisterTool?.('wythe_select_node');
    } catch {
      // Ignore cleanup if browser lacks unregisterTool
    }
  };
}
