import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  looksVisionCapableModel,
  probeBrowserLocalOpenAi,
  runBrowserLocalOpenAiAsk,
  runChromeBuiltInAsk,
  sanitizeEndpointOrigin,
} from '../wytheBrowserAi';

test('looksVisionCapableModel covers required multimodal and omni families without substring false positives', () => {
  const positives = [
    'mlx-community/Qwen3.5-27B-4bit',
    'mlx-community/Qwen3.6-35B-A3B-4bit',
    'Qwen/Qwen2.5-VL-7B-Instruct',
    'Qwen/Qwen2-VL-7B-Instruct',
    'moonshotai/Kimi-VL-A3B-Instruct',
    'allenai/Molmo-7B-D-0924',
    'rhymes-ai/Aria',
    'mistralai/Pixtral-12B-2409',
    'llava-hf/llava-1.5-7b-hf',
    'google/gemma-3-12b-it',
    'OpenGVLab/InternVL2_5-8B',
    'openbmb/MiniCPM-V-2_6',
  ];
  for (const model of positives) {
    assert.equal(looksVisionCapableModel(model), true, `Expected vision support for ${model}`);
  }
  assert.equal(looksVisionCapableModel('local/invariant-text-7b'), false);
  assert.equal(looksVisionCapableModel('local/qwen3-8b'), false);
});

test('sanitizeEndpointOrigin strips userinfo, path, query, and fragment', () => {
  assert.equal(
    sanitizeEndpointOrigin('http://alice:secret-token@127.0.0.1:8084/v1/chat?api_key=xyz#frag'),
    'http://127.0.0.1:8084',
  );
  assert.equal(sanitizeEndpointOrigin('https://100.64.0.10/custom/v1?x=1'), 'https://100.64.0.10');
  assert.equal(sanitizeEndpointOrigin('not-a-url'), null);
});

test('probeBrowserLocalOpenAi honors loaded flags on mlx_vlm and avoids tiny/aux/unloaded seats', async () => {
  const g = globalThis as unknown as Record<string, unknown>;
  const prevWin = g.window;
  const prevFetch = g.fetch;
  try {
    g.window = { location: { origin: 'http://127.0.0.1:3780' } };

    // 1) mlx_vlm server with loaded: true primary chat model + tiny aux/unloaded models
    g.fetch = async (url: unknown) => {
      if (String(url).endsWith('/models')) {
        return {
          ok: true,
          headers: { get: (k: string) => (k.toLowerCase() === 'server' ? 'mlx_vlm/0.6.17' : '') },
          json: async () => ({
            data: [
              { id: 'mlx-community/Qwen3-0.5B-4bit', loaded: true },
              { id: 'mlx-community/tiny-gate-0.6b', loaded: true },
              { id: 'mlx-community/draft-1b', loaded: true },
              { id: 'mlx-community/bge-embed-small', loaded: true },
              { id: 'mlx-community/bge-rerank-base', loaded: true },
              { id: 'mlx-community/whisper-large-v3', loaded: true },
              { id: 'mlx-community/kokoro-tts', loaded: true },
              { id: 'mlx-community/custom-omni-chat', loaded: true },
              { id: 'mlx-community/Qwen3.6-35B-A3B-4bit', loaded: false },
            ],
          }),
        };
      }
      throw new Error('unexpected url');
    };
    const mlxProbe = await probeBrowserLocalOpenAi('http://user:pw@127.0.0.1:8084/v1?k=1#h', true);
    assert.equal(mlxProbe.state, 'ready');
    assert.equal(mlxProbe.requestModelId, 'mlx-community/custom-omni-chat');
    assert.equal(mlxProbe.supportsVision, true);
    assert.equal(mlxProbe.baseUrl, 'http://127.0.0.1:8084/v1');

    // 2) All models unloaded -> unavailable (never pick loaded: false)
    g.fetch = async () => ({
      ok: true,
      headers: { get: () => 'mlx_vlm/0.6.17' },
      json: async () => ({
        data: [{ id: 'mlx-community/Qwen3.6-35B-A3B-4bit', loaded: false }],
      }),
    });
    const unloadedProbe = await probeBrowserLocalOpenAi('http://127.0.0.1:8084/v1', true);
    assert.equal(unloadedProbe.state, 'unavailable');
  } finally {
    g.window = prevWin;
    g.fetch = prevFetch;
  }
});

test('runBrowserLocalOpenAiAsk captures parsed.model, retries text-only on 400/404/422, and returns sanitized BrowserAiAnswer', async () => {
  const g = globalThis as unknown as Record<string, unknown>;
  const prevFetch = g.fetch;
  const bodies: Array<Record<string, unknown>> = [];
  let attempt = 0;

  try {
    g.fetch = async (_url: unknown, init?: { body?: string }) => {
      attempt += 1;
      const parsedBody = JSON.parse(init?.body ?? '{}') as Record<string, unknown>;
      bodies.push(parsedBody);
      if (attempt === 1) {
        return {
          ok: false,
          status: 422,
          json: async () => ({ error: 'multimodal not accepted' }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          model: 'mlx-community/Qwen3.5-27B-4bit',
          choices: [{ message: { content: 'Verified grounded answer.' } }],
        }),
      };
    };

    const ans = await runBrowserLocalOpenAiAsk({
      probe: {
        state: 'ready',
        baseUrl: 'http://alice:secret@127.0.0.1:8080/v1?token=abc#frag',
        requestModelId: 'default_model',
        displayModel: 'default_model (mlx_lm)',
        supportsVision: true,
        note: 'ready',
      },
      question: 'Explain this node.',
      xrayBrief: 'Node details',
      snapshotDataUrl: 'data:image/webp;base64,UklGRhIAAABXRUJQ',
    });

    assert.equal(bodies.length, 2);
    assert.equal(ans.answerMarkdown, 'Verified grounded answer.');
    assert.equal(ans.usedVision, false);
    assert.equal(ans.used_vision_snapshot, false);
    assert.equal(ans.execution_origin, 'browser_client');
    assert.equal(ans.endpoint_origin, 'http://127.0.0.1:8080');
    assert.equal(ans.requested_model_id, 'default_model');
    assert.equal(ans.resolved_model_id, 'mlx-community/Qwen3.5-27B-4bit');
    assert.equal(ans.fallback_from, 'vision');
  } finally {
    g.fetch = prevFetch;
  }
});

test('runChromeBuiltInAsk populates BrowserAiAnswer provenance', async () => {
  const g = globalThis as unknown as Record<string, unknown>;
  const prevWin = g.window;
  try {
    g.window = {
      LanguageModel: {
        availability: async () => 'available',
        create: async () => ({
          prompt: async () => 'Chrome answer.',
          destroy: () => {},
        }),
      },
    };
    const ans = await runChromeBuiltInAsk({
      question: 'What is this?',
      xrayBrief: 'Brief',
      snapshotDataUrl: null,
    });
    assert.equal(ans.answerMarkdown, 'Chrome answer.');
    assert.equal(ans.execution_origin, 'browser_client');
    assert.equal(ans.endpoint_origin, null);
    assert.equal(ans.requested_model_id, 'gemini-nano-in-browser');
    assert.equal(ans.resolved_model_id, 'gemini-nano-in-browser');
    assert.equal(ans.used_vision_snapshot, false);
    assert.equal(ans.fallback_from, null);
  } finally {
    g.window = prevWin;
  }
});
