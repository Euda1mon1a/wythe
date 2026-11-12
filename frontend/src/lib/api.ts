/**
 * Typed HTTP transport helpers bound to the loopback Wythe FastAPI backend.
 */

const DEV_UI_PORTS = new Set(['3000', '3180', '3780']);

function resolveApiBase(): string {
  if (process.env.NEXT_PUBLIC_WYTHE_API_URL) {
    return process.env.NEXT_PUBLIC_WYTHE_API_URL;
  }
  if (process.env.NEXT_PUBLIC_TRUTH_ATLAS_API_URL) {
    return process.env.NEXT_PUBLIC_TRUTH_ATLAS_API_URL;
  }
  if (typeof window !== 'undefined' && !DEV_UI_PORTS.has(window.location.port)) {
    return '/api/v1';
  }
  return 'http://127.0.0.1:8780/api/v1';
}

export class ApiRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${resolveApiBase()}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // keep status fallback
    }
    throw new ApiRequestError(res.status, detail);
  }
  return (await res.json()) as T;
}

export function get<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'GET' });
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function patch<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}
