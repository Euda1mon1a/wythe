/**
 * Per-tab human-agent investigation session identity, reload-safe follow state,
 * `#session=` / `?session=` explicit shared participation, and command receipt gating.
 */

export interface SessionStorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export const WYTHE_TAB_CLIENT_ID_KEY = 'wythe.tab.client_id';
export const WYTHE_TAB_ACTIVE_SLUG_KEY = 'wythe.tab.active_slug';
export const WYTHE_TAB_SESSION_MAP_KEY = 'wythe.tab.sessions_by_target';
export const WYTHE_TAB_FOLLOW_MAP_KEY = 'wythe.tab.follow_by_session';
export const WYTHE_TAB_ACKED_COMMANDS_KEY = 'wythe.tab.acked_commands_by_scope';
export const MIN_UI_FOCUS_DEBOUNCE_MS = 260;

const MAX_ACKED_COMMAND_KEYS = 128;
const SAFE_SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export function createMemoryTabStorage(): SessionStorageLike {
  const store = new Map<string, string>();
  return {
    getItem: (key) => (store.has(key) ? store.get(key)! : null),
    setItem: (key, value) => {
      store.set(key, String(value));
    },
    removeItem: (key) => {
      store.delete(key);
    },
  };
}

function defaultTabStorage(explicit?: SessionStorageLike | null): SessionStorageLike | null {
  if (explicit !== undefined) return explicit;
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function randomHex12(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  return Math.floor(Math.random() * 0xffffffffffff)
    .toString(16)
    .padStart(12, '0');
}

export function sanitizeInvestigationId(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 64) return null;
  if (!SAFE_SESSION_ID_RE.test(trimmed)) return null;
  return trimmed;
}

function readJsonRecord(
  storage: SessionStorageLike | null,
  key: string,
): Record<string, string> {
  if (!storage) return {};
  try {
    const raw = storage.getItem(key);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === 'string') out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

function writeJsonRecord(
  storage: SessionStorageLike | null,
  key: string,
  value: Record<string, string>,
): void {
  if (!storage) return;
  try {
    storage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore storage quota errors
  }
}

export function extractExplicitSessionIdFromUrl(
  urlOrHashOrSearch: string | null | undefined,
): string | null {
  if (!urlOrHashOrSearch) return null;
  const raw = urlOrHashOrSearch.trim();
  if (!raw) return null;

  const checkParams = (segment: string): string | null => {
    const cleaned = segment.replace(/^[#?&]+/, '');
    if (!cleaned) return null;
    const params = new URLSearchParams(cleaned);
    return sanitizeInvestigationId(params.get('session') ?? params.get('session_id'));
  };

  const hashIdx = raw.indexOf('#');
  const qIdx = raw.indexOf('?');
  if (hashIdx >= 0) {
    const fromHash = checkParams(raw.slice(hashIdx + 1));
    if (fromHash) return fromHash;
  }
  if (qIdx >= 0) {
    const end = hashIdx > qIdx ? hashIdx : raw.length;
    const fromQuery = checkParams(raw.slice(qIdx + 1, end));
    if (fromQuery) return fromQuery;
  }
  if (raw.startsWith('#') || raw.startsWith('?') || raw.includes('=')) {
    return checkParams(raw);
  }
  return null;
}

export function extractExplicitTargetFromUrl(
  urlOrHashOrSearch: string | null | undefined,
): string | null {
  if (!urlOrHashOrSearch) return null;
  const raw = urlOrHashOrSearch.trim();
  if (!raw) return null;

  const checkParams = (segment: string): string | null => {
    const cleaned = segment.replace(/^[#?&]+/, '');
    if (!cleaned) return null;
    const params = new URLSearchParams(cleaned);
    return sanitizeInvestigationId(params.get('target') ?? params.get('target_slug'));
  };

  const hashIdx = raw.indexOf('#');
  const qIdx = raw.indexOf('?');
  if (hashIdx >= 0) {
    const fromHash = checkParams(raw.slice(hashIdx + 1));
    if (fromHash) return fromHash;
  }
  if (qIdx >= 0) {
    const end = hashIdx > qIdx ? hashIdx : raw.length;
    const fromQuery = checkParams(raw.slice(qIdx + 1, end));
    if (fromQuery) return fromQuery;
  }
  if (raw.startsWith('#') || raw.startsWith('?') || raw.includes('=')) {
    return checkParams(raw);
  }
  return null;
}

export function getOrCreateTabClientId(storage?: SessionStorageLike | null): string {
  const store = defaultTabStorage(storage);
  const existing = sanitizeInvestigationId(store?.getItem(WYTHE_TAB_CLIENT_ID_KEY));
  if (existing) return existing;
  const next = `cli_${randomHex12()}`;
  try {
    store?.setItem(WYTHE_TAB_CLIENT_ID_KEY, next);
  } catch {
    // Ephemeral fallback when sessionStorage is disabled
  }
  return next;
}

export function resolveTabInvestigationIdentity(options: {
  targetSlug: string;
  locationHref?: string | null;
  storage?: SessionStorageLike | null;
}): { clientId: string; sessionId: string; sharedFromUrl: boolean } {
  const store = defaultTabStorage(options.storage);
  const clientId = getOrCreateTabClientId(store);
  const slug = options.targetSlug.trim() || 'wythe';
  const href =
    options.locationHref !== undefined
      ? options.locationHref
      : typeof window !== 'undefined'
        ? window.location.href
        : null;

  const map = readJsonRecord(store, WYTHE_TAB_SESSION_MAP_KEY);
  const fromUrl = extractExplicitSessionIdFromUrl(href);
  const urlTarget = extractExplicitTargetFromUrl(href);
  if (fromUrl && (!urlTarget || urlTarget === slug)) {
    map[slug] = fromUrl;
    writeJsonRecord(store, WYTHE_TAB_SESSION_MAP_KEY, map);
    return { clientId, sessionId: fromUrl, sharedFromUrl: true };
  }

  const saved = sanitizeInvestigationId(map[slug]);
  if (saved) {
    return { clientId, sessionId: saved, sharedFromUrl: false };
  }

  const generated = `inv_${randomHex12()}`;
  map[slug] = generated;
  writeJsonRecord(store, WYTHE_TAB_SESSION_MAP_KEY, map);
  return { clientId, sessionId: generated, sharedFromUrl: false };
}

export function switchTabSessionId(
  targetSlug: string,
  nextSessionId: string,
  storage?: SessionStorageLike | null,
): string {
  const store = defaultTabStorage(storage);
  const clean = sanitizeInvestigationId(nextSessionId) ?? `inv_${randomHex12()}`;
  const slug = targetSlug.trim() || 'wythe';
  const map = readJsonRecord(store, WYTHE_TAB_SESSION_MAP_KEY);
  map[slug] = clean;
  writeJsonRecord(store, WYTHE_TAB_SESSION_MAP_KEY, map);
  return clean;
}

export function rotateTabSessionId(
  targetSlug: string,
  storage?: SessionStorageLike | null,
): string {
  return switchTabSessionId(targetSlug, `inv_${randomHex12()}`, storage);
}

export function readPersistedActiveSlug(storage?: SessionStorageLike | null): string | null {
  const store = defaultTabStorage(storage);
  return sanitizeInvestigationId(store?.getItem(WYTHE_TAB_ACTIVE_SLUG_KEY));
}

export function writePersistedActiveSlug(
  targetSlug: string | null | undefined,
  storage?: SessionStorageLike | null,
): void {
  const clean = sanitizeInvestigationId(targetSlug);
  if (!clean) return;
  const store = defaultTabStorage(storage);
  try {
    store?.setItem(WYTHE_TAB_ACTIVE_SLUG_KEY, clean);
  } catch {
    // Ignore storage quota errors
  }
}

export function readPersistedFollowState(
  sessionId: string | null | undefined,
  storage?: SessionStorageLike | null,
): 'following' | 'paused' {
  const clean = sanitizeInvestigationId(sessionId);
  if (!clean) return 'following';
  const store = defaultTabStorage(storage);
  const map = readJsonRecord(store, WYTHE_TAB_FOLLOW_MAP_KEY);
  return map[clean] === 'paused' ? 'paused' : 'following';
}

export function writePersistedFollowState(
  sessionId: string | null | undefined,
  followState: 'following' | 'paused',
  storage?: SessionStorageLike | null,
): void {
  const clean = sanitizeInvestigationId(sessionId);
  if (!clean) return;
  const store = defaultTabStorage(storage);
  const map = readJsonRecord(store, WYTHE_TAB_FOLLOW_MAP_KEY);
  map[clean] = followState;
  writeJsonRecord(store, WYTHE_TAB_FOLLOW_MAP_KEY, map);
}

function scopeKey(targetSlug: string, sessionId: string | null | undefined): string {
  return `${targetSlug.trim() || 'wythe'}::${sanitizeInvestigationId(sessionId) ?? 'default'}`;
}

export function getViewportCommandKey(event: {
  seq: number;
  command: { command_id?: string | null };
}): string {
  const cid = sanitizeInvestigationId(event.command.command_id);
  return cid ?? `seq_${Math.max(0, Math.trunc(event.seq))}`;
}

export function readAckedCommandIds(
  targetSlug: string,
  sessionId: string | null | undefined,
  storage?: SessionStorageLike | null,
): string[] {
  const store = defaultTabStorage(storage);
  if (!store) return [];
  try {
    const raw = store.getItem(WYTHE_TAB_ACKED_COMMANDS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const arr = parsed?.[scopeKey(targetSlug, sessionId)];
    if (!Array.isArray(arr)) return [];
    return arr.filter((v): v is string => typeof v === 'string' && v.length > 0);
  } catch {
    return [];
  }
}

export function recordAckedCommandId(
  targetSlug: string,
  sessionId: string | null | undefined,
  commandKey: string,
  storage?: SessionStorageLike | null,
): string[] {
  const cleanKey = commandKey.trim();
  const current = readAckedCommandIds(targetSlug, sessionId, storage);
  if (!cleanKey) return current;
  const dedup = [...current.filter((k) => k !== cleanKey), cleanKey].slice(
    -MAX_ACKED_COMMAND_KEYS,
  );
  const store = defaultTabStorage(storage);
  if (store) {
    try {
      const raw = store.getItem(WYTHE_TAB_ACKED_COMMANDS_KEY);
      const all =
        raw && typeof JSON.parse(raw) === 'object' && !Array.isArray(JSON.parse(raw))
          ? (JSON.parse(raw) as Record<string, string[]>)
          : {};
      all[scopeKey(targetSlug, sessionId)] = dedup;
      store.setItem(WYTHE_TAB_ACKED_COMMANDS_KEY, JSON.stringify(all));
    } catch {
      // Ignore storage quota errors
    }
  }
  return dedup;
}

export type IncomingCommandDecision = {
  action: 'apply' | 'queue_while_paused' | 'hold_on_reload' | 'reject_stale' | 'reject' | 'ignore';
  shouldMoveCamera: boolean;
  receiptOutcome: 'applied' | 'paused_by_human' | 'rejected' | 'stale_revision' | null;
  markAcked: boolean;
  markPausedNotified: boolean;
  commandKey: string;
  reason: string;
};

export function evaluateIncomingViewportCommand(params: {
  event: {
    seq: number;
    delivery_state?: string | null;
    applied_by_client_ids?: ReadonlyArray<string>;
    command: {
      command_id?: string | null;
      target_slug: string;
      session_id?: string | null;
      expected_evidence_revision?: string | null;
      expires_at?: string | null;
    };
  };
  source: 'sse' | 'initial_state';
  activeTargetSlug: string;
  activeSessionId: string | null;
  clientId: string;
  followState: 'following' | 'paused';
  currentEvidenceRevisionId?: string | null;
  ackedCommandIds?: ReadonlySet<string> | ReadonlyArray<string>;
  pausedNotifiedCommandIds?: ReadonlySet<string>;
  nowMs?: number;
}): IncomingCommandDecision {
  const {
    event,
    source,
    activeTargetSlug,
    activeSessionId,
    clientId,
    followState,
    currentEvidenceRevisionId = null,
    ackedCommandIds = [],
    pausedNotifiedCommandIds,
    nowMs = Date.now(),
  } = params;

  const commandKey = getViewportCommandKey(event);
  const ackedSet =
    ackedCommandIds instanceof Set ? ackedCommandIds : new Set(ackedCommandIds);

  if (event.command.target_slug !== activeTargetSlug) {
    return {
      action: 'ignore',
      shouldMoveCamera: false,
      receiptOutcome: null,
      markAcked: false,
      markPausedNotified: false,
      commandKey,
      reason: 'wrong_target',
    };
  }
  if (
    event.command.session_id &&
    activeSessionId &&
    event.command.session_id !== activeSessionId
  ) {
    return {
      action: 'ignore',
      shouldMoveCamera: false,
      receiptOutcome: null,
      markAcked: false,
      markPausedNotified: false,
      commandKey,
      reason: 'wrong_session',
    };
  }
  const appliedByThisClient = Boolean(
    clientId && (event.applied_by_client_ids ?? []).includes(clientId),
  );
  if (ackedSet.has(commandKey) || appliedByThisClient) {
    return {
      action: 'ignore',
      shouldMoveCamera: false,
      receiptOutcome: null,
      markAcked: false,
      markPausedNotified: false,
      commandKey,
      reason: 'duplicate_command',
    };
  }

  const deliveryState = event.delivery_state ?? 'accepted_by_service';
  const expMs = event.command.expires_at ? Date.parse(event.command.expires_at) : NaN;
  if (deliveryState === 'expired' || (Number.isFinite(expMs) && expMs <= nowMs)) {
    return {
      action: 'ignore',
      shouldMoveCamera: false,
      receiptOutcome: null,
      markAcked: true,
      markPausedNotified: false,
      commandKey,
      reason: 'expired',
    };
  }

  if (source === 'initial_state') {
    if (
      deliveryState === 'applied_by_browser' ||
      deliveryState === 'stale' ||
      deliveryState === 'rejected'
    ) {
      return {
        action: 'ignore',
        shouldMoveCamera: false,
        receiptOutcome: null,
        markAcked: true,
        markPausedNotified: false,
        commandKey,
        reason: 'already_settled_before_reload',
      };
    }
    return {
      action: 'hold_on_reload',
      shouldMoveCamera: false,
      receiptOutcome: null,
      markAcked: false,
      markPausedNotified: false,
      commandKey,
      reason: 'held_on_reload_or_target_switch',
    };
  }

  const expectedRev = event.command.expected_evidence_revision?.trim() || null;
  if (
    deliveryState === 'stale' ||
    (expectedRev && currentEvidenceRevisionId && expectedRev !== currentEvidenceRevisionId)
  ) {
    return {
      action: 'reject_stale',
      shouldMoveCamera: false,
      receiptOutcome: 'stale_revision',
      markAcked: true,
      markPausedNotified: false,
      commandKey,
      reason: 'stale_evidence_revision',
    };
  }

  if (deliveryState === 'rejected') {
    return {
      action: 'reject',
      shouldMoveCamera: false,
      receiptOutcome: 'rejected',
      markAcked: true,
      markPausedNotified: false,
      commandKey,
      reason: 'rejected_by_service',
    };
  }

  if (followState === 'paused') {
    const alreadyNotified = Boolean(pausedNotifiedCommandIds?.has(commandKey));
    return {
      action: 'queue_while_paused',
      shouldMoveCamera: false,
      receiptOutcome: alreadyNotified ? null : 'paused_by_human',
      markAcked: false,
      markPausedNotified: true,
      commandKey,
      reason: 'follow_paused_by_human',
    };
  }

  return {
    action: 'apply',
    shouldMoveCamera: true,
    receiptOutcome: 'applied',
    markAcked: true,
    markPausedNotified: false,
    commandKey,
    reason: 'applied_under_active_follow',
  };
}

export function buildSessionShareUrl(
  baseOriginAndPath: string,
  targetSlug: string,
  sessionId: string,
): string {
  const prefix = baseOriginAndPath.replace(/[#?].*$/, '');
  return `${prefix}#target=${encodeURIComponent(targetSlug)}&session=${encodeURIComponent(sessionId)}`;
}
