'use client';

import dynamic from 'next/dynamic';
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import {
  Bot,
  Boxes,
  Command,
  Copy,
  Database,
  FileCode2,
  GitBranch,
  Globe,
  Maximize2,
  Minimize2,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  atlasApi,
  type AtlasNode,
  type BlastModeChoice,
  type BoundaryFinding,
  type EndToEndChain,
  type FollowState,
  type FramingPreset,
  type InvestigationCorrectionRead,
  type InvestigationRevisionComparisonRead,
  type InvestigationSessionRead,
  type InvestigationSummaryRead,
  type TierFilterChoice,
  type UiFocusExplainRead,
  type ViewportCommand,
  type ViewportCommandEvent,
  type ViewportCommandReceiptRead,
  type ViewportGroupByChoice,
  type ViewportReceiptOutcome,
  type ViewportTabChoice,
  type ZWytheSliceChoice,
} from '@/api/atlas';
import { AccessibleIndexView } from '@/components/AccessibleIndexView';
import { AskWytheDrawer } from '@/components/AskWytheDrawer';
import { CommandPalette } from '@/components/CommandPalette';
import { GateAndRulesView } from '@/components/GateAndRulesView';
import { InvestigationSessionBar } from '@/components/InvestigationCollabControls';
import { LineageExplorer } from '@/components/LineageExplorer';
import { NodeInspector } from '@/components/NodeInspector';
import { WhatsThisModal } from '@/components/WhatsThisModal';
import { WytheAppearanceControl, WytheBrandLockup, WytheMark } from '@/components/WytheMark';
import {
  useAdapterSlots,
  useCompareSnapshots,
  useDetectStack,
  useFetchContextCone,
  useFetchLlmsBrief,
  useFetchUiFocus,
  useGovernanceBundle,
  useRegisterTarget,
  useRules,
  useScanDiff,
  useScanHistory,
  useStackProfiles,
  useSyncGovernanceBundle,
  useSyncUiFocus,
  useTargets,
  useTargetScan,
  useTriggerScan,
  useViewportState,
  useVocabularies,
  useWytheVersion,
} from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import { formatObservedInstant } from '@/lib/clock';
import {
  applyIncomingViewportEvent,
  buildViewportPermalinkHash,
  computeSmartDenseSalience,
  createInitialAgentCameraState,
  isPureDrawerRefreshCommand,
  normalizeViewportTimeline,
  parseViewportPermalinkHash,
  resumeAgentCameraFollow,
  sanitizeViewportPlainText,
  stepTimelineFrame,
  yieldAgentCameraOnHumanInput,
  type AgentCameraFollowState,
  type HumanInputInterruptKind,
} from '@/lib/wytheCameraChoreography';
import type { QuickActionDef } from '@/lib/wytheCommands';
import {
  ALL_NODE_SUBKINDS,
  deriveDomainCluster,
  SCENE_LAYOUT_LABELS,
  SCENE_LENS_LABELS,
  type DiffOverlaySet,
  type EdgeFilterMode,
  type SceneLayoutMode,
  type SceneLens,
} from '@/lib/wytheSceneLenses';
import {
  SAVED_VIEWS_STORAGE_KEY,
  addNodesToWorkingSet,
  parseSavedViews,
  reconcileSavedView,
  serializeSavedViews,
  toggleNodeInWorkingSet,
  type SavedViewReconcileResult,
  type SavedWorkingView,
} from '@/lib/wytheWorkingSet';
import { tryCopyDataUrlPngToClipboard, type LiveViewportDigest } from '@/lib/wytheVisionBridge';
import { bumpViewportCameraRevision, registerWytheWebMcpBridge } from '@/lib/wytheBrowserAi';
import {
  MIN_UI_FOCUS_DEBOUNCE_MS,
  evaluateIncomingViewportCommand,
  extractExplicitSessionIdFromUrl,
  extractExplicitTargetFromUrl,
  getOrCreateTabClientId,
  getViewportCommandKey,
  readAckedCommandIds,
  readPersistedActiveSlug,
  readPersistedFollowState,
  recordAckedCommandId,
  resolveTabInvestigationIdentity,
  rotateTabSessionId,
  switchTabSessionId,
  writePersistedActiveSlug,
  writePersistedFollowState,
} from '@/lib/wytheInvestigationSession';
import { WYTHE_PRESETS, useWytheAppearance, type AppearanceMode } from '@/lib/wytheTheme';

const StratifiedScene3D = dynamic(
  () => import('@/components/StratifiedScene3D').then((m) => m.StratifiedScene3D),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[35rem] items-center justify-center border border-slate-800 bg-slate-950 font-mono text-xs text-slate-400">
        Initializing 3D Stratified Wythe Atlas…
      </div>
    ),
  },
);

type WorkspaceTab = '3d' | 'lineage' | 'gate' | 'index';

export default function WytheWorkspacePage() {
  const { data: targets = [], isLoading: loadingTargets } = useTargets();
  const prefersReducedMotion = useReducedMotion();
  const wytheTheme = useWytheAppearance();
  const tabRefs = useRef<Record<WorkspaceTab, HTMLButtonElement | null>>({
    '3d': null,
    lineage: null,
    gate: null,
    index: null,
  });
  const [activeSlug, setActiveSlug] = useState<string>('');
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('3d');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [tierFilter, setTierFilter] = useState<'all' | 'truth' | 'manipulate' | 'display'>('all');
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [isolateCone, setIsolateCone] = useState(false);
  const [connectedOnly, setConnectedOnly] = useState(false);
  const [neighborhoodHops, setNeighborhoodHops] = useState<0 | 1 | 2>(0);
  useEffect(() => {
    if (!selectedNodeId) {
      setIsolateCone(false);
      setNeighborhoodHops(0);
      setSelectedFindingId(null);
      setSelectedEdgeId(null);
    }
  }, [selectedNodeId]);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddTarget, setShowAddTarget] = useState(false);
  const [newSlug, setNewSlug] = useState('');
  const [newName, setNewName] = useState('');
  const [newPath, setNewPath] = useState('');
  const [newProfileSlug, setNewProfileSlug] = useState('fastapi-sqlalchemy-nextjs');
  const [newBackendSubdir, setNewBackendSubdir] = useState('backend');
  const [newFrontendSubdir, setNewFrontendSubdir] = useState('frontend');
  const [detectSummary, setDetectSummary] = useState<string | null>(null);

  useEffect(() => {
    if (activeSlug || targets.length === 0) return;
    const href = typeof window !== 'undefined' ? window.location.href : '';
    const urlTarget = extractExplicitTargetFromUrl(href);
    if (urlTarget && targets.some((t) => t.slug === urlTarget)) {
      setActiveSlug(urlTarget);
      return;
    }
    const urlSid = extractExplicitSessionIdFromUrl(href);
    if (urlSid) {
      let cancelled = false;
      void atlasApi
        .getInvestigation(urlSid)
        .then((found) => {
          if (cancelled) return;
          if (found.target_slug && targets.some((t) => t.slug === found.target_slug)) {
            switchTabSessionId(found.target_slug, found.session_id);
            setActiveSlug(found.target_slug);
            return;
          }
          const fallback = targets.find((t) => t.slug === 'wythe') ?? targets[0];
          setActiveSlug(fallback.slug);
        })
        .catch(() => {
          if (cancelled) return;
          const fallback = targets.find((t) => t.slug === 'wythe') ?? targets[0];
          setActiveSlug(fallback.slug);
        });
      return () => {
        cancelled = true;
      };
    }
    const storedSlug = readPersistedActiveSlug();
    if (storedSlug && targets.some((t) => t.slug === storedSlug)) {
      setActiveSlug(storedSlug);
      return;
    }
    const preferred = targets.find((t) => t.slug === 'wythe') ?? targets[0];
    setActiveSlug(preferred.slug);
  }, [targets, activeSlug]);

  useEffect(() => {
    if (!activeSlug) return;
    writePersistedActiveSlug(activeSlug);
  }, [activeSlug]);

  const { data: report, isLoading: loadingScan, error: scanError } = useTargetScan(activeSlug);
  const { data: rules = [] } = useRules();
  const { data: vocabularies = [] } = useVocabularies();
  const { data: slots = [] } = useAdapterSlots();
  const { data: profiles = [] } = useStackProfiles();
  const { data: govBundle } = useGovernanceBundle(activeSlug);
  const { data: healthz } = useWytheVersion();
  const triggerScan = useTriggerScan(activeSlug);
  const fetchLlmsBrief = useFetchLlmsBrief(activeSlug);
  const fetchContextCone = useFetchContextCone(activeSlug);
  const syncGovBundle = useSyncGovernanceBundle(activeSlug);
  const registerTarget = useRegisterTarget();
  const detectStack = useDetectStack();
  const [copiedBriefLabel, setCopiedBriefLabel] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteInitialQuery, setPaletteInitialQuery] = useState('');
  const [isFullscreen3D, setIsFullscreen3D] = useState(false);
  const [stepRequest, setStepRequest] = useState<{ seq: number; delta: -1 | 1 } | null>(null);
  const [resetCameraRequest, setResetCameraRequest] = useState(0);
  const [quickToast, setQuickToast] = useState<string | null>(null);
  const [sceneLens, setSceneLens] = useState<SceneLens>('status');
  const [sceneLayout, setSceneLayout] = useState<SceneLayoutMode>('cluster');
  const [subkindFilter, setSubkindFilter] = useState<'all' | AtlasNode['subkind']>('all');
  const [edgeFilter, setEdgeFilter] = useState<EdgeFilterMode>('all');
  const [blastMode, setBlastMode] = useState<'off' | 'git' | 'snapshot'>('off');
  const [diffBaseRef, setDiffBaseRef] = useState('HEAD~1');
  const [snapBaseId, setSnapBaseId] = useState<number | null>(null);
  const [activeTraceChain, setActiveTraceChain] = useState<EndToEndChain | null>(null);
  const [whatsThisRequest, setWhatsThisRequest] = useState(0);
  const [whatsThisOpen, setWhatsThisOpen] = useState(false);
  const [whatsThisSnapshotUrl, setWhatsThisSnapshotUrl] = useState<string | null>(null);
  const [whatsThisExplanation, setWhatsThisExplanation] = useState<UiFocusExplainRead | null>(null);
  const [whatsThisImageCopied, setWhatsThisImageCopied] = useState(false);
  const [askDrawerOpen, setAskDrawerOpen] = useState(false);
  const [workingSetIds, setWorkingSetIds] = useState<Set<string>>(() => new Set());
  const [workingSetActive, setWorkingSetActive] = useState(false);
  const [compactVisible, setCompactVisible] = useState(false);
  const [flatten2D, setFlatten2D] = useState(false);
  const [groupBy, setGroupBy] = useState<'none' | 'cluster' | 'subkind'>('none');
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set());
  const [pinnedPositions, setPinnedPositions] = useState<Record<string, [number, number, number]>>(
    () => ({}),
  );
  const [visibleSceneNodeIds, setVisibleSceneNodeIds] = useState<string[]>([]);
  const [savedViews, setSavedViews] = useState<SavedWorkingView[]>([]);
  const [selectedSavedViewId, setSelectedSavedViewId] = useState<string>('');
  const [savedViewNotice, setSavedViewNotice] = useState<SavedViewReconcileResult | null>(null);

  useEffect(() => {
    setSavedViews(parseSavedViews(window.localStorage.getItem(SAVED_VIEWS_STORAGE_KEY)));
  }, []);

  useEffect(() => {
    setWorkingSetIds(new Set());
    setWorkingSetActive(false);
    setPinnedPositions({});
    setCollapsedGroups(new Set());
    setSavedViewNotice(null);
    setSelectedSavedViewId('');
  }, [activeSlug]);
  const [askPrefillQuestion, setAskPrefillQuestion] = useState('');
  const [liveViewportDigest, setLiveViewportDigest] = useState<LiveViewportDigest | null>(null);
  const liveCaptureFnRef = useRef<(() => string | null) | null>(null);
  const focusCaptureTargetRef = useRef<'modal' | 'drawer' | 'silent'>('modal');
  const [hoverFocusMeta, setHoverFocusMeta] = useState<{
    hoveredNodeId: string | null;
    district: string | null;
    visualHeadline: string | null;
    cameraPosition: string | null;
    cameraTarget: string | null;
    visibleNodeCount: number;
  }>({
    hoveredNodeId: null,
    district: null,
    visualHeadline: null,
    cameraPosition: null,
    cameraTarget: null,
    visibleNodeCount: 0,
  });

  const syncUiFocus = useSyncUiFocus();
  const fetchUiFocus = useFetchUiFocus();

  const { data: scanHistory = [] } = useScanHistory(activeSlug);
  const latestSnapId = scanHistory[0]?.id ?? null;
  const effectiveBaseSnapId =
    snapBaseId ?? (scanHistory.length >= 2 ? scanHistory[1].id : null);
  const shouldFetchGitDiff =
    blastMode === 'git' || (sceneLayout === 'temporal_z' && blastMode === 'off');
  const { data: gitDiffReport } = useScanDiff(
    activeSlug,
    shouldFetchGitDiff ? diffBaseRef : '',
  );
  const { data: snapCompareReport } = useCompareSnapshots(
    activeSlug,
    blastMode === 'snapshot' ? effectiveBaseSnapId : null,
    blastMode === 'snapshot' ? latestSnapId : null,
  );

  const [zWytheSlice, setZWytheSlice] = useState<ZWytheSliceChoice>('all');
  const [requestedZoomStratum, setRequestedZoomStratum] = useState<1 | 2 | 3>(1);
  // Deterministic SSR-identical initial state (prevents React #418 hydration mismatch on static export)
  const [tabClientId, setTabClientId] = useState<string>('');
  const [sessionScope, setSessionScope] = useState<{ slug: string; sessionId: string } | null>(null);
  const activeSessionId: string | null =
    sessionScope && sessionScope.slug === activeSlug ? sessionScope.sessionId : null;
  const activeSlugRef = useRef<string>(activeSlug);
  activeSlugRef.current = activeSlug;
  const activeSessionIdRef = useRef<string | null>(activeSessionId);
  activeSessionIdRef.current = activeSessionId;
  const scopeEpochRef = useRef<number>(0);
  const [scopeEpoch, setScopeEpoch] = useState<number>(0);
  const followReqSeqRef = useRef<number>(0);
  const lastSeenSeqRef = useRef<number>(0);
  const targetsRef = useRef(targets);
  targetsRef.current = targets;
  const bumpScopeEpoch = useCallback(() => {
    scopeEpochRef.current += 1;
    followReqSeqRef.current += 1;
    lastSeenSeqRef.current = 0;
    setScopeEpoch(scopeEpochRef.current);
  }, []);

  const [agentCamState, setAgentCamState] = useState<AgentCameraFollowState>(() =>
    createInitialAgentCameraState('following'),
  );
  const agentCamStateRef = useRef<AgentCameraFollowState>(agentCamState);
  agentCamStateRef.current = agentCamState;
  const followModeRef = useRef<FollowState>(agentCamState.followMode);
  useEffect(() => {
    followModeRef.current = agentCamState.followMode;
  }, [agentCamState.followMode]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    setTabClientId(getOrCreateTabClientId());
  }, []);

  const [investigationSession, setInvestigationSession] =
    useState<InvestigationSessionRead | null>(null);
  const [priorSessions, setPriorSessions] = useState<InvestigationSummaryRead[]>([]);
  const [revisionComparison, setRevisionComparison] =
    useState<InvestigationRevisionComparisonRead | null>(null);
  const [lastViewportReceipt, setLastViewportReceipt] =
    useState<ViewportCommandReceiptRead | null>(null);
  const latestFocusRevisionRef = useRef<number>(0);
  const latestEvidenceRevRef = useRef<string | null>(null);
  const ackedCommandIdsRef = useRef<Set<string>>(new Set());
  const pausedNotifiedIdsRef = useRef<Set<string>>(new Set());
  const lastFindingResolvedKeyRef = useRef<string | null>(null);

  const [agentCameraRequest, setAgentCameraRequest] = useState<{
    seq: number;
    preset: FramingPreset;
    focusNodeIds: string[];
    highlightEdgeIds: string[];
    caption: string;
  } | null>(null);
  const [coldPermalinkActive, setColdPermalinkActive] = useState<boolean>(false);
  const coldPermalinkAppliedRef = useRef<boolean>(false);

  const setScopedSessionId = useCallback(
    (slug: string, sid: string | null) => {
      const prevSid = activeSessionIdRef.current;
      const prevSlug = activeSlugRef.current;
      if (!slug || !sid) {
        if (prevSid !== null) {
          bumpScopeEpoch();
        }
        activeSessionIdRef.current = null;
        setSessionScope(null);
        return;
      }
      if (prevSlug !== slug || prevSid !== sid) {
        bumpScopeEpoch();
        latestFocusRevisionRef.current = 0;
        latestEvidenceRevRef.current = null;
      }
      activeSlugRef.current = slug;
      activeSessionIdRef.current = sid;
      setSessionScope({ slug, sessionId: sid });
    },
    [bumpScopeEpoch],
  );

  const switchTargetCleanly = useCallback(
    (nextSlug: string) => {
      const cleanedSlug = nextSlug.trim();
      if (!cleanedSlug) return;
      const currentHref = typeof window !== 'undefined' ? window.location.href : '';
      if (
        cleanedSlug === activeSlugRef.current &&
        !extractExplicitSessionIdFromUrl(currentHref)
      ) {
        return;
      }
      if (typeof window !== 'undefined' && window.location.hash) {
        window.history.replaceState(null, '', window.location.pathname + window.location.search);
      }
      bumpScopeEpoch();
      latestFocusRevisionRef.current = 0;
      latestEvidenceRevRef.current = null;
      coldPermalinkAppliedRef.current = false;
      setColdPermalinkActive(false);
      setRevisionComparison(null);
      setInvestigationSession(null);
      setPriorSessions([]);
      setLastViewportReceipt(null);
      setSelectedNodeId(null);
      setSelectedFindingId(null);
      setSelectedEdgeId(null);
      setTierFilter('all');
      setSubkindFilter('all');
      setEdgeFilter('all');
      setOnlyFlagged(false);
      setIsolateCone(false);
      setConnectedOnly(false);
      setNeighborhoodHops(0);
      setSearchQuery('');
      setBlastMode('off');
      setWorkingSetIds(new Set());
      setWorkingSetActive(false);
      setCompactVisible(false);
      setCollapsedGroups(new Set());
      setPinnedPositions({});
      setActiveTraceChain(null);
      setZWytheSlice('all');
      setRequestedZoomStratum(1);
      setAgentCameraRequest(null);
      setWhatsThisSnapshotUrl(null);
      setWhatsThisExplanation(null);
      setLiveViewportDigest(null);
      setSnapBaseId(null);
      const identity = resolveTabInvestigationIdentity({
        targetSlug: cleanedSlug,
        locationHref: '',
      });
      const savedFollow = readPersistedFollowState(identity.sessionId);
      followModeRef.current = savedFollow;
      const nextCamState: AgentCameraFollowState = {
        ...agentCamStateRef.current,
        followMode: savedFollow,
        liveFollowing: savedFollow === 'following',
        isPlaying: savedFollow === 'paused' ? false : agentCamStateRef.current.isPlaying,
        activeEvent: null,
        pendingEventWhilePaused: null,
      };
      agentCamStateRef.current = nextCamState;
      setAgentCamState(nextCamState);
      writePersistedActiveSlug(cleanedSlug);
      activeSlugRef.current = cleanedSlug;
      activeSessionIdRef.current = identity.sessionId;
      setActiveSlug(cleanedSlug);
      setSessionScope({ slug: cleanedSlug, sessionId: identity.sessionId });
      ackedCommandIdsRef.current = new Set(readAckedCommandIds(cleanedSlug, identity.sessionId));
      pausedNotifiedIdsRef.current.clear();
    },
    [bumpScopeEpoch],
  );

  // Resolve per-tab `session_id` (or adopt `#session=` / `?session=` explicit shared ID)
  useEffect(() => {
    if (typeof window === 'undefined' || !activeSlug) return;
    if (sessionScope && sessionScope.slug === activeSlug && sessionScope.sessionId) {
      return;
    }
    const identity = resolveTabInvestigationIdentity({
      targetSlug: activeSlug,
      locationHref: window.location.href,
    });
    bumpScopeEpoch();
    latestFocusRevisionRef.current = 0;
    latestEvidenceRevRef.current = null;
    activeSlugRef.current = activeSlug;
    activeSessionIdRef.current = identity.sessionId;
    setSessionScope({ slug: activeSlug, sessionId: identity.sessionId });
    const savedFollow = readPersistedFollowState(identity.sessionId);
    followModeRef.current = savedFollow;
    if (agentCamStateRef.current.followMode !== savedFollow) {
      const nextCamState: AgentCameraFollowState = {
        ...agentCamStateRef.current,
        followMode: savedFollow,
        liveFollowing: savedFollow === 'following',
        isPlaying: savedFollow === 'paused' ? false : agentCamStateRef.current.isPlaying,
      };
      agentCamStateRef.current = nextCamState;
      setAgentCamState(nextCamState);
    }
    ackedCommandIdsRef.current = new Set(
      readAckedCommandIds(activeSlug, identity.sessionId),
    );
    pausedNotifiedIdsRef.current.clear();
  }, [activeSlug, sessionScope, bumpScopeEpoch]);

  const refreshInvestigationState = useCallback(
    async (sidOverride?: string | null) => {
      const sid = sidOverride ?? activeSessionId;
      if (!activeSlug || !sid || !tabClientId) return null;
      const slugAtStart = activeSlug;
      const epochAtStart = scopeEpochRef.current;
      const followSeqAtStart = followReqSeqRef.current;
      const isStaleScope = () =>
        scopeEpochRef.current !== epochAtStart ||
        activeSlugRef.current !== slugAtStart ||
        activeSessionIdRef.current !== sid;
      try {
        const listRes = await atlasApi.listInvestigations(slugAtStart).catch(() => null);
        if (isStaleScope()) return null;
        if (listRes?.sessions) setPriorSessions(listRes.sessions);
        let sess = await atlasApi.getInvestigation(sid).catch(() => null);
        if (isStaleScope()) return null;
        if (sess && sess.target_slug && sess.target_slug !== slugAtStart) {
          const urlSid =
            typeof window !== 'undefined'
              ? extractExplicitSessionIdFromUrl(window.location.href)
              : null;
          if (urlSid === sid) {
            switchTabSessionId(sess.target_slug, sess.session_id);
            bumpScopeEpoch();
            activeSlugRef.current = sess.target_slug;
            activeSessionIdRef.current = sess.session_id;
            setActiveSlug(sess.target_slug);
            setSessionScope({ slug: sess.target_slug, sessionId: sess.session_id });
            return sess;
          }
          const rotated = rotateTabSessionId(slugAtStart);
          bumpScopeEpoch();
          activeSessionIdRef.current = rotated;
          setSessionScope({ slug: slugAtStart, sessionId: rotated });
          return null;
        }
        if (!sess) {
          sess = await atlasApi.createOrReopenInvestigation({
            target_slug: slugAtStart,
            session_id: sid,
            client_id: tabClientId,
          });
        }
        if (
          !sess ||
          isStaleScope() ||
          sess.session_id !== sid ||
          (sess.target_slug && sess.target_slug !== slugAtStart)
        ) {
          return null;
        }
        const humanChangedFollowInFlight = followReqSeqRef.current !== followSeqAtStart;
        const storedLocalFollow = readPersistedFollowState(sid);
        const mergedFollow: FollowState = humanChangedFollowInFlight
          ? followModeRef.current
          : sess.follow_state === 'paused' || storedLocalFollow === 'paused'
            ? 'paused'
            : 'following';
        const effectiveSess: InvestigationSessionRead = humanChangedFollowInFlight
          ? { ...sess, follow_state: mergedFollow }
          : sess;
        setInvestigationSession(effectiveSess);
        latestFocusRevisionRef.current = Math.max(
          latestFocusRevisionRef.current,
          effectiveSess.focus_revision ?? 0,
        );
        latestEvidenceRevRef.current =
          effectiveSess.latest_evidence?.evidence_revision_id ?? latestEvidenceRevRef.current;
        if (!humanChangedFollowInFlight) {
          writePersistedFollowState(sid, mergedFollow);
          followModeRef.current = mergedFollow;
          setAgentCamState((prev) =>
            prev.followMode === mergedFollow
              ? prev
              : {
                  ...prev,
                  followMode: mergedFollow,
                  liveFollowing: mergedFollow === 'following',
                  isPlaying: mergedFollow === 'paused' ? false : prev.isPlaying,
                },
          );
        }
        if (!coldPermalinkAppliedRef.current) {
          if (effectiveSess.focus?.selected_node_id) {
            setSelectedNodeId((cur) => cur ?? effectiveSess.focus.selected_node_id ?? null);
          }
          if (effectiveSess.focus?.selected_finding_id) {
            setSelectedFindingId((cur) => cur ?? effectiveSess.focus.selected_finding_id ?? null);
          }
          if (effectiveSess.focus?.selected_edge_id) {
            setSelectedEdgeId((cur) => cur ?? effectiveSess.focus.selected_edge_id ?? null);
          }
        }
        if (effectiveSess.evidence_drifted) {
          void atlasApi
            .compareInvestigationRevisions(sid)
            .then((comp) => {
              if (!isStaleScope()) {
                setRevisionComparison(comp);
              }
            })
            .catch(() => {});
        }
        return effectiveSess;
      } catch {
        return null;
      }
    },
    [activeSlug, activeSessionId, tabClientId, bumpScopeEpoch],
  );

  useEffect(() => {
    if (!activeSlug || !activeSessionId || !tabClientId) return;
    void refreshInvestigationState(activeSessionId);
  }, [activeSlug, activeSessionId, tabClientId, scopeEpoch, refreshInvestigationState]);

  const { data: initialViewportState, isFetched: viewportStateFetched } = useViewportState(
    activeSlug,
    Boolean(activeSlug && activeSessionId),
    activeSessionId,
    {
      clientId: tabClientId,
      selectedEdgeId,
      selectedFindingId,
      followState: agentCamState.followMode,
    },
  );

  const workspaceViewRef = useRef({
    selectedNodeId,
    selectedEdgeId,
    selectedFindingId,
    sceneLens,
    sceneLayout,
    tierFilter,
    subkindFilter,
    edgeFilter,
    onlyFlagged,
    isolateCone,
    connectedOnly,
    neighborhoodHops,
    searchQuery,
    blastMode,
    diffBaseRef,
    workingSetActive,
    compactVisible,
    flatten2D,
    groupBy,
    activeTab,
    zWytheSlice,
    requestedZoomStratum,
    framingPreset: 'iso_overview' as FramingPreset,
    focusNodeIds: [] as string[],
    highlightEdgeIds: [] as string[],
  });

  const applyBeatToWorkspace = useCallback(
    (beat: {
      focusNodeIds: string[];
      highlightEdgeIds: string[];
      selectedNodeId?: string | null;
      selectedEdgeId?: string | null;
      findingId?: string | null;
      lens?: SceneLens | null;
      layoutMode?: SceneLayoutMode | null;
      tierFilter?: TierFilterChoice | null;
      subkindFilter?: string | null;
      edgeFilter?: string | null;
      onlyFlagged?: boolean | null;
      isolateCone?: boolean | null;
      connectedOnly?: boolean | null;
      neighborhoodHops?: 0 | 1 | 2 | null;
      searchQuery?: string | null;
      blastMode?: BlastModeChoice | null;
      diffBaseRef?: string | null;
      workingSetOnly?: boolean | null;
      compactVisible?: boolean | null;
      flatten2d?: boolean | null;
      groupBy?: ViewportGroupByChoice | null;
      activeTab?: ViewportTabChoice | null;
      openDrawer?: boolean | null;
      resetFilters?: boolean;
      isTimelineStep?: boolean;
      zWytheSlice?: ZWytheSliceChoice | null;
      zoomStratum?: 1 | 2 | 3;
      framingPreset: FramingPreset;
      caption: string;
      targetSlug?: string;
      chronicleTimeline?: ViewportCommand['chronicle_timeline'];
    }) => {
      if (beat.resetFilters) {
        setTierFilter('all');
        setSubkindFilter('all');
        setEdgeFilter('all');
        setOnlyFlagged(false);
        setIsolateCone(false);
        setConnectedOnly(false);
        setNeighborhoodHops(0);
        setSearchQuery('');
        setBlastMode('off');
        setWorkingSetActive(false);
        setCompactVisible(false);
        setFlatten2D(false);
        setGroupBy('none');
        setCollapsedGroups(new Set());
        if (!beat.zWytheSlice) setZWytheSlice('all');
      }

      if (beat.lens) setSceneLens(beat.lens);
      if (beat.layoutMode) setSceneLayout(beat.layoutMode);
      if (beat.zWytheSlice) setZWytheSlice(beat.zWytheSlice);
      else if (beat.isTimelineStep) setZWytheSlice('all');

      if (beat.tierFilter != null) setTierFilter(beat.tierFilter);
      if (beat.subkindFilter != null) {
        setSubkindFilter(beat.subkindFilter as 'all' | AtlasNode['subkind']);
      }
      if (beat.edgeFilter != null) setEdgeFilter(beat.edgeFilter as EdgeFilterMode);
      if (beat.onlyFlagged != null) setOnlyFlagged(beat.onlyFlagged);
      if (beat.isolateCone != null) setIsolateCone(beat.isolateCone);
      if (beat.connectedOnly != null) setConnectedOnly(beat.connectedOnly);
      if (beat.neighborhoodHops != null) setNeighborhoodHops(beat.neighborhoodHops);
      if (beat.searchQuery != null) setSearchQuery(beat.searchQuery);
      if (beat.blastMode != null) setBlastMode(beat.blastMode);
      if (beat.diffBaseRef != null) setDiffBaseRef(beat.diffBaseRef);
      if (beat.compactVisible != null) setCompactVisible(beat.compactVisible);
      if (beat.flatten2d != null) setFlatten2D(beat.flatten2d);
      if (beat.groupBy != null) setGroupBy(beat.groupBy);

      if (beat.activeTab != null) {
        if (beat.activeTab === 'governance' || beat.activeTab === 'gate') {
          setActiveTab('gate');
        } else if (beat.activeTab === 'understanding') {
          setActiveTab('3d');
          setAskDrawerOpen(true);
        } else {
          setActiveTab(beat.activeTab);
        }
      }
      if (beat.openDrawer === true) setAskDrawerOpen(true);
      else if (beat.openDrawer === false) setAskDrawerOpen(false);

      let resolvedFocus = [...beat.focusNodeIds];
      if (resolvedFocus.length === 0 && beat.selectedNodeId) {
        resolvedFocus = [beat.selectedNodeId];
      }
      let resolvedFindingId = beat.findingId ?? null;
      if (beat.findingId && report?.findings) {
        const hitFinding = report.findings.find(
          (f) => f.id === beat.findingId || f.rule_code.toLowerCase() === beat.findingId!.toLowerCase(),
        );
        resolvedFindingId = hitFinding?.id ?? beat.findingId;
        setSelectedFindingId(resolvedFindingId);
        if (resolvedFocus.length === 0 && hitFinding?.node_id) {
          resolvedFocus = [hitFinding.node_id];
        }
      } else if (beat.findingId) {
        setSelectedFindingId(beat.findingId);
      }
      if (beat.selectedEdgeId != null) {
        setSelectedEdgeId(beat.selectedEdgeId || null);
      }

      const isFilterOnlyMove =
        resolvedFocus.length === 0 &&
        beat.highlightEdgeIds.length === 0 &&
        !beat.resetFilters &&
        !beat.isTimelineStep &&
        !beat.chronicleTimeline &&
        beat.framingPreset === 'iso_overview' &&
        !beat.zWytheSlice &&
        (beat.zoomStratum == null || beat.zoomStratum === 1);

      if (beat.zoomStratum != null && (!isFilterOnlyMove || beat.zoomStratum !== 1)) {
        setRequestedZoomStratum(beat.zoomStratum);
      }

      if (beat.workingSetOnly === true) {
        if (resolvedFocus.length > 0) {
          const wsSet = new Set(resolvedFocus);
          if (beat.highlightEdgeIds.length > 0 && report?.edges) {
            const wantedEdges = new Set(beat.highlightEdgeIds);
            for (const edge of report.edges) {
              if (wantedEdges.has(edge.id)) {
                wsSet.add(edge.source_id);
                wsSet.add(edge.target_id);
              }
            }
          }
          setWorkingSetIds(wsSet);
        }
        setWorkingSetActive(true);
      } else if (beat.workingSetOnly === false) {
        setWorkingSetActive(false);
      }

      const salience = computeSmartDenseSalience({
        totalNodeCount: report?.nodes.length ?? 0,
        resolvedFocus,
        highlightEdgeIds: beat.highlightEdgeIds,
        allEdges: report?.edges ?? [],
        selectedNodeId: beat.selectedNodeId ?? null,
        isolateCone: beat.isolateCone ?? null,
        neighborhoodHops: beat.neighborhoodHops ?? null,
        workingSetOnly: beat.workingSetOnly ?? null,
        onlyFlagged: beat.onlyFlagged ?? null,
        tierFilter: beat.tierFilter ?? null,
        subkindFilter: beat.subkindFilter ?? null,
        searchQuery: beat.searchQuery ?? null,
        resetFilters: beat.resetFilters,
      });

      if (salience.mode === 'auto_isolate_cone') {
        setSelectedNodeId(salience.selectedNodeId);
        setIsolateCone(true);
        setNeighborhoodHops(0);
        setWorkingSetActive(false);
        setCompactVisible(false);
      } else if (salience.mode === 'auto_working_set_compact') {
        setSelectedNodeId(salience.selectedNodeId);
        setWorkingSetIds(new Set(salience.workingSetIds ?? resolvedFocus));
        setWorkingSetActive(true);
        setCompactVisible(true);
        setIsolateCone(false);
        setNeighborhoodHops(0);
      } else if (beat.selectedNodeId) {
        setSelectedNodeId(beat.selectedNodeId);
      } else if (resolvedFocus.length > 0) {
        setSelectedNodeId(resolvedFocus[0]);
      } else if (beat.resetFilters && !beat.selectedEdgeId && !beat.findingId) {
        setSelectedNodeId(null);
      }

      if (typeof window !== 'undefined') {
        const curView = workspaceViewRef.current;
        const effectiveIsolateCone =
          salience.mode === 'auto_isolate_cone'
            ? true
            : salience.mode === 'auto_working_set_compact'
              ? false
              : beat.isolateCone ?? (beat.resetFilters ? undefined : curView.isolateCone ? true : undefined);
        const effectiveWorkingSet =
          salience.mode === 'auto_working_set_compact'
            ? true
            : salience.mode === 'auto_isolate_cone'
              ? false
              : beat.workingSetOnly ??
                (beat.resetFilters ? undefined : curView.workingSetActive ? true : undefined);
        const effectiveCompact =
          salience.mode === 'auto_working_set_compact'
            ? true
            : salience.mode === 'auto_isolate_cone'
              ? false
              : beat.compactVisible ??
                (beat.resetFilters ? undefined : curView.compactVisible ? true : undefined);
        const effBlastMode =
          beat.blastMode ?? (beat.resetFilters ? 'off' : curView.blastMode);
        const effFocus =
          resolvedFocus.length > 0
            ? resolvedFocus
            : beat.resetFilters
              ? []
              : curView.focusNodeIds.length > 0
                ? curView.focusNodeIds
                : curView.selectedNodeId
                  ? [curView.selectedNodeId]
                  : [];
        const effEdges =
          beat.highlightEdgeIds.length > 0
            ? beat.highlightEdgeIds
            : beat.resetFilters
              ? []
              : curView.highlightEdgeIds;
        const effSelectedNode =
          beat.selectedNodeId ??
          (resolvedFocus.length > 0
            ? resolvedFocus[0]
            : beat.resetFilters
              ? undefined
              : curView.selectedNodeId ?? undefined);
        const effSelectedEdge =
          beat.selectedEdgeId !== undefined
            ? beat.selectedEdgeId || undefined
            : beat.resetFilters
              ? undefined
              : curView.selectedEdgeId ?? undefined;
        const effFinding = beat.findingId
          ? resolvedFindingId ?? undefined
          : beat.resetFilters
            ? undefined
            : curView.selectedFindingId ?? undefined;
        const effSearch =
          beat.searchQuery != null
            ? beat.searchQuery || undefined
            : beat.resetFilters
              ? undefined
              : curView.searchQuery || undefined;

        const hash = buildViewportPermalinkHash({
          target_slug: beat.targetSlug || activeSlugRef.current || activeSlug,
          session_id: activeSessionIdRef.current ?? activeSessionId ?? undefined,
          focus_node_ids: effFocus,
          highlight_edge_ids: effEdges,
          selected_node_id: effSelectedNode,
          selected_edge_id: effSelectedEdge,
          finding_id: effFinding,
          lens: beat.lens ?? curView.sceneLens,
          layout_mode: beat.layoutMode ?? curView.sceneLayout,
          tier_filter:
            beat.tierFilter ??
            (beat.resetFilters ? undefined : curView.tierFilter !== 'all' ? curView.tierFilter : undefined),
          subkind_filter:
            beat.subkindFilter ??
            (beat.resetFilters ? undefined : curView.subkindFilter !== 'all' ? curView.subkindFilter : undefined),
          edge_filter:
            beat.edgeFilter ??
            (beat.resetFilters ? undefined : curView.edgeFilter !== 'all' ? curView.edgeFilter : undefined),
          only_flagged:
            beat.onlyFlagged ?? (beat.resetFilters ? undefined : curView.onlyFlagged ? true : undefined),
          isolate_cone: effectiveIsolateCone,
          connected_only:
            beat.connectedOnly ?? (beat.resetFilters ? undefined : curView.connectedOnly ? true : undefined),
          neighborhood_hops:
            beat.neighborhoodHops ??
            (beat.resetFilters ? undefined : curView.neighborhoodHops > 0 ? curView.neighborhoodHops : undefined),
          search_query: effSearch,
          blast_mode: effBlastMode !== 'off' ? effBlastMode : undefined,
          diff_base_ref:
            effBlastMode === 'git' ? beat.diffBaseRef ?? curView.diffBaseRef : undefined,
          working_set_only: effectiveWorkingSet,
          compact_visible: effectiveCompact,
          flatten_2d:
            beat.flatten2d ?? (beat.resetFilters ? undefined : curView.flatten2D ? true : undefined),
          group_by:
            beat.groupBy ??
            (beat.resetFilters ? undefined : curView.groupBy !== 'none' ? curView.groupBy : undefined),
          active_tab:
            beat.activeTab ?? (curView.activeTab !== '3d' ? curView.activeTab : undefined),
          framing_preset: isFilterOnlyMove ? curView.framingPreset : beat.framingPreset,
          z_wythe_slice:
            beat.zWytheSlice ??
            (beat.resetFilters || beat.isTimelineStep
              ? undefined
              : curView.zWytheSlice !== 'all'
                ? curView.zWytheSlice
                : undefined),
          zoom_stratum: isFilterOnlyMove
            ? curView.requestedZoomStratum
            : beat.zoomStratum ?? (beat.resetFilters ? 1 : curView.requestedZoomStratum),
          chronicle_timeline: beat.chronicleTimeline ?? undefined,
        });
        if (hash.length > 1) {
          window.history.replaceState(null, '', hash);
        }
      }

      if (!isFilterOnlyMove) {
        setAgentCameraRequest((prev) => ({
          seq: (prev?.seq ?? 0) + 1,
          preset: beat.framingPreset,
          focusNodeIds: resolvedFocus,
          highlightEdgeIds: beat.highlightEdgeIds,
          caption: sanitizeViewportPlainText(beat.caption),
        }));
      }
    },
    [activeSlug, activeSessionId, report?.nodes.length, report?.edges, report?.findings],
  );

  const applyCommandOrFirstStep = useCallback(
    (cmd: ViewportCommand) => {
      if (isPureDrawerRefreshCommand(cmd)) {
        if (cmd.open_drawer === true) setAskDrawerOpen(true);
        return;
      }
      const items = normalizeViewportTimeline(cmd);
      if (items.length > 0) {
        const desiredIdx = cmd.chronicle_timeline
          ? Math.max(
              0,
              Math.min(items.length - 1, Math.trunc(cmd.chronicle_timeline.active_phase_index ?? 0)),
            )
          : 0;
        const selected = items[desiredIdx];
        applyBeatToWorkspace({
          targetSlug: cmd.target_slug,
          focusNodeIds: selected.focusNodeIds,
          highlightEdgeIds: selected.highlightEdgeIds,
          selectedNodeId: selected.selectedNodeId,
          selectedEdgeId: selected.selectedEdgeId,
          findingId: selected.findingId,
          lens: selected.lens,
          layoutMode: selected.layoutMode,
          tierFilter: selected.tierFilter,
          subkindFilter: selected.subkindFilter,
          edgeFilter: selected.edgeFilter,
          onlyFlagged: selected.onlyFlagged,
          isolateCone: selected.isolateCone,
          connectedOnly: selected.connectedOnly,
          neighborhoodHops: selected.neighborhoodHops,
          searchQuery: selected.searchQuery,
          blastMode: selected.blastMode,
          diffBaseRef: selected.diffBaseRef,
          workingSetOnly: selected.workingSetOnly,
          compactVisible: selected.compactVisible,
          flatten2d: selected.flatten2d,
          groupBy: selected.groupBy,
          activeTab: selected.activeTab,
          openDrawer: selected.openDrawer,
          resetFilters: selected.resetFilters,
          isTimelineStep: true,
          zWytheSlice: selected.zWytheSlice,
          zoomStratum: selected.zoomStratum,
          framingPreset: selected.framingPreset,
          caption: selected.caption,
          chronicleTimeline: cmd.chronicle_timeline
            ? { ...cmd.chronicle_timeline, active_phase_index: desiredIdx }
            : null,
        });
        return;
      }
      applyBeatToWorkspace({
        targetSlug: cmd.target_slug,
        focusNodeIds: cmd.focus_node_ids ?? [],
        highlightEdgeIds: cmd.highlight_edge_ids ?? [],
        selectedNodeId: cmd.selected_node_id ?? null,
        selectedEdgeId: cmd.selected_edge_id ?? null,
        findingId: cmd.finding_id,
        lens: (cmd.lens ?? null) as SceneLens | null,
        layoutMode: (cmd.layout_mode ?? null) as SceneLayoutMode | null,
        tierFilter: cmd.tier_filter ?? null,
        subkindFilter: cmd.subkind_filter ?? null,
        edgeFilter: cmd.edge_filter ?? null,
        onlyFlagged: cmd.only_flagged ?? null,
        isolateCone: cmd.isolate_cone ?? null,
        connectedOnly: cmd.connected_only ?? null,
        neighborhoodHops: cmd.neighborhood_hops ?? null,
        searchQuery: cmd.search_query ?? null,
        blastMode: cmd.blast_mode ?? null,
        diffBaseRef: cmd.diff_base_ref ?? null,
        workingSetOnly: cmd.working_set_only ?? null,
        compactVisible: cmd.compact_visible ?? null,
        flatten2d: cmd.flatten_2d ?? null,
        groupBy: cmd.group_by ?? null,
        activeTab: cmd.active_tab ?? null,
        openDrawer: cmd.open_drawer ?? null,
        resetFilters: Boolean(cmd.reset_filters),
        isTimelineStep: false,
        zWytheSlice: cmd.z_wythe_slice ?? null,
        zoomStratum: cmd.zoom_stratum ?? 1,
        framingPreset: cmd.framing_preset ?? 'iso_overview',
        caption: cmd.caption,
        chronicleTimeline: cmd.chronicle_timeline ?? null,
      });
    },
    [applyBeatToWorkspace],
  );

  const sendViewportReceipt = useCallback(
    (
      event: ViewportCommandEvent,
      outcome: ViewportReceiptOutcome,
      note = '',
    ) => {
      const cmdId = event.command.command_id?.trim() || `seq_${event.seq}`;
      const slug = event.command.target_slug || activeSlug;
      const sidAtReceipt = activeSessionId ?? event.command.session_id ?? undefined;
      if (!slug || !tabClientId) return;
      void atlasApi
        .postViewportReceipt({
          command_id: cmdId,
          seq: event.seq > 0 ? event.seq : undefined,
          target_slug: slug,
          session_id: sidAtReceipt,
          client_id: tabClientId,
          outcome,
          applied_focus_revision: latestFocusRevisionRef.current,
          note,
        })
        .then((receipt) => {
          if (
            activeSlugRef.current === slug &&
            (!sidAtReceipt || activeSessionIdRef.current === sidAtReceipt)
          ) {
            setLastViewportReceipt(receipt);
          }
        })
        .catch(() => {});
    },
    [activeSlug, activeSessionId, tabClientId],
  );

  const setScopedSessionIdRef = useRef(setScopedSessionId);
  setScopedSessionIdRef.current = setScopedSessionId;
  const applyCommandOrFirstStepRef = useRef(applyCommandOrFirstStep);
  applyCommandOrFirstStepRef.current = applyCommandOrFirstStep;
  const refreshInvestigationStateRef = useRef(refreshInvestigationState);
  refreshInvestigationStateRef.current = refreshInvestigationState;
  const sendViewportReceiptRef = useRef(sendViewportReceipt);
  sendViewportReceiptRef.current = sendViewportReceipt;
  const reportContentDigestRef = useRef<string | undefined>(report?.content_digest);
  reportContentDigestRef.current = report?.content_digest;

  // Hydrate cold `#focus=...` / `#session=...` / `#chronicle=...&phase=...` URL permalinks on load and hashchange
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const hydrateFromHash = () => {
      const currentTargets = targetsRef.current;
      const currentSlug = activeSlugRef.current;
      let currentSid = activeSessionIdRef.current;
      const explicitSid = extractExplicitSessionIdFromUrl(window.location.href);
      const urlTarget = extractExplicitTargetFromUrl(window.location.href);
      if (explicitSid && explicitSid !== currentSid) {
        const effSlug = urlTarget || currentSlug;
        if (effSlug && (!urlTarget || urlTarget === effSlug)) {
          const cleanSid = switchTabSessionId(effSlug, explicitSid);
          setScopedSessionIdRef.current(effSlug, cleanSid);
          currentSid = cleanSid;
        }
      }
      const parsed = parseViewportPermalinkHash(window.location.hash, currentSlug || 'wythe');
      if (!parsed) return;
      coldPermalinkAppliedRef.current = true;
      setColdPermalinkActive(true);
      const hasMatchedTarget = Boolean(
        parsed.target_slug && currentTargets.some((t) => t.slug === parsed.target_slug),
      );
      const destSlug = hasMatchedTarget ? parsed.target_slug : currentSlug || 'wythe';
      if (hasMatchedTarget && parsed.target_slug) {
        activeSlugRef.current = parsed.target_slug;
        setActiveSlug(parsed.target_slug);
      }
      if (parsed.session_id) {
        const cleanSid = switchTabSessionId(destSlug, parsed.session_id);
        setScopedSessionIdRef.current(destSlug, cleanSid);
        currentSid = cleanSid;
      }
      const syntheticEvent: ViewportCommandEvent = {
        seq: 0,
        issued_at: 'permalink',
        permalink: window.location.hash,
        command: parsed,
      };
      const savedFollow = readPersistedFollowState(currentSid);
      const nextCamState: AgentCameraFollowState = {
        ...agentCamStateRef.current,
        followMode: savedFollow,
        liveFollowing: savedFollow === 'following',
        haltedReason: null,
        chronicleTimelineId: parsed.chronicle_timeline?.timeline_id ?? null,
        activeEvent: savedFollow === 'following' ? syntheticEvent : agentCamStateRef.current.activeEvent,
        pendingEventWhilePaused: savedFollow === 'paused' ? syntheticEvent : null,
        timelineMode: parsed.chronicle_timeline ? 'chronicle' : 'none',
        stepIndex: parsed.chronicle_timeline?.active_phase_index ?? 0,
      };
      followModeRef.current = savedFollow;
      agentCamStateRef.current = nextCamState;
      setAgentCamState(nextCamState);
      if (savedFollow === 'following') {
        applyCommandOrFirstStepRef.current(parsed);
      } else {
        coldPermalinkAppliedRef.current = false;
        setColdPermalinkActive(false);
      }
    };
    hydrateFromHash();
    window.addEventListener('hashchange', hydrateFromHash);
    return () => window.removeEventListener('hashchange', hydrateFromHash);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targets.length]);

  // Hydrate initial `/viewport/state` WITHOUT unexpectedly seizing camera on reload, reconnect, or target switch
  useEffect(() => {
    const latest = initialViewportState?.latest ?? null;
    if (!latest || !activeSlug) return;
    if (coldPermalinkAppliedRef.current) {
      const coldTl = agentCamState.activeEvent?.command.chronicle_timeline;
      const latestTl = latest.command.chronicle_timeline;
      const coldFrames = coldTl?.frames ?? [];
      const latestFrames = latestTl?.frames ?? [];
      if (
        coldTl &&
        coldFrames.length === 0 &&
        latestTl &&
        latestTl.timeline_id === coldTl.timeline_id &&
        latestFrames.length > 0
      ) {
        const mergedPhase = Math.max(
          0,
          Math.min(latestFrames.length - 1, coldTl.active_phase_index ?? 0),
        );
        const mergedCmd: ViewportCommand = {
          ...latest.command,
          chronicle_timeline: { ...latestTl, active_phase_index: mergedPhase },
        };
        const nextCamState: AgentCameraFollowState = {
          ...agentCamStateRef.current,
          activeEvent: { ...latest, command: mergedCmd },
          timelineMode: 'chronicle',
          stepIndex: mergedPhase,
          haltedReason: sanitizeViewportPlainText(latestTl.halted_reason, 240) || null,
          liveFollowing: !latestTl.halted_reason && latestTl.live_following !== false,
          followMode:
            latestTl.halted_reason || latestTl.live_following === false
              ? 'paused'
              : agentCamStateRef.current.followMode,
        };
        agentCamStateRef.current = nextCamState;
        setAgentCamState(nextCamState);
        applyCommandOrFirstStep(mergedCmd);
      }
      return;
    }

    const decision = evaluateIncomingViewportCommand({
      event: latest,
      source: 'initial_state',
      activeTargetSlug: activeSlug,
      activeSessionId,
      clientId: tabClientId,
      followState: followModeRef.current,
      currentEvidenceRevisionId: latestEvidenceRevRef.current,
      ackedCommandIds: ackedCommandIdsRef.current,
    });
    if (decision.markAcked) {
      const updated = recordAckedCommandId(activeSlug, activeSessionId, decision.commandKey);
      ackedCommandIdsRef.current = new Set(updated);
    }
    if (decision.action === 'hold_on_reload') {
      const nextCamState: AgentCameraFollowState = {
        ...agentCamStateRef.current,
        pendingEventWhilePaused: latest,
      };
      agentCamStateRef.current = nextCamState;
      setAgentCamState(nextCamState);
    }
  }, [
    initialViewportState,
    activeSlug,
    activeSessionId,
    tabClientId,
    applyCommandOrFirstStep,
    agentCamState.activeEvent?.command.chronicle_timeline,
  ]);

  // Re-resolve `findingId -> node_id` once scan `report` finishes loading after cold permalink / early SSE
  useEffect(() => {
    const activeEvent = agentCamState.activeEvent;
    const activeCmd = activeEvent?.command;
    if (!activeEvent || !activeCmd || !report?.findings?.length || agentCamState.followMode !== 'following') {
      return;
    }
    const eventKey = `${activeEvent.seq}:${activeCmd.command_id ?? ''}:${activeCmd.finding_id ?? ''}`;
    if (lastFindingResolvedKeyRef.current === eventKey) {
      return;
    }
    const beatFinding = activeCmd.finding_id;
    const hasFocus = (activeCmd.focus_node_ids ?? []).length > 0;
    if (!hasFocus && beatFinding) {
      const hitFinding = report.findings.find(
        (f) => f.id === beatFinding || f.rule_code.toLowerCase() === beatFinding.toLowerCase(),
      );
      lastFindingResolvedKeyRef.current = eventKey;
      if (hitFinding?.node_id) {
        setSelectedNodeId(hitFinding.node_id);
        setSelectedFindingId(hitFinding.id);
        setAgentCameraRequest((prev) => ({
          seq: (prev?.seq ?? 0) + 1,
          preset: activeCmd.framing_preset ?? 'iso_overview',
          focusNodeIds: [hitFinding.node_id!],
          highlightEdgeIds: activeCmd.highlight_edge_ids ?? [],
          caption: sanitizeViewportPlainText(activeCmd.caption),
        }));
      }
    }
  }, [report?.findings, agentCamState.activeEvent, agentCamState.followMode]);

  // Re-apply Smart Dense-Graph Salience if a cold permalink hydrated before `report.nodes` finished loading
  useEffect(() => {
    const activeEvent = agentCamState.activeEvent;
    const activeCmd = activeEvent?.command;
    const totalNodes = report?.nodes.length ?? 0;
    if (
      !coldPermalinkActive ||
      activeEvent?.issued_at !== 'permalink' ||
      !activeCmd ||
      totalNodes <= 120 ||
      agentCamState.followMode !== 'following'
    ) {
      return;
    }
    const resolvedFocus = [...(activeCmd.focus_node_ids ?? [])];
    if (resolvedFocus.length === 0 && activeCmd.selected_node_id) {
      resolvedFocus.push(activeCmd.selected_node_id);
    }
    const salience = computeSmartDenseSalience({
      totalNodeCount: totalNodes,
      resolvedFocus,
      highlightEdgeIds: activeCmd.highlight_edge_ids ?? [],
      allEdges: report?.edges ?? [],
      selectedNodeId: activeCmd.selected_node_id ?? null,
      isolateCone: activeCmd.isolate_cone ?? null,
      neighborhoodHops: activeCmd.neighborhood_hops ?? null,
      workingSetOnly: activeCmd.working_set_only ?? null,
      onlyFlagged: activeCmd.only_flagged ?? null,
      tierFilter: activeCmd.tier_filter ?? null,
      subkindFilter: activeCmd.subkind_filter ?? null,
      searchQuery: activeCmd.search_query ?? null,
      resetFilters: Boolean(activeCmd.reset_filters),
    });
    if (salience.mode === 'auto_isolate_cone') {
      setSelectedNodeId(salience.selectedNodeId);
      setIsolateCone(true);
      setNeighborhoodHops(0);
      setWorkingSetActive(false);
      setCompactVisible(false);
    } else if (salience.mode === 'auto_working_set_compact') {
      setSelectedNodeId(salience.selectedNodeId);
      setWorkingSetIds(new Set(salience.workingSetIds ?? resolvedFocus));
      setWorkingSetActive(true);
      setCompactVisible(true);
      setIsolateCone(false);
      setNeighborhoodHops(0);
    }
  }, [
    coldPermalinkActive,
    report?.nodes.length,
    report?.edges,
    agentCamState.activeEvent,
    agentCamState.followMode,
  ]);

  // Subscribe to `/api/v1/viewport/stream?target_slug=...&session_id=...` SSE stream
  const sseBaselineSeqRef = useRef<number>(0);
  sseBaselineSeqRef.current = initialViewportState?.latest?.seq ?? 0;
  useEffect(() => {
    if (
      !activeSlug ||
      !activeSessionId ||
      typeof window === 'undefined' ||
      typeof EventSource === 'undefined'
    ) {
      return;
    }
    if (!viewportStateFetched) {
      return;
    }
    let es: EventSource | null = null;
    try {
      es = new EventSource(
        atlasApi.buildViewportEventsUrl(activeSlug, {
          sessionId: activeSessionId,
          clientId: tabClientId,
          actor: 'human',
          followState: followModeRef.current,
          sinceSeq: lastSeenSeqRef.current,
        }),
      );
    } catch {
      return;
    }
    const handleRawEvent = (ev: MessageEvent) => {
      try {
        const parsed = JSON.parse(String(ev.data)) as ViewportCommandEvent;
        if (!parsed || !parsed.command) return;
        if (parsed.seq > 0) {
          lastSeenSeqRef.current = Math.max(lastSeenSeqRef.current, parsed.seq);
        }
        if (coldPermalinkAppliedRef.current && parsed.seq <= sseBaselineSeqRef.current) {
          return;
        }
        coldPermalinkAppliedRef.current = false;

        const decision = evaluateIncomingViewportCommand({
          event: parsed,
          source: 'sse',
          activeTargetSlug: activeSlug,
          activeSessionId,
          clientId: tabClientId,
          followState: followModeRef.current,
          currentEvidenceRevisionId:
            latestEvidenceRevRef.current ?? reportContentDigestRef.current ?? undefined,
          ackedCommandIds: ackedCommandIdsRef.current,
          pausedNotifiedCommandIds: pausedNotifiedIdsRef.current,
        });

        if (decision.markAcked) {
          const updated = recordAckedCommandId(
            activeSlug,
            activeSessionId,
            decision.commandKey,
          );
          ackedCommandIdsRef.current = new Set(updated);
        }
        if (decision.markPausedNotified) {
          pausedNotifiedIdsRef.current.add(decision.commandKey);
        }

        const refreshSid = parsed.command.refresh_session_id;
        const isPureRefresh = isPureDrawerRefreshCommand(parsed.command);
        if (decision.action === 'apply' || decision.action === 'queue_while_paused') {
          if (refreshSid && (!activeSessionId || refreshSid === activeSessionId)) {
            void refreshInvestigationStateRef.current(refreshSid);
          } else if (parsed.command.open_drawer === true && activeSessionId) {
            void refreshInvestigationStateRef.current(activeSessionId);
          }
          if (parsed.command.open_drawer === true) {
            setAskDrawerOpen(true);
          }
          if (isPureRefresh) {
            const updated = recordAckedCommandId(
              activeSlug,
              activeSessionId,
              decision.commandKey,
            );
            ackedCommandIdsRef.current = new Set(updated);
            pausedNotifiedIdsRef.current.delete(decision.commandKey);
            sendViewportReceiptRef.current(parsed, 'applied', 'Refreshed investigation drawer');
            return;
          }
        }

        if (decision.action === 'apply') {
          const res = applyIncomingViewportEvent(
            { ...agentCamStateRef.current, followMode: 'following', liveFollowing: true },
            parsed,
          );
          followModeRef.current = res.state.followMode;
          agentCamStateRef.current = res.state;
          setAgentCamState(res.state);
          if (res.shouldMoveCamera) {
            applyCommandOrFirstStepRef.current(parsed.command);
          }
          if (decision.receiptOutcome) {
            sendViewportReceiptRef.current(parsed, decision.receiptOutcome);
          }
        } else if (decision.action === 'queue_while_paused') {
          const nextCamState: AgentCameraFollowState = {
            ...agentCamStateRef.current,
            pendingEventWhilePaused: parsed,
          };
          agentCamStateRef.current = nextCamState;
          setAgentCamState(nextCamState);
          if (decision.receiptOutcome) {
            sendViewportReceiptRef.current(
              parsed,
              decision.receiptOutcome,
              'Human camera follow is paused',
            );
          }
        } else if (
          decision.action === 'reject_stale' ||
          decision.action === 'reject'
        ) {
          if (decision.receiptOutcome) {
            sendViewportReceiptRef.current(parsed, decision.receiptOutcome, decision.reason);
          }
        }
      } catch {
        // Ignore malformed SSE heartbeats
      }
    };
    es.addEventListener('viewport_command', handleRawEvent as EventListener);
    es.onmessage = handleRawEvent;
    return () => {
      es?.close();
    };
  }, [activeSlug, activeSessionId, tabClientId, viewportStateFetched]);

  const activeTimelineItems = useMemo(
    () => normalizeViewportTimeline(agentCamState.activeEvent?.command),
    [agentCamState.activeEvent?.command],
  );
  const currentAgentBeat = useMemo(() => {
    if (activeTimelineItems.length > 0) {
      return activeTimelineItems[
        Math.min(agentCamState.stepIndex, activeTimelineItems.length - 1)
      ];
    }
    const cmd = agentCamState.activeEvent?.command;
    if (!cmd) return null;
    return {
      focusNodeIds: cmd.focus_node_ids ?? [],
      highlightEdgeIds: cmd.highlight_edge_ids ?? [],
      findingId: cmd.finding_id ?? null,
      lens: (cmd.lens ?? null) as SceneLens | null,
      layoutMode: (cmd.layout_mode ?? null) as SceneLayoutMode | null,
      zWytheSlice: cmd.z_wythe_slice ?? null,
      zoomStratum: cmd.zoom_stratum ?? 1,
      framingPreset: cmd.framing_preset ?? 'iso_overview',
      caption: sanitizeViewportPlainText(cmd.caption),
    };
  }, [activeTimelineItems, agentCamState.stepIndex, agentCamState.activeEvent?.command]);

  const activeFocusNodeSet = useMemo(
    () => new Set(currentAgentBeat?.focusNodeIds ?? []),
    [currentAgentBeat],
  );
  const activeHighlightEdgeSet = useMemo(
    () => new Set(currentAgentBeat?.highlightEdgeIds ?? []),
    [currentAgentBeat],
  );
  const activePermalinkHash = useMemo(
    () =>
      buildViewportPermalinkHash({
        target_slug: activeSlug || undefined,
        session_id: activeSessionId ?? undefined,
        focus_node_ids:
          currentAgentBeat?.focusNodeIds && currentAgentBeat.focusNodeIds.length > 0
            ? currentAgentBeat.focusNodeIds
            : selectedNodeId
              ? [selectedNodeId]
              : [],
        highlight_edge_ids: currentAgentBeat?.highlightEdgeIds ?? [],
        selected_edge_id: selectedEdgeId ?? undefined,
        finding_id: selectedFindingId ?? undefined,
        lens: sceneLens,
        layout_mode: sceneLayout,
        tier_filter: tierFilter !== 'all' ? tierFilter : undefined,
        subkind_filter: subkindFilter !== 'all' ? subkindFilter : undefined,
        edge_filter: edgeFilter !== 'all' ? edgeFilter : undefined,
        only_flagged: onlyFlagged ? true : undefined,
        isolate_cone: isolateCone ? true : undefined,
        connected_only: connectedOnly ? true : undefined,
        neighborhood_hops: neighborhoodHops > 0 ? neighborhoodHops : undefined,
        search_query: searchQuery || undefined,
        blast_mode: blastMode !== 'off' ? blastMode : undefined,
        diff_base_ref: blastMode === 'git' ? diffBaseRef : undefined,
        working_set_only: workingSetActive ? true : undefined,
        compact_visible: compactVisible ? true : undefined,
        flatten_2d: flatten2D ? true : undefined,
        group_by: groupBy !== 'none' ? groupBy : undefined,
        active_tab: activeTab !== '3d' ? activeTab : undefined,
        framing_preset: currentAgentBeat?.framingPreset ?? 'iso_overview',
        z_wythe_slice: zWytheSlice !== 'all' ? zWytheSlice : undefined,
        zoom_stratum: requestedZoomStratum,
        chronicle_timeline: agentCamState.activeEvent?.command.chronicle_timeline
          ? {
              ...agentCamState.activeEvent.command.chronicle_timeline,
              active_phase_index: agentCamState.stepIndex,
            }
          : undefined,
      }),
    [
      activeSlug,
      activeSessionId,
      currentAgentBeat,
      selectedNodeId,
      selectedEdgeId,
      selectedFindingId,
      sceneLens,
      sceneLayout,
      tierFilter,
      subkindFilter,
      edgeFilter,
      onlyFlagged,
      isolateCone,
      connectedOnly,
      neighborhoodHops,
      searchQuery,
      blastMode,
      diffBaseRef,
      workingSetActive,
      compactVisible,
      flatten2D,
      groupBy,
      activeTab,
      zWytheSlice,
      requestedZoomStratum,
      agentCamState.activeEvent?.command.chronicle_timeline,
      agentCamState.stepIndex,
    ],
  );

  workspaceViewRef.current = {
    selectedNodeId,
    selectedEdgeId,
    selectedFindingId,
    sceneLens,
    sceneLayout,
    tierFilter,
    subkindFilter,
    edgeFilter,
    onlyFlagged,
    isolateCone,
    connectedOnly,
    neighborhoodHops,
    searchQuery,
    blastMode,
    diffBaseRef,
    workingSetActive,
    compactVisible,
    flatten2D,
    groupBy,
    activeTab,
    zWytheSlice,
    requestedZoomStratum,
    framingPreset: currentAgentBeat?.framingPreset ?? 'iso_overview',
    focusNodeIds: currentAgentBeat?.focusNodeIds ?? [],
    highlightEdgeIds: currentAgentBeat?.highlightEdgeIds ?? [],
  };

  const syncFollowStateToBackend = useCallback(
    (nextFollow: FollowState, reason: string) => {
      const sidAtCall = activeSessionIdRef.current;
      const slugAtCall = activeSlugRef.current;
      const epochAtCall = scopeEpochRef.current;
      const reqSeq = ++followReqSeqRef.current;
      followModeRef.current = nextFollow;
      writePersistedFollowState(sidAtCall, nextFollow);
      if (!sidAtCall) return;
      void atlasApi
        .updateInvestigationFollow(sidAtCall, {
          client_id: tabClientId,
          actor: 'human',
          follow_state: nextFollow,
          reason,
        })
        .then((sess) => {
          if (
            scopeEpochRef.current === epochAtCall &&
            activeSlugRef.current === slugAtCall &&
            activeSessionIdRef.current === sidAtCall &&
            followReqSeqRef.current === reqSeq &&
            sess.session_id === sidAtCall
          ) {
            setInvestigationSession(sess);
          }
        })
        .catch(() => {});
    },
    [tabClientId],
  );

  const handleHumanYield = useCallback(
    (reason: HumanInputInterruptKind) => {
      const prev = agentCamStateRef.current;
      const next = yieldAgentCameraOnHumanInput(prev, reason);
      followModeRef.current = next.followMode;
      agentCamStateRef.current = next;
      setAgentCamState(next);
      if (prev.followMode !== 'paused') {
        syncFollowStateToBackend('paused', `human_input:${reason}`);
      }
    },
    [syncFollowStateToBackend],
  );

  const resumeFollowFromPaused = useCallback(
    (reason: string) => {
      const prev = agentCamStateRef.current;
      syncFollowStateToBackend('following', reason);
      const nowMs = Date.now();
      const currentEvidenceRev =
        latestEvidenceRevRef.current ?? report?.content_digest ?? undefined;
      const pendingEvt = prev.pendingEventWhilePaused;
      const resumeDecision =
        pendingEvt && activeSlug
          ? evaluateIncomingViewportCommand({
              event: pendingEvt,
              source: 'resume',
              activeTargetSlug: activeSlug,
              activeSessionId,
              clientId: tabClientId,
              followState: 'following',
              currentEvidenceRevisionId: currentEvidenceRev,
              ackedCommandIds: ackedCommandIdsRef.current,
              pausedNotifiedCommandIds: pausedNotifiedIdsRef.current,
              nowMs,
            })
          : null;
      const resumed = resumeAgentCameraFollow(prev, {
        nowMs,
        currentEvidenceRevisionId: currentEvidenceRev,
        activeTargetSlug: activeSlug || undefined,
        activeSessionId,
        clientId: tabClientId || undefined,
      });
      followModeRef.current = resumed.followMode;
      agentCamStateRef.current = resumed;
      setAgentCamState(resumed);

      if (pendingEvt) {
        const cmdKey = resumeDecision?.commandKey ?? getViewportCommandKey(pendingEvt);
        pausedNotifiedIdsRef.current.delete(cmdKey);
        if (resumeDecision && resumeDecision.action !== 'apply') {
          if (resumeDecision.markAcked && pendingEvt.seq > 0 && activeSlug) {
            const updated = recordAckedCommandId(activeSlug, activeSessionId, cmdKey);
            ackedCommandIdsRef.current = new Set(updated);
          }
          if (resumeDecision.receiptOutcome && pendingEvt.seq > 0 && activeSlug) {
            sendViewportReceipt(
              pendingEvt,
              resumeDecision.receiptOutcome,
              resumeDecision.reason,
            );
          }
          return;
        }
        if (isPureDrawerRefreshCommand(pendingEvt.command)) {
          const refreshSid = pendingEvt.command.refresh_session_id;
          if (refreshSid && (!activeSessionId || refreshSid === activeSessionId)) {
            void refreshInvestigationState(refreshSid);
          } else if (pendingEvt.command.open_drawer === true && activeSessionId) {
            void refreshInvestigationState(activeSessionId);
          }
          if (pendingEvt.command.open_drawer === true) {
            setAskDrawerOpen(true);
          }
          if (pendingEvt.seq > 0 && activeSlug && !ackedCommandIdsRef.current.has(cmdKey)) {
            const updated = recordAckedCommandId(activeSlug, activeSessionId, cmdKey);
            ackedCommandIdsRef.current = new Set(updated);
            sendViewportReceipt(pendingEvt, 'applied', 'Refreshed investigation drawer');
          }
          return;
        }
      }

      if (resumed.activeEvent?.command) {
        const items = normalizeViewportTimeline(resumed.activeEvent.command);
        if (items.length > 0) {
          const idx = Math.min(resumed.stepIndex, items.length - 1);
          const item = items[idx];
          applyBeatToWorkspace({
            targetSlug: resumed.activeEvent.command.target_slug,
            focusNodeIds: item.focusNodeIds,
            highlightEdgeIds: item.highlightEdgeIds,
            selectedNodeId: item.selectedNodeId,
            selectedEdgeId: item.selectedEdgeId,
            findingId: item.findingId,
            lens: item.lens,
            layoutMode: item.layoutMode,
            tierFilter: item.tierFilter,
            subkindFilter: item.subkindFilter,
            edgeFilter: item.edgeFilter,
            onlyFlagged: item.onlyFlagged,
            isolateCone: item.isolateCone,
            connectedOnly: item.connectedOnly,
            neighborhoodHops: item.neighborhoodHops,
            searchQuery: item.searchQuery,
            blastMode: item.blastMode,
            diffBaseRef: item.diffBaseRef,
            workingSetOnly: item.workingSetOnly,
            compactVisible: item.compactVisible,
            flatten2d: item.flatten2d,
            groupBy: item.groupBy,
            activeTab: item.activeTab,
            openDrawer: item.openDrawer,
            resetFilters: item.resetFilters,
            isTimelineStep: true,
            zWytheSlice: item.zWytheSlice,
            zoomStratum: item.zoomStratum,
            framingPreset: item.framingPreset,
            caption: item.caption,
            chronicleTimeline: resumed.activeEvent.command.chronicle_timeline
              ? { ...resumed.activeEvent.command.chronicle_timeline, active_phase_index: idx }
              : null,
          });
        } else {
          applyCommandOrFirstStep(resumed.activeEvent.command);
        }
      }
      if (pendingEvt && pendingEvt.seq > 0 && activeSlug) {
        const key = resumeDecision?.commandKey ?? getViewportCommandKey(pendingEvt);
        if (!ackedCommandIdsRef.current.has(key)) {
          const updated = recordAckedCommandId(activeSlug, activeSessionId, key);
          ackedCommandIdsRef.current = new Set(updated);
          sendViewportReceipt(pendingEvt, 'applied', 'Applied on explicit human resume');
        }
      }
    },
    [
      activeSlug,
      activeSessionId,
      tabClientId,
      report?.content_digest,
      applyBeatToWorkspace,
      applyCommandOrFirstStep,
      refreshInvestigationState,
      sendViewportReceipt,
      syncFollowStateToBackend,
    ],
  );

  const handleToggleAgentFollow = useCallback(() => {
    const prev = agentCamStateRef.current;
    if (prev.followMode === 'following') {
      const next = yieldAgentCameraOnHumanInput(prev, 'pointerdown');
      followModeRef.current = next.followMode;
      agentCamStateRef.current = next;
      setAgentCamState(next);
      syncFollowStateToBackend('paused', 'manual_pause_button');
      return;
    }
    resumeFollowFromPaused('manual_resume_button');
  }, [resumeFollowFromPaused, syncFollowStateToBackend]);

  const handleRejectPendingAgentCommand = useCallback(() => {
    const prev = agentCamStateRef.current;
    const pendingEvt = prev.pendingEventWhilePaused;
    const next: AgentCameraFollowState = { ...prev, pendingEventWhilePaused: null };
    agentCamStateRef.current = next;
    setAgentCamState(next);
    if (pendingEvt && pendingEvt.seq > 0 && activeSlug) {
      const key = getViewportCommandKey(pendingEvt);
      const updated = recordAckedCommandId(activeSlug, activeSessionId, key);
      ackedCommandIdsRef.current = new Set(updated);
      sendViewportReceipt(pendingEvt, 'rejected', 'Rejected by human while follow paused');
    }
  }, [activeSlug, activeSessionId, sendViewportReceipt]);

  const handleStepAgentTimeline = useCallback(
    (delta: -1 | 1 | { index: number }) => {
      const prev = agentCamStateRef.current;
      const stepped = stepTimelineFrame(prev, delta);
      const next: AgentCameraFollowState = {
        ...stepped,
        followMode: 'following',
        liveFollowing: true,
      };
      followModeRef.current = 'following';
      agentCamStateRef.current = next;
      setAgentCamState(next);
      const items = normalizeViewportTimeline(next.activeEvent?.command);
      if (items.length > 0) {
        const idx = Math.min(next.stepIndex, items.length - 1);
        const item = items[idx];
        applyBeatToWorkspace({
          targetSlug: next.activeEvent?.command.target_slug,
          focusNodeIds: item.focusNodeIds,
          highlightEdgeIds: item.highlightEdgeIds,
          selectedNodeId: item.selectedNodeId,
          selectedEdgeId: item.selectedEdgeId,
          findingId: item.findingId,
          lens: item.lens,
          layoutMode: item.layoutMode,
          tierFilter: item.tierFilter,
          subkindFilter: item.subkindFilter,
          edgeFilter: item.edgeFilter,
          onlyFlagged: item.onlyFlagged,
          isolateCone: item.isolateCone,
          connectedOnly: item.connectedOnly,
          neighborhoodHops: item.neighborhoodHops,
          searchQuery: item.searchQuery,
          blastMode: item.blastMode,
          diffBaseRef: item.diffBaseRef,
          workingSetOnly: item.workingSetOnly,
          compactVisible: item.compactVisible,
          flatten2d: item.flatten2d,
          groupBy: item.groupBy,
          activeTab: item.activeTab,
          openDrawer: item.openDrawer,
          resetFilters: item.resetFilters,
          isTimelineStep: true,
          zWytheSlice: item.zWytheSlice,
          zoomStratum: item.zoomStratum,
          framingPreset: item.framingPreset,
          caption: item.caption,
          chronicleTimeline: next.activeEvent?.command.chronicle_timeline
            ? { ...next.activeEvent.command.chronicle_timeline, active_phase_index: idx }
            : null,
        });
      }
    },
    [applyBeatToWorkspace],
  );

  const handleToggleAgentPlay = useCallback(() => {
    setAgentCamState((prev) => ({
      ...prev,
      followMode: 'following',
      liveFollowing: true,
      isPlaying: !prev.isPlaying,
    }));
  }, []);

  const handleExitAgentTimeline = useCallback(() => {
    setAgentCamState((prev) => ({
      ...prev,
      activeEvent: null,
      pendingEventWhilePaused: null,
      haltedReason: null,
      chronicleTimelineId: null,
      timelineMode: 'none',
      stepIndex: 0,
      isPlaying: false,
    }));
    setAgentCameraRequest(null);
    setRequestedZoomStratum(1);
    setZWytheSlice('all');
  }, []);

  useEffect(() => {
    if (!agentCamState.isPlaying || activeTimelineItems.length <= 1 || prefersReducedMotion) {
      return;
    }
    const timer = window.setInterval(() => {
      handleStepAgentTimeline(1);
    }, 2800);
    return () => window.clearInterval(timer);
  }, [agentCamState.isPlaying, activeTimelineItems.length, prefersReducedMotion, handleStepAgentTimeline]);

  const diffOverlay = useMemo<DiffOverlaySet | null>(() => {
    if (blastMode === 'git' && gitDiffReport) {
      return {
        label: `git ${gitDiffReport.base_ref}`,
        touchedIds: new Set(gitDiffReport.touched_node_ids ?? []),
        impactedIds: new Set([
          ...(gitDiffReport.impacted_display_nodes ?? []),
          ...(gitDiffReport.impacted_manipulator_nodes ?? []),
          ...(gitDiffReport.impacted_truth_nodes ?? []),
        ]),
        newFindingNodeIds: new Set(
          (gitDiffReport.new_findings ?? []).map((f) => f.node_id).filter(Boolean) as string[],
        ),
        addedIds: new Set(),
        resolvedIds: new Set(),
      };
    }
    if (blastMode === 'snapshot' && snapCompareReport) {
      return {
        label: `snap #${snapCompareReport.base_snapshot_id}→#${snapCompareReport.head_snapshot_id}`,
        touchedIds: new Set(),
        impactedIds: new Set(),
        newFindingNodeIds: new Set(
          (snapCompareReport.new_findings ?? [])
            .map((f) => f.node_id)
            .filter(Boolean) as string[],
        ),
        addedIds: new Set((snapCompareReport.added_nodes ?? []).map((n) => n.id)),
        resolvedIds: new Set(
          (snapCompareReport.resolved_findings ?? [])
            .map((f) => f.node_id)
            .filter(Boolean) as string[],
        ),
      };
    }
    return null;
  }, [blastMode, gitDiffReport, snapCompareReport]);

  const flashToast = useCallback((msg: string) => {
    setQuickToast(msg);
    window.setTimeout(() => setQuickToast(null), 2200);
  }, []);

  const enabledProfiles = useMemo(
    () => profiles.filter((p) => p.is_enabled),
    [profiles],
  );

  const nodesById = useMemo(() => {
    const map = new Map<string, AtlasNode>();
    for (const n of report?.nodes ?? []) {
      map.set(n.id, n);
    }
    return map;
  }, [report?.nodes]);

  const selectedNode = selectedNodeId ? nodesById.get(selectedNodeId) ?? null : null;

  const handleReopenSession = useCallback(
    (nextSessionId: string) => {
      if (!activeSlug) return;
      const clean = switchTabSessionId(activeSlug, nextSessionId);
      if (clean === activeSessionIdRef.current) {
        void refreshInvestigationState(clean);
        flashToast(`Reopened investigation ${clean}`);
        return;
      }
      setRevisionComparison(null);
      setInvestigationSession(null);
      setScopedSessionId(activeSlug, clean);
      const savedFollow = readPersistedFollowState(clean);
      followModeRef.current = savedFollow;
      setAgentCamState((prev) => ({
        ...prev,
        followMode: savedFollow,
        liveFollowing: savedFollow === 'following',
        isPlaying: savedFollow === 'paused' ? false : prev.isPlaying,
      }));
      ackedCommandIdsRef.current = new Set(readAckedCommandIds(activeSlug, clean));
      pausedNotifiedIdsRef.current.clear();
      flashToast(`Reopened investigation ${clean}`);
    },
    [activeSlug, setScopedSessionId, refreshInvestigationState, flashToast],
  );

  const handleNewIndependentSession = useCallback(() => {
    if (!activeSlug) return;
    const fresh = rotateTabSessionId(activeSlug);
    if (typeof window !== 'undefined' && window.location.hash.includes('session=')) {
      window.history.replaceState(null, '', window.location.pathname);
    }
    setRevisionComparison(null);
    setInvestigationSession(null);
    setSelectedNodeId(null);
    setScopedSessionId(activeSlug, fresh);
    followModeRef.current = 'following';
    setAgentCamState((prev) => ({
      ...prev,
      followMode: 'following',
      liveFollowing: true,
    }));
    ackedCommandIdsRef.current = new Set();
    pausedNotifiedIdsRef.current.clear();
    flashToast(`Started independent tab investigation ${fresh}`);
  }, [activeSlug, setScopedSessionId, flashToast]);

  const handleResetSession = useCallback(() => {
    const sidAtCall = activeSessionIdRef.current;
    const slugAtCall = activeSlugRef.current;
    const epochAtCall = scopeEpochRef.current;
    if (!sidAtCall) return;
    void atlasApi
      .resetInvestigation(sidAtCall)
      .then((sess) => {
        if (
          scopeEpochRef.current !== epochAtCall ||
          activeSlugRef.current !== slugAtCall ||
          activeSessionIdRef.current !== sidAtCall
        ) {
          return;
        }
        setInvestigationSession(sess);
        setRevisionComparison(null);
        void refreshInvestigationState(sidAtCall);
        flashToast(`Reset investigation ${sidAtCall}`);
      })
      .catch((err) => flashToast(`Reset failed: ${(err as Error).message}`));
  }, [refreshInvestigationState, flashToast]);

  const handleExportSession = useCallback(() => {
    if (!activeSessionId) return;
    void atlasApi
      .exportInvestigation(activeSessionId)
      .then((bundle) => {
        const jsonText = JSON.stringify(bundle, null, 2);
        void copyTextToClipboard(jsonText);
        if (typeof document !== 'undefined') {
          const blob = new Blob([jsonText], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `wythe-investigation-${activeSessionId}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }
        flashToast(`Exported investigation ${activeSessionId}.json`);
      })
      .catch((err) => flashToast(`Export failed: ${(err as Error).message}`));
  }, [activeSessionId, flashToast]);

  const handleDeleteSession = useCallback(() => {
    const slugAtCall = activeSlugRef.current;
    const doomed = activeSessionIdRef.current;
    const epochAtCall = scopeEpochRef.current;
    if (!slugAtCall || !doomed) return;
    void atlasApi
      .deleteInvestigation(doomed)
      .then(() => {
        if (
          scopeEpochRef.current !== epochAtCall ||
          activeSlugRef.current !== slugAtCall ||
          activeSessionIdRef.current !== doomed
        ) {
          return;
        }
        const fresh = rotateTabSessionId(slugAtCall);
        setRevisionComparison(null);
        setInvestigationSession(null);
        setScopedSessionId(slugAtCall, fresh);
        flashToast(`Deleted ${doomed}; started ${fresh}`);
      })
      .catch((err) => flashToast(`Delete failed: ${(err as Error).message}`));
  }, [setScopedSessionId, flashToast]);

  const handleCompareRevisions = useCallback(async () => {
    const sidAtCall = activeSessionIdRef.current;
    const slugAtCall = activeSlugRef.current;
    const epochAtCall = scopeEpochRef.current;
    if (!sidAtCall) return;
    try {
      const comp = await atlasApi.compareInvestigationRevisions(sidAtCall);
      if (
        scopeEpochRef.current !== epochAtCall ||
        activeSlugRef.current !== slugAtCall ||
        activeSessionIdRef.current !== sidAtCall
      ) {
        return;
      }
      setRevisionComparison(comp);
      await refreshInvestigationState(sidAtCall);
    } catch (err) {
      flashToast(`Compare failed: ${(err as Error).message}`);
    }
  }, [refreshInvestigationState, flashToast]);

  const handleCorrectionAdded = useCallback(
    (_created: InvestigationCorrectionRead) => {
      void refreshInvestigationState(activeSessionId);
    },
    [activeSessionId, refreshInvestigationState],
  );

  const isSessionHydrated = Boolean(
    activeSessionId && investigationSession && investigationSession.session_id === activeSessionId,
  );

  // Keep `focus=` in `window.location.hash` synchronized with human selection after hydration so `page.reload()` never reverts to an older agent `focus=`
  useEffect(() => {
    if (typeof window === 'undefined' || !isSessionHydrated) return;
    const rawHash = window.location.hash;
    if (!rawHash || rawHash.length <= 1) return;
    const params = new URLSearchParams(rawHash.slice(1));
    if (!params.has('focus') && !params.has('finding') && !params.has('edges')) {
      return;
    }
    const prevFocus = params.get('focus') ?? '';
    const nextFocus = selectedNodeId ?? '';
    const prevFocusItems = prevFocus
      ? prevFocus
          .split(',')
          .map((item) => {
            try {
              return decodeURIComponent(item);
            } catch {
              return item;
            }
          })
          .filter(Boolean)
      : [];
    if (
      (prevFocus === nextFocus || (selectedNodeId && prevFocusItems.includes(selectedNodeId))) &&
      !params.has('finding')
    ) {
      return;
    }
    if (selectedNodeId) {
      params.set('focus', selectedNodeId);
    } else {
      params.delete('focus');
    }
    params.delete('finding');
    params.delete('edges');
    const serialized = params.toString();
    window.history.replaceState(
      null,
      '',
      serialized ? `#${serialized}` : window.location.pathname + window.location.search,
    );
  }, [selectedNodeId, isSessionHydrated]);

  const hoverAndDigestRef = useRef({ hoverFocusMeta, liveViewportDigest });
  hoverAndDigestRef.current = { hoverFocusMeta, liveViewportDigest };

  const emitUiFocusPayload = useCallback(() => {
    if (!activeSlug || !activeSessionId || !tabClientId || !isSessionHydrated) return;
    const { hoverFocusMeta: curHover, liveViewportDigest: curDigest } = hoverAndDigestRef.current;
    const derivedDistrict =
      (selectedNode ? deriveDomainCluster(selectedNode) : null) ?? curHover.district;
    const knownRev =
      Number((whatsThisExplanation as { camera_revision?: number | null } | null)?.camera_revision ?? 0) || 0;
    const nextRev = bumpViewportCameraRevision(knownRev);
    syncUiFocus.mutate(
      {
        active_slug: activeSlug,
        session_id: activeSessionId,
        client_id: tabClientId,
        actor: 'human',
        active_tab: activeTab,
        selected_node_id: selectedNodeId,
        selected_edge_id: selectedEdgeId,
        selected_finding_id: selectedFindingId,
        hovered_node_id: curHover.hoveredNodeId,
        focused_district: derivedDistrict,
        follow_state: agentCamState.followMode,
        evidence_revision_id: latestEvidenceRevRef.current,
        tier_filter: tierFilter,
        subkind_filter: subkindFilter,
        edge_filter: edgeFilter,
        lens: sceneLens,
        layout_mode: sceneLayout,
        blast_mode: blastMode,
        diff_base_ref: diffBaseRef,
        only_flagged: onlyFlagged,
        isolate_cone: isolateCone,
        connected_only: connectedOnly,
        neighborhood_hops: neighborhoodHops,
        search_query: searchQuery,
        working_set_only: workingSetActive,
        compact_visible: compactVisible,
        flatten_2d: flatten2D,
        group_by: groupBy,
        z_wythe_slice: zWytheSlice,
        zoom_stratum: requestedZoomStratum,
        active_trace_route: activeTraceChain
          ? `${activeTraceChain.http_method} ${activeTraceChain.http_path}`
          : null,
        camera_position: curHover.cameraPosition,
        camera_target: curHover.cameraTarget,
        visible_node_count: curHover.visibleNodeCount,
        in_frustum_count: curDigest?.inFrustumCount ?? 0,
        visual_headline: curHover.visualHeadline,
        live_viewport_brief: curDigest?.markdownBrief ?? null,
        camera_revision: nextRev,
      },
      {
        onSuccess: (ack) => {
          if (
            activeSlugRef.current !== activeSlug ||
            activeSessionIdRef.current !== activeSessionId
          ) {
            return;
          }
          if (typeof ack.focus_revision === 'number') {
            latestFocusRevisionRef.current = ack.focus_revision;
          }
          if (ack.evidence_revision_id) {
            latestEvidenceRevRef.current = ack.evidence_revision_id;
          }
          if (askDrawerOpen) {
            fetchUiFocus.mutate(
              {
                targetSlug: activeSlug,
                sessionId: activeSessionId,
                clientId: tabClientId,
                selectedEdgeId,
                selectedFindingId,
                followState: agentCamState.followMode,
              },
              {
                onSuccess: (exp) => {
                  if (
                    activeSlugRef.current === activeSlug &&
                    activeSessionIdRef.current === activeSessionId
                  ) {
                    setWhatsThisExplanation(exp);
                  }
                },
              },
            );
          }
        },
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    activeSlug,
    activeSessionId,
    tabClientId,
    activeTab,
    selectedNode,
    selectedNodeId,
    selectedEdgeId,
    selectedFindingId,
    agentCamState.followMode,
    tierFilter,
    subkindFilter,
    edgeFilter,
    sceneLens,
    sceneLayout,
    blastMode,
    diffBaseRef,
    onlyFlagged,
    isolateCone,
    connectedOnly,
    neighborhoodHops,
    searchQuery,
    workingSetActive,
    compactVisible,
    flatten2D,
    groupBy,
    zWytheSlice,
    requestedZoomStratum,
    activeTraceChain,
    askDrawerOpen,
    isSessionHydrated,
  ]);

  const emitUiFocusRef = useRef(emitUiFocusPayload);
  emitUiFocusRef.current = emitUiFocusPayload;
  const pendingHoverTimerRef = useRef<number | null>(null);

  // 1) Prompt sync for explicit human selection, tab, filter, and follow changes (gated on session hydration so reload never wipes saved selection)
  useEffect(() => {
    if (!activeSlug || !activeSessionId || !tabClientId || !isSessionHydrated) return;
    if (pendingHoverTimerRef.current !== null) {
      window.clearTimeout(pendingHoverTimerRef.current);
      pendingHoverTimerRef.current = null;
    }
    const timer = window.setTimeout(() => {
      if (pendingHoverTimerRef.current !== null) {
        window.clearTimeout(pendingHoverTimerRef.current);
        pendingHoverTimerRef.current = null;
      }
      emitUiFocusRef.current();
    }, 35);
    return () => window.clearTimeout(timer);
  }, [emitUiFocusPayload, activeSlug, activeSessionId, tabClientId, isSessionHydrated]);

  // 2) Debounced (>= 250ms) sync for passive hover & settled camera framing metadata (always invokes fresh ref closure after hydration)
  useEffect(() => {
    if (!activeSlug || !activeSessionId || !tabClientId || !isSessionHydrated) return;
    if (pendingHoverTimerRef.current !== null) {
      window.clearTimeout(pendingHoverTimerRef.current);
    }
    const timer = window.setTimeout(() => {
      pendingHoverTimerRef.current = null;
      emitUiFocusRef.current();
    }, MIN_UI_FOCUS_DEBOUNCE_MS);
    pendingHoverTimerRef.current = timer;
    return () => {
      window.clearTimeout(timer);
      if (pendingHoverTimerRef.current === timer) {
        pendingHoverTimerRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    hoverFocusMeta.hoveredNodeId,
    hoverFocusMeta.district,
    hoverFocusMeta.cameraPosition,
    hoverFocusMeta.cameraTarget,
    hoverFocusMeta.visibleNodeCount,
    liveViewportDigest?.inFrustumCount,
  ]);

  const openAskWytheDrawer = useCallback(
    (prefill?: string) => {
      if (typeof prefill === 'string') setAskPrefillQuestion(prefill);
      setWhatsThisOpen(false);
      setAskDrawerOpen(true);
      void refreshInvestigationState(activeSessionId);
      if (activeTab === '3d' && !liveCaptureFnRef.current) {
        focusCaptureTargetRef.current = 'drawer';
        setWhatsThisRequest((n) => n + 1);
      } else if (activeSlug) {
        fetchUiFocus.mutate(
          {
            targetSlug: activeSlug,
            sessionId: activeSessionId,
            clientId: tabClientId,
            selectedEdgeId,
            selectedFindingId,
            followState: agentCamState.followMode,
          },
          {
            onSuccess: (exp) => {
              if (
                activeSlugRef.current === activeSlug &&
                activeSessionIdRef.current === activeSessionId
              ) {
                setWhatsThisExplanation(exp);
              }
            },
          },
        );
      }
    },
    [
      activeTab,
      activeSlug,
      activeSessionId,
      tabClientId,
      selectedEdgeId,
      selectedFindingId,
      agentCamState.followMode,
      fetchUiFocus,
      refreshInvestigationState,
    ],
  );

  useEffect(() => {
    if (!activeSlug) return;
    return registerWytheWebMcpBridge({
      getWhatIsThis: () =>
        atlasApi.getUiFocus(activeSlug, {
          sessionId: activeSessionId,
          clientId: tabClientId,
          actor: 'human',
          selectedEdgeId,
          selectedFindingId,
          followState: followModeRef.current,
        }),
      getLineageCone: (query) => atlasApi.getScanContextCone(activeSlug, query),
      selectNode: (nodeId) => setSelectedNodeId(nodeId),
      openAskDrawer: (q) => openAskWytheDrawer(q),
      getSession: () =>
        activeSessionId ? atlasApi.getInvestigation(activeSessionId) : Promise.resolve(null),
      submitCorrection: async (note, kind = 'disagreement') => {
        if (!activeSessionId) {
          throw new Error('No active investigation session.');
        }
        const sidAtCall = activeSessionId;
        const created = await atlasApi.addInvestigationCorrection(sidAtCall, {
          client_id: tabClientId,
          actor: 'human',
          target_ref_id: selectedFindingId ?? selectedEdgeId ?? selectedNodeId ?? undefined,
          kind,
          note,
        });
        await refreshInvestigationState(sidAtCall);
        return created;
      },
      setFollowState: async (state) => {
        if (state === 'paused') {
          const next = yieldAgentCameraOnHumanInput(agentCamStateRef.current, 'pointerdown');
          followModeRef.current = next.followMode;
          agentCamStateRef.current = next;
          setAgentCamState(next);
          syncFollowStateToBackend('paused', 'window_wythe_bridge');
        } else {
          resumeFollowFromPaused('window_wythe_bridge');
        }
        return { session_id: activeSessionId, follow_state: state };
      },
      compareRevisions: async () => {
        if (!activeSessionId) return null;
        const sidAtCall = activeSessionId;
        const slugAtCall = activeSlug;
        const comp = await atlasApi.compareInvestigationRevisions(sidAtCall);
        if (
          activeSlugRef.current === slugAtCall &&
          activeSessionIdRef.current === sidAtCall
        ) {
          setRevisionComparison(comp);
          await refreshInvestigationState(sidAtCall);
        }
        return comp;
      },
    });
  }, [
    activeSlug,
    activeSessionId,
    tabClientId,
    selectedNodeId,
    selectedEdgeId,
    selectedFindingId,
    openAskWytheDrawer,
    refreshInvestigationState,
    resumeFollowFromPaused,
    syncFollowStateToBackend,
  ]);

  const handleTriggerWhatsThis = useCallback(
    (payload: {
      snapshotDataUrl: string | null;
      hoveredNodeId: string | null;
      district: string | null;
      visualHeadline: string | null;
    }) => {
      if (!activeSlug) return;
      const mode = focusCaptureTargetRef.current;
      focusCaptureTargetRef.current = 'modal';
      setWhatsThisSnapshotUrl(payload.snapshotDataUrl);
      setWhatsThisImageCopied(false);
      if (mode === 'modal') {
        setWhatsThisOpen(true);
        if (payload.snapshotDataUrl) {
          void tryCopyDataUrlPngToClipboard(payload.snapshotDataUrl).then((copied) => {
            setWhatsThisImageCopied(copied);
          });
        }
      }
      const knownRev =
        Number((whatsThisExplanation as { camera_revision?: number | null } | null)?.camera_revision ?? 0) || 0;
      syncUiFocus.mutate(
        {
          active_slug: activeSlug,
          session_id: activeSessionId,
          client_id: tabClientId,
          actor: 'human',
          active_tab: activeTab,
          selected_node_id: selectedNodeId,
          selected_edge_id: selectedEdgeId,
          selected_finding_id: selectedFindingId,
          hovered_node_id: payload.hoveredNodeId,
          focused_district:
            (selectedNode ? deriveDomainCluster(selectedNode) : null) ?? payload.district,
          follow_state: agentCamState.followMode,
          evidence_revision_id: latestEvidenceRevRef.current,
          tier_filter: tierFilter,
          subkind_filter: subkindFilter,
          edge_filter: edgeFilter,
          lens: sceneLens,
          layout_mode: sceneLayout,
          blast_mode: blastMode,
          diff_base_ref: diffBaseRef,
          only_flagged: onlyFlagged,
          isolate_cone: isolateCone,
          connected_only: connectedOnly,
          neighborhood_hops: neighborhoodHops,
          search_query: searchQuery,
          working_set_only: workingSetActive,
          compact_visible: compactVisible,
          flatten_2d: flatten2D,
          group_by: groupBy,
          z_wythe_slice: zWytheSlice,
          zoom_stratum: requestedZoomStratum,
          active_trace_route: activeTraceChain
            ? `${activeTraceChain.http_method} ${activeTraceChain.http_path}`
            : null,
          camera_position: hoverFocusMeta.cameraPosition,
          camera_target: hoverFocusMeta.cameraTarget,
          visible_node_count: hoverFocusMeta.visibleNodeCount,
          in_frustum_count: liveViewportDigest?.inFrustumCount ?? 0,
          visual_headline: payload.visualHeadline,
          live_viewport_brief: liveViewportDigest?.markdownBrief ?? null,
          camera_revision: bumpViewportCameraRevision(knownRev),
          snapshot_data_url: payload.snapshotDataUrl,
        },
        {
          onSuccess: (ack) => {
            if (
              activeSlugRef.current !== activeSlug ||
              activeSessionIdRef.current !== activeSessionId
            ) {
              return;
            }
            if (typeof ack.focus_revision === 'number') {
              latestFocusRevisionRef.current = ack.focus_revision;
            }
            if (ack.evidence_revision_id) {
              latestEvidenceRevRef.current = ack.evidence_revision_id;
            }
            fetchUiFocus.mutate(
              {
                targetSlug: activeSlug,
                sessionId: activeSessionId,
                clientId: tabClientId,
                selectedEdgeId,
                selectedFindingId,
                followState: agentCamState.followMode,
              },
              {
                onSuccess: (exp) => {
                  if (
                    activeSlugRef.current === activeSlug &&
                    activeSessionIdRef.current === activeSessionId
                  ) {
                    setWhatsThisExplanation(exp);
                  }
                },
              },
            );
          },
        },
      );
    },
    [
      activeSlug,
      activeSessionId,
      tabClientId,
      activeTab,
      selectedNodeId,
      selectedEdgeId,
      selectedFindingId,
      selectedNode,
      agentCamState.followMode,
      tierFilter,
      subkindFilter,
      edgeFilter,
      sceneLens,
      sceneLayout,
      blastMode,
      diffBaseRef,
      onlyFlagged,
      isolateCone,
      connectedOnly,
      neighborhoodHops,
      searchQuery,
      workingSetActive,
      compactVisible,
      flatten2D,
      groupBy,
      zWytheSlice,
      requestedZoomStratum,
      activeTraceChain,
      hoverFocusMeta.cameraPosition,
      hoverFocusMeta.cameraTarget,
      hoverFocusMeta.visibleNodeCount,
      liveViewportDigest,
      syncUiFocus,
      fetchUiFocus,
    ],
  );

  const copyLlmsBriefNow = useCallback(() => {
    fetchLlmsBrief.mutate(undefined, {
      onSuccess: (brief) => {
        void copyTextToClipboard(brief.markdown).then((ok) => {
          const msg = ok ? `Copied llms.txt (~${brief.approx_tokens} tok)` : 'Clipboard copy failed';
          setCopiedBriefLabel(ok ? `Copied ~${brief.approx_tokens} tok` : 'Copy failed');
          flashToast(msg);
          window.setTimeout(() => setCopiedBriefLabel(null), 2200);
        });
      },
    });
  }, [fetchLlmsBrief, flashToast]);

  const copySelectedConeNow = useCallback(() => {
    if (!selectedNodeId) {
      flashToast('Select a node first to copy its 3-tier cone');
      return;
    }
    fetchContextCone.mutate(selectedNodeId, {
      onSuccess: (res) => {
        const comp = res.completeness;
        const compNote =
          comp && !comp.is_complete
            ? ` (truncated ${comp.nodes?.included ?? 0}/${comp.nodes?.eligible ?? 0} nodes; use Inspector "Full Cone")`
            : '';
        void copyTextToClipboard(res.markdown).then((ok) => {
          flashToast(
            ok ? `Copied 3-tier cone (~${res.approx_tokens} tok)${compNote}` : 'Clipboard copy failed',
          );
        });
      },
    });
  }, [selectedNodeId, fetchContextCone, flashToast]);

  const toggleFullscreen3D = useCallback(() => {
    setActiveTab('3d');
    setIsFullscreen3D((prev) => !prev);
  }, []);

  const toggleBrowserNativeFullscreen = useCallback(() => {
    setActiveTab('3d');
    if (document.fullscreenElement) {
      void document.exitFullscreen().catch(() => {});
      setIsFullscreen3D(false);
    } else {
      setIsFullscreen3D(true);
      void document.documentElement.requestFullscreen().catch(() => {});
    }
  }, []);

  const cycleTierFilter = useCallback(() => {
    const order: Array<'all' | 'display' | 'manipulate' | 'truth'> = [
      'all',
      'display',
      'manipulate',
      'truth',
    ];
    setTierFilter((cur) => {
      const next = order[(order.indexOf(cur) + 1) % order.length];
      flashToast(`Stratum filter: ${next.toUpperCase()}`);
      return next;
    });
  }, [flashToast]);

  const cycleAppearance = useCallback(() => {
    const order: AppearanceMode[] = ['system', 'dark', 'light'];
    const next = order[(order.indexOf(wytheTheme.appearance) + 1) % order.length];
    wytheTheme.setAppearance(next);
    flashToast(`Polarity: ${next.toUpperCase()}`);
  }, [wytheTheme, flashToast]);

  const cycleSceneLens = useCallback(() => {
    const order: SceneLens[] = [
      'status',
      'contention',
      'gravity',
      'subkind',
      'cluster',
      'containers',
    ];
    setSceneLens((cur) => {
      const next = order[(order.indexOf(cur) + 1) % order.length];
      flashToast(`3D Lens: ${SCENE_LENS_LABELS[next]}`);
      return next;
    });
  }, [flashToast]);

  const toggleSceneLayout = useCallback(() => {
    const order: readonly SceneLayoutMode[] = [
      'cluster',
      'grid',
      'subkind',
      'connected',
      'lifecycle_z',
      'temporal_z',
    ];
    setSceneLayout((cur) => {
      const next = order[(order.indexOf(cur) + 1) % order.length];
      flashToast(`3D Layout: ${SCENE_LAYOUT_LABELS[next]}`);
      return next;
    });
  }, [flashToast]);

  const handleToggleWorkingSetNode = useCallback(
    (nodeId: string) => {
      setWorkingSetIds((prev) => {
        const nextArr = toggleNodeInWorkingSet([...prev], nodeId);
        setWorkingSetActive(nextArr.length > 0);
        return new Set(nextArr);
      });
    },
    [],
  );

  const handleCollectVisibleToWorkingSet = useCallback(
    (replace: boolean) => {
      if (visibleSceneNodeIds.length === 0) return;
      setWorkingSetIds(
        (prev) => new Set(addNodesToWorkingSet(replace ? [] : [...prev], visibleSceneNodeIds)),
      );
      setWorkingSetActive(true);
      flashToast(
        replace
          ? `Working set replaced with ${visibleSceneNodeIds.length} visible nodes`
          : `Added ${visibleSceneNodeIds.length} visible nodes to working set`,
      );
    },
    [visibleSceneNodeIds, flashToast],
  );

  const handleExpandBoundary = useCallback(
    (externalIds: string[]) => {
      if (externalIds.length === 0) return;
      setWorkingSetIds((prev) => new Set(addNodesToWorkingSet([...prev], externalIds)));
      setWorkingSetActive(true);
      flashToast(`Expanded working set by ${externalIds.length} boundary nodes`);
    },
    [flashToast],
  );

  const handleToggleCollapseGroup = useCallback((key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const handleTogglePinNode = useCallback(
    (nodeId: string, pos?: [number, number, number]) => {
      setPinnedPositions((prev) => {
        const next = { ...prev };
        if (nodeId in next) {
          delete next[nodeId];
          flashToast('Unpinned node position');
        } else if (pos) {
          next[nodeId] = [...pos];
          flashToast('Pinned node position across layout switches');
        }
        return next;
      });
    },
    [flashToast],
  );

  const handleResetOverview = useCallback(() => {
    setWorkingSetActive(false);
    setCompactVisible(false);
    setFlatten2D(false);
    setGroupBy('none');
    setCollapsedGroups(new Set());
    setPinnedPositions({});
    setSavedViewNotice(null);
    setResetCameraRequest((n) => n + 1);
    flashToast('Reset to full overview');
  }, [flashToast]);

  const handleSaveWorkingView = useCallback(() => {
    if (!report || !activeSlug) return;
    const baseIds =
      workingSetActive && workingSetIds.size > 0 ? Array.from(workingSetIds) : visibleSceneNodeIds;
    const view: SavedWorkingView = {
      id: `${Date.now()}`,
      name: `${activeSlug} · ${SCENE_LAYOUT_LABELS[sceneLayout]} (${baseIds.length})`,
      createdAt: new Date().toISOString(),
      targetSlug: activeSlug,
      sourceCommit: report.source_commit ?? '',
      contentDigest: report.content_digest ?? '',
      nodeIds: baseIds,
      layoutMode: sceneLayout,
      compactVisible,
      flatten2D,
      lens: sceneLens,
      groupBy,
      pinnedPositions: { ...pinnedPositions },
      collapsedGroups: Array.from(collapsedGroups),
    };
    setSavedViews((prev) => {
      const next = [view, ...prev.slice(0, 19)];
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(SAVED_VIEWS_STORAGE_KEY, serializeSavedViews(next));
      }
      return next;
    });
    setSelectedSavedViewId(view.id);
    flashToast(`Saved view "${view.name}"`);
  }, [
    report,
    activeSlug,
    workingSetActive,
    workingSetIds,
    visibleSceneNodeIds,
    pinnedPositions,
    sceneLayout,
    sceneLens,
    flatten2D,
    compactVisible,
    groupBy,
    collapsedGroups,
    flashToast,
  ]);

  const handleLoadSavedView = useCallback(
    (viewId: string) => {
      setSelectedSavedViewId(viewId);
      const view = savedViews.find((v) => v.id === viewId);
      if (!view || !report) return;
      if (view.targetSlug !== activeSlug) {
        flashToast(`Switch target to ${view.targetSlug} before loading "${view.name}"`);
        return;
      }
      const res = reconcileSavedView(view, {
        target_slug: report.target_slug,
        source_commit: report.source_commit ?? '',
        content_digest: report.content_digest ?? '',
        nodes: report.nodes,
      });
      const matchedSet = new Set(res.matchedNodeIds);
      setWorkingSetIds(matchedSet);
      setWorkingSetActive(res.matchedNodeIds.length > 0);
      setSceneLayout(view.layoutMode);
      setSceneLens(view.lens ?? 'status');
      setFlatten2D(view.flatten2D);
      setCompactVisible(view.compactVisible);
      setGroupBy(view.groupBy ?? 'none');
      setCollapsedGroups(new Set(view.collapsedGroups ?? []));
      const nextPins: Record<string, [number, number, number]> = {};
      for (const [nid, pos] of Object.entries(view.pinnedPositions ?? {})) {
        if (matchedSet.has(nid)) nextPins[nid] = [...pos];
      }
      setPinnedPositions(nextPins);
      setSavedViewNotice(res);
      flashToast(`Loaded view "${view.name}" (${res.matchedNodeIds.length} present)`);
    },
    [savedViews, report, activeSlug, flashToast],
  );

  const toggleBlastOverlay = useCallback(() => {
    setBlastMode((cur) => {
      const next = cur === 'off' ? 'git' : cur === 'git' ? 'snapshot' : 'off';
      flashToast(
        next === 'off'
          ? '3D Blast Overlay: OFF'
          : next === 'git'
            ? `3D Blast Overlay: Git Diff (${diffBaseRef})`
            : '3D Blast Overlay: Snapshot Delta',
      );
      return next;
    });
  }, [diffBaseRef, flashToast]);

  const quickActions = useMemo<QuickActionDef[]>(() => {
    const closeAnd = (fn: () => void) => () => {
      setPaletteOpen(false);
      fn();
    };
    return [
      {
        id: 'fullscreen-3d',
        group: 'View & Camera',
        label: isFullscreen3D ? 'Exit Fullscreen 3D Lattice' : 'Enter Fullscreen 3D Lattice',
        subtitle: 'Expand Stratified 3D Wythe Lattice across the entire viewport',
        shortcut: 'F',
        keywords: 'zen theatre maximize fullscreen expand',
        run: closeAnd(toggleFullscreen3D),
      },
      {
        id: 'native-fullscreen',
        group: 'View & Camera',
        label: 'Toggle OS Native Fullscreen',
        subtitle: 'Enter or exit native browser fullscreen with floating HUD & Inspector',
        shortcut: '⇧F',
        keywords: 'browser os fullscreen',
        run: closeAnd(toggleBrowserNativeFullscreen),
      },
      {
        id: 'reset-camera',
        group: 'View & Camera',
        label: 'Reset 3D Camera & Clear Selection',
        subtitle: 'Recenter all 3 strata (Display, Manipulate, SQL Truth) in frame',
        shortcut: '0',
        run: closeAnd(() => {
          setSelectedNodeId(null);
          setResetCameraRequest((n) => n + 1);
        }),
      },
      {
        id: 'tab-3d',
        group: 'Workspace Tabs',
        label: 'Switch to 3D Stratified Lattice',
        subtitle: 'Interactive WebGL2 3-plane architecture & lineage cone inspector',
        shortcut: '1',
        run: closeAnd(() => setActiveTab('3d')),
      },
      {
        id: 'tab-lineage',
        group: 'Workspace Tabs',
        label: 'Switch to 3-Tier Lineage Chains',
        subtitle: 'Inspect verified end-to-end Display → Manipulate → Truth chains',
        shortcut: '2',
        run: closeAnd(() => {
          setIsFullscreen3D(false);
          setActiveTab('lineage');
        }),
      },
      {
        id: 'tab-gate',
        group: 'Workspace Tabs',
        label: 'Switch to Gate, Rules & Diff Blast Radius',
        subtitle: 'Configure DB rule policies, vocabulary packs, PR diff gate & ratchets',
        shortcut: '3',
        run: closeAnd(() => {
          setIsFullscreen3D(false);
          setActiveTab('gate');
        }),
      },
      {
        id: 'tab-index',
        group: 'Workspace Tabs',
        label: 'Switch to Accessible Index & Stack Adapters',
        subtitle: 'Tabular node directory and multi-language adapter matrix',
        shortcut: '4',
        run: closeAnd(() => {
          setIsFullscreen3D(false);
          setActiveTab('index');
        }),
      },
      {
        id: 'toggle-flagged',
        group: '3D Filters & Inspection',
        label: onlyFlagged ? 'Show All Nodes (Disable Flagged-Only)' : 'Filter: Flagged Nodes Only',
        subtitle: 'Focus boundary violations, duplicated truth, and unwired surfaces',
        shortcut: 'G',
        run: closeAnd(() => setOnlyFlagged((v) => !v)),
      },
      {
        id: 'toggle-cone',
        group: '3D Filters & Inspection',
        label: isolateCone ? 'Disable Lineage Cone Isolation' : 'Isolate Transitive Lineage Cone',
        subtitle: 'Hide nodes outside the selected node’s upstream/downstream 3-tier cone',
        shortcut: 'C',
        disabled: !selectedNodeId,
        run: closeAnd(() => { setIsolateCone((v) => !v); setNeighborhoodHops(0); }),
      },
      {
        id: 'stratum-all',
        group: '3D Filters & Inspection',
        label: 'Stratum Filter: ALL (Display + Manipulate + DB Truth)',
        subtitle: 'Show stratified 3-tier balance across all three planes',
        shortcut: 'T',
        run: closeAnd(() => setTierFilter('all')),
      },
      {
        id: 'stratum-truth',
        group: '3D Filters & Inspection',
        label: 'Stratum Filter: TRUTH (SQL Tables, Guards & Redis Queues)',
        subtitle: 'Focus Bedrock Tier 1 Icosa-20 & Hex-Torus lattice',
        run: closeAnd(() => setTierFilter('truth')),
      },
      {
        id: 'stratum-manipulate',
        group: '3D Filters & Inspection',
        label: 'Stratum Filter: MANIPULATE (Routes, Services & Workers)',
        subtitle: 'Focus Mid-Plane Tier 2 Octa-8 lattice',
        run: closeAnd(() => setTierFilter('manipulate')),
      },
      {
        id: 'stratum-display',
        group: '3D Filters & Inspection',
        label: 'Stratum Filter: DISPLAY (Pages, Hooks & Components)',
        subtitle: 'Focus Top-Plane Tier 3 Hex-12 lattice',
        run: closeAnd(() => setTierFilter('display')),
      },
      {
        id: 'ask-wythe-ai',
        group: 'LLM, CI & Governance',
        label: 'Ask Wythe On-Device AI (Apple FM / Chrome Nano / Local /v1)',
        subtitle:
          'Ask questions directly in-browser grounded in live 3D X-Ray & vision snapshot',
        shortcut: 'A',
        keywords: 'ask ai llm apple intelligence chrome gemini nano local openai mcp',
        run: closeAnd(() => openAskWytheDrawer()),
      },
      {
        id: 'whats-this-bridge',
        group: 'LLM, CI & Governance',
        label: "What's This? — Sync Live 3D X-Ray & Annotated Vision Card",
        subtitle:
          'Zero copy-paste Human <-> Vision/MCP Bridge (`wythe_what_is_this` + draggable PNG card)',
        shortcut: 'W',
        keywords: 'what is this vision bridge mcp screenshot cluster xray red',
        run: closeAnd(() => {
          focusCaptureTargetRef.current = 'modal';
          setActiveTab('3d');
          setWhatsThisRequest((n) => n + 1);
        }),
      },
      {
        id: 'copy-llms',
        group: 'LLM, CI & Governance',
        label: 'Copy llms.txt 3-Tier Architectural Brief',
        subtitle: 'Copy token-budgeted 3-tier pointer map to clipboard',
        shortcut: '⇧⌘L',
        run: closeAnd(copyLlmsBriefNow),
      },
      {
        id: 'copy-cone',
        group: 'LLM, CI & Governance',
        label: 'Copy Selected Node 3-Tier Lineage Cone',
        subtitle: selectedNode ? `Copy Markdown cone for ${selectedNode.label}` : 'Requires a selected node',
        shortcut: '⇧⌘C',
        disabled: !selectedNodeId,
        run: closeAnd(copySelectedConeNow),
      },
      {
        id: 'rescan',
        group: 'LLM, CI & Governance',
        label: 'Rescan Syntax Trees & Seal Snapshot Receipt',
        subtitle: 'Re-parse repository ASTs and record fresh observation receipt',
        shortcut: 'R',
        run: closeAnd(() => {
          triggerScan.mutate(undefined, {
            onSuccess: () => flashToast('Rescan complete & receipt sealed'),
          });
        }),
      },
      {
        id: 'gov-export',
        group: 'LLM, CI & Governance',
        label: 'Export .wythe/governance.json Bundle',
        subtitle: 'Write portable rules, vocabulary & ratchets into target repository',
        run: closeAnd(() => {
          syncGovBundle.mutate('export', {
            onSuccess: () => flashToast('Exported .wythe/governance.json'),
          });
        }),
      },
      {
        id: 'toggle-polygons',
        group: 'Appearance & Polygons',
        label:
          wytheTheme.polygonMode === 'atomic'
            ? 'Switch Polygons to Simple Solids'
            : 'Switch Polygons to Atomic Wythe Breathing Lattice',
        subtitle: 'Toggle between GPU SDF C3 Wythe latticework and classic solids',
        shortcut: 'P',
        run: closeAnd(() =>
          wytheTheme.setPolygonMode(wytheTheme.polygonMode === 'atomic' ? 'simple' : 'atomic'),
        ),
      },
      {
        id: 'cycle-polarity',
        group: 'Appearance & Polygons',
        label: `Cycle Polarity (Current: ${wytheTheme.appearance.toUpperCase()})`,
        subtitle: 'Switch between System auto-detect, Row 1 Dark, and Row 2 Light',
        shortcut: 'D',
        run: closeAnd(cycleAppearance),
      },
      ...(Object.keys(WYTHE_PRESETS) as Array<keyof typeof WYTHE_PRESETS>).map((presetKey) => ({
        id: `preset-${presetKey}`,
        group: 'Appearance & Polygons',
        label: `Color Preset: ${WYTHE_PRESETS[presetKey].label}`,
        subtitle: 'Apply adaptive Row 1 / Row 2 colorway across UI & 3D lattice',
        run: closeAnd(() => {
          wytheTheme.setPreset(presetKey);
          flashToast(`Preset: ${WYTHE_PRESETS[presetKey].label}`);
        }),
      })),
      {
        id: 'cycle-lens',
        group: '3D Lenses & Blast Radius',
        label: `Cycle 3D Lens (Current: ${SCENE_LENS_LABELS[sceneLens]})`,
        subtitle: 'Switch between Boundary Status, Write Contention, Fan-Out Gravity, 11 Subkinds & Domain Clusters',
        shortcut: 'V',
        keywords: 'heatmap contention gravity coupling subkind cluster lens',
        run: closeAnd(() => {
          setActiveTab('3d');
          cycleSceneLens();
        }),
      },
      {
        id: 'toggle-layout',
        group: '3D Lenses & Blast Radius',
        label:
          sceneLayout === 'cluster'
            ? '3D Layout: Switch to Uniform Grid'
            : '3D Layout: Switch to Vertical Domain Districts',
        subtitle: 'Align related UI, services, and SQL tables into vertical domain districts',
        shortcut: 'L',
        run: closeAnd(() => {
          setActiveTab('3d');
          toggleSceneLayout();
        }),
      },
      {
        id: 'toggle-blast',
        group: '3D Lenses & Blast Radius',
        label: `Cycle 3D Blast-Radius / Snapshot Overlay (Current: ${blastMode.toUpperCase()})`,
        subtitle: 'Project PR git diff blast cone or historical snapshot delta onto 3D lattice',
        shortcut: 'B',
        keywords: 'diff pr blast snapshot time travel',
        run: closeAnd(() => {
          setActiveTab('3d');
          toggleBlastOverlay();
        }),
      },
      {
        id: 'register-target',
        group: 'Targets',
        label: 'Register New Repository Target…',
        subtitle: 'Auto-detect stack profile and add local repository path',
        run: closeAnd(() => {
          setIsFullscreen3D(false);
          setShowAddTarget(true);
        }),
      },
    ];
  }, [
    isFullscreen3D,
    toggleFullscreen3D,
    toggleBrowserNativeFullscreen,
    onlyFlagged,
    isolateCone,
    connectedOnly,
    neighborhoodHops,
    selectedNodeId,
    selectedNode,
    copyLlmsBriefNow,
    copySelectedConeNow,
    triggerScan,
    syncGovBundle,
    wytheTheme,
    cycleAppearance,
    sceneLens,
    sceneLayout,
    blastMode,
    cycleSceneLens,
    toggleSceneLayout,
    toggleBlastOverlay,
    openAskWytheDrawer,
    flashToast,
  ]);

  useEffect(() => {
    const onWinKeyDown = (ev: globalThis.KeyboardEvent) => {
      const mod = ev.metaKey || ev.ctrlKey;
      const lower = ev.key.toLowerCase();

      if (mod && lower === 'k') {
        ev.preventDefault();
        setPaletteInitialQuery('');
        setPaletteOpen((prev) => !prev);
        return;
      }
      if (mod && lower === 'j') {
        ev.preventDefault();
        if (askDrawerOpen) {
          setAskDrawerOpen(false);
        } else {
          openAskWytheDrawer();
        }
        return;
      }
      if (mod && ev.shiftKey && lower === 'l') {
        ev.preventDefault();
        copyLlmsBriefNow();
        return;
      }
      if (mod && ev.shiftKey && lower === 'c' && selectedNodeId) {
        ev.preventDefault();
        copySelectedConeNow();
        return;
      }

      if (paletteOpen) return;

      const el = ev.target as HTMLElement | null;
      const tag = el?.tagName;
      const inEditable =
        tag === 'INPUT' ||
        tag === 'TEXTAREA' ||
        tag === 'SELECT' ||
        Boolean(el?.isContentEditable);

      if (ev.key === 'Escape') {
        if (inEditable) {
          el?.blur();
          return;
        }
        if (whatsThisOpen) {
          setWhatsThisOpen(false);
          return;
        }
        if (askDrawerOpen) {
          setAskDrawerOpen(false);
          return;
        }
        if (selectedNodeId) {
          setSelectedNodeId(null);
          return;
        }
        if (isFullscreen3D) {
          setIsFullscreen3D(false);
          if (document.fullscreenElement) {
            void document.exitFullscreen().catch(() => {});
          }
        }
        return;
      }

      if (inEditable || mod || ev.altKey) return;

      if (ev.key === '/') {
        ev.preventDefault();
        setPaletteInitialQuery('');
        setPaletteOpen(true);
      } else if (ev.key === '?') {
        ev.preventDefault();
        setPaletteInitialQuery('>');
        setPaletteOpen(true);
      } else if (ev.key === 'F' && ev.shiftKey) {
        ev.preventDefault();
        toggleBrowserNativeFullscreen();
      } else if (lower === 'f') {
        ev.preventDefault();
        toggleFullscreen3D();
      } else if (ev.key === '1') {
        setActiveTab('3d');
      } else if (ev.key === '2') {
        setIsFullscreen3D(false);
        setActiveTab('lineage');
      } else if (ev.key === '3') {
        setIsFullscreen3D(false);
        setActiveTab('gate');
      } else if (ev.key === '4') {
        setIsFullscreen3D(false);
        setActiveTab('index');
      } else if (lower === 't') {
        cycleTierFilter();
      } else if (lower === 'g') {
        setOnlyFlagged((v) => {
          flashToast(!v ? 'Filter: Flagged only' : 'Filter: Showing all nodes');
          return !v;
        });
      } else if (lower === 'c' && selectedNodeId) {
        setIsolateCone((v) => !v);
        setNeighborhoodHops(0);
      } else if (ev.key === '[' || lower === 'k') {
        handleHumanYield('keydown_nav');
        setStepRequest((prev) => ({ seq: (prev?.seq ?? 0) + 1, delta: -1 }));
      } else if (ev.key === ']' || lower === 'j') {
        handleHumanYield('keydown_nav');
        setStepRequest((prev) => ({ seq: (prev?.seq ?? 0) + 1, delta: 1 }));
      } else if (ev.key === '0') {
        handleHumanYield('keydown_nav');
        setSelectedNodeId(null);
        setResetCameraRequest((n) => n + 1);
      } else if (lower === 'p') {
        const nextMode = wytheTheme.polygonMode === 'atomic' ? 'simple' : 'atomic';
        wytheTheme.setPolygonMode(nextMode);
        flashToast(`Polygons: ${nextMode === 'atomic' ? 'Atomic Wythe' : 'Simple Solids'}`);
      } else if (lower === 'd') {
        cycleAppearance();
      } else if (lower === 'v') {
        cycleSceneLens();
      } else if (lower === 'l') {
        toggleSceneLayout();
      } else if (lower === 'b') {
        toggleBlastOverlay();
      } else if (lower === 'w') {
        ev.preventDefault();
        focusCaptureTargetRef.current = 'modal';
        setActiveTab('3d');
        setWhatsThisRequest((n) => n + 1);
      } else if (lower === 'a') {
        ev.preventDefault();
        openAskWytheDrawer();
      } else if (lower === 'r') {
        triggerScan.mutate(undefined, {
          onSuccess: () => flashToast('Rescan complete & receipt sealed'),
        });
      }
    };
    window.addEventListener('keydown', onWinKeyDown);
    return () => window.removeEventListener('keydown', onWinKeyDown);
  }, [
    paletteOpen,
    whatsThisOpen,
    askDrawerOpen,
    selectedNodeId,
    isFullscreen3D,
    copyLlmsBriefNow,
    copySelectedConeNow,
    toggleFullscreen3D,
    toggleBrowserNativeFullscreen,
    cycleTierFilter,
    cycleAppearance,
    cycleSceneLens,
    toggleSceneLayout,
    toggleBlastOverlay,
    openAskWytheDrawer,
    wytheTheme,
    triggerScan,
    flashToast,
  ]);

  const handleAutoDetect = () => {
    const trimmed = newPath.trim();
    if (!trimmed) return;
    detectStack.mutate(trimmed, {
      onSuccess: (det) => {
        setNewProfileSlug(det.recommended_profile_slug);
        setNewBackendSubdir(det.backend_subdir);
        setNewFrontendSubdir(det.frontend_subdir);
        if (!newSlug.trim()) {
          const base = det.repo_path.split('/').filter(Boolean).pop() ?? 'target';
          const normalized = base.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
          setNewSlug(normalized);
          if (!newName.trim()) setNewName(base);
        }
        const sigs = (det.detected_signals ?? []).join(', ') || 'default layout';
        setDetectSummary(
          `Detected ${det.recommended_profile_slug} (${det.confidence}: ${sigs})`,
        );
      },
      onError: (err) => {
        setDetectSummary(`Auto-detect error: ${(err as Error).message}`);
      },
    });
  };

  const handleAddTarget = (e: FormEvent) => {
    e.preventDefault();
    if (!newSlug.trim() || !newPath.trim()) return;
    registerTarget.mutate(
      {
        slug: newSlug.trim(),
        name: newName.trim() || newSlug.trim(),
        repo_path: newPath.trim(),
        stack_profile_slug: newProfileSlug,
        backend_subdir: newBackendSubdir.trim() || '.',
        frontend_subdir: newFrontendSubdir.trim() || '.',
        description: '',
        created_by: 'operator',
      },
      {
        onSuccess: (created) => {
          switchTargetCleanly(created.slug);
          setShowAddTarget(false);
          setNewSlug('');
          setNewName('');
          setNewPath('');
          setDetectSummary(null);
        },
      },
    );
  };

  const tabOrder: WorkspaceTab[] = ['3d', 'lineage', 'gate', 'index'];
  const handleTabKeyDown = (e: KeyboardEvent<HTMLButtonElement>, current: WorkspaceTab) => {
    const idx = tabOrder.indexOf(current);
    let nextTab: WorkspaceTab | null = null;
    if (e.key === 'ArrowRight') {
      nextTab = tabOrder[(idx + 1) % tabOrder.length];
    } else if (e.key === 'ArrowLeft') {
      nextTab = tabOrder[(idx - 1 + tabOrder.length) % tabOrder.length];
    } else if (e.key === 'Home') {
      nextTab = tabOrder[0];
    } else if (e.key === 'End') {
      nextTab = tabOrder[tabOrder.length - 1];
    }
    if (nextTab) {
      e.preventDefault();
      setActiveTab(nextTab);
      tabRefs.current[nextTab]?.focus();
    }
  };

  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main-workspace"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-50 focus:border focus:border-teal-400 focus:bg-slate-950 focus:px-3 focus:py-1.5 focus:font-mono focus:text-xs focus:text-teal-300"
      >
        Skip to main workspace
      </a>

      {/* Top Operational Telemetry Bar */}
      <header className="relative z-40 border-b border-slate-800 bg-slate-950/90 px-5 py-3 backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <WytheBrandLockup
              palette={wytheTheme.palette}
              version={healthz?.version}
              size={28}
            />

            {/* Target Repository Switcher */}
            <div className="flex items-center gap-1.5">
              <select
                id="wythe-target-select"
                aria-label="Target repository"
                value={activeSlug}
                onChange={(e) => {
                  switchTargetCleanly(e.target.value);
                }}
                className="min-h-6 border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-100 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                {loadingTargets && <option value="">Loading targets…</option>}
                {targets.map((t) => (
                  <option key={t.slug} value={t.slug}>
                    {t.name} ({t.slug})
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={() => setShowAddTarget((v) => !v)}
                aria-label="Register repository path"
                title="Register repository path"
                className="inline-flex min-h-6 min-w-6 items-center justify-center border border-slate-800 bg-slate-900 p-1.5 text-slate-300 hover:border-teal-400 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                <Plus className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={() => {
                  setPaletteInitialQuery('');
                  setPaletteOpen(true);
                }}
                aria-label="Open command palette and quick jump"
                title="Search commands, 3-tier nodes, findings & targets (⌘K or /)"
                className="flex min-h-6 min-w-6 items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                <Command className="h-3.5 w-3.5 text-teal-300" />
                <span>Commands</span>
                <kbd className="border border-slate-700 bg-slate-950 px-1 text-[10px] text-slate-300">
                  ⌘K
                </kbd>
              </button>
              <button
                type="button"
                onClick={() => openAskWytheDrawer()}
                aria-label="Open Ask Wythe On-Device AI drawer"
                title="Ask Apple Intelligence, Chrome Gemini Nano, or Local OpenAI /v1 directly about this view (A or ⌘J)"
                className="flex min-h-6 min-w-6 items-center gap-1.5 border border-sky-500/50 bg-sky-500/15 px-2.5 py-1 font-mono text-xs text-sky-200 hover:border-sky-400 hover:bg-sky-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                <Bot className="h-3.5 w-3.5 text-sky-300" />
                <span>Ask AI</span>
                <kbd className="border border-sky-500/40 bg-slate-950 px-1 text-[10px] text-sky-200">
                  A
                </kbd>
              </button>
            </div>
          </div>

          {/* Observation Receipt & Gate Status */}
          <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
            <WytheAppearanceControl
              appearance={wytheTheme.appearance}
              preset={wytheTheme.preset}
              polygonMode={wytheTheme.polygonMode}
              palette={wytheTheme.palette}
              onChangeAppearance={wytheTheme.setAppearance}
              onChangePreset={wytheTheme.setPreset}
              onChangePolygonMode={wytheTheme.setPolygonMode}
              onChangeCustomColor={wytheTheme.updateCustomColor}
              onResetPalette={wytheTheme.resetPalette}
            />
            {report && (
              <>
                <span className="flex items-center gap-1.5 text-slate-300">
                  <GitBranch className="h-3.5 w-3.5 text-slate-400" />
                  <span>
                    {report.source_commit === 'unavailable'
                      ? 'uncommitted'
                      : report.source_commit.slice(0, 10)}
                  </span>
                  {report.worktree_dirty && (
                    <span
                      title="Working tree had uncommitted changes when scanned; files on disk differed from HEAD."
                      className="border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-300"
                    >
                      +{report.dirty_path_count ?? 0} uncommitted
                    </span>
                  )}
                </span>
                <span className="text-slate-400">·</span>
                <span className="text-slate-300">
                  Observed {formatObservedInstant(report.observed_at)} ({report.observation_source})
                </span>
                <span
                  className={`flex items-center gap-1.5 border px-2.5 py-0.5 font-semibold ${
                    report.gate.verdict === 'FAIL'
                      ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                      : report.gate.verdict === 'RATCHET_PASS' ||
                          report.gate.verdict === 'INCOMPLETE'
                        ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                        : 'border-teal-500/40 bg-teal-500/10 text-teal-300'
                  }`}
                >
                  {report.gate.verdict === 'FAIL' ||
                  report.gate.verdict === 'INCOMPLETE' ? (
                    <ShieldAlert className="h-3.5 w-3.5" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  )}
                  GATE: {report.gate.verdict}
                </span>
                <button
                  type="button"
                  disabled={fetchLlmsBrief.isPending}
                  onClick={() => {
                    fetchLlmsBrief.mutate(undefined, {
                      onSuccess: (brief) => {
                        void copyTextToClipboard(brief.markdown).then((ok) => {
                          setCopiedBriefLabel(ok ? `Copied ~${brief.approx_tokens} tok` : 'Copy failed');
                          window.setTimeout(() => setCopiedBriefLabel(null), 2200);
                        });
                      },
                    });
                  }}
                  aria-label="Copy token-budgeted llms.txt architectural map"
                  title="Copy token-budgeted llms.txt pointer map (~2k tokens) for LLMs & coding agents"
                  className="flex min-h-6 min-w-6 items-center gap-1.5 border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-sky-200 hover:bg-sky-500/25 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                >
                  <Copy className="h-3.5 w-3.5" />
                  {copiedBriefLabel ?? 'Copy llms.txt'}
                </button>
                <button
                  type="button"
                  disabled={triggerScan.isPending}
                  onClick={() =>
                    triggerScan.mutate(undefined, {
                      onSuccess: () => {
                        void refreshInvestigationState(activeSessionId);
                        if (activeSessionId) {
                          void atlasApi
                            .compareInvestigationRevisions(activeSessionId)
                            .then(setRevisionComparison)
                            .catch(() => {});
                        }
                      },
                    })
                  }
                  className="flex min-h-6 min-w-6 items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 py-1 text-slate-200 hover:border-teal-400 hover:text-teal-300 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${triggerScan.isPending ? 'animate-spin' : ''}`}
                  />
                  Rescan &amp; Seal Receipt
                </button>
              </>
            )}
          </div>
        </div>

        {/* Inline Target Registration Form */}
        {showAddTarget && (
          <form
            onSubmit={handleAddTarget}
            className="mt-3 space-y-2 border-t border-slate-800 pt-3 font-mono text-xs"
          >
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                aria-label="Repository filesystem path"
                required
                placeholder="/absolute/path/to/repo"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
                className="min-h-6 w-72 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              />
              <button
                type="button"
                disabled={detectStack.isPending || !newPath.trim()}
                onClick={handleAutoDetect}
                className="min-h-6 min-w-6 border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-sky-300 hover:bg-sky-500/25 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                {detectStack.isPending ? 'Detecting…' : 'Auto-Detect Stack'}
              </button>
              <select
                aria-label="Stack profile"
                value={newProfileSlug}
                onChange={(e) => setNewProfileSlug(e.target.value)}
                className="min-h-6 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                {enabledProfiles.map((p) => (
                  <option key={p.slug} value={p.slug}>
                    {p.slug} — {p.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                aria-label="Target slug"
                required
                placeholder="slug (e.g. my-app)"
                value={newSlug}
                onChange={(e) => setNewSlug(e.target.value)}
                className="min-h-6 w-40 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              />
              <input
                type="text"
                aria-label="Target display name"
                placeholder="Display name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="min-h-6 w-44 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              />
              <input
                type="text"
                aria-label="Backend subdirectory"
                placeholder="backend subdir (or .)"
                title="Backend subdirectory relative to repo root (use . for full-stack root)"
                value={newBackendSubdir}
                onChange={(e) => setNewBackendSubdir(e.target.value)}
                className="min-h-6 w-36 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              />
              <input
                type="text"
                aria-label="Frontend subdirectory"
                placeholder="frontend subdir (or .)"
                title="Frontend subdirectory relative to repo root (use . for full-stack root)"
                value={newFrontendSubdir}
                onChange={(e) => setNewFrontendSubdir(e.target.value)}
                className="min-h-6 w-36 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              />
              <button
                type="submit"
                className="min-h-6 min-w-6 border border-teal-500/40 bg-teal-500/15 px-3 py-1 text-teal-300 hover:bg-teal-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
              >
                Register Target
              </button>
              {detectSummary && <span className="text-slate-400">{detectSummary}</span>}
            </div>
          </form>
        )}
      </header>

      {activeSlug && activeSessionId && (
        <InvestigationSessionBar
          activeSlug={activeSlug}
          sessionId={activeSessionId}
          clientId={tabClientId}
          followState={agentCamState.followMode}
          sessionData={investigationSession}
          priorSessions={priorSessions}
          comparison={revisionComparison}
          nodesById={nodesById}
          onToggleFollow={handleToggleAgentFollow}
          onReopenSession={handleReopenSession}
          onNewIndependentSession={handleNewIndependentSession}
          onResetSession={handleResetSession}
          onExportSession={handleExportSession}
          onDeleteSession={handleDeleteSession}
          onCompareRevisions={handleCompareRevisions}
          onSelectNode={setSelectedNodeId}
        />
      )}

      {/* 3-Tier Telemetry Strip + View Navigation */}
      {report && (
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 bg-slate-950/50 px-5 py-2.5 text-xs">
          <div className="flex flex-wrap items-center gap-5 font-mono">
            <span className="flex items-center gap-1.5 text-teal-300">
              <Database className="h-3.5 w-3.5" />
              Truth: <strong>{report.summary.truth_tables}</strong> tables ·{' '}
              <strong>{report.summary.sql_functions}</strong> SQL guards
              {(report.summary.ephemeral_stores ?? 0) > 0 && (
                <>
                  {' '}
                  · <strong>{report.summary.ephemeral_stores}</strong> Redis ephemeral
                </>
              )}
            </span>
            <span className="flex items-center gap-1.5 text-sky-300">
              <FileCode2 className="h-3.5 w-3.5" />
              Manipulate: <strong>{report.summary.manipulator_routes}</strong> routes ·{' '}
              <strong>{report.summary.manipulator_services}</strong> services
            </span>
            <span className="flex items-center gap-1.5 text-blue-300">
              <Globe className="h-3.5 w-3.5" />
              Display: <strong>{report.summary.display_pages}</strong> pages ·{' '}
              <strong>{report.summary.display_hooks_and_clients}</strong> hooks/clients
            </span>
            <span className="flex items-center gap-1.5 text-slate-300">
              <Boxes className="h-3.5 w-3.5 text-teal-400" />
              <strong>{report.summary.verified_edges}</strong> verified edges ·{' '}
              <strong>{report.summary.end_to_end_chains}</strong> E2E chains
            </span>
          </div>

          <div
            role="tablist"
            aria-label="Atlas views"
            className="flex border border-slate-800 bg-slate-950 p-0.5 font-mono text-xs"
          >
            {(
              [
                ['3d', '3D Stratified Atlas'],
                ['lineage', `3-Tier Lineage (${report.summary.end_to_end_chains})`],
                ['gate', `Gate & Rules (${report.findings.length})`],
                ['index', `Index & Adapters (${report.nodes.length})`],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                ref={(el) => {
                  tabRefs.current[key] = el;
                }}
                id={`tab-${key}`}
                role="tab"
                type="button"
                aria-selected={activeTab === key}
                aria-controls={`panel-${key}`}
                tabIndex={activeTab === key ? 0 : -1}
                onClick={() => setActiveTab(key)}
                onKeyDown={(e) => handleTabKeyDown(e, key)}
                className={`min-h-6 px-3 py-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                  activeTab === key
                    ? 'bg-teal-500/20 font-semibold text-teal-300'
                    : 'text-slate-300 hover:text-slate-100'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Split Workspace + Right-Hand Inspector */}
      <div className="grid flex-1 grid-cols-1 lg:grid-cols-12">
        <main id="main-workspace" className="p-5 lg:col-span-9">
          {loadingScan && (
            <div className="flex h-96 items-center justify-center font-mono text-xs text-slate-300">
              Scanning 3-tier syntax trees &amp; verifying cross-tier lineage…
            </div>
          )}
          {scanError && (
            <div className="border border-rose-500/30 bg-rose-950/20 p-5 font-mono text-xs text-rose-300">
              Failed to load scan: {(scanError as Error).message}
            </div>
          )}

          {report && (
            <motion.div
              key={`${activeSlug}-${activeTab}`}
              id={`panel-${activeTab}`}
              role="tabpanel"
              aria-labelledby={`tab-${activeTab}`}
              initial={prefersReducedMotion ? false : { y: 4 }}
              animate={{ y: 0 }}
              transition={{ duration: prefersReducedMotion ? 0 : 0.12 }}
            >
                {activeTab === '3d' && (
                  <div
                    className={
                      isFullscreen3D
                        ? 'fixed inset-0 z-[45] flex h-screen w-screen flex-col bg-slate-950'
                        : 'space-y-3'
                    }
                  >
                    <div
                      className={`space-y-1.5 font-mono text-xs ${
                        isFullscreen3D
                          ? 'border-b border-slate-800 bg-slate-950/95 px-4 py-2 backdrop-blur'
                          : ''
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {isFullscreen3D && (
                            <span className="mr-2 flex items-center gap-2 font-bold text-slate-100">
                              <WytheMark palette={wytheTheme.palette} size={22} />
                              <span>WYTHE</span>
                              <span className="border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] font-normal text-teal-300">
                                {activeSlug}
                              </span>
                            </span>
                          )}
                          <span className="text-slate-300">Stratum:</span>
                          {(['all', 'display', 'manipulate', 'truth'] as const).map((t) => (
                            <button
                              key={t}
                              type="button"
                              onClick={() => setTierFilter(t)}
                              className={`min-h-6 min-w-6 border px-2 py-0.5 uppercase focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                                tierFilter === t
                                  ? 'border-teal-400/60 bg-teal-500/15 text-teal-300'
                                  : 'border-slate-800 bg-slate-950 text-slate-300 hover:text-slate-100'
                              }`}
                            >
                              {t}
                            </button>
                          ))}
                          <select
                            aria-label="Filter 3D nodes by subkind"
                            value={subkindFilter}
                            onChange={(e) =>
                              setSubkindFilter(e.target.value as 'all' | AtlasNode['subkind'])
                            }
                            className="min-h-6 border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            <option value="all">Subkind: All ({ALL_NODE_SUBKINDS.length})</option>
                            {ALL_NODE_SUBKINDS.map((sk) => (
                              <option key={sk} value={sk}>
                                {sk}
                              </option>
                            ))}
                          </select>
                          <select
                            aria-label="Filter 3D edges by kind and verification"
                            value={edgeFilter}
                            onChange={(e) => setEdgeFilter(e.target.value as EdgeFilterMode)}
                            className="min-h-6 border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            <option value="all">Edges: All</option>
                            <option value="writes">Edges: Writes &amp; Mutations</option>
                            <option value="reads">Edges: Reads &amp; Queries</option>
                            <option value="guards">Edges: SQL Guards</option>
                            <option value="helpers">Edges: Hooks / Helpers</option>
                            <option value="verified">Edges: Statically Verified (Solid)</option>
                            <option value="declared">Edges: Declared Only (Dashed)</option>
                            <option value="unverified">Edges: Unverified / Heuristic (Dotted)</option>
                            <option value="broken">Edges: Broken Only (Gap)</option>
                          </select>
                          <input
                            type="search"
                            aria-label="Filter 3D nodes, columns, and routes"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Search node, column, /route…"
                            className="min-h-6 w-48 border border-slate-800 bg-slate-950 px-2.5 py-0.5 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          />
                        </div>
                        <div className="flex flex-wrap items-center gap-3">
                          <label className="flex min-h-6 cursor-pointer items-center gap-1.5 text-slate-300" title="Hide nodes without a connection in this filtered view. Missing connections do not prove code is unused.">
                            <input type="checkbox" checked={connectedOnly}
                              onChange={(e) => setConnectedOnly(e.target.checked)} className="accent-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400" />
                            Connected only
                          </label>
                          <select aria-label="Selected node neighborhood" disabled={!selectedNodeId}
                            value={neighborhoodHops}
                            onChange={(e) => { setNeighborhoodHops(Number(e.target.value) as 0 | 1 | 2); setIsolateCone(false); }}
                            title={selectedNodeId ? 'Follow connections in either direction using the active edge filter' : 'Select a node to focus its neighborhood'}
                            className="min-h-6 border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200 disabled:opacity-40 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400">
                            <option value={0}>Neighborhood: All</option>
                            <option value={1}>Neighborhood: 1 hop</option>
                            <option value={2}>Neighborhood: 2 hops</option>
                          </select>
                          <label className="flex min-h-6 cursor-pointer items-center gap-1.5 text-slate-300">
                            <input
                              type="checkbox"
                              checked={isolateCone}
                              disabled={!selectedNodeId}
                              onChange={(e) => { setIsolateCone(e.target.checked); setNeighborhoodHops(0); }}
                              className="accent-sky-400 disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            />
                            Cone [C]
                          </label>
                          <label className="flex min-h-6 cursor-pointer items-center gap-1.5 text-slate-300">
                            <input
                              type="checkbox"
                              checked={onlyFlagged}
                              onChange={(e) => setOnlyFlagged(e.target.checked)}
                              className="accent-amber-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            />
                            Flagged [G]
                          </label>
                          {isFullscreen3D && (
                            <button
                              type="button"
                              onClick={() => {
                                setPaletteInitialQuery('');
                                setPaletteOpen(true);
                              }}
                              aria-label="Open command palette in fullscreen"
                              className="flex min-h-6 min-w-6 items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              <Command className="h-3 w-3 text-teal-300" />
                              ⌘K
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={toggleFullscreen3D}
                            aria-label={isFullscreen3D ? 'Exit fullscreen 3D view' : 'Expand 3D view to fullscreen'}
                            className="flex min-h-6 min-w-6 items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            {isFullscreen3D ? (
                              <>
                                <Minimize2 className="h-3 w-3 text-teal-300" />
                                Exit [F]
                              </>
                            ) : (
                              <>
                                <Maximize2 className="h-3 w-3 text-teal-300" />
                                Fullscreen [F]
                              </>
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Granular Lens, Layout, 3D Blast Overlay & Packet Trace Bar */}
                      <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px]">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-slate-300">Lens [V]:</span>
                          {(
                            [
                              'status',
                              'contention',
                              'gravity',
                              'subkind',
                              'cluster',
                              'containers',
                            ] as const
                          ).map(
                            (lKey) => (
                              <button
                                key={lKey}
                                type="button"
                                onClick={() => setSceneLens(lKey)}
                                className={`min-h-6 min-w-6 border px-2 py-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                                  sceneLens === lKey
                                    ? 'border-sky-400/60 bg-sky-500/20 text-sky-200'
                                    : 'border-slate-800 bg-slate-950 text-slate-300 hover:text-slate-100'
                                }`}
                              >
                                {SCENE_LENS_LABELS[lKey]}
                              </button>
                            ),
                          )}
                          <div className="flex flex-wrap items-center gap-1.5">
                            <label className="sr-only" htmlFor="scene-layout-select">
                              3D spatial layout arrangement
                            </label>
                            <select
                              id="scene-layout-select"
                              aria-label="3D spatial layout arrangement"
                              value={sceneLayout}
                              onChange={(e) => setSceneLayout(e.target.value as SceneLayoutMode)}
                              className="ml-1 min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              <option value="cluster">Layout [L]: Domain Districts</option>
                              <option value="grid">Layout [L]: Uniform Grid</option>
                              <option value="subkind">Layout [L]: Role Subkinds</option>
                              <option value="connected">Layout [L]: Linked Components</option>
                              <option value="lifecycle_z">Layout [L]: Lifecycle Z-Depth</option>
                              <option value="temporal_z">Layout [L]: Temporal Z-Diff</option>
                            </select>
                            <button
                              type="button"
                              onClick={() => setFlatten2D((v) => !v)}
                              aria-pressed={flatten2D}
                              aria-label="Toggle 2D flat working plane versus 3D stratified tiers"
                              className={`min-h-6 min-w-6 border px-2 py-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                                flatten2D
                                  ? 'border-teal-400/60 bg-teal-950/80 text-teal-200'
                                  : 'border-slate-700 bg-slate-900 text-slate-200 hover:border-teal-400'
                              }`}
                            >
                              {flatten2D ? '2D Flat ✓' : '3D Tiers'}
                            </button>
                            <button
                              type="button"
                              onClick={() => setCompactVisible((v) => !v)}
                              aria-pressed={compactVisible}
                              aria-label="Toggle compact layout around currently visible working set"
                              className={`min-h-6 min-w-6 border px-2 py-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 ${
                                compactVisible
                                  ? 'border-teal-400/60 bg-teal-950/80 text-teal-200'
                                  : 'border-slate-700 bg-slate-900 text-slate-200 hover:border-teal-400'
                              }`}
                            >
                              {compactVisible ? 'Compacted ✓' : 'Compact visible'}
                            </button>
                            <label className="sr-only" htmlFor="scene-group-select">
                              Collapsible node grouping
                            </label>
                            <select
                              id="scene-group-select"
                              aria-label="Collapsible node grouping"
                              value={groupBy}
                              onChange={(e) => {
                                setGroupBy(e.target.value as 'none' | 'cluster' | 'subkind');
                                setCollapsedGroups(new Set());
                              }}
                              className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              <option value="none">Group: Off</option>
                              <option value="cluster">Group: Domain</option>
                              <option value="subkind">Group: Subkind</option>
                            </select>
                            <button
                              type="button"
                              onClick={() => handleCollectVisibleToWorkingSet(true)}
                              aria-label="Isolate visible nodes into a focused working set"
                              className="min-h-6 min-w-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              Isolate visible ({visibleSceneNodeIds.length})
                            </button>
                            <button
                              type="button"
                              onClick={() => handleCollectVisibleToWorkingSet(false)}
                              aria-label="Add visible nodes into the working set"
                              className="min-h-6 min-w-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              + Add visible
                            </button>
                            {workingSetActive && (
                              <button
                                type="button"
                                onClick={() => setWorkingSetActive(false)}
                                aria-label="Show full graph without leaving working set items cleared"
                                className="min-h-6 min-w-6 border border-amber-500/50 bg-amber-950/70 px-2 py-0.5 text-amber-200 hover:border-amber-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                              >
                                Exit set ({workingSetIds.size})
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={handleSaveWorkingView}
                              aria-label="Save current working set and layout view locally"
                              className="min-h-6 min-w-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              Save view
                            </button>
                            {savedViews.filter((v) => v.targetSlug === activeSlug).length > 0 && (
                              <>
                                <label className="sr-only" htmlFor="saved-view-select">
                                  Load saved working view
                                </label>
                                <select
                                  id="saved-view-select"
                                  aria-label="Load saved working view"
                                  value={selectedSavedViewId}
                                  onChange={(e) => {
                                    if (e.target.value) handleLoadSavedView(e.target.value);
                                  }}
                                  className="min-h-6 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                                >
                                  <option value="">Saved views ({savedViews.filter((v) => v.targetSlug === activeSlug).length})...</option>
                                  {savedViews
                                    .filter((v) => v.targetSlug === activeSlug)
                                    .map((v) => (
                                      <option key={v.id} value={v.id}>
                                        {v.name}
                                      </option>
                                    ))}
                                </select>
                              </>
                            )}
                            {(workingSetActive || compactVisible || flatten2D || groupBy !== 'none' || Object.keys(pinnedPositions).length > 0) && (
                              <button
                                type="button"
                                onClick={handleResetOverview}
                                aria-label="Reset working set and layout overrides to overview"
                                className="min-h-6 min-w-6 border border-slate-600 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                              >
                                Reset overview
                              </button>
                            )}
                          </div>
                        </div>

                        <div className="flex flex-wrap items-center gap-1.5">
                          <select
                            aria-label="3D blast radius or snapshot delta overlay"
                            value={blastMode}
                            onChange={(e) =>
                              setBlastMode(e.target.value as 'off' | 'git' | 'snapshot')
                            }
                            className="min-h-6 border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            <option value="off">3D Blast [B]: Off</option>
                            <option value="git">3D Blast: Git Diff ({diffBaseRef})</option>
                            <option value="snapshot" disabled={scanHistory.length < 2}>
                              3D Blast: Snapshot Delta ({scanHistory.length} snaps)
                            </option>
                          </select>
                          {blastMode === 'git' && (
                            <input
                              type="text"
                              aria-label="Git base reference for 3D blast overlay"
                              value={diffBaseRef}
                              onChange={(e) => setDiffBaseRef(e.target.value)}
                              className="min-h-6 w-24 border border-amber-500/40 bg-slate-950 px-1.5 py-0.5 text-amber-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            />
                          )}
                          {blastMode === 'snapshot' && scanHistory.length >= 2 && (
                            <select
                              aria-label="Base snapshot for 3D time scrubber"
                              value={effectiveBaseSnapId ?? ''}
                              onChange={(e) => setSnapBaseId(Number(e.target.value))}
                              className="min-h-6 border border-amber-500/40 bg-slate-950 px-1.5 py-0.5 text-amber-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                            >
                              {scanHistory.slice(1).map((s) => (
                                <option key={s.id} value={s.id}>
                                  vs #{s.id} ({s.source_commit.slice(0, 7)})
                                </option>
                              ))}
                            </select>
                          )}
                          <select
                            aria-label="Animate a verified 3-tier request chain in 3D"
                            value={activeTraceChain?.id ?? ''}
                            onChange={(e) => {
                              const found =
                                report.chains.find((c) => c.id === e.target.value) ?? null;
                              setActiveTraceChain(found);
                            }}
                            className="min-h-6 max-w-[14rem] border border-amber-400/40 bg-slate-950 px-2 py-0.5 text-amber-200 focus:border-teal-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            <option value="">Trace Request in 3D…</option>
                            {report.chains.slice(0, 50).map((c) => (
                              <option key={c.id} value={c.id}>
                                {c.http_method} {c.http_path} ({c.display_label})
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                    </div>
                    {savedViewNotice &&
                      (savedViewNotice.commitChanged ||
                        savedViewNotice.digestChanged ||
                        savedViewNotice.missingNodeIds.length > 0) && (
                        <div
                          role="status"
                          className="flex flex-wrap items-center justify-between gap-2 border border-amber-500/40 bg-amber-950/30 px-3 py-2 font-mono text-[11px] text-amber-200"
                        >
                          <span>
                            {savedViewNotice.statusNote}
                          </span>
                          <button
                            type="button"
                            onClick={() => setSavedViewNotice(null)}
                            aria-label="Dismiss saved view reconciliation warning"
                            className="min-h-6 min-w-6 border border-amber-500/40 px-2 py-0.5 text-amber-100 hover:border-amber-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
                          >
                            Dismiss
                          </button>
                        </div>
                      )}
                    <StratifiedScene3D
                      nodes={report.nodes}
                      edges={report.edges}
                      findings={report.findings}
                      observationSource={report.observation_source}
                      gitDiffReport={gitDiffReport ?? null}
                      snapCompareReport={snapCompareReport ?? null}
                      zWytheSlice={zWytheSlice}
                      activeSlug={activeSlug}
                      sourceCommit={report.source_commit}
                      selectedNodeId={selectedNodeId}
                      tierFilter={tierFilter}
                      subkindFilter={subkindFilter}
                      edgeFilter={edgeFilter}
                      lens={sceneLens}
                      layoutMode={sceneLayout}
                      compactVisible={compactVisible}
                      flatten2D={flatten2D}
                      workingSetIds={workingSetIds}
                      workingSetActive={workingSetActive}
                      groupBy={groupBy}
                      zoomStratum={requestedZoomStratum}
                      collapsedGroups={collapsedGroups}
                      pinnedPositions={pinnedPositions}
                      diffOverlay={diffOverlay}
                      activeTraceChain={activeTraceChain}
                      agentCameraRequest={agentCameraRequest}
                      agentFocusNodeIds={activeFocusNodeSet}
                      agentHighlightEdgeIds={activeHighlightEdgeSet}
                      agentFollowMode={agentCamState.followMode}
                      agentLiveFollowing={agentCamState.liveFollowing}
                      agentHaltedReason={agentCamState.haltedReason}
                      agentCaption={currentAgentBeat?.caption ?? ''}
                      agentTimelineItems={activeTimelineItems}
                      agentTimelineStepIndex={agentCamState.stepIndex}
                      agentTimelinePlaying={agentCamState.isPlaying}
                      agentPermalinkHash={activePermalinkHash}
                      hasPendingAgentCommand={Boolean(agentCamState.pendingEventWhilePaused)}
                      onHumanInputYield={handleHumanYield}
                      onToggleAgentFollow={handleToggleAgentFollow}
                      onRejectPendingAgentCommand={handleRejectPendingAgentCommand}
                      onStepAgentTimeline={handleStepAgentTimeline}
                      onToggleAgentPlay={handleToggleAgentPlay}
                      onExitAgentTimeline={handleExitAgentTimeline}
                      onChangeZWytheSlice={setZWytheSlice}
                      onlyFlagged={onlyFlagged}
                      isolateCone={isolateCone}
                      connectedOnly={connectedOnly}
                      neighborhoodHops={neighborhoodHops}
                      searchQuery={searchQuery}
                      polygonMode={wytheTheme.polygonMode}
                      palette={wytheTheme.palette}
                      polarity={wytheTheme.resolvedPolarity}
                      isFullscreen={isFullscreen3D}
                      stepRequest={stepRequest}
                      resetCameraRequest={resetCameraRequest}
                      whatsThisRequest={whatsThisRequest}
                      onExitTrace={() => setActiveTraceChain(null)}
                      onToggleFullscreen={toggleFullscreen3D}
                      onTogglePolygonMode={() =>
                        wytheTheme.setPolygonMode(
                          wytheTheme.polygonMode === 'atomic' ? 'simple' : 'atomic',
                        )
                      }
                      onHoverFocusChange={setHoverFocusMeta}
                      onTriggerWhatsThis={handleTriggerWhatsThis}
                      onLiveViewportDigest={setLiveViewportDigest}
                      onRegisterLiveCapture={(fn) => {
                        liveCaptureFnRef.current = fn;
                      }}
                      onOpenAskAi={() => openAskWytheDrawer()}
                      onSelectNode={setSelectedNodeId}
                      onToggleWorkingSetNode={handleToggleWorkingSetNode}
                      onToggleCollapseGroup={handleToggleCollapseGroup}
                      onExpandBoundary={handleExpandBoundary}
                      onTogglePinNode={handleTogglePinNode}
                      onResetOverview={handleResetOverview}
                      onVisibleNodeIdsChange={setVisibleSceneNodeIds}
                    />
                    {isFullscreen3D && selectedNode && (
                      <div className="fixed bottom-16 right-4 top-24 z-[46] w-96 max-w-[calc(100vw-2rem)] overflow-y-auto border border-slate-700 bg-slate-950/95 shadow-2xl backdrop-blur">
                        <NodeInspector
                          activeSlug={activeSlug}
                          node={selectedNode}
                          allNodesById={nodesById}
                          edges={report.edges}
                          findings={report.findings}
                          referenceExemplars={govBundle?.reference_exemplars ?? []}
                          diffOverlay={diffOverlay}
                          inWorkingSet={workingSetIds.has(selectedNode.id)}
                          requestedZoomStratum={requestedZoomStratum}
                          sessionId={activeSessionId}
                          clientId={tabClientId}
                          selectedFindingId={selectedFindingId}
                          selectedEdgeId={selectedEdgeId}
                          corrections={investigationSession?.corrections ?? []}
                          evidenceDrifted={Boolean(investigationSession?.evidence_drifted)}
                          revisionComparison={revisionComparison}
                          onCorrectionAdded={handleCorrectionAdded}
                          onCompareRevisions={handleCompareRevisions}
                          onSelectFinding={setSelectedFindingId}
                          onSelectEdge={setSelectedEdgeId}
                          onToggleWorkingSet={handleToggleWorkingSetNode}
                          onSelectNode={setSelectedNodeId}
                          onClose={() => setSelectedNodeId(null)}
                        />
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'lineage' && (
                  <LineageExplorer
                    chains={report.chains}
                    nodesById={nodesById}
                    searchQuery={searchQuery}
                    onSearchQueryChange={setSearchQuery}
                    onSelectNode={setSelectedNodeId}
                    onTraceChain={(chain) => {
                      setActiveTraceChain(chain);
                      setActiveTab('3d');
                    }}
                  />
                )}

                {activeTab === 'gate' && (
                  <GateAndRulesView
                    activeSlug={activeSlug}
                    report={report}
                    rules={rules}
                    vocabularies={vocabularies}
                    onSelectNode={setSelectedNodeId}
                  />
                )}

                {activeTab === 'index' && (
                  <AccessibleIndexView
                    nodes={report.nodes}
                    edges={report.edges}
                    findings={report.findings}
                    observationSource={report.observation_source}
                    gitDiffReport={gitDiffReport ?? null}
                    snapCompareReport={snapCompareReport ?? null}
                    rulings={report.rulings}
                    slots={slots}
                    profiles={profiles}
                    legacyBridge={report.legacy_bridge}
                    scanNotes={report.scan_notes ?? []}
                    agentCameraState={agentCamState}
                    activeAgentCaption={currentAgentBeat?.caption ?? ''}
                    activeAgentFocusIds={currentAgentBeat?.focusNodeIds ?? []}
                    activeSlug={activeSlug}
                    sessionId={activeSessionId}
                    clientId={tabClientId}
                    selectedNodeId={selectedNodeId}
                    selectedFindingId={selectedFindingId}
                    selectedEdgeId={selectedEdgeId}
                    corrections={investigationSession?.corrections ?? []}
                    evidenceDrifted={Boolean(investigationSession?.evidence_drifted)}
                    revisionComparison={revisionComparison}
                    lastReceipt={lastViewportReceipt}
                    onCorrectionAdded={handleCorrectionAdded}
                    onCompareRevisions={handleCompareRevisions}
                    onRejectPendingAgentCommand={handleRejectPendingAgentCommand}
                    onOpenAskAi={() => openAskWytheDrawer()}
                    onToggleAgentFollow={handleToggleAgentFollow}
                    onStepAgentTimeline={handleStepAgentTimeline}
                    onToggleAgentPlay={handleToggleAgentPlay}
                    onExitAgentTimeline={handleExitAgentTimeline}
                    onHumanNavigateYield={() => handleHumanYield('keydown_nav')}
                    onSelectNode={setSelectedNodeId}
                  />
                )}
            </motion.div>
          )}
        </main>

        <div className="lg:col-span-3">
          <NodeInspector
            activeSlug={activeSlug}
            node={selectedNode}
            allNodesById={nodesById}
            edges={report?.edges ?? []}
            findings={report?.findings ?? []}
            referenceExemplars={govBundle?.reference_exemplars ?? []}
            diffOverlay={diffOverlay}
            inWorkingSet={selectedNode ? workingSetIds.has(selectedNode.id) : false}
            requestedZoomStratum={requestedZoomStratum}
            sessionId={activeSessionId}
            clientId={tabClientId}
            selectedFindingId={selectedFindingId}
            selectedEdgeId={selectedEdgeId}
            corrections={investigationSession?.corrections ?? []}
            evidenceDrifted={Boolean(investigationSession?.evidence_drifted)}
            revisionComparison={revisionComparison}
            onCorrectionAdded={handleCorrectionAdded}
            onCompareRevisions={handleCompareRevisions}
            onSelectFinding={setSelectedFindingId}
            onSelectEdge={setSelectedEdgeId}
            onToggleWorkingSet={handleToggleWorkingSetNode}
            onSelectNode={setSelectedNodeId}
            onClose={() => setSelectedNodeId(null)}
          />
        </div>
      </div>

      <WhatsThisModal
        open={whatsThisOpen}
        explanation={whatsThisExplanation}
        snapshotDataUrl={whatsThisSnapshotUrl}
        isLoading={syncUiFocus.isPending || fetchUiFocus.isPending}
        imageCopiedToClipboard={whatsThisImageCopied}
        onAskAi={(prefill) => openAskWytheDrawer(prefill)}
        onClose={() => setWhatsThisOpen(false)}
      />

      <AskWytheDrawer
        open={askDrawerOpen}
        activeSlug={activeSlug}
        sessionId={activeSessionId}
        clientId={tabClientId}
        followState={agentCamState.followMode}
        selectedNodeId={selectedNodeId}
        selectedFindingId={selectedFindingId}
        selectedEdgeId={selectedEdgeId}
        sessionData={investigationSession}
        revisionComparison={revisionComparison}
        explanation={whatsThisExplanation}
        liveDigest={liveViewportDigest}
        snapshotDataUrl={whatsThisSnapshotUrl}
        captureLiveWebp={() => liveCaptureFnRef.current?.() ?? null}
        nodesById={nodesById}
        initialQuestion={askPrefillQuestion}
        onSessionMutated={() => {
          void refreshInvestigationState(activeSessionId);
        }}
        onCorrectionAdded={handleCorrectionAdded}
        onCompareRevisions={handleCompareRevisions}
        onRefreshFocus={() => {
          setActiveTab('3d');
          if (liveCaptureFnRef.current && activeSlug) {
            fetchUiFocus.mutate(
              {
                targetSlug: activeSlug,
                sessionId: activeSessionId,
                clientId: tabClientId,
                selectedEdgeId,
                selectedFindingId,
                followState: agentCamState.followMode,
              },
              {
                onSuccess: (exp) => setWhatsThisExplanation(exp),
              },
            );
          } else {
            focusCaptureTargetRef.current = 'silent';
            setWhatsThisRequest((n) => n + 1);
          }
        }}
        onSelectNode={(nid) => setSelectedNodeId(nid)}
        onClose={() => setAskDrawerOpen(false)}
      />

      {quickToast && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-5 right-5 z-[48] border border-teal-500/50 bg-slate-950/95 px-3.5 py-2 font-mono text-xs text-teal-200 shadow-2xl"
        >
          {quickToast}
        </div>
      )}

      <CommandPalette
        open={paletteOpen}
        initialQuery={paletteInitialQuery}
        actions={quickActions}
        nodes={report?.nodes ?? []}
        findings={(report?.findings ?? []) as BoundaryFinding[]}
        targets={targets}
        activeSlug={activeSlug}
        onClose={() => setPaletteOpen(false)}
        onSelectNode={(nodeId) => {
          setSelectedNodeId(nodeId);
        }}
        onSelectFinding={(f) => {
          setSelectedFindingId(f.id);
          if (f.node_id) {
            setSelectedNodeId(f.node_id);
          } else {
            setIsFullscreen3D(false);
            setActiveTab('gate');
          }
        }}
        onSelectTarget={(slug) => {
          switchTargetCleanly(slug);
        }}
      />
    </div>
  );
}
