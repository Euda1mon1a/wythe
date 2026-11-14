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
  type BoundaryFinding,
  type EndToEndChain,
  type UiFocusExplainRead,
} from '@/api/atlas';
import { AccessibleIndexView } from '@/components/AccessibleIndexView';
import { AskWytheDrawer } from '@/components/AskWytheDrawer';
import { CommandPalette } from '@/components/CommandPalette';
import { GateAndRulesView } from '@/components/GateAndRulesView';
import { LineageExplorer } from '@/components/LineageExplorer';
import { NodeInspector } from '@/components/NodeInspector';
import { WhatsThisModal } from '@/components/WhatsThisModal';
import { WytheAppearanceControl, WytheMark } from '@/components/WytheMark';
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
  useVocabularies,
} from '@/hooks/useAtlas';
import { copyTextToClipboard } from '@/lib/clipboard';
import { formatObservedInstant } from '@/lib/clock';
import type { QuickActionDef } from '@/lib/wytheCommands';
import {
  ALL_NODE_SUBKINDS,
  deriveDomainCluster,
  SCENE_LENS_LABELS,
  type DiffOverlaySet,
  type EdgeFilterMode,
  type SceneLayoutMode,
  type SceneLens,
} from '@/lib/wytheSceneLenses';
import { tryCopyDataUrlPngToClipboard, type LiveViewportDigest } from '@/lib/wytheVisionBridge';
import { registerWytheWebMcpBridge } from '@/lib/wytheBrowserAi';
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
  const [tierFilter, setTierFilter] = useState<'all' | 'truth' | 'manipulate' | 'display'>('all');
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [isolateCone, setIsolateCone] = useState(false);
  const [connectedOnly, setConnectedOnly] = useState(false);
  const [neighborhoodHops, setNeighborhoodHops] = useState<0 | 1 | 2>(0);
  useEffect(() => {
    if (!selectedNodeId) {
      setIsolateCone(false);
      setNeighborhoodHops(0);
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
    if (!activeSlug && targets.length > 0) {
      const preferred = targets.find((t) => t.slug === 'wythe') ?? targets[0];
      setActiveSlug(preferred.slug);
    }
  }, [targets, activeSlug]);

  const { data: report, isLoading: loadingScan, error: scanError } = useTargetScan(activeSlug);
  const { data: rules = [] } = useRules();
  const { data: vocabularies = [] } = useVocabularies();
  const { data: slots = [] } = useAdapterSlots();
  const { data: profiles = [] } = useStackProfiles();
  const { data: govBundle } = useGovernanceBundle(activeSlug);
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
  const { data: gitDiffReport } = useScanDiff(
    activeSlug,
    blastMode === 'git' ? diffBaseRef : '',
  );
  const { data: snapCompareReport } = useCompareSnapshots(
    activeSlug,
    blastMode === 'snapshot' ? effectiveBaseSnapId : null,
    blastMode === 'snapshot' ? latestSnapId : null,
  );

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

  // Debounced zero-copy-paste live sync of human viewport focus to MCP (`wythe_what_is_this`) & CLI (`wythe focus`)
  useEffect(() => {
    if (!activeSlug) return;
    const derivedDistrict =
      (selectedNode ? deriveDomainCluster(selectedNode) : null) ??
      hoverFocusMeta.district;
    const timer = window.setTimeout(() => {
      syncUiFocus.mutate(
        {
          active_slug: activeSlug,
          active_tab: activeTab,
          selected_node_id: selectedNodeId,
          hovered_node_id: hoverFocusMeta.hoveredNodeId,
          focused_district: derivedDistrict,
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
          active_trace_route: activeTraceChain
            ? `${activeTraceChain.http_method} ${activeTraceChain.http_path}`
            : null,
          camera_position: hoverFocusMeta.cameraPosition,
          camera_target: hoverFocusMeta.cameraTarget,
          visible_node_count: hoverFocusMeta.visibleNodeCount,
          in_frustum_count: liveViewportDigest?.inFrustumCount ?? 0,
          visual_headline: hoverFocusMeta.visualHeadline,
          live_viewport_brief: liveViewportDigest?.markdownBrief ?? null,
        },
        {
          onSuccess: () => {
            if (askDrawerOpen) {
              fetchUiFocus.mutate(activeSlug, {
                onSuccess: (exp) => setWhatsThisExplanation(exp),
              });
            }
          },
        },
      );
    }, 260);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    activeSlug,
    activeTab,
    selectedNodeId,
    hoverFocusMeta.hoveredNodeId,
    hoverFocusMeta.district,
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
    activeTraceChain,
    liveViewportDigest?.observedAtIso,
  ]);

  const openAskWytheDrawer = useCallback(
    (prefill?: string) => {
      if (typeof prefill === 'string') setAskPrefillQuestion(prefill);
      setWhatsThisOpen(false);
      setAskDrawerOpen(true);
      if (activeTab === '3d') {
        focusCaptureTargetRef.current = 'drawer';
        setWhatsThisRequest((n) => n + 1);
      } else if (activeSlug) {
        fetchUiFocus.mutate(activeSlug, {
          onSuccess: (exp) => setWhatsThisExplanation(exp),
        });
      }
    },
    [activeTab, activeSlug, fetchUiFocus],
  );

  useEffect(() => {
    if (!activeSlug) return;
    return registerWytheWebMcpBridge({
      getWhatIsThis: () => atlasApi.getUiFocus(activeSlug),
      getLineageCone: (query) => atlasApi.getScanContextCone(activeSlug, query),
      selectNode: (nodeId) => setSelectedNodeId(nodeId),
      openAskDrawer: (q) => openAskWytheDrawer(q),
    });
  }, [activeSlug, openAskWytheDrawer]);

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
      syncUiFocus.mutate(
        {
          active_slug: activeSlug,
          active_tab: activeTab,
          selected_node_id: selectedNodeId,
          hovered_node_id: payload.hoveredNodeId,
          focused_district:
            (selectedNode ? deriveDomainCluster(selectedNode) : null) ?? payload.district,
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
          active_trace_route: activeTraceChain
            ? `${activeTraceChain.http_method} ${activeTraceChain.http_path}`
            : null,
          camera_position: hoverFocusMeta.cameraPosition,
          camera_target: hoverFocusMeta.cameraTarget,
          visible_node_count: hoverFocusMeta.visibleNodeCount,
          in_frustum_count: liveViewportDigest?.inFrustumCount ?? 0,
          visual_headline: payload.visualHeadline,
          live_viewport_brief: liveViewportDigest?.markdownBrief ?? null,
          snapshot_data_url: payload.snapshotDataUrl,
        },
        {
          onSuccess: () => {
            fetchUiFocus.mutate(activeSlug, {
              onSuccess: (exp) => setWhatsThisExplanation(exp),
            });
          },
        },
      );
    },
    [
      activeSlug,
      activeTab,
      selectedNodeId,
      selectedNode,
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
    const order: SceneLens[] = ['status', 'contention', 'gravity', 'subkind', 'cluster'];
    setSceneLens((cur) => {
      const next = order[(order.indexOf(cur) + 1) % order.length];
      flashToast(`3D Lens: ${SCENE_LENS_LABELS[next]}`);
      return next;
    });
  }, [flashToast]);

  const toggleSceneLayout = useCallback(() => {
    setSceneLayout((cur) => {
      const next = cur === 'cluster' ? 'grid' : 'cluster';
      flashToast(`3D Layout: ${next === 'cluster' ? 'Domain Districts' : 'Uniform Grid'}`);
      return next;
    });
  }, [flashToast]);

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
        setStepRequest((prev) => ({ seq: (prev?.seq ?? 0) + 1, delta: -1 }));
      } else if (ev.key === ']' || lower === 'j') {
        setStepRequest((prev) => ({ seq: (prev?.seq ?? 0) + 1, delta: 1 }));
      } else if (ev.key === '0') {
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
          setActiveSlug(created.slug);
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
            <div>
              <div className="flex items-center gap-2.5">
                <WytheMark palette={wytheTheme.palette} size={28} />
                <span className="font-mono text-sm font-bold tracking-wider text-slate-100">
                  WYTHE
                </span>
                <span className="hidden border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-300 2xl:inline-block">
                  Why · ∴ · 3-Tier
                </span>
              </div>
            </div>

            {/* Target Repository Switcher */}
            <div className="flex items-center gap-1.5">
              <select
                id="wythe-target-select"
                aria-label="Target repository"
                value={activeSlug}
                onChange={(e) => {
                  setActiveSlug(e.target.value);
                  setSelectedNodeId(null);
                }}
                className="border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-100 focus:border-teal-400 focus:outline-none"
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
                className="border border-slate-800 bg-slate-900 p-1.5 text-slate-300 hover:border-teal-400 hover:text-teal-300"
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
                className="flex items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300"
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
                className="flex items-center gap-1.5 border border-sky-500/50 bg-sky-500/15 px-2.5 py-1 font-mono text-xs text-sky-200 hover:border-sky-400 hover:bg-sky-500/25"
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
                      : report.gate.verdict === 'RATCHET_PASS'
                        ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                        : 'border-teal-500/40 bg-teal-500/10 text-teal-300'
                  }`}
                >
                  {report.gate.verdict === 'FAIL' ? (
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
                  className="flex items-center gap-1.5 border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-sky-200 hover:bg-sky-500/25 disabled:opacity-50"
                >
                  <Copy className="h-3.5 w-3.5" />
                  {copiedBriefLabel ?? 'Copy llms.txt'}
                </button>
                <button
                  type="button"
                  disabled={triggerScan.isPending}
                  onClick={() => triggerScan.mutate()}
                  className="flex items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 py-1 text-slate-200 hover:border-teal-400 hover:text-teal-300 disabled:opacity-50"
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
                className="w-72 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400"
              />
              <button
                type="button"
                disabled={detectStack.isPending || !newPath.trim()}
                onClick={handleAutoDetect}
                className="border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-sky-300 hover:bg-sky-500/25 disabled:opacity-50"
              >
                {detectStack.isPending ? 'Detecting…' : 'Auto-Detect Stack'}
              </button>
              <select
                aria-label="Stack profile"
                value={newProfileSlug}
                onChange={(e) => setNewProfileSlug(e.target.value)}
                className="border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100"
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
                className="w-40 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400"
              />
              <input
                type="text"
                aria-label="Target display name"
                placeholder="Display name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-44 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400"
              />
              <input
                type="text"
                aria-label="Backend subdirectory"
                placeholder="backend subdir (or .)"
                title="Backend subdirectory relative to repo root (use . for full-stack root)"
                value={newBackendSubdir}
                onChange={(e) => setNewBackendSubdir(e.target.value)}
                className="w-36 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400"
              />
              <input
                type="text"
                aria-label="Frontend subdirectory"
                placeholder="frontend subdir (or .)"
                title="Frontend subdirectory relative to repo root (use . for full-stack root)"
                value={newFrontendSubdir}
                onChange={(e) => setNewFrontendSubdir(e.target.value)}
                className="w-36 border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-100 placeholder:text-slate-400"
              />
              <button
                type="submit"
                className="border border-teal-500/40 bg-teal-500/15 px-3 py-1 text-teal-300 hover:bg-teal-500/25"
              >
                Register Target
              </button>
              {detectSummary && <span className="text-slate-400">{detectSummary}</span>}
            </div>
          </form>
        )}
      </header>

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
                className={`px-3 py-1 transition-colors focus:outline-none focus:ring-2 focus:ring-teal-400 ${
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
                              className={`border px-2 py-0.5 uppercase ${
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
                            className="border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200"
                          >
                            <option value="all">Subkind: All (11)</option>
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
                            className="border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200"
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
                            className="w-48 border border-slate-800 bg-slate-950 px-2.5 py-0.5 text-slate-100 placeholder:text-slate-400 focus:border-teal-400 focus:outline-none"
                          />
                        </div>
                        <div className="flex flex-wrap items-center gap-3">
                          <label className="flex cursor-pointer items-center gap-1.5 text-slate-300" title="Hide nodes without a connection in this filtered view. Missing connections do not prove code is unused.">
                            <input type="checkbox" checked={connectedOnly}
                              onChange={(e) => setConnectedOnly(e.target.checked)} className="accent-teal-400" />
                            Connected only
                          </label>
                          <select aria-label="Selected node neighborhood" disabled={!selectedNodeId}
                            value={neighborhoodHops}
                            onChange={(e) => { setNeighborhoodHops(Number(e.target.value) as 0 | 1 | 2); setIsolateCone(false); }}
                            title={selectedNodeId ? 'Follow connections in either direction using the active edge filter' : 'Select a node to focus its neighborhood'}
                            className="border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200 disabled:opacity-40">
                            <option value={0}>Neighborhood: All</option>
                            <option value={1}>Neighborhood: 1 hop</option>
                            <option value={2}>Neighborhood: 2 hops</option>
                          </select>
                          <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                            <input
                              type="checkbox"
                              checked={isolateCone}
                              disabled={!selectedNodeId}
                              onChange={(e) => { setIsolateCone(e.target.checked); setNeighborhoodHops(0); }}
                              className="accent-sky-400 disabled:opacity-40"
                            />
                            Cone [C]
                          </label>
                          <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                            <input
                              type="checkbox"
                              checked={onlyFlagged}
                              onChange={(e) => setOnlyFlagged(e.target.checked)}
                              className="accent-amber-400"
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
                              className="flex items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 hover:text-teal-300"
                            >
                              <Command className="h-3 w-3 text-teal-300" />
                              ⌘K
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={toggleFullscreen3D}
                            aria-label={isFullscreen3D ? 'Exit fullscreen 3D view' : 'Expand 3D view to fullscreen'}
                            className="flex items-center gap-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400 hover:text-teal-300"
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
                          {(['status', 'contention', 'gravity', 'subkind', 'cluster'] as const).map(
                            (lKey) => (
                              <button
                                key={lKey}
                                type="button"
                                onClick={() => setSceneLens(lKey)}
                                className={`border px-2 py-0.5 ${
                                  sceneLens === lKey
                                    ? 'border-sky-400/60 bg-sky-500/20 text-sky-200'
                                    : 'border-slate-800 bg-slate-950 text-slate-300 hover:text-slate-100'
                                }`}
                              >
                                {SCENE_LENS_LABELS[lKey]}
                              </button>
                            ),
                          )}
                          <button
                            type="button"
                            onClick={toggleSceneLayout}
                            className="ml-1 border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400"
                          >
                            Layout [L]: {sceneLayout === 'cluster' ? 'Districts' : 'Grid'}
                          </button>
                        </div>

                        <div className="flex flex-wrap items-center gap-1.5">
                          <select
                            aria-label="3D blast radius or snapshot delta overlay"
                            value={blastMode}
                            onChange={(e) =>
                              setBlastMode(e.target.value as 'off' | 'git' | 'snapshot')
                            }
                            className="border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-200"
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
                              className="w-24 border border-amber-500/40 bg-slate-950 px-1.5 py-0.5 text-amber-200"
                            />
                          )}
                          {blastMode === 'snapshot' && scanHistory.length >= 2 && (
                            <select
                              aria-label="Base snapshot for 3D time scrubber"
                              value={effectiveBaseSnapId ?? ''}
                              onChange={(e) => setSnapBaseId(Number(e.target.value))}
                              className="border border-amber-500/40 bg-slate-950 px-1.5 py-0.5 text-amber-200"
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
                            className="max-w-[14rem] border border-amber-400/40 bg-slate-950 px-2 py-0.5 text-amber-200"
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
                    <StratifiedScene3D
                      nodes={report.nodes}
                      edges={report.edges}
                      findings={report.findings}
                      activeSlug={activeSlug}
                      sourceCommit={report.source_commit}
                      selectedNodeId={selectedNodeId}
                      tierFilter={tierFilter}
                      subkindFilter={subkindFilter}
                      edgeFilter={edgeFilter}
                      lens={sceneLens}
                      layoutMode={sceneLayout}
                      diffOverlay={diffOverlay}
                      activeTraceChain={activeTraceChain}
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
                    rulings={report.rulings}
                    slots={slots}
                    profiles={profiles}
                    legacyBridge={report.legacy_bridge}
                    scanNotes={report.scan_notes ?? []}
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
        explanation={whatsThisExplanation}
        liveDigest={liveViewportDigest}
        snapshotDataUrl={whatsThisSnapshotUrl}
        captureLiveWebp={() => liveCaptureFnRef.current?.() ?? null}
        nodesById={nodesById}
        initialQuestion={askPrefillQuestion}
        onRefreshFocus={() => {
          focusCaptureTargetRef.current = 'silent';
          setActiveTab('3d');
          setWhatsThisRequest((n) => n + 1);
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
          if (f.node_id) {
            setSelectedNodeId(f.node_id);
          } else {
            setIsFullscreen3D(false);
            setActiveTab('gate');
          }
        }}
        onSelectTarget={(slug) => {
          setActiveSlug(slug);
          setSelectedNodeId(null);
        }}
      />
    </div>
  );
}
