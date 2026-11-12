'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Bot, Crosshair, Maximize2, Minimize2, Play, Sparkles, X } from 'lucide-react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import type { AtlasEdge, AtlasNode, BoundaryFinding, EndToEndChain } from '@/api/atlas';
import { createAtomicDeltahedra, createWytheAtomicMaterial } from '@/lib/wytheAtomicShader';
import {
  computeScenePositions,
  deriveDomainCluster,
  evaluateEdgeVisual,
  evaluateNodeVisual,
  getLensLegendItems,
  SCENE_LENS_LABELS,
  type DiffOverlaySet,
  type EdgeFilterMode,
  type SceneLayoutMode,
  type SceneLens,
} from '@/lib/wytheSceneLenses';
import {
  WYTHE_PRESETS,
  type PolygonRenderMode,
  type WythePaletteColors,
} from '@/lib/wytheTheme';
import {
  buildLiveViewportDigest,
  captureAnnotatedXrayPng,
  captureCompactViewportWebp,
  computeVisualFocusFiducial,
  type LiveViewportDigest,
} from '@/lib/wytheVisionBridge';

interface StratifiedScene3DProps {
  nodes: AtlasNode[];
  edges: AtlasEdge[];
  findings?: BoundaryFinding[];
  activeSlug?: string;
  sourceCommit?: string;
  selectedNodeId: string | null;
  tierFilter: 'all' | 'truth' | 'manipulate' | 'display';
  subkindFilter?: 'all' | AtlasNode['subkind'];
  edgeFilter?: EdgeFilterMode;
  lens?: SceneLens;
  layoutMode?: SceneLayoutMode;
  diffOverlay?: DiffOverlaySet | null;
  activeTraceChain?: EndToEndChain | null;
  onlyFlagged: boolean;
  isolateCone?: boolean;
  searchQuery?: string;
  polygonMode?: PolygonRenderMode;
  palette?: WythePaletteColors;
  polarity?: 'dark' | 'light';
  isFullscreen?: boolean;
  stepRequest?: { seq: number; delta: -1 | 1 } | null;
  resetCameraRequest?: number;
  whatsThisRequest?: number;
  onExitTrace?: () => void;
  onToggleFullscreen?: () => void;
  onTogglePolygonMode?: () => void;
  onHoverFocusChange?: (info: {
    hoveredNodeId: string | null;
    district: string | null;
    visualHeadline: string | null;
    cameraPosition: string | null;
    cameraTarget: string | null;
    visibleNodeCount: number;
  }) => void;
  onTriggerWhatsThis?: (payload: {
    snapshotDataUrl: string | null;
    hoveredNodeId: string | null;
    district: string | null;
    visualHeadline: string | null;
  }) => void;
  onLiveViewportDigest?: (digest: LiveViewportDigest) => void;
  onRegisterLiveCapture?: (fn: () => string | null) => void;
  onOpenAskAi?: () => void;
  onSelectNode: (nodeId: string | null) => void;
}

interface HoverTip {
  nodeId: string;
  x: number;
  y: number;
  label: string;
  tier: string;
  subkind: string;
  status: string;
  cluster: string;
  metrics: string;
}

const MAX_VISIBLE_NODES = 660;

function rankNodeDeterministic(n: AtlasNode, connectedIds: Set<string>): number {
  if (n.status === 'duplicated_truth') return 1;
  if (n.status === 'policy_in_code' || n.status === 'gray_zone') return 2;
  if (n.subkind === 'sql_function' || n.subkind === 'cache_store' || n.subkind === 'solver') {
    return 3;
  }
  if (n.status === 'clean' && connectedIds.has(n.id)) return 4;
  if (n.status === 'clean') return 5;
  return 6;
}

function selectStratifiedNodesStable(
  filtered: AtlasNode[],
  maxTotal: number,
  connectedIds: Set<string>,
  pinnedIds: Set<string>,
): AtlasNode[] {
  if (filtered.length <= maxTotal) return filtered;
  const tiers: Array<AtlasNode['tier']> = ['display', 'manipulate', 'truth'];
  const buckets: Record<AtlasNode['tier'], AtlasNode[]> = {
    display: [],
    manipulate: [],
    truth: [],
  };
  for (const n of filtered) {
    buckets[n.tier].push(n);
  }
  for (const t of tiers) {
    buckets[t].sort(
      (a, b) =>
        rankNodeDeterministic(a, connectedIds) - rankNodeDeterministic(b, connectedIds) ||
        a.id.localeCompare(b.id),
    );
  }

  const activeTiers = tiers.filter((t) => buckets[t].length > 0);
  let base: AtlasNode[];
  if (activeTiers.length <= 1) {
    base = filtered
      .slice()
      .sort(
        (a, b) =>
          rankNodeDeterministic(a, connectedIds) - rankNodeDeterministic(b, connectedIds) ||
          a.id.localeCompare(b.id),
      )
      .slice(0, maxTotal);
  } else {
    const quotas: Record<AtlasNode['tier'], number> = { display: 0, manipulate: 0, truth: 0 };
    let remaining = maxTotal;
    const pending = [...activeTiers];
    while (pending.length > 0 && remaining > 0) {
      const share = Math.max(1, Math.floor(remaining / pending.length));
      let settledAny = false;
      for (let i = pending.length - 1; i >= 0; i -= 1) {
        const t = pending[i];
        if (buckets[t].length - quotas[t] <= share) {
          const take = buckets[t].length - quotas[t];
          quotas[t] += take;
          remaining -= take;
          pending.splice(i, 1);
          settledAny = true;
        }
      }
      if (!settledAny) {
        for (const t of pending) {
          const take = Math.min(share, remaining, buckets[t].length - quotas[t]);
          quotas[t] += take;
          remaining -= take;
        }
        break;
      }
    }
    for (const t of pending) {
      while (remaining > 0 && quotas[t] < buckets[t].length) {
        quotas[t] += 1;
        remaining -= 1;
      }
    }
    base = [
      ...buckets.display.slice(0, quotas.display),
      ...buckets.manipulate.slice(0, quotas.manipulate),
      ...buckets.truth.slice(0, quotas.truth),
    ];
  }

  if (pinnedIds.size === 0) return base;
  const present = new Set(base.map((n) => n.id));
  const extras = filtered.filter((n) => pinnedIds.has(n.id) && !present.has(n.id));
  return extras.length > 0 ? [...base, ...extras] : base;
}

function disposeGroupContents(group: THREE.Group) {
  const seenGeos = new Set<THREE.BufferGeometry>();
  const seenMats = new Set<THREE.Material>();
  group.traverse((obj) => {
    const meshOrLine = obj as THREE.Mesh | THREE.Line;
    if (meshOrLine.geometry) {
      seenGeos.add(meshOrLine.geometry);
    }
    const mat = meshOrLine.material;
    if (Array.isArray(mat)) {
      mat.forEach((m) => seenMats.add(m));
    } else if (mat) {
      seenMats.add(mat);
    }
  });
  group.clear();
  seenGeos.forEach((g) => g.dispose());
  seenMats.forEach((m) => m.dispose());
}

export function StratifiedScene3D({
  nodes,
  edges,
  findings = [],
  activeSlug = 'wythe',
  sourceCommit = '',
  selectedNodeId,
  tierFilter,
  subkindFilter = 'all',
  edgeFilter = 'all',
  lens = 'status',
  layoutMode = 'cluster',
  diffOverlay = null,
  activeTraceChain = null,
  onlyFlagged,
  isolateCone = false,
  searchQuery = '',
  polygonMode = 'atomic',
  palette,
  polarity = 'dark',
  isFullscreen = false,
  stepRequest = null,
  resetCameraRequest = 0,
  whatsThisRequest = 0,
  onExitTrace,
  onToggleFullscreen,
  onTogglePolygonMode,
  onHoverFocusChange,
  onTriggerWhatsThis,
  onLiveViewportDigest,
  onRegisterLiveCapture,
  onOpenAskAi,
  onSelectNode,
}: StratifiedScene3DProps) {
  const activePalette = palette ?? WYTHE_PRESETS.stratified[polarity];
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hoverTip, setHoverTip] = useState<HoverTip | null>(null);
  const [webglUnavailable, setWebglUnavailable] = useState(false);
  const [fitSerial, setFitSerial] = useState(0);
  const [camSettleSeq, setCamSettleSeq] = useState(0);
  const camSettleTimerRef = useRef<number | null>(null);

  // Persistent WebGL refs so node selection / lens switches NEVER recreate camera or OrbitControls
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const ambientRef = useRef<THREE.AmbientLight | null>(null);
  const contentGroupRef = useRef<THREE.Group | null>(null);
  const pickablesRef = useRef<THREE.Mesh[]>([]);
  const nodeByMeshRef = useRef<Map<THREE.Object3D, AtlasNode>>(new Map());
  const atomicMaterialsRef = useRef<THREE.ShaderMaterial[]>([]);
  const traceWaypointsRef = useRef<THREE.Vector3[]>([]);
  const selectedNodeIdRef = useRef<string | null>(selectedNodeId);
  const onSelectNodeRef = useRef(onSelectNode);
  const tierFilterRef = useRef(tierFilter);

  selectedNodeIdRef.current = selectedNodeId;
  onSelectNodeRef.current = onSelectNode;
  tierFilterRef.current = tierFilter;

  const syncCameraTelemetry = useCallback(() => {
    const canvas = canvasRef.current;
    const cam = cameraRef.current;
    const ctrl = controlsRef.current;
    if (!canvas || !cam || !ctrl) return;
    canvas.dataset.camPos = cam.position
      .toArray()
      .map((v) => v.toFixed(3))
      .join(',');
    canvas.dataset.camTarget = ctrl.target
      .toArray()
      .map((v) => v.toFixed(3))
      .join(',');
    if (camSettleTimerRef.current !== null) {
      window.clearTimeout(camSettleTimerRef.current);
    }
    camSettleTimerRef.current = window.setTimeout(() => {
      setCamSettleSeq((s) => s + 1);
    }, 160);
  }, []);

  const { connectedNodeIds, degreeByNode, guardedTableIds, mutatorNodeIds } = useMemo(() => {
    const connected = new Set<string>();
    const deg = new Map<string, number>();
    const guarded = new Set<string>();
    const mutators = new Set<string>();
    for (const e of edges) {
      connected.add(e.source_id);
      connected.add(e.target_id);
      deg.set(e.source_id, (deg.get(e.source_id) ?? 0) + 1);
      deg.set(e.target_id, (deg.get(e.target_id) ?? 0) + 1);
      if (e.kind === 'guards_truth') {
        guarded.add(e.target_id);
      }
      if (e.kind === 'writes_truth' || e.kind === 'mutates_endpoint') {
        mutators.add(e.source_id);
      }
    }
    return {
      connectedNodeIds: connected,
      degreeByNode: deg,
      guardedTableIds: guarded,
      mutatorNodeIds: mutators,
    };
  }, [edges]);

  const coneNodeIds = useMemo(() => {
    const cone = new Set<string>();
    if (!selectedNodeId) return cone;
    const fwd = new Map<string, string[]>();
    const rev = new Map<string, string[]>();
    for (const e of edges) {
      const fList = fwd.get(e.source_id) ?? [];
      fList.push(e.target_id);
      fwd.set(e.source_id, fList);
      const rList = rev.get(e.target_id) ?? [];
      rList.push(e.source_id);
      rev.set(e.target_id, rList);
    }
    const bfs = (adj: Map<string, string[]>) => {
      const q = [selectedNodeId];
      const visited = new Set<string>([selectedNodeId]);
      while (q.length > 0) {
        const cur = q.shift()!;
        cone.add(cur);
        for (const nxt of adj.get(cur) ?? []) {
          if (!visited.has(nxt)) {
            visited.add(nxt);
            q.push(nxt);
          }
        }
      }
    };
    bfs(fwd);
    bfs(rev);
    return cone;
  }, [edges, selectedNodeId]);

  const traceHopIds = useMemo(() => {
    if (!activeTraceChain) return [];
    const raw = [
      activeTraceChain.display_node_id,
      ...(activeTraceChain.via_node_ids ?? []),
      activeTraceChain.route_node_id,
      ...(activeTraceChain.manipulator_node_ids ?? []),
      ...(activeTraceChain.truth_table_ids ?? []).slice(0, 2),
    ].filter(Boolean);
    const deduped: string[] = [];
    for (const id of raw) {
      if (deduped[deduped.length - 1] !== id) {
        deduped.push(id);
      }
    }
    return deduped;
  }, [activeTraceChain]);

  const traceHopSet = useMemo(() => new Set(traceHopIds), [traceHopIds]);

  const { visibleNodes, totalFilteredCount, visibleByTier } = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const pinned = new Set<string>(traceHopIds);
    if (selectedNodeId) pinned.add(selectedNodeId);

    const filtered = nodes.filter((n) => {
      if (pinned.has(n.id)) return true;
      if (isolateCone && selectedNodeId && !coneNodeIds.has(n.id)) return false;
      if (tierFilter !== 'all' && n.tier !== tierFilter && !(isolateCone && coneNodeIds.has(n.id))) {
        return false;
      }
      if (subkindFilter !== 'all' && n.subkind !== subkindFilter) {
        return false;
      }
      if (onlyFlagged && n.status === 'clean' && !coneNodeIds.has(n.id)) {
        return false;
      }
      if (
        q &&
        !n.label.toLowerCase().includes(q) &&
        !n.source_file.toLowerCase().includes(q) &&
        !(n.columns ?? []).some((c) => c.toLowerCase().includes(q)) &&
        !(n.http_paths ?? []).some((p) => p.toLowerCase().includes(q))
      ) {
        return false;
      }
      return true;
    });
    const chosen = selectStratifiedNodesStable(
      filtered,
      MAX_VISIBLE_NODES,
      connectedNodeIds,
      pinned,
    );
    const counts = { display: 0, manipulate: 0, truth: 0 };
    for (const n of chosen) {
      counts[n.tier] += 1;
    }
    return { visibleNodes: chosen, totalFilteredCount: filtered.length, visibleByTier: counts };
  }, [
    nodes,
    tierFilter,
    subkindFilter,
    onlyFlagged,
    isolateCone,
    searchQuery,
    selectedNodeId,
    coneNodeIds,
    connectedNodeIds,
    traceHopIds,
  ]);

  const positions = useMemo(
    () => computeScenePositions(visibleNodes, layoutMode),
    [visibleNodes, layoutMode],
  );

  const nodesById = useMemo(() => {
    const m = new Map<string, AtlasNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  const selectedNodeObj = selectedNodeId ? nodesById.get(selectedNodeId) ?? null : null;

  const stepSelection = useCallback(
    (delta: -1 | 1) => {
      if (visibleNodes.length === 0) return;
      const curIdx = selectedNodeId ? visibleNodes.findIndex((n) => n.id === selectedNodeId) : -1;
      const nextIdx =
        curIdx < 0
          ? delta > 0
            ? 0
            : visibleNodes.length - 1
          : (curIdx + delta + visibleNodes.length) % visibleNodes.length;
      onSelectNode(visibleNodes[nextIdx].id);
    },
    [visibleNodes, selectedNodeId, onSelectNode],
  );

  useEffect(() => {
    if (!stepRequest) return;
    stepSelection(stepRequest.delta);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stepRequest?.seq]);

  useEffect(() => {
    if (resetCameraRequest > 0) {
      setFitSerial((s) => s + 1);
    }
  }, [resetCameraRequest]);

  const centerCameraOnSelected = useCallback(() => {
    if (!selectedNodeId || !positions.has(selectedNodeId)) return;
    const cam = cameraRef.current;
    const ctrl = controlsRef.current;
    if (!cam || !ctrl) return;
    const [sx, sy, sz] = positions.get(selectedNodeId)!;
    const offset = cam.position.clone().sub(ctrl.target);
    ctrl.target.set(sx, sy, sz);
    cam.position.copy(ctrl.target).add(offset);
    ctrl.update();
    syncCameraTelemetry();
  }, [selectedNodeId, positions, syncCameraTelemetry]);

  // 1. Mount-once WebGL context, camera, OrbitControls, raycaster & animation loop
  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;

    const ctxAttrs: WebGLContextAttributes = {
      antialias: true,
      preserveDrawingBuffer: true,
    };
    const glProbe =
      canvas.getContext('webgl2', ctxAttrs) || canvas.getContext('webgl', ctxAttrs);
    if (!glProbe) {
      setWebglUnavailable(true);
      return;
    }

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        canvas,
        context: glProbe as WebGLRenderingContext,
        antialias: true,
        preserveDrawingBuffer: true,
      });
    } catch {
      setWebglUnavailable(true);
      return;
    }

    const scene = new THREE.Scene();
    sceneRef.current = scene;

    const camera = new THREE.PerspectiveCamera(46, 1, 0.1, 520);
    camera.position.set(44, 24, 72);
    cameraRef.current = camera;

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const controls = new OrbitControls(camera, canvas);
    controls.enableDamping = !prefersReducedMotion;
    controls.dampingFactor = 0.08;
    controls.target.set(0, -1, 0);
    controlsRef.current = controls;
    controls.addEventListener('change', syncCameraTelemetry);

    const ambient = new THREE.AmbientLight(0xffffff, 0.8);
    ambientRef.current = ambient;
    scene.add(ambient);

    const dirLight = new THREE.DirectionalLight(0x93c5fd, 1.15);
    dirLight.position.set(28, 55, 36);
    scene.add(dirLight);

    const contentGroup = new THREE.Group();
    contentGroupRef.current = contentGroup;
    scene.add(contentGroup);

    // Animated request-packet orb for "Follow a Request" 3D trace
    const packetGroup = new THREE.Group();
    packetGroup.visible = false;
    const packetCore = new THREE.Mesh(
      new THREE.SphereGeometry(0.68, 18, 18),
      new THREE.MeshBasicMaterial({ color: 0xfacc15 }),
    );
    const packetHalo = new THREE.Mesh(
      new THREE.SphereGeometry(1.25, 16, 16),
      new THREE.MeshBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0.34,
        depthWrite: false,
      }),
    );
    packetGroup.add(packetCore, packetHalo);
    scene.add(packetGroup);

    const resize = () => {
      const w = container.clientWidth || 800;
      const h = container.clientHeight || 520;
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    };
    resize();
    syncCameraTelemetry();

    const ro = new ResizeObserver(() => resize());
    ro.observe(container);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();

    const hitTest = (ev: PointerEvent): AtlasNode | null => {
      const rect = canvas.getBoundingClientRect();
      if (!rect.width || !rect.height) return null;
      pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(pickablesRef.current, false);
      return hits.length > 0 ? nodeByMeshRef.current.get(hits[0].object) ?? null : null;
    };

    const onMove = (ev: PointerEvent) => {
      const hit = hitTest(ev);
      if (!hit) {
        setHoverTip(null);
        canvas.style.cursor = 'grab';
        return;
      }
      const rect = container.getBoundingClientRect();
      canvas.style.cursor = 'pointer';
      const rw =
        hit.tier === 'truth'
          ? ` · R:${hit.read_by_count ?? 0} W:${hit.written_by_count ?? 0}`
          : '';
      setHoverTip({
        nodeId: hit.id,
        x: ev.clientX - rect.left + 12,
        y: ev.clientY - rect.top + 12,
        label: hit.label,
        tier: hit.tier,
        subkind: hit.subkind,
        status: hit.status,
        cluster: deriveDomainCluster(hit),
        metrics: rw,
      });
    };

    let downX = 0;
    let downY = 0;
    const onPointerDown = (ev: PointerEvent) => {
      downX = ev.clientX;
      downY = ev.clientY;
    };

    const onClick = (ev: MouseEvent) => {
      if (Math.hypot(ev.clientX - downX, ev.clientY - downY) > 5) {
        return;
      }
      const hit = hitTest(ev as unknown as PointerEvent);
      const curSelected = selectedNodeIdRef.current;
      if (hit) {
        onSelectNodeRef.current(hit.id === curSelected ? null : hit.id);
      } else if (curSelected !== null) {
        onSelectNodeRef.current(null);
      }
    };

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onMove);
    canvas.addEventListener('click', onClick);

    let raf = 0;
    const tStart = performance.now();
    const animate = () => {
      raf = requestAnimationFrame(animate);
      const elapsed = (performance.now() - tStart) * 0.001;
      if (!prefersReducedMotion && atomicMaterialsRef.current.length > 0) {
        for (const m of atomicMaterialsRef.current) {
          m.uniforms.uTime.value = elapsed;
        }
      }
      const wps = traceWaypointsRef.current;
      if (wps.length >= 2) {
        packetGroup.visible = true;
        const segCount = wps.length - 1;
        const progress = prefersReducedMotion ? 0.5 : (elapsed * 0.65) % segCount;
        const segIdx = Math.min(segCount - 1, Math.floor(progress));
        const alpha = progress - segIdx;
        packetGroup.position.lerpVectors(wps[segIdx], wps[segIdx + 1], alpha);
        const pulse = 1.0 + 0.22 * Math.sin(elapsed * 5.0);
        packetHalo.scale.setScalar(pulse);
      } else {
        packetGroup.visible = false;
      }
      controls.update();
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      controls.removeEventListener('change', syncCameraTelemetry);
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointermove', onMove);
      canvas.removeEventListener('click', onClick);
      disposeGroupContents(contentGroup);
      packetCore.geometry.dispose();
      (packetCore.material as THREE.Material).dispose();
      packetHalo.geometry.dispose();
      (packetHalo.material as THREE.Material).dispose();
      controls.dispose();
      renderer.dispose();
    };
  }, [syncCameraTelemetry]);

  // 2. Explicit Camera Reset ONLY when user triggers Reset Camera (fitSerial > 0)
  useEffect(() => {
    if (fitSerial === 0) return;
    const cam = cameraRef.current;
    const ctrl = controlsRef.current;
    if (!cam || !ctrl) return;
    const tf = tierFilterRef.current;
    const focusY = tf === 'display' ? 18 : tf === 'truth' ? -18 : tf === 'manipulate' ? 0 : -1;
    cam.position.set(tf === 'all' ? 44 : 34, tf === 'all' ? 24 : focusY + 22, tf === 'all' ? 72 : 54);
    ctrl.target.set(0, focusY, 0);
    ctrl.update();
    syncCameraTelemetry();
  }, [fitSerial, syncCameraTelemetry]);

  // 3. Scene-Content Sync: updates meshes/lines/planes WITHOUT moving camera or OrbitControls!
  useEffect(() => {
    const scene = sceneRef.current;
    const contentGroup = contentGroupRef.current;
    if (!scene || !contentGroup) return;

    const bgColor = new THREE.Color(activePalette.sceneBg);
    scene.background = bgColor;
    scene.fog = new THREE.Fog(bgColor.getHex(), 95, 260);
    if (ambientRef.current) {
      ambientRef.current.intensity = polarity === 'light' ? 0.92 : 0.78;
    }

    disposeGroupContents(contentGroup);
    const pickables: THREE.Mesh[] = [];
    const nodeByMesh = new Map<THREE.Object3D, AtlasNode>();
    const atomicMaterials: THREE.ShaderMaterial[] = [];

    // Reference planes
    for (const [y, tintHex] of [
      [18, activePalette.display],
      [0, activePalette.manipulate],
      [-18, activePalette.truth],
    ] as const) {
      const tint = new THREE.Color(tintHex);
      const planeGeo = new THREE.PlaneGeometry(118, 86);
      const planeMat = new THREE.MeshBasicMaterial({
        color: tint,
        transparent: true,
        opacity: polarity === 'light' ? 0.055 : 0.032,
        side: THREE.DoubleSide,
        depthWrite: false,
      });
      const plane = new THREE.Mesh(planeGeo, planeMat);
      plane.rotation.x = -Math.PI / 2;
      plane.position.y = y - 0.65;
      contentGroup.add(plane);

      if (polygonMode === 'simple') {
        const grid = new THREE.GridHelper(
          108,
          18,
          tint.getHex(),
          polarity === 'light' ? 0xcbd5e1 : 0x1e293b,
        );
        grid.position.y = y - 0.62;
        (grid.material as THREE.Material).transparent = true;
        (grid.material as THREE.Material).opacity = 0.18;
        contentGroup.add(grid);
      }
    }

    const sharedDelta = polygonMode === 'atomic' ? createAtomicDeltahedra() : null;
    const simpleGeos =
      polygonMode === 'simple'
        ? {
            cache: new THREE.TorusGeometry(0.68, 0.22, 12, 24),
            sqlGuard: new THREE.OctahedronGeometry(0.72, 0),
            truth: new THREE.CylinderGeometry(0.75, 0.75, 0.9, 18),
            solver: new THREE.IcosahedronGeometry(0.92, 0),
            manipulate: new THREE.OctahedronGeometry(0.82, 0),
            display: new THREE.BoxGeometry(1.15, 0.55, 1.15),
          }
        : null;

    visibleNodes.forEach((n, idx) => {
      const pos = positions.get(n.id);
      if (!pos) return;
      const isSelected = n.id === selectedNodeId;
      const inTrace = traceHopSet.has(n.id);
      const inCone = (selectedNodeId !== null && coneNodeIds.has(n.id)) || inTrace;
      const deg = degreeByNode.get(n.id) ?? 0;

      const vis = evaluateNodeVisual({
        node: n,
        lens,
        palette: activePalette,
        degree: deg,
        guardedTableIds,
        mutatorNodeIds,
        diffOverlay,
      });

      const isDimmed =
        vis.forceDim ||
        (traceHopIds.length > 0 && !inTrace && !isSelected) ||
        (selectedNodeId !== null && !inCone && traceHopIds.length === 0);

      let mesh: THREE.Mesh;
      if (polygonMode === 'atomic' && sharedDelta) {
        const geo =
          n.subkind === 'cache_store'
            ? sharedDelta.cache
            : n.subkind === 'sql_function'
              ? sharedDelta.sqlGuard
              : n.subkind === 'solver'
                ? sharedDelta.solver
                : n.tier === 'truth'
                  ? sharedDelta.truth
                  : n.tier === 'manipulate'
                    ? sharedDelta.manipulate
                    : sharedDelta.display;
        const mat = createWytheAtomicMaterial({
          barColor: vis.barHex,
          inquiryColor: vis.inquiryHex,
          hollow: vis.hollow,
          flagged: vis.flagged,
          dimmed: isDimmed,
          selected: isSelected || inTrace,
          inCone,
          phase: (idx * 0.67) % (Math.PI * 2),
        });
        atomicMaterials.push(mat);
        mesh = new THREE.Mesh(geo, mat);
      } else {
        const geo =
          n.subkind === 'cache_store'
            ? simpleGeos!.cache
            : n.subkind === 'sql_function'
              ? simpleGeos!.sqlGuard
              : n.subkind === 'solver'
                ? simpleGeos!.solver
                : n.tier === 'truth'
                  ? simpleGeos!.truth
                  : n.tier === 'manipulate'
                    ? simpleGeos!.manipulate
                    : simpleGeos!.display;
        const col = new THREE.Color(vis.barHex).getHex();
        const mat = new THREE.MeshStandardMaterial({
          color: col,
          emissive: col,
          emissiveIntensity: isSelected || inTrace ? 0.95 : inCone ? 0.62 : isDimmed ? 0.08 : 0.3,
          wireframe: vis.hollow,
          transparent: isDimmed,
          opacity: isDimmed ? 0.2 : 1.0,
          roughness: 0.35,
          metalness: 0.2,
        });
        mesh = new THREE.Mesh(geo, mat);
      }

      if (n.subkind === 'cache_store') {
        mesh.rotation.x = Math.PI / 2;
      }
      mesh.position.set(pos[0], pos[1], pos[2]);
      const mult = isSelected ? 1.58 : inTrace ? 1.38 : inCone ? 1.18 : 1.0;
      mesh.scale.setScalar(vis.scale * mult);
      contentGroup.add(mesh);
      pickables.push(mesh);
      nodeByMesh.set(mesh, n);
    });

    // Edges with 8-EdgeKind + VerificationState styling
    const maxEdges = 1050;
    let drawn = 0;
    for (const e of edges) {
      if (drawn >= maxEdges) break;
      const p1 = positions.get(e.source_id);
      const p2 = positions.get(e.target_id);
      if (!p1 || !p2) continue;
      const edgeVis = evaluateEdgeVisual(e, edgeFilter);
      if (!edgeVis.visible) continue;

      const inConeEdge =
        (selectedNodeId !== null && coneNodeIds.has(e.source_id) && coneNodeIds.has(e.target_id)) ||
        (traceHopSet.has(e.source_id) && traceHopSet.has(e.target_id));
      if (selectedNodeId && !inConeEdge && edges.length > 350 && drawn > 200) continue;

      const pts = [new THREE.Vector3(...p1), new THREE.Vector3(...p2)];
      const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);
      const isCrossTier = Math.abs(p1[1] - p2[1]) > 4;
      const opacity = inConeEdge
        ? 0.94
        : selectedNodeId || traceHopIds.length > 0
          ? 0.08
          : edgeFilter !== 'all'
            ? 0.68
            : isCrossTier
              ? 0.36
              : 0.18;
      const lineMat = new THREE.LineBasicMaterial({
        color: edgeVis.hex,
        transparent: true,
        opacity,
      });
      contentGroup.add(new THREE.Line(lineGeo, lineMat));
      drawn += 1;
    }

    // Active Request Trace Waypoints + Golden Trajectory Beam
    const wps: THREE.Vector3[] = [];
    for (const id of traceHopIds) {
      const p = positions.get(id);
      if (p) wps.push(new THREE.Vector3(...p));
    }
    traceWaypointsRef.current = wps;
    if (wps.length >= 2) {
      const traceGeo = new THREE.BufferGeometry().setFromPoints(wps);
      const traceMat = new THREE.LineBasicMaterial({
        color: 0xfacc15,
        transparent: true,
        opacity: 0.96,
      });
      contentGroup.add(new THREE.Line(traceGeo, traceMat));
    }

    pickablesRef.current = pickables;
    nodeByMeshRef.current = nodeByMesh;
    atomicMaterialsRef.current = atomicMaterials;
  }, [
    visibleNodes,
    edges,
    positions,
    selectedNodeId,
    coneNodeIds,
    polygonMode,
    activePalette,
    polarity,
    lens,
    edgeFilter,
    diffOverlay,
    degreeByNode,
    guardedTableIds,
    mutatorNodeIds,
    traceHopIds,
    traceHopSet,
  ]);

  const legendItems = useMemo(
    () => getLensLegendItems(lens, Boolean(diffOverlay)),
    [lens, diffOverlay],
  );

  const visualFiducial = useMemo(
    () =>
      computeVisualFocusFiducial({
        nodes,
        findings,
        selectedNodeId,
        hoveredNodeId: hoverTip?.nodeId ?? null,
        diffOverlay,
        lens,
      }),
    [nodes, findings, selectedNodeId, hoverTip?.nodeId, diffOverlay, lens],
  );

  useEffect(() => {
    if (!onHoverFocusChange) return;
    const canvas = canvasRef.current;
    onHoverFocusChange({
      hoveredNodeId: hoverTip?.nodeId ?? null,
      district: visualFiducial?.district ?? null,
      visualHeadline: visualFiducial
        ? `${visualFiducial.headline} — ${visualFiducial.reason}`
        : null,
      cameraPosition: canvas?.dataset.camPos ?? null,
      cameraTarget: canvas?.dataset.camTarget ?? null,
      visibleNodeCount: visibleNodes.length,
    });
  }, [hoverTip?.nodeId, visualFiducial, visibleNodes.length, onHoverFocusChange]);

  useEffect(() => {
    if (!onRegisterLiveCapture) return;
    onRegisterLiveCapture(() => captureCompactViewportWebp(canvasRef.current, 1024, 0.82));
  }, [onRegisterLiveCapture]);

  useEffect(() => {
    if (!onLiveViewportDigest || visibleNodes.length === 0) return;
    const cam = cameraRef.current;
    let projectToNdc: ((x: number, y: number, z: number) => [number, number, number]) | null = null;
    if (cam) {
      cam.updateMatrixWorld();
      const scratch = new THREE.Vector3();
      projectToNdc = (x: number, y: number, z: number) => {
        scratch.set(x, y, z).project(cam);
        return [scratch.x, scratch.y, scratch.z];
      };
    }
    const digest = buildLiveViewportDigest({
      activeSlug,
      sourceCommit,
      projectToNdc,
      visibleNodes,
      positions,
      edges,
      findings,
      selectedNodeId,
      hoveredNodeId: hoverTip?.nodeId ?? null,
      coneNodeIds,
      lens,
      layoutMode,
      tierFilter,
      subkindFilter,
      onlyFlagged,
      searchQuery,
      diffOverlay,
      palette: activePalette,
      degreeByNode,
      guardedTableIds,
      mutatorNodeIds,
    });
    onLiveViewportDigest(digest);
  }, [
    onLiveViewportDigest,
    activeSlug,
    sourceCommit,
    visibleNodes,
    positions,
    edges,
    findings,
    selectedNodeId,
    hoverTip?.nodeId,
    coneNodeIds,
    lens,
    layoutMode,
    tierFilter,
    subkindFilter,
    onlyFlagged,
    searchQuery,
    diffOverlay,
    activePalette,
    degreeByNode,
    guardedTableIds,
    mutatorNodeIds,
    camSettleSeq,
  ]);

  const triggerWhatsThisSnapshot = useCallback(() => {
    if (!onTriggerWhatsThis) return;
    const canvas = canvasRef.current;
    const snap = canvas
      ? captureAnnotatedXrayPng(canvas, {
          targetSlug: activeSlug,
          sourceCommit,
          lensLabel: diffOverlay ? `${SCENE_LENS_LABELS[lens]} + ${diffOverlay.label}` : SCENE_LENS_LABELS[lens],
          headline: visualFiducial?.headline ?? `3D Stratified Lattice (${visibleNodes.length} visible nodes)`,
          reason: visualFiducial?.reason ?? `Viewing ${activeSlug} across 3 tiers`,
        })
      : null;
    onTriggerWhatsThis({
      snapshotDataUrl: snap,
      hoveredNodeId: hoverTip?.nodeId ?? null,
      district: visualFiducial?.district ?? null,
      visualHeadline: visualFiducial
        ? `${visualFiducial.headline} — ${visualFiducial.reason}`
        : null,
    });
  }, [
    onTriggerWhatsThis,
    activeSlug,
    sourceCommit,
    diffOverlay,
    lens,
    visualFiducial,
    visibleNodes.length,
    hoverTip?.nodeId,
  ]);

  const prevWhatsThisReq = useRef(0);
  useEffect(() => {
    if (whatsThisRequest > prevWhatsThisReq.current) {
      prevWhatsThisReq.current = whatsThisRequest;
      triggerWhatsThisSnapshot();
    }
  }, [whatsThisRequest, triggerWhatsThisSnapshot]);

  if (webglUnavailable) {
    return (
      <div className="flex h-[34rem] flex-col items-center justify-center border border-slate-800 bg-slate-950 p-8 text-center">
        <p className="font-mono text-xs uppercase tracking-widest text-amber-400">WebGL Unavailable</p>
        <p className="mt-2 max-w-md text-sm text-slate-300">
          Hardware 3D context could not be initialized in this browser environment. Switch to{' '}
          <strong className="text-slate-100">3-Tier Lineage</strong> or{' '}
          <strong className="text-slate-100">Index &amp; Adapters</strong> for full keyboard-accessible inspection.
        </p>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      style={{ backgroundColor: activePalette.sceneBg }}
      className={`relative w-full overflow-hidden ${
        isFullscreen ? 'h-full flex-1 border-0' : 'h-[35rem] border border-slate-800'
      }`}
    >
      <canvas
        ref={canvasRef}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            e.preventDefault();
            onSelectNode(null);
          } else if (e.key === '[' || e.key === 'ArrowLeft') {
            e.preventDefault();
            stepSelection(-1);
          } else if (e.key === ']' || e.key === 'ArrowRight') {
            e.preventDefault();
            stepSelection(1);
          } else if (e.key.toLowerCase() === 'm' && selectedNodeId) {
            e.preventDefault();
            centerCameraOnSelected();
          } else if (e.key.toLowerCase() === 'w') {
            e.preventDefault();
            triggerWhatsThisSnapshot();
          }
        }}
        className="block h-full w-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-teal-400"
        aria-label="3D Stratified Wythe Atlas — use Left and Right Arrow keys or Prev/Next buttons to step through nodes"
      />

      <div className="sr-only" aria-live="polite">
        {selectedNodeObj
          ? `Selected ${selectedNodeObj.tier} ${selectedNodeObj.subkind} ${selectedNodeObj.label}, status ${selectedNodeObj.status}, ${coneNodeIds.size} nodes in transitive 3-tier lineage cone.`
          : `Showing ${visibleNodes.length} nodes across 3D stratified atlas.`}
      </div>

      {/* Stratum Labels */}
      <div className="pointer-events-none absolute left-4 top-4 space-y-1.5 font-mono text-[11px]">
        <div className="flex items-center gap-2 text-blue-300">
          <span className="inline-block h-2 w-2" style={{ backgroundColor: activePalette.display }} />
          <span>
            TOP PLANE · FRONTEND DISPLAY ({polygonMode === 'atomic' ? 'Hex-12' : 'Boxes'} · {visibleByTier.display})
          </span>
        </div>
        <div className="flex items-center gap-2 text-sky-300">
          <span className="inline-block h-2 w-2 rotate-45" style={{ backgroundColor: activePalette.manipulate }} />
          <span>
            MID PLANE · BACKEND MANIPULATION ({polygonMode === 'atomic' ? 'Octa-8 / Solver-20' : 'Octahedra'} · {visibleByTier.manipulate})
          </span>
        </div>
        <div className="flex items-center gap-2 text-teal-300">
          <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: activePalette.truth }} />
          <span>
            BEDROCK · SQL TRUTH, GUARDS &amp; QUEUES ({polygonMode === 'atomic' ? 'Icosa-20 / Guard-8' : 'Cylinders'} · {visibleByTier.truth})
          </span>
        </div>
        {selectedNodeId && coneNodeIds.size > 0 && (
          <div className="mt-1 inline-block border border-sky-500/40 bg-slate-950/90 px-2 py-0.5 text-sky-300">
            Lineage Cone: <strong>{coneNodeIds.size}</strong> connected nodes (sky=read, amber=write, lime=SQL guard)
          </div>
        )}
        {diffOverlay && (
          <div className="mt-1 block border border-amber-500/40 bg-slate-950/90 px-2 py-0.5 text-amber-200">
            3D Blast Overlay ({diffOverlay.label}):{' '}
            <strong>{diffOverlay.touchedIds.size + diffOverlay.addedIds.size}</strong> touched ·{' '}
            <strong>{diffOverlay.impactedIds.size}</strong> impacted ·{' '}
            <strong>{diffOverlay.newFindingNodeIds.size}</strong> new findings
          </div>
        )}
        {visualFiducial && (
          <div
            className={`mt-1 max-w-xl border bg-slate-950/95 px-2.5 py-1 leading-snug backdrop-blur ${
              visualFiducial.tone === 'crimson'
                ? 'border-rose-500/50 text-rose-200'
                : visualFiducial.tone === 'amber'
                  ? 'border-amber-500/50 text-amber-200'
                  : 'border-teal-500/50 text-teal-200'
            }`}
          >
            <div className="font-semibold">
              X-Ray [{activeSlug}@{sourceCommit.slice(0, 8)}] · {visualFiducial.headline}
            </div>
            <div className="text-[10px] text-slate-200">{visualFiducial.reason}</div>
          </div>
        )}
      </div>

      {/* Animated Request Packet Trace Narrator HUD */}
      {activeTraceChain && traceHopIds.length > 0 && (
        <div className="absolute right-4 top-4 z-10 max-w-md border border-amber-400/50 bg-slate-950/95 p-3 font-mono text-xs shadow-2xl backdrop-blur">
          <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5">
            <span className="flex items-center gap-1.5 font-semibold text-amber-300">
              <Play className="h-3.5 w-3.5 fill-amber-300" />
              Live 3D Request Packet Trace ({activeTraceChain.http_method} {activeTraceChain.http_path})
            </span>
            {onExitTrace && (
              <button
                type="button"
                onClick={onExitTrace}
                aria-label="Exit 3D request trace"
                className="text-slate-300 hover:text-slate-100"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <p className="mt-1.5 font-sans text-[11px] leading-relaxed text-slate-200">
            Follow the glowing packet from <strong className="text-blue-300">Display UI</strong>{' '}
            down through typed hooks/HTTP routes into{' '}
            <strong className="text-sky-300">Backend Manipulation</strong> and{' '}
            <strong className="text-teal-300">SQL Bedrock</strong>. Click any hop to inspect its code without moving your camera:
          </p>
          <div className="mt-2 flex max-h-28 flex-wrap gap-1 overflow-y-auto pr-1">
            {traceHopIds.map((hid, idx) => {
              const hopNode = nodesById.get(hid);
              const isCur = hid === selectedNodeId;
              return (
                <button
                  key={hid}
                  type="button"
                  onClick={() => onSelectNode(hid)}
                  className={`border px-1.5 py-0.5 text-[10px] ${
                    isCur
                      ? 'border-amber-300 bg-amber-500/25 text-amber-100'
                      : 'border-slate-700 bg-slate-900 text-slate-200 hover:border-teal-400'
                  }`}
                >
                  {idx + 1}. {hopNode?.label ?? hid}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Camera / Keyboard / Legend Bar */}
      <div className="absolute bottom-3 left-4 right-4 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3 bg-slate-950/90 px-3 py-1.5 font-mono text-[11px] text-slate-200 backdrop-blur">
          {legendItems.map((item) => (
            <span key={item.label} className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
              {item.label}
            </span>
          ))}
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 border border-slate-300" />{' '}
            {polygonMode === 'atomic' ? 'hollow = unwired' : 'wireframe = unwired'}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {onTriggerWhatsThis && (
            <button
              type="button"
              onClick={triggerWhatsThisSnapshot}
              aria-label="What's This — sync live 3D X-Ray to MCP and open annotated vision card"
              title="Zero copy-paste Human <-> Vision/MCP Bridge: sync live cluster/node X-Ray & annotated PNG [W]"
              className="flex items-center gap-1 border border-teal-400/60 bg-teal-500/20 px-2.5 py-1 font-mono text-xs font-medium text-teal-200 hover:bg-teal-500/30"
            >
              <Sparkles className="h-3.5 w-3.5" />
              What&apos;s This? [W]
            </button>
          )}
          {onOpenAskAi && (
            <button
              type="button"
              onClick={onOpenAskAi}
              aria-label="Ask Wythe On-Device AI about this 3D view"
              title="Ask Apple Intelligence, Chrome Gemini Nano, or Local OpenAI /v1 directly about this view [A]"
              className="flex items-center gap-1 border border-sky-400/60 bg-sky-500/20 px-2.5 py-1 font-mono text-xs font-medium text-sky-200 hover:bg-sky-500/30"
            >
              <Bot className="h-3.5 w-3.5" />
              Ask AI [A]
            </button>
          )}
          {onTogglePolygonMode && (
            <button
              type="button"
              onClick={onTogglePolygonMode}
              className="border border-slate-700 bg-slate-900/90 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300"
            >
              {polygonMode === 'atomic' ? 'Mode: Atomic [P]' : 'Mode: Simple [P]'}
            </button>
          )}
          {selectedNodeId && (
            <>
              <button
                type="button"
                onClick={centerCameraOnSelected}
                aria-label="Center camera on selected node"
                title="Opt-in: smoothly center orbit pivot on selected node without changing zoom angle"
                className="flex items-center gap-1 border border-sky-500/40 bg-sky-950/80 px-2.5 py-1 font-mono text-xs text-sky-200 hover:border-sky-400"
              >
                <Crosshair className="h-3 w-3" />
                Center [M]
              </button>
              <button
                type="button"
                onClick={() => onSelectNode(null)}
                aria-label="Clear selected node"
                className="border border-rose-500/40 bg-rose-950/80 px-2.5 py-1 font-mono text-xs text-rose-200 hover:border-rose-400 hover:text-rose-100"
              >
                Clear (Esc)
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => stepSelection(-1)}
            aria-label="Select previous node in 3D atlas"
            className="border border-slate-700 bg-slate-900/90 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300"
          >
            ← Prev
          </button>
          <button
            type="button"
            onClick={() => stepSelection(1)}
            aria-label="Select next node in 3D atlas"
            className="border border-slate-700 bg-slate-900/90 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300"
          >
            Next →
          </button>
          <button
            type="button"
            onClick={() => setFitSerial((s) => s + 1)}
            className="border border-slate-700 bg-slate-900/90 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400 hover:text-teal-300"
          >
            Reset Camera (
            {visibleNodes.length < totalFilteredCount
              ? `${visibleNodes.length}/${totalFilteredCount}`
              : `${visibleNodes.length}`}{' '}
            nodes)
          </button>
          {onToggleFullscreen && (
            <button
              type="button"
              onClick={onToggleFullscreen}
              aria-label={isFullscreen ? 'Exit fullscreen 3D mode' : 'Enter fullscreen 3D mode'}
              className="flex items-center gap-1.5 border border-teal-500/50 bg-teal-500/15 px-2.5 py-1 font-mono text-xs text-teal-300 hover:bg-teal-500/25"
            >
              {isFullscreen ? (
                <>
                  <Minimize2 className="h-3.5 w-3.5" />
                  Exit Fullscreen [F]
                </>
              ) : (
                <>
                  <Maximize2 className="h-3.5 w-3.5" />
                  Fullscreen [F]
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {hoverTip && (
        <div
          style={{ left: hoverTip.x, top: hoverTip.y }}
          className="pointer-events-none absolute z-20 border border-slate-700 bg-slate-950/95 px-2.5 py-1.5 font-mono text-xs shadow-xl"
        >
          <div className="font-semibold text-slate-100">{hoverTip.label}</div>
          <div className="text-[11px] text-slate-300">
            {hoverTip.tier} · {hoverTip.subkind} · {hoverTip.cluster}
            {hoverTip.metrics} · <span className="text-teal-300">{hoverTip.status}</span>
          </div>
        </div>
      )}
    </div>
  );
}
