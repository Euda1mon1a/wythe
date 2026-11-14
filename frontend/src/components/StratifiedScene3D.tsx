'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Bot, Crosshair, Maximize2, Minimize2, Play, Sparkles, X } from 'lucide-react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import type { AtlasEdge, AtlasNode, BoundaryFinding, EndToEndChain } from '@/api/atlas';
import { selectSceneGraph, type NeighborhoodHops } from '@/lib/wytheSceneGraph';
import { createBatchedNodes, createBatchedEdges, fitGraphCamera, type SceneRenderNode, type SceneRenderEdge, type SceneRenderStats } from '@/lib/wytheSceneBatches';
import {
  computeScenePositions,
  deriveDomainCluster,
  evaluateEdgeVisual,
  evaluateNodeVisual,
  getEdgeVerificationLegendItems,
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
  connectedOnly?: boolean;
  neighborhoodHops?: NeighborhoodHops;
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

function disposeGroupContents(group: THREE.Group) {
  const seenGeos = new Set<THREE.BufferGeometry>();
  const seenMats = new Set<THREE.Material>();
  group.traverse((obj) => {
    if (obj instanceof THREE.InstancedMesh) obj.dispose();
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
  connectedOnly = false,
  neighborhoodHops = 0,
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
  const nodeBatchRef = useRef<ReturnType<typeof createBatchedNodes> | null>(null);
  const lodDirtyRef = useRef(true);
  const [renderStats, setRenderStats] = useState<SceneRenderStats>({ total: 0, inFrustum: 0, detailed: 0, overview: 0 });
  const atomicMaterialsRef = useRef<THREE.ShaderMaterial[]>([]);
  const traceWaypointsRef = useRef<THREE.Vector3[]>([]);
  const selectedNodeIdRef = useRef<string | null>(selectedNodeId);
  const onSelectNodeRef = useRef(onSelectNode);


  selectedNodeIdRef.current = selectedNodeId;
  onSelectNodeRef.current = onSelectNode;


  const syncCameraTelemetry = useCallback(() => {
    lodDirtyRef.current = true;
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
      if (nodeBatchRef.current) setRenderStats({ ...nodeBatchRef.current.stats });
    }, 160);
  }, []);

  const { degreeByNode, guardedTableIds, mutatorNodeIds } = useMemo(() => {
    const deg = new Map<string, number>();
    const guarded = new Set<string>();
    const mutators = new Set<string>();
    for (const e of edges) {
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
      for (let index = 0; index < q.length; index += 1) {
        const cur = q[index];
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
      ...(activeTraceChain.truth_table_ids ?? []),
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

  const graph = useMemo(() => selectSceneGraph(nodes, edges, {
    tier: tierFilter, subkind: subkindFilter, edgeFilter, onlyFlagged, connectedOnly,
    searchQuery, selectedId: selectedNodeId, traceIds: traceHopSet, coneIds: coneNodeIds,
    isolateCone, neighborhoodHops,
  }), [nodes, edges, tierFilter, subkindFilter, edgeFilter, onlyFlagged, connectedOnly,
    searchQuery, selectedNodeId, traceHopSet, coneNodeIds, isolateCone, neighborhoodHops]);
  const { nodes: visibleNodes, edges: visibleEdges, counts: visibleByTier } = graph;

  // Filtering and camera motion never repack the map: only a layout/source change does.
  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const positions = useMemo(() => computeScenePositions(nodes, layoutMode), [nodes, layoutMode]);

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
    controls.zoomToCursor = true;
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
      syncCameraTelemetry();
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
      return nodeBatchRef.current?.pick(raycaster, ev.clientX - rect.left, ev.clientY - rect.top) ?? null;
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
      if (lodDirtyRef.current && nodeBatchRef.current) {
        const stats = nodeBatchRef.current.update(camera, container.clientWidth || 800, container.clientHeight || 520, renderer.getPixelRatio());
        canvas.dataset.detailedNodes = String(stats.detailed);
        canvas.dataset.overviewNodes = String(stats.overview);
        canvas.dataset.representedNodes = String(stats.total);
        lodDirtyRef.current = false;
      }
      renderer.render(scene, camera);
      canvas.dataset.drawCalls = String(renderer.info.render.calls);
    };
    animate();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      if (camSettleTimerRef.current !== null) window.clearTimeout(camSettleTimerRef.current);
      nodeBatchRef.current = null;
      lastFitRef.current = null;
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

  // Fit on a new map/layout or an explicit request, never on selection/filter changes.
  const lastFitRef = useRef<{ positions: typeof positions; serial: number } | null>(null);
  useEffect(() => {
    if (lastFitRef.current?.positions === positions && lastFitRef.current?.serial === fitSerial) return;
    const cam = cameraRef.current;
    const ctrl = controlsRef.current;
    if (!cam || !ctrl) return;
    const points = visibleNodes.flatMap((node) => {
      const position = positions.get(node.id);
      return position ? [position] : [];
    });
    ctrl.target.copy(fitGraphCamera(cam, points));
    ctrl.maxDistance = cam.far / 2;
    ctrl.update();
    lastFitRef.current = { positions, serial: fitSerial };
    syncCameraTelemetry();
  }, [fitSerial, positions, visibleNodes, syncCameraTelemetry]);

  // 3. Scene-Content Sync: updates meshes/lines/planes WITHOUT moving camera or OrbitControls!
  useEffect(() => {
    const scene = sceneRef.current;
    const contentGroup = contentGroupRef.current;
    if (!scene || !contentGroup) return;

    const bgColor = new THREE.Color(activePalette.sceneBg);
    scene.background = bgColor;
    scene.fog = null;
    if (ambientRef.current) {
      ambientRef.current.intensity = polarity === 'light' ? 0.92 : 0.78;
    }

    disposeGroupContents(contentGroup);
    const bounds = new THREE.Box3();
    for (const position of positions.values()) bounds.expandByPoint(new THREE.Vector3(...position));
    const planeWidth = bounds.isEmpty() ? 118 : Math.max(30, bounds.max.x - bounds.min.x + 12);
    const planeDepth = bounds.isEmpty() ? 86 : Math.max(30, bounds.max.z - bounds.min.z + 12);
    const planeCenter = bounds.isEmpty() ? new THREE.Vector3() : bounds.getCenter(new THREE.Vector3());

    // Reference planes
    for (const [y, tintHex] of [
      [18, activePalette.display],
      [0, activePalette.manipulate],
      [-18, activePalette.truth],
    ] as const) {
      const tint = new THREE.Color(tintHex);
      const planeGeo = new THREE.PlaneGeometry(planeWidth, planeDepth);
      const planeMat = new THREE.MeshBasicMaterial({
        color: tint,
        transparent: true,
        opacity: polarity === 'light' ? 0.055 : 0.032,
        side: THREE.DoubleSide,
        depthWrite: false,
      });
      const plane = new THREE.Mesh(planeGeo, planeMat);
      plane.rotation.x = -Math.PI / 2;
      plane.position.set(planeCenter.x, y - 0.65, planeCenter.z);
      contentGroup.add(plane);

      if (polygonMode === 'simple') {
        const grid = new THREE.GridHelper(
          Math.max(planeWidth, planeDepth),
          24,
          tint.getHex(),
          polarity === 'light' ? 0xcbd5e1 : 0x1e293b,
        );
        grid.position.set(planeCenter.x, y - 0.62, planeCenter.z);
        (grid.material as THREE.Material).transparent = true;
        (grid.material as THREE.Material).opacity = 0.18;
        contentGroup.add(grid);
      }
    }

    const renderNodes: SceneRenderNode[] = [];
    visibleNodes.forEach((n) => {
      const pos = positions.get(n.id);
      if (!pos) return;
      const isSelected = n.id === selectedNodeId;
      const inTrace = traceHopSet.has(n.id);
      const inCone = (selectedNodeId !== null && coneNodeIds.has(n.id)) || inTrace;
      const vis = evaluateNodeVisual({
        node: n, lens, palette: activePalette, degree: degreeByNode.get(n.id) ?? 0,
        guardedTableIds, mutatorNodeIds, diffOverlay,
      });
      const dimmed = vis.forceDim ||
        (traceHopIds.length > 0 && !inTrace && !isSelected) ||
        (selectedNodeId !== null && !inCone && traceHopIds.length === 0);
      const mult = isSelected ? 1.58 : inTrace ? 1.38 : inCone ? 1.18 : 1.0;
      renderNodes.push({
        node: n, position: pos, scale: vis.scale * mult,
        style: { barColor: vis.barHex, inquiryColor: vis.inquiryHex, hollow: vis.hollow,
          flagged: vis.flagged, dimmed, selected: isSelected || inTrace, inCone, phase: 0 },
      });
    });
    const nodeBatch = createBatchedNodes(renderNodes, polygonMode);
    contentGroup.add(nodeBatch.group);
    nodeBatchRef.current = nodeBatch;
    atomicMaterialsRef.current = nodeBatch.atomicMaterials;

    // Edges with 8-EdgeKind + VerificationState styling
    const renderEdges: SceneRenderEdge[] = [];
    for (const e of visibleEdges) {
      const p1 = positions.get(e.source_id);
      const p2 = positions.get(e.target_id);
      if (!p1 || !p2) continue;
      const edgeVis = evaluateEdgeVisual(e, edgeFilter);
      if (!edgeVis.visible) continue;

      const inConeEdge =
        (selectedNodeId !== null && coneNodeIds.has(e.source_id) && coneNodeIds.has(e.target_id)) ||
        (traceHopSet.has(e.source_id) && traceHopSet.has(e.target_id));

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
      renderEdges.push({
        start: p1,
        end: p2,
        color: edgeVis.hex,
        opacity,
        pattern: edgeVis.pattern,
      });
    }
    contentGroup.add(createBatchedEdges(renderEdges));

    // Active Request Trace Waypoints + Golden Trajectory Beam
    const wps: THREE.Vector3[] = [];
    for (const id of traceHopIds.every((id) => visibleNodeIds.has(id)) ? traceHopIds : []) {
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

    syncCameraTelemetry();
  }, [
    visibleNodes,
    visibleEdges,
    visibleNodeIds,
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
    syncCameraTelemetry,
  ]);

  const legendItems = useMemo(
    () => getLensLegendItems(lens, Boolean(diffOverlay)),
    [lens, diffOverlay],
  );
  const edgeLegendItems = useMemo(
    () => getEdgeVerificationLegendItems(visibleEdges),
    [visibleEdges],
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
  }, [hoverTip?.nodeId, visualFiducial, visibleNodes.length, onHoverFocusChange, camSettleSeq]);

  useEffect(() => {
    if (!onRegisterLiveCapture) return;
    onRegisterLiveCapture(() => captureCompactViewportWebp(canvasRef.current, 1024, 0.82));
  }, [onRegisterLiveCapture]);

  useEffect(() => {
    if (!onLiveViewportDigest) return;
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
      edges: visibleEdges,
      findings,
      selectedNodeId,
      hoveredNodeId: hoverTip?.nodeId ?? null,
      coneNodeIds,
      lens,
      layoutMode,
      tierFilter,
      subkindFilter,
      onlyFlagged,
      connectedOnly,
      neighborhoodHops,
      renderedNodeIds: nodeBatchRef.current?.renderedNodeIds,
      overviewNodeIds: nodeBatchRef.current?.overviewNodeIds,
      traceIds: traceHopSet,
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
    connectedOnly,
    neighborhoodHops,
    traceHopSet,
    visibleEdges,
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

      {visibleNodes.length === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <p role="status" className="border border-slate-700 bg-slate-950/95 px-4 py-3 text-sm text-slate-200">
            No nodes match this view. Adjust the filters to show more of the graph.
          </p>
        </div>
      )}

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
        <div className="mt-2 w-fit border border-slate-700 bg-slate-950/90 px-2 py-1 text-slate-200" aria-live="polite">
          <div>{visibleNodes.length.toLocaleString()} / {nodes.length.toLocaleString()} nodes · {visibleEdges.length.toLocaleString()} connections · {graph.hiddenCount.toLocaleString()} hidden by filters</div>
          <div className="text-slate-400">In view: {renderStats.overview.toLocaleString()} dots + {renderStats.detailed.toLocaleString()} detailed · zoom in for detail</div>
          {graph.pinnedExtraCount > 0 && <div className="text-sky-300">Includes {graph.pinnedExtraCount} selected / traced nodes outside other filters</div>}
          {selectedNodeId && !visibleNodeIds.has(selectedNodeId) && <div className="text-amber-300">Selected node has no connection in this view and is hidden</div>}
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
          <span
            className="flex flex-wrap items-center gap-2.5 border-l border-slate-700/80 pl-2.5"
            title="Static AST/route edge verification states (never implies runtime execution)"
          >
            {edgeLegendItems.map((edgeItem) => {
              const borderStyle =
                edgeItem.pattern === 'dashed'
                  ? 'border-dashed'
                  : edgeItem.pattern === 'dotted'
                    ? 'border-dotted'
                    : edgeItem.pattern === 'broken_gap'
                      ? 'border-double'
                      : 'border-solid';
              return (
                <span key={edgeItem.verification} className="flex items-center gap-1">
                  <span
                    className={`inline-block w-3.5 border-t-2 ${borderStyle}`}
                    style={{ borderColor: edgeItem.color }}
                  />
                  {edgeItem.label}: {edgeItem.count}
                </span>
              );
            })}
          </span>
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
            Fit view ({visibleNodes.length} nodes)
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
