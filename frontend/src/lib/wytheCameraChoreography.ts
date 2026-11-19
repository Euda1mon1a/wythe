import * as THREE from 'three';
import type {
  AtlasEdge,
  BlastModeChoice,
  ChronicleFrame,
  ChronicleTimeline,
  FramingPreset,
  TierFilterChoice,
  TourKeyframe,
  ViewportCommand,
  ViewportCommandEvent,
  ViewportGroupByChoice,
  ViewportLayoutChoice,
  ViewportTabChoice,
  ZWytheSliceChoice,
} from '@/api/atlas';
import type { SceneLayoutMode, SceneLens } from '@/lib/wytheSceneLenses';

export interface SemanticFramingBeamEndpoint {
  id: string;
  start: [number, number, number];
  end: [number, number, number];
}

export interface SemanticCameraFramingInput {
  preset: FramingPreset;
  focusNodeIds?: ReadonlyArray<string>;
  highlightEdgeIds?: ReadonlyArray<string>;
  positions: ReadonlyMap<string, [number, number, number]>;
  allEdges?: ReadonlyArray<Pick<AtlasEdge, 'id' | 'source_id' | 'target_id'>>;
  extraBeamEndpoints?: ReadonlyArray<SemanticFramingBeamEndpoint>;
  fovDeg?: number;
  aspect?: number;
  flatten2D?: boolean;
}

export interface SemanticCameraFramingResult {
  preset: FramingPreset;
  cameraPosition: [number, number, number];
  cameraTarget: [number, number, number];
  distance: number;
  azimuthDeg: number;
  elevationDeg: number;
  boundingCenter: [number, number, number];
  boundingRadius: number;
  focalPoints: Array<[number, number, number]>;
  occlusionScore: number;
  clearedSlabs: boolean;
  clearedNeighborColumns: boolean;
}

const REFERENCE_SLAB_YS = [17.35, -0.65, -18.65] as const;
const BRICK_OCCLUSION_CLEARANCE = 2.4;

function pointSegmentPerpDist(
  px: number,
  py: number,
  pz: number,
  ax: number,
  ay: number,
  az: number,
  bx: number,
  by: number,
  bz: number,
): { dist: number; t: number } {
  const abx = bx - ax;
  const aby = by - ay;
  const abz = bz - az;
  const lenSq = abx * abx + aby * aby + abz * abz;
  if (lenSq < 1e-6) {
    return { dist: Math.hypot(px - ax, py - ay, pz - az), t: 0 };
  }
  const t = ((px - ax) * abx + (py - ay) * aby + (pz - az) * abz) / lenSq;
  const clamped = Math.max(0, Math.min(1, t));
  const cx = ax + abx * clamped;
  const cy = ay + aby * clamped;
  const cz = az + abz * clamped;
  return { dist: Math.hypot(px - cx, py - cy, pz - cz), t };
}

function buildPresetCandidates(
  preset: FramingPreset,
  focalPoints: ReadonlyArray<[number, number, number]>,
): Array<[number, number]> {
  if (preset === 'tier_elevation') {
    return [
      [0, 5],
      [14, 5],
      [-14, 5],
      [26, 6],
      [-26, 6],
      [180, 5],
      [166, 5],
      [-166, 5],
    ];
  }
  if (preset === 'wythe_cross_section') {
    return [
      [90, 6],
      [-90, 6],
      [80, 7],
      [-80, 7],
      [100, 7],
      [-100, 7],
      [68, 9],
      [-68, 9],
      [112, 9],
      [-112, 9],
    ];
  }
  if (preset === 'corridor_trace') {
    let bestDx = 0;
    let bestDz = 0;
    let bestSpan = 0;
    const sample = focalPoints.slice(0, 24);
    for (let i = 0; i < sample.length; i += 1) {
      for (let j = i + 1; j < sample.length; j += 1) {
        const dx = sample[j][0] - sample[i][0];
        const dz = sample[j][2] - sample[i][2];
        const span = Math.hypot(dx, dz);
        if (span > bestSpan) {
          bestSpan = span;
          bestDx = dx;
          bestDz = dz;
        }
      }
    }
    if (bestSpan > 0.5) {
      const normalAz = THREE.MathUtils.radToDeg(Math.atan2(-bestDz, bestDx));
      return [
        [normalAz, 7],
        [normalAz + 180, 7],
        [normalAz + 15, 9],
        [normalAz - 15, 9],
        [normalAz + 165, 9],
        [normalAz + 195, 9],
      ];
    }
    return [
      [24, 6],
      [-24, 6],
      [90, 6],
      [-90, 6],
      [156, 6],
      [-156, 6],
    ];
  }
  return [
    [32, 26],
    [-32, 26],
    [48, 30],
    [-48, 30],
    [148, 26],
    [-148, 26],
    [20, 18],
    [-20, 18],
  ];
}

export function solveSemanticCameraFraming(
  input: SemanticCameraFramingInput,
): SemanticCameraFramingResult {
  const {
    preset,
    focusNodeIds = [],
    highlightEdgeIds = [],
    positions,
    allEdges = [],
    extraBeamEndpoints = [],
    fovDeg = 46,
    aspect = 1.6,
    flatten2D = false,
  } = input;

  const focalPoints: Array<[number, number, number]> = [];
  const focalIdSet = new Set<string>();
  const addFocalId = (id: string) => {
    focalIdSet.add(id);
    const direct = positions.get(id);
    if (direct) focalPoints.push(direct);
    for (const suffix of ['@z_head', '@z_base', '@z1', '@z2']) {
      const inst = positions.get(`${id}${suffix}`);
      if (inst) {
        focalIdSet.add(`${id}${suffix}`);
        focalPoints.push(inst);
      }
    }
  };

  for (const nid of focusNodeIds) addFocalId(nid);
  if (highlightEdgeIds.length > 0) {
    const edgeWanted = new Set(highlightEdgeIds);
    for (const e of allEdges) {
      if (edgeWanted.has(e.id)) {
        addFocalId(e.source_id);
        addFocalId(e.target_id);
      }
    }
    for (const b of extraBeamEndpoints) {
      if (edgeWanted.has(b.id)) {
        focalPoints.push(b.start, b.end);
      }
    }
  }

  if (focalPoints.length === 0) {
    for (const [id, p] of positions.entries()) {
      focalIdSet.add(id);
      focalPoints.push(p);
    }
  }
  if (focalPoints.length === 0) {
    focalPoints.push([0, 0, 0]);
  }

  const rawBox = new THREE.Box3();
  for (const p of focalPoints) rawBox.expandByPoint(new THREE.Vector3(...p));
  const centerVec = rawBox.getCenter(new THREE.Vector3());
  const paddedBox = rawBox.clone().expandByScalar(3.6);
  const sphere = paddedBox.getBoundingSphere(new THREE.Sphere());
  const boundingRadius = Math.max(5.5, sphere.radius);

  const halfVert = THREE.MathUtils.degToRad(fovDeg / 2);
  const halfHoriz = Math.atan(Math.tan(halfVert) * Math.max(0.25, aspect));
  const minHalf = Math.max(0.12, Math.min(halfVert, halfHoriz));
  const baseDistance = (boundingRadius / Math.sin(minHalf)) * 1.18;

  const nonFocalObstacles: Array<[number, number, number]> = [];
  for (const [id, p] of positions.entries()) {
    if (!focalIdSet.has(id)) nonFocalObstacles.push(p);
  }
  const sampleTargets: Array<[number, number, number]> = [
    [centerVec.x, centerVec.y, centerVec.z],
    ...focalPoints.slice(0, 8),
  ];

  const focalMinY = rawBox.min.y;
  const focalMaxY = rawBox.max.y;
  const candidates = buildPresetCandidates(preset, focalPoints);

  let bestAz = candidates[0][0];
  let bestEl = candidates[0][1];
  let bestScore = Infinity;
  let bestClearedSlabs = true;
  let bestClearedCols = true;

  candidates.forEach(([azDeg, elDeg], idx) => {
    const azRad = THREE.MathUtils.degToRad(azDeg);
    const elRad = THREE.MathUtils.degToRad(elDeg);
    const dx = Math.sin(azRad) * Math.cos(elRad);
    const dy = Math.sin(elRad);
    const dz = Math.cos(azRad) * Math.cos(elRad);
    const cx = centerVec.x + dx * baseDistance;
    const cy = centerVec.y + dy * baseDistance;
    const cz = centerVec.z + dz * baseDistance;

    let slabCrossings = 0;
    if (!flatten2D) {
      for (const sy of REFERENCE_SLAB_YS) {
        const focalSpansSlab = focalMinY - 0.5 <= sy && sy <= focalMaxY + 0.5;
        if (focalSpansSlab) continue;
        for (const tp of sampleTargets) {
          if ((cy - sy) * (tp[1] - sy) < -0.05) {
            slabCrossings += 1;
            break;
          }
        }
      }
    }

    let brickHits = 0;
    for (const obs of nonFocalObstacles) {
      for (const tp of sampleTargets) {
        const { dist, t } = pointSegmentPerpDist(
          obs[0],
          obs[1],
          obs[2],
          cx,
          cy,
          cz,
          tp[0],
          tp[1],
          tp[2],
        );
        if (t > 0.05 && t < 0.94) {
          if (dist < 3.4) {
            brickHits += (3.4 - dist) * 14;
            break;
          }
          const rayX = cx + (tp[0] - cx) * t;
          const rayY = cy + (tp[1] - cy) * t;
          const rayZ = cz + (tp[2] - cz) * t;
          const xzDist = Math.hypot(obs[0] - rayX, obs[2] - rayZ);
          if (xzDist < 3.6 && Math.abs(obs[1] - rayY) < 6.5) {
            brickHits += (3.6 - xzDist) * 10;
            break;
          }
        }
      }
    }

    const totalScore = slabCrossings * 60 + brickHits + idx * 0.02;
    if (totalScore < bestScore) {
      bestScore = totalScore;
      bestAz = azDeg;
      bestEl = elDeg;
      bestClearedSlabs = slabCrossings === 0;
      bestClearedCols = brickHits === 0;
    }
  });

  const bestAzRad = THREE.MathUtils.degToRad(bestAz);
  const bestElRad = THREE.MathUtils.degToRad(bestEl);
  const dirVec = new THREE.Vector3(
    Math.sin(bestAzRad) * Math.cos(bestElRad),
    Math.sin(bestElRad),
    Math.cos(bestAzRad) * Math.cos(bestElRad),
  ).normalize();

  let finalDistance = baseDistance;
  const testCam = new THREE.PerspectiveCamera(fovDeg, Math.max(0.25, aspect), 0.1, 5000);
  testCam.position.copy(centerVec).addScaledVector(dirVec, finalDistance);
  testCam.lookAt(centerVec);
  testCam.updateProjectionMatrix();
  testCam.updateMatrixWorld();

  let maxAbsNdc = 0;
  const proj = new THREE.Vector3();
  for (const fp of focalPoints) {
    proj.set(fp[0], fp[1], fp[2]).project(testCam);
    maxAbsNdc = Math.max(maxAbsNdc, Math.abs(proj.x), Math.abs(proj.y));
  }
  if (maxAbsNdc > 0.9) {
    finalDistance *= maxAbsNdc / 0.86;
  }

  const finalPos = centerVec.clone().addScaledVector(dirVec, finalDistance);
  return {
    preset,
    cameraPosition: [finalPos.x, finalPos.y, finalPos.z],
    cameraTarget: [centerVec.x, centerVec.y, centerVec.z],
    distance: finalDistance,
    azimuthDeg: bestAz,
    elevationDeg: bestEl,
    boundingCenter: [centerVec.x, centerVec.y, centerVec.z],
    boundingRadius,
    focalPoints,
    occlusionScore: Math.max(0, Number((bestScore - (bestScore % 0.02)).toFixed(3))),
    clearedSlabs: bestClearedSlabs,
    clearedNeighborColumns: bestClearedCols,
  };
}
export type HumanInputInterruptKind =
  | 'pointerdown'
  | 'pointerdrag'
  | 'wheel'
  | 'touchstart'
  | 'keydown_nav';

export interface NormalizedTimelineItem {
  index: number;
  kind: 'tour' | 'chronicle';
  title: string;
  phaseKey: string | null;
  tier: 'truth' | 'manipulate' | 'display' | null;
  status: 'ok' | 'warning' | 'failed' | 'pending';
  focusNodeIds: string[];
  highlightEdgeIds: string[];
  selectedNodeId?: string | null;
  selectedEdgeId?: string | null;
  findingId: string | null;
  lens: SceneLens | null;
  layoutMode: SceneLayoutMode | null;
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
  zWytheSlice: ZWytheSliceChoice | null;
  zoomStratum: 1 | 2 | 3;
  framingPreset: FramingPreset;
  caption: string;
  substeps: string[];
}

export interface SmartDenseSalienceInput {
  totalNodeCount: number;
  resolvedFocus: ReadonlyArray<string>;
  highlightEdgeIds?: ReadonlyArray<string>;
  allEdges?: ReadonlyArray<Pick<AtlasEdge, 'id' | 'source_id' | 'target_id'>>;
  selectedNodeId?: string | null;
  isolateCone?: boolean | null;
  neighborhoodHops?: 0 | 1 | 2 | null;
  workingSetOnly?: boolean | null;
  onlyFlagged?: boolean | null;
  tierFilter?: string | null;
  subkindFilter?: string | null;
  searchQuery?: string | null;
  resetFilters?: boolean;
}

export interface SmartDenseSalienceResult {
  mode: 'none' | 'auto_isolate_cone' | 'auto_working_set_compact';
  selectedNodeId: string | null;
  isolateCone?: boolean;
  workingSetIds?: string[];
  workingSetActive?: boolean;
  compactVisible?: boolean;
}

export function isPureDrawerRefreshCommand(
  cmd: Partial<ViewportCommand> | null | undefined,
): boolean {
  if (!cmd) return false;
  const hasDrawerWakeup = Boolean(cmd.refresh_session_id) || cmd.open_drawer === true;
  if (!hasDrawerWakeup) return false;
  return (
    (cmd.focus_node_ids?.length ?? 0) === 0 &&
    (cmd.highlight_edge_ids?.length ?? 0) === 0 &&
    (cmd.tour_keyframes?.length ?? 0) === 0 &&
    (cmd.chronicle_frames?.length ?? 0) === 0 &&
    !cmd.chronicle_timeline &&
    !cmd.selected_node_id &&
    !cmd.selected_edge_id &&
    !cmd.finding_id &&
    !cmd.reset_filters &&
    cmd.lens == null &&
    cmd.layout_mode == null &&
    cmd.z_wythe_slice == null &&
    cmd.tier_filter == null &&
    cmd.subkind_filter == null &&
    cmd.edge_filter == null &&
    cmd.only_flagged == null &&
    cmd.isolate_cone == null &&
    cmd.connected_only == null &&
    cmd.neighborhood_hops == null &&
    !cmd.search_query &&
    cmd.blast_mode == null &&
    cmd.diff_base_ref == null &&
    cmd.working_set_only == null &&
    cmd.compact_visible == null &&
    cmd.flatten_2d == null &&
    cmd.group_by == null &&
    cmd.active_tab == null
  );
}

export function computeSmartDenseSalience(
  input: SmartDenseSalienceInput,
): SmartDenseSalienceResult {
  const {
    totalNodeCount,
    resolvedFocus,
    highlightEdgeIds = [],
    allEdges = [],
    selectedNodeId = null,
    isolateCone = null,
    neighborhoodHops = null,
    workingSetOnly = null,
    onlyFlagged = null,
    tierFilter = null,
    subkindFilter = null,
    searchQuery = null,
    resetFilters = false,
  } = input;

  const fallbackSelected =
    selectedNodeId ?? (resolvedFocus.length > 0 ? resolvedFocus[0] : null);
  const explicitFilterSet =
    isolateCone != null ||
    neighborhoodHops != null ||
    workingSetOnly != null ||
    onlyFlagged != null ||
    tierFilter != null ||
    subkindFilter != null ||
    Boolean(searchQuery) ||
    Boolean(resetFilters);

  if (totalNodeCount <= 120 || resolvedFocus.length === 0 || explicitFilterSet) {
    return {
      mode: 'none',
      selectedNodeId: fallbackSelected,
    };
  }

  if (resolvedFocus.length === 1) {
    return {
      mode: 'auto_isolate_cone',
      selectedNodeId: fallbackSelected,
      isolateCone: true,
      workingSetActive: false,
      compactVisible: false,
    };
  }

  const salientIds = new Set<string>(resolvedFocus);
  if (highlightEdgeIds.length > 0 && allEdges.length > 0) {
    const wantedEdges = new Set<string>(highlightEdgeIds);
    for (const edge of allEdges) {
      if (wantedEdges.has(edge.id)) {
        salientIds.add(edge.source_id);
        salientIds.add(edge.target_id);
      }
    }
  }

  return {
    mode: 'auto_working_set_compact',
    selectedNodeId: fallbackSelected,
    isolateCone: false,
    workingSetIds: [...salientIds],
    workingSetActive: true,
    compactVisible: true,
  };
}

export interface AgentCameraFollowState {
  followMode: 'following' | 'paused';
  liveFollowing: boolean;
  haltedReason: string | null;
  chronicleTimelineId: string | null;
  lastYieldReason: HumanInputInterruptKind | null;
  activeEvent: ViewportCommandEvent | null;
  pendingEventWhilePaused: ViewportCommandEvent | null;
  timelineMode: 'none' | 'tour' | 'chronicle';
  stepIndex: number;
  isPlaying: boolean;
}

export function createInitialAgentCameraState(
  initialFollowMode: 'following' | 'paused' = 'following',
): AgentCameraFollowState {
  return {
    followMode: initialFollowMode,
    liveFollowing: initialFollowMode === 'following',
    haltedReason: null,
    chronicleTimelineId: null,
    lastYieldReason: null,
    activeEvent: null,
    pendingEventWhilePaused: null,
    timelineMode: 'none',
    stepIndex: 0,
    isPlaying: false,
  };
}

const EXEC_MARKUP_RE =
  /(?:<\s*\/?\s*(?:script|iframe|object|embed)\b|\b(?:javascript|vbscript)\s*:|\bdata\s*:\s*text\/html|<\s*[a-zA-Z][^>]*\bon[a-zA-Z]+\s*=)/i;
const BENIGN_HTML_TAG_RE =
  /<(?:!--[\s\S]*?--|![a-zA-Z][^>]*|\?[^>]*|\/\s*[a-zA-Z][a-zA-Z0-9:-]*\s*|[a-zA-Z][a-zA-Z0-9:-]*(?:\s[^<>]*)?\/?)>/g;
const UNCLOSED_HTML_TAG_RE = /<(?:\/\s*)?[a-zA-Z][a-zA-Z0-9:-]*(?:\s[^<>]*)?$/;

export function sanitizeViewportPlainText(raw: string | null | undefined, maxLen = 400): string {
  if (!raw) return '';
  let cleaned = raw.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  if (EXEC_MARKUP_RE.test(cleaned)) {
    return '[sanitized unsafe markup]';
  }
  while (true) {
    const next = cleaned.replace(BENIGN_HTML_TAG_RE, '').replace(UNCLOSED_HTML_TAG_RE, '');
    if (EXEC_MARKUP_RE.test(next)) {
      return '[sanitized unsafe markup]';
    }
    if (next === cleaned) {
      break;
    }
    cleaned = next;
  }
  return cleaned
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen);
}

export function normalizeViewportTimeline(
  cmd: ViewportCommand | null | undefined,
): NormalizedTimelineItem[] {
  if (!cmd) return [];
  if (cmd.tour_keyframes && cmd.tour_keyframes.length > 0) {
    return cmd.tour_keyframes.map((kf: TourKeyframe, idx) => ({
      index: idx,
      kind: 'tour',
      title: sanitizeViewportPlainText(kf.title, 120) || `Step ${idx + 1}`,
      phaseKey: null,
      tier: null,
      status: 'ok',
      focusNodeIds: kf.focus_node_ids ?? [],
      highlightEdgeIds: kf.highlight_edge_ids ?? [],
      selectedNodeId: kf.selected_node_id ?? cmd.selected_node_id ?? null,
      selectedEdgeId: kf.selected_edge_id ?? cmd.selected_edge_id ?? null,
      findingId: kf.finding_id ?? cmd.finding_id ?? null,
      lens: (kf.lens ?? cmd.lens ?? null) as SceneLens | null,
      layoutMode: (kf.layout_mode ?? cmd.layout_mode ?? null) as SceneLayoutMode | null,
      tierFilter: kf.tier_filter ?? cmd.tier_filter ?? null,
      subkindFilter: kf.subkind_filter ?? cmd.subkind_filter ?? null,
      edgeFilter: kf.edge_filter ?? cmd.edge_filter ?? null,
      onlyFlagged: kf.only_flagged ?? cmd.only_flagged ?? null,
      isolateCone: kf.isolate_cone ?? cmd.isolate_cone ?? null,
      connectedOnly: kf.connected_only ?? cmd.connected_only ?? null,
      neighborhoodHops: kf.neighborhood_hops ?? cmd.neighborhood_hops ?? null,
      searchQuery: kf.search_query ?? cmd.search_query ?? null,
      blastMode: kf.blast_mode ?? cmd.blast_mode ?? null,
      diffBaseRef: kf.diff_base_ref ?? cmd.diff_base_ref ?? null,
      workingSetOnly: kf.working_set_only ?? cmd.working_set_only ?? null,
      compactVisible: kf.compact_visible ?? cmd.compact_visible ?? null,
      flatten2d: kf.flatten_2d ?? cmd.flatten_2d ?? null,
      groupBy: kf.group_by ?? cmd.group_by ?? null,
      activeTab: kf.active_tab ?? cmd.active_tab ?? null,
      openDrawer: kf.open_drawer ?? cmd.open_drawer ?? null,
      resetFilters: Boolean(kf.reset_filters ?? cmd.reset_filters),
      zWytheSlice: kf.z_wythe_slice ?? cmd.z_wythe_slice ?? null,
      zoomStratum: kf.zoom_stratum ?? cmd.zoom_stratum ?? 1,
      framingPreset: kf.framing_preset ?? cmd.framing_preset ?? 'iso_overview',
      caption: sanitizeViewportPlainText(kf.caption || cmd.caption, 400),
      substeps: [],
    }));
  }
  const chronFrames =
    cmd.chronicle_timeline?.frames && cmd.chronicle_timeline.frames.length > 0
      ? cmd.chronicle_timeline.frames
      : cmd.chronicle_frames;
  if (chronFrames && chronFrames.length > 0) {
    return chronFrames.map((cf: ChronicleFrame, idx) => ({
      index: idx,
      kind: 'chronicle',
      title: sanitizeViewportPlainText(cf.phase_label, 120) || cf.phase_key,
      phaseKey: cf.phase_key,
      tier: cf.tier,
      status: cf.status ?? 'ok',
      focusNodeIds: cf.focus_node_ids ?? [],
      highlightEdgeIds: cf.highlight_edge_ids ?? [],
      selectedNodeId: cmd.selected_node_id ?? null,
      selectedEdgeId: cmd.selected_edge_id ?? null,
      findingId: cmd.finding_id ?? null,
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
      zWytheSlice: cmd.z_wythe_slice ?? null,
      zoomStratum: cmd.zoom_stratum ?? 1,
      framingPreset: cmd.framing_preset ?? 'corridor_trace',
      caption: sanitizeViewportPlainText(cf.caption || cmd.caption, 400),
      substeps: (cf.substeps ?? []).map((s) => sanitizeViewportPlainText(s, 200)).filter(Boolean),
    }));
  }
  return [];
}

export function yieldAgentCameraOnHumanInput(
  state: AgentCameraFollowState,
  reason: HumanInputInterruptKind,
): AgentCameraFollowState {
  if (state.followMode === 'paused' && !state.liveFollowing && !state.isPlaying) {
    return { ...state, lastYieldReason: reason };
  }
  return {
    ...state,
    followMode: 'paused',
    liveFollowing: false,
    lastYieldReason: reason,
    isPlaying: false,
  };
}

export function resumeAgentCameraFollow(state: AgentCameraFollowState): AgentCameraFollowState {
  const nextActive = state.pendingEventWhilePaused ?? state.activeEvent;
  const items = normalizeViewportTimeline(nextActive?.command);
  const nextTl: ChronicleTimeline | null = nextActive?.command.chronicle_timeline ?? null;
  const timelineMode: AgentCameraFollowState['timelineMode'] =
    items.length > 0 ? items[0].kind : nextTl ? 'chronicle' : 'none';
  const maxStep = Math.max(0, items.length - 1);
  const nextStep = state.pendingEventWhilePaused
    ? nextTl
      ? Math.max(0, Math.min(maxStep, Math.trunc(nextTl.active_phase_index ?? 0)))
      : 0
    : Math.min(state.stepIndex, maxStep);
  return {
    ...state,
    followMode: 'following',
    liveFollowing: true,
    haltedReason: null,
    chronicleTimelineId: nextTl?.timeline_id ?? state.chronicleTimelineId,
    lastYieldReason: null,
    activeEvent: nextActive,
    pendingEventWhilePaused: null,
    timelineMode,
    stepIndex: nextStep,
  };
}

export function applyIncomingViewportEvent(
  state: AgentCameraFollowState,
  event: ViewportCommandEvent,
): { state: AgentCameraFollowState; shouldMoveCamera: boolean } {
  if (state.activeEvent && event.seq <= state.activeEvent.seq && event.seq > 0) {
    return { state, shouldMoveCamera: false };
  }
  if (state.followMode === 'paused') {
    return {
      state: {
        ...state,
        pendingEventWhilePaused: event,
        activeEvent: state.activeEvent ?? event,
      },
      shouldMoveCamera: false,
    };
  }
  const items = normalizeViewportTimeline(event.command);
  const tl = event.command.chronicle_timeline ?? null;
  const haltedReason = sanitizeViewportPlainText(tl?.halted_reason, 240) || null;
  const autoHalted = Boolean(haltedReason) || tl?.live_following === false;
  const rawPhase = tl ? Math.max(0, Math.trunc(tl.active_phase_index ?? 0)) : 0;
  const stepIndex = items.length > 0 ? Math.min(items.length - 1, rawPhase) : rawPhase;
  return {
    state: {
      ...state,
      followMode: autoHalted ? 'paused' : 'following',
      liveFollowing: !autoHalted,
      haltedReason,
      chronicleTimelineId: tl?.timeline_id ?? null,
      activeEvent: event,
      pendingEventWhilePaused: null,
      timelineMode: items.length > 0 ? items[0].kind : tl ? 'chronicle' : 'none',
      stepIndex,
      isPlaying: false,
    },
    shouldMoveCamera: true,
  };
}

export function stepTimelineFrame(
  state: AgentCameraFollowState,
  step: -1 | 1 | { index: number },
): AgentCameraFollowState {
  const items = normalizeViewportTimeline(state.activeEvent?.command);
  if (items.length === 0) return state;
  const nextIndex =
    typeof step === 'number'
      ? (state.stepIndex + step + items.length) % items.length
      : Math.max(0, Math.min(items.length - 1, step.index));
  return {
    ...state,
    stepIndex: nextIndex,
  };
}

export function computeCameraTransition(params: {
  fromPos: [number, number, number];
  fromTarget: [number, number, number];
  toPos: [number, number, number];
  toTarget: [number, number, number];
  prefersReducedMotion: boolean;
  progress01: number;
}): {
  mode: 'instant_cut' | 'smooth_sweep';
  durationMs: number;
  position: [number, number, number];
  target: [number, number, number];
  done: boolean;
} {
  const { fromPos, fromTarget, toPos, toTarget, prefersReducedMotion, progress01 } = params;
  if (prefersReducedMotion) {
    return {
      mode: 'instant_cut',
      durationMs: 0,
      position: [...toPos],
      target: [...toTarget],
      done: true,
    };
  }
  const clamped = Math.max(0, Math.min(1, progress01));
  const eased = 1 - Math.pow(1 - clamped, 3);
  const lerp3 = (
    a: [number, number, number],
    b: [number, number, number],
  ): [number, number, number] => [
    a[0] + (b[0] - a[0]) * eased,
    a[1] + (b[1] - a[1]) * eased,
    a[2] + (b[2] - a[2]) * eased,
  ];
  return {
    mode: 'smooth_sweep',
    durationMs: 480,
    position: clamped >= 1 ? [...toPos] : lerp3(fromPos, toPos),
    target: clamped >= 1 ? [...toTarget] : lerp3(fromTarget, toTarget),
    done: clamped >= 1,
  };
}

const VALID_LENSES = new Set<SceneLens>([
  'status',
  'contention',
  'gravity',
  'subkind',
  'cluster',
  'containers',
]);
const VALID_LAYOUTS = new Set<ViewportLayoutChoice>([
  'cluster',
  'grid',
  'subkind',
  'connected',
  'lifecycle_z',
  'temporal_z',
]);
const VALID_PRESETS = new Set<FramingPreset>([
  'iso_overview',
  'tier_elevation',
  'wythe_cross_section',
  'corridor_trace',
]);
const VALID_Z_SLICES = new Set<ZWytheSliceChoice>([
  'all',
  'z0_blueprint',
  'z1_built',
  'z2_runtime',
  'z_base',
  'z_head',
]);
const VALID_TIERS = new Set<TierFilterChoice>(['all', 'truth', 'manipulate', 'display']);
const VALID_BLAST_MODES = new Set<BlastModeChoice>(['off', 'git', 'snapshot']);
const VALID_GROUP_BY = new Set<ViewportGroupByChoice>(['none', 'cluster', 'subkind']);
const VALID_TABS = new Set<ViewportTabChoice>([
  '3d',
  'index',
  'governance',
  'understanding',
  'lineage',
  'gate',
]);

export function buildViewportPermalinkHash(cmd: Partial<ViewportCommand>): string {
  const parts: string[] = [];
  if (cmd.target_slug) {
    parts.push(`target=${encodeURIComponent(cmd.target_slug)}`);
  }
  if (cmd.session_id) {
    parts.push(`session=${encodeURIComponent(cmd.session_id)}`);
  }
  if (cmd.focus_node_ids && cmd.focus_node_ids.length > 0) {
    const dedupFocus = [...new Set(cmd.focus_node_ids)];
    parts.push(`focus=${dedupFocus.map((id) => encodeURIComponent(id)).join(',')}`);
  }
  if (cmd.highlight_edge_ids && cmd.highlight_edge_ids.length > 0) {
    const dedupEdges = [...new Set(cmd.highlight_edge_ids)];
    parts.push(`edges=${dedupEdges.map((id) => encodeURIComponent(id)).join(',')}`);
  }
  if (cmd.lens && VALID_LENSES.has(cmd.lens)) {
    parts.push(`lens=${encodeURIComponent(cmd.lens)}`);
  }
  if (cmd.layout_mode && VALID_LAYOUTS.has(cmd.layout_mode)) {
    parts.push(`layout=${encodeURIComponent(cmd.layout_mode)}`);
  }
  const preset = cmd.framing_preset ?? 'iso_overview';
  if (VALID_PRESETS.has(preset)) {
    parts.push(`preset=${encodeURIComponent(preset)}`);
  }
  if (cmd.z_wythe_slice && VALID_Z_SLICES.has(cmd.z_wythe_slice)) {
    parts.push(`z=${encodeURIComponent(cmd.z_wythe_slice)}`);
  }
  const zoom: 1 | 2 | 3 = cmd.zoom_stratum === 2 || cmd.zoom_stratum === 3 ? cmd.zoom_stratum : 1;
  parts.push(`zoom=${zoom}`);
  if (cmd.chronicle_timeline && cmd.chronicle_timeline.timeline_id) {
    parts.push(`chronicle=${encodeURIComponent(cmd.chronicle_timeline.timeline_id)}`);
    const phaseIdx = Math.max(
      0,
      Math.min(64, Math.trunc(cmd.chronicle_timeline.active_phase_index ?? 0)),
    );
    parts.push(`phase=${phaseIdx}`);
  }
  if (cmd.finding_id) {
    parts.push(`finding=${encodeURIComponent(cmd.finding_id)}`);
  }
  if (cmd.selected_node_id) {
    parts.push(`selected_node=${encodeURIComponent(cmd.selected_node_id)}`);
  }
  if (cmd.selected_edge_id) {
    parts.push(`selected_edge=${encodeURIComponent(cmd.selected_edge_id)}`);
  }
  if (cmd.tier_filter && cmd.tier_filter !== 'all' && VALID_TIERS.has(cmd.tier_filter)) {
    parts.push(`tier=${encodeURIComponent(cmd.tier_filter)}`);
  }
  if (cmd.subkind_filter && cmd.subkind_filter !== 'all') {
    parts.push(`subkind=${encodeURIComponent(cmd.subkind_filter)}`);
  }
  if (cmd.edge_filter && cmd.edge_filter !== 'all') {
    parts.push(`edge_filter=${encodeURIComponent(cmd.edge_filter)}`);
  }
  if (cmd.only_flagged === true) {
    parts.push('only_flagged=1');
  }
  if (cmd.isolate_cone === true) {
    parts.push('isolate_cone=1');
  }
  if (cmd.connected_only === true) {
    parts.push('connected_only=1');
  }
  if (cmd.neighborhood_hops === 1 || cmd.neighborhood_hops === 2) {
    parts.push(`hops=${cmd.neighborhood_hops}`);
  }
  if (cmd.search_query) {
    parts.push(`q=${encodeURIComponent(cmd.search_query)}`);
  }
  if (cmd.blast_mode && cmd.blast_mode !== 'off' && VALID_BLAST_MODES.has(cmd.blast_mode)) {
    parts.push(`blast=${encodeURIComponent(cmd.blast_mode)}`);
    if (cmd.diff_base_ref && cmd.blast_mode === 'git') {
      parts.push(`base_ref=${encodeURIComponent(cmd.diff_base_ref)}`);
    }
  }
  if (cmd.working_set_only === true) {
    parts.push('working_set=1');
  }
  if (cmd.compact_visible === true) {
    parts.push('compact=1');
  }
  if (cmd.flatten_2d === true) {
    parts.push('flat2d=1');
  }
  if (cmd.group_by && cmd.group_by !== 'none' && VALID_GROUP_BY.has(cmd.group_by)) {
    parts.push(`group_by=${encodeURIComponent(cmd.group_by)}`);
  }
  if (cmd.active_tab && cmd.active_tab !== '3d' && VALID_TABS.has(cmd.active_tab)) {
    parts.push(`tab=${encodeURIComponent(cmd.active_tab)}`);
  }
  return `#${parts.join('&')}`;
}

function decodePctOnce(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function parseViewportPermalinkHash(
  hashOrUrl: string | null | undefined,
  fallbackTargetSlug = 'wythe',
): ViewportCommand | null {
  if (!hashOrUrl) return null;
  const hashIdx = hashOrUrl.indexOf('#');
  const qIdx = hashIdx < 0 ? hashOrUrl.indexOf('?') : -1;
  const fragment =
    hashIdx >= 0
      ? hashOrUrl.slice(hashIdx + 1)
      : qIdx >= 0
        ? hashOrUrl.slice(qIdx + 1)
        : hashOrUrl.includes('=')
          ? hashOrUrl
          : '';
  if (!fragment || !fragment.includes('=')) return null;

  const rawParams = new Map<string, string>();
  for (const pair of fragment.split('&')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = decodePctOnce(pair.slice(0, eqIdx));
    const rawVal = pair.slice(eqIdx + 1);
    rawParams.set(key, rawVal);
  }

  const recognizedKeys = [
    'target',
    'focus',
    'edges',
    'finding',
    'selected_node',
    'selected_edge',
    'lens',
    'layout',
    'preset',
    'z',
    'zoom',
    'chronicle',
    'phase',
    'tier',
    'subkind',
    'edge_filter',
    'only_flagged',
    'isolate_cone',
    'connected_only',
    'hops',
    'q',
    'blast',
    'working_set',
    'compact',
    'flat2d',
    'group_by',
    'tab',
  ];
  if (!recognizedKeys.some((k) => rawParams.has(k))) return null;

  const decodeCsv = (raw: string | undefined, cap: number): string[] => {
    if (!raw) return [];
    const seen = new Set<string>();
    const out: string[] = [];
    for (const item of raw.split(',')) {
      const cleaned = sanitizeViewportPlainText(decodePctOnce(item), 180);
      if (cleaned && !seen.has(cleaned)) {
        seen.add(cleaned);
        out.push(cleaned);
        if (out.length >= cap) break;
      }
    }
    return out;
  };

  const getDecoded = (key: string): string | null => {
    const v = rawParams.get(key);
    return v === undefined ? null : decodePctOnce(v);
  };
  const parseBoolParam = (key: string): boolean | undefined => {
    const v = getDecoded(key);
    if (v === null) return undefined;
    const norm = v.trim().toLowerCase();
    if (norm === '1' || norm === 'true') return true;
    if (norm === '0' || norm === 'false') return false;
    return undefined;
  };

  const targetRaw = sanitizeViewportPlainText(getDecoded('target'), 64);
  const resolvedSlug = targetRaw || fallbackTargetSlug;
  const sessionRaw = sanitizeViewportPlainText(
    getDecoded('session') ?? getDecoded('session_id'),
    64,
  );
  const lensRaw = getDecoded('lens') as SceneLens | null;
  const layoutRaw = getDecoded('layout') as ViewportLayoutChoice | null;
  const presetRaw = getDecoded('preset') as FramingPreset | null;
  const zRaw = getDecoded('z') as ZWytheSliceChoice | null;
  const zoomNum = Number(getDecoded('zoom') ?? '1');
  const findingRaw = sanitizeViewportPlainText(getDecoded('finding'), 120);
  const selectedNodeRaw = sanitizeViewportPlainText(getDecoded('selected_node'), 240);
  const selectedEdgeRaw = sanitizeViewportPlainText(getDecoded('selected_edge'), 240);
  const tierRaw = getDecoded('tier') as TierFilterChoice | null;
  const subkindRaw = sanitizeViewportPlainText(getDecoded('subkind'), 80);
  const edgeFilterRaw = sanitizeViewportPlainText(getDecoded('edge_filter'), 80);
  const onlyFlaggedVal = parseBoolParam('only_flagged');
  const isolateConeVal = parseBoolParam('isolate_cone');
  const connectedOnlyVal = parseBoolParam('connected_only');
  const hopsDecoded = getDecoded('hops');
  const hopsVal: 0 | 1 | 2 | undefined =
    hopsDecoded === '0' ? 0 : hopsDecoded === '1' ? 1 : hopsDecoded === '2' ? 2 : undefined;
  const searchQueryRaw = sanitizeViewportPlainText(getDecoded('q'), 160);
  const blastRaw = getDecoded('blast') as BlastModeChoice | null;
  const baseRefRaw = sanitizeViewportPlainText(getDecoded('base_ref'), 120);
  const workingSetVal = parseBoolParam('working_set');
  const compactVal = parseBoolParam('compact');
  const flat2dVal = parseBoolParam('flat2d');
  const groupByRaw = getDecoded('group_by') as ViewportGroupByChoice | null;
  const tabRaw = getDecoded('tab') as ViewportTabChoice | null;
  const chronicleRaw = sanitizeViewportPlainText(getDecoded('chronicle'), 64);
  const phaseDecoded = getDecoded('phase');
  const phaseIdx =
    phaseDecoded !== null && /^\d+$/.test(phaseDecoded.trim())
      ? Math.max(0, Math.min(64, Number(phaseDecoded.trim())))
      : 0;

  return {
    target_slug: resolvedSlug,
    ...(sessionRaw ? { session_id: sessionRaw } : {}),
    focus_node_ids: decodeCsv(rawParams.get('focus'), 50),
    highlight_edge_ids: decodeCsv(rawParams.get('edges'), 80),
    ...(selectedNodeRaw ? { selected_node_id: selectedNodeRaw } : {}),
    ...(selectedEdgeRaw ? { selected_edge_id: selectedEdgeRaw } : {}),
    finding_id: findingRaw || null,
    lens: lensRaw && VALID_LENSES.has(lensRaw) ? lensRaw : null,
    layout_mode: layoutRaw && VALID_LAYOUTS.has(layoutRaw) ? layoutRaw : null,
    ...(tierRaw && VALID_TIERS.has(tierRaw) ? { tier_filter: tierRaw } : {}),
    ...(subkindRaw ? { subkind_filter: subkindRaw } : {}),
    ...(edgeFilterRaw ? { edge_filter: edgeFilterRaw } : {}),
    ...(onlyFlaggedVal !== undefined ? { only_flagged: onlyFlaggedVal } : {}),
    ...(isolateConeVal !== undefined ? { isolate_cone: isolateConeVal } : {}),
    ...(connectedOnlyVal !== undefined ? { connected_only: connectedOnlyVal } : {}),
    ...(hopsVal !== undefined ? { neighborhood_hops: hopsVal } : {}),
    ...(searchQueryRaw ? { search_query: searchQueryRaw } : {}),
    ...(blastRaw && VALID_BLAST_MODES.has(blastRaw) ? { blast_mode: blastRaw } : {}),
    ...(baseRefRaw ? { diff_base_ref: baseRefRaw } : {}),
    ...(workingSetVal !== undefined ? { working_set_only: workingSetVal } : {}),
    ...(compactVal !== undefined ? { compact_visible: compactVal } : {}),
    ...(flat2dVal !== undefined ? { flatten_2d: flat2dVal } : {}),
    ...(groupByRaw && VALID_GROUP_BY.has(groupByRaw) ? { group_by: groupByRaw } : {}),
    ...(tabRaw && VALID_TABS.has(tabRaw) ? { active_tab: tabRaw } : {}),
    z_wythe_slice: zRaw && VALID_Z_SLICES.has(zRaw) ? zRaw : null,
    zoom_stratum: zoomNum === 2 || zoomNum === 3 ? zoomNum : 1,
    framing_preset: presetRaw && VALID_PRESETS.has(presetRaw) ? presetRaw : 'iso_overview',
    caption: sanitizeViewportPlainText(getDecoded('caption'), 400),
    tour_keyframes: [],
    chronicle_frames: [],
    chronicle_timeline: chronicleRaw
      ? {
          timeline_id: chronicleRaw,
          target_slug: resolvedSlug,
          title: '',
          live_following: true,
          halted_reason: null,
          active_phase_index: phaseIdx,
          frames: [],
        }
      : null,
  };
}
