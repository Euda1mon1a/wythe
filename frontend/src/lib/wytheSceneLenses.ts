import type { AtlasEdge, AtlasNode } from '@/api/atlas';
import type { WythePaletteColors } from '@/lib/wytheTheme';

export type SceneLens = 'status' | 'contention' | 'gravity' | 'subkind' | 'cluster';
export type SceneLayoutMode = 'cluster' | 'grid' | 'subkind' | 'connected';

export const SCENE_LAYOUT_LABELS: Record<SceneLayoutMode, string> = {
  cluster: 'Domain Districts',
  grid: 'Uniform Grid',
  subkind: 'Kind Groups',
  connected: 'Connected Components',
};

export const SCENE_LAYOUT_DISTANCE_NOTES: Record<SceneLayoutMode, string> = {
  cluster: 'Distances group inferred domain districts across tiers; not edge coupling.',
  grid: 'Distances pack tiers alphabetically in rows; not edge proximity.',
  subkind: 'Distances group nodes by subkind across tiers; not runtime call flow.',
  connected:
    'Deterministic spring heuristic pulls linked nodes closer and packs singletons separately; illustrative only.',
};

export interface ScenePositionOptions {
  edges?: AtlasEdge[];
  flatten2D?: boolean;
  pinnedPositions?:
    | ReadonlyMap<string, [number, number, number]>
    | Record<string, [number, number, number]>;
}
export type EdgeLinePattern = 'solid' | 'dashed' | 'dotted' | 'broken_gap';
export type EdgeFilterMode =
  | 'all'
  | 'writes'
  | 'reads'
  | 'guards'
  | 'helpers'
  | 'verified'
  | 'declared'
  | 'unverified'
  | 'broken';

export const SCENE_LENS_LABELS: Record<SceneLens, string> = {
  status: 'Boundary Status',
  contention: 'Write Contention',
  gravity: 'Fan-Out Gravity',
  subkind: '11-Subkind Taxonomy',
  cluster: 'Domain Clusters',
};

export const ALL_NODE_SUBKINDS: Array<AtlasNode['subkind']> = [
  'table',
  'sql_function',
  'cache_store',
  'route',
  'service',
  'solver',
  'cli',
  'page',
  'hook',
  'api_client',
  'component',
];

export const SUBKIND_HEX: Record<AtlasNode['subkind'], string> = {
  table: '#2dd4bf',
  sql_function: '#a3e635',
  cache_store: '#fb923c',
  route: '#38bdf8',
  service: '#818cf8',
  solver: '#e879f9',
  cli: '#facc15',
  page: '#3b82f6',
  hook: '#22d3ee',
  api_client: '#60a5fa',
  component: '#a78bfa',
};

const CLUSTER_PALETTE = [
  '#2dd4bf',
  '#38bdf8',
  '#f59e0b',
  '#a78bfa',
  '#34d399',
  '#fb7185',
  '#facc15',
  '#22d3ee',
  '#f97316',
  '#818cf8',
];

export interface DiffOverlaySet {
  label: string;
  touchedIds: Set<string>;
  impactedIds: Set<string>;
  newFindingNodeIds: Set<string>;
  addedIds: Set<string>;
  resolvedIds: Set<string>;
}

const TIER_BASE_Y: Record<AtlasNode['tier'], number> = {
  display: 18,
  manipulate: 0,
  truth: -18,
};

export function deriveDomainCluster(node: AtlasNode): string {
  if (node.cluster && node.cluster !== 'core') {
    return node.cluster;
  }
  const cleanPath = node.source_file.replace(/\\/g, '/');
  const segs = cleanPath.split('/').filter(Boolean);
  for (const s of segs) {
    if (
      ![
        'backend',
        'frontend',
        'src',
        'app',
        'api',
        'v1',
        'routes',
        'services',
        'models',
        'schemas',
        'components',
        'hooks',
        'pages',
        'lib',
        'db',
        'migrations',
        'alembic',
        'versions',
      ].includes(s) &&
      !s.includes('.')
    ) {
      return s.slice(0, 18);
    }
  }
  const stem = (segs[segs.length - 1] ?? node.label)
    .replace(/\.[a-z0-9]+$/i, '')
    .replace(/(_service|_router|_route|Service|View|Panel|Page)$/g, '');
  const token = stem.split(/[_/-]/).filter(Boolean)[0] ?? 'core';
  return token.toLowerCase().slice(0, 16) || 'core';
}

export function clusterColorHex(clusterName: string): string {
  let h = 2166136261;
  for (let i = 0; i < clusterName.length; i += 1) {
    h ^= clusterName.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return CLUSTER_PALETTE[Math.abs(h) % CLUSTER_PALETTE.length];
}

const TIER_ORDER: Record<AtlasNode['tier'], number> = { display: 0, manipulate: 1, truth: 2 };

function packGroupedDistricts(
  nodes: AtlasNode[],
  keyFn: (node: AtlasNode) => string,
  orderedKeys: string[] | null,
  flatten2D: boolean,
  yForNode: (node: AtlasNode) => number,
): Map<string, [number, number, number]> {
  const map = new Map<string, [number, number, number]>();
  const totals = new Map<string, number>();
  const nodeKey = new Map<string, string>();
  for (const n of nodes) {
    const key = keyFn(n);
    nodeKey.set(n.id, key);
    totals.set(key, (totals.get(key) ?? 0) + 1);
  }
  const allDistricts = orderedKeys
    ? orderedKeys.filter((k) => (totals.get(k) ?? 0) > 0)
    : [...totals.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([name]) => name);

  const groups = new Map<string, Map<AtlasNode['tier'], AtlasNode[]>>();
  for (const node of nodes) {
    const district = nodeKey.get(node.id)!;
    if (!groups.has(district)) groups.set(district, new Map());
    const tiers = groups.get(district)!;
    if (!tiers.has(node.tier)) tiers.set(node.tier, []);
    tiers.get(node.tier)!.push(node);
  }
  const dimensions = (count: number) => {
    const cols = Math.max(1, Math.ceil(Math.sqrt(count * 1.3)));
    return { cols, rows: Math.max(1, Math.ceil(count / cols)), cell: count > 25 ? 2.8 : 3.5 };
  };
  const dCols = Math.max(1, Math.ceil(Math.sqrt(allDistricts.length * 1.35)));
  const dRows = Math.max(1, Math.ceil(allDistricts.length / dCols));
  const widths = Array<number>(dCols).fill(0);
  const depths = Array<number>(dRows).fill(0);
  allDistricts.forEach((district, index) => {
    if (flatten2D) {
      const { cols, rows, cell } = dimensions(totals.get(district) ?? 0);
      widths[index % dCols] = Math.max(widths[index % dCols], cols * cell + 8);
      depths[Math.floor(index / dCols)] = Math.max(depths[Math.floor(index / dCols)], rows * cell + 8);
    } else {
      for (const group of groups.get(district)!.values()) {
        const { cols, rows, cell } = dimensions(group.length);
        widths[index % dCols] = Math.max(widths[index % dCols], cols * cell + 8);
        depths[Math.floor(index / dCols)] = Math.max(depths[Math.floor(index / dCols)], rows * cell + 8);
      }
    }
  });
  const centers = (sizes: number[]) => {
    let cursor = -sizes.reduce((a, b) => a + b, 0) / 2;
    return sizes.map((size) => {
      const center = cursor + size / 2;
      cursor += size;
      return center;
    });
  };
  const xs = centers(widths);
  const zs = centers(depths);
  const anchors = new Map(
    allDistricts.map((district, index) => [district, [xs[index % dCols], zs[Math.floor(index / dCols)]]] as const),
  );

  if (flatten2D) {
    for (const dKey of allDistricts) {
      const [ax, az] = anchors.get(dKey) ?? [0, 0];
      const allInGroup = [...(groups.get(dKey)?.values() ?? [])]
        .flat()
        .sort((a, b) => TIER_ORDER[a.tier] - TIER_ORDER[b.tier] || a.id.localeCompare(b.id));
      const { cols: gCols, rows: gRows, cell } = dimensions(allInGroup.length);
      allInGroup.forEach((n, idx) => {
        const r = Math.floor(idx / gCols);
        const c = idx % gCols;
        map.set(n.id, [ax + (c - (gCols - 1) / 2) * cell, 0, az + (r - (gRows - 1) / 2) * cell]);
      });
    }
    return map;
  }

  for (const tier of ['display', 'manipulate', 'truth'] as const) {
    const tierNodes = nodes.filter((n) => n.tier === tier);
    const byDistrict = new Map<string, AtlasNode[]>();
    for (const n of tierNodes) {
      const key = nodeKey.get(n.id) ?? 'core';
      const arr = byDistrict.get(key) ?? [];
      arr.push(n);
      byDistrict.set(key, arr);
    }
    for (const [dKey, group] of byDistrict.entries()) {
      const [ax, az] = anchors.get(dKey) ?? [0, 0];
      group.sort((a, b) => a.id.localeCompare(b.id));
      const { cols: gCols, rows: gRows, cell } = dimensions(group.length);
      group.forEach((n, idx) => {
        const r = Math.floor(idx / gCols);
        const c = idx % gCols;
        map.set(n.id, [
          ax + (c - (gCols - 1) / 2) * cell,
          yForNode(n),
          az + (r - (gRows - 1) / 2) * cell,
        ]);
      });
    }
  }
  return map;
}

function layoutConnectedComponents(
  nodes: AtlasNode[],
  edges: AtlasEdge[],
  flatten2D: boolean,
  yForNode: (node: AtlasNode) => number,
): Map<string, [number, number, number]> {
  const map = new Map<string, [number, number, number]>();
  const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id));
  const byId = new Map(sorted.map((n) => [n.id, n]));
  const adj = new Map<string, string[]>();
  for (const n of sorted) adj.set(n.id, []);
  for (const e of edges) {
    if (e.source_id === e.target_id) continue;
    if (!byId.has(e.source_id) || !byId.has(e.target_id)) continue;
    adj.get(e.source_id)!.push(e.target_id);
    adj.get(e.target_id)!.push(e.source_id);
  }
  for (const list of adj.values()) list.sort();

  const visited = new Set<string>();
  const components: AtlasNode[][] = [];
  const singletons: AtlasNode[] = [];
  for (const seed of sorted) {
    if (visited.has(seed.id)) continue;
    const comp: AtlasNode[] = [];
    const queue = [seed.id];
    visited.add(seed.id);
    for (let qi = 0; qi < queue.length; qi += 1) {
      const cur = queue[qi];
      comp.push(byId.get(cur)!);
      for (const nxt of adj.get(cur) ?? []) {
        if (!visited.has(nxt)) {
          visited.add(nxt);
          queue.push(nxt);
        }
      }
    }
    if (comp.length <= 1) singletons.push(comp[0]);
    else components.push(comp);
  }
  components.sort((a, b) => b.length - a.length || a[0].id.localeCompare(b[0].id));

  interface Box {
    items: Array<{ node: AtlasNode; lx: number; lz: number }>;
    width: number;
    depth: number;
  }
  const boxes: Box[] = [];
  const idealDist = 3.2;
  const minDist = 3.2;

  for (const comp of components) {
    const n = comp.length;
    const root = [...comp].sort(
      (a, b) => (adj.get(b.id)?.length ?? 0) - (adj.get(a.id)?.length ?? 0) || a.id.localeCompare(b.id),
    )[0];
    const bfsOrder: Array<{ id: string; depth: number }> = [];
    const seen = new Set<string>([root.id]);
    const bfsQ: Array<{ id: string; depth: number }> = [{ id: root.id, depth: 0 }];
    for (let qi = 0; qi < bfsQ.length; qi += 1) {
      const item = bfsQ[qi];
      bfsOrder.push(item);
      for (const nxt of adj.get(item.id) ?? []) {
        if (seen.has(nxt)) continue;
        seen.add(nxt);
        bfsQ.push({ id: nxt, depth: item.depth + 1 });
      }
    }
    const ringCounts = new Map<number, number>();
    const ringIdx = new Map<number, number>();
    for (const item of bfsOrder) ringCounts.set(item.depth, (ringCounts.get(item.depth) ?? 0) + 1);
    const localPos = new Map<string, [number, number]>();
    for (const item of bfsOrder) {
      if (item.depth === 0) {
        localPos.set(item.id, [0, 0]);
        continue;
      }
      const idx = ringIdx.get(item.depth) ?? 0;
      ringIdx.set(item.depth, idx + 1);
      const count = ringCounts.get(item.depth) ?? 1;
      const angle = (2 * Math.PI * idx) / count + item.depth * 0.37;
      const radius = item.depth * 3.8 + Math.sqrt(count) * 0.6;
      localPos.set(item.id, [Math.cos(angle) * radius, Math.sin(angle) * radius]);
    }
    const compIds = new Set(comp.map((c) => c.id));
    const internalEdges = edges.filter(
      (e) => e.source_id !== e.target_id && compIds.has(e.source_id) && compIds.has(e.target_id),
    );
    const cellSize = minDist;
    for (let iter = 0; iter < 30 && n > 1; iter += 1) {
      const forces = new Map<string, [number, number]>(comp.map((c) => [c.id, [0, 0]]));
      for (const e of internalEdges) {
        const pa = localPos.get(e.source_id)!;
        const pb = localPos.get(e.target_id)!;
        const dx = pb[0] - pa[0];
        const dz = pb[1] - pa[1];
        const dist = Math.hypot(dx, dz) || 0.01;
        const pull = (dist - idealDist) * 0.14;
        const fx = (dx / dist) * pull;
        const fz = (dz / dist) * pull;
        forces.get(e.source_id)![0] += fx;
        forces.get(e.source_id)![1] += fz;
        forces.get(e.target_id)![0] -= fx;
        forces.get(e.target_id)![1] -= fz;
      }
      const buckets = new Map<string, string[]>();
      for (const c of comp) {
        const [x, z] = localPos.get(c.id)!;
        const key = `${Math.floor(x / cellSize)},${Math.floor(z / cellSize)}`;
        const arr = buckets.get(key) ?? [];
        arr.push(c.id);
        buckets.set(key, arr);
      }
      for (const c of comp) {
        const pa = localPos.get(c.id)!;
        const bx = Math.floor(pa[0] / cellSize);
        const bz = Math.floor(pa[1] / cellSize);
        for (let ox = -1; ox <= 1; ox += 1) {
          for (let oz = -1; oz <= 1; oz += 1) {
            for (const otherId of buckets.get(`${bx + ox},${bz + oz}`) ?? []) {
              if (otherId <= c.id) continue;
              const pb = localPos.get(otherId)!;
              const dx = pa[0] - pb[0];
              const dz = pa[1] - pb[1];
              const dist = Math.hypot(dx, dz) || 0.01;
              if (dist >= minDist) continue;
              const push = ((minDist - dist) / dist) * 0.45;
              const px = dx * push;
              const pz = dz * push;
              forces.get(c.id)![0] += px;
              forces.get(c.id)![1] += pz;
              forces.get(otherId)![0] -= px;
              forces.get(otherId)![1] -= pz;
            }
          }
        }
      }
      for (const c of comp) {
        const p = localPos.get(c.id)!;
        const f = forces.get(c.id)!;
        const mag = Math.hypot(f[0], f[1]);
        const clamp = mag > 1.8 ? 1.8 / mag : 1;
        p[0] += f[0] * clamp;
        p[1] += f[1] * clamp;
      }
    }

    let minX = Infinity;
    let maxX = -Infinity;
    let minZ = Infinity;
    let maxZ = -Infinity;
    for (const [x, z] of localPos.values()) {
      minX = Math.min(minX, x);
      maxX = Math.max(maxX, x);
      minZ = Math.min(minZ, z);
      maxZ = Math.max(maxZ, z);
    }
    const cx = (minX + maxX) / 2;
    const cz = (minZ + maxZ) / 2;
    boxes.push({
      items: comp.map((node) => {
        const [x, z] = localPos.get(node.id)!;
        return { node, lx: x - cx, lz: z - cz };
      }),
      width: Math.max(6, maxX - minX + 7),
      depth: Math.max(6, maxZ - minZ + 7),
    });
  }

  if (singletons.length > 0) {
    const sCols = Math.max(1, Math.ceil(Math.sqrt(singletons.length * 1.4)));
    const sRows = Math.max(1, Math.ceil(singletons.length / sCols));
    const cell = singletons.length > 40 ? 3.0 : 3.8;
    boxes.push({
      items: singletons.map((node, idx) => ({
        node,
        lx: ((idx % sCols) - (sCols - 1) / 2) * cell,
        lz: (Math.floor(idx / sCols) - (sRows - 1) / 2) * cell,
      })),
      width: Math.max(6, sCols * cell + 7),
      depth: Math.max(6, sRows * cell + 7),
    });
  }

  const bCols = Math.max(1, Math.ceil(Math.sqrt(boxes.length * 1.35)));
  const bRows = Math.max(1, Math.ceil(boxes.length / bCols));
  const widths = Array<number>(bCols).fill(0);
  const depths = Array<number>(bRows).fill(0);
  boxes.forEach((box, idx) => {
    widths[idx % bCols] = Math.max(widths[idx % bCols], box.width);
    depths[Math.floor(idx / bCols)] = Math.max(depths[Math.floor(idx / bCols)], box.depth);
  });
  const centers = (sizes: number[]) => {
    let cursor = -sizes.reduce((a, b) => a + b, 0) / 2;
    return sizes.map((size) => {
      const center = cursor + size / 2;
      cursor += size;
      return center;
    });
  };
  const xs = centers(widths);
  const zs = centers(depths);
  boxes.forEach((box, idx) => {
    const ax = xs[idx % bCols];
    const az = zs[Math.floor(idx / bCols)];
    for (const item of box.items) {
      map.set(item.node.id, [ax + item.lx, flatten2D ? 0 : yForNode(item.node), az + item.lz]);
    }
  });
  return map;
}

export function computeScenePositions(
  nodes: AtlasNode[],
  layoutMode: SceneLayoutMode,
  options: ScenePositionOptions = {},
): Map<string, [number, number, number]> {
  const flatten2D = Boolean(options.flatten2D);
  const yForNode = (n: AtlasNode) =>
    flatten2D ? 0 : n.subkind === 'sql_function' ? -15.2 : TIER_BASE_Y[n.tier];

  let map: Map<string, [number, number, number]>;
  if (layoutMode === 'grid') {
    map = new Map<string, [number, number, number]>();
    const bands = (['display', 'manipulate', 'truth'] as const).map((tier) => {
      const list = nodes.filter((n) => n.tier === tier).sort((a, b) => a.id.localeCompare(b.id));
      const count = list.length;
      const cols = Math.max(1, Math.ceil(Math.sqrt(count * 1.5)));
      const rows = Math.max(1, Math.ceil(count / cols));
      const sp = count > 180 ? 2.8 : count > 50 ? 4.2 : 6.5;
      return { tier, list, cols, rows, sp, depth: rows * sp };
    });
    const totalDepth2D = bands.reduce((acc, b) => acc + (b.list.length ? b.depth + 6 : 0), 0);
    let cursorZ = -totalDepth2D / 2;
    for (const band of bands) {
      if (band.list.length === 0) continue;
      const bandCenterZ = flatten2D ? cursorZ + (band.depth + 6) / 2 : 0;
      if (flatten2D) cursorZ += band.depth + 6;
      band.list.forEach((n, idx) => {
        const r = Math.floor(idx / band.cols);
        const c = idx % band.cols;
        const jit = ((idx * 7) % 5) * 0.14;
        map.set(n.id, [
          (c - (band.cols - 1) / 2) * band.sp + jit,
          yForNode(n),
          bandCenterZ + (r - (band.rows - 1) / 2) * band.sp - jit,
        ]);
      });
    }
  } else if (layoutMode === 'subkind') {
    map = packGroupedDistricts(nodes, (n) => n.subkind, [...ALL_NODE_SUBKINDS], flatten2D, yForNode);
  } else if (layoutMode === 'connected') {
    map = layoutConnectedComponents(nodes, options.edges ?? [], flatten2D, yForNode);
  } else {
    map = packGroupedDistricts(nodes, deriveDomainCluster, null, flatten2D, yForNode);
  }

  if (options.pinnedPositions) {
    const entries =
      options.pinnedPositions instanceof Map
        ? options.pinnedPositions.entries()
        : Object.entries(options.pinnedPositions);
    for (const [id, coords] of entries) {
      if (map.has(id)) {
        map.set(id, [coords[0], flatten2D ? 0 : coords[1], coords[2]]);
      }
    }
  }
  return map;
}

export interface EvaluatedNodeVisual {
  barHex: string;
  inquiryHex: string;
  scale: number;
  hollow: boolean;
  flagged: boolean;
  forceDim: boolean;
}

export function evaluateNodeVisual(opts: {
  node: AtlasNode;
  lens: SceneLens;
  palette: WythePaletteColors;
  degree: number;
  guardedTableIds: Set<string>;
  mutatorNodeIds: Set<string>;
  diffOverlay: DiffOverlaySet | null;
}): EvaluatedNodeVisual {
  const { node: n, lens, palette, degree, guardedTableIds, mutatorNodeIds, diffOverlay } = opts;
  const hollow = n.status === 'in_flight' || n.status === 'unwired' || n.status === 'orphaned';
  const baseFlagged =
    n.status === 'policy_in_code' || n.status === 'duplicated_truth' || n.status === 'gray_zone';
  const tierHex =
    n.tier === 'display'
      ? palette.display
      : n.tier === 'manipulate'
        ? palette.manipulate
        : palette.truth;

  let barHex = tierHex;
  let inquiryHex = baseFlagged ? palette.warn : palette.inquiry;
  let scale = 1.0;
  let flagged = baseFlagged;

  if (lens === 'status') {
    barHex =
      n.status === 'duplicated_truth'
        ? palette.danger
        : baseFlagged
          ? palette.warn
          : hollow
            ? palette.muted
            : tierHex;
    inquiryHex =
      n.status === 'duplicated_truth'
        ? palette.danger
        : baseFlagged
          ? palette.warn
          : palette.inquiry;
  } else if (lens === 'contention') {
    const writes = n.written_by_count ?? 0;
    const isGuarded = guardedTableIds.has(n.id);
    if (n.subkind === 'sql_function') {
      barHex = '#a3e635';
      inquiryHex = '#ecfccb';
      scale = 1.18;
    } else if (n.tier === 'truth') {
      if (writes >= 3 && !isGuarded) {
        barHex = '#f43f5e';
        inquiryHex = '#fda4af';
        flagged = true;
        scale = 1.38;
      } else if (writes >= 2) {
        barHex = isGuarded ? '#2dd4bf' : '#f59e0b';
        inquiryHex = isGuarded ? '#a3e635' : '#fde047';
        flagged = !isGuarded;
        scale = 1.2;
      } else if (writes === 1) {
        barHex = '#10b981';
      } else {
        barHex = '#475569';
      }
    } else if (mutatorNodeIds.has(n.id)) {
      barHex = '#f59e0b';
      inquiryHex = '#fef08a';
      scale = 1.12;
    } else {
      barHex = '#334155';
    }
  } else if (lens === 'gravity') {
    const touchScore = degree + (n.read_by_count ?? 0) + (n.written_by_count ?? 0) * 2;
    scale = Math.min(2.15, Math.max(0.78, 0.78 + 0.24 * Math.log2(1 + touchScore)));
    if (touchScore >= 18) {
      barHex = '#f43f5e';
      inquiryHex = '#fecdd3';
      flagged = true;
    } else if (touchScore >= 9) {
      barHex = '#f59e0b';
      inquiryHex = '#fef08a';
    } else if (touchScore >= 4) {
      barHex = '#2dd4bf';
    } else if (touchScore >= 1) {
      barHex = '#38bdf8';
    } else {
      barHex = '#475569';
    }
  } else if (lens === 'subkind') {
    barHex = SUBKIND_HEX[n.subkind] ?? tierHex;
    inquiryHex = palette.inquiry;
    if (n.subkind === 'sql_function' || n.subkind === 'solver') {
      scale = 1.18;
    }
  } else if (lens === 'cluster') {
    barHex = clusterColorHex(deriveDomainCluster(n));
    inquiryHex = palette.inquiry;
  }

  let forceDim = false;
  if (diffOverlay) {
    const isTouched = diffOverlay.touchedIds.has(n.id) || diffOverlay.addedIds.has(n.id);
    const isImpacted = diffOverlay.impactedIds.has(n.id);
    const hasNewFinding = diffOverlay.newFindingNodeIds.has(n.id);
    const isResolved = diffOverlay.resolvedIds.has(n.id);
    if (hasNewFinding) {
      barHex = '#f43f5e';
      inquiryHex = '#fda4af';
      flagged = true;
      scale *= 1.35;
    } else if (isTouched) {
      barHex = '#facc15';
      inquiryHex = '#fef9c3';
      flagged = true;
      scale *= 1.3;
    } else if (isResolved) {
      barHex = '#34d399';
      inquiryHex = '#d1fae5';
      scale *= 1.18;
    } else if (isImpacted) {
      barHex = '#38bdf8';
      scale *= 1.12;
    } else {
      forceDim = true;
    }
  }

  return { barHex, inquiryHex, scale, hollow, flagged, forceDim };
}

export interface EdgeVisual {
  visible: boolean;
  hex: number;
  pattern: EdgeLinePattern;
  verification: AtlasEdge['verification'];
  verificationLabel: string;
}

export interface EdgeVerificationLegendItem {
  verification: AtlasEdge['verification'];
  color: string;
  pattern: EdgeLinePattern;
  label: string;
  count: number;
}

export function evaluateEdgeVisual(
  edge: AtlasEdge,
  filterMode: EdgeFilterMode,
): EdgeVisual {
  const isWrite = edge.kind === 'writes_truth' || edge.kind === 'mutates_endpoint';
  const isRead = edge.kind === 'reads_truth' || edge.kind === 'queries_endpoint';
  const isGuard = edge.kind === 'guards_truth';
  const isHelper =
    edge.kind === 'calls_helper' || edge.kind === 'uses_hook' || edge.kind === 'uses_client';
  const ver = edge.verification;

  const hidden: EdgeVisual = {
    visible: false,
    hex: 0,
    pattern: 'solid',
    verification: ver,
    verificationLabel: '',
  };

  if (filterMode === 'writes' && !isWrite) return hidden;
  if (filterMode === 'reads' && !isRead) return hidden;
  if (filterMode === 'guards' && !isGuard) return hidden;
  if (filterMode === 'helpers' && !isHelper) return hidden;
  if (filterMode === 'verified' && ver !== 'verified') return hidden;
  if (filterMode === 'declared' && ver !== 'declared') return hidden;
  if (filterMode === 'unverified' && ver !== 'unverified') return hidden;
  if (filterMode === 'broken' && ver !== 'broken') return hidden;

  if (ver === 'broken') {
    return {
      visible: true,
      hex: 0xf43f5e,
      pattern: 'broken_gap',
      verification: 'broken',
      verificationLabel: 'Broken Contract',
    };
  }
  if (ver === 'declared') {
    return {
      visible: true,
      hex: 0xa78bfa,
      pattern: 'dashed',
      verification: 'declared',
      verificationLabel: 'Declared Only',
    };
  }
  if (ver === 'unverified') {
    return {
      visible: true,
      hex: 0xfacc15,
      pattern: 'dotted',
      verification: 'unverified',
      verificationLabel: 'Unverified / Heuristic',
    };
  }

  const hex = isGuard ? 0xa3e635 : isWrite ? 0xf59e0b : isRead ? 0x38bdf8 : 0x64748b;
  return {
    visible: true,
    hex,
    pattern: 'solid',
    verification: 'verified',
    verificationLabel: 'Statically Verified',
  };
}

export function getEdgeVerificationLegendItems(
  edges: AtlasEdge[] = [],
): EdgeVerificationLegendItem[] {
  const counts: Record<AtlasEdge['verification'], number> = {
    verified: 0,
    declared: 0,
    unverified: 0,
    broken: 0,
  };
  for (const e of edges) {
    counts[e.verification] = (counts[e.verification] ?? 0) + 1;
  }
  return [
    {
      verification: 'verified',
      color: '#38bdf8',
      pattern: 'solid',
      label: 'verified (solid)',
      count: counts.verified,
    },
    {
      verification: 'declared',
      color: '#a78bfa',
      pattern: 'dashed',
      label: 'declared (dashed)',
      count: counts.declared,
    },
    {
      verification: 'unverified',
      color: '#facc15',
      pattern: 'dotted',
      label: 'unverified (dotted)',
      count: counts.unverified,
    },
    {
      verification: 'broken',
      color: '#f43f5e',
      pattern: 'broken_gap',
      label: 'broken (gap)',
      count: counts.broken,
    },
  ];
}

export function getLensLegendItems(
  lens: SceneLens,
  diffActive: boolean,
): Array<{ color: string; label: string }> {
  if (diffActive) {
    return [
      { color: '#facc15', label: 'touched / +added' },
      { color: '#38bdf8', label: 'blast-cone impacted' },
      { color: '#f43f5e', label: 'new finding' },
      { color: '#34d399', label: 'resolved finding' },
    ];
  }
  if (lens === 'contention') {
    return [
      { color: '#f43f5e', label: '3+ writers (unguarded)' },
      { color: '#f59e0b', label: '2 writers / mutator' },
      { color: '#a3e635', label: 'SQL guard function' },
      { color: '#10b981', label: 'single-writer table' },
    ];
  }
  if (lens === 'gravity') {
    return [
      { color: '#f43f5e', label: 'critical hub (18+ links)' },
      { color: '#f59e0b', label: 'high fan-out (9–17)' },
      { color: '#2dd4bf', label: 'medium (4–8)' },
      { color: '#38bdf8', label: 'leaf (1–3)' },
    ];
  }
  if (lens === 'subkind') {
    return [
      { color: '#2dd4bf', label: 'table' },
      { color: '#a3e635', label: 'sql_function' },
      { color: '#fb923c', label: 'cache_store' },
      { color: '#38bdf8', label: 'route' },
      { color: '#818cf8', label: 'service' },
      { color: '#e879f9', label: 'solver' },
      { color: '#3b82f6', label: 'page/hook/client' },
    ];
  }
  if (lens === 'cluster') {
    return [
      { color: '#2dd4bf', label: 'vertical domain districts aligned across Display · Manipulate · Truth' },
    ];
  }
  return [
    { color: '#2dd4bf', label: 'clean' },
    { color: '#f59e0b', label: 'policy_in_code / gray_zone' },
    { color: '#f43f5e', label: 'duplicated_truth' },
  ];
}
