import type { AtlasEdge, AtlasNode } from '@/api/atlas';
import type { WythePaletteColors } from '@/lib/wytheTheme';

export type SceneLens = 'status' | 'contention' | 'gravity' | 'subkind' | 'cluster';
export type SceneLayoutMode = 'cluster' | 'grid';
export type EdgeFilterMode = 'all' | 'writes' | 'reads' | 'guards' | 'helpers' | 'unverified';

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

export function computeScenePositions(
  nodes: AtlasNode[],
  layoutMode: SceneLayoutMode,
): Map<string, [number, number, number]> {
  const map = new Map<string, [number, number, number]>();
  const yForNode = (n: AtlasNode) =>
    n.subkind === 'sql_function' ? -15.2 : TIER_BASE_Y[n.tier];

  if (layoutMode === 'grid') {
    for (const tier of ['display', 'manipulate', 'truth'] as const) {
      const list = nodes.filter((n) => n.tier === tier).sort((a, b) => a.id.localeCompare(b.id));
      const count = list.length;
      const cols = Math.max(1, Math.ceil(Math.sqrt(count * 1.5)));
      const rows = Math.max(1, Math.ceil(count / cols));
      const sp = count > 180 ? 2.8 : count > 50 ? 4.2 : 6.5;
      list.forEach((n, idx) => {
        const r = Math.floor(idx / cols);
        const c = idx % cols;
        const jit = ((idx * 7) % 5) * 0.14;
        map.set(n.id, [(c - (cols - 1) / 2) * sp + jit, yForNode(n), (r - (rows - 1) / 2) * sp - jit]);
      });
    }
    return map;
  }

  // Domain Cluster Layout: shared (anchorX, anchorZ) districts across all 3 strata
  const clusterTotals = new Map<string, number>();
  const nodeCluster = new Map<string, string>();
  for (const n of nodes) {
    const cl = deriveDomainCluster(n);
    nodeCluster.set(n.id, cl);
    clusterTotals.set(cl, (clusterTotals.get(cl) ?? 0) + 1);
  }
  const allDistricts = [...clusterTotals.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([name]) => name);
  const groups = new Map<string, Map<AtlasNode['tier'], AtlasNode[]>>();
  for (const node of nodes) {
    const district = nodeCluster.get(node.id)!;
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
    for (const group of groups.get(district)!.values()) {
      const { cols, rows, cell } = dimensions(group.length);
      widths[index % dCols] = Math.max(widths[index % dCols], cols * cell + 8);
      depths[Math.floor(index / dCols)] = Math.max(depths[Math.floor(index / dCols)], rows * cell + 8);
    }
  });
  const centers = (sizes: number[]) => {
    let cursor = -sizes.reduce((a, b) => a + b, 0) / 2;
    return sizes.map((size) => { const center = cursor + size / 2; cursor += size; return center; });
  };
  const xs = centers(widths);
  const zs = centers(depths);
  const anchors = new Map(allDistricts.map((district, index) =>
    [district, [xs[index % dCols], zs[Math.floor(index / dCols)]]] as const,
  ));

  for (const tier of ['display', 'manipulate', 'truth'] as const) {
    const tierNodes = nodes.filter((n) => n.tier === tier);
    const byDistrict = new Map<string, AtlasNode[]>();
    for (const n of tierNodes) {
      const raw = nodeCluster.get(n.id) ?? 'core';
      const key = raw;
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
        const lx = (c - (gCols - 1) / 2) * cell;
        const lz = (r - (gRows - 1) / 2) * cell;
        map.set(n.id, [ax + lx, yForNode(n), az + lz]);
      });
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

export function evaluateEdgeVisual(
  edge: AtlasEdge,
  filterMode: EdgeFilterMode,
): { visible: boolean; hex: number } {
  const isWrite = edge.kind === 'writes_truth' || edge.kind === 'mutates_endpoint';
  const isRead = edge.kind === 'reads_truth' || edge.kind === 'queries_endpoint';
  const isGuard = edge.kind === 'guards_truth';
  const isHelper =
    edge.kind === 'calls_helper' || edge.kind === 'uses_hook' || edge.kind === 'uses_client';
  const isUnverified = edge.verification !== 'verified';

  if (filterMode === 'writes' && !isWrite) return { visible: false, hex: 0 };
  if (filterMode === 'reads' && !isRead) return { visible: false, hex: 0 };
  if (filterMode === 'guards' && !isGuard) return { visible: false, hex: 0 };
  if (filterMode === 'helpers' && !isHelper) return { visible: false, hex: 0 };
  if (filterMode === 'unverified' && !isUnverified) return { visible: false, hex: 0 };

  if (isUnverified) return { visible: true, hex: 0xf43f5e };
  if (isGuard) return { visible: true, hex: 0xa3e635 };
  if (isWrite) return { visible: true, hex: 0xf59e0b };
  if (isRead) return { visible: true, hex: 0x38bdf8 };
  return { visible: true, hex: 0x64748b };
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
