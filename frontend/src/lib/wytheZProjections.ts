import type {
  AtlasEdge,
  AtlasNode,
  BoundaryFinding,
  DiffBlastRadiusReport,
  SnapshotComparisonReport,
} from '@/api/atlas';

export type LifecycleWytheIndex = 0 | 1 | 2;

export interface CanonicalXYOptions {
  edges?: ReadonlyArray<AtlasEdge>;
  unionNodes?: ReadonlyArray<AtlasNode>;
  flatten2D?: boolean;
  pairContainerAnchors?: boolean;
}

export interface LifecycleWallTie {
  id: string;
  logicalKey: string;
  sourceNodeId: string;
  targetNodeId: string;
  fromWythe: LifecycleWytheIndex;
  toWythe: LifecycleWytheIndex;
  start: [number, number, number];
  end: [number, number, number];
  status: 'intact' | 'drift';
  kind:
    | 'truth_catalog_drift'
    | 'container_packaging_drift'
    | 'container_entrypoint_tie'
    | 'plugin_stratum_mismatch'
    | 'plugin_stratum_tie'
    | 'runtime_store_tie'
    | 'stage_identity_tie';
  ruleCode: string | null;
  label: string;
}

export interface LifecycleProjectedBrick {
  instanceId: string;
  node: AtlasNode;
  wythe: LifecycleWytheIndex;
  position: [number, number, number];
  isReplica: boolean;
  driftStatus: 'intact' | 'drift';
  ruleCodes: string[];
}

export interface LifecycleEntityPresence {
  nodeId: string;
  logicalKey: string;
  wythes: LifecycleWytheIndex[];
  wytheLabels: string[];
  tieStatus: 'blueprint_only' | 'intact' | 'drift';
  driftRuleCodes: string[];
  summary: string;
}

export interface LifecycleZProjectionResult {
  canonicalXY: Map<string, [number, number]>;
  activeWythes: LifecycleWytheIndex[];
  wytheZ: Map<LifecycleWytheIndex, number>;
  primaryPositions: Map<string, [number, number, number]>;
  bricks: LifecycleProjectedBrick[];
  wallTies: LifecycleWallTie[];
  entityPresence: Map<string, LifecycleEntityPresence>;
}

const STAGE_ID_PREFIX_RE = /^(?:z0:|z1:|z2:|blueprint:|built:|crate:|image:|live:|runtime:|wiretap:)/i;
const NATIVE_Z2_PREFIX_RE = /^(?:z2:|live:|runtime:|wiretap:)/i;
const NATIVE_Z1_PREFIX_RE = /^(?:z1:|built:|crate:|image:|m:registry:)/i;
const CONTAINER_NODE_PREFIXES = [
  'm:dockerfile:',
  'm:compose:',
  'm:k8s:',
  'm:launchd:',
  'm:systemd:',
] as const;

const Z1_BADGE_KEY_RE =
  /(?:metal|air|\bir\b|sil|llvm|binary|macho|elf|codesign|entitlement|crate|sbom|syft|trivy|zoom2|z1)/i;
const Z2_BADGE_KEY_RE =
  /(?:wiretap|otel|ebpf|trace|memgraph|heap|retain|vmmap|runtime|catalog|zoom3|z2)/i;
const DRIFT_BADGE_KEY_RE =
  /(?:drift|mismatch|missing|omit|unexercised|runtime_only|retain_cycle|leak|orphan|broken)/i;

const TIER_ELEVATION_Y: Record<AtlasNode['tier'], number> = {
  display: 18,
  manipulate: 0,
  truth: -18,
};

const TIER_SORT_INDEX: Record<AtlasNode['tier'], number> = {
  display: 0,
  manipulate: 1,
  truth: 2,
};

export function isContainerBuildNode(node: Pick<AtlasNode, 'id' | 'cluster'>): boolean {
  if (node.cluster === 'containers') return true;
  return CONTAINER_NODE_PREFIXES.some((prefix) => node.id.startsWith(prefix));
}

export function deriveLogicalIdentityKey(node: Pick<AtlasNode, 'id'>): string {
  return node.id.replace(STAGE_ID_PREFIX_RE, '');
}

export function classifyNativeWythe(node: Pick<AtlasNode, 'id' | 'cluster'>): LifecycleWytheIndex {
  if (NATIVE_Z2_PREFIX_RE.test(node.id)) return 2;
  if (NATIVE_Z1_PREFIX_RE.test(node.id) || isContainerBuildNode(node)) return 1;
  return 0;
}

function inferDomainKey(node: AtlasNode): string {
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

export function computeCanonicalXYPositions(
  nodes: ReadonlyArray<AtlasNode>,
  options: CanonicalXYOptions = {},
): Map<string, [number, number]> {
  const flatten2D = Boolean(options.flatten2D);
  const allById = new Map<string, AtlasNode>();
  for (const u of options.unionNodes ?? []) allById.set(u.id, u);
  for (const n of nodes) allById.set(n.id, n);
  const universe = [...allById.values()];
  if (universe.length === 0) return new Map();

  // Pair unique container build nodes on Z=1 to their primary Z=0 entrypoint when enabled.
  const containerAnchorLogical = new Map<string, string>();
  const claimedZ1Anchors = new Set<string>();
  if ((options.pairContainerAnchors ?? true) && options.edges && options.edges.length > 0) {
    const sortedEdges = [...options.edges].sort((a, b) => a.id.localeCompare(b.id));
    for (const e of sortedEdges) {
      const src = allById.get(e.source_id);
      const dst = allById.get(e.target_id);
      if (!src || !dst) continue;
      if (isContainerBuildNode(src) && classifyNativeWythe(dst) === 0) {
        const anchorKey = deriveLogicalIdentityKey(dst);
        if (!containerAnchorLogical.has(src.id) && !claimedZ1Anchors.has(anchorKey)) {
          containerAnchorLogical.set(src.id, anchorKey);
          claimedZ1Anchors.add(anchorKey);
        }
      } else if (isContainerBuildNode(dst) && classifyNativeWythe(src) === 0) {
        const anchorKey = deriveLogicalIdentityKey(src);
        if (!containerAnchorLogical.has(dst.id) && !claimedZ1Anchors.has(anchorKey)) {
          containerAnchorLogical.set(dst.id, anchorKey);
          claimedZ1Anchors.add(anchorKey);
        }
      }
    }
  }

  const repByLogical = new Map<string, AtlasNode>();
  const membersByLogical = new Map<string, AtlasNode[]>();
  for (const n of [...universe].sort((a, b) => classifyNativeWythe(a) - classifyNativeWythe(b) || a.id.localeCompare(b.id))) {
    const lKey = containerAnchorLogical.get(n.id) ?? deriveLogicalIdentityKey(n);
    if (!repByLogical.has(lKey)) repByLogical.set(lKey, n);
    const list = membersByLogical.get(lKey) ?? [];
    list.push(n);
    membersByLogical.set(lKey, list);
  }

  const byDomain = new Map<string, Map<AtlasNode['tier'], string[]>>();
  for (const [lKey, rep] of repByLogical.entries()) {
    const dom = inferDomainKey(rep);
    if (!byDomain.has(dom)) byDomain.set(dom, new Map());
    const tierMap = byDomain.get(dom)!;
    const arr = tierMap.get(rep.tier) ?? [];
    arr.push(lKey);
    tierMap.set(rep.tier, arr);
  }

  const domains = [...byDomain.keys()].sort((a, b) => a.localeCompare(b));
  const subCellX = 3.4;
  const colGap = 5.8;
  const stdPitch = 16.0;
  const colWidths = domains.map((dom) => {
    const tierMap = byDomain.get(dom)!;
    if (flatten2D) {
      const total = [...tierMap.values()].reduce((s, arr) => s + arr.length, 0);
      const subCols = total <= 1 ? 1 : total <= 4 ? 2 : total <= 15 ? 3 : Math.ceil(Math.sqrt(total * 1.2));
      return Math.max(stdPitch, subCols * subCellX + colGap);
    }
    let maxSubCols = 1;
    for (const arr of tierMap.values()) {
      const cnt = arr.length;
      const sc = cnt <= 1 ? 1 : cnt <= 4 ? 2 : cnt <= 15 ? 3 : Math.ceil(Math.sqrt(cnt * 1.2));
      if (sc > maxSubCols) maxSubCols = sc;
    }
    return Math.max(stdPitch, maxSubCols * subCellX + colGap);
  });

  const totalWidth = colWidths.reduce((a, b) => a + b, 0);
  let cursorX = -totalWidth / 2;
  const domainCenterX = new Map<string, number>();
  domains.forEach((dom, idx) => {
    const w = colWidths[idx];
    domainCenterX.set(dom, cursorX + w / 2);
    cursorX += w;
  });
  const logicalXY = new Map<string, [number, number]>();
  for (const dom of domains) {
    const cx = domainCenterX.get(dom) ?? 0;
    const tierMap = byDomain.get(dom)!;
    if (flatten2D) {
      const flatKeys = [...tierMap.entries()]
        .sort((a, b) => TIER_SORT_INDEX[a[0]] - TIER_SORT_INDEX[b[0]])
        .flatMap(([, keys]) => [...keys].sort((a, b) => a.localeCompare(b)));
      const cnt = flatKeys.length;
      const gCols = cnt <= 1 ? 1 : cnt <= 4 ? 2 : cnt <= 15 ? 3 : Math.ceil(Math.sqrt(cnt * 1.2));
      flatKeys.forEach((lKey, idx) => {
        const c = idx % gCols;
        const r = Math.floor(idx / gCols);
        const x = cx + (c - (gCols - 1) / 2) * subCellX + (r % 2) * 0.22;
        logicalXY.set(lKey, [x, 0]);
      });
      continue;
    }
    for (const tier of ['display', 'manipulate', 'truth'] as const) {
      const rawKeys = tierMap.get(tier) ?? [];
      if (rawKeys.length === 0) continue;
      const sortedKeys = [...rawKeys].sort((a, b) => {
        const ra = repByLogical.get(a)!;
        const rb = repByLogical.get(b)!;
        const guardOrdA = ra.subkind === 'sql_function' ? 0 : 1;
        const guardOrdB = rb.subkind === 'sql_function' ? 0 : 1;
        return guardOrdA - guardOrdB || a.localeCompare(b);
      });
      const cnt = sortedKeys.length;
      const gCols = cnt <= 1 ? 1 : cnt <= 4 ? 2 : cnt <= 15 ? 3 : Math.ceil(Math.sqrt(cnt * 1.2));
      const gRows = Math.max(1, Math.ceil(cnt / gCols));
      const stepY = Math.min(1.45, 9.6 / Math.max(1, gRows));
      const baseY = TIER_ELEVATION_Y[tier];
      sortedKeys.forEach((lKey, idx) => {
        const r = Math.floor(idx / gCols);
        const c = idx % gCols;
        const x = cx + (c - (gCols - 1) / 2) * subCellX;
        const y = baseY + ((gRows - 1) / 2 - r) * stepY;
        logicalXY.set(lKey, [x, y]);
      });
    }
  }

  const out = new Map<string, [number, number]>();
  const targetIds = new Set(nodes.map((n) => n.id));
  for (const [lKey, members] of membersByLogical.entries()) {
    const xy = logicalXY.get(lKey) ?? [0, 0];
    for (const m of members) {
      if (targetIds.has(m.id)) {
        out.set(m.id, [xy[0], xy[1]]);
      }
    }
  }
  return out;
}

export interface LifecycleProjectionOptions {
  observationSource?: string;
  flatten2D?: boolean;
}

const WYTHE_LABELS: Record<LifecycleWytheIndex, string> = {
  0: 'Z=0 Blueprint',
  1: 'Z=1 Built Crate',
  2: 'Z=2 Live Runtime',
};

function computeCollapsedWytheZ(active: LifecycleWytheIndex[]): Map<LifecycleWytheIndex, number> {
  const map = new Map<LifecycleWytheIndex, number>();
  if (active.length <= 1) {
    map.set(active[0] ?? 0, 0);
    return map;
  }
  const pitch = active.length === 2 ? 28 : 24;
  active.forEach((w, idx) => {
    map.set(w, (idx - (active.length - 1) / 2) * pitch);
  });
  return map;
}

export function computeLifecycleZProjection(
  nodes: ReadonlyArray<AtlasNode>,
  edges: ReadonlyArray<AtlasEdge> = [],
  findings: ReadonlyArray<BoundaryFinding> = [],
  options: LifecycleProjectionOptions = {},
): LifecycleZProjectionResult {
  const canonicalXY = computeCanonicalXYPositions(nodes, {
    edges,
    flatten2D: options.flatten2D,
    pairContainerAnchors: true,
  });
  const nodesById = new Map(nodes.map((n) => [n.id, n]));
  const liveCatalogActive = Boolean(
    options.observationSource &&
      /(?:live|pg_catalog|dsn|hybrid|catalog|redis)/i.test(options.observationSource),
  );

  const findingsByNode = new Map<string, BoundaryFinding[]>();
  const registerFinding = (nid: string | null | undefined, f: BoundaryFinding) => {
    if (!nid || !nodesById.has(nid)) return;
    const arr = findingsByNode.get(nid) ?? [];
    if (!arr.includes(f)) {
      arr.push(f);
      findingsByNode.set(nid, arr);
    }
  };
  for (const f of findings) {
    registerFinding(f.node_id, f);
    registerFinding(f.target_node_id, f);
    if (f.rule_code === 'MANIP-005' || f.rule_code === 'MANIP-004') {
      for (const n of nodes) {
        if (
          classifyNativeWythe(n) === 0 &&
          n.source_file &&
          (f.title.includes(n.source_file) || f.detail.includes(n.source_file))
        ) {
          registerFinding(n.id, f);
        }
      }
    }
  }

  const nativeByLogical = new Map<string, Map<LifecycleWytheIndex, AtlasNode[]>>();
  for (const n of nodes) {
    const lKey = deriveLogicalIdentityKey(n);
    const w = classifyNativeWythe(n);
    if (!nativeByLogical.has(lKey)) nativeByLogical.set(lKey, new Map());
    const wm = nativeByLogical.get(lKey)!;
    const arr = wm.get(w) ?? [];
    arr.push(n);
    wm.set(w, arr);
  }

  // Container Z=1 <-> Z=0 entrypoint pairings
  const containerLinks: Array<{ container: AtlasNode; entrypoint: AtlasNode; edge: AtlasEdge }> = [];
  const entrypointHasContainerNode = new Set<string>();
  for (const e of edges) {
    const s = nodesById.get(e.source_id);
    const t = nodesById.get(e.target_id);
    if (!s || !t) continue;
    if (isContainerBuildNode(s) && classifyNativeWythe(t) === 0) {
      containerLinks.push({ container: s, entrypoint: t, edge: e });
      entrypointHasContainerNode.add(t.id);
    } else if (isContainerBuildNode(t) && classifyNativeWythe(s) === 0) {
      containerLinks.push({ container: t, entrypoint: s, edge: e });
      entrypointHasContainerNode.add(s.id);
    }
  }

  interface PendingBrick {
    instanceId: string;
    node: AtlasNode;
    wythe: LifecycleWytheIndex;
    xy: [number, number];
    isReplica: boolean;
    driftStatus: 'intact' | 'drift';
    ruleCodes: string[];
  }
  const pendingBricks: PendingBrick[] = [];
  const occupiedSlot = new Set<string>();
  const brickXYByNodeAndWythe = new Map<string, [number, number]>();
  const addBrick = (b: PendingBrick) => {
    while (occupiedSlot.has(`${b.wythe}:${b.xy[0].toFixed(2)}:${b.xy[1].toFixed(2)}`)) {
      if (b.isReplica) {
        if (!brickXYByNodeAndWythe.has(`${b.node.id}@${b.wythe}`)) {
          brickXYByNodeAndWythe.set(`${b.node.id}@${b.wythe}`, b.xy);
        }
        return;
      }
      b = { ...b, xy: [b.xy[0] + 1.9, b.xy[1]] };
    }
    occupiedSlot.add(`${b.wythe}:${b.xy[0].toFixed(2)}:${b.xy[1].toFixed(2)}`);
    brickXYByNodeAndWythe.set(`${b.node.id}@${b.wythe}`, b.xy);
    pendingBricks.push(b);
  };

  for (const n of nodes) {
    const w = classifyNativeWythe(n);
    const xy = canonicalXY.get(n.id) ?? [0, 0];
    const nf = findingsByNode.get(n.id) ?? [];
    const rules = [...new Set(nf.map((f) => f.rule_code))];
    const hasDrift =
      nf.some((f) => ['TRUTH-002', 'TRUTH-005', 'MANIP-004', 'MANIP-005'].includes(f.rule_code)) ||
      (n.stratum_badges ?? []).some((b) => DRIFT_BADGE_KEY_RE.test(b.key) && b.count > 0);
    addBrick({
      instanceId: n.id,
      node: n,
      wythe: w,
      xy,
      isReplica: false,
      driftStatus: hasDrift ? 'drift' : 'intact',
      ruleCodes: rules,
    });
  }
  interface TieSeed {
    logicalKey: string;
    sourceNodeId: string;
    targetNodeId: string;
    fromWythe: LifecycleWytheIndex;
    toWythe: LifecycleWytheIndex;
    fromXY: [number, number];
    toXY: [number, number];
    status: 'intact' | 'drift';
    kind: LifecycleWallTie['kind'];
    ruleCode: string | null;
    label: string;
  }
  const tieSeeds: TieSeed[] = [];
  const seenTiePairs = new Set<string>();
  const pushTie = (seed: TieSeed) => {
    const key = `${seed.sourceNodeId}@${seed.fromWythe}->${seed.targetNodeId}@${seed.toWythe}:${seed.kind}`;
    if (seenTiePairs.has(key)) return;
    seenTiePairs.add(key);
    tieSeeds.push(seed);
  };

  // 1. Explicit multi-stage logical identity ties (Z=0 <-> Z=1, Z=0 <-> Z=2, Z=1 <-> Z=2)
  for (const [lKey, wm] of nativeByLogical.entries()) {
    const z0 = wm.get(0)?.[0];
    const z1 = wm.get(1)?.[0];
    const z2 = wm.get(2)?.[0];
    const checkPair = (a: AtlasNode, wa: LifecycleWytheIndex, b: AtlasNode, wb: LifecycleWytheIndex) => {
      const af = findingsByNode.get(a.id) ?? [];
      const bf = findingsByNode.get(b.id) ?? [];
      const driftFinding = [...af, ...bf].find((f) =>
        ['TRUTH-002', 'TRUTH-005', 'MANIP-004', 'MANIP-005'].includes(f.rule_code),
      );
      const pluginDrift = [...(a.stratum_badges ?? []), ...(b.stratum_badges ?? [])].find(
        (bg) => DRIFT_BADGE_KEY_RE.test(bg.key) && bg.count > 0,
      );
      const isDrift = Boolean(driftFinding || pluginDrift);
      pushTie({
        logicalKey: lKey,
        sourceNodeId: a.id,
        targetNodeId: b.id,
        fromWythe: wa,
        toWythe: wb,
        fromXY: canonicalXY.get(a.id) ?? [0, 0],
        toXY: canonicalXY.get(b.id) ?? [0, 0],
        status: isDrift ? 'drift' : 'intact',
        kind: driftFinding
          ? driftFinding.rule_code.startsWith('TRUTH')
            ? 'truth_catalog_drift'
            : 'container_packaging_drift'
          : pluginDrift
            ? 'plugin_stratum_mismatch'
            : 'stage_identity_tie',
        ruleCode: driftFinding?.rule_code ?? null,
        label: driftFinding
          ? `${driftFinding.rule_code}: ${driftFinding.title}`
          : pluginDrift
            ? `Stratum drift (${pluginDrift.label}: ${pluginDrift.count})`
            : `${a.label} (${WYTHE_LABELS[wa]} <-> ${WYTHE_LABELS[wb]})`,
      });
    };
    if (z0 && z1) checkPair(z0, 0, z1, 1);
    if (z0 && z2) checkPair(z0, 0, z2, 2);
    if (!z0 && z1 && z2) checkPair(z1, 1, z2, 2);
  }

  // 2. Container Z=1 <-> Blueprint Z=0 entrypoint wall-ties
  for (const { container, entrypoint, edge } of containerLinks) {
    const cf = findingsByNode.get(container.id) ?? [];
    const ef = findingsByNode.get(entrypoint.id) ?? [];
    const pkgDrift = [...cf, ...ef].find(
      (f) => f.rule_code === 'MANIP-005' || f.rule_code === 'MANIP-004',
    );
    const brokenEdge = edge.verification === 'broken';
    const isDrift = Boolean(pkgDrift || brokenEdge);
    pushTie({
      logicalKey: deriveLogicalIdentityKey(entrypoint),
      sourceNodeId: entrypoint.id,
      targetNodeId: container.id,
      fromWythe: 0,
      toWythe: 1,
      fromXY: canonicalXY.get(entrypoint.id) ?? [0, 0],
      toXY: canonicalXY.get(container.id) ?? [0, 0],
      status: isDrift ? 'drift' : 'intact',
      kind: pkgDrift ? 'container_packaging_drift' : 'container_entrypoint_tie',
      ruleCode: pkgDrift?.rule_code ?? null,
      label: pkgDrift
        ? `${pkgDrift.rule_code}: ${pkgDrift.title}`
        : `Container entrypoint tie (${entrypoint.label} <-> ${container.label})`,
    });
  }

  // 3. Projected Z=1 (MANIP-005 / Zoom-2 compiler-binary badges) & Z=2 (TRUTH-002/005 / --dsn / cache_store / wiretap)
  for (const n of nodes) {
    if (classifyNativeWythe(n) !== 0) continue;
    const lKey = deriveLogicalIdentityKey(n);
    const xy = canonicalXY.get(n.id) ?? [0, 0];
    const nf = findingsByNode.get(n.id) ?? [];
    const badges = n.stratum_badges ?? [];
    const wm = nativeByLogical.get(lKey);

    const manipDrift = nf.find((f) => f.rule_code === 'MANIP-005' || f.rule_code === 'MANIP-004');
    const z1Badges = badges.filter((b) => Z1_BADGE_KEY_RE.test(b.key) && b.count > 0);
    if (!wm?.has(1) && !entrypointHasContainerNode.has(n.id) && (manipDrift || z1Badges.length > 0)) {
      const z1PluginDrift = z1Badges.find((b) => DRIFT_BADGE_KEY_RE.test(b.key));
      const isDrift = Boolean(manipDrift || z1PluginDrift);
      addBrick({
        instanceId: `${n.id}@z1`,
        node: n,
        wythe: 1,
        xy,
        isReplica: true,
        driftStatus: isDrift ? 'drift' : 'intact',
        ruleCodes: manipDrift ? [manipDrift.rule_code] : [],
      });
      pushTie({
        logicalKey: lKey,
        sourceNodeId: n.id,
        targetNodeId: n.id,
        fromWythe: 0,
        toWythe: 1,
        fromXY: xy,
        toXY: xy,
        status: isDrift ? 'drift' : 'intact',
        kind: manipDrift
          ? 'container_packaging_drift'
          : z1PluginDrift
            ? 'plugin_stratum_mismatch'
            : 'plugin_stratum_tie',
        ruleCode: manipDrift?.rule_code ?? null,
        label: manipDrift
          ? `${manipDrift.rule_code}: ${manipDrift.title}`
          : `${n.label} Z=1 stratum (${z1Badges.map((b) => `${b.label}:${b.count}`).join(', ')})`,
      });
    }

    const truthDrift = nf.find((f) => f.rule_code === 'TRUTH-002' || f.rule_code === 'TRUTH-005');
    const z2Badges = badges.filter((b) => Z2_BADGE_KEY_RE.test(b.key) && b.count > 0);
    const hasLiveCatalogNote = Boolean(
      n.verification_note && /(?:live catalog|pg_catalog|live database)/i.test(n.verification_note),
    );
    const projectsToZ2 =
      Boolean(truthDrift) ||
      z2Badges.length > 0 ||
      n.subkind === 'cache_store' ||
      (n.tier === 'truth' && (liveCatalogActive || hasLiveCatalogNote));
    if (!wm?.has(2) && projectsToZ2) {
      const z2PluginDrift = z2Badges.find((b) => DRIFT_BADGE_KEY_RE.test(b.key));
      const isDrift = Boolean(truthDrift || z2PluginDrift || n.status === 'duplicated_truth');
      addBrick({
        instanceId: `${n.id}@z2`,
        node: n,
        wythe: 2,
        xy,
        isReplica: true,
        driftStatus: isDrift ? 'drift' : 'intact',
        ruleCodes: truthDrift ? [truthDrift.rule_code] : [],
      });
      pushTie({
        logicalKey: lKey,
        sourceNodeId: n.id,
        targetNodeId: n.id,
        fromWythe: 0,
        toWythe: 2,
        fromXY: xy,
        toXY: xy,
        status: isDrift ? 'drift' : 'intact',
        kind: truthDrift
          ? 'truth_catalog_drift'
          : z2PluginDrift
            ? 'plugin_stratum_mismatch'
            : 'runtime_store_tie',
        ruleCode: truthDrift?.rule_code ?? null,
        label: truthDrift
          ? `${truthDrift.rule_code}: ${truthDrift.title}`
          : z2PluginDrift
            ? `Runtime stratum mismatch (${z2PluginDrift.label}:${z2PluginDrift.count})`
            : `${n.label} (Z=0 Blueprint <-> Z=2 Live Runtime)`,
      });
    }
  }

  const presentSet = new Set<LifecycleWytheIndex>(pendingBricks.map((b) => b.wythe));
  const activeWythes = ([0, 1, 2] as LifecycleWytheIndex[]).filter((w) => presentSet.has(w));
  if (activeWythes.length === 0) activeWythes.push(0);
  const wytheZ = computeCollapsedWytheZ(activeWythes);

  const bricks: LifecycleProjectedBrick[] = pendingBricks.map((b) => ({
    instanceId: b.instanceId,
    node: b.node,
    wythe: b.wythe,
    position: [b.xy[0], b.xy[1], wytheZ.get(b.wythe) ?? 0],
    isReplica: b.isReplica,
    driftStatus: b.driftStatus,
    ruleCodes: b.ruleCodes,
  }));

  const primaryPositions = new Map<string, [number, number, number]>();
  for (const b of bricks) {
    if (!b.isReplica) primaryPositions.set(b.node.id, b.position);
  }

  const wallTies: LifecycleWallTie[] = tieSeeds
    .filter((s) => wytheZ.has(s.fromWythe) && wytheZ.has(s.toWythe))
    .map((s, idx) => {
      const actualFromXY = brickXYByNodeAndWythe.get(`${s.sourceNodeId}@${s.fromWythe}`) ?? s.fromXY;
      const actualToXY = brickXYByNodeAndWythe.get(`${s.targetNodeId}@${s.toWythe}`) ?? s.toXY;
      return {
        id: `tie:${idx}:${s.sourceNodeId}->${s.targetNodeId}:z${s.fromWythe}-z${s.toWythe}`,
        logicalKey: s.logicalKey,
        sourceNodeId: s.sourceNodeId,
        targetNodeId: s.targetNodeId,
        fromWythe: s.fromWythe,
        toWythe: s.toWythe,
        start: [actualFromXY[0], actualFromXY[1], wytheZ.get(s.fromWythe)!],
        end: [actualToXY[0], actualToXY[1], wytheZ.get(s.toWythe)!],
        status: s.status,
        kind: s.kind,
        ruleCode: s.ruleCode,
        label: s.label,
      };
    });

  const entityPresence = new Map<string, LifecycleEntityPresence>();
  for (const n of nodes) {
    const lKey = deriveLogicalIdentityKey(n);
    const nodeBricks = bricks.filter(
      (b) => b.node.id === n.id || deriveLogicalIdentityKey(b.node) === lKey,
    );
    const nodeTies = wallTies.filter(
      (t) => t.sourceNodeId === n.id || t.targetNodeId === n.id || t.logicalKey === lKey,
    );
    const wythes = ([0, 1, 2] as LifecycleWytheIndex[]).filter((w) =>
      nodeBricks.some((b) => b.wythe === w) ||
      nodeTies.some((t) => t.fromWythe === w || t.toWythe === w),
    );
    const finalWythes: LifecycleWytheIndex[] = wythes.length > 0 ? wythes : [classifyNativeWythe(n)];
    const driftTies = nodeTies.filter((t) => t.status === 'drift');
    const driftRuleCodes = [
      ...new Set(driftTies.map((t) => t.ruleCode).filter((r): r is string => Boolean(r))),
    ];
    const tieStatus: LifecycleEntityPresence['tieStatus'] =
      driftTies.length > 0
        ? 'drift'
        : nodeTies.length > 0 || finalWythes.length > 1
          ? 'intact'
          : 'blueprint_only';
    entityPresence.set(n.id, {
      nodeId: n.id,
      logicalKey: lKey,
      wythes: finalWythes,
      wytheLabels: finalWythes.map((w) => WYTHE_LABELS[w]),
      tieStatus,
      driftRuleCodes,
      summary:
        driftTies.length > 0
          ? driftTies.map((t) => t.label).join(' · ')
          : tieStatus === 'intact'
            ? `Intact across ${finalWythes.map((w) => `Z=${w}`).join(' + ')}`
            : `${WYTHE_LABELS[finalWythes[0]]} only`,
    });
  }

  return {
    canonicalXY,
    activeWythes,
    wytheZ,
    primaryPositions,
    bricks,
    wallTies,
    entityPresence,
  };
}

export function computeLifecycleWallTies(
  nodes: ReadonlyArray<AtlasNode>,
  edges: ReadonlyArray<AtlasEdge> = [],
  findings: ReadonlyArray<BoundaryFinding> = [],
  options: LifecycleProjectionOptions = {},
): LifecycleWallTie[] {
  return computeLifecycleZProjection(nodes, edges, findings, options).wallTies;
}
export type TemporalVectorKind =
  | 'unchanged_continuity'
  | 'added_seam'
  | 'removed_severed'
  | 'new_finding_delta';

export interface TemporalZVector {
  id: string;
  kind: TemporalVectorKind;
  sourceNodeId: string;
  targetNodeId: string;
  start: [number, number, number];
  end: [number, number, number];
  ruleCode: string | null;
  label: string;
}

export interface TemporalProjectedBrick {
  instanceId: string;
  node: AtlasNode;
  slice: 'z_base' | 'z_head';
  position: [number, number, number];
  changeState: 'unchanged' | 'added' | 'removed' | 'touched' | 'impacted' | 'new_finding';
}

export interface TemporalDiffSummaryRow {
  nodeId: string;
  label: string;
  tier: AtlasNode['tier'];
  subkind: AtlasNode['subkind'];
  district: string;
  transition: 'added' | 'removed' | 'new_finding' | 'touched' | 'impacted' | 'resolved';
  presentInBase: boolean;
  presentInHead: boolean;
  findingCodes: string[];
  detail: string;
}

export interface TemporalZProjectionResult {
  hasDiff: boolean;
  label: string;
  canonicalXY: Map<string, [number, number]>;
  activeSlices: Array<'z_base' | 'z_head'>;
  zBase: number;
  zHead: number;
  basePositions: Map<string, [number, number, number]>;
  headPositions: Map<string, [number, number, number]>;
  bricks: TemporalProjectedBrick[];
  vectors: TemporalZVector[];
  diffRows: TemporalDiffSummaryRow[];
}

export function computeTemporalZProjection(params: {
  headNodes: ReadonlyArray<AtlasNode>;
  headEdges?: ReadonlyArray<AtlasEdge>;
  gitDiffReport?: DiffBlastRadiusReport | null;
  snapCompareReport?: SnapshotComparisonReport | null;
  baseNodes?: ReadonlyArray<AtlasNode>;
  baseEdges?: ReadonlyArray<AtlasEdge>;
  flatten2D?: boolean;
}): TemporalZProjectionResult {
  const {
    headNodes,
    headEdges = [],
    gitDiffReport = null,
    snapCompareReport = null,
    baseNodes,
    baseEdges = [],
    flatten2D = false,
  } = params;

  if (!gitDiffReport && !snapCompareReport && !baseNodes) {
    const canonicalXY = computeCanonicalXYPositions(headNodes, { edges: headEdges, flatten2D });
    const headPositions = new Map<string, [number, number, number]>();
    const bricks: TemporalProjectedBrick[] = headNodes.map((n) => {
      const xy = canonicalXY.get(n.id) ?? [0, 0];
      const pos: [number, number, number] = [xy[0], xy[1], 0];
      headPositions.set(n.id, pos);
      return {
        instanceId: n.id,
        node: n,
        slice: 'z_head',
        position: pos,
        changeState: 'unchanged',
      };
    });
    return {
      hasDiff: false,
      label: 'Single Snapshot (HEAD)',
      canonicalXY,
      activeSlices: ['z_head'],
      zBase: 0,
      zHead: 0,
      basePositions: new Map(),
      headPositions,
      bricks,
      vectors: [],
      diffRows: [],
    };
  }

  const headById = new Map(headNodes.map((n) => [n.id, n]));
  const addedMap = new Map<string, AtlasNode>();
  const removedMap = new Map<string, AtlasNode>();
  for (const an of snapCompareReport?.added_nodes ?? []) addedMap.set(an.id, an);
  for (const rn of snapCompareReport?.removed_nodes ?? []) removedMap.set(rn.id, rn);
  for (const rn of gitDiffReport?.removed_nodes ?? []) removedMap.set(rn.id, rn);

  if (baseNodes) {
    const baseIds = new Set(baseNodes.map((n) => n.id));
    for (const hn of headNodes) {
      if (!baseIds.has(hn.id)) addedMap.set(hn.id, hn);
    }
    for (const bn of baseNodes) {
      if (!headById.has(bn.id)) removedMap.set(bn.id, bn);
    }
  }

  const effectiveBaseById = new Map<string, AtlasNode>();
  if (baseNodes) {
    for (const bn of baseNodes) effectiveBaseById.set(bn.id, bn);
  } else {
    for (const hn of headNodes) {
      if (!addedMap.has(hn.id)) effectiveBaseById.set(hn.id, hn);
    }
  }
  for (const [rid, rn] of removedMap.entries()) effectiveBaseById.set(rid, rn);

  const unionById = new Map<string, AtlasNode>(effectiveBaseById);
  for (const hn of headNodes) unionById.set(hn.id, hn);
  const unionNodes = [...unionById.values()];

  const canonicalXY = computeCanonicalXYPositions(unionNodes, {
    edges: [...baseEdges, ...headEdges],
    flatten2D,
    pairContainerAnchors: false,
  });

  const touchedSet = new Set(gitDiffReport?.touched_node_ids ?? []);
  const impactedSet = new Set([
    ...(gitDiffReport?.impacted_display_nodes ?? []),
    ...(gitDiffReport?.impacted_manipulator_nodes ?? []),
    ...(gitDiffReport?.impacted_truth_nodes ?? []),
    ...(gitDiffReport?.base_impacted_node_ids ?? []),
  ]);
  const newFindingsList = [
    ...(gitDiffReport?.new_findings ?? []),
    ...(snapCompareReport?.new_findings ?? []),
  ];
  const newFindingCodesByNode = new Map<string, string[]>();
  for (const f of newFindingsList) {
    for (const nid of [f.node_id, f.target_node_id]) {
      if (!nid) continue;
      const arr = newFindingCodesByNode.get(nid) ?? [];
      if (!arr.includes(f.rule_code)) arr.push(f.rule_code);
      newFindingCodesByNode.set(nid, arr);
    }
  }
  const resolvedSet = new Set(
    (snapCompareReport?.resolved_findings ?? [])
      .map((f) => f.node_id)
      .filter((id): id is string => Boolean(id)),
  );

  const zBase = -18;
  const zHead = 18;
  const basePositions = new Map<string, [number, number, number]>();
  const headPositions = new Map<string, [number, number, number]>();
  const bricks: TemporalProjectedBrick[] = [];

  for (const bn of effectiveBaseById.values()) {
    const xy = canonicalXY.get(bn.id) ?? [0, 0];
    const pos: [number, number, number] = [xy[0], xy[1], zBase];
    basePositions.set(bn.id, pos);
    bricks.push({
      instanceId: `${bn.id}@z_base`,
      node: bn,
      slice: 'z_base',
      position: pos,
      changeState: removedMap.has(bn.id) ? 'removed' : 'unchanged',
    });
  }

  for (const hn of headNodes) {
    const xy = canonicalXY.get(hn.id) ?? [0, 0];
    const pos: [number, number, number] = [xy[0], xy[1], zHead];
    headPositions.set(hn.id, pos);
    const changeState: TemporalProjectedBrick['changeState'] = newFindingCodesByNode.has(hn.id)
      ? 'new_finding'
      : addedMap.has(hn.id)
        ? 'added'
        : touchedSet.has(hn.id)
          ? 'touched'
          : impactedSet.has(hn.id)
            ? 'impacted'
            : 'unchanged';
    bricks.push({
      instanceId: `${hn.id}@z_head`,
      node: hn,
      slice: 'z_head',
      position: pos,
      changeState,
    });
  }

  const vectors: TemporalZVector[] = [];
  for (const hn of headNodes) {
    const hPos = headPositions.get(hn.id)!;
    const bPos = basePositions.get(hn.id);
    const nfCodes = newFindingCodesByNode.get(hn.id) ?? [];
    if (bPos) {
      if (nfCodes.length > 0) {
        vectors.push({
          id: `tv:finding:${hn.id}`,
          kind: 'new_finding_delta',
          sourceNodeId: hn.id,
          targetNodeId: hn.id,
          start: bPos,
          end: hPos,
          ruleCode: nfCodes[0],
          label: `New finding (${nfCodes.join(', ')}) on ${hn.label}`,
        });
      } else if (touchedSet.has(hn.id)) {
        vectors.push({
          id: `tv:touched:${hn.id}`,
          kind: 'added_seam',
          sourceNodeId: hn.id,
          targetNodeId: hn.id,
          start: bPos,
          end: hPos,
          ruleCode: null,
          label: `Modified in HEAD: ${hn.label}`,
        });
      } else {
        vectors.push({
          id: `tv:cont:${hn.id}`,
          kind: 'unchanged_continuity',
          sourceNodeId: hn.id,
          targetNodeId: hn.id,
          start: bPos,
          end: hPos,
          ruleCode: null,
          label: `Unchanged continuity: ${hn.label}`,
        });
      }
    } else if (addedMap.has(hn.id)) {
      vectors.push({
        id: `tv:added:${hn.id}`,
        kind: 'added_seam',
        sourceNodeId: hn.id,
        targetNodeId: hn.id,
        start: [hPos[0], hPos[1], zBase],
        end: hPos,
        ruleCode: nfCodes[0] ?? null,
        label: `Added in HEAD: ${hn.label}`,
      });
    }
  }

  for (const [rid, rNode] of removedMap.entries()) {
    const bPos = basePositions.get(rid);
    if (!bPos) continue;
    const callerIds = new Set<string>();
    for (const be of baseEdges) {
      if (be.source_id === rid && headPositions.has(be.target_id)) callerIds.add(be.target_id);
      if (be.target_id === rid && headPositions.has(be.source_id)) callerIds.add(be.source_id);
    }
    if (callerIds.size === 0) {
      const rDom = inferDomainKey(rNode);
      const candidates = [...impactedSet].filter((id) => headPositions.has(id));
      const sameDom = candidates.filter((id) => inferDomainKey(headById.get(id)!) === rDom);
      for (const cid of (sameDom.length > 0 ? sameDom : candidates).slice(0, 3)) {
        callerIds.add(cid);
      }
    }
    if (callerIds.size > 0) {
      for (const cid of [...callerIds].slice(0, 4)) {
        vectors.push({
          id: `tv:severed:${rid}->${cid}`,
          kind: 'removed_severed',
          sourceNodeId: rid,
          targetNodeId: cid,
          start: bPos,
          end: headPositions.get(cid)!,
          ruleCode: null,
          label: `Removed ${rNode.label} severed seam -> impacted ${headById.get(cid)?.label ?? cid}`,
        });
      }
    } else {
      vectors.push({
        id: `tv:severed:${rid}:stub`,
        kind: 'removed_severed',
        sourceNodeId: rid,
        targetNodeId: rid,
        start: bPos,
        end: [bPos[0], bPos[1], 0],
        ruleCode: null,
        label: `Removed in HEAD (before-image anchor): ${rNode.label}`,
      });
    }
  }

  const diffRows: TemporalDiffSummaryRow[] = [];
  for (const [rid, rn] of removedMap.entries()) {
    diffRows.push({
      nodeId: rid,
      label: rn.label,
      tier: rn.tier,
      subkind: rn.subkind,
      district: inferDomainKey(rn),
      transition: 'removed',
      presentInBase: true,
      presentInHead: false,
      findingCodes: [],
      detail: `Deleted from HEAD; before-image preserved on Z_base (${rn.source_file}:${rn.line})`,
    });
  }
  for (const hn of headNodes) {
    const nf = newFindingCodesByNode.get(hn.id) ?? [];
    const transition: TemporalDiffSummaryRow['transition'] | null =
      nf.length > 0
        ? 'new_finding'
        : addedMap.has(hn.id)
          ? 'added'
          : touchedSet.has(hn.id)
            ? 'touched'
            : impactedSet.has(hn.id)
              ? 'impacted'
              : resolvedSet.has(hn.id)
                ? 'resolved'
                : null;
    if (!transition) continue;
    diffRows.push({
      nodeId: hn.id,
      label: hn.label,
      tier: hn.tier,
      subkind: hn.subkind,
      district: inferDomainKey(hn),
      transition,
      presentInBase: effectiveBaseById.has(hn.id),
      presentInHead: true,
      findingCodes: nf,
      detail:
        nf.length > 0
          ? `New finding(s): ${nf.join(', ')}`
          : transition === 'added'
            ? `Added on Z_head (${hn.source_file}:${hn.line})`
            : transition === 'touched'
              ? `Modified in diff range (${hn.source_file}:${hn.line})`
              : transition === 'impacted'
                ? 'Inside transitive 3-tier blast radius'
                : 'Resolved prior finding in HEAD',
    });
  }

  const rank: Record<TemporalDiffSummaryRow['transition'], number> = {
    new_finding: 0,
    removed: 1,
    added: 2,
    touched: 3,
    impacted: 4,
    resolved: 5,
  };
  diffRows.sort((a, b) => rank[a.transition] - rank[b.transition] || a.nodeId.localeCompare(b.nodeId));

  const label = gitDiffReport
    ? `git ${gitDiffReport.base_ref} -> HEAD`
    : snapCompareReport
      ? `snap #${snapCompareReport.base_snapshot_id} -> #${snapCompareReport.head_snapshot_id}`
      : 'base -> HEAD';

  return {
    hasDiff: true,
    label,
    canonicalXY,
    activeSlices: ['z_base', 'z_head'],
    zBase,
    zHead,
    basePositions,
    headPositions,
    bricks,
    vectors,
    diffRows,
  };
}
