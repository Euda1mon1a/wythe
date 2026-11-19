import assert from 'node:assert/strict';
import {
  addNodesToWorkingSet,
  computeBoundaryCrossings,
  computeGroupSummaries,
  expandWorkingSetBoundary,
  parseSavedViews,
  reconcileSavedView,
  removeNodesFromWorkingSet,
  serializeSavedViews,
  toggleNodeInWorkingSet,
} from '../src/lib/wytheWorkingSet';
import { test } from 'node:test';
import * as THREE from 'three';
import type { AtlasEdge, AtlasNode, BoundaryFinding, PortableReferenceExemplar } from '../src/api/atlas';
import { selectSceneGraph, collectNeighborhood, type SceneGraphFilters } from '../src/lib/wytheSceneGraph';
import {
  computeCanonicalXYPositions,
  computeLifecycleWallTies,
  computeLifecycleZProjection,
  computeScenePositions,
  computeTemporalZProjection,
  evaluateEdgeVisual,
  getEdgeVerificationLegendItems,
} from '../src/lib/wytheSceneLenses';
import {
  applyIncomingViewportEvent,
  buildViewportPermalinkHash,
  computeCameraTransition,
  computeSmartDenseSalience,
  createInitialAgentCameraState,
  isPureDrawerRefreshCommand,
  normalizeViewportTimeline,
  parseViewportPermalinkHash,
  resumeAgentCameraFollow,
  sanitizeViewportPlainText,
  solveSemanticCameraFraming,
  stepTimelineFrame,
  yieldAgentCameraOnHumanInput,
} from '../src/lib/wytheCameraChoreography';
import { createBatchedNodes, createBatchedEdges, fitGraphCamera, type SceneRenderNode } from '../src/lib/wytheSceneBatches';
import { buildLiveViewportDigest } from '../src/lib/wytheVisionBridge';
import { buildDiagnosticBrief, selectReferenceExemplar } from '../src/lib/wytheBriefBuilder';
import { computeWrappedFocusIndex } from '../src/lib/wytheDialogFocus';
import {
  bumpViewportCameraRevision,
  probeBrowserLocalOpenAi,
  registerWytheWebMcpBridge,
} from '../src/lib/wytheBrowserAi';
import {
  MIN_UI_FOCUS_DEBOUNCE_MS,
  buildSessionShareUrl,
  createMemoryTabStorage,
  evaluateIncomingViewportCommand,
  extractExplicitSessionIdFromUrl,
  readAckedCommandIds,
  readPersistedFollowState,
  recordAckedCommandId,
  resolveTabInvestigationIdentity,
  rotateTabSessionId,
  switchTabSessionId,
  writePersistedFollowState,
} from '../src/lib/wytheInvestigationSession';
import { WYTHE_PRESETS } from '../src/lib/wytheTheme';

const node = (id: string, overrides: Partial<AtlasNode> = {}): AtlasNode => ({
  id, label: id, tier: 'manipulate', subkind: 'service', status: 'clean',
  source_file: 'backend/services/example.py', line: 1, role: 'mechanism', cluster: 'core',
  summary: '', read_by_count: 0, written_by_count: 0, ...overrides,
});
const edge = (source_id: string, target_id: string, kind: AtlasEdge['kind'] = 'calls_helper'): AtlasEdge => ({
  id: `${source_id}-${target_id}-${kind}`, source_id, target_id, kind, verification: 'verified', evidence_note: '',
});
const defaults: SceneGraphFilters = {
  tier: 'all', subkind: 'all', edgeFilter: 'all', onlyFlagged: false,
  connectedOnly: false, searchQuery: '', selectedId: null, traceIds: new Set(),
  coneIds: new Set(), isolateCone: false, neighborhoodHops: 0,
};
const nodes = Array.from({ length: 2500 }, (_, index) => node(`node-${String(index).padStart(4, '0')}`, {
  tier: (['display', 'manipulate', 'truth'] as const)[index % 3], cluster: `district-${index % 25}`,
}));
const edges = Array.from({ length: 9000 }, (_, index) => edge(nodes[index % nodes.length].id, nodes[(index * 7 + 1) % nodes.length].id));

test('all tiers retain every node and edge beyond the old quotas', () => {
  const graph = selectSceneGraph(nodes, edges, defaults);
  assert.equal(graph.nodes.length, 2500);
  assert.equal(graph.edges.length, 9000);
  assert.equal(graph.hiddenCount, 0);
  assert.equal(Object.values(graph.counts).reduce((a, b) => a + b), 2500);
  assert(graph.nodes.includes(nodes.at(-1)!));
});

test('connected-only uses displayed edges, both endpoints, and no pinned exception', () => {
  const list = ['a', 'b', 'c', 'self', 'isolated', 'dangling'].map((id) => node(id));
  const links = [edge('a', 'b', 'reads_truth'), edge('b', 'c', 'writes_truth'),
    edge('self', 'self', 'reads_truth'), edge('dangling', 'absent', 'reads_truth')];
  const graph = selectSceneGraph(list, links, { ...defaults, connectedOnly: true, edgeFilter: 'reads', selectedId: 'isolated' });
  assert.deepEqual(graph.nodes.map((n) => n.id), ['a', 'b', 'self']);
  assert.equal(graph.edges.length, 2);
  assert.equal(graph.hiddenCount, 3);
  const searched = selectSceneGraph(list, links, { ...defaults, connectedOnly: true, searchQuery: 'isolated' });
  assert.equal(searched.nodes.length, 0);
  assert.equal(searched.edges.length, 0);
});

test('filtering one endpoint removes the edge and strips its former neighbor', () => {
  const list = [node('a'), node('b', { tier: 'truth', subkind: 'table' })];
  const graph = selectSceneGraph(list, [edge('a', 'b')], { ...defaults, tier: 'truth', connectedOnly: true });
  assert.equal(graph.nodes.length, 0);
  assert.equal(graph.edges.length, 0);
});

test('neighborhood handles reverse links, cycles, and the active edge filter', () => {
  const links = [edge('a', 'b'), edge('c', 'b'), edge('c', 'd'), edge('b', 'a'), edge('d', 'e', 'writes_truth')];
  assert.deepEqual([...collectNeighborhood('a', links, 1)].sort(), ['a', 'b']);
  assert.deepEqual([...collectNeighborhood('a', links, 2)].sort(), ['a', 'b', 'c']);
  const graph = selectSceneGraph(['a', 'b', 'c', 'd', 'e'].map((id) => node(id)), links,
    { ...defaults, selectedId: 'd', neighborhoodHops: 2, edgeFilter: 'helpers' });
  assert.deepEqual(graph.nodes.map((n) => n.id), ['b', 'c', 'd']);
});

test('selection and trace pins are counted explicitly outside other filters', () => {
  const graph = selectSceneGraph(nodes, edges, { ...defaults, searchQuery: 'no-match',
    selectedId: nodes[0].id, traceIds: new Set([nodes[1].id]) });
  assert.equal(graph.nodes.length, 2);
  assert.equal(graph.pinnedExtraCount, 2);
});

test('a neighborhood cannot traverse an intermediate node hidden by the stratum filter', () => {
  const list = [node('a'), node('b', { tier: 'truth' }), node('c')];
  const graph = selectSceneGraph(list, [edge('a', 'b'), edge('b', 'c')], {
    ...defaults, selectedId: 'a', tier: 'manipulate', neighborhoodHops: 2,
  });
  assert.deepEqual(graph.nodes.map((n) => n.id), ['a']);
  assert.equal(graph.edges.length, 0);
});

test('flagged-only does not silently retain clean lineage neighbors', () => {
  const list = [node('a'), node('b'), node('c', { status: 'gray_zone' })];
  const graph = selectSceneGraph(list, [edge('a', 'b'), edge('b', 'c')], {
    ...defaults, selectedId: 'a', onlyFlagged: true, coneIds: new Set(['a', 'b', 'c']),
  });
  assert.deepEqual(graph.nodes.map((n) => n.id), ['a', 'c']);
  assert.equal(graph.pinnedExtraCount, 1);
});

for (const layout of ['grid', 'cluster'] as const) {
  test(`${layout} places every node deterministically without coincident positions`, () => {
    const positions = computeScenePositions(nodes, layout);
    const reversed = computeScenePositions([...nodes].reverse(), layout);
    assert.equal(positions.size, nodes.length);
    assert.equal(new Set([...positions.values()].map((p) => p.join(','))).size, nodes.length);
    for (const [id, position] of positions) assert.deepEqual(reversed.get(id), position);
  });
}

test('district packing leaves room for an oversized district without folding others together', () => {
  const list = Array.from({ length: 1000 }, (_, i) => node(`large-${i}`, { cluster: 'large' }));
  list.push(...Array.from({ length: 25 }, (_, i) => node(`small-${i}`, { cluster: `small-${i}` })));
  const positions = computeScenePositions(list, 'cluster');
  const large = new THREE.Box3().setFromPoints(list.slice(0, 1000).map((n) => new THREE.Vector3(...positions.get(n.id)!)));
  large.expandByScalar(2);
  for (const n of list.slice(1000)) assert.equal(large.containsPoint(new THREE.Vector3(...positions.get(n.id)!)), false);
});

test('camera fit includes all grid points on wide and narrow canvases', () => {
  const positions = computeScenePositions(nodes, 'grid');
  for (const aspect of [0.5, 1.6, 3]) {
    const camera = new THREE.PerspectiveCamera(46, aspect, 0.1, 520);
    fitGraphCamera(camera, positions.values());
    for (const position of positions.values()) {
      const projected = new THREE.Vector3(...position).project(camera);
      assert(Math.abs(projected.x) < 1 && Math.abs(projected.y) < 1 && projected.z < 1);
    }
  }
});

const renderRecord = (n: AtlasNode, position: [number, number, number]): SceneRenderNode => ({
  node: n, position, scale: 1,
  style: { barColor: '#38bdf8', inquiryColor: '#ffffff', hollow: false,
    flagged: false, dimmed: false, selected: false, inCone: false, phase: 0 },
});

for (const mode of ['atomic', 'simple'] as const) {
  test(`${mode} represents all 2500 nodes and changes detail, not membership, on zoom`, () => {
    const positions = computeScenePositions(nodes, 'grid');
    const batch = createBatchedNodes(nodes.map((n) => renderRecord(n, positions.get(n.id)!)), mode);
    const camera = new THREE.PerspectiveCamera(46, 1.6, 0.1, 520);
    fitGraphCamera(camera, positions.values());
    const far = batch.update(camera, 800, 500);
    assert.equal(far.total, 2500);
    assert.equal(far.inFrustum, 2500);
    assert.equal(far.detailed + far.overview, 2500);
    assert(far.overview > 660);
    assert(batch.renderedNodeIds.has(nodes.at(-1)!.id));
    assert(batch.group.children.length < 20, 'draw objects must be batched, not one per node');
    camera.position.multiplyScalar(0.18);
    const near = batch.update(camera, 800, 500);
    assert.equal(near.total, far.total);
    assert(near.detailed > far.detailed);
    assert(near.inFrustum < near.total, 'offscreen is distinct from filtered out');
  });
}

test('a node beyond the old quota is selectable as a dot and a detailed instance', () => {
  const target = nodes.at(-1)!;
  const batch = createBatchedNodes(nodes.map((n, index) => renderRecord(n,
    n === target ? [0, 0, 0] : [10000 + index * 5, 0, 0])), 'atomic');
  const camera = new THREE.PerspectiveCamera(46, 1.6, 0.1, 1000);
  const ray = new THREE.Raycaster();
  for (const distance of [200, 12, 200]) {
    camera.position.set(0, 0, distance);
    camera.lookAt(0, 0, 0);
    const stats = batch.update(camera, 800, 500);
    batch.group.updateMatrixWorld(true);
    ray.setFromCamera(new THREE.Vector2(0, 0), camera);
    assert.equal(batch.pick(ray, 400, 250)?.id, target.id);
    assert.equal(stats.inFrustum, 1);
    assert.equal(stats.detailed, distance === 12 ? 1 : 0);
  }
});

test('edge batching retains every connection beyond the old limit', () => {
  const group = createBatchedEdges(edges.map((_, index) => ({ start: [index, 0, 0],
    end: [index, 1, 0], color: 0x38bdf8, opacity: index % 2 ? 0.18 : 0.36 })));
  assert.equal(group.children.length, 2);
  assert.equal(group.children.reduce((count, child) => count +
    (child as THREE.LineSegments).geometry.getAttribute('position').count / 2, 0), 9000);
});

test('overview counts use the dot footprint at the viewport edge', () => {
  const camera = new THREE.PerspectiveCamera(46, 1.6, 0.1, 1000);
  camera.position.set(0, 0, 150);
  camera.lookAt(0, 0, 0);
  const halfWidth = 150 * Math.tan(THREE.MathUtils.degToRad(23)) * 1.6;
  const batch = createBatchedNodes([renderRecord(node('outside-dot'), [halfWidth * 1.01, 0, 0])], 'atomic');
  const stats = batch.update(camera, 800, 500);
  assert.equal(stats.total, 1);
  assert.equal(stats.overview, 0, 'a dot four pixels beyond the edge does not overlap the viewport');
  assert.equal(batch.renderedNodeIds.size, 0);
});

test('viewport digest reports the filtered graph and clears an empty view', () => {
  const params = {
    activeSlug: 'example', sourceCommit: '1234567890', visibleNodes: [nodes[0]],
    positions: new Map([[nodes[0].id, [0, 0, 0] as [number, number, number]]]),
    edges: [], findings: [], selectedNodeId: null, hoveredNodeId: null,
    coneNodeIds: new Set<string>(), lens: 'status' as const, layoutMode: 'grid' as const,
    tierFilter: 'all', subkindFilter: 'all', onlyFlagged: false, connectedOnly: true,
    neighborhoodHops: 2 as const, searchQuery: '', diffOverlay: null,
    palette: WYTHE_PRESETS.stratified.dark, degreeByNode: new Map<string, number>(),
    guardedTableIds: new Set<string>(), mutatorNodeIds: new Set<string>(),
    renderedNodeIds: new Set([nodes[0].id]), overviewNodeIds: new Set([nodes[0].id]),
  };
  const digest = buildLiveViewportDigest(params);
  assert.equal(digest.visibleNodeCount, 1);
  assert.equal(digest.inFrustumCount, 1);
  assert.match(digest.markdownBrief, /ConnectedOnly=`true`/);
  assert.match(digest.markdownBrief, /NeighborhoodHops=`2`/);
  assert.match(digest.markdownBrief, /1 overview dots/);
  const empty = buildLiveViewportDigest({ ...params, visibleNodes: [], renderedNodeIds: new Set(), overviewNodeIds: new Set() });
  assert.equal(empty.inFrustumCount, 0);
  assert.equal(empty.visibleNodeCount, 0);
  assert.deepEqual(empty.referencedNodeIds, []);
});

test('edge visuals, filters, patterns, and legend distinguish all 4 verification states', () => {
  const states: Array<AtlasEdge['verification']> = ['verified', 'declared', 'unverified', 'broken'];
  const fixtureEdges: AtlasEdge[] = states.map((verification, idx) => ({
    id: `e-${verification}`,
    source_id: `src-${idx}`,
    target_id: `dst-${idx}`,
    kind: 'writes_truth',
    verification,
    evidence_path: `backend/file_${idx}.py:${idx + 1}`,
    evidence_note: `Edge marked ${verification}`,
  }));

  const visuals = fixtureEdges.map((item) => evaluateEdgeVisual(item, 'all'));
  assert.deepEqual(visuals.map((v) => v.pattern), ['solid', 'dashed', 'dotted', 'broken_gap']);
  assert.equal(new Set(visuals.map((v) => v.hex)).size, 4);
  for (const state of states) {
    const filtered = fixtureEdges.filter((item) => evaluateEdgeVisual(item, state).visible);
    assert.deepEqual(filtered.map((f) => f.verification), [state]);
  }

  const group = createBatchedEdges(
    visuals.map((vis, idx) => ({
      start: [0, idx, 0],
      end: [10, idx, 0],
      color: vis.hex,
      opacity: 0.9,
      pattern: vis.pattern,
    })),
  );
  assert.deepEqual(group.userData.patternCounts, { solid: 1, dashed: 1, dotted: 1, broken_gap: 1 });
  assert.deepEqual(group.userData.patternSegmentCounts, { solid: 1, dashed: 4, dotted: 7, broken_gap: 2 });

  const legend = getEdgeVerificationLegendItems(fixtureEdges);
  assert.equal(legend.length, 4);
  assert.deepEqual(legend.map((l) => [l.verification, l.pattern, l.count]), [
    ['verified', 'solid', 1],
    ['declared', 'dashed', 1],
    ['unverified', 'dotted', 1],
    ['broken', 'broken_gap', 1],
  ]);
});

test('diagnostic briefs default to investigation, qualify exemplars, and disclose neighbor truncation', () => {
  const solverNode = node('manip:solver:sched', { subkind: 'solver', status: 'policy_in_code', line: 12 });
  const unrelatedCleanSvc = node('manip:svc:billing', { subkind: 'service', status: 'clean' });
  const unwiredComp = node('disp:comp:legacy', { tier: 'display', subkind: 'component', status: 'unwired' });
  const cleanSameSubkind = node('manip:solver:clean', { subkind: 'solver', status: 'clean', line: 3 });

  // Unrelated clean service is never selected as exemplar for a solver node.
  const noMatch = selectReferenceExemplar(solverNode, new Map([[solverNode.id, solverNode], [unrelatedCleanSvc.id, unrelatedCleanSvc]]));
  assert.equal(noMatch.kind, 'none');

  // Same-subkind clean neighbor is explicitly flagged as unvalidated.
  const unvalMatch = selectReferenceExemplar(solverNode, new Map([[solverNode.id, solverNode], [cleanSameSubkind.id, cleanSameSubkind]]));
  assert.equal(unvalMatch.kind, 'unvalidated_neighbor');
  assert.match(unvalMatch.caveat, /UNVALIDATED/);

  // Configured authority overrides unvalidated clean neighbor.
  const configured: PortableReferenceExemplar[] = [{
    title: 'Approved Solver Reference',
    pointer: 'backend/services/approved_solver.py:1',
    applies_to_tiers: ['manipulate'],
    applies_to_subkinds: ['solver'],
    rationale: 'Injects DB clock authority cleanly.',
    approved_by: 'operator',
  }];
  const cfgMatch = selectReferenceExemplar(solverNode, new Map([[solverNode.id, solverNode], [cleanSameSubkind.id, cleanSameSubkind]]), configured);
  assert.equal(cfgMatch.kind, 'configured');

  // Unwired component requires retain/retire decision instead of clean-neighbor imitation.
  const unwiredMatch = selectReferenceExemplar(
    unwiredComp,
    new Map([[unwiredComp.id, unwiredComp], [node('disp:comp:active', { tier: 'display', subkind: 'component', status: 'clean' }).id, node('disp:comp:active', { tier: 'display', subkind: 'component', status: 'clean' })]]),
  );
  assert.equal(unwiredMatch.kind, 'none');

  const warnFinding: BoundaryFinding = {
    id: 'f-warn',
    rule_code: 'TRUTH-004',
    tier: 'truth',
    severity: 'warning',
    blocks_gate: false,
    confidence: 'candidate',
    evidence_strength: 'heuristic',
    node_id: solverNode.id,
    source_file: 'backend/services/orders.py',
    line: 88,
    title: 'Candidate unbounded cache write',
    detail: 'No static TTL literal found.',
    remediation: 'Confirm store purpose or set TTL.',
  };
  const inboundMany = Array.from({ length: 8 }, (_, idx) => edge(`caller-${idx}`, solverNode.id, 'calls_helper'));
  const briefDefault = buildDiagnosticBrief({
    activeSlug: 'demo',
    node: solverNode,
    allNodesById: new Map([[solverNode.id, solverNode], [cleanSameSubkind.id, cleanSameSubkind]]),
    inbound: inboundMany,
    outbound: [],
    nodeFindings: [warnFinding],
    exemplar: unvalMatch,
  });
  assert.match(briefDefault, /\[investigate\]/);
  assert.match(briefDefault, /INVESTIGATE ONLY/);
  assert.match(briefDefault, /severity=warning \| confidence=candidate \| evidence=heuristic/);
  assert.match(briefDefault, /Triggering Location: backend\/services\/orders\.py:88/);
  assert.match(briefDefault, /Inbound Links \(6 of 8; 2 omitted\)/);
  assert.match(briefDefault, /wythe context demo "manip:solver:sched" --full/);

  const briefIssue = buildDiagnosticBrief({
    activeSlug: 'demo',
    node: unwiredComp,
    allNodesById: new Map([[unwiredComp.id, unwiredComp]]),
    inbound: [],
    outbound: [],
    nodeFindings: [{ ...warnFinding, node_id: unwiredComp.id }],
    exemplar: unwiredMatch,
    intent: 'prepare_issue',
  });
  assert.match(briefIssue, /\[prepare_issue\]/);
  assert.match(briefIssue, /PREPARE ISSUE ONLY/);
  assert.match(briefIssue, /Retain \/ Retire Decision Required/);
});

test('working-set compaction shrinks bounding box, preserves pins, and isolates external selection', () => {
  const manyNodes = Array.from({ length: 120 }, (_, i) =>
    node(`n:${i}`, {
      tier: i % 3 === 0 ? 'truth' : i % 3 === 1 ? 'manipulate' : 'display',
      subkind: i % 2 === 0 ? 'service' : 'component',
      source_file: `src/domain_${i % 12}/file_${i}.ts`,
    }),
  );
  const fullPos = computeScenePositions(manyNodes, 'cluster');
  const subset = manyNodes.slice(0, 6);
  const compactPos = computeScenePositions(subset, 'cluster');

  const span = (pos: Map<string, [number, number, number]>) => {
    const xs = Array.from(pos.values()).map((p) => p[0]);
    const zs = Array.from(pos.values()).map((p) => p[2]);
    return Math.hypot(Math.max(...xs) - Math.min(...xs), Math.max(...zs) - Math.min(...zs));
  };
  assert.ok(span(compactPos) < span(fullPos), 'compact subset bounding span must shrink vs full map');

  // External selection outside an active working set stays suppressed rather than leaking back in.
  const wsList = addNodesToWorkingSet([], [manyNodes[0].id, manyNodes[1].id, manyNodes[2].id]);
  const wsEdges = [edge(manyNodes[2].id, manyNodes[3].id, 'calls_helper'), edge(manyNodes[0].id, manyNodes[1].id, 'reads_truth')];
  const filtered = selectSceneGraph(manyNodes, wsEdges, {
    ...defaults,
    selectedId: manyNodes[10].id,
    workingSetIds: new Set(wsList),
    workingSetActive: true,
  });
  assert.equal(filtered.nodes.length, 3);
  assert.ok(!filtered.nodes.some((n) => n.id === manyNodes[10].id));
  assert.deepEqual(filtered.boundaryCrossings.externalNeighborIds, [manyNodes[3].id]);

  const expanded = expandWorkingSetBoundary(wsList, wsEdges);
  assert.equal(expanded.length, 4);
  assert.ok(expanded.includes(manyNodes[3].id));

  // Manual pin overrides survive layout mode switches.
  const pinCoord: [number, number, number] = [42.5, 9, -17.25];
  const pinned = new Map<string, [number, number, number]>([[manyNodes[0].id, pinCoord]]);
  const switchedPos = computeScenePositions(subset, 'grid', { pinnedPositions: pinned });
  assert.deepEqual(switchedPos.get(manyNodes[0].id), pinCoord);

  // Toggling and removal update working-set membership cleanly.
  const toggled = toggleNodeInWorkingSet(wsList, manyNodes[0].id);
  assert.equal(toggled.includes(manyNodes[0].id), false);
  const removed = removeNodesFromWorkingSet(wsList, [manyNodes[1].id]);
  assert.equal(removed.includes(manyNodes[1].id), false);
});

test('subkind, connected, and flatten2D layouts are deterministic with zero 2D collisions', () => {
  const nodes = [
    node('a1', { subkind: 'table', tier: 'truth', source_file: 'db/a.py' }),
    node('a2', { subkind: 'route', tier: 'manipulate', source_file: 'api/a.py' }),
    node('a3', { subkind: 'page', tier: 'display', source_file: 'ui/a.tsx' }),
    node('b1', { subkind: 'route', tier: 'manipulate', source_file: 'api/b.py' }),
    node('b2', { subkind: 'component', tier: 'display', source_file: 'ui/b.tsx' }),
    node('solo1', { subkind: 'service', tier: 'manipulate', source_file: 'svc/solo1.py' }),
    node('solo2', { subkind: 'cache_store', tier: 'truth', source_file: 'db/solo2.py' }),
  ];
  const edges = [
    edge('a2', 'a1', 'reads_truth'),
    edge('a3', 'a2', 'queries_endpoint'),
    edge('b2', 'b1', 'queries_endpoint'),
  ];

  const sub1 = computeScenePositions(nodes, 'subkind');
  const sub2 = computeScenePositions(nodes, 'subkind');
  assert.deepEqual(Array.from(sub1.entries()), Array.from(sub2.entries()));

  const conn = computeScenePositions(nodes, 'connected', { edges });
  for (const [, coords] of conn.entries()) {
    assert.ok(coords.every((c) => Number.isFinite(c)), 'connected coordinates must be finite');
  }
  const dist2d = (p: [number, number, number], q: [number, number, number]) =>
    Math.hypot(p[0] - q[0], p[2] - q[2]);
  assert.ok(
    dist2d(conn.get('a2')!, conn.get('a1')!) < dist2d(conn.get('a2')!, conn.get('b1')!),
    'connected layout keeps linked components closer than unlinked nodes',
  );

  for (const mode of ['cluster', 'grid', 'subkind', 'connected'] as const) {
    const flat = computeScenePositions(nodes, mode, { edges, flatten2D: true });
    const seenXZ = new Set<string>();
    for (const [id, [x, y, z]] of flat.entries()) {
      assert.equal(y, 0, `${mode} flatten2D must place ${id} at y=0`);
      const key = `${x.toFixed(2)}:${z.toFixed(2)}`;
      assert.ok(!seenXZ.has(key), `${mode} flatten2D collision at ${key}`);
      seenXZ.add(key);
    }
  }
});

test('group summaries collapse and saved-view reconciliation flags commit drift and missing nodes', () => {
  const nodes = [
    node('g1', { subkind: 'route', source_file: 'api/orders/list.py', status: 'policy_in_code' }),
    node('g2', { subkind: 'service', source_file: 'api/orders/svc.py', status: 'clean' }),
    node('g3', { subkind: 'table', source_file: 'db/billing.py', status: 'clean' }),
  ];
  const collapsed = new Set<string>(['route']);
  const summaries = computeGroupSummaries(nodes, 'subkind', collapsed);
  const routeGroup = summaries.find((s) => s.key === 'route');
  assert.ok(routeGroup && routeGroup.collapsed && routeGroup.count === 1 && routeGroup.flaggedCount === 1);

  const groupedGraph = selectSceneGraph(nodes, [], {
    ...defaults,
    groupBy: 'subkind',
    collapsedGroups: collapsed,
  });
  assert.equal(groupedGraph.collapsedCount, 1);
  assert.ok(!groupedGraph.nodes.some((n) => n.id === 'g1'));

  const boundary = computeBoundaryCrossings(new Set(['g1']), nodes, [edge('g1', 'g2', 'calls_helper')]);
  assert.equal(boundary.crossingEdges.length, 1);
  assert.deepEqual(boundary.externalNeighborIds, ['g2']);

  const savedJson = serializeSavedViews([
    {
      id: 'v1',
      name: 'Orders flow',
      createdAt: '2026-11-13T00:00:00Z',
      targetSlug: 'wythe',
      sourceCommit: 'abc111',
      contentDigest: 'dig111',
      nodeIds: ['g1', 'deleted-node'],
      layoutMode: 'connected',
      flatten2D: true,
      compactVisible: true,
      lens: 'status',
      groupBy: 'cluster',
      collapsedGroups: ['billing'],
      pinnedPositions: { g1: [1, 0, 2], 'deleted-node': [5, 0, 5] },
    },
  ]);
  const parsed = parseSavedViews(savedJson);
  assert.equal(parsed.length, 1);
  const reconciled = reconcileSavedView(parsed[0], {
    target_slug: 'wythe',
    source_commit: 'def222',
    content_digest: 'dig222',
    nodes,
  });
  assert.deepEqual(reconciled.matchedNodeIds, ['g1']);
  assert.deepEqual(reconciled.missingNodeIds, ['deleted-node']);
  assert.equal(reconciled.commitChanged, true);
  assert.equal(reconciled.digestChanged, true);
});

test('computeWrappedFocusIndex wraps Tab and Shift+Tab focus cleanly across dialog controls', () => {
  assert.equal(computeWrappedFocusIndex(0, 0, false), -1);
  assert.equal(computeWrappedFocusIndex(0, -1, true), -1);
  assert.equal(computeWrappedFocusIndex(-2, 0, false), -1);

  assert.equal(computeWrappedFocusIndex(1, 0, false), 0);
  assert.equal(computeWrappedFocusIndex(1, 0, true), 0);

  // Forward stepping and forward wrap from last control to first
  assert.equal(computeWrappedFocusIndex(4, 0, false), 1);
  assert.equal(computeWrappedFocusIndex(4, 2, false), 3);
  assert.equal(computeWrappedFocusIndex(4, 3, false), 0);

  // Backward stepping and backward wrap from first control to last
  assert.equal(computeWrappedFocusIndex(4, 3, true), 2);
  assert.equal(computeWrappedFocusIndex(4, 1, true), 0);
  assert.equal(computeWrappedFocusIndex(4, 0, true), 3);

  // Out-of-range currentIndex enters at start on Tab or end on Shift+Tab
  assert.equal(computeWrappedFocusIndex(4, -1, false), 0);
  assert.equal(computeWrappedFocusIndex(4, -1, true), 3);
  assert.equal(computeWrappedFocusIndex(4, 4, false), 0);
  assert.equal(computeWrappedFocusIndex(4, 99, true), 3);
});

test('WebMCP 4/4 bridge executes handlers, bumpViewportCameraRevision advances monotonically, and multi-model probe avoids weight swaps', async () => {
  const r1 = bumpViewportCameraRevision(5);
  const r2 = bumpViewportCameraRevision(2);
  assert.ok(r1 >= 6);
  assert.equal(r2, r1 + 1);

  const registered = new Map<string, { execute: (args: Record<string, unknown>) => Promise<unknown> }>();
  const unregistered: string[] = [];
  const g = globalThis as Record<string, unknown>;
  const prevWin = g.window;
  const prevNavDesc = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const prevFetch = g.fetch;
  try {
    g.window = { location: { origin: 'http://127.0.0.1:8780' } };
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      value: {
        modelContext: {
          registerTool: (def: { name: string; execute: (args: Record<string, unknown>) => Promise<unknown> }) => {
            registered.set(def.name, def);
          },
          unregisterTool: (name: string) => {
            unregistered.push(name);
            registered.delete(name);
          },
        },
      },
    });

    const selectedIds: string[] = [];
    const askedQuestions: string[] = [];
    const cleanup = registerWytheWebMcpBridge({
      getWhatIsThis: async () => ({ active_slug: 'demo' }),
      getLineageCone: async (q) => ({ query: q, matched_seed_ids: ['t:orders'] }),
      selectNode: (id) => selectedIds.push(id),
      openAskDrawer: (q) => askedQuestions.push(q ?? ''),
    });

    assert.deepEqual(
      Array.from(registered.keys()).sort(),
      ['wythe_ask', 'wythe_lineage_cone', 'wythe_select_node', 'wythe_what_is_this'],
    );
    await registered.get('wythe_select_node')!.execute({ nodeId: 't:orders' });
    await registered.get('wythe_ask')!.execute({ question: 'Why gray?' });
    const coneOut = await registered.get('wythe_lineage_cone')!.execute({ query: 'orders' });
    assert.deepEqual(selectedIds, ['t:orders']);
    assert.deepEqual(askedQuestions, ['Why gray?']);
    assert.match(JSON.stringify(coneOut), /t:orders/);

    // L7: Multi-model seat (`qwen3:8b` first, `llava:34b` second) must NOT pick `llava:34b` to force a weight swap
    g.fetch = async (url: unknown) => {
      if (String(url) === 'http://127.0.0.1:19999/v1/models') {
        return {
          ok: true,
          headers: { get: () => '' },
          json: async () => ({
            data: [{ id: 'qwen3:8b' }, { id: 'llava:34b' }],
          }),
        };
      }
      throw new Error('offline');
    };
    const probe = await probeBrowserLocalOpenAi('http://127.0.0.1:19999/v1', true);
    assert.equal(probe.state, 'ready');
    assert.equal(probe.requestModelId, 'qwen3:8b');
    assert.equal(probe.supportsVision, false);

    cleanup();
    assert.equal(unregistered.length, 4);
  } finally {
    g.window = prevWin;
    if (prevNavDesc) {
      Object.defineProperty(globalThis, 'navigator', prevNavDesc);
    } else {
      delete g.navigator;
    }
    g.fetch = prevFetch;
  }
});

test('Lifecycle Z-Depth (#81) pins matched logical (X, Y) coordinates across Z=0/1/2 with zero (X, Y, Z) collisions', () => {
  const fixtureNodes: AtlasNode[] = [
    node('t:orders', { tier: 'truth', subkind: 'table', cluster: 'orders', source_file: 'backend/models/orders.py' }),
    node('t:order_guard', { tier: 'truth', subkind: 'sql_function', cluster: 'orders', source_file: 'backend/db/guard.sql' }),
    node('m:svc:orders', { tier: 'manipulate', subkind: 'service', cluster: 'orders', source_file: 'backend/services/orders.py' }),
    node('z1:m:svc:orders', { tier: 'manipulate', subkind: 'service', cluster: 'orders', source_file: 'dist/orders.metallib' }),
    node('z2:m:svc:orders', { tier: 'manipulate', subkind: 'service', cluster: 'orders', source_file: 'otel/orders.span' }),
    node('m:cli:api', { tier: 'manipulate', subkind: 'cli', cluster: 'api', source_file: 'backend/cli.py' }),
    node('m:dockerfile:Dockerfile', { tier: 'manipulate', subkind: 'cli', cluster: 'containers', source_file: 'Dockerfile' }),
    node('m:dockerfile:Dockerfile.worker', { tier: 'manipulate', subkind: 'cli', cluster: 'containers', source_file: 'Dockerfile.worker' }),
    node('d:page:orders', { tier: 'display', subkind: 'page', cluster: 'orders', source_file: 'frontend/src/app/orders/page.tsx' }),
  ];
  const fixtureEdges: AtlasEdge[] = [
    edge('m:dockerfile:Dockerfile', 'm:cli:api', 'calls_helper'),
    edge('m:dockerfile:Dockerfile.worker', 'm:cli:api', 'calls_helper'),
  ];

  const xy = computeCanonicalXYPositions(fixtureNodes, { edges: fixtureEdges });
  assert.deepEqual(xy.get('m:svc:orders'), xy.get('z1:m:svc:orders'));
  assert.deepEqual(xy.get('m:svc:orders'), xy.get('z2:m:svc:orders'));
  assert.deepEqual(xy.get('m:cli:api'), xy.get('m:dockerfile:Dockerfile'));

  const proj = computeLifecycleZProjection(fixtureNodes, fixtureEdges, []);
  assert.deepEqual(proj.activeWythes, [0, 1, 2]);
  assert.ok(proj.wytheZ.get(0)! < proj.wytheZ.get(1)!);
  assert.ok(proj.wytheZ.get(1)! < proj.wytheZ.get(2)!);

  const z0Pos = proj.primaryPositions.get('m:svc:orders')!;
  const z1Pos = proj.primaryPositions.get('z1:m:svc:orders')!;
  const z2Pos = proj.primaryPositions.get('z2:m:svc:orders')!;
  assert.equal(z0Pos[0], z1Pos[0]);
  assert.equal(z0Pos[1], z1Pos[1]);
  assert.equal(z1Pos[0], z2Pos[0]);
  assert.equal(z1Pos[1], z2Pos[1]);
  assert.notEqual(z0Pos[2], z1Pos[2]);
  assert.notEqual(z1Pos[2], z2Pos[2]);

  // No two rendered bricks may share identical (X, Y, Z) even when two Dockerfiles target one CLI
  const seenXYZ = new Set<string>();
  for (const brick of proj.bricks) {
    const key = brick.position.map((v) => v.toFixed(2)).join(':');
    assert.equal(seenXYZ.has(key), false, `duplicate (X,Y,Z) brick slot at ${key}`);
    seenXYZ.add(key);
  }
});

test('Lifecycle Z-Depth (#81) collapses empty Z planes and emits TRUTH-002 & MANIP-005 drift wall-ties', () => {
  const blueprintOnly = [
    node('t:users', { tier: 'truth', subkind: 'table', cluster: 'auth' }),
    node('m:svc:auth', { tier: 'manipulate', subkind: 'service', cluster: 'auth' }),
  ];
  const collapsedAll = computeLifecycleZProjection(blueprintOnly, [], []);
  assert.deepEqual(collapsedAll.activeWythes, [0]);
  assert.equal(collapsedAll.wytheZ.get(0), 0);
  assert.equal(collapsedAll.wytheZ.has(1), false);
  assert.equal(collapsedAll.wytheZ.has(2), false);
  assert.equal(collapsedAll.wallTies.length, 0);

  // Blueprint + Runtime only (Z=1 absent -> collapsed so span is 28 rather than 48)
  const truthDriftFinding: BoundaryFinding = {
    id: 'f-truth-002',
    rule_code: 'TRUTH-002',
    tier: 'truth',
    severity: 'blocking',
    blocks_gate: true,
    confidence: 'confirmed',
    evidence_strength: 'structural_match',
    node_id: 't:users',
    source_file: 'backend/models/users.py',
    line: 14,
    title: 'ORM model `users` absent from live database catalog',
    detail: 'Live catalog check did not find `users`.',
    remediation: 'Run migrations.',
  };
  const z0AndZ2 = computeLifecycleZProjection(blueprintOnly, [], [truthDriftFinding]);
  assert.deepEqual(z0AndZ2.activeWythes, [0, 2]);
  assert.equal(z0AndZ2.wytheZ.has(1), false);
  assert.equal(z0AndZ2.wytheZ.get(2)! - z0AndZ2.wytheZ.get(0)!, 28);
  assert.equal(z0AndZ2.wallTies.length, 1);
  assert.equal(z0AndZ2.wallTies[0].status, 'drift');
  assert.equal(z0AndZ2.wallTies[0].ruleCode, 'TRUTH-002');
  assert.equal(z0AndZ2.wallTies[0].fromWythe, 0);
  assert.equal(z0AndZ2.wallTies[0].toWythe, 2);
  assert.equal(z0AndZ2.wallTies[0].start[0], z0AndZ2.wallTies[0].end[0]);
  assert.equal(z0AndZ2.wallTies[0].start[1], z0AndZ2.wallTies[0].end[1]);

  // Add MANIP-005 container packaging omission + Zoom-2 intact plugin badge -> all 3 wythes active
  const withCrate: AtlasNode[] = [
    ...blueprintOnly,
    node('m:dockerfile:Dockerfile', { tier: 'manipulate', subkind: 'cli', cluster: 'containers', source_file: 'Dockerfile' }),
    node('m:svc:shader', {
      tier: 'manipulate',
      subkind: 'service',
      cluster: 'render',
      source_file: 'src/shader.swift',
      stratum_badges: [{ key: 'metal_kernels', label: 'Metal AIR Kernels', count: 4 }],
    }),
  ];
  const manip005: BoundaryFinding = {
    id: 'f-manip-005',
    rule_code: 'MANIP-005',
    tier: 'manipulate',
    severity: 'blocking',
    blocks_gate: true,
    confidence: 'confirmed',
    evidence_strength: 'structural_match',
    node_id: 'm:dockerfile:Dockerfile',
    source_file: 'Dockerfile',
    line: 18,
    title: 'Container entrypoint imports `backend/services/example.py` omitted from final-stage `COPY`',
    detail: 'Final-stage command reaches `backend/services/example.py` without COPY.',
    remediation: 'Copy module into runtime stage.',
  };
  const ties = computeLifecycleWallTies(
    withCrate,
    [edge('m:dockerfile:Dockerfile', 'm:svc:auth', 'calls_helper')],
    [truthDriftFinding, manip005],
  );
  assert.ok(ties.some((t) => t.ruleCode === 'TRUTH-002' && t.status === 'drift' && t.toWythe === 2));
  assert.ok(ties.some((t) => t.ruleCode === 'MANIP-005' && t.status === 'drift' && t.toWythe === 1));
  assert.ok(ties.some((t) => t.sourceNodeId === 'm:svc:shader' && t.status === 'intact' && t.toWythe === 1));
});

test('Temporal Z-Diff (#82) pins union (X, Y), preserves surviving columns on add/delete, and falls back on single snapshot', () => {
  const stableBilling = node('t:invoices', { tier: 'truth', subkind: 'table', cluster: 'billing', source_file: 'db/billing.py' });
  const stableOrders = node('m:svc:orders', { tier: 'manipulate', subkind: 'service', cluster: 'orders', source_file: 'svc/orders.py' });
  const deletedLegacy = node('m:svc:legacy_xml', { tier: 'manipulate', subkind: 'service', cluster: 'legacy', source_file: 'svc/legacy.py' });
  const addedAudit = node('t:audit_log', { tier: 'truth', subkind: 'table', cluster: 'orders', source_file: 'db/audit.py' });
  const impactedPage = node('d:page:checkout', { tier: 'display', subkind: 'page', cluster: 'orders', source_file: 'ui/checkout.tsx' });

  const baseNodes = [stableBilling, stableOrders, deletedLegacy, impactedPage];
  const headNodes = [stableBilling, stableOrders, addedAudit, impactedPage];

  // Single-snapshot fallback when no diff report or base snapshot is supplied
  const singleSnap = computeTemporalZProjection({ headNodes });
  assert.equal(singleSnap.hasDiff, false);
  assert.deepEqual(singleSnap.activeSlices, ['z_head']);
  assert.equal(singleSnap.vectors.length, 0);
  for (const [, pos] of singleSnap.headPositions) assert.equal(pos[2], 0);

  // Full base -> HEAD temporal diff with added node, #26 deleted before-image node, impacted caller, and new finding
  const diffProj = computeTemporalZProjection({
    headNodes,
    baseNodes,
    baseEdges: [edge('d:page:checkout', 'm:svc:legacy_xml', 'calls_helper')],
    gitDiffReport: {
      target_slug: 'demo',
      base_ref: 'HEAD~1',
      base_commit: 'aaa1111',
      base_graph_status: 'available',
      base_impacted_node_ids: ['d:page:checkout'],
      removed_nodes: [deletedLegacy],
      analysis_notes: [],
      head_commit: 'bbb2222',
      commits_in_range: ['bbb2222'],
      changed_files: ['svc/legacy.py', 'db/audit.py'],
      touched_node_ids: ['m:svc:orders'],
      impacted_truth_nodes: [],
      impacted_manipulator_nodes: [],
      impacted_display_nodes: ['d:page:checkout'],
      impacted_chains: [],
      new_findings: [
        {
          id: 'f-new-1',
          rule_code: 'MANIP-001',
          tier: 'manipulate',
          severity: 'blocking',
          blocks_gate: true,
          confidence: 'confirmed',
          evidence_strength: 'ast_exact',
          node_id: 'm:svc:orders',
          source_file: 'svc/orders.py',
          line: 9,
          title: 'Shadow policy constant',
          detail: 'Hardcoded cap.',
          remediation: 'Move to DB.',
        },
      ],
      blocking_new_findings: 1,
      diff_verdict: 'FAIL',
    },
  });

  assert.equal(diffProj.hasDiff, true);
  assert.ok(diffProj.zBase < 0 && diffProj.zHead > 0);

  // Every surviving node has bit-identical (X, Y) across Z_base and Z_head
  for (const id of ['t:invoices', 'm:svc:orders', 'd:page:checkout']) {
    const bp = diffProj.basePositions.get(id)!;
    const hp = diffProj.headPositions.get(id)!;
    assert.equal(bp[0], hp[0], `${id} X must stay pinned across Z_base/Z_head`);
    assert.equal(bp[1], hp[1], `${id} Y must stay pinned across Z_base/Z_head`);
  }

  // Surviving column stability across separate base vs HEAD scene position calls pinned to unionNodes
  const unionNodes = [...baseNodes, addedAudit];
  const baseScenePos = computeScenePositions(baseNodes, 'temporal_z', { unionNodes });
  const headScenePos = computeScenePositions(headNodes, 'temporal_z', { unionNodes });
  assert.equal(baseScenePos.get('t:invoices')![0], headScenePos.get('t:invoices')![0]);
  assert.equal(baseScenePos.get('t:invoices')![1], headScenePos.get('t:invoices')![1]);

  // Deleted #26 before-image node anchored on Z_base and projects removed_severed vector to impacted Z_head caller
  assert.equal(diffProj.basePositions.has('m:svc:legacy_xml'), true);
  assert.equal(diffProj.headPositions.has('m:svc:legacy_xml'), false);
  const severed = diffProj.vectors.find((v) => v.kind === 'removed_severed' && v.sourceNodeId === 'm:svc:legacy_xml');
  assert.ok(severed && severed.targetNodeId === 'd:page:checkout');
  assert.ok(diffProj.vectors.some((v) => v.kind === 'unchanged_continuity' && v.sourceNodeId === 't:invoices'));
  assert.ok(diffProj.vectors.some((v) => v.kind === 'added_seam' && v.targetNodeId === 't:audit_log'));
  assert.ok(diffProj.vectors.some((v) => v.kind === 'new_finding_delta' && v.sourceNodeId === 'm:svc:orders'));
});

test('solveSemanticCameraFraming (#86) fits frustum across all 4 presets and clears slabs + neighbor columns', () => {
  const posMap = new Map<string, [number, number, number]>([
    ['target-z0', [-24, -18, -16]],
    ['target-z2', [-24, -18, 16]],
    ['blocker-mid-1', [0, -18, -8]],
    ['blocker-mid-2', [0, -18, 0]],
    ['blocker-mid-3', [0, -18, 8]],
    ['blocker-right', [24, -18, 0]],
    ['upper-manip', [-24, 0, 0]],
    ['upper-disp', [-24, 18, 0]],
  ]);

  for (const preset of ['iso_overview', 'tier_elevation', 'wythe_cross_section', 'corridor_trace'] as const) {
    for (const aspect of [0.6, 1.6, 2.6]) {
      const framed = solveSemanticCameraFraming({
        preset,
        focusNodeIds: ['target-z0', 'target-z2'],
        positions: posMap,
        aspect,
      });
      const cam = new THREE.PerspectiveCamera(46, aspect, 0.1, 4000);
      cam.position.set(...framed.cameraPosition);
      cam.lookAt(...framed.cameraTarget);
      cam.updateProjectionMatrix();
      cam.updateMatrixWorld();
      for (const fp of framed.focalPoints) {
        const ndc = new THREE.Vector3(...fp).project(cam);
        assert.ok(Math.abs(ndc.x) <= 0.96 && Math.abs(ndc.y) <= 0.96, `${preset}@${aspect} out of frustum`);
      }
    }
  }

  // Single-tier Truth focus under tier_elevation & wythe_cross_section never crosses Manipulate/Display slabs
  const elevTruth = solveSemanticCameraFraming({
    preset: 'tier_elevation',
    focusNodeIds: ['target-z0'],
    positions: posMap,
  });
  assert.equal(elevTruth.clearedSlabs, true);
  assert.ok(elevTruth.cameraPosition[1] < -0.65 && elevTruth.cameraPosition[1] > -18.65);

  // Neighbor-column occlusion avoidance: focal column at x=-24 with blockers at x=0,+24 selects -X flank
  const crossLeft = solveSemanticCameraFraming({
    preset: 'wythe_cross_section',
    focusNodeIds: ['target-z0', 'target-z2'],
    positions: posMap,
  });
  assert.equal(crossLeft.clearedSlabs, true);
  assert.equal(crossLeft.clearedNeighborColumns, true);
  assert.ok(crossLeft.cameraPosition[0] < -24, 'must view -X flank without crossing x=0 blocker column');

  // Mirror blockers to x=-48 so +X side is open -> solver flips to +X flank
  const mirroredMap = new Map<string, [number, number, number]>([
    ['target-z0', [24, 0, -16]],
    ['target-z2', [24, 0, 16]],
    ['blocker-left-1', [0, 0, -4]],
    ['blocker-left-2', [0, 0, 4]],
  ]);
  const crossRight = solveSemanticCameraFraming({
    preset: 'wythe_cross_section',
    focusNodeIds: ['target-z0', 'target-z2'],
    positions: mirroredMap,
  });
  assert.equal(crossRight.clearedNeighborColumns, true);
  assert.ok(crossRight.cameraPosition[0] > 24, 'must view +X flank when x=0 blocks -X sightline');

  // Corridor trace aligns perpendicular to horizontal corridor vector so trace is broadside, not end-on
  const corridorMap = new Map<string, [number, number, number]>([
    ['hop-1', [-20, 0, 0]],
    ['hop-2', [20, 0, 0]],
  ]);
  const corridorFrame = solveSemanticCameraFraming({
    preset: 'corridor_trace',
    focusNodeIds: ['hop-1', 'hop-2'],
    positions: corridorMap,
  });
  const camDirXZ = new THREE.Vector2(
    corridorFrame.cameraPosition[0] - corridorFrame.cameraTarget[0],
    corridorFrame.cameraPosition[2] - corridorFrame.cameraTarget[2],
  ).normalize();
  assert.ok(Math.abs(camDirXZ.dot(new THREE.Vector2(1, 0))) < 0.35);
});

test('instant human yield state machine, reduced-motion cut mode, and Tour/Chronicle timeline stepping (#86/#88)', () => {
  const tourEvent = {
    seq: 1,
    issued_at: '2026-11-15T12:00:00Z',
    permalink: '/#target=wythe&focus=t%3Aorders&preset=wythe_cross_section',
    command: {
      target_slug: 'wythe',
      focus_node_ids: ['t:orders'],
      highlight_edge_ids: ['e:1'],
      zoom_stratum: 1 as const,
      framing_preset: 'wythe_cross_section' as const,
      caption: 'Z=0 <-> Z=2 catalog drift',
      tour_keyframes: [
        {
          step_index: 0,
          title: 'Blueprint Table',
          focus_node_ids: ['t:orders'],
          highlight_edge_ids: [],
          zoom_stratum: 1 as const,
          framing_preset: 'tier_elevation' as const,
          caption: 'Step 1: ORM declaration on Z=0',
        },
        {
          step_index: 1,
          title: 'Live Drift Tie',
          focus_node_ids: ['t:orders'],
          highlight_edge_ids: ['e:1'],
          zoom_stratum: 1 as const,
          framing_preset: 'wythe_cross_section' as const,
          caption: 'Step 2: Z=0 <-> Z=2 TRUTH-002 beam',
        },
      ],
      chronicle_frames: [],
    },
  };

  const init = createInitialAgentCameraState();
  assert.equal(init.followMode, 'following');
  const applied = applyIncomingViewportEvent(init, tourEvent);
  assert.equal(applied.shouldMoveCamera, true);
  assert.equal(applied.state.timelineMode, 'tour');

  // Every human input kind immediately yields Follow -> Paused and stops playback
  for (const kind of ['pointerdown', 'pointerdrag', 'wheel', 'touchstart', 'keydown_nav'] as const) {
    const playing = { ...applied.state, isPlaying: true };
    const yielded = yieldAgentCameraOnHumanInput(playing, kind);
    assert.equal(yielded.followMode, 'paused');
    assert.equal(yielded.isPlaying, false);
    assert.equal(yielded.lastYieldReason, kind);
  }

  // Incoming SSE command while paused buffers without moving camera until human explicitly resumes
  const paused = yieldAgentCameraOnHumanInput(applied.state, 'wheel');
  const nextEvent = {
    ...tourEvent,
    seq: 2,
    command: {
      ...tourEvent.command,
      tour_keyframes: [],
      chronicle_frames: [
        {
          phase_index: 0,
          phase_key: 'ingest',
          phase_label: 'Phase 1: Ingest',
          tier: 'truth' as const,
          focus_node_ids: ['t:orders'],
          highlight_edge_ids: [],
          status: 'ok' as const,
          caption: 'Ingest truth records',
          substeps: ['Load rows', 'Verify constraints'],
        },
        {
          phase_index: 1,
          phase_key: 'solve',
          phase_label: 'Phase 2: Transform',
          tier: 'manipulate' as const,
          focus_node_ids: ['m:svc:orders'],
          highlight_edge_ids: ['e:1'],
          status: 'warning' as const,
          caption: 'Transform stage',
          substeps: ['Apply bounds'],
        },
      ],
    },
  };
  const whilePaused = applyIncomingViewportEvent(paused, nextEvent);
  assert.equal(whilePaused.shouldMoveCamera, false);
  assert.equal(whilePaused.state.pendingEventWhilePaused?.seq, 2);

  const resumed = resumeAgentCameraFollow(whilePaused.state);
  assert.equal(resumed.followMode, 'following');
  assert.equal(resumed.activeEvent?.seq, 2);
  assert.equal(resumed.timelineMode, 'chronicle');
  const chronItems = normalizeViewportTimeline(resumed.activeEvent?.command);
  assert.equal(chronItems.length, 2);
  assert.deepEqual(chronItems[0].substeps, ['Load rows', 'Verify constraints']);

  const stepped = stepTimelineFrame(resumed, 1);
  assert.equal(stepped.stepIndex, 1);
  assert.equal(stepTimelineFrame(stepped, 1).stepIndex, 0);

  // Reduced-motion cut mode vs smooth sweep
  const cut = computeCameraTransition({
    fromPos: [0, 0, 50],
    fromTarget: [0, 0, 0],
    toPos: [30, 12, -20],
    toTarget: [5, -18, 0],
    prefersReducedMotion: true,
    progress01: 0.05,
  });
  assert.equal(cut.mode, 'instant_cut');
  assert.equal(cut.durationMs, 0);
  assert.equal(cut.done, true);
  assert.deepEqual(cut.position, [30, 12, -20]);
  assert.deepEqual(cut.target, [5, -18, 0]);

  const sweepMid = computeCameraTransition({
    fromPos: [0, 0, 50],
    fromTarget: [0, 0, 0],
    toPos: [30, 12, -20],
    toTarget: [5, -18, 0],
    prefersReducedMotion: false,
    progress01: 0.5,
  });
  assert.equal(sweepMid.mode, 'smooth_sweep');
  assert.equal(sweepMid.done, false);
  assert.ok(sweepMid.position[0] > 0 && sweepMid.position[0] < 30);
});

test('cold #focus=... permalink determinism, round-trip hydration, and plain-text sanitization (#86)', () => {
  const hashA = buildViewportPermalinkHash({
    target_slug: 'wythe',
    focus_node_ids: ['t:orders', 'm:svc:orders'],
    highlight_edge_ids: ['e:1'],
    lens: 'containers',
    layout_mode: 'lifecycle_z',
    framing_preset: 'wythe_cross_section',
    z_wythe_slice: 'z1_built',
    zoom_stratum: 2,
  });
  const hashB = buildViewportPermalinkHash({
    target_slug: 'wythe',
    focus_node_ids: ['t:orders', 'm:svc:orders'],
    highlight_edge_ids: ['e:1'],
    lens: 'containers',
    layout_mode: 'lifecycle_z',
    framing_preset: 'wythe_cross_section',
    z_wythe_slice: 'z1_built',
    zoom_stratum: 2,
  });
  assert.equal(hashA, hashB);
  assert.equal(
    hashA,
    '#target=wythe&focus=t%3Aorders,m%3Asvc%3Aorders&edges=e%3A1&lens=containers&layout=lifecycle_z&preset=wythe_cross_section&z=z1_built&zoom=2',
  );

  const hydrated = parseViewportPermalinkHash(`http://127.0.0.1:8780/${hashA}`);
  assert.ok(hydrated);
  assert.equal(hydrated.target_slug, 'wythe');
  assert.deepEqual(hydrated.focus_node_ids, ['t:orders', 'm:svc:orders']);
  assert.deepEqual(hydrated.highlight_edge_ids, ['e:1']);
  assert.equal(hydrated.lens, 'containers');
  assert.equal(hydrated.layout_mode, 'lifecycle_z');
  assert.equal(hydrated.framing_preset, 'wythe_cross_section');
  assert.equal(hydrated.z_wythe_slice, 'z1_built');
  assert.equal(hydrated.zoom_stratum, 2);

  // Skip-link and empty hashes never false-hydrate
  assert.equal(parseViewportPermalinkHash('#main-workspace'), null);
  assert.equal(parseViewportPermalinkHash(''), null);

  // Preserves Wythe <-> / -> arrows while stripping HTML and blocking script/javascript: payloads
  assert.equal(sanitizeViewportPlainText('Z=0 <-> Z=1 <-> Z=2 -> clean'), 'Z=0 <-> Z=1 <-> Z=2 -> clean');
  assert.equal(sanitizeViewportPlainText('<b>Safe</b> <i>caption</i>'), 'Safe caption');
  assert.equal(sanitizeViewportPlainText('<script>alert(1)</script>'), '[sanitized unsafe markup]');
  assert.equal(sanitizeViewportPlainText('<scr<tag>ipt>alert(1)</script>'), '[sanitized unsafe markup]');
  assert.equal(sanitizeViewportPlainText('javascript:alert(1)'), '[sanitized unsafe markup]');
});


test('adversarial sanitizer comparisons, %2C/+ permalink fidelity, and Temporal Dockerfile/CLI decollision (#81/#82/#86)', () => {
  // Item 4 (TS): `a < b` and `if a < b && c > d` stay intact; null-byte & >4-deep `<script>` blocked
  assert.equal(sanitizeViewportPlainText('a < b'), 'a < b');
  assert.equal(sanitizeViewportPlainText('if a < b && c > d'), 'if a < b && c > d');
  assert.equal(sanitizeViewportPlainText('<\u0000script>alert(1)</script>'), '[sanitized unsafe markup]');
  assert.equal(sanitizeViewportPlainText('java\u0000script:alert(1)'), '[sanitized unsafe markup]');
  assert.equal(
    sanitizeViewportPlainText('<scr<a<b<c<d<e<f>e>d>c>b>a>ipt>alert(1)</script>'),
    '[sanitized unsafe markup]',
  );

  // Item 6: Default `&zoom=1`, focus/edge deduplication, and `%2C` / `+` / `%25` round-trip parity
  assert.equal(
    buildViewportPermalinkHash({ target_slug: 'wythe' }),
    '#target=wythe&preset=iso_overview&zoom=1',
  );
  const dedupHash = buildViewportPermalinkHash({
    target_slug: 'wythe',
    focus_node_ids: ['m:svc:a,b', 'm:svc:a,b', 't:a+b', 't:x%20y'],
    highlight_edge_ids: ['e:1,2', 'e:1,2'],
  });
  assert.equal(
    dedupHash,
    '#target=wythe&focus=m%3Asvc%3Aa%2Cb,t%3Aa%2Bb,t%3Ax%2520y&edges=e%3A1%2C2&preset=iso_overview&zoom=1',
  );
  const parsedCsv = parseViewportPermalinkHash(dedupHash);
  assert.ok(parsedCsv);
  assert.deepEqual(parsedCsv.focus_node_ids, ['m:svc:a,b', 't:a+b', 't:x%20y']);
  assert.deepEqual(parsedCsv.highlight_edge_ids, ['e:1,2']);
  assert.equal(parsedCsv.zoom_stratum, 1);

  // Item 7a: Temporal Z-Diff never collides `m:dockerfile:Dockerfile` with its `m:cli:api` entrypoint
  const dockerNode: AtlasNode = {
    id: 'm:dockerfile:Dockerfile',
    tier: 'manipulate',
    subkind: 'service',
    label: 'Dockerfile',
    source_file: 'Dockerfile',
    line: 1,
    status: 'clean',
    role: 'mechanism',
    cluster: 'containers',
    summary: 'Container build definition.',
    read_by_count: 0,
    written_by_count: 0,
  };
  const cliEntryNode: AtlasNode = {
    id: 'm:cli:api',
    tier: 'manipulate',
    subkind: 'cli',
    label: 'api',
    source_file: 'backend/app/cli.py',
    line: 1,
    status: 'clean',
    role: 'mechanism',
    cluster: 'core',
    summary: 'CLI entrypoint.',
    read_by_count: 0,
    written_by_count: 0,
  };
  const containerEdge: AtlasEdge = {
    id: 'e:docker->cli',
    source_id: 'm:dockerfile:Dockerfile',
    target_id: 'm:cli:api',
    kind: 'calls_helper',
    verification: 'declared',
    evidence_note: 'CMD wythe serve',
  };
  const tempProj = computeTemporalZProjection({
    headNodes: [dockerNode, cliEntryNode],
    headEdges: [containerEdge],
    gitDiffReport: {
      target_slug: 'wythe',
      base_ref: 'HEAD~1',
      base_commit: 'aaa111',
      base_graph_status: 'available',
      head_commit: 'bbb222',
      touched_node_ids: ['m:cli:api'],
      blocking_new_findings: 0,
      diff_verdict: 'PASS',
    },
  });
  const headCoords = new Set(
    [...tempProj.headPositions.values()].map((pos) => pos.map((v) => v.toFixed(3)).join(',')),
  );
  const baseCoords = new Set(
    [...tempProj.basePositions.values()].map((pos) => pos.map((v) => v.toFixed(3)).join(',')),
  );
  assert.equal(headCoords.size, 2, 'Dockerfile and entrypoint must not collide on Z_head');
  assert.equal(baseCoords.size, 2, 'Dockerfile and entrypoint must not collide on Z_base');

  // Item 7b: Multi-brick slot decollision (`while`) keeps wall-tie endpoints aligned to shifted brick XY
  const dupZ0Nodes: AtlasNode[] = [0, 1, 2].map((idx) => ({
    id: `t:orders_part_${idx}`,
    tier: 'truth',
    subkind: 'table',
    label: 'orders',
    source_file: `backend/schema_${idx}.sql`,
    line: 1,
    status: 'duplicated_truth',
    role: 'mechanism',
    cluster: 'orders',
    summary: 'Duplicate table declaration.',
    read_by_count: 0,
    written_by_count: 0,
    verification_note: 'Verified against live catalog',
  }));
  const lifeDup = computeLifecycleZProjection(dupZ0Nodes, [], [], { observationSource: 'live_pg_catalog' });
  const z0BrickCoords = lifeDup.bricks
    .filter((b) => b.wythe === 0)
    .map((b) => `${b.position[0].toFixed(2)},${b.position[1].toFixed(2)}`);
  assert.equal(new Set(z0BrickCoords).size, 3, 'All 3 colliding Z=0 bricks must decollide uniquely');
  const brickByKey = new Map(lifeDup.bricks.map((b) => [`${b.node.id}@${b.wythe}`, b.position]));
  for (const tie of lifeDup.wallTies) {
    const srcPos = brickByKey.get(`${tie.sourceNodeId}@${tie.fromWythe}`);
    assert.ok(srcPos);
    assert.equal(tie.start[0], srcPos[0]);
    assert.equal(tie.start[1], srcPos[1]);
  }
});

test('ChronicleTimeline (#88 core hook) permalink #chronicle=<id>&phase=<idx> round-trips and Live Follow halts on halted_reason or human input', () => {
  const chronHash = buildViewportPermalinkHash({
    target_slug: 'wythe',
    focus_node_ids: ['t:orders'],
    framing_preset: 'corridor_trace',
    zoom_stratum: 2,
    chronicle_timeline: {
      timeline_id: 'chron-run-01',
      target_slug: 'wythe',
      title: 'Execution Chronicle',
      live_following: true,
      halted_reason: null,
      active_phase_index: 3,
      frames: [],
    },
  });
  assert.equal(
    chronHash,
    '#target=wythe&focus=t%3Aorders&preset=corridor_trace&zoom=2&chronicle=chron-run-01&phase=3',
  );
  const hydrated = parseViewportPermalinkHash(`http://127.0.0.1:8780/${chronHash}`);
  assert.ok(hydrated);
  assert.ok(hydrated.chronicle_timeline);
  assert.equal(hydrated.chronicle_timeline.timeline_id, 'chron-run-01');
  assert.equal(hydrated.chronicle_timeline.active_phase_index, 3);
  assert.equal(hydrated.zoom_stratum, 2);

  // Live Follow advances active_phase_index while live_following=true, then auto-halts when halted_reason is set
  const init = createInitialAgentCameraState();
  assert.equal(init.liveFollowing, true);

  const liveEvent = {
    seq: 10,
    issued_at: '2026-11-16T08:00:00Z',
    permalink: '/#target=wythe&preset=corridor_trace&zoom=1&chronicle=chron-run-01&phase=1',
    command: {
      target_slug: 'wythe',
      focus_node_ids: ['m:svc:orders'],
      highlight_edge_ids: [],
      zoom_stratum: 1 as const,
      framing_preset: 'corridor_trace' as const,
      caption: 'Phase 2 active',
      tour_keyframes: [],
      chronicle_frames: [],
      chronicle_timeline: {
        timeline_id: 'chron-run-01',
        target_slug: 'wythe',
        title: 'Live Execution',
        live_following: true,
        halted_reason: null,
        active_phase_index: 1,
        frames: [
          {
            phase_index: 0,
            phase_key: '1.load',
            phase_label: '[1.Load] Context',
            tier: 'truth' as const,
            focus_node_ids: ['t:orders'],
            highlight_edge_ids: [],
            status: 'ok' as const,
            caption: 'Loaded rows',
            substeps: ['Read truth'],
          },
          {
            phase_index: 1,
            phase_key: '2.build',
            phase_label: '[2.Build] Assembly',
            tier: 'manipulate' as const,
            focus_node_ids: ['m:svc:orders'],
            highlight_edge_ids: [],
            status: 'ok' as const,
            caption: 'Assembling stage',
            substeps: ['Wire builders'],
          },
        ],
      },
    },
  };
  const liveApplied = applyIncomingViewportEvent(init, liveEvent);
  assert.equal(liveApplied.shouldMoveCamera, true);
  assert.equal(liveApplied.state.followMode, 'following');
  assert.equal(liveApplied.state.liveFollowing, true);
  assert.equal(liveApplied.state.timelineMode, 'chronicle');
  assert.equal(liveApplied.state.stepIndex, 1);
  assert.equal(normalizeViewportTimeline(liveEvent.command).length, 2);

  const haltEvent = {
    ...liveEvent,
    seq: 11,
    command: {
      ...liveEvent.command,
      chronicle_timeline: {
        ...liveEvent.command.chronicle_timeline,
        live_following: false,
        halted_reason: 'Contradiction detected at Phase 2',
        active_phase_index: 1,
      },
    },
  };
  const haltApplied = applyIncomingViewportEvent(liveApplied.state, haltEvent);
  assert.equal(haltApplied.shouldMoveCamera, true, 'halt event frames the causal phase immediately');
  assert.equal(haltApplied.state.followMode, 'paused');
  assert.equal(haltApplied.state.liveFollowing, false);
  assert.equal(haltApplied.state.haltedReason, 'Contradiction detected at Phase 2');

  const resumed = resumeAgentCameraFollow(haltApplied.state);
  assert.equal(resumed.followMode, 'following');
  assert.equal(resumed.liveFollowing, true);
  assert.equal(resumed.haltedReason, null);
  const humanPaused = yieldAgentCameraOnHumanInput(resumed, 'wheel');
  assert.equal(humanPaused.followMode, 'paused');
  assert.equal(humanPaused.liveFollowing, false);
});


test('Wave 5: per-tab session isolation, reload persistence, and #session= / ?session= permalinks', () => {
  assert(MIN_UI_FOCUS_DEBOUNCE_MS >= 250, 'hover ui-focus debounce must be >= 250ms');

  const tabAStorage = createMemoryTabStorage();
  const tabBStorage = createMemoryTabStorage();
  const tabCStorage = createMemoryTabStorage();

  const tabAFirst = resolveTabInvestigationIdentity({
    targetSlug: 'quota-service',
    locationHref: 'http://127.0.0.1:8780/',
    storage: tabAStorage,
  });
  const tabBFirst = resolveTabInvestigationIdentity({
    targetSlug: 'quota-service',
    locationHref: 'http://127.0.0.1:8780/',
    storage: tabBStorage,
  });

  assert.notEqual(tabAFirst.clientId, tabBFirst.clientId, 'independent tabs get distinct client_ids');
  assert.notEqual(tabAFirst.sessionId, tabBFirst.sessionId, 'independent tabs get distinct session_ids');
  assert.equal(tabAFirst.sharedFromUrl, false);

  // Reloading Tab A preserves both client_id and session_id
  const tabAReload = resolveTabInvestigationIdentity({
    targetSlug: 'quota-service',
    locationHref: 'http://127.0.0.1:8780/',
    storage: tabAStorage,
  });
  assert.equal(tabAReload.clientId, tabAFirst.clientId);
  assert.equal(tabAReload.sessionId, tabAFirst.sessionId);

  // Explicit #session= share URL joins Tab A's session while keeping Tab C's own client_id
  const shareUrl = buildSessionShareUrl('http://127.0.0.1:8780/', 'quota-service', tabAFirst.sessionId);
  assert.equal(extractExplicitSessionIdFromUrl(shareUrl), tabAFirst.sessionId);
  assert.equal(
    extractExplicitSessionIdFromUrl(`http://127.0.0.1:8780/?session=${tabAFirst.sessionId}`),
    tabAFirst.sessionId,
  );
  const tabCShared = resolveTabInvestigationIdentity({
    targetSlug: 'quota-service',
    locationHref: shareUrl,
    storage: tabCStorage,
  });
  assert.equal(tabCShared.sessionId, tabAFirst.sessionId);
  assert.notEqual(tabCShared.clientId, tabAFirst.clientId);
  assert.equal(tabCShared.sharedFromUrl, true);

  // Unsafe markup in #session= is rejected; bare #session= does not synthesize a camera jump
  assert.equal(extractExplicitSessionIdFromUrl('#session=<script>alert(1)</script>'), null);
  assert.equal(parseViewportPermalinkHash(`#session=${tabAFirst.sessionId}`), null);

  // Permalink hash round-trips session_id when combined with viewport focus
  const hashWithFocus = buildViewportPermalinkHash({
    target_slug: 'quota-service',
    session_id: tabAFirst.sessionId,
    focus_node_ids: ['service:quota_guard'],
    framing_preset: 'tier_elevation',
  });
  assert.match(hashWithFocus, /session=/);
  const parsedFocus = parseViewportPermalinkHash(hashWithFocus);
  assert(parsedFocus);
  assert.equal(parsedFocus.session_id, tabAFirst.sessionId);
  assert.deepEqual(parsedFocus.focus_node_ids, ['service:quota_guard']);

  // Reopen & rotate lifecycle helpers
  const reopened = switchTabSessionId('quota-service', 'inv_prior_session', tabBStorage);
  assert.equal(reopened, 'inv_prior_session');
  const rotated = rotateTabSessionId('quota-service', tabBStorage);
  assert.notEqual(rotated, 'inv_prior_session');
});

test('Wave 5: duplicate, stale, paused, wrong-session, and reload command receipt gating', () => {
  const storage = createMemoryTabStorage();
  const baseEvent = {
    seq: 4,
    delivery_state: 'waiting_for_follow',
    applied_by_client_ids: [] as string[],
    command: {
      command_id: 'cmd_walk_01',
      target_slug: 'quota-service',
      session_id: 'inv_tab_1',
      expected_evidence_revision: 'ev_rev_current',
      expires_at: null as string | null,
    },
  };

  // 1. Initial reload/target-switch hydration NEVER unexpectedly seizes the camera
  const reloadHold = evaluateIncomingViewportCommand({
    event: baseEvent,
    source: 'initial_state',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'following',
    currentEvidenceRevisionId: 'ev_rev_current',
    ackedCommandIds: readAckedCommandIds('quota-service', 'inv_tab_1', storage),
  });
  assert.equal(reloadHold.action, 'hold_on_reload');
  assert.equal(reloadHold.shouldMoveCamera, false);
  assert.equal(reloadHold.receiptOutcome, null);

  // 2. Live SSE under active follow applies and emits `applied` receipt
  const liveApply = evaluateIncomingViewportCommand({
    event: baseEvent,
    source: 'sse',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'following',
    currentEvidenceRevisionId: 'ev_rev_current',
    ackedCommandIds: readAckedCommandIds('quota-service', 'inv_tab_1', storage),
  });
  assert.equal(liveApply.action, 'apply');
  assert.equal(liveApply.shouldMoveCamera, true);
  assert.equal(liveApply.receiptOutcome, 'applied');
  assert.equal(liveApply.markAcked, true);

  const acked = recordAckedCommandId('quota-service', 'inv_tab_1', liveApply.commandKey, storage);
  assert.deepEqual(acked, ['cmd_walk_01']);

  // 3. Reconnected / duplicate command_id is suppressed with zero movement or duplicate receipt
  const dupDecision = evaluateIncomingViewportCommand({
    event: baseEvent,
    source: 'sse',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'following',
    currentEvidenceRevisionId: 'ev_rev_current',
    ackedCommandIds: readAckedCommandIds('quota-service', 'inv_tab_1', storage),
  });
  assert.equal(dupDecision.action, 'ignore');
  assert.equal(dupDecision.reason, 'duplicate_command');
  assert.equal(dupDecision.shouldMoveCamera, false);
  assert.equal(dupDecision.receiptOutcome, null);

  // 4. Scoped command for another tab is ignored
  const otherTabDecision = evaluateIncomingViewportCommand({
    event: {
      ...baseEvent,
      seq: 5,
      command: { ...baseEvent.command, command_id: 'cmd_tab_2', session_id: 'inv_tab_2' },
    },
    source: 'sse',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'following',
  });
  assert.equal(otherTabDecision.action, 'ignore');
  assert.equal(otherTabDecision.reason, 'wrong_session');

  // 5. Stale evidence revision emits `stale_revision` receipt and refuses camera movement
  const staleDecision = evaluateIncomingViewportCommand({
    event: {
      ...baseEvent,
      seq: 6,
      command: {
        ...baseEvent.command,
        command_id: 'cmd_stale_01',
        expected_evidence_revision: 'ev_rev_old',
      },
    },
    source: 'sse',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'following',
    currentEvidenceRevisionId: 'ev_rev_current',
  });
  assert.equal(staleDecision.action, 'reject_stale');
  assert.equal(staleDecision.shouldMoveCamera, false);
  assert.equal(staleDecision.receiptOutcome, 'stale_revision');

  // 6. Paused follow queues command without moving camera and emits `paused_by_human` once
  const pausedNotified = new Set<string>();
  const pausedFirst = evaluateIncomingViewportCommand({
    event: {
      ...baseEvent,
      seq: 7,
      command: { ...baseEvent.command, command_id: 'cmd_paused_01' },
    },
    source: 'sse',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'paused',
    currentEvidenceRevisionId: 'ev_rev_current',
    pausedNotifiedCommandIds: pausedNotified,
  });
  assert.equal(pausedFirst.action, 'queue_while_paused');
  assert.equal(pausedFirst.shouldMoveCamera, false);
  assert.equal(pausedFirst.receiptOutcome, 'paused_by_human');
  pausedNotified.add(pausedFirst.commandKey);

  const pausedRepeat = evaluateIncomingViewportCommand({
    event: {
      ...baseEvent,
      seq: 7,
      command: { ...baseEvent.command, command_id: 'cmd_paused_01' },
    },
    source: 'sse',
    activeTargetSlug: 'quota-service',
    activeSessionId: 'inv_tab_1',
    clientId: 'cli_tab_1',
    followState: 'paused',
    currentEvidenceRevisionId: 'ev_rev_current',
    pausedNotifiedCommandIds: pausedNotified,
  });
  assert.equal(pausedRepeat.receiptOutcome, null);
});

test('Wave 5: human interruption persistence across reloads and window.wythe investigation methods', async () => {
  const storage = createMemoryTabStorage();
  assert.equal(readPersistedFollowState('inv_reload_1', storage), 'following');
  writePersistedFollowState('inv_reload_1', 'paused', storage);
  assert.equal(readPersistedFollowState('inv_reload_1', storage), 'paused');

  const reloadedState = createInitialAgentCameraState(
    readPersistedFollowState('inv_reload_1', storage),
  );
  assert.equal(reloadedState.followMode, 'paused');
  assert.equal(reloadedState.liveFollowing, false);

  const g = globalThis as unknown as Record<string, unknown>;
  const prevWin = g.window;
  const prevNavDesc = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  try {
    g.window = { location: { origin: 'http://127.0.0.1:8780' } };
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      value: {},
    });
    const corrections: Array<{ note: string; kind?: string }> = [];
    let follow: 'following' | 'paused' = 'following';
    const cleanup = registerWytheWebMcpBridge({
      getWhatIsThis: async () => ({ active_slug: 'quota-service' }),
      getLineageCone: async (q) => ({ query: q }),
      selectNode: () => {},
      openAskDrawer: () => {},
      getSession: async () => ({ session_id: 'inv_reload_1', follow_state: follow }),
      submitCorrection: async (note, kind) => {
        corrections.push({ note, kind });
        return { correction_id: 'corr_1', promoted_to_ruling: false };
      },
      setFollowState: async (state) => {
        follow = state;
        return { follow_state: state };
      },
      compareRevisions: async () => ({ digest_changed: true, vanished_refs: ['node:removed'] }),
    });
    const wytheBridge = (g.window as Record<string, unknown>).wythe as {
      getSession: () => Promise<{ session_id: string; follow_state: string }>;
      submitCorrection: (note: string, kind?: string) => Promise<{ promoted_to_ruling: boolean }>;
      setFollowState: (s: 'following' | 'paused') => Promise<{ follow_state: string }>;
      compareRevisions: () => Promise<{ digest_changed: boolean }>;
    };
    await wytheBridge.setFollowState('paused');
    const sess = await wytheBridge.getSession();
    assert.equal(sess.follow_state, 'paused');
    const corr = await wytheBridge.submitCorrection('Algorithmic constant, not policy', 'algorithmic_constant');
    assert.equal(corr.promoted_to_ruling, false);
    assert.equal(corrections.length, 1);
    const comp = await wytheBridge.compareRevisions();
    assert.equal(comp.digest_changed, true);
    cleanup();
  } finally {
    g.window = prevWin;
    if (prevNavDesc) {
      Object.defineProperty(globalThis, 'navigator', prevNavDesc);
    }
  }
});

test('Wave 5: target-scoped URL hash never leaks prior target session_id onto switched target', () => {
  const tabStore = createMemoryTabStorage();
  const wytheIdent = resolveTabInvestigationIdentity({
    targetSlug: 'wythe',
    locationHref: 'http://127.0.0.1:8780/#target=wythe&session=inv_wythe_1',
    storage: tabStore,
  });
  assert.equal(wytheIdent.sessionId, 'inv_wythe_1');

  // Switching to truth-lab while #target=wythe&session=inv_wythe_1 is still in href MUST NOT adopt inv_wythe_1
  const labIdent = resolveTabInvestigationIdentity({
    targetSlug: 'truth-lab',
    locationHref: 'http://127.0.0.1:8780/#target=wythe&session=inv_wythe_1',
    storage: tabStore,
  });
  assert.notEqual(labIdent.sessionId, 'inv_wythe_1');
  assert.equal(labIdent.sharedFromUrl, false);

  // Bare #session=<id> (no conflicting target=) explicitly joins that shared session
  const tab3Bare = resolveTabInvestigationIdentity({
    targetSlug: 'truth-lab',
    locationHref: 'http://127.0.0.1:8780/#session=inv_shared_tab1',
    storage: createMemoryTabStorage(),
  });
  assert.equal(tab3Bare.sessionId, 'inv_shared_tab1');
  assert.equal(tab3Bare.sharedFromUrl, true);
});

test('v0.2.7: 1:1 viewport parity permalinks, smart dense-graph salience, and pure drawer wakeup guard', () => {
  // 1. Smart dense-graph salience (>120 nodes) auto-enables isolateCone for 1 node and workingSet+compact for >=2 nodes
  const singleSalience = computeSmartDenseSalience({
    totalNodeCount: 450,
    resolvedFocus: ['table:quota_records'],
  });
  assert.equal(singleSalience.mode, 'auto_isolate_cone');
  assert.equal(singleSalience.selectedNodeId, 'table:quota_records');
  assert.equal(singleSalience.isolateCone, true);
  assert.equal(singleSalience.workingSetActive, false);
  assert.equal(singleSalience.compactVisible, false);

  const multiSalience = computeSmartDenseSalience({
    totalNodeCount: 450,
    resolvedFocus: ['table:quota_records', 'service:enforce_quota', 'route:post_quota'],
    highlightEdgeIds: ['edge:1'],
    allEdges: [{ id: 'edge:1', source_id: 'route:post_quota', target_id: 'ui:QuotaCard' }],
  });
  assert.equal(multiSalience.mode, 'auto_working_set_compact');
  assert.equal(multiSalience.selectedNodeId, 'table:quota_records');
  assert.equal(multiSalience.isolateCone, false);
  assert.equal(multiSalience.workingSetActive, true);
  assert.equal(multiSalience.compactVisible, true);
  assert.deepEqual(multiSalience.workingSetIds, [
    'table:quota_records',
    'service:enforce_quota',
    'route:post_quota',
    'ui:QuotaCard',
  ]);

  // Explicit filter suppresses auto-salience override
  const explicitOverride = computeSmartDenseSalience({
    totalNodeCount: 450,
    resolvedFocus: ['table:quota_records'],
    onlyFlagged: true,
  });
  assert.equal(explicitOverride.mode, 'none');

  // Small graph (<=120 nodes) leaves salience mode untouched
  const smallGraph = computeSmartDenseSalience({
    totalNodeCount: 80,
    resolvedFocus: ['table:quota_records'],
  });
  assert.equal(smallGraph.mode, 'none');

  // 2. Pure drawer refresh command is detected without clobbering camera or filters
  assert.equal(
    isPureDrawerRefreshCommand({
      target_slug: 'wythe',
      session_id: 'inv_1',
      refresh_session_id: 'inv_1',
      open_drawer: true,
    }),
    true,
  );
  assert.equal(
    isPureDrawerRefreshCommand({
      target_slug: 'wythe',
      refresh_session_id: 'inv_1',
      open_drawer: true,
      focus_node_ids: ['table:quota_records'],
    }),
    false,
  );
  assert.equal(
    isPureDrawerRefreshCommand({
      target_slug: 'wythe',
      refresh_session_id: 'inv_1',
      only_flagged: true,
    }),
    false,
  );

  // 3. Parity filter permalink round-tripping
  const parityHash = buildViewportPermalinkHash({
    target_slug: 'wythe',
    session_id: 'inv_parity',
    focus_node_ids: ['table:quota_records'],
    tier_filter: 'truth',
    subkind_filter: 'db_table',
    edge_filter: 'writes_truth',
    only_flagged: true,
    isolate_cone: true,
    connected_only: true,
    neighborhood_hops: 2,
    search_query: 'quota',
    blast_mode: 'git',
    diff_base_ref: 'HEAD~2',
    working_set_only: true,
    compact_visible: true,
    flatten_2d: true,
    group_by: 'cluster',
    active_tab: 'governance',
  });
  const parsedParity = parseViewportPermalinkHash(parityHash);
  assert.ok(parsedParity);
  assert.equal(parsedParity.tier_filter, 'truth');
  assert.equal(parsedParity.subkind_filter, 'db_table');
  assert.equal(parsedParity.edge_filter, 'writes_truth');
  assert.equal(parsedParity.only_flagged, true);
  assert.equal(parsedParity.isolate_cone, true);
  assert.equal(parsedParity.connected_only, true);
  assert.equal(parsedParity.neighborhood_hops, 2);
  assert.equal(parsedParity.search_query, 'quota');
  assert.equal(parsedParity.blast_mode, 'git');
  assert.equal(parsedParity.diff_base_ref, 'HEAD~2');
  assert.equal(parsedParity.working_set_only, true);
  assert.equal(parsedParity.compact_visible, true);
  assert.equal(parsedParity.flatten_2d, true);
  assert.equal(parsedParity.group_by, 'cluster');
  assert.equal(parsedParity.active_tab, 'governance');
});
