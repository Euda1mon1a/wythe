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
  computeScenePositions,
  evaluateEdgeVisual,
  getEdgeVerificationLegendItems,
} from '../src/lib/wytheSceneLenses';
import { createBatchedNodes, createBatchedEdges, fitGraphCamera, type SceneRenderNode } from '../src/lib/wytheSceneBatches';
import { buildLiveViewportDigest } from '../src/lib/wytheVisionBridge';
import { buildDiagnosticBrief, selectReferenceExemplar } from '../src/lib/wytheBriefBuilder';
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
    approved_by: 'aaron',
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
