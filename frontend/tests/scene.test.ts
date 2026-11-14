import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as THREE from 'three';
import type { AtlasEdge, AtlasNode } from '../src/api/atlas';
import { selectSceneGraph, collectNeighborhood, type SceneGraphFilters } from '../src/lib/wytheSceneGraph';
import { computeScenePositions } from '../src/lib/wytheSceneLenses';
import { createBatchedNodes, createBatchedEdges, fitGraphCamera, type SceneRenderNode } from '../src/lib/wytheSceneBatches';
import { buildLiveViewportDigest } from '../src/lib/wytheVisionBridge';
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
