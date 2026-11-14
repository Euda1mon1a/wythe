import type { AtlasEdge, AtlasNode } from '@/api/atlas';
import { evaluateEdgeVisual, type EdgeFilterMode } from './wytheSceneLenses';

export type NeighborhoodHops = 0 | 1 | 2;

/** Undirected, bounded neighborhood over the connections the user chose to show. */
export function collectNeighborhood(
  selectedId: string | null,
  edges: AtlasEdge[],
  hops: NeighborhoodHops,
): Set<string> {
  if (!selectedId) return new Set();
  const adjacent = new Map<string, Set<string>>();
  for (const edge of edges) {
    for (const [a, b] of [[edge.source_id, edge.target_id], [edge.target_id, edge.source_id]]) {
      if (!adjacent.has(a)) adjacent.set(a, new Set());
      adjacent.get(a)!.add(b);
    }
  }
  const found = new Set([selectedId]);
  let frontier = [selectedId];
  for (let depth = 0; depth < hops; depth += 1) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const neighbor of adjacent.get(id) ?? []) {
        if (!found.has(neighbor)) {
          found.add(neighbor);
          next.push(neighbor);
        }
      }
    }
    frontier = next;
  }
  return found;
}

export interface SceneGraphFilters {
  tier: 'all' | AtlasNode['tier'];
  subkind: 'all' | AtlasNode['subkind'];
  edgeFilter: EdgeFilterMode;
  onlyFlagged: boolean;
  connectedOnly: boolean;
  searchQuery: string;
  selectedId: string | null;
  traceIds: Set<string>;
  coneIds: Set<string>;
  isolateCone: boolean;
  neighborhoodHops: NeighborhoodHops;
}

/** No sampling: every matching node and connection is retained. */
export function selectSceneGraph(nodes: AtlasNode[], edges: AtlasEdge[], filters: SceneGraphFilters) {
  const known = new Set(nodes.map((node) => node.id));
  const eligibleEdges = edges.filter((edge) =>
    known.has(edge.source_id) && known.has(edge.target_id) &&
    evaluateEdgeVisual(edge, filters.edgeFilter).visible,
  );
  const pinned = new Set(filters.traceIds);
  if (filters.selectedId) pinned.add(filters.selectedId);
  const query = filters.searchQuery.trim().toLowerCase();
  const matches = (node: AtlasNode) => {
    if (filters.tier !== 'all' && node.tier !== filters.tier) return false;
    if (filters.subkind !== 'all' && node.subkind !== filters.subkind) return false;
    if (filters.onlyFlagged && node.status === 'clean') return false;
    return !query || [node.label, node.source_file, ...(node.columns ?? []), ...(node.http_paths ?? [])]
      .some((text) => text.toLowerCase().includes(query));
  };
  const matchingIds = new Set(nodes.filter(matches).map((node) => node.id));
  const candidateIds = new Set([...matchingIds, ...pinned]);
  const candidateEdges = eligibleEdges.filter((edge) => candidateIds.has(edge.source_id) && candidateIds.has(edge.target_id));
  const neighborhood = collectNeighborhood(filters.selectedId, candidateEdges, filters.neighborhoodHops);
  for (const id of matchingIds) {
    if (filters.selectedId && ((filters.isolateCone && !filters.coneIds.has(id)) ||
        (filters.neighborhoodHops && !neighborhood.has(id)))) matchingIds.delete(id);
  }
  let shown = nodes.filter((node) => matchingIds.has(node.id) || pinned.has(node.id));
  const shownIds = new Set(shown.map((node) => node.id));
  const shownEdges = candidateEdges.filter((edge) => shownIds.has(edge.source_id) && shownIds.has(edge.target_id));
  const connected = new Set(shownEdges.flatMap((edge) => [edge.source_id, edge.target_id]));
  const disconnectedCount = shown.filter((node) => !connected.has(node.id)).length;
  // No pin exception here: "Connected only" must mean an edge exists in this view.
  // A self-loop counts; a dangling edge to an absent endpoint does not.
  if (filters.connectedOnly) shown = shown.filter((node) => connected.has(node.id));
  const counts = { display: 0, manipulate: 0, truth: 0 };
  for (const node of shown) counts[node.tier] += 1;
  return {
    nodes: shown,
    edges: shownEdges,
    counts,
    hiddenCount: nodes.length - shown.length,
    disconnectedCount,
    pinnedExtraCount: shown.filter((node) => !matchingIds.has(node.id)).length,
  };
}
