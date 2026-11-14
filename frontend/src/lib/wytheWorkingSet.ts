import type { AtlasEdge, AtlasNode } from '../api/atlas';
import {
  ALL_NODE_SUBKINDS,
  deriveDomainCluster,
  type SceneLayoutMode,
  type SceneLens,
} from './wytheSceneLenses';

export const SAVED_VIEWS_STORAGE_KEY = 'wythe:saved-working-views:v1';

export interface BoundaryCrossingsResult {
  crossingEdges: AtlasEdge[];
  externalNeighborIds: string[];
  inboundCount: number;
  outboundCount: number;
}

export interface GroupSummary {
  key: string;
  label: string;
  count: number;
  flaggedCount: number;
  collapsed: boolean;
}

export interface SavedWorkingView {
  id: string;
  name: string;
  createdAt: string;
  targetSlug: string;
  sourceCommit: string;
  contentDigest: string;
  nodeIds: string[];
  layoutMode: SceneLayoutMode;
  compactVisible: boolean;
  flatten2D: boolean;
  lens: SceneLens;
  groupBy?: 'none' | 'subkind' | 'cluster';
  pinnedPositions: Record<string, [number, number, number]>;
  collapsedGroups: string[];
}

export interface SavedViewReconcileResult {
  matchedNodeIds: string[];
  missingNodeIds: string[];
  targetMismatch: boolean;
  commitChanged: boolean;
  digestChanged: boolean;
  statusNote: string;
}

function dedupeIds(ids: Iterable<string>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    if (id && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

export function addNodesToWorkingSet(currentIds: string[], additions: Iterable<string>): string[] {
  return dedupeIds([...currentIds, ...additions]);
}

export function removeNodesFromWorkingSet(currentIds: string[], removals: Iterable<string>): string[] {
  const drop = new Set(removals);
  return currentIds.filter((id) => !drop.has(id));
}

export function toggleNodeInWorkingSet(currentIds: string[], nodeId: string): string[] {
  if (!nodeId) return currentIds;
  return currentIds.includes(nodeId)
    ? currentIds.filter((id) => id !== nodeId)
    : [...currentIds, nodeId];
}

/** Collect every eligible edge that crosses the working-set boundary into known nodes outside it. */
export function computeBoundaryCrossings(
  workingIds: ReadonlySet<string>,
  allNodes: AtlasNode[],
  eligibleEdges: AtlasEdge[],
): BoundaryCrossingsResult {
  const knownIds = new Set(allNodes.map((n) => n.id));
  const crossingEdges: AtlasEdge[] = [];
  const externalNeighborIds: string[] = [];
  const seenExternal = new Set<string>();
  let inboundCount = 0;
  let outboundCount = 0;

  for (const edge of eligibleEdges) {
    if (!knownIds.has(edge.source_id) || !knownIds.has(edge.target_id)) continue;
    const srcIn = workingIds.has(edge.source_id);
    const dstIn = workingIds.has(edge.target_id);
    if (srcIn === dstIn) continue;
    crossingEdges.push(edge);
    if (srcIn) {
      outboundCount += 1;
      if (!seenExternal.has(edge.target_id)) {
        seenExternal.add(edge.target_id);
        externalNeighborIds.push(edge.target_id);
      }
    } else {
      inboundCount += 1;
      if (!seenExternal.has(edge.source_id)) {
        seenExternal.add(edge.source_id);
        externalNeighborIds.push(edge.source_id);
      }
    }
  }

  return { crossingEdges, externalNeighborIds, inboundCount, outboundCount };
}

export function expandWorkingSetBoundary(
  workingIds: Iterable<string>,
  crossingEdges: AtlasEdge[],
): string[] {
  const additions: string[] = [];
  const base = new Set(workingIds);
  for (const edge of crossingEdges) {
    if (base.has(edge.source_id) && !base.has(edge.target_id)) additions.push(edge.target_id);
    if (base.has(edge.target_id) && !base.has(edge.source_id)) additions.push(edge.source_id);
  }
  return addNodesToWorkingSet([...base], additions);
}

const SUBKIND_ORDER = new Map<string, number>(ALL_NODE_SUBKINDS.map((k, idx) => [k, idx]));

export function computeGroupSummaries(
  nodes: AtlasNode[],
  groupBy: 'subkind' | 'cluster',
  collapsedGroups: ReadonlySet<string>,
): GroupSummary[] {
  const counts = new Map<string, number>();
  const flaggedCounts = new Map<string, number>();
  for (const node of nodes) {
    const key = groupBy === 'subkind' ? node.subkind : deriveDomainCluster(node);
    counts.set(key, (counts.get(key) ?? 0) + 1);
    if (node.status !== 'clean') {
      flaggedCounts.set(key, (flaggedCounts.get(key) ?? 0) + 1);
    }
  }
  const keys = [...counts.keys()].sort((a, b) => {
    if (groupBy === 'subkind') {
      return (SUBKIND_ORDER.get(a) ?? 99) - (SUBKIND_ORDER.get(b) ?? 99) || a.localeCompare(b);
    }
    return (counts.get(b) ?? 0) - (counts.get(a) ?? 0) || a.localeCompare(b);
  });
  return keys.map((key) => ({
    key,
    label: key.replace(/_/g, ' '),
    count: counts.get(key) ?? 0,
    flaggedCount: flaggedCounts.get(key) ?? 0,
    collapsed: collapsedGroups.has(key),
  }));
}

export function reconcileSavedView(
  saved: SavedWorkingView,
  report: {
    target_slug: string;
    source_commit: string;
    content_digest: string;
    nodes: Array<Pick<AtlasNode, 'id'>>;
  },
): SavedViewReconcileResult {
  const currentIds = new Set(report.nodes.map((n) => n.id));
  const matchedNodeIds: string[] = [];
  const missingNodeIds: string[] = [];
  for (const id of saved.nodeIds) {
    if (currentIds.has(id)) matchedNodeIds.push(id);
    else missingNodeIds.push(id);
  }
  const targetMismatch = saved.targetSlug !== report.target_slug;
  const commitChanged = saved.sourceCommit !== report.source_commit;
  const digestChanged = saved.contentDigest !== report.content_digest;

  const warnings: string[] = [];
  if (targetMismatch) {
    warnings.push(`Saved for target "${saved.targetSlug}", loaded on "${report.target_slug}"`);
  }
  if (commitChanged || digestChanged) {
    const oldSha = saved.sourceCommit.slice(0, 8) || 'unknown';
    const curSha = report.source_commit.slice(0, 8) || 'unknown';
    warnings.push(`Scan changed (${oldSha} -> ${curSha})`);
  }
  if (missingNodeIds.length > 0) {
    warnings.push(
      `${missingNodeIds.length} saved node(s) missing in current scan (${matchedNodeIds.length}/${saved.nodeIds.length} matched)`,
    );
  }

  return {
    matchedNodeIds,
    missingNodeIds,
    targetMismatch,
    commitChanged,
    digestChanged,
    statusNote:
      warnings.length > 0
        ? warnings.join('; ')
        : `Exact match for ${saved.targetSlug}@${saved.sourceCommit.slice(0, 8)} (${matchedNodeIds.length} nodes).`,
  };
}

export function parseSavedViews(raw: string | null): SavedWorkingView[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is SavedWorkingView =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as SavedWorkingView).id === 'string' &&
        typeof (item as SavedWorkingView).name === 'string' &&
        typeof (item as SavedWorkingView).targetSlug === 'string' &&
        Array.isArray((item as SavedWorkingView).nodeIds),
    );
  } catch {
    return [];
  }
}

export function serializeSavedViews(views: SavedWorkingView[]): string {
  return JSON.stringify(views);
}
