/**
 * Visual Fiducial & Annotated WebGL X-Ray Snapshot helpers for the
 * zero-copy-paste Human <-> Vision/MCP LLM Bridge.
 */

import type { AtlasEdge, AtlasNode, BoundaryFinding } from '@/api/atlas';
import {
  collectContainerEntrypointIds,
  deriveDomainCluster,
  evaluateNodeVisual,
  getLensLegendItems,
  SCENE_LENS_LABELS,
  type DiffOverlaySet,
  type SceneLayoutMode,
  type SceneLens,
} from './wytheSceneLenses';
import type { WythePaletteColors } from '@/lib/wytheTheme';

const BOUNDARY_TAG_RE = /<\s*\/?\s*untrusted_repo_metadata\b[^>]*>?/gi;

export function sanitizeRepoMetadataText(
  value: string | null | undefined,
  maxLen = 280,
): string {
  if (!value) return '';
  return value
    .replace(BOUNDARY_TAG_RE, '[redacted-boundary-tag]')
    .replace(/[\r\n\t\x00-\x1f\x7f]+/g, ' ')
    .trim()
    .slice(0, maxLen);
}

export function fenceUntrustedRepoMetadata(raw: string): string {
  const neutralized = raw.replace(BOUNDARY_TAG_RE, '[redacted-boundary-tag]');
  return `<untrusted_repo_metadata>\n${neutralized}\n</untrusted_repo_metadata>`;
}

export interface VisualFocusFiducial {
  district: string | null;
  focusedNodeId: string | null;
  headline: string;
  reason: string;
  tone: 'crimson' | 'amber' | 'sky' | 'teal';
}

export function computeVisualFocusFiducial(params: {
  nodes: AtlasNode[];
  findings: BoundaryFinding[];
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  diffOverlay: DiffOverlaySet | null;
  lens: SceneLens;
}): VisualFocusFiducial | null {
  const { nodes, findings, selectedNodeId, hoveredNodeId, diffOverlay, lens } = params;
  if (nodes.length === 0) return null;

  const nodesById = new Map<string, AtlasNode>();
  for (const n of nodes) nodesById.set(n.id, n);

  const findingsByNode = new Map<string, BoundaryFinding[]>();
  const addFindingRef = (key: string | null | undefined, f: BoundaryFinding) => {
    if (!key) return;
    const arr = findingsByNode.get(key) ?? [];
    if (!arr.includes(f)) {
      arr.push(f);
      findingsByNode.set(key, arr);
    }
  };
  for (const f of findings) {
    addFindingRef(f.node_id, f);
    if (f.target_node_id && f.target_node_id !== f.node_id) {
      addFindingRef(f.target_node_id, f);
    }
  }

  const activeId = selectedNodeId ?? hoveredNodeId;
  const focusNode = activeId ? nodesById.get(activeId) ?? null : null;

  let district: string | null = focusNode ? deriveDomainCluster(focusNode) : null;
  if (!district && diffOverlay && diffOverlay.newFindingNodeIds.size > 0) {
    const counts = new Map<string, number>();
    diffOverlay.newFindingNodeIds.forEach((nid) => {
      const n = nodesById.get(nid);
      if (n) {
        const d = deriveDomainCluster(n);
        counts.set(d, (counts.get(d) ?? 0) + 1);
      }
    });
    let best = '';
    let bestN = 0;
    counts.forEach((cnt, d) => {
      if (cnt > bestN) {
        best = d;
        bestN = cnt;
      }
    });
    if (best) district = best;
  }

  if (!district && !focusNode) {
    return null;
  }

  const distNodes = district
    ? nodes.filter((n) => deriveDomainCluster(n) === district)
    : [];
  const distFlagged = distNodes.filter(
    (n) => n.status !== 'clean' || (findingsByNode.get(n.id)?.length ?? 0) > 0,
  );
  const distFindings = distNodes.flatMap((n) => findingsByNode.get(n.id) ?? []);
  const topFinding =
    (focusNode ? findingsByNode.get(focusNode.id)?.[0] : undefined) ?? distFindings[0];

  if (focusNode) {
    const nf = findingsByNode.get(focusNode.id) ?? [];
    const inCrimson = diffOverlay?.newFindingNodeIds.has(focusNode.id) ?? false;
    const inTouched = diffOverlay?.touchedIds.has(focusNode.id) ?? false;
    const headline = `${focusNode.tier.toUpperCase()} ${focusNode.subkind} "${focusNode.label}" · district "${district}" (${distFlagged.length}/${distNodes.length} flagged)`;
    if (inCrimson && topFinding) {
      return {
        district,
        focusedNodeId: focusNode.id,
        headline,
        reason: `Crimson in ${diffOverlay?.label}: ${topFinding.rule_code} (${topFinding.title})`,
        tone: 'crimson',
      };
    }
    if (nf.length > 0 && topFinding) {
      return {
        district,
        focusedNodeId: focusNode.id,
        headline,
        reason: `${topFinding.rule_code}: ${topFinding.title} (${focusNode.source_file}:${focusNode.line})`,
        tone: 'crimson',
      };
    }
    if (inTouched) {
      return {
        district,
        focusedNodeId: focusNode.id,
        headline,
        reason: `Amber in ${diffOverlay?.label}: modified in ${focusNode.source_file}`,
        tone: 'amber',
      };
    }
    return {
      district,
      focusedNodeId: focusNode.id,
      headline,
      reason: `Lens "${SCENE_LENS_LABELS[lens]}" · status=${focusNode.status} · R:${focusNode.read_by_count ?? 0} W:${focusNode.written_by_count ?? 0}`,
      tone: 'teal',
    };
  }

  return {
    district,
    focusedNodeId: null,
    headline: `Dominant Crimson Cluster · district "${district}" (${distFlagged.length}/${distNodes.length} nodes flagged)`,
    reason: topFinding
      ? `${topFinding.rule_code}: ${topFinding.title}`
      : `Highlighted in ${diffOverlay?.label ?? SCENE_LENS_LABELS[lens]}`,
    tone: 'crimson',
  };
}

export function captureAnnotatedXrayPng(
  webglCanvas: HTMLCanvasElement,
  meta: {
    targetSlug: string;
    sourceCommit: string;
    lensLabel: string;
    headline: string;
    reason: string;
  },
): string | null {
  try {
    const srcW = webglCanvas.width || 1280;
    const srcH = webglCanvas.height || 720;
    const bannerH = 92;
    const out = document.createElement('canvas');
    out.width = srcW;
    out.height = srcH + bannerH;
    const ctx = out.getContext('2d');
    if (!ctx) return null;

    ctx.fillStyle = '#020617';
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, srcW, bannerH);
    ctx.fillStyle = '#14b8a6';
    ctx.fillRect(0, bannerH - 2, srcW, 2);

    ctx.font = 'bold 18px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = '#5eead4';
    ctx.fillText(
      `WYTHE 3-TIER X-RAY :: ${meta.targetSlug} @ ${meta.sourceCommit.slice(0, 10)} · Lens: ${meta.lensLabel}`,
      20,
      28,
    );
    ctx.font = 'bold 16px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = '#f8fafc';
    ctx.fillText(meta.headline.slice(0, 125), 20, 54);
    ctx.font = '15px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = '#fda4af';
    ctx.fillText(meta.reason.slice(0, 135), 20, 78);

    ctx.drawImage(webglCanvas, 0, bannerH, srcW, srcH);
    return out.toDataURL('image/png');
  } catch {
    return null;
  }
}

export function captureCompactViewportWebp(
  webglCanvas: HTMLCanvasElement | null,
  maxEdge = 1024,
  quality = 0.82,
): string | null {
  if (!webglCanvas) return null;
  try {
    const srcW = webglCanvas.width || 1280;
    const srcH = webglCanvas.height || 720;
    const ratio = Math.min(1, maxEdge / Math.max(srcW, srcH));
    const dstW = Math.max(64, Math.round(srcW * ratio));
    const dstH = Math.max(64, Math.round(srcH * ratio));
    const out = document.createElement('canvas');
    out.width = dstW;
    out.height = dstH;
    const ctx = out.getContext('2d');
    if (!ctx) return null;
    ctx.drawImage(webglCanvas, 0, 0, dstW, dstH);
    const webp = out.toDataURL('image/webp', quality);
    if (webp.startsWith('data:image/webp;base64,')) return webp;
    return out.toDataURL('image/jpeg', quality);
  } catch {
    return null;
  }
}

export interface LiveViewportDigest {
  observedAtIso: string;
  activeSlug: string;
  sourceCommit: string;
  lens: SceneLens;
  layoutMode: SceneLayoutMode;
  visibleNodeCount: number;
  inFrustumCount: number;
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  summaryPill: string;
  referencedNodeIds: string[];
  markdownBrief: string;
}

function classifyRenderedColor(hex: string, hollow: boolean, dimmed: boolean): string {
  if (dimmed) return 'Dimmed / Outside Focus';
  if (hollow) return 'Hollow marker (orphaned / unwired)';
  const h = hex.trim().toLowerCase();
  if (['#f43f5e', '#ef4444', '#fb7185', '#e11d48', '#dc2626'].includes(h)) return 'Red / Crimson';
  if (['#f59e0b', '#facc15', '#eab308', '#fbbf24'].includes(h)) return 'Amber / Gold';
  if (['#fb923c', '#f97316'].includes(h)) return 'Orange';
  if (['#a3e635', '#10b981', '#34d399', '#22c55e'].includes(h)) return 'Lime / Emerald Green';
  if (['#2dd4bf', '#14b8a6', '#22d3ee', '#06b6d4'].includes(h)) return 'Teal / Cyan';
  if (['#38bdf8', '#60a5fa', '#3b82f6', '#818cf8'].includes(h)) return 'Sky / Blue / Indigo';
  if (['#a78bfa', '#e879f9', '#c084fc'].includes(h)) return 'Violet / Magenta';
  return 'Slate / Muted';
}

export function buildLiveViewportDigest(params: {
  activeSlug: string;
  sourceCommit: string;
  projectToNdc?: ((x: number, y: number, z: number) => [number, number, number]) | null;
  visibleNodes: AtlasNode[];
  positions: Map<string, [number, number, number]>;
  edges: AtlasEdge[];
  findings: BoundaryFinding[];
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  coneNodeIds: Set<string>;
  lens: SceneLens;
  layoutMode: SceneLayoutMode;
  tierFilter: string;
  subkindFilter: string;
  edgeFilter?: string;
  onlyFlagged: boolean;
  isolateCone?: boolean;
  connectedOnly?: boolean;
  neighborhoodHops?: 0 | 1 | 2;
  workingSetOnly?: boolean;
  compactVisible?: boolean;
  flatten2D?: boolean;
  groupBy?: string;
  zWytheSlice?: string;
  zoomStratum?: 1 | 2 | 3;
  renderedNodeIds?: Set<string>;
  overviewNodeIds?: Set<string>;
  traceIds?: Set<string>;
  searchQuery: string;
  diffOverlay: DiffOverlaySet | null;
  palette: WythePaletteColors;
  degreeByNode: Map<string, number>;
  guardedTableIds: Set<string>;
  mutatorNodeIds: Set<string>;
}): LiveViewportDigest {
  const {
    activeSlug,
    sourceCommit,
    projectToNdc,
    visibleNodes,
    positions,
    edges,
    findings,
    selectedNodeId,
    hoveredNodeId,
    coneNodeIds,
    lens,
    layoutMode,
    tierFilter,
    subkindFilter,
    edgeFilter = 'all',
    onlyFlagged,
    isolateCone = false,
    connectedOnly = false,
    neighborhoodHops = 0,
    workingSetOnly = false,
    compactVisible = false,
    flatten2D = false,
    groupBy = 'none',
    zWytheSlice = 'all',
    zoomStratum = 1,
    renderedNodeIds,
    overviewNodeIds,
    traceIds,
    searchQuery,
    diffOverlay,
    palette,
    degreeByNode,
    guardedTableIds,
    mutatorNodeIds,
  } = params;

  const nodesById = new Map<string, AtlasNode>();
  for (const n of visibleNodes) nodesById.set(n.id, n);

  const findingsByNode = new Map<string, BoundaryFinding[]>();
  const addFindingRef = (key: string | null | undefined, f: BoundaryFinding) => {
    if (!key) return;
    const arr = findingsByNode.get(key) ?? [];
    if (!arr.includes(f)) {
      arr.push(f);
      findingsByNode.set(key, arr);
    }
  };
  for (const f of findings) {
    addFindingRef(f.node_id, f);
    if (f.target_node_id && f.target_node_id !== f.node_id) {
      addFindingRef(f.target_node_id, f);
    }
  }

  interface FrustumEntry {
    node: AtlasNode;
    centerDist2: number;
    colorBucket: string;
    barHex: string;
  }

  const frustumEntries: FrustumEntry[] = [];
  const colorBuckets = new Map<string, AtlasNode[]>();
  const containerEntrypointIds = collectContainerEntrypointIds(visibleNodes, edges);

  for (const n of visibleNodes) {
    const pos = positions.get(n.id);
    if (!pos) continue;
    let inFrustum = true;
    let centerDist2 = 0.5;
    if (projectToNdc) {
      const [nx, ny, nz] = projectToNdc(pos[0], pos[1], pos[2]);
      inFrustum =
        Math.abs(nx) <= 1.04 &&
        Math.abs(ny) <= 1.04 &&
        nz >= -1.0 &&
        nz <= 1.0;
      centerDist2 = nx * nx + ny * ny;
    }
    if (renderedNodeIds ? !renderedNodeIds.has(n.id) : !inFrustum) continue;

    const vis = evaluateNodeVisual({
      node: n,
      lens,
      palette,
      degree: degreeByNode.get(n.id) ?? 0,
      guardedTableIds,
      mutatorNodeIds,
      diffOverlay,
      containerEntrypointIds,
    });
    const isDimmed =
      vis.forceDim || (traceIds?.size
        ? !traceIds.has(n.id) && n.id !== selectedNodeId
        : selectedNodeId !== null && n.id !== selectedNodeId && !coneNodeIds.has(n.id));
    const bucket = classifyRenderedColor(vis.barHex, vis.hollow, isDimmed);
    frustumEntries.push({ node: n, centerDist2, colorBucket: bucket, barHex: vis.barHex });
    const list = colorBuckets.get(bucket) ?? [];
    list.push(n);
    colorBuckets.set(bucket, list);
  }

  frustumEntries.sort((a, b) => a.centerDist2 - b.centerDist2);
  const centerTop = frustumEntries.slice(0, 12);

  const selNode = selectedNodeId ? nodesById.get(selectedNodeId) ?? null : null;
  const hovNode = hoveredNodeId ? nodesById.get(hoveredNodeId) ?? null : null;
  const legend = getLensLegendItems(lens, Boolean(diffOverlay));

  const safeSlug = sanitizeRepoMetadataText(activeSlug, 80);
  const safeCommit = sanitizeRepoMetadataText(sourceCommit, 40).slice(0, 10);
  const safeSearch = sanitizeRepoMetadataText(searchQuery, 120);
  const safeDiffLabel = diffOverlay ? sanitizeRepoMetadataText(diffOverlay.label, 120) : '';
  const lines: string[] = [
    `### Live 3D Camera Frustum & Exact Screen Colors (${safeSlug} @ ${safeCommit})`,
    `- **Camera Frustum**: **${frustumEntries.length}** nodes within camera bounds (out of ${visibleNodes.length} represented nodes; ${overviewNodeIds?.size ?? 0} overview dots).`,
    `- **Active Controls**: Lens=\`${lens}\` (${SCENE_LENS_LABELS[lens]}) | Layout=\`${layoutMode}\` | Tier=\`${tierFilter}\` | Subkind=\`${sanitizeRepoMetadataText(subkindFilter, 64)}\` | EdgeFilter=\`${sanitizeRepoMetadataText(edgeFilter, 64)}\` | FlaggedOnly=\`${onlyFlagged}\` | IsolateCone=\`${isolateCone}\` | ConnectedOnly=\`${connectedOnly}\` | NeighborhoodHops=\`${neighborhoodHops}\` | WorkingSet=\`${workingSetOnly}\` | Compact=\`${compactVisible}\` | Flat2D=\`${flatten2D}\` | GroupBy=\`${groupBy}\` | ZSlice=\`${zWytheSlice}\` | ZoomStratum=\`${zoomStratum}\`${safeSearch ? ` | Search=\`${safeSearch}\`` : ''}${diffOverlay ? ` | 3D Blast=\`${safeDiffLabel}\`` : ' | 3D Blast=`off`'}`,
    `- **Active Color Legend**: ${legend.map((it) => `${it.label} (${it.color})`).join(' · ')}`,
  ];

  if (selNode) {
    const sf = findingsByNode.get(selNode.id) ?? [];
    const inb = edges.filter((e) => e.target_id === selNode.id).slice(0, 6);
    const outb = edges.filter((e) => e.source_id === selNode.id).slice(0, 6);
    const sId = sanitizeRepoMetadataText(selNode.id, 160);
    const sLabel = sanitizeRepoMetadataText(selNode.label, 160);
    const sCluster = sanitizeRepoMetadataText(deriveDomainCluster(selNode), 80);
    const sFile = sanitizeRepoMetadataText(selNode.source_file, 200);
    lines.push(
      `- **SELECTED / HIGHLIGHTED NODE (Pinned by User)**: \`${sId}\` (${selNode.tier} \`${selNode.subkind}\`, label=\`${sLabel}\`, status=\`${selNode.status}\`, district=\`${sCluster}\`, discovery_pointer=\`${sFile}:${selNode.line}\`)`,
    );
    if (selNode.store_purpose) {
      const sp = selNode.store_purpose;
      const details = [
        `intended_use=${sanitizeRepoMetadataText(sp.intended_use, 80)}`,
        sp.authoritative_source ? `authoritative_source=${sanitizeRepoMetadataText(sp.authoritative_source, 160)}` : null,
        sp.copy_reason ? `copy_reason=${sanitizeRepoMetadataText(sp.copy_reason, 180)}` : null,
        sp.refresh_policy ? `refresh_policy=${sanitizeRepoMetadataText(sp.refresh_policy, 120)}` : null,
        sp.recovery_expectation ? `recovery_expectation=${sanitizeRepoMetadataText(sp.recovery_expectation, 120)}` : null,
        sp.keyspace_scope ? `keyspace_scope=${sanitizeRepoMetadataText(sp.keyspace_scope, 120)}` : null,
      ]
        .filter(Boolean)
        .join(', ');
      lines.push(`  - Declared Store Purpose (intent, NOT proof of verification): ${details}`);
      if (sp.verification_summary) {
        lines.push(`  - Purpose Verification: ${sanitizeRepoMetadataText(sp.verification_summary, 240)}`);
      }
    } else if (selNode.verification_note) {
      lines.push(`  - Static Verification Note: ${sanitizeRepoMetadataText(selNode.verification_note, 240)}`);
    }
    if (sf.length > 0) {
      lines.push(
        `  - Selected Node Findings: ${sf
          .slice(0, 4)
          .map((f) => {
            const fNode = sanitizeRepoMetadataText(f.node_id, 160);
            const fFile = sanitizeRepoMetadataText(f.source_file, 200);
            const fTitle = sanitizeRepoMetadataText(f.title, 200);
            const fRule = sanitizeRepoMetadataText(f.rule_code, 48);
            const loc =
              f.target_node_id === selNode.id && f.node_id !== selNode.id
                ? `causal writer \`${fNode}\` @ \`${fFile}:${f.line}\``
                : `\`${fFile}:${f.line}\``;
            return `\`${fRule}\` [${f.severity} | ${f.confidence} | ${f.evidence_strength}] ${fTitle} (${loc})`;
          })
          .join('; ')}`,
      );
    }
    if (inb.length > 0) {
      lines.push(
        `  - Inbound Callers/Readers: ${inb.map((e) => `\`${sanitizeRepoMetadataText(e.source_id, 160)}\` --[${e.kind} | ${e.verification}]-->`).join(', ')}`,
      );
    }
    if (outb.length > 0) {
      lines.push(
        `  - Outbound Targets/Tables: ${outb.map((e) => `--[${e.kind} | ${e.verification}]--> \`${sanitizeRepoMetadataText(e.target_id, 160)}\``).join(', ')}`,
      );
    }
  } else {
    lines.push('- **SELECTED / HIGHLIGHTED NODE**: None explicitly clicked (see Center-of-Screen nodes below).');
  }

  if (hovNode && hovNode.id !== selNode?.id) {
    lines.push(
      `- **Cursor Currently Hovering**: \`${sanitizeRepoMetadataText(hovNode.id, 160)}\` (\`${sanitizeRepoMetadataText(hovNode.label, 160)}\`, ${hovNode.subkind}, \`${sanitizeRepoMetadataText(hovNode.source_file, 200)}:${hovNode.line}\`, status=\`${hovNode.status}\`)`,
    );
  }

  lines.push('\n#### Exact Rendered Colors Currently Visible On Screen');
  for (const [bucket, bucketNodes] of colorBuckets.entries()) {
    const sample = bucketNodes
      .slice(0, 6)
      .map((n) => `\`${sanitizeRepoMetadataText(n.label, 120)}\` (${n.subkind}, status=${n.status})`)
      .join(', ');
    lines.push(`- **${bucket}**: **${bucketNodes.length}** nodes on screen — e.g. ${sample}`);
  }
  lines.push(
    '- **Epistemic Guardrail**: Color (\`amber\`/\`gray_zone\` = unestablished lifetime or unverified store claim; \`crimson\`/\`duplicated_truth\` = conflicting authority or overlapping write evidence) indicates static risk requiring code inspection, NOT proven duplicate runtime data or safe deletion.',
  );

  if (centerTop.length > 0) {
    lines.push('\n#### Top Center-of-Screen Nodes in Camera View');
    for (const entry of centerTop) {
      const n = entry.node;
      const nf = findingsByNode.get(n.id)?.[0];
      const nfText = nf
        ? `, finding=\`${sanitizeRepoMetadataText(nf.rule_code, 48)}\`: ${sanitizeRepoMetadataText(nf.title, 180)}`
        : '';
      lines.push(
        `- \`${sanitizeRepoMetadataText(n.id, 160)}\` (\`${sanitizeRepoMetadataText(n.label, 120)}\`, ${n.tier}/${n.subkind}, color=**${entry.colorBucket}**, \`${sanitizeRepoMetadataText(n.source_file, 200)}:${n.line}\`${nfText})`,
      );
    }
  }

  const refIds: string[] = [];
  if (selNode) refIds.push(selNode.id);
  if (hovNode && !refIds.includes(hovNode.id)) refIds.push(hovNode.id);
  for (const c of centerTop.slice(0, 4)) {
    if (!refIds.includes(c.node.id)) refIds.push(c.node.id);
  }

  const focusTag = selNode
    ? `Selected: ${sanitizeRepoMetadataText(selNode.label, 80)}`
    : hovNode
      ? `Hover: ${sanitizeRepoMetadataText(hovNode.label, 80)}`
      : centerTop[0]
        ? `Center: ${sanitizeRepoMetadataText(centerTop[0].node.label, 80)}`
        : safeSlug;

  return {
    observedAtIso: new Date().toISOString(),
    activeSlug,
    sourceCommit,
    lens,
    layoutMode,
    visibleNodeCount: visibleNodes.length,
    inFrustumCount: frustumEntries.length,
    selectedNodeId,
    hoveredNodeId,
    summaryPill: `${frustumEntries.length}/${visibleNodes.length} in camera · ${focusTag}`,
    referencedNodeIds: refIds,
    markdownBrief: fenceUntrustedRepoMetadata(lines.join('\n')),
  };
}

export async function tryCopyDataUrlPngToClipboard(dataUrl: string): Promise<boolean> {
  if (
    typeof window === 'undefined' ||
    !navigator.clipboard ||
    typeof navigator.clipboard.write !== 'function' ||
    typeof ClipboardItem === 'undefined'
  ) {
    return false;
  }
  try {
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
    return true;
  } catch {
    return false;
  }
}
