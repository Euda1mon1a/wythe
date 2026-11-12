/**
 * Visual Fiducial & Annotated WebGL X-Ray Snapshot helpers for the
 * zero-copy-paste Human <-> Vision/MCP LLM Bridge.
 */

import type { AtlasEdge, AtlasNode, BoundaryFinding } from '@/api/atlas';
import {
  deriveDomainCluster,
  evaluateNodeVisual,
  getLensLegendItems,
  SCENE_LENS_LABELS,
  type DiffOverlaySet,
  type SceneLayoutMode,
  type SceneLens,
} from '@/lib/wytheSceneLenses';
import type { WythePaletteColors } from '@/lib/wytheTheme';

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
  for (const f of findings) {
    if (!f.node_id) continue;
    const arr = findingsByNode.get(f.node_id) ?? [];
    arr.push(f);
    findingsByNode.set(f.node_id, arr);
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
  if (hollow) return 'Hollow Wireframe (orphaned / unwired)';
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
  onlyFlagged: boolean;
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
    onlyFlagged,
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
  for (const f of findings) {
    if (!f.node_id) continue;
    const arr = findingsByNode.get(f.node_id) ?? [];
    arr.push(f);
    findingsByNode.set(f.node_id, arr);
  }

  interface FrustumEntry {
    node: AtlasNode;
    centerDist2: number;
    colorBucket: string;
    barHex: string;
  }

  const frustumEntries: FrustumEntry[] = [];
  const colorBuckets = new Map<string, AtlasNode[]>();

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
    if (!inFrustum) continue;

    const vis = evaluateNodeVisual({
      node: n,
      lens,
      palette,
      degree: degreeByNode.get(n.id) ?? 0,
      guardedTableIds,
      mutatorNodeIds,
      diffOverlay,
    });
    const isDimmed =
      vis.forceDim || (selectedNodeId !== null && n.id !== selectedNodeId && !coneNodeIds.has(n.id));
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

  const lines: string[] = [
    `### Live 3D Camera Frustum & Exact Screen Colors (${activeSlug} @ ${sourceCommit.slice(0, 10)})`,
    `- **Camera Frustum**: **${frustumEntries.length}** nodes currently on screen (out of ${visibleNodes.length} filtered visible nodes).`,
    `- **Active Controls**: Lens=\`${lens}\` (${SCENE_LENS_LABELS[lens]}) | Layout=\`${layoutMode}\` | Tier=\`${tierFilter}\` | Subkind=\`${subkindFilter}\` | FlaggedOnly=\`${onlyFlagged}\`${searchQuery ? ` | Search=\`${searchQuery}\`` : ''}${diffOverlay ? ` | 3D Blast=\`${diffOverlay.label}\`` : ' | 3D Blast=`off`'}`,
    `- **Active Color Legend**: ${legend.map((it) => `${it.label} (${it.color})`).join(' · ')}`,
  ];

  if (selNode) {
    const sf = findingsByNode.get(selNode.id) ?? [];
    const inb = edges.filter((e) => e.target_id === selNode.id).slice(0, 6);
    const outb = edges.filter((e) => e.source_id === selNode.id).slice(0, 6);
    lines.push(
      `- **SELECTED / HIGHLIGHTED NODE (Pinned by User)**: \`${selNode.id}\` (${selNode.tier} \`${selNode.subkind}\`, label=\`${selNode.label}\`, status=\`${selNode.status}\`, district=\`${deriveDomainCluster(selNode)}\`, pointer=\`${selNode.source_file}:${selNode.line}\`)`,
    );
    if (sf.length > 0) {
      lines.push(
        `  - Selected Node Findings: ${sf.slice(0, 4).map((f) => `\`${f.rule_code}\` [${f.severity}] ${f.title} (line ${f.line})`).join('; ')}`,
      );
    }
    if (inb.length > 0) {
      lines.push(`  - Inbound Callers/Readers: ${inb.map((e) => `\`${e.source_id}\` --[${e.kind}]-->`).join(', ')}`);
    }
    if (outb.length > 0) {
      lines.push(`  - Outbound Targets/Tables: ${outb.map((e) => `--[${e.kind}]--> \`${e.target_id}\``).join(', ')}`);
    }
  } else {
    lines.push('- **SELECTED / HIGHLIGHTED NODE**: None explicitly clicked (see Center-of-Screen nodes below).');
  }

  if (hovNode && hovNode.id !== selNode?.id) {
    lines.push(
      `- **Cursor Currently Hovering**: \`${hovNode.id}\` (\`${hovNode.label}\`, ${hovNode.subkind}, \`${hovNode.source_file}:${hovNode.line}\`, status=\`${hovNode.status}\`)`,
    );
  }

  lines.push('\n#### Exact Rendered Colors Currently Visible On Screen');
  for (const [bucket, bucketNodes] of colorBuckets.entries()) {
    const sample = bucketNodes
      .slice(0, 6)
      .map((n) => `\`${n.label}\` (${n.subkind}, status=${n.status})`)
      .join(', ');
    lines.push(`- **${bucket}**: **${bucketNodes.length}** nodes on screen — e.g. ${sample}`);
  }

  if (centerTop.length > 0) {
    lines.push('\n#### Top Center-of-Screen Nodes in Camera View');
    for (const entry of centerTop) {
      const n = entry.node;
      const nf = findingsByNode.get(n.id)?.[0];
      lines.push(
        `- \`${n.id}\` (\`${n.label}\`, ${n.tier}/${n.subkind}, color=**${entry.colorBucket}**, \`${n.source_file}:${n.line}\`${nf ? `, finding=\`${nf.rule_code}\`: ${nf.title}` : ''})`,
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
    ? `Selected: ${selNode.label}`
    : hovNode
      ? `Hover: ${hovNode.label}`
      : centerTop[0]
        ? `Center: ${centerTop[0].node.label}`
        : activeSlug;

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
    markdownBrief: lines.join('\n'),
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
