import type { AtlasNode, BoundaryFinding, TargetProjectRead } from '@/api/atlas';

export type PaletteMode = 'all' | 'actions' | 'nodes' | 'findings' | 'targets';

export interface QuickActionDef {
  id: string;
  label: string;
  subtitle: string;
  group: string;
  shortcut?: string;
  keywords?: string;
  disabled?: boolean;
  run: () => void;
}

export interface PaletteItem {
  key: string;
  kind: 'action' | 'node' | 'finding' | 'target';
  group: string;
  label: string;
  subtitle: string;
  badge?: string;
  badgeTone?: 'teal' | 'sky' | 'amber' | 'rose' | 'slate';
  shortcut?: string;
  disabled?: boolean;
  score: number;
  onSelect: () => void;
}

export function parsePaletteQuery(raw: string): { mode: PaletteMode; term: string } {
  const trimmed = raw.trimStart();
  if (trimmed.startsWith('>')) return { mode: 'actions', term: trimmed.slice(1).trim() };
  if (trimmed.startsWith('@')) return { mode: 'nodes', term: trimmed.slice(1).trim() };
  if (trimmed.startsWith('!')) return { mode: 'findings', term: trimmed.slice(1).trim() };
  if (trimmed.startsWith('#')) return { mode: 'targets', term: trimmed.slice(1).trim() };
  return { mode: 'all', term: trimmed.trim() };
}

export function scoreQueryMatch(term: string, primary: string, secondary = ''): number {
  if (!term) return 1;
  const q = term.toLowerCase();
  const p = primary.toLowerCase();
  const s = secondary.toLowerCase();

  if (p === q) return 120;
  if (p.startsWith(q)) return 95;
  const boundaryIdx = p.search(new RegExp(`(^|[/_.:\\s-])${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  if (boundaryIdx >= 0) return 82 - Math.min(boundaryIdx, 20);
  const subIdx = p.indexOf(q);
  if (subIdx >= 0) return 68 - Math.min(subIdx, 20);
  const secIdx = s.indexOf(q);
  if (secIdx >= 0) return 45 - Math.min(secIdx, 15);

  // Ordered subsequence fuzzy match on primary
  let qi = 0;
  let gaps = 0;
  for (let i = 0; i < p.length && qi < q.length; i += 1) {
    if (p[i] === q[qi]) {
      qi += 1;
    } else if (qi > 0) {
      gaps += 1;
    }
  }
  if (qi === q.length && gaps <= 14) {
    return Math.max(12, 36 - gaps);
  }
  return 0;
}

function toneForNodeStatus(status: string): PaletteItem['badgeTone'] {
  if (status === 'duplicated_truth') return 'rose';
  if (status === 'policy_in_code' || status === 'gray_zone') return 'amber';
  if (status === 'orphaned' || status === 'unwired' || status === 'in_flight') return 'slate';
  return 'teal';
}

export function buildPaletteItems(opts: {
  rawQuery: string;
  filterOverride: PaletteMode | null;
  actions: QuickActionDef[];
  nodes: AtlasNode[];
  findings: BoundaryFinding[];
  targets: TargetProjectRead[];
  activeSlug: string;
  onSelectNode: (nodeId: string) => void;
  onSelectFinding: (finding: BoundaryFinding) => void;
  onSelectTarget: (slug: string) => void;
}): PaletteItem[] {
  const parsed = parsePaletteQuery(opts.rawQuery);
  const mode = opts.filterOverride ?? parsed.mode;
  const term = parsed.term;
  const out: PaletteItem[] = [];

  if (mode === 'all' || mode === 'actions') {
    for (const act of opts.actions) {
      if (act.disabled) continue;
      const sc = scoreQueryMatch(term, act.label, `${act.subtitle} ${act.keywords ?? ''} ${act.group}`);
      if (sc > 0) {
        out.push({
          key: `act:${act.id}`,
          kind: 'action',
          group: act.group,
          label: act.label,
          subtitle: act.subtitle,
          shortcut: act.shortcut,
          score: sc + (term ? 8 : 20),
          onSelect: act.run,
        });
      }
    }
  }

  if (mode === 'all' || mode === 'targets') {
    for (const t of opts.targets) {
      const sc = scoreQueryMatch(term, `${t.name} ${t.slug}`, t.repo_path);
      if (sc > 0 && (mode === 'targets' || term.length > 0)) {
        out.push({
          key: `tgt:${t.slug}`,
          kind: 'target',
          group: 'Targets',
          label: `${t.name} (${t.slug})`,
          subtitle: t.repo_path,
          badge: t.slug === opts.activeSlug ? 'ACTIVE' : t.stack_profile_slug,
          badgeTone: t.slug === opts.activeSlug ? 'teal' : 'sky',
          score: sc + 6,
          onSelect: () => opts.onSelectTarget(t.slug),
        });
      }
    }
  }

  if (mode === 'all' || mode === 'nodes' || mode === 'findings') {
    const nodePool =
      mode === 'findings' ? opts.nodes.filter((n) => n.status !== 'clean') : opts.nodes;
    const nodeCap = mode === 'nodes' ? 60 : 28;
    const matchedNodes: PaletteItem[] = [];
    const lowerTerm = term.toLowerCase();
    const colPrefix = lowerTerm.startsWith('col:') ? lowerTerm.slice(4).trim() : null;
    const httpPrefix = lowerTerm.startsWith('http:') ? lowerTerm.slice(5).trim() : null;
    const subPrefix = lowerTerm.startsWith('sub:') ? lowerTerm.slice(4).trim() : null;

    for (const n of nodePool) {
      const cols = n.columns ?? [];
      const paths = n.http_paths ?? [];
      const methods = n.http_methods ?? [];

      let sc = 0;
      let extraSubtitle = '';
      if (colPrefix !== null) {
        const hitCol = cols.find((c) => c.toLowerCase().includes(colPrefix));
        if (hitCol) {
          sc = 95;
          extraSubtitle = ` · col:${hitCol}`;
        }
      } else if (httpPrefix !== null) {
        const hitHttp = [...methods, ...paths].find((h) => h.toLowerCase().includes(httpPrefix));
        if (hitHttp) {
          sc = 95;
          extraSubtitle = ` · ${hitHttp}`;
        }
      } else if (subPrefix !== null) {
        if (n.subkind.toLowerCase().includes(subPrefix)) {
          sc = 92;
        }
      } else {
        const httpHint = `${methods.join(' ')} ${paths.join(' ')} ${cols.join(' ')}`;
        sc = scoreQueryMatch(
          term,
          n.label,
          `${n.tier} ${n.subkind} ${n.status} ${n.source_file} ${httpHint}`,
        );
      }

      if (sc > 0 && (mode !== 'all' || term.length > 0)) {
        matchedNodes.push({
          key: `node:${n.id}`,
          kind: 'node',
          group: '3-Tier Nodes',
          label: n.label,
          subtitle: `${n.tier} · ${n.subkind} · ${n.source_file}:${n.line}${extraSubtitle}`,
          badge: n.status,
          badgeTone: toneForNodeStatus(n.status),
          score: sc,
          onSelect: () => opts.onSelectNode(n.id),
        });
      }
    }
    matchedNodes.sort((a, b) => b.score - a.score);
    out.push(...matchedNodes.slice(0, nodeCap));
  }

  if (mode === 'all' || mode === 'findings') {
    const matchedFindings: PaletteItem[] = [];
    for (const f of opts.findings) {
      const sc = scoreQueryMatch(
        term,
        `${f.rule_code} ${f.title}`,
        `${f.source_file} ${f.node_id ?? ''}`,
      );
      if (sc > 0 && (mode === 'findings' || term.length >= 2)) {
        matchedFindings.push({
          key: `find:${f.id}`,
          kind: 'finding',
          group: 'Boundary Findings',
          label: `${f.rule_code}: ${f.title}`,
          subtitle: `${f.source_file}:${f.line}`,
          badge: f.severity,
          badgeTone: f.severity === 'blocking' ? 'rose' : 'amber',
          score: sc + 2,
          onSelect: () => opts.onSelectFinding(f),
        });
      }
    }
    matchedFindings.sort((a, b) => b.score - a.score);
    out.push(...matchedFindings.slice(0, mode === 'findings' ? 45 : 16));
  }

  if (term) {
    out.sort((a, b) => b.score - a.score);
  }
  return out.slice(0, 80);
}
