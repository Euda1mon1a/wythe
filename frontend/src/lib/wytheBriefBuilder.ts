import type {
  AtlasEdge,
  AtlasNode,
  BoundaryFinding,
  PortableReferenceExemplar,
} from '../api/atlas';

export type BriefTaskIntent = 'investigate' | 'prepare_issue' | 'scoped_refactor';

export const BRIEF_TASK_INTENT_LABELS: Record<BriefTaskIntent, string> = {
  investigate: 'Investigate evidence (read-only)',
  prepare_issue: 'Prepare issue / triage report (no edits)',
  scoped_refactor: 'Propose or implement scoped refactor',
};

export interface ExemplarSelection {
  kind: 'configured' | 'unvalidated_neighbor' | 'none';
  configured?: PortableReferenceExemplar;
  neighborNode?: AtlasNode;
  rationale: string;
  caveat: string;
}

const RETAIN_RETIRE_RULES = new Set(['MANIP-003', 'DISP-007', 'TRUTH-001', 'TRUTH-005']);

export function isRetainOrRetireCandidate(
  node: AtlasNode,
  nodeFindings: BoundaryFinding[],
): boolean {
  if (node.status === 'unwired') return true;
  return nodeFindings.some((f) => RETAIN_RETIRE_RULES.has(f.rule_code));
}

export function selectReferenceExemplar(
  node: AtlasNode,
  allNodesById: Map<string, AtlasNode>,
  configuredExemplars: PortableReferenceExemplar[] = [],
): ExemplarSelection {
  // 1. Prefer an explicit repository-configured reference authority when one applies.
  const exactNodeMatch = configuredExemplars.find((ex) => ex.node_id === node.id);
  if (exactNodeMatch) {
    return {
      kind: 'configured',
      configured: exactNodeMatch,
      rationale: exactNodeMatch.rationale,
      caveat: exactNodeMatch.approved_by
        ? `Configured project reference (approved by ${exactNodeMatch.approved_by}).`
        : 'Configured project reference from .wythe/governance.json.',
    };
  }

  const subkindMatch = configuredExemplars.find((ex) =>
    (ex.applies_to_subkinds ?? []).includes(node.subkind),
  );
  if (subkindMatch) {
    return {
      kind: 'configured',
      configured: subkindMatch,
      rationale: subkindMatch.rationale,
      caveat: subkindMatch.approved_by
        ? `Configured ${node.subkind} project reference (approved by ${subkindMatch.approved_by}).`
        : `Configured ${node.subkind} project reference from .wythe/governance.json.`,
    };
  }

  const tierMatch = configuredExemplars.find(
    (ex) =>
      (ex.applies_to_subkinds ?? []).length === 0 &&
      (ex.applies_to_tiers ?? []).includes(node.tier),
  );
  if (tierMatch) {
    return {
      kind: 'configured',
      configured: tierMatch,
      rationale: tierMatch.rationale,
      caveat: tierMatch.approved_by
        ? `Configured ${node.tier}-tier project reference (approved by ${tierMatch.approved_by}).`
        : `Configured ${node.tier}-tier project reference from .wythe/governance.json.`,
    };
  }

  // Unwired surfaces need an explicit retain/wire/retire decision rather than neighbor imitation.
  if (node.status === 'unwired') {
    return {
      kind: 'none',
      rationale:
        'Unwired surface: confirm whether this symbol should be retained/wired or retired before comparing against another module.',
      caveat:
        'Omitted unvalidated clean neighbors because unwired surfaces require a retain/retire decision first.',
    };
  }

  // 2. Fall back strictly to same-tier AND same-subkind clean neighbors (never cross-subkind).
  for (const candidate of allNodesById.values()) {
    if (
      candidate.id !== node.id &&
      candidate.tier === node.tier &&
      candidate.subkind === node.subkind &&
      candidate.status === 'clean'
    ) {
      return {
        kind: 'unvalidated_neighbor',
        neighborNode: candidate,
        rationale: `Same tier (${node.tier}) and subkind (${node.subkind}) neighbor with clean scan status.`,
        caveat:
          'UNVALIDATED example only: status="clean" means zero findings attached in this scan, NOT an approved architectural pattern. Verify clock, ownership, and persistence suitability before imitating.',
      };
    }
  }

  return {
    kind: 'none',
    rationale: `No configured exemplar or clean same-subkind (${node.subkind}) neighbor was found in this snapshot.`,
    caveat: 'No reference exemplar attached.',
  };
}

export interface DiagnosticBriefInput {
  activeSlug: string;
  node: AtlasNode;
  allNodesById: Map<string, AtlasNode>;
  inbound: AtlasEdge[];
  outbound: AtlasEdge[];
  nodeFindings: BoundaryFinding[];
  exemplar: ExemplarSelection;
  intent?: BriefTaskIntent;
  snippetLines?: Array<{ line_number: number; text: string; is_focus?: boolean }>;
  maxLinksPerDirection?: number;
}

export function buildDiagnosticBrief({
  activeSlug,
  node,
  allNodesById,
  inbound,
  outbound,
  nodeFindings,
  exemplar,
  intent = 'investigate',
  snippetLines = [],
  maxLinksPerDirection = 6,
}: DiagnosticBriefInput): string {
  const shownIn = inbound.slice(0, maxLinksPerDirection);
  const shownOut = outbound.slice(0, maxLinksPerDirection);
  const omittedIn = Math.max(0, inbound.length - shownIn.length);
  const omittedOut = Math.max(0, outbound.length - shownOut.length);

  const formatEdge = (e: AtlasEdge, dir: 'in' | 'out') => {
    const peerId = dir === 'in' ? e.source_id : e.target_id;
    const arrow = dir === 'in' ? '<-' : '->';
    const peerLabel = allNodesById.get(peerId)?.label ?? peerId;
    const ev = e.evidence_path ? ` @ ${e.evidence_path}` : '';
    return `${e.kind} [${e.verification}] ${arrow} ${peerLabel}${ev}`;
  };

  const inSummary =
    shownIn.length > 0
      ? `Inbound Links (${shownIn.length} of ${inbound.length}${omittedIn > 0 ? `; ${omittedIn} omitted` : ''}): ${shownIn.map((e) => formatEdge(e, 'in')).join(', ')}`
      : 'Inbound Links (0 of 0): none';
  const outSummary =
    shownOut.length > 0
      ? `Outbound Links (${shownOut.length} of ${outbound.length}${omittedOut > 0 ? `; ${omittedOut} omitted` : ''}): ${shownOut.map((e) => formatEdge(e, 'out')).join(', ')}`
      : 'Outbound Links (0 of 0): none';

  const sp = node.store_purpose;
  const purposeBlock = sp
    ? [
        `Declared Store Purpose (intent, NOT verified safety): intended_use=${sp.intended_use}`,
        sp.authoritative_source ? `Authoritative Source: ${sp.authoritative_source}` : '',
        sp.copy_reason ? `Copy Reason: ${sp.copy_reason}` : '',
        sp.refresh_policy ? `Refresh / Invalidation Policy: ${sp.refresh_policy}` : '',
        sp.recovery_expectation ? `Recovery Expectation: ${sp.recovery_expectation}` : '',
        sp.keyspace_scope ? `Keyspace Scope: ${sp.keyspace_scope}` : '',
        sp.verification_summary ? `Static Verification: ${sp.verification_summary}` : '',
      ]
        .filter(Boolean)
        .join('\n')
    : node.verification_note
      ? `Static Verification: ${node.verification_note}`
      : '';

  let exemplarLine = `Reference Exemplar: none (${exemplar.caveat})`;
  if (exemplar.kind === 'configured' && exemplar.configured) {
    exemplarLine = `Configured Project Reference Exemplar: ${exemplar.configured.title} (${exemplar.configured.pointer}) — ${exemplar.caveat} Rationale: ${exemplar.rationale}`;
  } else if (exemplar.kind === 'unvalidated_neighbor' && exemplar.neighborNode) {
    const nb = exemplar.neighborNode;
    exemplarLine = `Unvalidated Clean Same-Subkind Neighbor (NOT an approved pattern): ${nb.label} (${nb.source_file}:${nb.line}) — ${exemplar.caveat}`;
  }

  const retainRetireLine = isRetainOrRetireCandidate(node, nodeFindings)
    ? 'Retain / Retire Decision Required: Surface is unwired or flagged only by unreferenced-code candidate checks; confirm whether to retain, wire, or retire before refactoring.'
    : '';

  const findingBlocks = nodeFindings
    .map((f) => {
      const causal =
        f.target_node_id === node.id && f.node_id !== node.id
          ? ` (attached via upstream writer ${f.node_id})`
          : '';
      return [
        `- [${f.rule_code}] severity=${f.severity} | confidence=${f.confidence} | evidence=${f.evidence_strength} — ${f.title}${causal}`,
        `  Triggering Location: ${f.source_file}:${f.line}`,
        `  Detail: ${f.detail}`,
        `  Suggested remediation (unverified): ${f.remediation}`,
      ].join('\n');
    })
    .join('\n');

  const codeLines = snippetLines
    .map((l) => `${l.is_focus ? '>' : ' '} ${String(l.line_number).padStart(4, ' ')} | ${l.text}`)
    .join('\n');

  const fullConeUrl = `/scans/${activeSlug}/context?q=${encodeURIComponent(node.id)}&full=true`;
  const heading =
    intent === 'prepare_issue'
      ? `Wythe Issue Preparation Brief [prepare_issue] (${activeSlug})`
      : intent === 'scoped_refactor'
        ? `Wythe Scoped Refactor Brief [scoped_refactor] (${activeSlug})`
        : `Wythe Diagnostic Brief [investigate] (${activeSlug})`;

  const closingTask =
    intent === 'prepare_issue'
      ? 'Task (prepare_issue): PREPARE ISSUE ONLY (do NOT edit code). Summarize exact triggering file:line coordinates, severity/confidence/evidence strength, static edge states, and open questions for maintainer triage.'
      : intent === 'scoped_refactor'
        ? 'Task (scoped_refactor): PROPOSE OR IMPLEMENT SCOPED REFACTOR only after confirming causality at each triggering coordinate above, keeping Tier 1 truth in DB, Tier 2 orchestration in backend, and Tier 3 typed display.'
        : 'Task (investigate): INVESTIGATE ONLY (do NOT edit code yet). Inspect the triggering coordinates, static edge states, store purpose verification notes, and any unvalidated exemplars above before proposing changes or filing an issue.';

  return [
    `# ${heading}`,
    `Task Intent: ${intent} (${BRIEF_TASK_INTENT_LABELS[intent]})`,
    `Target Node: ${node.label} (${node.tier} :: ${node.subkind}, status=${node.status})`,
    `Representative Discovery Anchor: ${node.source_file}:${node.line} (note: inspect per-finding Triggering Locations below; representative file line is not always the causal operation)`,
    inSummary,
    outSummary,
    `Full Lineage Cone Evidence: wythe context ${activeSlug} "${node.id}" --full (API: ${fullConeUrl})`,
    purposeBlock,
    exemplarLine,
    retainRetireLine,
    nodeFindings.length > 0 ? '' : '',
    nodeFindings.length > 0
      ? `## Observed Scanner Findings (Requires Evidence Review)\n${findingBlocks}`
      : '## Observed Scanner Findings\nNo active findings attached to this node.',
    codeLines
      ? `\n## Local Source Excerpt Around Discovery Anchor (${node.source_file})\n\`\`\`\n${codeLines}\n\`\`\``
      : '',
    '',
    closingTask,
  ]
    .filter((line) => line !== '')
    .join('\n');
}
