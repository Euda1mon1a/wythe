"""PR Diff Gate, Directional 3-Tier Blast-Radius Slicer, & SARIF 2.1.0 Exporter."""

from __future__ import annotations

import re
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ScanSnapshot
from app.schemas.atlas import (
    BoundaryFinding,
    DiffBlastRadiusReport,
    SnapshotComparisonReport,
    TruthAtlasReport,
)

_DIFF_FILE_RE = re.compile(r"^\+\+\+\s+b/(?P<path>.+)$")
_DIFF_HUNK_RE = re.compile(r"^@@\s+-[0-9,]+\s+\+(?P<start>\d+)(?:,(?P<count>\d+))?\s+@@")


def _collect_git_changed_ranges(
    repo_root: Path, base_ref: str
) -> dict[str, list[tuple[int, int]]]:
    """Return `{rel_posix_path: [(start_line, end_line), ...]}` relative to `base_ref`."""
    ref = "HEAD" if base_ref.upper() == "WORKING" else base_ref
    diff_text = ""
    for candidate_ref in (ref, "HEAD"):
        try:
            proc = subprocess.run(
                ["git", "diff", "--unified=0", candidate_ref],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            diff_text = proc.stdout
            break
        except (OSError, subprocess.SubprocessError):
            continue

    changed: dict[str, list[tuple[int, int]]] = {}
    current_path: str | None = None
    for raw_line in diff_text.splitlines():
        fm = _DIFF_FILE_RE.match(raw_line)
        if fm is not None:
            p = fm.group("path").strip()
            current_path = None if p == "/dev/null" else p
            if current_path is not None:
                changed.setdefault(current_path, [])
            continue
        hm = _DIFF_HUNK_RE.match(raw_line)
        if hm is not None and current_path is not None:
            start = int(hm.group("start"))
            count = int(hm.group("count")) if hm.group("count") is not None else 1
            if count > 0:
                changed.setdefault(current_path, []).append((start, start + count - 1))

    # Include untracked working-tree files so uncommitted files are gated before `git add`.
    try:
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=4,
        )
        for rel in untracked.stdout.splitlines():
            clean_rel = rel.strip()
            if clean_rel:
                changed[clean_rel] = [(1, 1_000_000)]
    except (OSError, subprocess.SubprocessError):
        pass

    return changed


def _directional_slice(start_ids: set[str], adj: dict[str, set[str]]) -> set[str]:
    visited = set(start_ids)
    q: deque[str] = deque(sorted(start_ids))
    while q:
        cur = q.popleft()
        for nxt in sorted(adj.get(cur, set())):
            if nxt not in visited:
                visited.add(nxt)
                q.append(nxt)
    return visited


def compute_diff_and_blast_radius(
    repo_root: Path,
    report: TruthAtlasReport,
    base_ref: str = "HEAD~1",
) -> DiffBlastRadiusReport:
    """Compute changed-line boundary findings + upstream/downstream 3-tier blast radius."""
    changed_ranges = _collect_git_changed_ranges(repo_root, base_ref)
    changed_files = sorted(changed_ranges.keys())
    changed_set = set(changed_files)

    touched_ids: set[str] = {
        n.id for n in report.nodes if n.source_file in changed_set
    }

    fwd_adj: dict[str, set[str]] = {}
    rev_adj: dict[str, set[str]] = {}
    for edge in report.edges:
        fwd_adj.setdefault(edge.source_id, set()).add(edge.target_id)
        rev_adj.setdefault(edge.target_id, set()).add(edge.source_id)

    # Separate forward (downstream) and backward (upstream) slices prevent false sibling bleed.
    impacted_all = _directional_slice(touched_ids, fwd_adj) | _directional_slice(
        touched_ids, rev_adj
    )
    nodes_by_id = {n.id: n for n in report.nodes}

    impacted_truth = sorted(
        nid for nid in impacted_all if nid in nodes_by_id and nodes_by_id[nid].tier == "truth"
    )
    impacted_manip = sorted(
        nid for nid in impacted_all if nid in nodes_by_id and nodes_by_id[nid].tier == "manipulate"
    )
    impacted_disp = sorted(
        nid for nid in impacted_all if nid in nodes_by_id and nodes_by_id[nid].tier == "display"
    )

    impacted_chains = [
        ch
        for ch in report.chains
        if (
            ch.display_node_id in impacted_all
            and ch.route_node_id in impacted_all
            and (
                ch.display_node_id in touched_ids
                or ch.route_node_id in touched_ids
                or any(v in touched_ids for v in ch.via_node_ids)
                or any(m in touched_ids for m in ch.manipulator_node_ids)
                or any(t in touched_ids for t in ch.truth_table_ids)
            )
        )
    ]

    new_findings: list[BoundaryFinding] = []
    for f in report.findings:
        ranges = changed_ranges.get(f.source_file)
        if not ranges:
            continue
        if any(lo <= f.line <= hi for lo, hi in ranges):
            new_findings.append(f)

    blocking_new = sum(1 for f in new_findings if f.blocks_gate)
    commits_in_range: list[str] = []
    if base_ref.upper() != "WORKING":
        try:
            log_proc = subprocess.run(
                ["git", "log", "--oneline", "--first-parent", "-n", "25", f"{base_ref}..HEAD"],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
                timeout=4,
            )
            commits_in_range = [
                ln.strip() for ln in log_proc.stdout.splitlines() if ln.strip()
            ]
        except (OSError, subprocess.SubprocessError):
            commits_in_range = []

    return DiffBlastRadiusReport(
        target_slug=report.target_slug,
        base_ref=base_ref,
        head_commit=report.source_commit,
        commits_in_range=commits_in_range,
        changed_files=changed_files,
        touched_node_ids=sorted(touched_ids),
        impacted_truth_nodes=impacted_truth,
        impacted_manipulator_nodes=impacted_manip,
        impacted_display_nodes=impacted_disp,
        impacted_chains=impacted_chains,
        new_findings=new_findings,
        blocking_new_findings=blocking_new,
        diff_verdict="FAIL" if blocking_new > 0 else "PASS",
    )


def compare_recorded_snapshots(
    session: Session,
    target_id: int,
    target_slug: str,
    base_snapshot_id: int,
    head_snapshot_id: int,
) -> SnapshotComparisonReport | None:
    """Compare two persisted `ScanSnapshot` rows and return exact structural/finding deltas."""
    base_row = session.scalar(
        select(ScanSnapshot).where(
            ScanSnapshot.target_id == target_id,
            ScanSnapshot.id == base_snapshot_id,
        )
    )
    head_row = session.scalar(
        select(ScanSnapshot).where(
            ScanSnapshot.target_id == target_id,
            ScanSnapshot.id == head_snapshot_id,
        )
    )
    if base_row is None or head_row is None:
        return None

    base_rep = TruthAtlasReport.model_validate_json(base_row.payload_json)
    head_rep = TruthAtlasReport.model_validate_json(head_row.payload_json)

    base_nodes = {n.id: n for n in base_rep.nodes}
    head_nodes = {n.id: n for n in head_rep.nodes}
    added_nodes = [head_nodes[nid] for nid in sorted(head_nodes.keys() - base_nodes.keys())]
    removed_nodes = [base_nodes[nid] for nid in sorted(base_nodes.keys() - head_nodes.keys())]

    def _f_key(f: BoundaryFinding) -> tuple[str, str | None, str, str]:
        return (f.rule_code, f.node_id, f.source_file, f.title)

    base_f = {_f_key(f): f for f in base_rep.findings}
    head_f = {_f_key(f): f for f in head_rep.findings}
    new_findings = [head_f[k] for k in sorted(head_f.keys() - base_f.keys(), key=str)]
    resolved_findings = [base_f[k] for k in sorted(base_f.keys() - head_f.keys(), key=str)]

    return SnapshotComparisonReport(
        target_slug=target_slug,
        base_snapshot_id=base_row.id,
        head_snapshot_id=head_row.id,
        base_commit=base_row.source_commit,
        head_commit=head_row.source_commit,
        base_observed_at=base_row.observed_at,
        head_observed_at=head_row.observed_at,
        edge_delta=head_rep.summary.verified_edges - base_rep.summary.verified_edges,
        chain_delta=head_rep.summary.end_to_end_chains - base_rep.summary.end_to_end_chains,
        blocking_delta=head_rep.summary.blocking_findings - base_rep.summary.blocking_findings,
        warning_delta=head_rep.summary.warning_findings - base_rep.summary.warning_findings,
        added_nodes=added_nodes,
        removed_nodes=removed_nodes,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
    )


def build_sarif_log(
    report: TruthAtlasReport,
    findings_override: list[BoundaryFinding] | None = None,
) -> dict[str, Any]:
    """Serialize findings into OASIS SARIF 2.1.0 format for GitHub/Gitea/GitLab code scanning."""
    active_findings = findings_override if findings_override is not None else report.findings
    rules_payload = [
        {
            "id": row.rule_code,
            "name": row.rule_code.replace("-", "_"),
            "shortDescription": {"text": row.title},
            "properties": {"tier": row.tier, "severity": row.severity},
            "defaultConfiguration": {
                "level": "error" if row.blocks_gate else "warning"
            },
        }
        for row in report.gate.rule_counts
    ]
    results_payload = [
        {
            "ruleId": f.rule_code,
            "level": "error" if f.blocks_gate else "warning",
            "message": {
                "text": f"{f.title} — {f.detail} Remediation: {f.remediation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.source_file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, f.line)},
                    }
                }
            ],
        }
        for f in active_findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Wythe",
                        "version": "0.3.0",
                        "informationUri": "https://github.com/wythe-dev/wythe",
                        "rules": rules_payload,
                    }
                },
                "automationDetails": {
                    "id": f"wythe/{report.target_slug}/{report.stack_profile}"
                },
                "results": results_payload,
            }
        ],
    }
