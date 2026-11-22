"""PR Diff Gate, Directional 3-Tier Blast-Radius Slicer, & SARIF 2.1.0 Exporter."""

from __future__ import annotations

import subprocess
import tempfile
import urllib.parse
from collections import Counter, deque
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.core.safe_git import SafeGitError, run_safe_git
from app.models import ScanSnapshot, TargetProject
from app.schemas.atlas import (
    BoundaryFinding,
    DiffBlastRadiusReport,
    SnapshotComparisonReport,
    TruthAtlasReport,
)
from app.services.git_diff import GitChanges, collect_git_changes, materialize_base_tree
from app.services.scanner_service import run_target_scan


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


def _finding_delta_key(f: BoundaryFinding) -> tuple[str, str | None, str | None, str, str]:
    return (
        f.rule_code,
        f.node_id,
        f.target_node_id,
        f.source_file,
        f.title,
    )


def _compute_new_findings(
    head_findings: list[BoundaryFinding],
    base_findings: list[BoundaryFinding] | None,
    changed_ranges: dict[str, list[tuple[int, int]]],
) -> list[BoundaryFinding]:
    """Compute genuine `(head - base)` multiset finding delta (falling back to hunk overlap if base missing)."""
    def _in_hunk(f: BoundaryFinding) -> bool:
        ranges = changed_ranges.get(f.source_file)
        return bool(ranges and any(lo <= f.line <= hi for lo, hi in ranges))

    if base_findings is None:
        return [f for f in head_findings if _in_hunk(f)]

    base_counts = Counter(_finding_delta_key(bf) for bf in base_findings)
    grouped_head: dict[tuple[str, str | None, str | None, str, str], list[BoundaryFinding]] = {}
    for hf in head_findings:
        grouped_head.setdefault(_finding_delta_key(hf), []).append(hf)

    selected_ids: set[int] = set()
    for key, instances in grouped_head.items():
        excess = len(instances) - base_counts.get(key, 0)
        if excess <= 0:
            continue
        # Prefer instances landing inside changed hunks first when a file already had an older duplicate
        ranked = sorted(instances, key=lambda item: (0 if _in_hunk(item) else 1, item.line))
        for chosen in ranked[:excess]:
            selected_ids.add(id(chosen))

    return [hf for hf in head_findings if id(hf) in selected_ids]


def _encode_sarif_uri(source_file: str) -> str:
    clean = source_file.replace("\\", "/").lstrip("/")
    return urllib.parse.quote(clean, safe="/:@!$&'()*+,;=-._~")


def compute_diff_and_blast_radius(
    repo_root: Path,
    report: TruthAtlasReport,
    base_ref: str = "HEAD~1",
    *,
    base_report: TruthAtlasReport | None = None,
    changes: GitChanges | None = None,
    analysis_notes: list[str] | None = None,
) -> DiffBlastRadiusReport:
    """Compute new cross-tier boundary findings + upstream/downstream 3-tier blast radius."""
    changes = changes or collect_git_changes(repo_root, base_ref)
    if base_report is not None and base_report.source_commit != changes.base_commit:
        raise ValueError("Base graph does not match the requested Git commit")
    changed_ranges = changes.after
    changed_files = sorted(changes.before.keys() | changes.after.keys())
    notes = list(analysis_notes or [])
    base_recovery_failed = any(
        n.startswith("Base graph could not be recovered:") for n in notes
    )
    base_missing = (bool(changes.before) or base_recovery_failed) and base_report is None
    head_incomplete = not report.coverage_complete
    base_incomplete = base_report is not None and not base_report.coverage_complete
    incomplete = base_missing or head_incomplete or base_incomplete
    if base_missing:
        notes.append("Base graph unavailable: removed dependencies may be missing from the blast radius.")
    if head_incomplete:
        for scan_note in report.scan_notes:
            if scan_note not in notes:
                notes.append(scan_note)
        if not report.scan_notes:
            notes.append(
                "Head scan coverage is incomplete because one or more stack tiers lacked coverage."
            )
    if base_incomplete:
        notes.append(
            "Base scan coverage is incomplete because one or more stack tiers lacked coverage."
        )
    notes.append(
        "Static dependency evidence is not proof of safe deletion; "
        "check external entry points and runtime effects."
    )

    touched_ids: set[str] = set()
    impacted_all: set[str] = set()
    base_impacted: set[str] = set()
    nodes_by_id = {}
    chains_by_id = {}
    for graph, paths in ((base_report, changes.before), (report, changes.after)):
        if graph is None:
            continue
        touched = {n.id for n in graph.nodes if n.source_file in paths}
        fwd_adj: dict[str, set[str]] = {}
        rev_adj: dict[str, set[str]] = {}
        for edge in graph.edges:
            fwd_adj.setdefault(edge.source_id, set()).add(edge.target_id)
            rev_adj.setdefault(edge.target_id, set()).add(edge.source_id)
        impacted = _directional_slice(touched, fwd_adj) | _directional_slice(touched, rev_adj)
        if graph is base_report:
            base_impacted = impacted
        touched_ids.update(touched)
        impacted_all.update(impacted)
        nodes_by_id.update({n.id: n for n in graph.nodes})
        for ch in graph.chains:
            if ch.display_node_id in impacted and ch.route_node_id in impacted and touched.intersection(
                [ch.display_node_id, ch.route_node_id, *ch.via_node_ids,
                 *ch.manipulator_node_ids, *ch.truth_table_ids]
            ):
                chains_by_id[ch.id] = ch
    impacted_truth = sorted(
        nid for nid in impacted_all if nid in nodes_by_id and nodes_by_id[nid].tier == "truth"
    )
    impacted_manip = sorted(
        nid for nid in impacted_all if nid in nodes_by_id and nodes_by_id[nid].tier == "manipulate"
    )
    impacted_disp = sorted(
        nid for nid in impacted_all if nid in nodes_by_id and nodes_by_id[nid].tier == "display"
    )

    effective_base_findings: list[BoundaryFinding] | None = (
        base_report.findings if base_report is not None else None
    )
    new_findings = _compute_new_findings(report.findings, effective_base_findings, changed_ranges)
    blocking_new = sum(1 for f in new_findings if f.blocks_gate)

    commits_in_range: list[str] = []
    if base_ref.upper() != "WORKING":
        try:
            log_proc = run_safe_git(
                repo_root,
                "log",
                "--oneline",
                "--first-parent",
                "-n",
                "25",
                f"{changes.base_commit}..HEAD",
                "--",
                text=True,
                check=True,
                timeout=4.0,
            )
            commits_in_range = [
                ln.strip() for ln in str(log_proc.stdout).splitlines() if ln.strip()
            ]
        except (OSError, subprocess.SubprocessError, SafeGitError):
            commits_in_range = []

    head_ids = {node.id for node in report.nodes}
    return DiffBlastRadiusReport(
        target_slug=report.target_slug,
        base_ref=base_ref,
        base_commit=changes.base_commit,
        base_graph_status="unavailable" if base_missing else "available" if base_report else "not_needed",
        base_impacted_node_ids=sorted(base_impacted),
        removed_nodes=[n for n in (base_report.nodes if base_report else [])
                       if n.id in touched_ids and n.id not in head_ids],
        analysis_notes=notes,
        head_commit=report.source_commit,
        commits_in_range=commits_in_range,
        changed_files=changed_files,
        touched_node_ids=sorted(touched_ids),
        impacted_truth_nodes=impacted_truth,
        impacted_manipulator_nodes=impacted_manip,
        impacted_display_nodes=impacted_disp,
        impacted_chains=list(chains_by_id.values()),
        new_findings=new_findings,
        blocking_new_findings=blocking_new,
        diff_verdict=(
            "FAIL"
            if blocking_new > 0
            else "INCOMPLETE"
            if incomplete
            else "PASS"
        ),
    )


def run_target_diff(
    session: Session,
    target: TargetProject,
    report: TruthAtlasReport,
    base_ref: str,
    *,
    pg_dsn: str | None = None,
    redis_dsn: str | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_gate: bool = True,
) -> DiffBlastRadiusReport:
    """Scan the requested base in isolation; never modify or execute the target tree."""
    root = Path(target.repo_path).resolve()
    changes = collect_git_changes(root, base_ref)
    base_report = None
    notes: list[str] = []
    if changes.before or changes.after:
        try:
            with tempfile.TemporaryDirectory(prefix="wythe-base-") as directory:
                base_root = Path(directory)
                materialize_base_tree(root, changes.base_commit, base_root)
                base_target = TargetProject(
                    id=target.id, slug=target.slug, name=target.name, repo_path=directory,
                    stack_profile_slug=target.stack_profile_slug,
                    backend_subdir=target.backend_subdir, frontend_subdir=target.frontend_subdir,
                    legacy_snapshot_relpath=target.legacy_snapshot_relpath,
                )
                base_report = run_target_scan(
                    session,
                    base_target,
                    pg_dsn=pg_dsn,
                    redis_dsn=redis_dsn,
                    strict_gate=strict_gate,
                    persist_snapshot=False,
                    allow_local_plugins=allow_local_plugins,
                    local_plugin_modules=local_plugin_modules,
                    source_commit_override=changes.base_commit,
                ).model_copy(update={"source_commit": changes.base_commit})
        except Exception as exc:  # noqa: BLE001 - incomplete evidence must never become PASS
            notes.append(f"Base graph could not be recovered: {exc}")
    return compute_diff_and_blast_radius(
        root, report, base_ref, base_report=base_report, changes=changes, analysis_notes=notes,
    )


def compare_recorded_snapshots(
    session: Session,
    target_id: int,
    target_slug: str,
    base_snapshot_id: int,
    head_snapshot_id: int,
) -> SnapshotComparisonReport | None:
    """Compare two persisted `ScanSnapshot` rows and return exact multiset structural/finding deltas."""
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

    def _snap_key(f: BoundaryFinding) -> tuple[str, str | None, str, int, str]:
        return (f.rule_code, f.node_id, f.source_file, f.line, f.title)

    base_counts = Counter(_snap_key(f) for f in base_rep.findings)
    head_counts = Counter(_snap_key(f) for f in head_rep.findings)

    new_findings: list[BoundaryFinding] = []
    seen_new: Counter[tuple[str, str | None, str, int, str]] = Counter()
    for hf in head_rep.findings:
        k = _snap_key(hf)
        if seen_new[k] < max(0, head_counts[k] - base_counts[k]):
            seen_new[k] += 1
            new_findings.append(hf)

    resolved_findings: list[BoundaryFinding] = []
    seen_res: Counter[tuple[str, str | None, str, int, str]] = Counter()
    for bf in base_rep.findings:
        k = _snap_key(bf)
        if seen_res[k] < max(0, base_counts[k] - head_counts[k]):
            seen_res[k] += 1
            resolved_findings.append(bf)

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
    *,
    diff: DiffBlastRadiusReport | None = None,
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
                            "uri": _encode_sarif_uri(f.source_file),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, f.line)},
                    }
                }
            ],
        }
        for f in active_findings
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Wythe",
                        "version": __version__,
                        "informationUri": "https://github.com/Euda1mon1a/wythe",
                        "rules": rules_payload,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": ""},
                },
                "automationDetails": {
                    "id": f"wythe/{report.target_slug}/{report.stack_profile}"
                },
                "results": results_payload,
                "properties": {
                    "sourceCommit": report.source_commit,
                    "worktreeDirty": report.worktree_dirty,
                    "dirtyPathCount": report.dirty_path_count,
                    "observationSource": report.observation_source,
                    "gateVerdict": report.gate.verdict,
                    "coverageComplete": report.gate.coverage_complete,
                    "scanNotes": list(report.scan_notes),
                },
            }
        ],
    }
    if diff is not None:
        run = payload["runs"][0]
        run["properties"].update(
            baseCommit=diff.base_commit, baseGraphStatus=diff.base_graph_status,
            diffVerdict=diff.diff_verdict, analysisNotes=diff.analysis_notes,
        )
        incomplete_diff = (
            diff.diff_verdict == "INCOMPLETE"
            or not report.coverage_complete
            or any("coverage is incomplete" in note for note in diff.analysis_notes)
        )
        run["invocations"] = [{
            "executionSuccessful": not incomplete_diff,
            "toolExecutionNotifications": [
                {
                    "level": "error" if diff.diff_verdict == "INCOMPLETE" else "warning",
                    "message": {"text": note},
                }
                for note in diff.analysis_notes if incomplete_diff
            ],
        }]
    elif report.gate.verdict == "INCOMPLETE":
        run = payload["runs"][0]
        notes = list(report.scan_notes) or [
            "Architecture verification is incomplete because one or more stack tiers lacked coverage."
        ]
        run["invocations"] = [{
            "executionSuccessful": False,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": note}}
                for note in notes
            ],
        }]
    return payload
