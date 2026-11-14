"""Gate evaluation and snapshot query service backed by persisted RulePolicy and RatchetBaseline rows."""

from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.adapters.base import RawCandidateFinding
from app.core.clock import utc_now, utc_today
from app.models import RatchetBaseline, RulePolicy, ScanSnapshot
from app.schemas.atlas import (
    BoundaryFinding,
    GateEvaluation,
    RuleGateRow,
    ScanSnapshotSummary,
)


def load_effective_rules(session: Session) -> dict[str, RulePolicy]:
    """Load RulePolicy rows from database truth, honoring effective date windows."""
    today = utc_today()
    rows = session.scalars(select(RulePolicy).order_by(RulePolicy.rule_code)).all()
    active: dict[str, RulePolicy] = {}
    for row in rows:
        if row.effective_from > today:
            continue
        if row.effective_until is not None and row.effective_until < today:
            continue
        active[row.rule_code] = row
    return active


def evaluate_findings_and_gate(
    session: Session,
    raw_findings: list[RawCandidateFinding],
    target_id: int | None = None,
    strict: bool = False,
) -> tuple[list[BoundaryFinding], GateEvaluation]:
    """Bind candidate findings to persisted RulePolicy rows and compute gate verdict."""
    rules_by_code = load_effective_rules(session)
    baselines: dict[str, int] = {}
    if target_id is not None and not strict:
        b_rows = session.scalars(
            select(RatchetBaseline).where(RatchetBaseline.target_id == target_id)
        ).all()
        baselines = {b.rule_code: b.max_allowed_count for b in b_rows}

    materialized: list[BoundaryFinding] = []
    counts_by_rule: dict[str, int] = {code: 0 for code in rules_by_code}

    for idx, cand in enumerate(raw_findings, start=1):
        policy = rules_by_code.get(cand.rule_code)
        if policy is None or not policy.enabled:
            continue
        counts_by_rule[cand.rule_code] = counts_by_rule.get(cand.rule_code, 0) + 1
        materialized.append(
            BoundaryFinding(
                id=f"f:{cand.rule_code}:{idx}",
                rule_code=cand.rule_code,
                tier=policy.tier,  # type: ignore[arg-type]
                severity=policy.severity,
                blocks_gate=policy.blocks_gate,
                node_id=cand.node_id,
                target_node_id=cand.target_node_id,
                source_file=cand.source_file,
                line=cand.line,
                title=cand.title,
                detail=cand.detail,
                remediation=cand.remediation,
            )
        )

    use_ratchet = bool(baselines) and not strict
    mode = "ratchet" if use_ratchet else "strict"
    rule_rows: list[RuleGateRow] = []
    exceeded: list[str] = []
    blocking_total = 0

    for code, policy in sorted(rules_by_code.items()):
        obs = counts_by_rule.get(code, 0)
        b_max = baselines.get(code) if use_ratchet else None
        if not policy.enabled:
            row_status = "disabled"
        elif not policy.blocks_gate or obs == 0:
            row_status = "pass"
        else:
            blocking_total += obs
            if use_ratchet and b_max is not None and obs <= b_max:
                row_status = "ratcheted"
            else:
                row_status = "exceeded"
                exceeded.append(code)

        rule_rows.append(
            RuleGateRow(
                rule_code=code,
                tier=policy.tier,  # type: ignore[arg-type]
                title=policy.title,
                severity=policy.severity,
                enabled=policy.enabled,
                blocks_gate=policy.blocks_gate,
                observed_count=obs,
                baseline_max=b_max,
                status=row_status,  # type: ignore[arg-type]
            )
        )

    if exceeded:
        verdict = "FAIL"
    elif blocking_total > 0 and use_ratchet:
        verdict = "RATCHET_PASS"
    else:
        verdict = "PASS"

    return materialized, GateEvaluation(
        verdict=verdict,  # type: ignore[arg-type]
        mode=mode,  # type: ignore[arg-type]
        blocking_violations=blocking_total,
        ratchet_exceeded_rules=exceeded,
        rule_counts=rule_rows,
        evaluated_at=utc_now(),
    )


def list_recent_snapshots(
    session: Session,
    target_id: int,
    limit: int = 10,
) -> list[ScanSnapshotSummary]:
    """Read back immutable scan receipt summaries for a target project."""
    rows = session.scalars(
        select(ScanSnapshot)
        .where(ScanSnapshot.target_id == target_id)
        .order_by(desc(ScanSnapshot.observed_at))
        .limit(limit)
    ).all()
    return [
        ScanSnapshotSummary(
            id=r.id,
            source_commit=r.source_commit,
            observation_source=r.observation_source,
            observed_at=r.observed_at,
            valid_until=r.valid_until,
            content_digest=r.content_digest,
            truth_node_count=r.truth_node_count,
            manipulator_node_count=r.manipulator_node_count,
            display_node_count=r.display_node_count,
            verified_edge_count=r.verified_edge_count,
            blocking_finding_count=r.blocking_finding_count,
            warning_finding_count=r.warning_finding_count,
        )
        for r in rows
    ]
