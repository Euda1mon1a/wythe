"""Database-is-truth proofs: policy behavior changes via DB rows without editing Python."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utc_today
from app.models import RulePolicy
from app.schemas.atlas import (
    AuditRulingCreate,
    BoundaryFinding,
    RatchetCaptureRequest,
    RulePolicyUpdate,
    TargetProjectCreate,
)
from app.services.gate_service import evaluate_findings_and_gate
from app.services.governance_service import (
    capture_ratchet_baselines,
    get_target_by_slug,
    record_audit_ruling,
    register_target,
    update_rule_policy,
)
from app.services.scanner_service import run_target_scan


def _create_policy_violating_repo(root: Path) -> Path:
    repo = root / "sample_violating_repo"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE work_items (id INTEGER PRIMARY KEY, label TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models" / "item.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class WorkItem(Base):\n"
        "    __tablename__ = 'work_items'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    label: Mapped[str]\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "item_service.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models.item import WorkItem\n"
        "MAX_WORKLOAD_HOURS = 80\n"
        "def list_items(db):\n"
        "    return db.scalars(select(WorkItem)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.item_service import list_items\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def get_items():\n"
        "    return list_items(None)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function Page() { return <div>Items</div>; }\n",
        encoding="utf-8",
    )
    return repo


def test_db_rule_policy_row_controls_gate_without_python_edits(
    db_session: Session, tmp_path: Path
) -> None:
    """Prove postgres-domain-truth: changing DB policy rows flips gate FAIL -> PASS."""
    repo = _create_policy_violating_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(
            slug="violating-sample",
            name="Violating Sample",
            repo_path=str(repo),
        ),
    )
    target = get_target_by_slug(db_session, "violating-sample")
    assert target is not None

    # State 1: Default seeded DB policy marks MANIP-001 as enabled + blocks_gate=True.
    first_report = run_target_scan(db_session, target, strict_gate=True)
    assert first_report.gate.verdict == "FAIL"
    assert any(f.rule_code == "MANIP-001" for f in first_report.findings)

    # State 2: Mutate ONLY the RulePolicy row in the database (blocks_gate=False).
    update_rule_policy(
        db_session,
        "MANIP-001",
        RulePolicyUpdate(blocks_gate=False, severity="warning", updated_by="test-operator"),
    )
    second_report = run_target_scan(db_session, target, strict_gate=True)
    assert second_report.gate.verdict == "PASS"
    assert second_report.gate.blocking_violations == 0

    # State 3: Expire the RulePolicy row via temporal effective_until column in DB.
    rule_row = db_session.scalar(select(RulePolicy).where(RulePolicy.rule_code == "MANIP-001"))
    assert rule_row is not None
    rule_row.effective_until = utc_today() - timedelta(days=1)
    db_session.commit()

    third_report = run_target_scan(db_session, target, strict_gate=True)
    assert all(f.rule_code != "MANIP-001" for f in third_report.findings)


def test_ratchet_baseline_is_strictly_downward_only(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify ratchet ceilings pass at or below baseline, fail above, and never loosen upward."""
    repo = _create_policy_violating_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(slug="ratchet-sample", name="Ratchet Sample", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "ratchet-sample")
    assert target is not None

    initial = run_target_scan(db_session, target, strict_gate=False)
    assert initial.gate.verdict == "FAIL"

    # Capture current violation count (1 MANIP-001) as ratchet ceiling.
    baselines = capture_ratchet_baselines(
        db_session,
        target.id,
        initial,
        RatchetCaptureRequest(recorded_by="test-operator", note="Initial baseline"),
    )
    manip_baseline = next(b for b in baselines if b.rule_code == "MANIP-001")
    assert manip_baseline.max_allowed_count == 1

    # Re-scan in ratchet mode: 1 <= 1 -> RATCHET_PASS.
    ratcheted = run_target_scan(db_session, target, strict_gate=False)
    assert ratcheted.gate.verdict == "RATCHET_PASS"

    # Simulate 2 MANIP-001 findings against the ceiling of 1 -> FAIL, and capture refuses to raise ceiling!
    synthetic_two = [
        BoundaryFinding(
            id=f"f:{idx}",
            rule_code="MANIP-001",
            tier="manipulate",
            severity="blocking",
            blocks_gate=True,
            source_file="backend/app/services/item_service.py",
            line=idx,
            title="Policy constant",
            detail="Test",
            remediation="Move to DB",
        )
        for idx in (1, 2)
    ]
    _, exceeded_gate = evaluate_findings_and_gate(
        db_session, synthetic_two, target_id=target.id, strict=False
    )
    assert exceeded_gate.verdict == "FAIL"
    assert "MANIP-001" in exceeded_gate.ratchet_exceeded_rules

    ratcheted_copy = ratcheted.model_copy(update={"gate": exceeded_gate})
    after_higher_capture = capture_ratchet_baselines(
        db_session,
        target.id,
        ratcheted_copy,
        RatchetCaptureRequest(recorded_by="test-operator", note="Attempt upward relaxation"),
    )
    still_one = next(b for b in after_higher_capture if b.rule_code == "MANIP-001")
    assert still_one.max_allowed_count == 1


def test_audit_ruling_separates_cutover_history_from_clean_status(
    db_session: Session, tmp_path: Path
) -> None:
    """Completed cutovers stay status='clean' while cutover_history preserves provenance."""
    repo = _create_policy_violating_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(slug="ruling-sample", name="Ruling Sample", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "ruling-sample")
    assert target is not None

    before = run_target_scan(db_session, target, strict_gate=False)
    svc_node = next(n for n in before.nodes if "item_service.py" in n.source_file)
    assert svc_node.status == "policy_in_code"

    record_audit_ruling(
        db_session,
        target.id,
        audited_commit="abc1234",
        payload=AuditRulingCreate(
            node_id=svc_node.id,
            disposition="accepted_clean",
            summary="Verified mechanism envelope; thresholds moved to DB.",
            cutover_history="Migrated from Python dictionary to Postgres table in 2026-11.",
            recorded_by="test-operator",
        ),
    )

    after = run_target_scan(db_session, target, strict_gate=False)
    updated_node = next(n for n in after.nodes if n.id == svc_node.id)
    assert updated_node.status == "clean"
    assert updated_node.cutover_history == "Migrated from Python dictionary to Postgres table in 2026-11."
    assert "[accepted_clean]" in (updated_node.ruling_summary or "")
