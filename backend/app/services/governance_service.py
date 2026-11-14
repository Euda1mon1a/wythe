"""Audited domain write-door for targets, rule policies, ratchets, and ownership rulings."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utc_now, utc_today
from app.models import (
    AuditRuling,
    PolicyVocabulary,
    RatchetBaseline,
    RulePolicy,
    StackProfile,
    TargetProject,
)
from app.schemas.atlas import (
    AuditRulingCreate,
    AuditRulingRead,
    PolicyVocabularyCreate,
    PolicyVocabularyRead,
    PolicyVocabularyUpdate,
    RatchetBaselineRead,
    RatchetCaptureRequest,
    RulePolicyRead,
    RulePolicyUpdate,
    StackProfileRead,
    TargetProjectCreate,
    TargetProjectRead,
    TruthAtlasReport,
)
from app.services.ruling_metadata import (
    pack_ruling_cutover_payload,
    unpack_ruling_cutover_payload,
)


def list_stack_profiles(session: Session) -> list[StackProfileRead]:
    rows = session.scalars(select(StackProfile).order_by(StackProfile.id)).all()
    return [
        StackProfileRead(
            slug=r.slug,
            label=r.label,
            truth_adapter=r.truth_adapter,
            manipulator_adapter=r.manipulator_adapter,
            display_adapter=r.display_adapter,
            implementation_status=r.implementation_status,
            is_enabled=r.is_enabled,
            description=r.description,
        )
        for r in rows
    ]


def list_targets(session: Session) -> list[TargetProjectRead]:
    rows = session.scalars(
        select(TargetProject).where(TargetProject.is_active.is_(True)).order_by(TargetProject.slug)
    ).all()
    return [_to_target_read(r) for r in rows]


def get_target_by_slug(session: Session, slug: str) -> TargetProject | None:
    found = session.scalar(select(TargetProject).where(TargetProject.slug == slug))
    if found is None and slug == "truth-atlas":
        return session.scalar(select(TargetProject).where(TargetProject.slug == "wythe"))
    return found


def register_target(session: Session, payload: TargetProjectCreate) -> TargetProjectRead:
    resolved_repo = Path(payload.repo_path).expanduser().resolve()
    if not resolved_repo.is_dir():
        raise ValueError(f"Repository path does not exist: {resolved_repo}")
    effective_slug = (
        "fastapi-sqlalchemy-nextjs"
        if payload.stack_profile_slug.endswith("-native")
        else payload.stack_profile_slug
    )
    profile = session.scalar(
        select(StackProfile).where(StackProfile.slug == effective_slug)
    )
    if profile is None or not profile.is_enabled:
        raise ValueError(f"Stack profile '{payload.stack_profile_slug}' is not enabled")

    existing = get_target_by_slug(session, payload.slug)
    now = utc_now()
    if existing is not None:
        existing.name = payload.name
        existing.repo_path = str(resolved_repo)
        existing.stack_profile_slug = effective_slug
        existing.backend_subdir = payload.backend_subdir
        existing.frontend_subdir = payload.frontend_subdir
        existing.legacy_snapshot_relpath = payload.legacy_snapshot_relpath
        existing.description = payload.description
        existing.is_active = True
        existing.updated_at = now
        session.commit()
        return _to_target_read(existing)

    created = TargetProject(
        slug=payload.slug,
        name=payload.name,
        repo_path=str(resolved_repo),
        stack_profile_slug=effective_slug,
        backend_subdir=payload.backend_subdir,
        frontend_subdir=payload.frontend_subdir,
        legacy_snapshot_relpath=payload.legacy_snapshot_relpath,
        description=payload.description,
        is_active=True,
        created_by=payload.created_by,
        created_at=now,
        updated_at=now,
    )
    session.add(created)
    session.commit()
    session.refresh(created)
    return _to_target_read(created)


def list_rule_policies(session: Session) -> list[RulePolicyRead]:
    rows = session.scalars(select(RulePolicy).order_by(RulePolicy.rule_code)).all()
    return [_to_rule_read(r) for r in rows]


def update_rule_policy(
    session: Session,
    rule_code: str,
    payload: RulePolicyUpdate,
) -> RulePolicyRead:
    row = session.scalar(select(RulePolicy).where(RulePolicy.rule_code == rule_code))
    if row is None:
        raise KeyError(f"Unknown rule policy: {rule_code}")
    if payload.severity is not None:
        row.severity = payload.severity
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.blocks_gate is not None:
        row.blocks_gate = payload.blocks_gate
    row.updated_by = payload.updated_by
    row.updated_at = utc_now()
    session.commit()
    session.refresh(row)
    return _to_rule_read(row)


def list_rulings(session: Session, target_id: int) -> list[AuditRulingRead]:
    rows = session.scalars(
        select(AuditRuling)
        .where(AuditRuling.target_id == target_id)
        .order_by(AuditRuling.created_at.desc())
    ).all()
    return [_to_ruling_read(r) for r in rows]


def record_audit_ruling(
    session: Session,
    target_id: int,
    audited_commit: str,
    payload: AuditRulingCreate,
) -> AuditRulingRead:
    now = utc_now()
    today = utc_today()
    ruling = AuditRuling(
        target_id=target_id,
        node_id=payload.node_id,
        disposition=payload.disposition,
        summary=payload.summary,
        cutover_history=pack_ruling_cutover_payload(
            payload.cutover_history,
            payload.store_purpose,
            payload.evidence_scope,
        ),
        audited_commit=audited_commit,
        audited_at=today,
        effective_from=today,
        recorded_by=payload.recorded_by,
        created_at=now,
    )
    session.add(ruling)
    session.commit()
    session.refresh(ruling)
    return _to_ruling_read(ruling)


def list_ratchet_baselines(session: Session, target_id: int) -> list[RatchetBaselineRead]:
    rows = session.scalars(
        select(RatchetBaseline)
        .where(RatchetBaseline.target_id == target_id)
        .order_by(RatchetBaseline.rule_code)
    ).all()
    return [
        RatchetBaselineRead(
            rule_code=r.rule_code,
            max_allowed_count=r.max_allowed_count,
            recorded_commit=r.recorded_commit,
            recorded_by=r.recorded_by,
            recorded_at=r.recorded_at,
            note=r.note,
        )
        for r in rows
    ]


def capture_ratchet_baselines(
    session: Session,
    target_id: int,
    report: TruthAtlasReport,
    payload: RatchetCaptureRequest,
) -> list[RatchetBaselineRead]:
    """Capture downward-only ratchet ceilings per rule (existing ceilings never increase)."""
    existing = {
        r.rule_code: r
        for r in session.scalars(
            select(RatchetBaseline).where(RatchetBaseline.target_id == target_id)
        ).all()
    }
    now = utc_now()
    for gate_row in report.gate.rule_counts:
        prev = existing.get(gate_row.rule_code)
        if prev is None:
            session.add(
                RatchetBaseline(
                    target_id=target_id,
                    rule_code=gate_row.rule_code,
                    max_allowed_count=gate_row.observed_count,
                    recorded_commit=report.source_commit,
                    recorded_by=payload.recorded_by,
                    recorded_at=now,
                    note=payload.note,
                )
            )
        elif gate_row.observed_count < prev.max_allowed_count:
            prev.max_allowed_count = gate_row.observed_count
            prev.recorded_commit = report.source_commit
            prev.recorded_by = payload.recorded_by
            prev.recorded_at = now
            prev.note = payload.note
    session.commit()
    return list_ratchet_baselines(session, target_id)


def list_policy_vocabularies(session: Session) -> list[PolicyVocabularyRead]:
    rows = session.scalars(
        select(PolicyVocabulary).order_by(PolicyVocabulary.domain_pack, PolicyVocabulary.token)
    ).all()
    return [_to_vocab_read(r) for r in rows]


def create_policy_vocabulary(
    session: Session, payload: PolicyVocabularyCreate
) -> PolicyVocabularyRead:
    norm_pack = payload.domain_pack.strip().lower()
    norm_token = payload.token.strip().upper()
    existing = session.scalar(
        select(PolicyVocabulary).where(
            PolicyVocabulary.domain_pack == norm_pack,
            PolicyVocabulary.token == norm_token,
        )
    )
    if existing is not None:
        existing.description = payload.description
        existing.is_enabled = payload.is_enabled
        session.commit()
        session.refresh(existing)
        return _to_vocab_read(existing)

    created = PolicyVocabulary(
        domain_pack=norm_pack,
        token=norm_token,
        description=payload.description,
        is_enabled=payload.is_enabled,
        created_by=payload.created_by,
        created_at=utc_now(),
    )
    session.add(created)
    session.commit()
    session.refresh(created)
    return _to_vocab_read(created)


def update_policy_vocabulary(
    session: Session, vocab_id: int, payload: PolicyVocabularyUpdate
) -> PolicyVocabularyRead:
    row = session.get(PolicyVocabulary, vocab_id)
    if row is None:
        raise KeyError(f"Unknown policy vocabulary id: {vocab_id}")
    if payload.description is not None:
        row.description = payload.description
    if payload.is_enabled is not None:
        row.is_enabled = payload.is_enabled
    session.commit()
    session.refresh(row)
    return _to_vocab_read(row)


def _to_target_read(r: TargetProject) -> TargetProjectRead:
    return TargetProjectRead(
        id=r.id,
        slug=r.slug,
        name=r.name,
        repo_path=r.repo_path,
        stack_profile_slug=r.stack_profile_slug,
        backend_subdir=r.backend_subdir,
        frontend_subdir=r.frontend_subdir,
        legacy_snapshot_relpath=r.legacy_snapshot_relpath,
        description=r.description,
        is_active=r.is_active,
    )


def _to_rule_read(r: RulePolicy) -> RulePolicyRead:
    return RulePolicyRead(
        rule_code=r.rule_code,
        tier=r.tier,
        category=r.category,
        title=r.title,
        rationale=r.rationale,
        severity=r.severity,
        enabled=r.enabled,
        blocks_gate=r.blocks_gate,
        effective_from=r.effective_from,
        effective_until=r.effective_until,
        updated_by=r.updated_by,
        updated_at=r.updated_at,
    )


def _to_ruling_read(r: AuditRuling) -> AuditRulingRead:
    clean_history, store_purpose, evidence_scope = unpack_ruling_cutover_payload(r.cutover_history)
    return AuditRulingRead(
        id=r.id,
        target_id=r.target_id,
        node_id=r.node_id,
        disposition=r.disposition,
        summary=r.summary,
        cutover_history=clean_history,
        store_purpose=store_purpose,
        evidence_scope=evidence_scope,
        audited_commit=r.audited_commit,
        audited_at=r.audited_at,
        effective_from=r.effective_from,
        effective_until=r.effective_until,
        recorded_by=r.recorded_by,
        created_at=r.created_at,
    )


def _to_vocab_read(r: PolicyVocabulary) -> PolicyVocabularyRead:
    return PolicyVocabularyRead(
        id=r.id,
        domain_pack=r.domain_pack,
        token=r.token,
        description=r.description,
        is_enabled=r.is_enabled,
        created_by=r.created_by,
        created_at=r.created_at,
    )
