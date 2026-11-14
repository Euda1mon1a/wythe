"""Git-Portable Governance Bundle Sync (`.wythe/governance.json` <-> DB Truth).

Allows ephemeral CI runners (GitHub Actions, Gitea Actions, GitLab CI) to hydrate rule
policies, custom domain vocabularies, downward ratchets, and audit rulings from version
control into SQLite/PostgreSQL before running `wythe gate`.
"""

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
    TargetProject,
)
from app.schemas.atlas import (
    GovernanceSyncReceipt,
    PortableGovernanceBundle,
    PortableRatchetItem,
    PortableReferenceExemplar,
    PortableRuleOverride,
    PortableRulingItem,
    PortableVocabularyEntry,
)
from app.services.ruling_metadata import (
    pack_ruling_cutover_payload,
    unpack_ruling_cutover_payload,
)


def default_bundle_path(target: TargetProject) -> Path:
    return Path(target.repo_path).resolve() / ".wythe" / "governance.json"


def resolve_existing_bundle_path(repo_root: Path) -> Path:
    primary = repo_root / ".wythe" / "governance.json"
    if primary.is_file():
        return primary
    legacy = repo_root / ".truth-atlas" / "governance.json"
    if legacy.is_file():
        return legacy
    return primary


def build_portable_bundle(
    session: Session, target: TargetProject
) -> PortableGovernanceBundle:
    """Snapshot DB governance state for `target` into a Git-committable schema."""
    rules = session.scalars(select(RulePolicy).order_by(RulePolicy.rule_code)).all()
    vocabs = session.scalars(
        select(PolicyVocabulary).order_by(PolicyVocabulary.domain_pack, PolicyVocabulary.token)
    ).all()
    baselines = (
        session.scalars(
            select(RatchetBaseline)
            .where(RatchetBaseline.target_id == target.id)
            .order_by(RatchetBaseline.rule_code)
        ).all()
        if target.id
        else []
    )
    rulings = (
        session.scalars(
            select(AuditRuling)
            .where(AuditRuling.target_id == target.id)
            .order_by(AuditRuling.id)
        ).all()
        if target.id
        else []
    )

    reference_exemplars: list[PortableReferenceExemplar] = []
    try:
        existing_path = resolve_existing_bundle_path(Path(target.repo_path).resolve())
        if existing_path.is_file():
            existing_bundle = PortableGovernanceBundle.model_validate_json(
                existing_path.read_text(encoding="utf-8")
            )
            reference_exemplars = list(existing_bundle.reference_exemplars)
    except (OSError, ValueError):
        reference_exemplars = []

    return PortableGovernanceBundle(
        schema_version="1.0",
        target_slug=target.slug,
        exported_at=utc_now(),
        rule_overrides=[
            PortableRuleOverride(
                rule_code=r.rule_code,
                severity=r.severity,
                enabled=r.enabled,
                blocks_gate=r.blocks_gate,
                updated_by=r.updated_by,
            )
            for r in rules
        ],
        vocabularies=[
            PortableVocabularyEntry(
                domain_pack=v.domain_pack,
                token=v.token,
                description=v.description,
                is_enabled=v.is_enabled,
            )
            for v in vocabs
        ],
        ratchet_baselines=[
            PortableRatchetItem(
                rule_code=b.rule_code,
                max_allowed_count=b.max_allowed_count,
                recorded_commit=b.recorded_commit,
                recorded_by=b.recorded_by,
                note=b.note,
            )
            for b in baselines
        ],
        audit_rulings=[
            PortableRulingItem(
                node_id=rl.node_id,
                disposition=rl.disposition,
                summary=rl.summary,
                cutover_history=hist,
                store_purpose=sp,
                evidence_scope=scope,
                audited_commit=rl.audited_commit,
                recorded_by=rl.recorded_by,
            )
            for rl in rulings
            for hist, sp, scope in (unpack_ruling_cutover_payload(rl.cutover_history),)
        ],
        reference_exemplars=reference_exemplars,
    )


def export_portable_bundle_to_disk(
    session: Session, target: TargetProject, out_path: Path | None = None
) -> GovernanceSyncReceipt:
    """Write `.truth-atlas/governance.json` into the target repository (or `out_path`)."""
    bundle = build_portable_bundle(session, target)
    dest = (out_path or default_bundle_path(target)).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return GovernanceSyncReceipt(
        target_slug=target.slug,
        direction="export",
        bundle_path=str(dest),
        rules_synced=len(bundle.rule_overrides),
        vocabularies_synced=len(bundle.vocabularies),
        baselines_synced=len(bundle.ratchet_baselines),
        rulings_synced=len(bundle.audit_rulings),
        synced_at=utc_now(),
    )


def sync_portable_bundle_from_disk(
    session: Session,
    target: TargetProject,
    in_path: Path | None = None,
    bundle: PortableGovernanceBundle | None = None,
) -> GovernanceSyncReceipt:
    """Hydrate DB truth from `.wythe/governance.json` (or legacy `.truth-atlas/governance.json`) idempotently."""
    src = (in_path or resolve_existing_bundle_path(Path(target.repo_path).resolve())).resolve()
    if bundle is None:
        if not src.is_file():
            raise FileNotFoundError(f"Governance bundle not found at {src}")
        bundle = PortableGovernanceBundle.model_validate_json(
            src.read_text(encoding="utf-8")
        )

    now = utc_now()
    today = utc_today()

    rules_by_code = {
        r.rule_code: r for r in session.scalars(select(RulePolicy)).all()
    }
    rules_count = 0
    for ro in bundle.rule_overrides:
        row = rules_by_code.get(ro.rule_code)
        if row is not None:
            row.severity = ro.severity
            row.enabled = ro.enabled
            row.blocks_gate = ro.blocks_gate
            row.updated_by = ro.updated_by
            row.updated_at = now
            rules_count += 1

    vocabs_by_key = {
        (v.domain_pack, v.token): v
        for v in session.scalars(select(PolicyVocabulary)).all()
    }
    vocabs_count = 0
    for ve in bundle.vocabularies:
        key = (ve.domain_pack.lower(), ve.token.upper())
        existing_v = vocabs_by_key.get(key)
        if existing_v is not None:
            existing_v.description = ve.description
            existing_v.is_enabled = ve.is_enabled
        else:
            session.add(
                PolicyVocabulary(
                    domain_pack=key[0],
                    token=key[1],
                    description=ve.description,
                    is_enabled=ve.is_enabled,
                    created_by="portable-sync",
                    created_at=now,
                )
            )
        vocabs_count += 1

    baselines_count = 0
    rulings_count = 0
    if target.id:
        existing_b = {
            b.rule_code: b
            for b in session.scalars(
                select(RatchetBaseline).where(RatchetBaseline.target_id == target.id)
            ).all()
        }
        for bi in bundle.ratchet_baselines:
            prev_b = existing_b.get(bi.rule_code)
            if prev_b is None:
                session.add(
                    RatchetBaseline(
                        target_id=target.id,
                        rule_code=bi.rule_code,
                        max_allowed_count=bi.max_allowed_count,
                        recorded_commit=bi.recorded_commit,
                        recorded_by=bi.recorded_by,
                        recorded_at=now,
                        note=bi.note,
                    )
                )
            elif bi.max_allowed_count < prev_b.max_allowed_count:
                prev_b.max_allowed_count = bi.max_allowed_count
                prev_b.recorded_commit = bi.recorded_commit
                prev_b.recorded_by = bi.recorded_by
                prev_b.recorded_at = now
                prev_b.note = bi.note
            baselines_count += 1

        existing_r = {
            (rl.node_id, rl.disposition, rl.audited_commit, rl.cutover_history or "")
            for rl in session.scalars(
                select(AuditRuling).where(AuditRuling.target_id == target.id)
            ).all()
        }
        for ri in bundle.audit_rulings:
            packed_cutover = pack_ruling_cutover_payload(
                ri.cutover_history, ri.store_purpose, ri.evidence_scope
            )
            rkey = (ri.node_id, ri.disposition, ri.audited_commit, packed_cutover or "")
            if rkey not in existing_r:
                existing_r.add(rkey)
                session.add(
                    AuditRuling(
                        target_id=target.id,
                        node_id=ri.node_id,
                        disposition=ri.disposition,
                        summary=ri.summary,
                        cutover_history=packed_cutover,
                        audited_commit=ri.audited_commit,
                        audited_at=today,
                        effective_from=today,
                        recorded_by=ri.recorded_by,
                        created_at=now,
                    )
                )
            rulings_count += 1

    session.commit()
    return GovernanceSyncReceipt(
        target_slug=target.slug,
        direction="import",
        bundle_path=str(src),
        rules_synced=rules_count,
        vocabularies_synced=vocabs_count,
        baselines_synced=baselines_count,
        rulings_synced=rulings_count,
        synced_at=now,
    )
