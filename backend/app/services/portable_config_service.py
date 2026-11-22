"""Git-Portable Governance Bundle Sync (`.wythe/governance.json` <-> Per-Target DB Truth).

Scopes imported rule & vocabulary overrides strictly per `target_id` so an untrusted
repository's `.wythe/governance.json` can never disable rules or vocabularies for any
other target, enforces `O_NOFOLLOW` + symlink containment on both read and write, and
supports reading governance bundles from a trusted Git ref (`--trusted-config-ref`).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import weakref
from pathlib import Path
from typing import Any

from sqlalchemy import Column, Integer, MetaData, String, Table, Text, delete, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.clock import utc_now, utc_today
from app.core.safe_git import SafeGitError, run_safe_git
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

_MAX_GOV_BYTES = 2_000_000
_TARGET_GOV_META = MetaData()
_TARGET_GOV_TABLE = Table(
    "target_governance_bundles",
    _TARGET_GOV_META,
    Column("target_id", Integer, primary_key=True),
    Column("rule_overrides_json", Text, nullable=False),
    Column("vocabularies_json", Text, nullable=False),
    Column("allowlist_json", Text, nullable=False, server_default="[]"),
    Column("reference_exemplars_json", Text, nullable=False, server_default="[]"),
    Column("updated_at", String(64), nullable=False),
)
_INITIALIZED_ENGINES: weakref.WeakSet[Any] = weakref.WeakSet()


def _ensure_target_gov_table(session: Session) -> None:
    bind = session.get_bind()
    _TARGET_GOV_META.create_all(bind=bind, checkfirst=True)
    engine_obj = getattr(bind, "engine", bind)
    if engine_obj in _INITIALIZED_ENGINES:
        return
    existing_cols = {
        col["name"] for col in inspect(bind).get_columns("target_governance_bundles")
    }
    if "allowlist_json" not in existing_cols:
        session.execute(
            text(
                "ALTER TABLE target_governance_bundles "
                "ADD COLUMN allowlist_json TEXT NOT NULL DEFAULT '[]'"
            )
        )
    if "reference_exemplars_json" not in existing_cols:
        session.execute(
            text(
                "ALTER TABLE target_governance_bundles "
                "ADD COLUMN reference_exemplars_json TEXT NOT NULL DEFAULT '[]'"
            )
        )
    _INITIALIZED_ENGINES.add(engine_obj)


def load_target_governance_overrides(
    session: Session,
    target_id: int | None,
) -> tuple[dict[str, PortableRuleOverride], list[PortableVocabularyEntry]]:
    """Return `(rule_overrides_by_code, vocabularies)` scoped strictly to `target_id`."""
    if not target_id or target_id <= 0:
        return {}, []
    try:
        _ensure_target_gov_table(session)
        row = session.execute(
            select(
                _TARGET_GOV_TABLE.c.rule_overrides_json,
                _TARGET_GOV_TABLE.c.vocabularies_json,
            ).where(_TARGET_GOV_TABLE.c.target_id == int(target_id))
        ).first()
    except SQLAlchemyError:
        return {}, []
    if row is None:
        return {}, []
    try:
        raw_rules = json.loads(str(row[0] or "[]"))
        raw_vocabs = json.loads(str(row[1] or "[]"))
        rule_map = {
            ro.rule_code: ro
            for item in raw_rules
            if isinstance(item, dict)
            for ro in (PortableRuleOverride.model_validate(item),)
        }
        vocab_list = [
            PortableVocabularyEntry.model_validate(item)
            for item in raw_vocabs
            if isinstance(item, dict)
        ]
        return rule_map, vocab_list
    except ValueError:
        return {}, []


def _load_target_governance_extras(
    session: Session,
    target_id: int | None,
) -> tuple[list[str], list[PortableReferenceExemplar]]:
    if not target_id or target_id <= 0:
        return [], []
    try:
        _ensure_target_gov_table(session)
        row = session.execute(
            select(
                _TARGET_GOV_TABLE.c.allowlist_json,
                _TARGET_GOV_TABLE.c.reference_exemplars_json,
            ).where(_TARGET_GOV_TABLE.c.target_id == int(target_id))
        ).first()
    except SQLAlchemyError:
        return [], []
    if row is None:
        return [], []
    try:
        raw_allow = json.loads(str(row[0] or "[]"))
        raw_ex = json.loads(str(row[1] or "[]"))
        allowlist = [
            str(item).strip().lstrip("./")
            for item in raw_allow
            if isinstance(item, str) and item.strip()
        ]
        exemplars = [
            PortableReferenceExemplar.model_validate(item)
            for item in raw_ex
            if isinstance(item, dict)
        ]
        return allowlist, exemplars
    except ValueError:
        return [], []


def load_target_governance_allowlist(
    session: Session,
    target_id: int | None,
) -> set[str]:
    """Return DB-synced fabricated fallback allowlist & fixture exemplar pointers for `target_id`."""
    allowlist, exemplars = _load_target_governance_extras(session, target_id)
    out = {item for item in allowlist if item}
    for ex in exemplars:
        text_blob = f"{ex.title} {ex.rationale}".lower()
        ptr = str(ex.pointer or "").strip().lstrip("./")
        if ptr and any(tok in text_blob for tok in ("demo", "fixture", "disp-009", "disp-010")):
            out.add(ptr)
    return out


def _save_target_governance_overrides(
    session: Session,
    target_id: int,
    rule_overrides: list[PortableRuleOverride],
    vocabularies: list[PortableVocabularyEntry],
    now_iso: str,
    *,
    fabricated_fallback_allowlist: list[str] = (),
    reference_exemplars: list[PortableReferenceExemplar] = (),
) -> None:
    _ensure_target_gov_table(session)
    rules_json = json.dumps([ro.model_dump(mode="json") for ro in rule_overrides])
    vocabs_json = json.dumps([ve.model_dump(mode="json") for ve in vocabularies])
    allowlist_json = json.dumps(
        [str(item).strip().lstrip("./") for item in fabricated_fallback_allowlist if str(item).strip()]
    )
    exemplars_json = json.dumps(
        [ex.model_dump(mode="json") for ex in reference_exemplars]
    )
    existing = session.execute(
        select(_TARGET_GOV_TABLE.c.target_id).where(_TARGET_GOV_TABLE.c.target_id == int(target_id))
    ).first()
    if existing is None:
        session.execute(
            _TARGET_GOV_TABLE.insert().values(
                target_id=int(target_id),
                rule_overrides_json=rules_json,
                vocabularies_json=vocabs_json,
                allowlist_json=allowlist_json,
                reference_exemplars_json=exemplars_json,
                updated_at=now_iso,
            )
        )
    else:
        session.execute(
            _TARGET_GOV_TABLE.update()
            .where(_TARGET_GOV_TABLE.c.target_id == int(target_id))
            .values(
                rule_overrides_json=rules_json,
                vocabularies_json=vocabs_json,
                allowlist_json=allowlist_json,
                reference_exemplars_json=exemplars_json,
                updated_at=now_iso,
            )
        )


def _reject_symlink_walk(path: Path, *, repo_root: Path | None = None) -> Path:
    expanded = path.expanduser()
    if "\x00" in str(expanded):
        raise ValueError("Null byte in governance bundle path is forbidden.")
    if repo_root is not None:
        if repo_root.is_symlink():
            raise ValueError(f"Refusing symlinked repository root: {repo_root}")
        clean_root = repo_root.resolve()
        if not expanded.is_absolute():
            rel_parts = expanded.parts
        else:
            # Walk components strictly beneath `clean_root` if inside `clean_root`
            try:
                rel_parts = expanded.relative_to(clean_root).parts
            except ValueError:
                try:
                    rel_parts = expanded.relative_to(repo_root).parts
                except ValueError as exc:
                    raise ValueError(
                        f"Governance bundle path '{path}' escapes repository root '{clean_root}'."
                    ) from exc
        cur = clean_root
        for part in rel_parts:
            if part in ("", "."):
                continue
            if part == "..":
                raise ValueError("Parent traversal ('..') is forbidden in governance bundle path.")
            cur = cur / part
            if cur.is_symlink():
                raise ValueError(f"Refusing symlink component in governance path: {cur}")
        return cur

    # Custom external `--in` / `--out` path: reject `..` and symlink leaf/ancestors below parent
    if ".." in expanded.parts:
        raise ValueError("Parent traversal ('..') is forbidden in governance bundle path.")
    if expanded.is_symlink():
        raise ValueError(f"Refusing symlink governance file: {expanded}")
    if expanded.parent.is_symlink():
        raise ValueError(f"Refusing symlink parent directory for governance file: {expanded.parent}")
    resolved_parent = expanded.parent.resolve()
    cand = resolved_parent / expanded.name
    if cand.is_symlink():
        raise ValueError(f"Refusing symlink governance file: {cand}")
    return cand


def _read_regular_nofollow_text(safe_path: Path) -> str:
    if safe_path.is_symlink():
        raise ValueError(f"Refusing symlink governance bundle: {safe_path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(safe_path, flags)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Governance bundle must be a regular file: {safe_path}")
        if st.st_size > _MAX_GOV_BYTES:
            raise ValueError("Governance bundle exceeds 2 MB limit.")
        raw = fh.read(_MAX_GOV_BYTES + 1)
    if len(raw) > _MAX_GOV_BYTES:
        raise ValueError("Governance bundle exceeds 2 MB limit.")
    return raw.decode("utf-8")


def _write_regular_nofollow_text(safe_path: Path, text: str) -> None:
    if safe_path.parent.is_symlink():
        raise ValueError(f"Refusing symlink directory in governance export: {safe_path.parent}")
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    if safe_path.is_symlink():
        raise ValueError(f"Refusing to overwrite symlink governance target: {safe_path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(safe_path, flags, 0o644)
    with os.fdopen(fd, "wb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Refusing non-regular governance export target: {safe_path}")
        fh.write(text.encode("utf-8"))


def default_bundle_path(target: TargetProject) -> Path:
    return Path(target.repo_path).resolve() / ".wythe" / "governance.json"


def resolve_existing_bundle_path(repo_root: Path) -> Path:
    primary = repo_root / ".wythe" / "governance.json"
    if not primary.is_symlink() and not primary.parent.is_symlink() and primary.is_file():
        return primary
    legacy = repo_root / ".truth-atlas" / "governance.json"
    if not legacy.is_symlink() and not legacy.parent.is_symlink() and legacy.is_file():
        return legacy
    return primary


def build_portable_bundle(
    session: Session, target: TargetProject
) -> PortableGovernanceBundle:
    """Snapshot per-target + catalog governance state for `target` into a Git-committable schema."""
    rules = session.scalars(select(RulePolicy).order_by(RulePolicy.rule_code)).all()
    vocabs = session.scalars(
        select(PolicyVocabulary).order_by(PolicyVocabulary.domain_pack, PolicyVocabulary.token)
    ).all()
    target_rule_ov, target_vocab_ov = load_target_governance_overrides(session, target.id or None)

    merged_vocabs: dict[tuple[str, str], PortableVocabularyEntry] = {
        (v.domain_pack, v.token): PortableVocabularyEntry(
            domain_pack=v.domain_pack,
            token=v.token,
            description=v.description,
            is_enabled=v.is_enabled,
        )
        for v in vocabs
    }
    for tv in target_vocab_ov:
        merged_vocabs[(tv.domain_pack.lower(), tv.token.upper())] = PortableVocabularyEntry(
            domain_pack=tv.domain_pack.lower(),
            token=tv.token.upper(),
            description=tv.description,
            is_enabled=tv.is_enabled,
        )

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

    db_allowlist, db_exemplars = _load_target_governance_extras(session, target.id or None)
    reference_exemplars: list[PortableReferenceExemplar] = list(db_exemplars)
    fabricated_allowlist: list[str] = list(db_allowlist)
    if not reference_exemplars and not fabricated_allowlist:
        try:
            repo_root = Path(target.repo_path).resolve()
            existing_cand = resolve_existing_bundle_path(repo_root)
            safe_existing = _reject_symlink_walk(existing_cand, repo_root=repo_root)
            if safe_existing.is_file():
                existing_bundle = PortableGovernanceBundle.model_validate_json(
                    _read_regular_nofollow_text(safe_existing)
                )
                reference_exemplars = list(existing_bundle.reference_exemplars)
                fabricated_allowlist = list(
                    getattr(existing_bundle, "fabricated_fallback_allowlist", [])
                )
        except (OSError, ValueError):
            reference_exemplars = []
            fabricated_allowlist = []

    return PortableGovernanceBundle(
        schema_version="1.0",
        target_slug=target.slug,
        exported_at=utc_now(),
        rule_overrides=[
            target_rule_ov.get(
                r.rule_code,
                PortableRuleOverride(
                    rule_code=r.rule_code,
                    severity=r.severity,
                    enabled=r.enabled,
                    blocks_gate=r.blocks_gate,
                    updated_by=r.updated_by,
                ),
            )
            for r in rules
        ],
        vocabularies=[merged_vocabs[k] for k in sorted(merged_vocabs)],
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
                effective_until=rl.effective_until,
                recorded_by=rl.recorded_by,
            )
            for rl in rulings
            for hist, sp, scope in (unpack_ruling_cutover_payload(rl.cutover_history),)
        ],
        reference_exemplars=reference_exemplars,
        fabricated_fallback_allowlist=fabricated_allowlist,
    )


def export_portable_bundle_to_disk(
    session: Session, target: TargetProject, out_path: Path | None = None
) -> GovernanceSyncReceipt:
    """Write `.wythe/governance.json` safely with `O_NOFOLLOW` (refusing symlinks)."""
    bundle = build_portable_bundle(session, target)
    repo_root = Path(target.repo_path).resolve()
    if out_path is None:
        safe_dest = _reject_symlink_walk(repo_root / ".wythe" / "governance.json", repo_root=repo_root)
    else:
        safe_dest = _reject_symlink_walk(out_path)
    _write_regular_nofollow_text(safe_dest, bundle.model_dump_json(indent=2) + "\n")
    return GovernanceSyncReceipt(
        target_slug=target.slug,
        direction="export",
        bundle_path=str(safe_dest),
        rules_synced=len(bundle.rule_overrides),
        vocabularies_synced=len(bundle.vocabularies),
        baselines_synced=len(bundle.ratchet_baselines),
        rulings_synced=len(bundle.audit_rulings),
        synced_at=utc_now(),
    )


def _read_bundle_from_trusted_git_ref(repo_root: Path, git_ref: str) -> tuple[PortableGovernanceBundle, str] | None:
    commit_proc = run_safe_git(
        repo_root, "rev-parse", "--verify", "--end-of-options", f"{git_ref}^{{commit}}", text=True
    )
    commit_sha = str(commit_proc.stdout).strip()
    prefix_proc = run_safe_git(repo_root, "rev-parse", "--show-prefix", text=True)
    prefix = str(prefix_proc.stdout).strip()
    for rel in (".wythe/governance.json", ".truth-atlas/governance.json"):
        git_obj = f"{commit_sha}:{prefix}{rel}"
        try:
            blob_proc = run_safe_git(repo_root, "show", git_obj, text=False, check=True)
            raw_bytes = bytes(blob_proc.stdout)
            if len(raw_bytes) > _MAX_GOV_BYTES:
                raise ValueError(f"Trusted governance bundle '{git_obj}' exceeds 2 MB limit.")
            parsed = PortableGovernanceBundle.model_validate_json(raw_bytes.decode("utf-8"))
            return parsed, f"git:{git_obj}"
        except (SafeGitError, subprocess.TimeoutExpired):
            raise
        except (OSError, subprocess.CalledProcessError):
            continue
    return None


def sync_portable_bundle_from_disk(
    session: Session,
    target: TargetProject,
    in_path: Path | None = None,
    bundle: PortableGovernanceBundle | None = None,
    *,
    trusted_git_ref: str | None = None,
) -> GovernanceSyncReceipt:
    """Hydrate per-target governance state without mutating global `RulePolicy`/`PolicyVocabulary`."""
    repo_root = Path(target.repo_path).resolve()
    bundle_label = "inline"
    if bundle is None:
        if trusted_git_ref is not None:
            ref_clean = trusted_git_ref.strip()
            if not ref_clean or ref_clean.startswith("-"):
                raise ValueError("trusted_git_ref must not be empty or start with '-'")
            loaded = _read_bundle_from_trusted_git_ref(repo_root, ref_clean)
            if loaded is None:
                if target.id:
                    _ensure_target_gov_table(session)
                    session.execute(
                        _TARGET_GOV_TABLE.delete().where(
                            _TARGET_GOV_TABLE.c.target_id == int(target.id)
                        )
                    )
                    session.execute(
                        delete(RatchetBaseline).where(RatchetBaseline.target_id == target.id)
                    )
                    session.execute(
                        delete(AuditRuling).where(AuditRuling.target_id == target.id)
                    )
                    session.commit()
                return GovernanceSyncReceipt(
                    target_slug=target.slug,
                    direction="import",
                    bundle_path=f"git:{ref_clean}:(none)",
                    rules_synced=0,
                    vocabularies_synced=0,
                    baselines_synced=0,
                    rulings_synced=0,
                    synced_at=utc_now(),
                )
            bundle, bundle_label = loaded
        else:
            if in_path is None:
                cand = repo_root / ".wythe" / "governance.json"
                if not cand.exists() and not cand.is_symlink():
                    legacy = repo_root / ".truth-atlas" / "governance.json"
                    if legacy.exists() or legacy.is_symlink():
                        cand = legacy
                safe_src = _reject_symlink_walk(cand, repo_root=repo_root)
            else:
                safe_src = _reject_symlink_walk(in_path)
            if not safe_src.exists():
                raise FileNotFoundError(f"Governance bundle not found at {safe_src}")
            bundle = PortableGovernanceBundle.model_validate_json(
                _read_regular_nofollow_text(safe_src)
            )
            bundle_label = str(safe_src)

    now = utc_now()
    today = utc_today()

    known_rule_codes = set(session.scalars(select(RulePolicy.rule_code)).all())
    valid_rule_overrides = [ro for ro in bundle.rule_overrides if ro.rule_code in known_rule_codes]
    norm_vocabs = [
        PortableVocabularyEntry(
            domain_pack=ve.domain_pack.strip().lower(),
            token=ve.token.strip().upper(),
            description=ve.description,
            is_enabled=ve.is_enabled,
        )
        for ve in bundle.vocabularies
        if ve.domain_pack.strip() and ve.token.strip()
    ]

    baselines_count = 0
    rulings_count = 0
    if target.id:
        _save_target_governance_overrides(
            session,
            target.id,
            valid_rule_overrides,
            norm_vocabs,
            now.isoformat(),
            fabricated_fallback_allowlist=list(
                getattr(bundle, "fabricated_fallback_allowlist", [])
            ),
            reference_exemplars=list(bundle.reference_exemplars),
        )
        existing_b = {
            b.rule_code: b
            for b in session.scalars(
                select(RatchetBaseline).where(RatchetBaseline.target_id == target.id)
            ).all()
        }
        desired_baseline_codes = {
            bi.rule_code for bi in bundle.ratchet_baselines if bi.rule_code in known_rule_codes
        }
        for code, stale_b in existing_b.items():
            if code not in desired_baseline_codes:
                session.delete(stale_b)
        for bi in bundle.ratchet_baselines:
            if bi.rule_code not in known_rule_codes:
                continue
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

        desired_rulings: list[
            tuple[tuple[str, str, str, str, str], PortableRulingItem, str | None]
        ] = []
        desired_ruling_keys: set[tuple[str, str, str, str, str]] = set()
        for ri in bundle.audit_rulings:
            packed_cutover = pack_ruling_cutover_payload(
                ri.cutover_history, ri.store_purpose, ri.evidence_scope
            )
            until_iso = ri.effective_until.isoformat() if ri.effective_until is not None else ""
            rkey = (ri.node_id, ri.disposition, ri.audited_commit, packed_cutover or "", until_iso)
            desired_ruling_keys.add(rkey)
            desired_rulings.append((rkey, ri, packed_cutover))

        existing_r: set[tuple[str, str, str, str, str]] = set()
        for rl in session.scalars(
            select(AuditRuling).where(AuditRuling.target_id == target.id)
        ).all():
            e_until = rl.effective_until.isoformat() if rl.effective_until is not None else ""
            ekey = (rl.node_id, rl.disposition, rl.audited_commit, rl.cutover_history or "", e_until)
            if ekey not in desired_ruling_keys or ekey in existing_r:
                session.delete(rl)
            else:
                existing_r.add(ekey)

        for rkey, ri, packed_cutover in desired_rulings:
            if rkey not in existing_r:
                existing_r.add(rkey)
                eff_from = (
                    min(today, ri.effective_until)
                    if ri.effective_until is not None
                    else today
                )
                session.add(
                    AuditRuling(
                        target_id=target.id,
                        node_id=ri.node_id,
                        disposition=ri.disposition,
                        summary=ri.summary,
                        cutover_history=packed_cutover,
                        audited_commit=ri.audited_commit,
                        audited_at=today,
                        effective_from=eff_from,
                        effective_until=ri.effective_until,
                        recorded_by=ri.recorded_by,
                        created_at=now,
                    )
                )
            rulings_count += 1

    session.commit()
    return GovernanceSyncReceipt(
        target_slug=target.slug,
        direction="import",
        bundle_path=bundle_label,
        rules_synced=len(valid_rule_overrides),
        vocabularies_synced=len(norm_vocabs),
        baselines_synced=baselines_count,
        rulings_synced=rulings_count,
        synced_at=now,
    )
