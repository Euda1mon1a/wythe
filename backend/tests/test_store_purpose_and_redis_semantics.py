"""Tests for store purpose declarations, Redis lifecycle semantics, scoped rulings, and causal focus (#45)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditRuling
from app.schemas.atlas import (
    AskWytheRequest,
    AuditRulingCreate,
    OnDeviceEngineStatus,
    StorePurposeDeclaration,
    TargetProjectCreate,
    UiFocusStatePayload,
)
from app.services import on_device_llm_service
from app.services.governance_service import get_target_by_slug, record_audit_ruling, register_target
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.portable_config_service import (
    export_portable_bundle_to_disk,
    sync_portable_bundle_from_disk,
)
from app.services.scanner_service import run_target_scan
from app.services.ui_focus_service import explain_ui_focus, record_ui_focus


def _w(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _build_redis_semantics_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "redis-purpose-repo"
    _w(
        repo,
        "backend/schema.sql",
        "CREATE TABLE catalog (id INTEGER PRIMARY KEY, name TEXT);\n",
    )
    _w(
        repo,
        "backend/app/models/catalog.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Catalog(Base):\n"
        "    __tablename__ = 'catalog'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    name: Mapped[str]\n",
    )
    _w(
        repo,
        "backend/app/services/store_ops.py",
        "import redis\n"
        "from app.models.catalog import Catalog\n"
        "redis_client = redis.Redis()\n\n"
        "def write_sql_catalog(db, item_id: int, name: str) -> None:\n"
        "    obj = Catalog(id=item_id, name=name)\n"
        "    db.add(obj)\n\n"
        "def write_derived_catalog(item_id: int, val: str) -> None:\n"
        "    redis_client.set(f'catalog:{item_id}', val)\n\n"
        "def write_ttl_cache(user_id: int, val: str) -> None:\n"
        "    redis_client.setex(f'ttl_view:{user_id}', 60, val)\n\n"
        "def write_invalidated_cache(user_id: int, val: str) -> None:\n"
        "    redis_client.set(f'inv_view:{user_id}', val)\n\n"
        "def invalidate_cache(user_id: int) -> None:\n"
        "    redis_client.delete(f'inv_view:{user_id}')\n\n"
        "def write_unknown_lifetime(key: str, val: str) -> None:\n"
        "    redis_client.set(f'ephemeral_box:{key}', val)\n\n"
        "def write_config_flag(val: str) -> None:\n"
        "    redis_client.set('feature_config:mode', val)\n\n"
        "def write_dynamic_default(dyn_key: str, val: str) -> None:\n"
        "    redis_client.set(dyn_key, val)\n",
    )
    _w(
        repo,
        "backend/app/api/routes/admin.py",
        "from fastapi import APIRouter\n"
        "import redis\n"
        "from app.services.store_ops import (\n"
        "    write_sql_catalog,\n"
        "    write_derived_catalog,\n"
        "    write_ttl_cache,\n"
        "    write_invalidated_cache,\n"
        "    write_unknown_lifetime,\n"
        "    write_config_flag,\n"
        "    write_dynamic_default,\n"
        ")\n"
        "router = APIRouter()\n"
        "redis_client = redis.Redis()\n\n"
        "@router.post('/admin/dyn')\n"
        "def mutate_default_in_route(key: str, val: str) -> dict:\n"
        "    redis_client.set(key, val)\n"
        "    write_sql_catalog(None, 1, val)\n"
        "    write_derived_catalog(1, val)\n"
        "    write_ttl_cache(1, val)\n"
        "    write_invalidated_cache(1, val)\n"
        "    write_unknown_lifetime(key, val)\n"
        "    write_config_flag(val)\n"
        "    write_dynamic_default(key, val)\n"
        "    return {'ok': True}\n",
    )
    _w(
        repo,
        "backend/app/main.py",
        "from fastapi import FastAPI\n"
        "from app.api.routes.admin import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
    )
    _w(repo, "frontend/src/app/page.tsx", "export default function Home() { return <main>Ok</main>; }\n")
    return repo


def test_redis_four_lifecycles_and_derived_cache_roundtrip(db_session: Session, tmp_path: Path) -> None:
    """Verify TTL, invalidation, unknown lifetime, SQL conflict, and store_purpose roundtrip."""
    repo = _build_redis_semantics_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(slug="redis-sem", name="Redis Semantics", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "redis-sem")
    assert target is not None

    rep = run_target_scan(db_session, target, strict_gate=False)
    by_id = {n.id: n for n in rep.nodes}

    # TTL & explicit invalidation are clean; unknown lifetime without SQL conflict is gray_zone;
    # unbounded catalog matching written SQL table is duplicated_truth.
    assert by_id["t:redis:ttl_view"].status == "clean"
    assert by_id["t:redis:inv_view"].status == "clean"
    assert "explicit invalidation observed" in (by_id["t:redis:inv_view"].verification_note or "")
    assert not any(f.rule_code == "TRUTH-004" and f.target_node_id == "t:redis:inv_view" for f in rep.findings)
    assert by_id["t:redis:ephemeral_box"].status == "gray_zone"
    assert by_id["t:redis:catalog"].status == "duplicated_truth"

    # Declare derived_cache purpose referencing authoritative SQL catalog -> still keeps TRUTH-004
    # unverified status (gray_zone), separating declared intent from verification!
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=rep.source_commit,
        payload=AuditRulingCreate(
            node_id="t:redis:catalog",
            disposition="intentional_copy",
            summary="Intentional read cache built from SQL catalog.",
            store_purpose=StorePurposeDeclaration(
                intended_use="derived_cache",
                authoritative_source="t:sql:catalog",
                copy_reason="Fast catalog lookup",
                refresh_policy="5m webhook invalidation",
            ),
            recorded_by="architect",
        ),
    )

    rep_declared = run_target_scan(db_session, target, strict_gate=False)
    cat_node = next(n for n in rep_declared.nodes if n.id == "t:redis:catalog")
    assert cat_node.store_purpose is not None
    assert cat_node.store_purpose.intended_use == "derived_cache"
    assert cat_node.store_purpose.authoritative_source == "t:sql:catalog"
    assert "invalidation/TTL not verified" in (cat_node.store_purpose.verification_summary or "")
    assert cat_node.status == "gray_zone"

    # Portable governance bundle export/import preserves store_purpose across fresh DB hydration.
    bundle_path = tmp_path / "gov.json"
    exp_receipt = export_portable_bundle_to_disk(db_session, target, out_path=bundle_path)
    assert exp_receipt.rulings_synced >= 1
    raw_bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert raw_bundle["audit_rulings"][0]["store_purpose"]["intended_use"] == "derived_cache"

    sync_receipt = sync_portable_bundle_from_disk(db_session, target, in_path=bundle_path)
    assert sync_receipt.rulings_synced == 1
    db_rulings = db_session.scalars(select(AuditRuling).where(AuditRuling.target_id == target.id)).all()
    assert len(db_rulings) == 1  # idempotent re-sync does not duplicate DB ruling rows

    # Hydrating onto a fresh target restores store_purpose losslessly.
    register_target(
        db_session,
        TargetProjectCreate(slug="redis-sem-clone", name="Redis Clone", repo_path=str(repo)),
    )
    clone_target = get_target_by_slug(db_session, "redis-sem-clone")
    assert clone_target is not None
    clone_sync = sync_portable_bundle_from_disk(db_session, clone_target, in_path=bundle_path)
    assert clone_sync.rulings_synced == 1
    clone_rep = run_target_scan(db_session, clone_target, strict_gate=False)
    clone_cat = next(n for n in clone_rep.nodes if n.id == "t:redis:catalog")
    assert clone_cat.store_purpose is not None
    assert clone_cat.store_purpose.intended_use == "derived_cache"
    assert clone_cat.store_purpose.authoritative_source == "t:sql:catalog"


def test_persistent_config_scoped_default_waiver_and_conflict(db_session: Session, tmp_path: Path) -> None:
    """Test persistent_config recovery requirement, scoped default waivers, and dual-authority conflicts."""
    repo = _build_redis_semantics_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(slug="redis-scope", name="Redis Scope", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "redis-scope")
    assert target is not None

    rep0 = run_target_scan(db_session, target, strict_gate=False)
    # 1. persistent_config WITHOUT recovery_expectation keeps TRUTH-004 gray_zone
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=rep0.source_commit,
        payload=AuditRulingCreate(
            node_id="t:redis:feature_config",
            disposition="intentional_copy",
            summary="Durable feature toggle store.",
            store_purpose=StorePurposeDeclaration(intended_use="persistent_config"),
            recorded_by="architect",
        ),
    )
    rep1 = run_target_scan(db_session, target, strict_gate=False)
    cfg1 = next(n for n in rep1.nodes if n.id == "t:redis:feature_config")
    assert cfg1.status == "gray_zone"
    assert any(f.target_node_id == "t:redis:feature_config" and "recovery expectation" in f.title for f in rep1.findings)

    # With recovery_expectation declared -> becomes clean ("no TTL required")
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=rep0.source_commit,
        payload=AuditRulingCreate(
            node_id="t:redis:feature_config",
            disposition="accepted_clean",
            summary="Feature flags backed up via daily seed.",
            store_purpose=StorePurposeDeclaration(
                intended_use="persistent_config",
                recovery_expectation="Postgres seed / daily RDB snapshot",
            ),
            recorded_by="architect",
        ),
    )

    # 2. Blanket accepted_clean on t:redis:default MUST NOT waive dynamic writes or TRUTH-003!
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=rep0.source_commit,
        payload=AuditRulingCreate(
            node_id="t:redis:default",
            disposition="accepted_clean",
            summary="Too broad blanket waiver attempt.",
            recorded_by="architect",
        ),
    )

    # 3. Declaring authoritative_store on Redis `catalog` while SQL `catalog` has writes conflicts -> duplicated_truth
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=rep0.source_commit,
        payload=AuditRulingCreate(
            node_id="t:redis:catalog",
            disposition="confirmed_owner_intent",
            summary="Claiming Redis owns catalog.",
            store_purpose=StorePurposeDeclaration(intended_use="authoritative_store"),
            recorded_by="architect",
        ),
    )

    rep2 = run_target_scan(db_session, target, strict_gate=False)
    by_id2 = {n.id: n for n in rep2.nodes}
    assert by_id2["t:redis:feature_config"].status == "clean"
    assert by_id2["t:redis:default"].status != "clean"
    assert any(f.target_node_id == "t:redis:default" and f.rule_code == "TRUTH-003" for f in rep2.findings)
    assert any(f.target_node_id == "t:redis:default" and f.rule_code == "TRUTH-004" for f in rep2.findings)
    assert by_id2["t:redis:catalog"].status == "duplicated_truth"
    assert any("Conflicting authoritative stores" in f.title for f in rep2.findings)


def test_causal_writer_focus_cone_and_ai_guardrails(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inspecting a Redis store surfaces causal writer file:line, purpose vs verification, and AI guardrails."""
    repo = _build_redis_semantics_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(slug="redis-focus", name="Redis Focus", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "redis-focus")
    assert target is not None

    rep = run_target_scan(db_session, target, strict_gate=False)
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=rep.source_commit,
        payload=AuditRulingCreate(
            node_id="t:redis:ephemeral_box",
            disposition="intentional_copy",
            summary="Ephemeral session box.",
            store_purpose=StorePurposeDeclaration(intended_use="ephemeral_state"),
            recorded_by="architect",
        ),
    )
    record_ui_focus(
        UiFocusStatePayload(
            active_slug="redis-focus",
            selected_node_id="t:redis:ephemeral_box",
        )
    )
    explain = explain_ui_focus(db_session, target_override="redis-focus")
    assert any(f.target_node_id == "t:redis:ephemeral_box" and f.rule_code == "TRUTH-004" for f in explain.active_findings)
    assert "store_ops.py:" in explain.color_reason
    assert "Declared Purpose" in explain.markdown_brief
    assert "Verification" in explain.markdown_brief

    rep_post = run_target_scan(db_session, target, strict_gate=False)
    cone = build_lineage_cone_slice(rep_post, "t:redis:ephemeral_box")
    assert "TRUTH-004" in cone.markdown
    assert "[writer=`m:service:services.store_ops` -> target=`t:redis:ephemeral_box`]" in cone.markdown
    assert "declared_purpose=ephemeral_state" in cone.markdown

    captured_system: list[str] = []

    def _fake_probe(*_args: object, **_kwargs: object) -> OnDeviceEngineStatus:
        return OnDeviceEngineStatus(
            engine="local",
            label="Mock Local",
            state="ready",
            base_url="http://127.0.0.1:8080/v1",
            model_id="mock-qwen",
            supports_vision=False,
            note="mock-qwen ready at http://127.0.0.1:8080/v1",
        )

    def _fake_chat(
        _base_url: str,
        _model_id: str,
        instructions: str,
        _prompt: str,
        *_rest: object,
        **_kw: object,
    ) -> tuple[str, bool]:
        captured_system.append(instructions)
        return "Verified from live context: `t:redis:ephemeral_box` has unestablished expiration.", False

    monkeypatch.setattr(on_device_llm_service, "probe_local_openai_engine", _fake_probe)
    monkeypatch.setattr(on_device_llm_service, "_run_local_chat_completion", _fake_chat)
    res = on_device_llm_service.ask_wythe_with_live_context(
        db_session,
        AskWytheRequest(
            target_slug="redis-focus",
            question="Is ephemeral_box safe to delete?",
            engine="local",
        ),
    )
    assert res.engine_used == "local"
    assert "Never treat a node's color or status" in captured_system[0]
    assert "causal writer" in captured_system[0]
