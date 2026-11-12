"""Routes reading and recording dated human ownership rulings and cutover provenance."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import AuditRulingCreate, AuditRulingRead
from app.services.governance_service import (
    get_target_by_slug,
    list_rulings,
    record_audit_ruling,
)
from app.services.scanner_service import run_target_scan

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("/{target_slug}", response_model=list[AuditRulingRead])
def get_target_rulings(
    target_slug: str,
    db: DbSession,
) -> list[AuditRulingRead]:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    return list_rulings(db, target.id)


@router.post("/{target_slug}", response_model=AuditRulingRead, status_code=201)
def create_target_ruling(
    target_slug: str,
    payload: AuditRulingCreate,
    db: DbSession,
) -> AuditRulingRead:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, persist_snapshot=False)
    return record_audit_ruling(db, target.id, report.source_commit, payload)
