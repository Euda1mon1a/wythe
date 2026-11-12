"""Routes exposing registered language/framework adapters and stack profiles."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.adapters import build_default_registry
from app.adapters.autodetect import detect_repository_stack
from app.db.session import get_db
from app.schemas.atlas import AdapterSlotSchema, StackDetectionResult, StackProfileRead
from app.services.governance_service import list_stack_profiles

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("/slots", response_model=list[AdapterSlotSchema])
def get_adapter_slots() -> list[AdapterSlotSchema]:
    return build_default_registry().list_slots()


@router.get("/profiles", response_model=list[StackProfileRead])
def get_stack_profiles(db: DbSession) -> list[StackProfileRead]:
    return list_stack_profiles(db)


@router.get("/detect", response_model=StackDetectionResult)
def detect_target_stack(
    repo_path: Annotated[str, Query(min_length=1, description="Filesystem directory to inspect")],
    db: DbSession,
) -> StackDetectionResult:
    try:
        return detect_repository_stack(db, repo_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
