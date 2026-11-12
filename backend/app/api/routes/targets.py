"""Routes managing registered target repositories."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import (
    GovernanceSyncReceipt,
    PortableGovernanceBundle,
    TargetProjectCreate,
    TargetProjectRead,
)
from app.services.governance_service import (
    get_target_by_slug,
    list_targets,
    register_target,
)
from app.services.portable_config_service import (
    build_portable_bundle,
    export_portable_bundle_to_disk,
    sync_portable_bundle_from_disk,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[TargetProjectRead])
def get_targets(db: DbSession) -> list[TargetProjectRead]:
    return list_targets(db)


@router.post("", response_model=TargetProjectRead, status_code=201)
def create_or_update_target(
    payload: TargetProjectCreate,
    db: DbSession,
) -> TargetProjectRead:
    try:
        return register_target(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{target_slug}/governance-bundle", response_model=PortableGovernanceBundle)
def get_governance_bundle(
    target_slug: str,
    db: DbSession,
) -> PortableGovernanceBundle:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    return build_portable_bundle(db, target)


@router.post("/{target_slug}/governance-sync", response_model=GovernanceSyncReceipt)
def sync_governance_bundle(
    target_slug: str,
    db: DbSession,
    direction: Annotated[Literal["export", "import"], Query()] = "export",
) -> GovernanceSyncReceipt:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    if direction == "export":
        return export_portable_bundle_to_disk(db, target)
    try:
        return sync_portable_bundle_from_disk(db, target)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
