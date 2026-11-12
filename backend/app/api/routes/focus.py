"""Live Human <-> Vision/MCP Bridge endpoints (`/api/v1/ui-focus`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import (
    UiFocusExplainRead,
    UiFocusStatePayload,
    UiFocusSyncAck,
)
from app.services.ui_focus_service import (
    explain_ui_focus,
    load_latest_snapshot_png,
    record_ui_focus,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.post("", response_model=UiFocusSyncAck)
def sync_ui_focus_route(payload: UiFocusStatePayload) -> UiFocusSyncAck:
    return record_ui_focus(payload)


@router.get("", response_model=UiFocusExplainRead)
def get_ui_focus_explanation_route(
    db: DbSession,
    target: Annotated[str | None, Query(max_length=64)] = None,
) -> UiFocusExplainRead:
    try:
        return explain_ui_focus(db, target_override=target)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/snapshot.png")
def get_ui_focus_snapshot_route() -> FileResponse:
    png_path = load_latest_snapshot_png()
    if png_path is None:
        raise HTTPException(status_code=404, detail="No UI focus snapshot captured yet.")
    return FileResponse(png_path, media_type="image/png")
