"""Agent <-> Human 3D Viewport Choreography, Receipts & SSE endpoints (`/api/v1/viewport`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import (
    ViewportCommand,
    ViewportCommandAck,
    ViewportCommandReceiptCreate,
    ViewportCommandReceiptRead,
    ViewportStateRead,
    validate_semantic_atlas_id,
)
from app.services.governance_service import get_target_by_slug
from app.services.investigation_service import (
    build_evidence_identity,
    get_or_run_cached_scan,
)
from app.services.viewport_service import (
    get_viewport_state,
    list_viewport_receipts,
    publish_viewport_command,
    record_viewport_receipt,
    stream_viewport_events,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.post("/command", response_model=ViewportCommandAck)
def post_viewport_command_route(
    payload: ViewportCommand,
    db: DbSession,
) -> ViewportCommandAck:
    cur_ev_rev: str | None = None
    if payload.expected_evidence_revision:
        target = get_target_by_slug(db, payload.target_slug)
        if target is not None:
            rep = get_or_run_cached_scan(db, target)
            cur_ev_rev = build_evidence_identity(rep).evidence_revision_id
    try:
        return publish_viewport_command(
            payload,
            local_only=True,
            current_evidence_revision=cur_ev_rev,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/receipts", response_model=ViewportCommandReceiptRead)
def post_viewport_receipt_route(
    payload: ViewportCommandReceiptCreate,
) -> ViewportCommandReceiptRead:
    try:
        return record_viewport_receipt(payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/receipts", response_model=list[ViewportCommandReceiptRead])
def get_viewport_receipts_route(
    target_slug: Annotated[str | None, Query(max_length=64)] = None,
    session_id: Annotated[str | None, Query(max_length=64)] = None,
    command_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ViewportCommandReceiptRead]:
    return list_viewport_receipts(
        target_slug=target_slug,
        session_id=session_id,
        command_id=command_id,
        limit=limit,
    )


@router.get("/state", response_model=ViewportStateRead)
def get_viewport_state_route(
    target_slug: Annotated[str, Query(min_length=1, max_length=64)],
    session_id: Annotated[str | None, Query(max_length=64)] = None,
    since_seq: Annotated[int, Query(ge=0)] = 0,
) -> ViewportStateRead:
    try:
        clean_slug = validate_semantic_atlas_id(target_slug, field_name="target_slug")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return get_viewport_state(
        clean_slug,
        session_id=session_id,
        since_seq=since_seq,
    )


@router.get("/stream", include_in_schema=False)
@router.get("/events")
async def get_viewport_events_route(
    request: Request,
    target_slug: Annotated[str, Query(min_length=1, max_length=64)],
    session_id: Annotated[str | None, Query(max_length=64)] = None,
    since_seq: Annotated[int, Query(ge=0)] = 0,
    once: Annotated[bool, Query()] = False,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    try:
        clean_slug = validate_semantic_atlas_id(target_slug, field_name="target_slug")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    effective_since = since_seq
    if last_event_id is not None and last_event_id.strip().isdigit():
        effective_since = max(effective_since, int(last_event_id.strip()))

    generator = stream_viewport_events(
        clean_slug,
        session_id=session_id,
        since_seq=effective_since,
        once=once,
        is_disconnected=request.is_disconnected,
    )
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
