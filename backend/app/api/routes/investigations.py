"""Shared human-agent investigation lifecycle & continuity routes (`/api/v1/investigations`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import (
    InvestigationCorrectionCreate,
    InvestigationCorrectionRead,
    InvestigationCreateRequest,
    InvestigationDeltaEventsResponse,
    InvestigationExportBundle,
    InvestigationFollowUpdate,
    InvestigationListResponse,
    InvestigationRevisionComparisonRead,
    InvestigationSessionRead,
    InvestigationTurnCreate,
    InvestigationTurnRead,
    ViewportCommand,
)
from app.services.investigation_service import (
    add_investigation_correction,
    compare_investigation_revisions,
    create_or_reopen_investigation,
    delete_investigation_session,
    export_investigation_session,
    get_investigation_delta_events,
    get_investigation_session,
    list_investigations,
    record_investigation_turn,
    reset_investigation_session,
    update_investigation_follow,
)
from app.services.viewport_service import publish_viewport_command

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]
SessionIdPath = Annotated[str, Path(min_length=1, max_length=64)]


@router.get("", response_model=InvestigationListResponse)
def list_investigations_route(
    target_slug: Annotated[str | None, Query(max_length=64)] = None,
) -> InvestigationListResponse:
    return list_investigations(target_slug=target_slug)


@router.post("", response_model=InvestigationSessionRead)
def create_or_reopen_investigation_route(
    payload: InvestigationCreateRequest,
    db: DbSession,
) -> InvestigationSessionRead:
    try:
        return create_or_reopen_investigation(db, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{session_id}", response_model=InvestigationSessionRead)
def get_investigation_route(session_id: SessionIdPath) -> InvestigationSessionRead:
    found = get_investigation_session(session_id)
    if found is None:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation session `{session_id}` not found.",
        )
    return found


@router.post("/{session_id}/corrections", response_model=InvestigationCorrectionRead)
def post_investigation_correction_route(
    session_id: SessionIdPath,
    payload: InvestigationCorrectionCreate,
) -> InvestigationCorrectionRead:
    try:
        return add_investigation_correction(session_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{session_id}/follow", response_model=InvestigationSessionRead)
def post_investigation_follow_route(
    session_id: SessionIdPath,
    payload: InvestigationFollowUpdate,
) -> InvestigationSessionRead:
    try:
        return update_investigation_follow(session_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{session_id}/turns", response_model=InvestigationTurnRead)
def post_investigation_turn_route(
    session_id: SessionIdPath,
    payload: InvestigationTurnCreate,
    db: DbSession,
) -> InvestigationTurnRead:
    try:
        turn = record_investigation_turn(db, session_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if payload.actor == "agent":
        inv = get_investigation_session(session_id)
        if inv is not None:
            publish_viewport_command(
                ViewportCommand(
                    target_slug=inv.target_slug,
                    session_id=session_id,
                    refresh_session_id=session_id,
                    open_drawer=True,
                ),
                local_only=True,
                current_evidence_revision=turn.evidence_revision_id,
            )
    return turn


@router.get("/{session_id}/events", response_model=InvestigationDeltaEventsResponse)
def get_investigation_events_route(
    session_id: SessionIdPath,
    since_revision: Annotated[int, Query(ge=0)] = 0,
) -> InvestigationDeltaEventsResponse:
    try:
        return get_investigation_delta_events(session_id, since_revision=since_revision)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{session_id}/compare", response_model=InvestigationRevisionComparisonRead)
def compare_investigation_route(
    session_id: SessionIdPath,
    db: DbSession,
) -> InvestigationRevisionComparisonRead:
    try:
        return compare_investigation_revisions(db, session_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{session_id}/export", response_model=InvestigationExportBundle)
def export_investigation_route(
    session_id: SessionIdPath,
    db: DbSession,
) -> InvestigationExportBundle:
    try:
        return export_investigation_session(db, session_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{session_id}/reset", response_model=InvestigationSessionRead)
def reset_investigation_route(
    session_id: SessionIdPath,
    db: DbSession,
) -> InvestigationSessionRead:
    try:
        return reset_investigation_session(db, session_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{session_id}")
def delete_investigation_route(session_id: SessionIdPath) -> dict[str, object]:
    deleted = delete_investigation_session(session_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation session `{session_id}` not found.",
        )
    return {"session_id": session_id, "deleted": True}
