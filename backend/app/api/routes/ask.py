"""Zero-setup on-device local LLM Q&A routes (`/api/v1/ask`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import AskEnginesRead, AskWytheRequest, AskWytheResponse
from app.services.on_device_llm_service import (
    ask_wythe_with_live_context,
    list_ask_engines,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("/engines", response_model=AskEnginesRead)
def get_ask_engines_route(
    local_base_url: Annotated[str | None, Query(max_length=256)] = None,
) -> AskEnginesRead:
    return list_ask_engines(custom_base_url=local_base_url)


@router.post("", response_model=AskWytheResponse)
def post_ask_wythe_route(
    payload: AskWytheRequest,
    db: DbSession,
) -> AskWytheResponse:
    try:
        return ask_wythe_with_live_context(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
