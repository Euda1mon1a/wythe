"""Routes managing persisted domain policy vocabularies (`MANIP-001` & `DISP-001`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import (
    PolicyVocabularyCreate,
    PolicyVocabularyRead,
    PolicyVocabularyUpdate,
)
from app.services.governance_service import (
    create_policy_vocabulary,
    list_policy_vocabularies,
    update_policy_vocabulary,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[PolicyVocabularyRead])
def get_vocabularies(db: DbSession) -> list[PolicyVocabularyRead]:
    return list_policy_vocabularies(db)


@router.post("", response_model=PolicyVocabularyRead, status_code=201)
def add_vocabulary(
    payload: PolicyVocabularyCreate,
    db: DbSession,
) -> PolicyVocabularyRead:
    return create_policy_vocabulary(db, payload)


@router.patch("/{vocab_id}", response_model=PolicyVocabularyRead)
def patch_vocabulary(
    vocab_id: int,
    payload: PolicyVocabularyUpdate,
    db: DbSession,
) -> PolicyVocabularyRead:
    try:
        return update_policy_vocabulary(db, vocab_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
