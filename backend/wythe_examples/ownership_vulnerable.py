"""Intentionally vulnerable fixture. Synthetic data only; do not deploy."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .ownership_common import Record, RecordUpdate, User, get_session, get_user

router = APIRouter()


@router.patch("/records/{record_id}")
def update_record(
    record_id: int,
    payload: RecordUpdate,
    user: Annotated[User, Depends(get_user)],
    db: Annotated[Session, Depends(get_session)],
):
    record = db.get(Record, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Record not found")
    record.title = payload.title
    db.commit()
    return {"id": record.id, "title": record.title}
