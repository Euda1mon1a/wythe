"""Routes reading and updating database-backed RulePolicy truth."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import RulePolicyRead, RulePolicyUpdate
from app.services.governance_service import list_rule_policies, update_rule_policy

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[RulePolicyRead])
def get_rules(db: DbSession) -> list[RulePolicyRead]:
    return list_rule_policies(db)


@router.patch("/{rule_code}", response_model=RulePolicyRead)
def patch_rule(
    rule_code: str,
    payload: RulePolicyUpdate,
    db: DbSession,
) -> RulePolicyRead:
    try:
        return update_rule_policy(db, rule_code, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
