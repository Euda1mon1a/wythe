"""Read-only Six-Link Understanding routes (`/api/v1/understanding`).

Mount in `app.api.routes` via:
    api_router.include_router(understanding.router, prefix="/understanding", tags=["understanding"])
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.understanding_service import (
    UnderstandingAnalyzeRequest,
    UnderstandingChainReport,
    UnderstandingExampleRead,
    UnderstandingExampleSummary,
    analyze_understanding_bundle,
    get_understanding_example,
    list_understanding_examples,
)

ROUTER_PREFIX = "/understanding"
router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]
ExampleSlugPath = Annotated[str, Path(min_length=1, max_length=64)]


@router.post("/analyze", response_model=UnderstandingChainReport)
def post_analyze_understanding_route(
    payload: UnderstandingAnalyzeRequest,
    db: DbSession,
) -> UnderstandingChainReport:
    try:
        return analyze_understanding_bundle(payload, db=db)
    except (LookupError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/explain", response_model=UnderstandingChainReport)
def get_explain_understanding_route(
    db: DbSession,
    target_slug: Annotated[str | None, Query(max_length=64)] = None,
    target: Annotated[str | None, Query(max_length=64)] = None,
    example_slug: Annotated[str | None, Query(max_length=64)] = None,
    session_id: Annotated[str | None, Query(max_length=64)] = None,
    subject_id: Annotated[str | None, Query(max_length=128)] = None,
    node_id: Annotated[str | None, Query(max_length=128)] = None,
    finding_id: Annotated[str | None, Query(max_length=128)] = None,
    edge_id: Annotated[str | None, Query(max_length=128)] = None,
    question: Annotated[str | None, Query(max_length=512)] = None,
    observed_at: Annotated[str | None, Query(max_length=64)] = None,
    prior_explanation_revision: Annotated[str | None, Query(max_length=128)] = None,
    bundle_path: Annotated[str | None, Query(max_length=512)] = None,
) -> UnderstandingChainReport:
    req = UnderstandingAnalyzeRequest(
        target_slug=target_slug or target,
        example_slug=example_slug,
        session_id=session_id,
        subject_id=subject_id,
        node_id=node_id,
        finding_id=finding_id,
        edge_id=edge_id,
        question=question,
        observed_at=observed_at,
        prior_explanation_revision=prior_explanation_revision,
        bundle_path=bundle_path,
    )
    try:
        return analyze_understanding_bundle(req, db=db)
    except (LookupError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/examples", response_model=list[UnderstandingExampleSummary])
def list_understanding_examples_route() -> list[UnderstandingExampleSummary]:
    return list_understanding_examples()


@router.get("/examples/{example_slug}", response_model=UnderstandingExampleRead)
def get_understanding_example_route(example_slug: ExampleSlugPath) -> UnderstandingExampleRead:
    try:
        return get_understanding_example(example_slug)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
