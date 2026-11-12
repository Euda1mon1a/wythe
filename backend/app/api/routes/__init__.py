"""API router mounting all Truth Atlas route domains."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    adapters,
    ask,
    focus,
    mcp_http,
    rules,
    rulings,
    scans,
    targets,
    vocabularies,
)

api_router = APIRouter()
api_router.include_router(adapters.router, prefix="/adapters", tags=["adapters"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(rules.router, prefix="/rules", tags=["rules"])
api_router.include_router(rulings.router, prefix="/rulings", tags=["rulings"])
api_router.include_router(vocabularies.router, prefix="/vocabularies", tags=["vocabularies"])
api_router.include_router(focus.router, prefix="/ui-focus", tags=["ui-focus"])
api_router.include_router(ask.router, prefix="/ask", tags=["ask"])
api_router.include_router(mcp_http.router, prefix="/mcp", tags=["mcp"])
