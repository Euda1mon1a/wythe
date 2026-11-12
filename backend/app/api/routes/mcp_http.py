"""Streamable HTTP Model Context Protocol (MCP) JSON-RPC 2.0 endpoint (`/api/v1/mcp`)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.mcp_service import MCP_TOOLS, dispatch_mcp_request

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("")
def get_mcp_http_manifest_route() -> dict[str, Any]:
    """Return Streamable HTTP MCP discovery manifest & read-only tool schemas."""
    return {
        "name": "wythe",
        "version": "0.1.0",
        "transport": "streamable-http",
        "protocolVersion": "2025-03-26",
        "endpoint": "/api/v1/mcp",
        "openapi": "/openapi.json",
        "tools": MCP_TOOLS,
    }


@router.post("")
def post_mcp_http_rpc_route(
    payload: Annotated[dict[str, Any] | list[dict[str, Any]], Body()],
    db: DbSession,
) -> Response:
    """Handle single or batched JSON-RPC 2.0 MCP requests over Streamable HTTP."""
    if isinstance(payload, list):
        responses = [
            res
            for item in payload
            if isinstance(item, dict)
            for res in [dispatch_mcp_request(db, item)]
            if res is not None
        ]
        if not responses:
            return Response(status_code=202)
        return JSONResponse(content=responses)

    res = dispatch_mcp_request(db, payload)
    if res is None:
        return Response(status_code=202)
    return JSONResponse(content=res)
