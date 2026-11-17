"""Streamable HTTP Model Context Protocol (MCP) JSON-RPC 2.0 endpoint (`/api/v1/mcp`)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app import __version__
from app.db.session import get_db
from app.services.mcp_service import (
    MCP_RESOURCE_TEMPLATES,
    dispatch_mcp_request,
    get_mcp_tools,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]
SliceQuery = Annotated[Literal["full", "slm"], Query(alias="slice")]


@router.get("")
def get_mcp_http_manifest_route(
    slice_mode: SliceQuery = "full",
) -> dict[str, Any]:
    """Return Streamable HTTP MCP discovery manifest & read-only tool/resource schemas."""
    return {
        "name": "wythe",
        "version": __version__,
        "transport": "streamable-http",
        "protocolVersion": "2025-03-26",
        "endpoint": "/api/v1/mcp",
        "openapi": "/openapi.json",
        "slice": slice_mode,
        "capabilities": {"tools": {}, "resources": {}},
        "tools": get_mcp_tools(slice_mode),
        "resourceTemplates": MCP_RESOURCE_TEMPLATES,
    }


@router.post("")
def post_mcp_http_rpc_route(
    payload: Annotated[dict[str, Any] | list[dict[str, Any]], Body()],
    db: DbSession,
    slice_mode: SliceQuery = "full",
) -> Response:
    """Handle single or batched JSON-RPC 2.0 MCP requests over Streamable HTTP."""
    if isinstance(payload, list):
        responses = [
            res
            for item in payload
            if isinstance(item, dict)
            for res in [
                dispatch_mcp_request(
                    db, item, slice_mode=slice_mode, local_viewport_only=True
                )
            ]
            if res is not None
        ]
        if not responses:
            return Response(status_code=202)
        return JSONResponse(content=responses)

    res = dispatch_mcp_request(
        db, payload, slice_mode=slice_mode, local_viewport_only=True
    )
    if res is None:
        return Response(status_code=202)
    return JSONResponse(content=res)
