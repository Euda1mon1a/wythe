"""Routes exposing registered language/framework adapters and stack profiles."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.adapters import build_default_registry
from app.adapters.autodetect import detect_repository_stack
from app.adapters.plugin_registry import ENTRY_POINT_GROUP, WythePluginSpec, discover_plugins
from app.db.session import get_db
from app.schemas.atlas import (
    AdapterSlotSchema,
    PluginListResponse,
    PluginSpecItem,
    StackDetectionResult,
    StackProfileRead,
)
from app.services.governance_service import list_stack_profiles

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


def _plugin_source_label(spec: WythePluginSpec) -> str:
    hook = spec.manipulator_hook or spec.post_scan_hook
    mod_name = getattr(hook, "__module__", "") if hook is not None else ""
    if spec.origin == "builtin":
        return mod_name or f"builtin:{spec.name}"
    if spec.origin == "entry_point":
        return f"{ENTRY_POINT_GROUP}:{mod_name}" if mod_name else f"{ENTRY_POINT_GROUP}:{spec.name}"
    return mod_name or f"local:{spec.name}"


@router.get("/slots", response_model=list[AdapterSlotSchema])
def get_adapter_slots() -> list[AdapterSlotSchema]:
    return build_default_registry().list_slots()


@router.get("/plugins", response_model=PluginListResponse)
def get_registered_plugins() -> PluginListResponse:
    load_errors: list[str] = []
    specs = discover_plugins(
        include_builtins=True,
        include_entry_points=True,
        allow_local_plugins=False,
        strict_plugins=False,
        notes_out=load_errors,
    )
    items = [
        PluginSpecItem(
            name=spec.name,
            kind=spec.kind,
            source=_plugin_source_label(spec),
            origin=spec.origin,
            tier="manipulate" if spec.kind == "manipulator_augmenter" else "cross_tier",
            version=spec.version or "unknown",
            description=spec.description,
            enabled_by_default=spec.enabled_by_default,
            trusted=spec.origin in ("builtin", "entry_point"),
        )
        for spec in specs
    ]
    return PluginListResponse(
        plugins=items,
        local_plugins_allowed=False,
        load_errors=load_errors,
    )


@router.get("/profiles", response_model=list[StackProfileRead])
def get_stack_profiles(db: DbSession) -> list[StackProfileRead]:
    return list_stack_profiles(db)


@router.get("/detect", response_model=StackDetectionResult)
def detect_target_stack(
    repo_path: Annotated[str, Query(min_length=1, description="Filesystem directory to inspect")],
    db: DbSession,
) -> StackDetectionResult:
    try:
        return detect_repository_stack(db, repo_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
