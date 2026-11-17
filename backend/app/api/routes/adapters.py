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
    fallback_mcp = spec.mcp_tools[0].handler if spec.mcp_tools else None
    fallback_cli = next(iter(spec.cli_subcommands.values()), None)
    fallback_comp = next(iter(spec.companion_handlers.values()), None)
    fallback_adapter = next(
        iter((*spec.truth_adapters, *spec.manipulator_adapters, *spec.display_adapters)),
        None,
    )
    hook = (
        spec.manipulator_hook
        or spec.post_scan_hook
        or spec.stratum_badge_hook
        or spec.stratum_expand_hook
        or fallback_adapter
        or fallback_mcp
        or fallback_cli
        or fallback_comp
    )
    mod_name = (
        getattr(hook, "__module__", "")
        or getattr(type(hook), "__module__", "")
        if hook is not None
        else ""
    )
    if mod_name == "builtins":
        mod_name = ""
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
    items = []
    for spec in specs:
        supported_caps, unsupported_caps = spec.resolved_interaction_capabilities()
        items.append(
            PluginSpecItem(
                name=spec.name,
                kind=spec.kind,
                source=_plugin_source_label(spec),
                origin=spec.origin,
                tier="manipulate" if spec.kind == "manipulator_augmenter" else "cross_tier",
                version=spec.version or "unknown",
                description=spec.description,
                enabled_by_default=spec.enabled_by_default,
                supported_zooms=(
                    list(spec.supported_zooms or (2, 3))
                    if (
                        spec.kind == "stratum_inspector"
                        or spec.stratum_badge_hook is not None
                        or spec.stratum_expand_hook is not None
                    )
                    else []
                ),
                rules=[r.rule_code for r in spec.rules],
                mcp_tools=[t.name for t in spec.mcp_tools],
                cli_subcommands=sorted(spec.cli_subcommands),
                stack_profiles=[p.slug for p in spec.stack_profiles],
                tier_adapters=[
                    str(getattr(a, "name", ""))
                    for a in (*spec.truth_adapters, *spec.manipulator_adapters, *spec.display_adapters)
                    if getattr(a, "name", None)
                ],
                interaction_capabilities=supported_caps,
                unsupported_interaction_capabilities=unsupported_caps,
                evidence_source_kinds=spec.resolved_evidence_source_kinds(),
                trusted=spec.origin in ("builtin", "entry_point"),
            )
        )
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
