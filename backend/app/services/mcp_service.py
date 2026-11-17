"""Zero-dependency read-only Model Context Protocol (MCP) stdio server for Wythe."""

from __future__ import annotations

import base64
import difflib
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, BinaryIO, Literal

from sqlalchemy.orm import Session

from app import __version__
from app.adapters.autodetect import detect_repository_stack
from app.adapters.plugin_registry import collect_enabled_plugin_mcp_tools, discover_plugins
from app.db.session import get_session_factory
from app.models import TargetProject
from app.schemas.atlas import (
    ChronicleFrame,
    ChronicleTimeline,
    DiffBlastRadiusReport,
    InvestigationCorrectionCreate,
    InvestigationCreateRequest,
    InvestigationFollowUpdate,
    LlmContextConeReport,
    TourKeyframe,
    TruthAtlasReport,
    ViewportCommand,
)
from app.services.companion_export_service import build_openlineage_static_bundle
from app.services.diff_and_sarif_service import run_target_diff
from app.services.governance_service import (
    get_target_by_slug,
    list_stack_profiles,
    list_targets,
)
from app.services.investigation_service import (
    add_investigation_correction,
    build_evidence_identity,
    compare_investigation_revisions,
    create_or_reopen_investigation,
    get_investigation_delta_events,
    get_investigation_session,
    get_or_run_cached_scan,
    list_investigations,
    update_investigation_follow,
)
from app.services.llm_context_service import (
    DEFAULT_BRIEF_TOKENS,
    DEFAULT_CONE_NODES,
    build_lineage_cone_slice,
    build_llms_txt_brief,
)
from app.services.scanner_service import run_target_scan
from app.services.ui_focus_service import explain_ui_focus, read_saved_ui_focus_state
from app.services.viewport_service import (
    get_viewport_state,
    list_viewport_receipts,
    publish_viewport_command,
    viewport_delivery_scope,
)

McpSliceMode = Literal["full", "slm"]

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "wythe_list_targets",
        "description": "List registered Wythe repositories and enabled 3-tier stack profiles.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "wythe_overview",
        "description": (
            "Return a token-budgeted `llms.txt` 3-tier architectural pointer map (`file:line` tables, "
            "SQL guards, Redis/worker queue lanes, HTTP routes, services, UI pages, sample E2E chains, and grouped findings)."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Registered target slug or repository path."},
                "max_tokens": {"type": "integer", "default": DEFAULT_BRIEF_TOKENS, "minimum": 400, "maximum": 12000},
                "profile": {"type": "string", "default": "auto"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_lineage_cone",
        "description": (
            "Slice the surgical upstream/downstream 3-tier Lineage Cone (`Page -> Route -> Service/Worker -> SQL Table/Queue`) "
            "around a specific table name, file path, `/api/...` route, queue lane, or node ID."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Registered target slug or repository path."},
                "query": {"type": "string", "description": "Table name, file path, HTTP route, queue, or node ID."},
                "max_nodes": {"type": "integer", "default": DEFAULT_CONE_NODES, "minimum": 5, "maximum": 5000},
                "full": {
                    "type": "boolean",
                    "default": False,
                    "description": "Disable node/edge/finding caps and export the full cone.",
                },
                "zoom": {
                    "type": "integer",
                    "enum": [1, 2, 3],
                    "default": 1,
                    "description": "Progressive LOD stratum: 1 (3-wythe default), 2 (IR / Metal AIR), or 3 (binary / heap).",
                },
                "unfiltered_ir": {
                    "type": "boolean",
                    "default": False,
                    "description": "Disable stdlib/ARC/witness thunk compaction when zoom is 2 or 3.",
                },
                "profile": {"type": "string", "default": "auto"},
            },
            "required": ["target", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_blast_radius",
        "description": (
            "Compute git diff 3-tier blast radius and newly introduced boundary/accessibility violations "
            "(use `base_ref='WORKING'` to self-verify uncommitted changes before committing)."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Registered target slug or repository path."},
                "base_ref": {"type": "string", "default": "WORKING"},
                "profile": {"type": "string", "default": "auto"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_findings",
        "description": "Filter and paginate 3-tier boundary & WCAG accessibility (`DISP-005`) findings with remediation hints.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Registered target slug or repository path."},
                "rule_code": {"type": "string", "description": "Optional rule filter (e.g. 'TRUTH-003', 'MANIP-001', 'DISP-005')."},
                "tier": {"type": "string", "enum": ["truth", "manipulate", "display"]},
                "limit": {"type": "integer", "default": 25, "minimum": 1, "maximum": 100},
                "offset": {"type": "integer", "default": 0, "minimum": 0},
                "profile": {"type": "string", "default": "auto"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_what_is_this",
        "description": (
            "Zero-copy-paste Human <-> LLM Bridge: inspect what the human is currently viewing, hovering, "
            "or highlighting in the live 3D/accessible Wythe GUI (selection, focus/evidence revisions, "
            "active human corrections, delta events, viewport command delivery states, multi-tab ambiguity, "
            "and optional annotated WebGL snapshot)."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Optional target slug override (defaults to active GUI target)."},
                "session_id": {"type": "string", "description": "Optional investigation/browser session ID."},
                "since_revision": {"type": "integer", "minimum": 0, "description": "Optional session revision cursor for delta events."},
                "include_image": {"type": "boolean", "default": False, "description": "Include latest annotated 3D viewport PNG/WebP block if captured."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_plugins",
        "description": (
            "List registered built-in and installed `wythe.plugins` entry-point companion plugins "
            "(local untrusted repository plugins are never executed over MCP)."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "wythe_openlineage",
        "description": (
            "Export a concise static OpenLineage 2.0.2 summary (SQL/cache datasets and Tier-2/E2E "
            "job read `inputs` vs write `outputs`) for a registered target or directory."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Registered target slug or repository path.",
                },
                "profile": {"type": "string", "default": "auto"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_focus_camera",
        "description": (
            "Agent -> Human 3D Camera Choreography: steer a connected 3D Wythe browser tab to frame "
            "semantic Atlas node IDs, call/drift edges, Z-wythe slices, Zoom strata, or boundary findings "
            "without raw coordinates, returning headless structured evidence, `#target=...` permalink, "
            "and honest `delivery_state`."
        ),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Registered target slug or repository path (defaults to active GUI target).",
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional browser session ID for multi-tab viewport isolation.",
                },
                "correlation_id": {
                    "type": "string",
                    "description": "Optional idempotency key scoped to `(target_slug, session_id)`.",
                },
                "expected_evidence_revision": {
                    "type": "string",
                    "description": "Optional `evidence_revision_id` guard; marks command `stale` on mismatch.",
                },
                "focus_node_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 50,
                    "description": "Semantic Atlas node IDs or unique table/route/service labels to frame.",
                },
                "highlight_edge_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 80,
                    "description": "Optional Atlas edge IDs (`e:...`) to illuminate along the lineage corridor.",
                },
                "finding_id": {
                    "type": "string",
                    "description": "Optional BoundaryFinding ID (`f:TRUTH-003:0`) or rule code.",
                },
                "lens": {
                    "type": "string",
                    "enum": ["status", "contention", "gravity", "subkind", "cluster", "containers"],
                },
                "layout_mode": {
                    "type": "string",
                    "enum": ["cluster", "grid", "subkind", "connected", "lifecycle_z", "temporal_z"],
                },
                "z_wythe_slice": {
                    "type": "string",
                    "enum": ["all", "z0_blueprint", "z1_built", "z2_runtime", "z_base", "z_head"],
                },
                "zoom_stratum": {"type": "integer", "enum": [1, 2, 3], "default": 1},
                "framing_preset": {
                    "type": "string",
                    "enum": ["iso_overview", "tier_elevation", "wythe_cross_section", "corridor_trace"],
                    "default": "iso_overview",
                },
                "caption": {
                    "type": "string",
                    "maxLength": 400,
                    "description": "Plain-text caption announced in the 3D HUD and WCAG aria-live region.",
                },
                "chronicle_frames": {
                    "type": "array",
                    "maxItems": 32,
                    "items": {"type": "object"},
                    "description": "Optional domain-agnostic ordered `ChronicleFrame[]` playback timeline.",
                },
                "chronicle_timeline": {
                    "type": "object",
                    "description": "Optional domain-agnostic `ChronicleTimeline` descriptor.",
                },
                "profile": {"type": "string", "default": "auto"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_camera_tour",
        "description": (
            "Agent -> Human Multi-Step 3D Walkthrough: publish an ordered `TourKeyframe[]` camera tour "
            "(and optional `ChronicleFrame[]` timeline) to connected browser tabs and return headless "
            "structured evidence, permalink, and honest `delivery_state`."
        ),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Registered target slug or repository path (defaults to active GUI target).",
                },
                "session_id": {"type": "string"},
                "correlation_id": {"type": "string"},
                "expected_evidence_revision": {"type": "string"},
                "tour_keyframes": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "items": {"type": "object"},
                    "description": "Ordered `TourKeyframe[]` walkthrough steps.",
                },
                "keyframes": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "items": {"type": "object"},
                    "description": "Alias for `tour_keyframes`.",
                },
                "chronicle_frames": {
                    "type": "array",
                    "maxItems": 32,
                    "items": {"type": "object"},
                },
                "chronicle_timeline": {
                    "type": "object",
                },
                "focus_node_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "highlight_edge_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 80},
                "finding_id": {"type": "string"},
                "lens": {
                    "type": "string",
                    "enum": ["status", "contention", "gravity", "subkind", "cluster", "containers"],
                },
                "layout_mode": {
                    "type": "string",
                    "enum": ["cluster", "grid", "subkind", "connected", "lifecycle_z", "temporal_z"],
                },
                "z_wythe_slice": {
                    "type": "string",
                    "enum": ["all", "z0_blueprint", "z1_built", "z2_runtime", "z_base", "z_head"],
                },
                "zoom_stratum": {"type": "integer", "enum": [1, 2, 3], "default": 1},
                "framing_preset": {
                    "type": "string",
                    "enum": ["iso_overview", "tier_elevation", "wythe_cross_section", "corridor_trace"],
                    "default": "iso_overview",
                },
                "caption": {"type": "string", "maxLength": 400},
                "profile": {"type": "string", "default": "auto"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_investigation",
        "description": (
            "Shared Human-Agent Investigation & Six-Link Understanding: list/inspect durable sessions, "
            "record clarifications (`promoted_to_ruling=False`), compare pinned vs current scan revisions, "
            "read browser delivery receipts, or evaluate the Six-Link Understanding Chain and shipped examples."
        ),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "list_sessions",
                        "get_session",
                        "create_session",
                        "record_correction",
                        "set_follow",
                        "compare_revisions",
                        "get_receipts",
                        "list_understanding_examples",
                        "get_understanding_example",
                        "explain_understanding",
                    ],
                    "default": "list_sessions",
                },
                "target": {"type": "string"},
                "session_id": {"type": "string"},
                "client_id": {"type": "string"},
                "title": {"type": "string"},
                "note": {"type": "string"},
                "target_ref_id": {"type": "string"},
                "turn_id": {"type": "string"},
                "kind": {"type": "string"},
                "follow_state": {"type": "string", "enum": ["following", "paused"]},
                "reason": {"type": "string"},
                "command_id": {"type": "string"},
                "since_revision": {"type": "integer", "minimum": 0},
                "example_slug": {"type": "string"},
                "bundle_path": {"type": "string"},
                "subject_id": {"type": "string"},
                "question": {"type": "string"},
                "prior_explanation_revision": {"type": "string"},
                "observed_at": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
]


MCP_SLM_TOOLS: list[dict[str, Any]] = [
    {
        "name": "wythe_context",
        "description": "Read bounded 3-tier brief, UI focus, and top findings in one call.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target slug or repo path."},
                "section": {
                    "type": "string",
                    "enum": ["overview", "focus", "findings", "all"],
                    "default": "all",
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_lineage_cone",
        "description": "Slice 3-tier lineage cone and policy field consumption around a table, route, file, or node.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target slug or repo path."},
                "query": {"type": "string", "description": "Table, route, file, queue, or node ID."},
                "full": {"type": "boolean", "default": False},
            },
            "required": ["target", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_check_change",
        "description": "Run strict 3-tier gate and git diff blast-radius verdict in one call.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target slug or repo path."},
                "base_ref": {"type": "string", "default": "WORKING"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wythe_what_is_this",
        "description": "Explain live 3D camera focus, session revisions, and optional image.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "session_id": {"type": "string"},
                "since_revision": {"type": "integer", "minimum": 0},
                "include_image": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
]

MCP_RESOURCE_TEMPLATES: list[dict[str, Any]] = [
    {
        "uriTemplate": "wythe://{slug}/llms",
        "name": "Wythe 3-Tier Architectural Map (llms.txt)",
        "description": "Bounded deterministic 3-tier pointer map for registered target `{slug}`.",
        "mimeType": "text/markdown",
    },
    {
        "uriTemplate": "wythe://{slug}/ui-focus",
        "name": "Wythe Live 3D UI Focus X-Ray",
        "description": "Live 3D viewport camera frustum, selection, and snapshot metadata for `{slug}`.",
        "mimeType": "text/markdown",
    },
    {
        "uriTemplate": "wythe://{slug}/findings",
        "name": "Wythe Boundary & Accessibility Findings",
        "description": "Active 3-tier boundary and WCAG (`DISP-005`) findings for `{slug}`.",
        "mimeType": "text/markdown",
    },
    {
        "uriTemplate": "wythe://{slug}/cone/{node_id}",
        "name": "Wythe Surgical 3-Tier Lineage Cone",
        "description": "Upstream/downstream 3-tier lineage cone and PolicyFieldConsumption around `{node_id}`.",
        "mimeType": "text/markdown",
    },
    {
        "uriTemplate": "wythe://{slug}/investigation/{session_id}",
        "name": "Wythe Shared Human-Agent Investigation",
        "description": "Durable shared investigation state, turns, corrections, and receipts for `{session_id}`.",
        "mimeType": "text/markdown",
    },
]


def normalize_mcp_slice(slice_mode: str | None = "full") -> McpSliceMode:
    """Validate and normalize MCP tool slice mode (`full` default or compact `slm`)."""
    cleaned = (slice_mode or "full").strip().lower()
    if cleaned not in ("full", "slm"):
        raise ValueError(f"Unsupported MCP slice `{slice_mode}`; expected `full` or `slm`.")
    return "slm" if cleaned == "slm" else "full"


def get_mcp_tools(slice_mode: str = "full") -> list[dict[str, Any]]:
    """Return advertised MCP tool schemas (`full` appends enabled plugin tools; `slm` stays 4 tools)."""
    if normalize_mcp_slice(slice_mode) == "slm":
        return MCP_SLM_TOOLS
    tools: list[dict[str, Any]] = list(MCP_TOOLS)
    seen_names = {str(t.get("name") or "") for t in tools}
    for p_tool in collect_enabled_plugin_mcp_tools():
        if p_tool.name and p_tool.name not in seen_names:
            seen_names.add(p_tool.name)
            tools.append(dict(p_tool.definition))
    return tools


def _format_unknown_target_error(session: Session, raw_target: str, *, for_uri: str | None = None) -> str:
    registered = [t.slug for t in list_targets(session)]
    q_low = raw_target.strip().lower()
    close = difflib.get_close_matches(q_low, registered, n=4, cutoff=0.35)
    for slug in registered:
        if (q_low and (q_low in slug.lower() or slug.lower() in q_low)) and slug not in close:
            close.append(slug)
    known_str = ", ".join(f"`{s}`" for s in registered) if registered else "none"
    close_str = f" Closest match(es): {', '.join(f'`{c}`' for c in close[:4])}." if close else ""
    if for_uri:
        return (
            f"Unknown target slug `{raw_target}` in resource URI `{for_uri}`.{close_str} "
            f"Registered target slugs: {known_str}. Retry with `wythe://<slug>/llms`, "
            f"`wythe://<slug>/ui-focus`, `wythe://<slug>/findings`, or `wythe://<slug>/cone/<node_id>`."
        )
    return (
        f"Unknown target `{raw_target}`.{close_str} Registered target slugs: {known_str}. "
        "Pass one of those registered slugs as `target` (or an existing local repository path)."
    )


def _format_unmatched_query_error(
    report: TruthAtlasReport,
    query: str,
    base_suggestions: list[str],
) -> str:
    q_low = query.strip().lower()
    candidates: list[str] = []
    seen: set[str] = set()
    for item in base_suggestions:
        if item not in seen:
            seen.add(item)
            candidates.append(item)

    scored: list[tuple[float, str]] = []
    for node in report.nodes:
        ptr = f"{node.source_file}:{node.line}" if node.line else node.source_file
        entry = f"`{node.id}` (label=`{node.label}`, `{ptr}`)"
        if entry in seen or f"{node.id} ({ptr})" in seen:
            continue
        fields = [node.id.lower(), node.label.lower(), node.source_file.lower(), *(p.lower() for p in node.http_paths)]
        best = max((difflib.SequenceMatcher(None, q_low, f).ratio() for f in fields if f), default=0.0)
        if best >= 0.35:
            scored.append((best, entry))
    scored.sort(key=lambda it: (-it[0], it[1]))
    for _, entry in scored[:6]:
        if len(candidates) >= 8:
            break
        candidates.append(entry)

    if not candidates and report.nodes:
        ranked_nodes = sorted(
            report.nodes,
            key=lambda n: (-(n.read_by_count + n.written_by_count), n.tier != "truth", n.id),
        )
        for node in ranked_nodes[:6]:
            ptr = f"{node.source_file}:{node.line}" if node.line else node.source_file
            candidates.append(f"`{node.id}` (label=`{node.label}`, `{ptr}`)")

    cand_str = "; ".join(candidates[:6]) if candidates else "none"
    return (
        f"No node matched `{query}` in target `{report.target_slug}`. "
        f"Closest / valid node IDs & labels: {cand_str}. "
        f"Retry `wythe_lineage_cone` with one of those node IDs, table names, route paths, or file names."
    )


def _resolve_readonly_target(session: Session, target_or_path: str, profile: str = "auto") -> TargetProject:
    existing = get_target_by_slug(session, target_or_path)
    if existing is not None:
        return existing
    looks_like_path = (
        target_or_path in (".", "..")
        or "/" in target_or_path
        or "\\" in target_or_path
        or target_or_path.startswith("~")
    )
    candidate = Path(target_or_path).expanduser().resolve()
    if not (looks_like_path or candidate.is_dir()) or not candidate.is_dir():
        raise ValueError(_format_unknown_target_error(session, target_or_path))
    det = detect_repository_stack(session, str(candidate))
    chosen = det.recommended_profile_slug if profile == "auto" else profile
    clean_slug = re.sub(r"[^a-z0-9-_]", "-", candidate.name.lower()).strip("-") or "mcp-target"
    return TargetProject(
        id=0,
        slug=clean_slug,
        name=candidate.name,
        repo_path=str(candidate),
        stack_profile_slug=chosen,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        legacy_snapshot_relpath=None,
        description="Read-only MCP target",
        is_active=True,
    )


def _resolve_target_for_mcp(
    session: Session,
    raw_target: Any = None,
    *,
    profile: str = "auto",
) -> TargetProject:
    """Resolve explicit target slug/path or fall back to active UI-focus / registered target."""
    cleaned = str(raw_target or "").strip()
    if cleaned:
        return _resolve_readonly_target(session, cleaned, profile=profile)
    saved_focus = read_saved_ui_focus_state()
    active_slug = str(saved_focus.get("active_slug") or "").strip()
    if active_slug:
        active_proj = get_target_by_slug(session, active_slug)
        if active_proj is not None:
            return active_proj
    registered = list_targets(session)
    if registered:
        return registered[0]
    raise ValueError("Missing `target` parameter and no registered Wythe targets are available.")


_FORBIDDEN_COORD_KEYS = frozenset(
    {
        "x",
        "y",
        "z",
        "position",
        "camera_position",
        "camera_target",
        "euler",
        "rotation",
        "quaternion",
        "coordinates",
        "coords",
        "azimuth",
        "elevation",
        "look_at",
    }
)


def _resolve_camera_beat_ids(
    report: TruthAtlasReport,
    focus_node_ids: list[str],
    highlight_edge_ids: list[str],
    finding_id: str | None,
    notes: list[str],
    unresolved_nodes: list[str],
    unresolved_edges: list[str],
    unresolved_findings: list[str],
) -> tuple[list[str], list[str], str | None]:
    nodes_by_id = {n.id: n for n in report.nodes}
    lower_id_map = {n.id.lower(): n.id for n in report.nodes}
    label_buckets: dict[str, list[str]] = {}
    for node in report.nodes:
        label_buckets.setdefault(node.label.lower(), []).append(node.id)

    resolved_nodes: list[str] = []
    for raw_nid in focus_node_ids:
        if raw_nid in nodes_by_id:
            resolved_nodes.append(raw_nid)
            continue
        if raw_nid.lower() in lower_id_map:
            canon = lower_id_map[raw_nid.lower()]
            resolved_nodes.append(canon)
            notes.append(f"Resolved node ID `{raw_nid}` -> `{canon}`.")
            continue
        lbl_matches = label_buckets.get(raw_nid.lower(), [])
        if len(lbl_matches) == 1:
            canon = lbl_matches[0]
            resolved_nodes.append(canon)
            notes.append(f"Resolved label `{raw_nid}` -> canonical node ID `{canon}`.")
            continue
        resolved_nodes.append(raw_nid)
        if raw_nid not in unresolved_nodes:
            unresolved_nodes.append(raw_nid)
        hints = difflib.get_close_matches(raw_nid.lower(), list(lower_id_map), n=3, cutoff=0.35)
        hint_str = (
            f" Closest scan IDs: {', '.join(f'`{lower_id_map[h]}`' for h in hints)}."
            if hints
            else ""
        )
        notes.append(
            f"Warning: focus node `{raw_nid}` is absent from latest `{report.target_slug}` scan "
            f"(preserved verbatim without inventing nodes).{hint_str}"
        )

    known_edges = {e.id for e in report.edges}
    for eid in highlight_edge_ids:
        if eid not in known_edges and eid not in unresolved_edges:
            unresolved_edges.append(eid)
            notes.append(
                f"Warning: edge `{eid}` is absent from latest `{report.target_slug}` scan."
            )

    resolved_finding = finding_id
    if finding_id:
        findings_by_id = {f.id: f for f in report.findings}
        matched = findings_by_id.get(finding_id)
        if matched is None:
            by_rule = [f for f in report.findings if f.rule_code.lower() == finding_id.lower()]
            if by_rule:
                matched = by_rule[0]
                resolved_finding = matched.id
                notes.append(f"Resolved rule `{finding_id}` -> finding `{matched.id}`.")
        if matched is None:
            if finding_id not in unresolved_findings:
                unresolved_findings.append(finding_id)
            notes.append(
                f"Warning: finding `{finding_id}` is absent from latest `{report.target_slug}` scan."
            )
        elif not resolved_nodes:
            for fnid in (matched.node_id, matched.target_node_id):
                if fnid and fnid not in resolved_nodes:
                    resolved_nodes.append(fnid)

    return list(dict.fromkeys(resolved_nodes)), list(dict.fromkeys(highlight_edge_ids)), resolved_finding


def _execute_camera_choreography_tool(
    session: Session,
    canonical: str,
    args: dict[str, Any],
    *,
    server_url: str | None = None,
    allow_remote_viewport: bool = False,
    local_viewport_only: bool = False,
) -> str:
    is_tour = canonical == "wythe_camera_tour"
    base_allowed = {
        "target",
        "profile",
        "session_id",
        "correlation_id",
        "expected_evidence_revision",
        "focus_node_ids",
        "highlight_edge_ids",
        "finding_id",
        "lens",
        "layout_mode",
        "z_wythe_slice",
        "zoom_stratum",
        "framing_preset",
        "caption",
        "chronicle_frames",
        "chronicle_timeline",
    }
    allowed = base_allowed | ({"tour_keyframes", "keyframes"} if is_tour else set())
    unknown = sorted(set(args) - allowed)
    if unknown:
        if set(unknown) & _FORBIDDEN_COORD_KEYS:
            raise ValueError(
                f"Raw numeric coordinates (`{', '.join(unknown)}`) are forbidden; "
                "pass semantic Atlas IDs and `framing_preset` instead."
            )
        raise ValueError(f"Unsupported argument(s) for `{canonical}`: {', '.join(unknown)}.")

    raw_chronicle = [] if args.get("chronicle_frames") is None else args.get("chronicle_frames")
    if not isinstance(raw_chronicle, list):
        raise TypeError("`chronicle_frames` must be a list of `ChronicleFrame` objects.")
    chronicle_frames = [ChronicleFrame.model_validate(item) for item in raw_chronicle]

    raw_tl = args.get("chronicle_timeline")
    prelim_tl: ChronicleTimeline | None = None
    if raw_tl is not None:
        if not isinstance(raw_tl, dict):
            raise TypeError("`chronicle_timeline` must be a JSON object when provided.")
        prelim_tl = ChronicleTimeline.model_validate(raw_tl)

    raw_focus_ids = [] if args.get("focus_node_ids") is None else args.get("focus_node_ids")
    if not isinstance(raw_focus_ids, list):
        raise TypeError("`focus_node_ids` must be a list of semantic Atlas node IDs.")
    raw_edge_ids = [] if args.get("highlight_edge_ids") is None else args.get("highlight_edge_ids")
    if not isinstance(raw_edge_ids, list):
        raise TypeError("`highlight_edge_ids` must be a list of semantic Atlas edge IDs.")
    raw_caption = "" if args.get("caption") is None else args.get("caption")
    if not isinstance(raw_caption, str):
        raise TypeError("`caption` must be a string.")
    for opt_str_key in (
        "target",
        "profile",
        "session_id",
        "correlation_id",
        "expected_evidence_revision",
        "finding_id",
    ):
        opt_val = args.get(opt_str_key)
        if opt_val is not None and not isinstance(opt_val, str):
            raise TypeError(f"`{opt_str_key}` must be a string when provided.")

    parsed_keyframes: list[TourKeyframe] = []
    if is_tour:
        raw_kfs = args.get("tour_keyframes") if "tour_keyframes" in args else args.get("keyframes")
        if not isinstance(raw_kfs, list) or not raw_kfs:
            raise ValueError(
                "`wythe_camera_tour` requires a non-empty `tour_keyframes` list (1..32 steps)."
            )
        for idx, item in enumerate(raw_kfs):
            if not isinstance(item, dict):
                raise TypeError("Each item in `tour_keyframes` must be a JSON object.")
            kf_payload = dict(item)
            kf_payload.setdefault("step_index", idx)
            parsed_keyframes.append(TourKeyframe.model_validate(kf_payload))

    prelim_slug = str(args.get("target") or "").strip()
    prelim_slug_safe = (
        re.sub(r"[^a-z0-9-_]", "-", Path(prelim_slug).name.lower()).strip("-") or "wythe"
        if ("/" in prelim_slug or "\\" in prelim_slug or prelim_slug in (".", ".."))
        else (prelim_slug or "wythe")
    )
    prelim_cmd = ViewportCommand(
        target_slug=prelim_slug_safe[:64],
        session_id=args.get("session_id"),
        correlation_id=args.get("correlation_id"),
        expected_evidence_revision=args.get("expected_evidence_revision"),
        focus_node_ids=raw_focus_ids,
        highlight_edge_ids=raw_edge_ids,
        finding_id=args.get("finding_id"),
        lens=args.get("lens"),
        layout_mode=args.get("layout_mode"),
        z_wythe_slice=args.get("z_wythe_slice"),
        zoom_stratum=1 if args.get("zoom_stratum") is None else args.get("zoom_stratum"),
        framing_preset=(
            "iso_overview" if args.get("framing_preset") is None else args.get("framing_preset")
        ),
        caption=raw_caption,
        tour_keyframes=parsed_keyframes,
        chronicle_frames=chronicle_frames,
        chronicle_timeline=prelim_tl,
    )

    profile = str(args.get("profile") or "auto")
    target = _resolve_target_for_mcp(session, args.get("target"), profile=profile)
    report = get_or_run_cached_scan(session, target, strict_gate=True)
    ev_identity = build_evidence_identity(report)

    notes: list[str] = []
    unresolved_nodes: list[str] = []
    unresolved_edges: list[str] = []
    unresolved_findings: list[str] = []

    resolved_kfs: list[TourKeyframe] = []
    for kf in prelim_cmd.tour_keyframes:
        kf_nodes, kf_edges, kf_finding = _resolve_camera_beat_ids(
            report,
            kf.focus_node_ids,
            kf.highlight_edge_ids,
            kf.finding_id,
            notes,
            unresolved_nodes,
            unresolved_edges,
            unresolved_findings,
        )
        resolved_kfs.append(
            kf.model_copy(
                update={
                    "focus_node_ids": kf_nodes,
                    "highlight_edge_ids": kf_edges,
                    "finding_id": kf_finding,
                }
            )
        )

    resolved_cfs: list[ChronicleFrame] = []
    for cf in prelim_cmd.chronicle_frames:
        cf_nodes, cf_edges, _ = _resolve_camera_beat_ids(
            report,
            cf.focus_node_ids,
            cf.highlight_edge_ids,
            None,
            notes,
            unresolved_nodes,
            unresolved_edges,
            unresolved_findings,
        )
        resolved_cfs.append(
            cf.model_copy(
                update={
                    "focus_node_ids": cf_nodes,
                    "highlight_edge_ids": cf_edges,
                }
            )
        )

    resolved_tl: ChronicleTimeline | None = None
    if prelim_cmd.chronicle_timeline is not None:
        tl_frames: list[ChronicleFrame] = []
        for tl_cf in prelim_cmd.chronicle_timeline.frames:
            tl_nodes, tl_edges, _ = _resolve_camera_beat_ids(
                report,
                tl_cf.focus_node_ids,
                tl_cf.highlight_edge_ids,
                None,
                notes,
                unresolved_nodes,
                unresolved_edges,
                unresolved_findings,
            )
            tl_frames.append(
                tl_cf.model_copy(
                    update={
                        "focus_node_ids": tl_nodes,
                        "highlight_edge_ids": tl_edges,
                    }
                )
            )
        resolved_tl = prelim_cmd.chronicle_timeline.model_copy(
            update={
                "target_slug": report.target_slug,
                "frames": tl_frames,
            }
        )

    top_nodes, top_edges, top_finding = _resolve_camera_beat_ids(
        report,
        prelim_cmd.focus_node_ids,
        prelim_cmd.highlight_edge_ids,
        prelim_cmd.finding_id,
        notes,
        unresolved_nodes,
        unresolved_edges,
        unresolved_findings,
    )

    if resolved_kfs:
        first_kf = resolved_kfs[0]
        final_cmd = ViewportCommand(
            target_slug=report.target_slug,
            session_id=prelim_cmd.session_id,
            correlation_id=prelim_cmd.correlation_id,
            expected_evidence_revision=prelim_cmd.expected_evidence_revision,
            focus_node_ids=top_nodes or list(first_kf.focus_node_ids),
            highlight_edge_ids=top_edges or list(first_kf.highlight_edge_ids),
            finding_id=top_finding or first_kf.finding_id,
            lens=prelim_cmd.lens if "lens" in args and args["lens"] is not None else first_kf.lens,
            layout_mode=(
                prelim_cmd.layout_mode
                if "layout_mode" in args and args["layout_mode"] is not None
                else first_kf.layout_mode
            ),
            z_wythe_slice=(
                prelim_cmd.z_wythe_slice
                if "z_wythe_slice" in args and args["z_wythe_slice"] is not None
                else first_kf.z_wythe_slice
            ),
            zoom_stratum=(
                prelim_cmd.zoom_stratum if "zoom_stratum" in args else first_kf.zoom_stratum
            ),
            framing_preset=(
                prelim_cmd.framing_preset if "framing_preset" in args else first_kf.framing_preset
            ),
            caption=prelim_cmd.caption or first_kf.caption or first_kf.title,
            tour_keyframes=resolved_kfs,
            chronicle_frames=resolved_cfs,
            chronicle_timeline=resolved_tl,
        )
    else:
        final_cmd = ViewportCommand(
            target_slug=report.target_slug,
            session_id=prelim_cmd.session_id,
            correlation_id=prelim_cmd.correlation_id,
            expected_evidence_revision=prelim_cmd.expected_evidence_revision,
            focus_node_ids=top_nodes,
            highlight_edge_ids=top_edges,
            finding_id=top_finding,
            lens=prelim_cmd.lens,
            layout_mode=prelim_cmd.layout_mode,
            z_wythe_slice=prelim_cmd.z_wythe_slice,
            zoom_stratum=prelim_cmd.zoom_stratum,
            framing_preset=prelim_cmd.framing_preset,
            caption=prelim_cmd.caption,
            tour_keyframes=[],
            chronicle_frames=resolved_cfs,
            chronicle_timeline=resolved_tl,
        )

    ack = publish_viewport_command(
        final_cmd,
        server_url=server_url,
        allow_remote=allow_remote_viewport,
        local_only=local_viewport_only,
        current_evidence_revision=ev_identity.evidence_revision_id,
    )
    if final_cmd.tour_keyframes:
        exported_keyframes = [kf.model_dump() for kf in final_cmd.tour_keyframes]
    else:
        single_kf = TourKeyframe(
            step_index=0,
            title=(final_cmd.caption[:120] if final_cmd.caption else f"Focus {report.target_slug}"),
            focus_node_ids=final_cmd.focus_node_ids,
            highlight_edge_ids=final_cmd.highlight_edge_ids,
            finding_id=final_cmd.finding_id,
            lens=final_cmd.lens,
            layout_mode=final_cmd.layout_mode,
            z_wythe_slice=final_cmd.z_wythe_slice,
            zoom_stratum=final_cmd.zoom_stratum,
            framing_preset=final_cmd.framing_preset,
            caption=final_cmd.caption,
        )
        exported_keyframes = [single_kf.model_dump()]

    nodes_map = {n.id: n for n in report.nodes}
    edges_map = {e.id: e for e in report.edges}
    findings_map = {f.id: f for f in report.findings}
    headless_nodes = [
        {
            "id": n.id,
            "tier": n.tier,
            "subkind": n.subkind,
            "label": n.label,
            "pointer": f"{n.source_file}:{n.line}",
            "status": n.status,
            "policy_field_consumption": (
                n.policy_field_consumption.model_dump() if n.policy_field_consumption else None
            ),
        }
        for nid in final_cmd.focus_node_ids
        if (n := nodes_map.get(nid)) is not None
    ]
    headless_edges = [
        {
            "id": e.id,
            "source_id": e.source_id,
            "target_id": e.target_id,
            "kind": e.kind,
            "verification": e.verification,
            "evidence_path": e.evidence_path,
        }
        for eid in final_cmd.highlight_edge_ids
        if (e := edges_map.get(eid)) is not None
    ]
    headless_finding = (
        findings_map[final_cmd.finding_id].model_dump()
        if final_cmd.finding_id and final_cmd.finding_id in findings_map
        else None
    )

    artifact = {
        "seq": ack.seq,
        "command_id": ack.command_id,
        "correlation_id": ack.correlation_id,
        "issued_at": ack.issued_at.isoformat(),
        "target_slug": ack.target_slug,
        "session_id": ack.session_id,
        "delivery_state": ack.delivery_state,
        "applied_by_client_ids": ack.applied_by_client_ids,
        "idempotent_replay": ack.idempotent_replay,
        "subscriber_count": ack.subscriber_count,
        "evidence_revision_id": ev_identity.evidence_revision_id,
        "permalink": ack.permalink,
        "framing_preset": final_cmd.framing_preset,
        "focus_node_ids": final_cmd.focus_node_ids,
        "highlight_edge_ids": final_cmd.highlight_edge_ids,
        "finding_id": final_cmd.finding_id,
        "headless_evidence": {
            "focused_nodes": headless_nodes,
            "highlighted_edges": headless_edges,
            "finding": headless_finding,
        },
        "tour_keyframes": exported_keyframes,
        "chronicle_frames": [cf.model_dump() for cf in final_cmd.chronicle_frames],
        "chronicle_timeline": (
            final_cmd.chronicle_timeline.model_dump() if final_cmd.chronicle_timeline else None
        ),
        "unresolved_focus_ids": unresolved_nodes,
        "unresolved_edge_ids": unresolved_edges,
        "unresolved_finding_ids": unresolved_findings,
    }

    mode_title = "Camera Tour" if is_tour else "Camera Focus"
    md = [
        f"# Wythe 3D {mode_title} :: `{report.target_slug}` (seq={ack.seq})",
        (
            f"> Command: `{ack.command_id}` | Delivery: `{ack.delivery_state}` | "
            f"Framing: `{final_cmd.framing_preset}` | Zoom: `{final_cmd.zoom_stratum}` | "
            f"Live SSE Subscribers: {ack.subscriber_count} | Steps: {len(exported_keyframes)}"
        ),
        f"- **Evidence Revision**: `{ev_identity.evidence_revision_id}` (`{ev_identity.source_commit[:16]}`)",
        f"- **Canonical Permalink**: `{ack.permalink}`",
    ]
    if final_cmd.focus_node_ids:
        md.append(f"- **Focused Nodes**: {', '.join(f'`{n}`' for n in final_cmd.focus_node_ids)}")
    if final_cmd.highlight_edge_ids:
        md.append(
            f"- **Highlighted Edges**: {', '.join(f'`{e}`' for e in final_cmd.highlight_edge_ids)}"
        )
    if final_cmd.caption:
        md.append(f"- **Caption**: {final_cmd.caption}")
    if notes:
        md.append("\n## Diagnostic Notes")
        for note in notes:
            md.append(f"- {note}")
    md.append("\n## Viewport Artifact JSON")
    md.append("```json\n" + json.dumps(artifact, indent=2) + "\n```")
    return "\n".join(md)


def _render_investigation_resource_markdown(inv: Any) -> str:
    lines = [
        f"# Shared Investigation :: `{inv.session_id}` (`{inv.target_slug}`)",
        (
            f"> Title: {inv.title} | Revision: `{inv.session_revision}` | "
            f"Focus rev: `{inv.focus_revision}` | Follow: `{inv.follow_state}` | "
            f"Drifted: `{inv.evidence_drifted}`"
        ),
        (
            f"- **Pinned Evidence**: `{inv.pinned_evidence.evidence_revision_id}` "
            f"(`{inv.pinned_evidence.source_commit[:20]}`)"
        ),
        (
            f"- **Latest Evidence**: `{inv.latest_evidence.evidence_revision_id}` "
            f"(`{inv.latest_evidence.source_commit[:20]}`)"
        ),
        f"- **Selected Node / Finding / Edge**: `{inv.focus.selected_node_id}` / `{inv.focus.selected_finding_id}` / `{inv.focus.selected_edge_id}`",
        f"- **Turns**: {len(inv.turns)} ({len(inv.unresolved_questions)} unresolved) | **Corrections**: {len(inv.corrections)} | **Receipts**: {len(inv.recent_receipts)}",
        "\n## Investigation JSON",
        "```json\n" + inv.model_dump_json(indent=2) + "\n```",
    ]
    return "\n".join(lines)


def list_mcp_resources(session: Session) -> list[dict[str, Any]]:
    """List concrete `wythe://` MCP resources for registered targets plus active investigations."""
    saved_focus = read_saved_ui_focus_state()
    active_focus_slug = str(saved_focus.get("active_slug") or "").strip()
    ordered_targets: list[TargetProject] = list(list_targets(session))
    seen_slugs = {t.slug for t in ordered_targets}
    if active_focus_slug and active_focus_slug not in seen_slugs:
        extra_target = get_target_by_slug(session, active_focus_slug)
        if extra_target is not None:
            ordered_targets.insert(0, extra_target)
            seen_slugs.add(extra_target.slug)

    resources: list[dict[str, Any]] = []
    for target in ordered_targets:
        slug = target.slug
        active_tag = " (active viewport)" if slug == active_focus_slug else ""
        resources.extend(
            [
                {
                    "uri": f"wythe://{slug}/llms",
                    "name": f"{target.name} — 3-Tier Map (llms.txt)",
                    "description": f"Bounded deterministic 3-tier architectural map for `{slug}`.",
                    "mimeType": "text/markdown",
                },
                {
                    "uri": f"wythe://{slug}/ui-focus",
                    "name": f"{target.name} — Live UI Focus{active_tag}",
                    "description": f"Live 3D viewport focus X-Ray for `{slug}`{active_tag}.",
                    "mimeType": "text/markdown",
                },
                {
                    "uri": f"wythe://{slug}/findings",
                    "name": f"{target.name} — Boundary Findings",
                    "description": f"Active 3-tier boundary and WCAG findings for `{slug}`.",
                    "mimeType": "text/markdown",
                },
            ]
        )
        for inv_sum in list_investigations(target_slug=slug).sessions[:16]:
            resources.append(
                {
                    "uri": f"wythe://{slug}/investigation/{inv_sum.session_id}",
                    "name": f"{target.name} — Investigation `{inv_sum.session_id}`",
                    "description": (
                        f"Shared investigation `{inv_sum.title}` "
                        f"(rev={inv_sum.session_revision}, follow={inv_sum.follow_state})."
                    ),
                    "mimeType": "text/markdown",
                }
            )
    return resources


def _parse_cone_zoom(raw_zoom: object) -> Literal[1, 2, 3]:
    if raw_zoom is None:
        return 1
    if isinstance(raw_zoom, bool):
        raise TypeError(f"Invalid `zoom` `{raw_zoom}`; expected integer `1`, `2`, or `3`.")
    if isinstance(raw_zoom, str):
        stripped = raw_zoom.strip()
        if stripped not in ("1", "2", "3"):
            raise ValueError(f"Invalid `zoom` `{raw_zoom}`; expected `1`, `2`, or `3`.")
        raw_zoom = int(stripped)
    if not isinstance(raw_zoom, int):
        raise TypeError(f"Invalid `zoom` `{raw_zoom}`; expected `1`, `2`, or `3`.")
    if raw_zoom not in (1, 2, 3):
        raise ValueError(f"Invalid `zoom` `{raw_zoom}`; expected `1`, `2`, or `3`.")
    if raw_zoom == 2:
        return 2
    if raw_zoom == 3:
        return 3
    return 1


def read_mcp_resource(session: Session, uri: str) -> list[dict[str, Any]]:
    """Read a `wythe://{slug}/...` resource URI and return MCP `contents` items."""
    cleaned = uri.strip()
    if not cleaned.startswith("wythe://"):
        raise ValueError(
            f"Unsupported resource URI `{uri}`; expected `wythe://<slug>/llms`, "
            "`wythe://<slug>/ui-focus`, `wythe://<slug>/findings`, "
            "`wythe://<slug>/cone/<node_id>`, or `wythe://<slug>/investigation/<session_id>`."
        )
    remainder = cleaned.removeprefix("wythe://")
    raw_slug, sep, raw_path = remainder.partition("/")
    slug = urllib.parse.unquote(raw_slug).strip()
    path_only, _, query_str = raw_path.partition("?")
    leading_trimmed = path_only.lstrip("/")
    resource_path = (
        leading_trimmed
        if leading_trimmed.startswith(("cone/", "investigation/"))
        else path_only.strip("/")
    )
    if not slug or not sep or not resource_path or ".." in resource_path.split("/"):
        raise ValueError(
            f"Malformed resource URI `{uri}`; expected `wythe://<slug>/llms|ui-focus|findings|cone/<node_id>|investigation/<session_id>`."
        )

    node_query = ""
    inv_session_id = ""
    cone_zoom: Literal[1, 2, 3] = 1
    cone_unfiltered = False
    raw_query_fallback = ""
    if resource_path.startswith("investigation/"):
        inv_session_id = urllib.parse.unquote(
            resource_path.removeprefix("investigation/").strip("/")
        ).strip()
        if not inv_session_id or "/" in inv_session_id or ".." in inv_session_id:
            raise ValueError(f"Missing or invalid `<session_id>` in investigation URI `{cleaned}`.")
    elif resource_path.startswith("cone/"):
        node_query = urllib.parse.unquote(resource_path.removeprefix("cone/")).strip()
        if not node_query:
            raise ValueError(f"Missing `<node_id>` in cone resource URI `{cleaned}`.")
        if query_str:
            qs = urllib.parse.parse_qs(query_str, keep_blank_values=False)
            zoom_vals = qs.get("zoom")
            unfiltered_vals = qs.get("unfiltered_ir")
            if zoom_vals or unfiltered_vals:
                if zoom_vals:
                    cone_zoom = _parse_cone_zoom(zoom_vals[-1])
                if unfiltered_vals:
                    cone_unfiltered = unfiltered_vals[-1].strip().lower() in ("1", "true", "yes")
            else:
                raw_query_fallback = f"{node_query}?{urllib.parse.unquote(query_str)}"
    elif resource_path not in ("llms", "ui-focus", "findings", "understanding"):
        raise ValueError(
            f"Unknown resource path `{resource_path}` in `{cleaned}`. "
            "Supported paths: `llms`, `ui-focus`, `findings`, `understanding`, `cone/{node_id}`, `investigation/{session_id}`."
        )

    target = get_target_by_slug(session, slug)
    if target is None:
        raise LookupError(_format_unknown_target_error(session, slug, for_uri=cleaned))

    if resource_path == "understanding":
        from app.services.understanding_service import (
            UnderstandingAnalyzeRequest,
            analyze_understanding_bundle,
        )

        qs = urllib.parse.parse_qs(query_str, keep_blank_values=False) if query_str else {}
        chain = analyze_understanding_bundle(
            UnderstandingAnalyzeRequest(
                target_slug=target.slug,
                session_id=(qs.get("session_id") or [None])[-1],
                subject_id=(qs.get("subject_id") or [None])[-1],
                question=(qs.get("question") or [None])[-1],
            ),
            db=session,
        )
        return [
            {
                "uri": cleaned,
                "mimeType": "text/markdown",
                "text": _render_understanding_chain_markdown(chain),
            }
        ]

    if inv_session_id:
        inv = get_investigation_session(inv_session_id)
        if inv is None or inv.target_slug != target.slug:
            raise LookupError(
                f"Investigation session `{inv_session_id}` not found for target `{target.slug}`."
            )
        return [
            {
                "uri": cleaned,
                "mimeType": "text/markdown",
                "text": _render_investigation_resource_markdown(inv),
            }
        ]

    if resource_path == "ui-focus":
        explain = explain_ui_focus(session, target_project=target)
        items: list[dict[str, Any]] = [
            {"uri": cleaned, "mimeType": "text/markdown", "text": explain.markdown_brief}
        ]
        if explain.has_snapshot and explain.snapshot_path and not explain.snapshot_stale:
            snap_file = Path(explain.snapshot_path)
            if not snap_file.is_symlink() and snap_file.is_file():
                b64 = base64.b64encode(snap_file.read_bytes()).decode("ascii")
                items.append(
                    {
                        "uri": f"{cleaned}#snapshot",
                        "mimeType": explain.snapshot_mime_type or "image/png",
                        "blob": b64,
                    }
                )
        return items

    report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)
    if resource_path == "llms":
        text = build_llms_txt_brief(report, max_tokens=DEFAULT_BRIEF_TOKENS).markdown
        return [{"uri": cleaned, "mimeType": "text/markdown", "text": text}]

    if resource_path == "findings":
        text = _format_findings_markdown(report, limit=50, offset=0)
        return [{"uri": cleaned, "mimeType": "text/markdown", "text": text}]

    primary_query = raw_query_fallback if raw_query_fallback else node_query
    cone = build_lineage_cone_slice(
        report,
        primary_query,
        max_nodes=DEFAULT_CONE_NODES,
        full=False,
        zoom=cone_zoom,
        unfiltered_ir=cone_unfiltered,
    )
    if not cone.matched_seed_ids and raw_query_fallback:
        cone = build_lineage_cone_slice(
            report,
            node_query,
            max_nodes=DEFAULT_CONE_NODES,
            full=False,
            zoom=cone_zoom,
            unfiltered_ir=cone_unfiltered,
        )
    if not cone.matched_seed_ids:
        raise LookupError(_format_unmatched_query_error(report, primary_query, cone.suggestions))
    return [
        {
            "uri": cleaned,
            "mimeType": "text/markdown",
            "text": _render_cone_markdown_with_policy(report, cone),
        }
    ]


def dispatch_mcp_request(
    session: Session,
    msg: dict[str, Any],
    slice_mode: str = "full",
    *,
    server_url: str | None = None,
    allow_remote_viewport: bool = False,
    local_viewport_only: bool = False,
) -> dict[str, Any] | None:
    """Process one JSON-RPC 2.0 MCP request message; returns `None` for notifications."""
    if not isinstance(msg, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: expected a JSON object."},
        }
    method = msg.get("method", "")
    req_id = msg.get("id")
    if req_id is None:
        return None
    if not isinstance(method, str) or not method:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid Request: `method` must be a non-empty string."},
        }

    raw_params = msg.get("params")
    if raw_params is not None and not isinstance(raw_params, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": "Invalid params: `params` must be a JSON object."},
        }
    params: dict[str, Any] = raw_params or {}

    try:
        active_slice = normalize_mcp_slice(slice_mode)
    except ValueError as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": str(exc)},
        }

    if method == "initialize":
        proto = params.get("protocolVersion") or "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": proto,
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "wythe", "version": __version__},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": get_mcp_tools(active_slice)}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": list_mcp_resources(session)}}
    if method == "resources/templates/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": MCP_RESOURCE_TEMPLATES}}
    if method == "resources/read":
        uri_param = params.get("uri")
        if not isinstance(uri_param, str) or not uri_param.strip():
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Missing or invalid string parameter `uri`."},
            }
        try:
            contents = read_mcp_resource(session, uri_param.strip())
            return {"jsonrpc": "2.0", "id": req_id, "result": {"contents": contents}}
        except (ValueError, TypeError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": str(exc)},
            }
        except LookupError as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32002, "message": str(exc)},
            }
    if method != "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    tool_name = params.get("name", "")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": "Invalid params: `name` must be a non-empty string."},
        }
    raw_args = params.get("arguments")
    if raw_args is not None and not isinstance(raw_args, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": "Invalid params: `arguments` must be a JSON object."},
        }
    args: dict[str, Any] = raw_args or {}
    canonical_name = (
        tool_name.replace("atlas_", "wythe_", 1) if tool_name.startswith("atlas_") else tool_name
    )
    core_names = {t["name"] for t in [*MCP_TOOLS, *MCP_SLM_TOOLS]} | {
        "wythe_active_view",
        "wythe_understanding",
    }
    with viewport_delivery_scope(
        server_url=server_url,
        allow_remote=allow_remote_viewport,
        local_only=local_viewport_only,
    ):
        if (
            active_slice == "full"
            and canonical_name not in core_names
            and tool_name not in core_names
        ):
            plugin_tools = {t.name: t for t in collect_enabled_plugin_mcp_tools()}
            matched_plugin_tool = plugin_tools.get(tool_name) or plugin_tools.get(canonical_name)
            if matched_plugin_tool is not None:
                try:
                    plugin_result = matched_plugin_tool.handler(session, args)
                    content_blocks, is_err = _normalize_plugin_mcp_result(plugin_result)
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": content_blocks, "isError": is_err},
                    }
                except ValueError as exc:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": str(exc)},
                    }
                except Exception as exc:  # noqa: BLE001
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Wythe MCP error: {exc}"}],
                            "isError": True,
                        },
                    }

        try:
            content_blocks = _execute_tool_blocks(
                session,
                tool_name,
                args,
                server_url=server_url,
                allow_remote_viewport=allow_remote_viewport,
                local_viewport_only=local_viewport_only,
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": content_blocks, "isError": False},
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Wythe MCP error: {exc}"}],
                    "isError": True,
                },
            }


def _normalize_plugin_mcp_result(raw_out: Any) -> tuple[list[dict[str, Any]], bool]:
    if isinstance(raw_out, str):
        return [{"type": "text", "text": raw_out}], False
    if isinstance(raw_out, list) and all(isinstance(item, dict) for item in raw_out):
        return raw_out, False
    if isinstance(raw_out, dict):
        if isinstance(raw_out.get("content"), list) and all(
            isinstance(item, dict) for item in raw_out["content"]
        ):
            return raw_out["content"], bool(raw_out.get("isError", False))
        return [{"type": "text", "text": json.dumps(raw_out, indent=2)}], False
    return [{"type": "text", "text": str(raw_out)}], False


def _execute_tool_blocks(
    session: Session,
    tool_name: str,
    args: dict[str, Any],
    *,
    server_url: str | None = None,
    allow_remote_viewport: bool = False,
    local_viewport_only: bool = False,
) -> list[dict[str, Any]]:
    canonical = tool_name.replace("atlas_", "wythe_", 1) if tool_name.startswith("atlas_") else tool_name
    if canonical in ("wythe_what_is_this", "wythe_active_view"):
        target_ovr = str(args.get("target") or "").strip() or None
        req_sid = str(args.get("session_id") or "").strip() or None
        raw_since = args.get("since_revision")
        if raw_since is not None and (isinstance(raw_since, bool) or not isinstance(raw_since, int) or raw_since < 0):
            raise ValueError("`since_revision` must be a non-negative integer.")
        if target_ovr and get_target_by_slug(session, target_ovr) is None:
            resolved_proj = _resolve_readonly_target(session, target_ovr)
            explain = explain_ui_focus(session, target_project=resolved_proj, session_id=req_sid)
        else:
            explain = explain_ui_focus(session, target_override=target_ovr, session_id=req_sid)

        eff_sid = explain.session_id
        delta_items: list[dict[str, Any]] = []
        latest_session_rev = 0
        if eff_sid:
            try:
                deltas = get_investigation_delta_events(
                    eff_sid, since_revision=int(raw_since or 0)
                )
                latest_session_rev = deltas.latest_revision
                delta_items = [ev.model_dump(mode="json") for ev in deltas.events[-25:]]
            except LookupError:
                pass

        vp_state = get_viewport_state(explain.active_slug, session_id=eff_sid)
        recent_cmds = [
            {
                "seq": ev.seq,
                "command_id": ev.command.command_id,
                "correlation_id": ev.command.correlation_id,
                "delivery_state": ev.delivery_state,
                "applied_by_client_ids": ev.applied_by_client_ids,
                "focus_node_ids": ev.command.focus_node_ids,
            }
            for ev in vp_state.history[-8:]
        ]
        recent_rcpts = [
            r.model_dump(mode="json")
            for r in list_viewport_receipts(
                target_slug=explain.active_slug, session_id=eff_sid, limit=10
            )
        ]
        context_json = {
            "target_slug": explain.active_slug,
            "session_id": eff_sid,
            "session_revision": latest_session_rev,
            "focus_revision": explain.focus_revision,
            "evidence_revision_id": explain.evidence_revision_id,
            "follow_state": explain.follow_state,
            "selected_node_id": explain.focused_node.id if explain.focused_node else None,
            "selected_edge_id": explain.selected_edge_id,
            "selected_finding_id": explain.selected_finding_id,
            "ambiguous_session_ids": explain.ambiguous_session_ids,
            "corrections": [c.model_dump(mode="json") for c in explain.corrections],
            "delta_events": delta_items,
            "recent_commands": recent_cmds,
            "recent_receipts": recent_rcpts,
        }
        enriched_md = (
            f"{explain.markdown_brief}\n\n"
            "## Shared Investigation Context JSON\n"
            f"```json\n{json.dumps(context_json, indent=2)}\n```"
        )
        blocks: list[dict[str, Any]] = [{"type": "text", "text": enriched_md}]
        if (
            bool(args.get("include_image"))
            and explain.has_snapshot
            and explain.snapshot_path
            and not explain.snapshot_stale
        ):
            snap_file = Path(explain.snapshot_path)
            if snap_file.is_file():
                b64 = base64.b64encode(snap_file.read_bytes()).decode("ascii")
                blocks.append(
                    {
                        "type": "image",
                        "data": b64,
                        "mimeType": explain.snapshot_mime_type or "image/png",
                    }
                )
        return blocks
    return [
        {
            "type": "text",
            "text": _execute_tool(
                session,
                tool_name,
                args,
                server_url=server_url,
                allow_remote_viewport=allow_remote_viewport,
                local_viewport_only=local_viewport_only,
            ),
        }
    ]


def _render_cone_markdown_with_policy(
    report: TruthAtlasReport,
    cone: LlmContextConeReport,
) -> str:
    cone_ids = set(cone.matched_seed_ids)
    cone_ids.update(p.id for p in cone.upstream_display_nodes)
    cone_ids.update(p.id for p in cone.manipulator_nodes)
    cone_ids.update(p.id for p in cone.downstream_truth_nodes)
    lines = ["## Policy Field Consumption"]
    entries: list[str] = []
    for item in cone.cone_edge_items:
        pfc = item.policy_field_consumption
        if pfc is None:
            continue
        extra = f" — {pfc.note}" if pfc.note else ""
        entries.append(
            f"- Edge `{item.source_id} -> {item.target_id}`: state=`{pfc.state}` (`{pfc.mechanism}`), "
            f"consumed={pfc.consumed_columns}, unconsumed_policy={pfc.unconsumed_policy_columns}, "
            f"substituted_constants={pfc.substituted_constants}, fallback_constants={pfc.fallback_constants}{extra}"
        )
    for node in report.nodes:
        if node.id not in cone_ids or node.policy_field_consumption is None:
            continue
        pfc = node.policy_field_consumption
        extra = f" — {pfc.note}" if pfc.note else ""
        entries.append(
            f"- Node `{node.id}` (`{node.label}`): state=`{pfc.state}` (`{pfc.mechanism}`), "
            f"consumed={pfc.consumed_columns}, unconsumed_policy={pfc.unconsumed_policy_columns}, "
            f"substituted_constants={pfc.substituted_constants}, fallback_constants={pfc.fallback_constants}{extra}"
        )
    if entries:
        lines.extend(entries[:25])
    else:
        lines.append("- No policy-column consumption annotations in this cone.")
    return f"{cone.markdown}\n\n" + "\n".join(lines)


def _format_findings_markdown(
    report: TruthAtlasReport,
    *,
    rule_code: str | None = None,
    tier: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> str:
    filtered = [
        f
        for f in report.findings
        if (not rule_code or f.rule_code == rule_code) and (not tier or f.tier == tier)
    ]
    page = filtered[offset : offset + limit]
    lines = [
        f"# Findings :: `{report.target_slug}` (showing {len(page)} of {len(filtered)} matching; offset={offset})"
    ]
    for f in page:
        lines.append(
            f"- **{f.rule_code}** [{f.severity}/{f.tier}] `{f.source_file}:{f.line}` (`{f.node_id}`) — {f.title}\n"
            f"  Remediation: {f.remediation}"
        )
    return "\n".join(lines)


def _format_diff_markdown(diff_rep: DiffBlastRadiusReport, *, heading: str | None = None) -> str:
    hdr = heading or (
        f"# Diff Blast Radius :: `{diff_rep.target_slug}` "
        f"(`{diff_rep.base_ref}` -> `{diff_rep.head_commit[:10]}`)"
    )
    out = [
        hdr,
        (
            f"> Verdict: `{diff_rep.diff_verdict}` | Base Graph: `{diff_rep.base_graph_status}` | "
            f"Changed files: {len(diff_rep.changed_files)} | Touched nodes: {len(diff_rep.touched_node_ids)} | "
            f"Blocking new: {diff_rep.blocking_new_findings}"
        ),
        f"- Impacted Truth: {', '.join(diff_rep.impacted_truth_nodes[:15]) or 'none'}",
        f"- Impacted Manipulate: {', '.join(diff_rep.impacted_manipulator_nodes[:15]) or 'none'}",
        f"- Impacted Display: {', '.join(diff_rep.impacted_display_nodes[:15]) or 'none'}",
        f"- Impacted E2E Chains: {len(diff_rep.impacted_chains)}",
    ]
    if diff_rep.removed_nodes:
        out.append(f"- Removed Nodes: {', '.join(n.id for n in diff_rep.removed_nodes[:15])}")
    if diff_rep.commits_in_range:
        out.append(f"\n## Commits in Range ({len(diff_rep.commits_in_range)})")
        for cm in diff_rep.commits_in_range[:15]:
            out.append(f"- `{cm}`")
    if diff_rep.new_findings:
        out.append("\n## Newly Introduced Findings")
        for f in diff_rep.new_findings[:25]:
            out.append(
                f"- **{f.rule_code}** [{f.severity}] `{f.source_file}:{f.line}` — {f.title} | Fix: {f.remediation}"
            )
    return "\n".join(out)


def _render_understanding_chain_markdown(chain: Any) -> str:
    lines = [
        f"# Wythe Six-Link Understanding Chain :: `{chain.example_slug or chain.target_slug or 'bundle'}`",
        f"> Question: {chain.question}",
        f"> Evidence Revision: `{chain.evidence_revision}` | Subject: `{chain.selected_subject_id or 'all'}`",
        f"> **Headline**: {chain.consequence_headline}",
        f"> **Last Supported Cause**: {chain.last_supported_cause}",
        "\n## Six-Link Chain",
    ]
    for lk in chain.links:
        lines.append(f"- **`{lk.link_key}` — {lk.label}** (`{lk.state}`): {lk.consequence_summary}")
    if chain.overall_missing_joins:
        lines.append(f"\n## Missing Joins ({len(chain.overall_missing_joins)})")
        for mj in chain.overall_missing_joins:
            lines.append(f"- `{mj}`")
    lines.append(f"\n> Coverage: {chain.coverage_statement}")
    lines.append("\n```json\n" + chain.model_dump_json(indent=2) + "\n```")
    return "\n".join(lines)


def _execute_investigation_tool(session: Session, args: dict[str, Any]) -> str:
    action = str(args.get("action") or "list_sessions").strip()
    valid_actions = {
        "list_sessions",
        "get_session",
        "create_session",
        "record_correction",
        "set_follow",
        "compare_revisions",
        "get_receipts",
        "list_understanding_examples",
        "get_understanding_example",
        "explain_understanding",
    }
    if action not in valid_actions:
        raise ValueError(
            f"Unsupported `wythe_investigation` action `{action}`; expected one of {sorted(valid_actions)}."
        )
    target_arg = str(args.get("target") or "").strip() or None
    sid = str(args.get("session_id") or "").strip() or None

    if action in (
        "list_understanding_examples",
        "get_understanding_example",
        "explain_understanding",
    ):
        from app.services.understanding_service import (
            UnderstandingAnalyzeRequest,
            analyze_understanding_bundle,
            get_understanding_example,
            list_understanding_examples,
        )

        if action == "list_understanding_examples":
            exs = list_understanding_examples()
            lines = [f"# Wythe Understanding Examples ({len(exs)})"]
            for ex in exs:
                lines.append(f"- `{ex.slug}` :: {ex.title} — {ex.question}")
            lines.append(
                "\n```json\n"
                + json.dumps([ex.model_dump(mode="json") for ex in exs], indent=2)
                + "\n```"
            )
            return "\n".join(lines)

        ex_slug = str(args.get("example_slug") or "").strip() or None
        if action == "get_understanding_example":
            if not ex_slug:
                raise ValueError("`get_understanding_example` requires `example_slug`.")
            ex_read = get_understanding_example(ex_slug)
            return _render_understanding_chain_markdown(ex_read.evaluated_chain)

        eff_target_slug: str | None = None
        if target_arg:
            resolved_t = _resolve_readonly_target(session, target_arg)
            eff_target_slug = resolved_t.slug
        chain = analyze_understanding_bundle(
            UnderstandingAnalyzeRequest(
                target_slug=eff_target_slug,
                example_slug=ex_slug,
                session_id=sid,
                subject_id=str(args.get("subject_id") or args.get("target_ref_id") or "").strip() or None,
                question=str(args.get("question") or "").strip() or None,
                observed_at=str(args.get("observed_at") or "").strip() or None,
                prior_explanation_revision=str(args.get("prior_explanation_revision") or "").strip() or None,
                bundle_path=str(args.get("bundle_path") or "").strip() or None,
            ),
            db=session,
        )
        return _render_understanding_chain_markdown(chain)

    if action == "list_sessions":
        res = list_investigations(target_slug=target_arg)
        lines = [
            f"# Wythe Shared Investigations ({len(res.sessions)})",
            f"> Retention: max_sessions={res.retention_policy.max_sessions}, max_turns={res.retention_policy.max_turns_per_session}, max_events={res.retention_policy.max_events_per_session}",
        ]
        for s in res.sessions:
            lines.append(
                f"- `{s.session_id}` (`{s.target_slug}`, rev={s.session_revision}, focus_rev={s.focus_revision}, "
                f"follow=`{s.follow_state}`, turns={s.turn_count}, corrections={s.correction_count}) — {s.title}"
            )
        lines.append("\n```json\n" + res.model_dump_json(indent=2) + "\n```")
        return "\n".join(lines)

    if action == "create_session":
        if not target_arg:
            raise ValueError("`create_session` requires `target`.")
        resolved_t = _resolve_readonly_target(session, target_arg)
        inv = create_or_reopen_investigation(
            session,
            InvestigationCreateRequest(
                target_slug=resolved_t.slug,
                session_id=sid,
                client_id=args.get("client_id"),
                title=args.get("title"),
            ),
        )
        return _render_investigation_resource_markdown(inv)

    if action == "get_receipts":
        cmd_id = str(args.get("command_id") or "").strip() or None
        receipts = list_viewport_receipts(
            target_slug=target_arg,
            session_id=sid,
            command_id=cmd_id,
            limit=40,
        )
        vp_state = (
            get_viewport_state(target_arg, session_id=sid)
            if target_arg
            else None
        )
        payload = {
            "receipts": [r.model_dump(mode="json") for r in receipts],
            "latest_command": vp_state.latest.model_dump(mode="json") if (vp_state and vp_state.latest) else None,
        }
        return (
            f"# Viewport Delivery Receipts ({len(receipts)})\n\n"
            f"```json\n{json.dumps(payload, indent=2)}\n```"
        )

    if not sid:
        raise ValueError(f"`{action}` requires `session_id`.")

    if action == "get_session":
        inv_obj = get_investigation_session(sid)
        if inv_obj is None:
            raise ValueError(f"Investigation session `{sid}` not found.")
        since_rev = args.get("since_revision")
        if since_rev is not None:
            deltas = get_investigation_delta_events(sid, since_revision=int(since_rev))
            return (
                _render_investigation_resource_markdown(inv_obj)
                + "\n\n## Delta Events\n```json\n"
                + deltas.model_dump_json(indent=2)
                + "\n```"
            )
        return _render_investigation_resource_markdown(inv_obj)

    if action == "record_correction":
        note = str(args.get("note") or "").strip()
        if not note:
            raise ValueError("`record_correction` requires non-empty `note`.")
        corr = add_investigation_correction(
            sid,
            InvestigationCorrectionCreate(
                client_id=args.get("client_id"),
                actor="agent",
                target_ref_id=args.get("target_ref_id"),
                turn_id=args.get("turn_id"),
                kind=str(args.get("kind") or "clarification"),
                note=note,
            ),
        )
        return (
            f"# Recorded Investigation Correction `{corr.correction_id}`\n"
            f"> Session: `{sid}` | Promoted to governance ruling: `{corr.promoted_to_ruling}`\n\n"
            f"```json\n{corr.model_dump_json(indent=2)}\n```"
        )

    if action == "set_follow":
        fstate = args.get("follow_state")
        if fstate not in ("following", "paused"):
            raise ValueError("`set_follow` requires `follow_state` ('following' or 'paused').")
        updated = update_investigation_follow(
            sid,
            InvestigationFollowUpdate(
                client_id=args.get("client_id"),
                actor="agent",
                follow_state=fstate,
                reason=str(args.get("reason") or ""),
            ),
        )
        return _render_investigation_resource_markdown(updated)

    comp = compare_investigation_revisions(session, sid)
    return f"{comp.summary_markdown}\n\n```json\n{comp.model_dump_json(indent=2)}\n```"


def _execute_tool(
    session: Session,
    tool_name: str,
    args: dict[str, Any],
    *,
    server_url: str | None = None,
    allow_remote_viewport: bool = False,
    local_viewport_only: bool = False,
) -> str:
    canonical = tool_name.replace("atlas_", "wythe_", 1) if tool_name.startswith("atlas_") else tool_name
    if canonical == "wythe_list_targets":
        targets = list_targets(session)
        profiles = [p for p in list_stack_profiles(session) if p.is_enabled]
        lines = ["## Registered Targets"]
        for t in targets:
            lines.append(f"- `{t.slug}` ({t.stack_profile_slug}) -> `{t.repo_path}`")
        lines.append(f"\n## Enabled Stack Profiles ({len(profiles)})")
        for p in profiles:
            lines.append(f"- `{p.slug}`: {p.truth_adapter} + {p.manipulator_adapter} + {p.display_adapter}")
        return "\n".join(lines)

    if canonical == "wythe_plugins":
        load_errors: list[str] = []
        specs = discover_plugins(
            include_builtins=True,
            include_entry_points=True,
            allow_local_plugins=False,
            strict_plugins=False,
            notes_out=load_errors,
        )
        lines = [
            f"# Registered Wythe Plugins ({len(specs)})",
            "> Security boundary: `local_plugins_allowed=false` (untrusted repo code is never imported).",
        ]
        for spec in specs:
            state = "enabled" if spec.enabled_by_default else "disabled"
            ver = spec.version or "unknown"
            sup_caps, unsup_caps = spec.resolved_interaction_capabilities()
            ev_kinds = spec.resolved_evidence_source_kinds()
            zoom_tag = (
                f" | StratumPlugin zooms={list(spec.supported_zooms or (2, 3))}"
                if spec.kind == "stratum_inspector"
                else ""
            )
            lines.append(
                f"- `{spec.name}` [{spec.kind} | {spec.origin} | v{ver} | {state}{zoom_tag}] "
                f"sources={ev_kinds} caps={sup_caps} unsupported={unsup_caps} — {spec.description}"
            )
        if load_errors:
            lines.append(f"\n## Isolated Load Errors ({len(load_errors)})")
            for err in load_errors:
                lines.append(f"- {err}")
        return "\n".join(lines)

    if canonical == "wythe_investigation":
        return _execute_investigation_tool(session, args)

    if canonical == "wythe_understanding":
        und_action = str(args.get("action") or "explain_understanding")
        return _execute_investigation_tool(session, {**args, "action": und_action})

    if canonical in ("wythe_focus_camera", "wythe_camera_tour"):
        return _execute_camera_choreography_tool(
            session,
            canonical,
            args,
            server_url=server_url,
            allow_remote_viewport=allow_remote_viewport,
            local_viewport_only=local_viewport_only,
        )

    raw_target = str(args.get("target") or "").strip()
    if not raw_target:
        raise ValueError("Missing required parameter `target` (slug or directory path).")
    profile = str(args.get("profile") or "auto")
    target = _resolve_readonly_target(session, raw_target, profile=profile)
    report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    if canonical == "wythe_overview":
        max_tok = int(args.get("max_tokens") or DEFAULT_BRIEF_TOKENS)
        return build_llms_txt_brief(report, max_tokens=max_tok).markdown

    if canonical == "wythe_context":
        section = str(args.get("section") or "all").strip().lower()
        if section not in ("overview", "focus", "findings", "all"):
            raise ValueError(
                f"Invalid `section` `{section}`. Expected one of: `overview`, `focus`, `findings`, `all`."
            )
        parts: list[str] = []
        if section in ("overview", "all"):
            tok_budget = 1100 if section == "all" else DEFAULT_BRIEF_TOKENS
            parts.append(build_llms_txt_brief(report, max_tokens=tok_budget).markdown)
        if section in ("focus", "all"):
            explain = explain_ui_focus(
                session, target_project=target, precomputed_report=report
            )
            if section == "focus":
                parts.append(explain.markdown_brief)
            else:
                focus_lines = [
                    "## Active UI Focus Summary",
                    f"- Headline: {explain.headline}",
                    f"- Lens / Layout / Blast: `{explain.lens}` / `{explain.layout_mode}` / `{explain.blast_mode}`",
                    f"- Why It Looks Like This: {explain.color_reason}",
                ]
                if explain.focused_node is not None:
                    focus_lines.append(
                        f"- Focused Node: `{explain.focused_node.id}` (`{explain.focused_node.pointer}`, status=`{explain.focused_node.status}`)"
                    )
                if explain.has_snapshot:
                    st_label = "stale" if explain.snapshot_stale else "fresh"
                    focus_lines.append(
                        f"- Viewport Snapshot: `{explain.snapshot_mime_type or 'image/png'}` ({st_label})"
                    )
                parts.append("\n".join(focus_lines))
        if section in ("findings", "all"):
            lim = 12 if section == "all" else 25
            parts.append(_format_findings_markdown(report, limit=lim, offset=0))
        return "\n\n".join(parts)

    if canonical == "wythe_lineage_cone":
        query = str(args.get("query") or "").strip()
        if not query:
            raise ValueError("Missing required parameter `query`.")
        max_nodes = int(args.get("max_nodes") or DEFAULT_CONE_NODES)
        full = bool(args.get("full", False))
        zoom = _parse_cone_zoom(args.get("zoom", 1))
        unfiltered_ir = bool(args.get("unfiltered_ir", False))
        cone = build_lineage_cone_slice(
            report,
            query,
            max_nodes=max_nodes,
            full=full,
            zoom=zoom,
            unfiltered_ir=unfiltered_ir,
        )
        if not cone.matched_seed_ids:
            raise ValueError(_format_unmatched_query_error(report, query, cone.suggestions))
        return _render_cone_markdown_with_policy(report, cone)

    if canonical == "wythe_blast_radius":
        base_ref = str(args.get("base_ref") or "WORKING")
        diff_rep = run_target_diff(session, target, report, base_ref)
        return _format_diff_markdown(diff_rep)

    if canonical == "wythe_check_change":
        base_ref = str(args.get("base_ref") or "WORKING")
        s = report.summary
        gate_lines = [
            f"# Change Check :: `{report.target_slug}` @ `{report.source_commit[:10]}`",
            "## 1. Strict 3-Tier Gate",
            (
                f"> Gate Verdict: `{report.gate.verdict}` (mode=`{report.gate.mode}`, "
                f"blocking={s.blocking_findings}, warnings={s.warning_findings}, "
                f"coverage_complete={report.coverage_complete})"
            ),
        ]
        for row in report.gate.rule_counts:
            if row.observed_count > 0:
                gate_lines.append(
                    f"- **{row.rule_code}** [{row.tier}] count={row.observed_count} ({row.status}) — {row.title}"
                )
        diff_rep = run_target_diff(session, target, report, base_ref)
        diff_section = _format_diff_markdown(
            diff_rep,
            heading=f"## 2. Git Diff Blast Radius (`{diff_rep.base_ref}` -> `{diff_rep.head_commit[:10]}`)",
        )
        return "\n".join(gate_lines) + "\n\n" + diff_section

    if canonical == "wythe_findings":
        rcode = args.get("rule_code")
        tier = args.get("tier")
        limit = max(1, min(100, int(args.get("limit") or 25)))
        offset = max(0, int(args.get("offset") or 0))
        return _format_findings_markdown(
            report,
            rule_code=str(rcode) if rcode else None,
            tier=str(tier) if tier else None,
            limit=limit,
            offset=offset,
        )

    if canonical == "wythe_openlineage":
        bundle = build_openlineage_static_bundle(report)
        datasets: list[dict[str, Any]] = bundle["datasets"]  # type: ignore[assignment]
        jobs: list[dict[str, Any]] = bundle["jobs"]  # type: ignore[assignment]
        active_jobs = [j for j in jobs if j.get("inputs") or j.get("outputs")]
        lines = [
            f"# Static OpenLineage Bundle :: `{report.target_slug}` (`{report.source_commit[:10]}`)",
            f"> Schema: `{bundle['schemaURL']}` | Datasets: {len(datasets)} | Jobs: {len(jobs)} ({len(active_jobs)} with dataset lineage)",
            f"> Notice: {bundle['nonCertificationNotice']}",
            f"\n## Datasets ({len(datasets)})",
        ]
        for ds in datasets[:40]:
            fields = ds.get("facets", {}).get("schema", {}).get("fields", [])
            lines.append(f"- `{ds['namespace']}/{ds['name']}` ({len(fields)} column(s))")
        lines.append(f"\n## Jobs with Inputs/Outputs (showing {min(len(active_jobs), 40)} of {len(active_jobs)})")
        for job in active_jobs[:40]:
            ins = ", ".join(r["name"] for r in job.get("inputs", ())) or "none"
            outs = ", ".join(r["name"] for r in job.get("outputs", ())) or "none"
            lines.append(f"- `{job['name']}` ({job['namespace']}) :: inputs=[{ins}] -> outputs=[{outs}]")
        return "\n".join(lines)

    unique_names = list(dict.fromkeys(t["name"] for t in [*MCP_SLM_TOOLS, *MCP_TOOLS]))
    all_known = ", ".join(f"`{name}`" for name in unique_names)
    raise ValueError(f"Unknown tool `{tool_name}`. Available Wythe MCP tools: {all_known}.")


def run_mcp_stdio_server(
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    slice_mode: str = "full",
    *,
    server_url: str | None = None,
    allow_remote_viewport: bool = False,
) -> int:
    """Serve JSON-RPC 2.0 MCP requests over stdio (supports JSON-lines and Content-Length framing)."""
    active_slice = normalize_mcp_slice(slice_mode)
    from app.main import initialize_database

    initialize_database()
    factory = get_session_factory()
    in_stream = stdin or sys.stdin.buffer
    out_stream = stdout or sys.stdout.buffer

    while True:
        raw_line = in_stream.readline()
        if not raw_line:
            break
        stripped = raw_line.strip()
        if not stripped:
            continue

        use_headers = False
        if stripped.lower().startswith(b"content-length:"):
            use_headers = True
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hdr = in_stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            payload_bytes = in_stream.read(length)
        else:
            payload_bytes = stripped

        try:
            msg = json.loads(payload_bytes.decode("utf-8"))
        except ValueError:
            continue

        try:
            with factory() as session:
                resp = dispatch_mcp_request(
                    session,
                    msg,
                    slice_mode=active_slice,
                    server_url=server_url,
                    allow_remote_viewport=allow_remote_viewport,
                )
        except Exception as exc:  # noqa: BLE001
            err_id = msg.get("id") if isinstance(msg, dict) else None
            if err_id is None and isinstance(msg, dict):
                continue
            resp = {
                "jsonrpc": "2.0",
                "id": err_id,
                "error": {"code": -32603, "message": f"Internal MCP error: {exc}"},
            }
        if resp is None:
            continue
        encoded = json.dumps(resp, separators=(",", ":")).encode("utf-8")
        if use_headers:
            out_stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
        else:
            out_stream.write(encoded + b"\n")
        out_stream.flush()
    return 0
