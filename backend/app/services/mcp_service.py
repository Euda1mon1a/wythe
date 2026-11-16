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
from app.adapters.plugin_registry import discover_plugins
from app.db.session import get_session_factory
from app.models import TargetProject
from app.schemas.atlas import DiffBlastRadiusReport, LlmContextConeReport, TruthAtlasReport
from app.services.companion_export_service import build_openlineage_static_bundle
from app.services.diff_and_sarif_service import run_target_diff
from app.services.governance_service import (
    get_target_by_slug,
    list_stack_profiles,
    list_targets,
)
from app.services.llm_context_service import (
    DEFAULT_BRIEF_TOKENS,
    DEFAULT_CONE_NODES,
    build_lineage_cone_slice,
    build_llms_txt_brief,
)
from app.services.scanner_service import run_target_scan
from app.services.ui_focus_service import explain_ui_focus, read_saved_ui_focus_state

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
            "or highlighting in the live 3D Wythe GUI (node, vertical district, lens, blast-overlay reason, "
            "and optional annotated WebGL PNG image). Call this whenever the user asks 'what is this?' or "
            "'what is this red cluster?' without needing any node ID or copy-paste."
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Optional target slug override (defaults to active GUI target)."},
                "include_image": {"type": "boolean", "default": False, "description": "Include latest annotated 3D viewport PNG block if captured."},
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
        "description": "Explain live 3D camera frustum focus and optional viewport image.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Optional target slug."},
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
]


def normalize_mcp_slice(slice_mode: str | None = "full") -> McpSliceMode:
    """Validate and normalize MCP tool slice mode (`full` default or compact `slm`)."""
    cleaned = (slice_mode or "full").strip().lower()
    if cleaned not in ("full", "slm"):
        raise ValueError(f"Unsupported MCP slice `{slice_mode}`; expected `full` or `slm`.")
    return "slm" if cleaned == "slm" else "full"


def get_mcp_tools(slice_mode: str = "full") -> list[dict[str, Any]]:
    """Return the advertised MCP tool schemas for `full` (8 tools) or `slm` (4 tools)."""
    return MCP_SLM_TOOLS if normalize_mcp_slice(slice_mode) == "slm" else MCP_TOOLS


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


def list_mcp_resources(session: Session) -> list[dict[str, Any]]:
    """List concrete `wythe://` MCP resources for registered targets plus active UI-focus target."""
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
    return resources


def read_mcp_resource(session: Session, uri: str) -> list[dict[str, Any]]:
    """Read a `wythe://{slug}/...` resource URI and return MCP `contents` items."""
    cleaned = uri.strip()
    if not cleaned.startswith("wythe://"):
        raise ValueError(
            f"Unsupported resource URI `{uri}`; expected `wythe://<slug>/llms`, "
            "`wythe://<slug>/ui-focus`, `wythe://<slug>/findings`, or `wythe://<slug>/cone/<node_id>`."
        )
    remainder = cleaned.removeprefix("wythe://")
    raw_slug, sep, raw_path = remainder.partition("/")
    slug = urllib.parse.unquote(raw_slug).strip()
    resource_path = raw_path.strip("/")
    if not slug or not sep or not resource_path:
        raise ValueError(
            f"Malformed resource URI `{uri}`; expected `wythe://<slug>/llms|ui-focus|findings|cone/<node_id>`."
        )

    node_query = ""
    if resource_path.startswith("cone/"):
        node_query = urllib.parse.unquote(resource_path.removeprefix("cone/")).strip()
        if not node_query:
            raise ValueError(f"Missing `<node_id>` in cone resource URI `{cleaned}`.")
    elif resource_path not in ("llms", "ui-focus", "findings"):
        raise ValueError(
            f"Unknown resource path `{resource_path}` in `{cleaned}`. "
            "Supported paths: `llms`, `ui-focus`, `findings`, `cone/{node_id}`."
        )

    target = get_target_by_slug(session, slug)
    if target is None:
        raise LookupError(_format_unknown_target_error(session, slug, for_uri=cleaned))

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

    cone = build_lineage_cone_slice(report, node_query, max_nodes=DEFAULT_CONE_NODES, full=False)
    if not cone.matched_seed_ids:
        raise LookupError(_format_unmatched_query_error(report, node_query, cone.suggestions))
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
        except ValueError as exc:
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
    try:
        content_blocks = _execute_tool_blocks(session, tool_name, args)
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


def _execute_tool_blocks(
    session: Session, tool_name: str, args: dict[str, Any]
) -> list[dict[str, Any]]:
    canonical = tool_name.replace("atlas_", "wythe_", 1) if tool_name.startswith("atlas_") else tool_name
    if canonical in ("wythe_what_is_this", "wythe_active_view"):
        target_ovr = str(args.get("target") or "").strip() or None
        if target_ovr and get_target_by_slug(session, target_ovr) is None:
            resolved_proj = _resolve_readonly_target(session, target_ovr)
            explain = explain_ui_focus(session, target_project=resolved_proj)
        else:
            explain = explain_ui_focus(session, target_override=target_ovr)
        blocks: list[dict[str, Any]] = [{"type": "text", "text": explain.markdown_brief}]
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
    return [{"type": "text", "text": _execute_tool(session, tool_name, args)}]


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


def _execute_tool(session: Session, tool_name: str, args: dict[str, Any]) -> str:
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
            lines.append(
                f"- `{spec.name}` [{spec.kind} | {spec.origin} | v{ver} | {state}] — {spec.description}"
            )
        if load_errors:
            lines.append(f"\n## Isolated Load Errors ({len(load_errors)})")
            for err in load_errors:
                lines.append(f"- {err}")
        return "\n".join(lines)

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
        cone = build_lineage_cone_slice(report, query, max_nodes=max_nodes, full=full)
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
                resp = dispatch_mcp_request(session, msg, slice_mode=active_slice)
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
