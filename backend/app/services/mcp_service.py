"""Zero-dependency read-only Model Context Protocol (MCP) stdio server for Wythe."""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path
from typing import Any, BinaryIO

from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.db.session import get_session_factory
from app.models import TargetProject
from app.services.diff_and_sarif_service import compute_diff_and_blast_radius
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
from app.services.ui_focus_service import explain_ui_focus

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
                "max_nodes": {"type": "integer", "default": DEFAULT_CONE_NODES, "minimum": 5, "maximum": 150},
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
]


def _resolve_readonly_target(session: Session, target_or_path: str, profile: str = "auto") -> TargetProject:
    existing = get_target_by_slug(session, target_or_path)
    if existing is not None:
        return existing
    candidate = Path(target_or_path).expanduser().resolve()
    if not candidate.is_dir():
        known = ", ".join(t.slug for t in list_targets(session)) or "none"
        raise ValueError(
            f"Target '{target_or_path}' is neither a registered slug ({known}) nor an existing directory."
        )
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


def dispatch_mcp_request(session: Session, msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process one JSON-RPC 2.0 MCP request message; returns `None` for notifications."""
    method = msg.get("method", "")
    req_id = msg.get("id")
    if req_id is None:
        return None

    if method == "initialize":
        params = msg.get("params") or {}
        proto = params.get("protocolVersion") or "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": proto,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "wythe", "version": "0.1.1"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}
    if method != "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    params = msg.get("params") or {}
    tool_name = params.get("name", "")
    args = params.get("arguments") or {}
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
        explain = explain_ui_focus(session, target_override=target_ovr)
        blocks: list[dict[str, Any]] = [{"type": "text", "text": explain.markdown_brief}]
        if bool(args.get("include_image")) and explain.snapshot_path:
            snap_file = Path(explain.snapshot_path)
            if snap_file.is_file():
                b64 = base64.b64encode(snap_file.read_bytes()).decode("ascii")
                blocks.append({"type": "image", "data": b64, "mimeType": "image/png"})
        return blocks
    return [{"type": "text", "text": _execute_tool(session, tool_name, args)}]


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

    raw_target = str(args.get("target") or "").strip()
    if not raw_target:
        raise ValueError("Missing required parameter `target` (slug or directory path).")
    profile = str(args.get("profile") or "auto")
    target = _resolve_readonly_target(session, raw_target, profile=profile)
    report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    if canonical == "wythe_overview":
        max_tok = int(args.get("max_tokens") or DEFAULT_BRIEF_TOKENS)
        return build_llms_txt_brief(report, max_tokens=max_tok).markdown

    if canonical == "wythe_lineage_cone":
        query = str(args.get("query") or "").strip()
        if not query:
            raise ValueError("Missing required parameter `query`.")
        max_nodes = int(args.get("max_nodes") or DEFAULT_CONE_NODES)
        return build_lineage_cone_slice(report, query, max_nodes=max_nodes).markdown

    if canonical == "wythe_blast_radius":
        base_ref = str(args.get("base_ref") or "WORKING")
        diff_rep = compute_diff_and_blast_radius(
            Path(target.repo_path).resolve(), report, base_ref=base_ref
        )
        out = [
            f"# Diff Blast Radius :: `{diff_rep.target_slug}` (`{diff_rep.base_ref}` -> `{diff_rep.head_commit[:10]}`)",
            f"> Verdict: `{diff_rep.diff_verdict}` | Changed files: {len(diff_rep.changed_files)} | Touched nodes: {len(diff_rep.touched_node_ids)} | Blocking new: {diff_rep.blocking_new_findings}",
            f"- Impacted Truth: {', '.join(diff_rep.impacted_truth_nodes[:15]) or 'none'}",
            f"- Impacted Manipulate: {', '.join(diff_rep.impacted_manipulator_nodes[:15]) or 'none'}",
            f"- Impacted Display: {', '.join(diff_rep.impacted_display_nodes[:15]) or 'none'}",
            f"- Impacted E2E Chains: {len(diff_rep.impacted_chains)}",
        ]
        if diff_rep.commits_in_range:
            out.append(f"\n## Commits in Range ({len(diff_rep.commits_in_range)})")
            for cm in diff_rep.commits_in_range[:15]:
                out.append(f"- `{cm}`")
        if diff_rep.new_findings:
            out.append("\n## Newly Introduced Findings")
            for f in diff_rep.new_findings[:25]:
                out.append(f"- **{f.rule_code}** [{f.severity}] `{f.source_file}:{f.line}` — {f.title} | Fix: {f.remediation}")
        return "\n".join(out)

    if canonical == "wythe_findings":
        rcode = args.get("rule_code")
        tier = args.get("tier")
        limit = max(1, min(100, int(args.get("limit") or 25)))
        offset = max(0, int(args.get("offset") or 0))
        filtered = [
            f
            for f in report.findings
            if (not rcode or f.rule_code == rcode) and (not tier or f.tier == tier)
        ]
        page = filtered[offset : offset + limit]
        lines = [
            f"# Findings :: `{report.target_slug}` (showing {len(page)} of {len(filtered)} matching; offset={offset})"
        ]
        for f in page:
            lines.append(
                f"- **{f.rule_code}** [{f.severity}/{f.tier}] `{f.source_file}:{f.line}` (`{f.node_id}`) — {f.title}\n  Remediation: {f.remediation}"
            )
        return "\n".join(lines)

    raise ValueError(f"Unknown tool '{tool_name}'.")


def run_mcp_stdio_server(
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> int:
    """Serve JSON-RPC 2.0 MCP requests over stdio (supports JSON-lines and Content-Length framing)."""
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

        with factory() as session:
            resp = dispatch_mcp_request(session, msg)
        if resp is None:
            continue
        encoded = json.dumps(resp, separators=(",", ":")).encode("utf-8")
        if use_headers:
            out_stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
        else:
            out_stream.write(encoded + b"\n")
        out_stream.flush()
    return 0
