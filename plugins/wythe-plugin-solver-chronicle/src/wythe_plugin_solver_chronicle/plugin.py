"""Wythe plugin registration, `PostScanCheckPlugin` hook, and MCP tool handler."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar, Final

from app.schemas.atlas import TruthAtlasReport
from app.services.mcp_service import _resolve_target_for_mcp
from app.services.scanner_service import run_target_scan
from wythe_plugin_solver_chronicle.log_parser import (
    CpModelProtoSummary,
    CpSolverResponseSummary,
    IncrementalSolverLogParser,
    parse_cp_model_proto_file,
    parse_cp_solver_response_file,
    read_safe_companion_text,
)
from wythe_plugin_solver_chronicle.synthesizer import (
    build_chronicle_permalink,
    build_chronicle_viewport_command,
    publish_chronicle_to_viewport,
    serialize_chronicle_payload,
    synthesize_solver_chronicle,
)

MCP_SOLVER_CHRONICLE_DEFINITION: Final[dict[str, Any]] = {
    "name": "wythe_solver_chronicle",
    "description": (
        "Synthesize the 6-phase causal 3-tier solver chronicle (`[1.Load]` -> `[6.Render]`), "
        "classify `MODEL_INVALID` / `INFEASIBLE` / search-pathology forensics back to `Z=0` AST "
        "builders (`file:line`) and `[1.Load]` Truth tables, and optionally publish the timeline "
        "and `#chronicle=...&phase=...` permalink to connected 3D viewports."
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
                "description": "Registered target slug or repository path.",
            },
            "solve_log_path": {
                "type": "string",
                "description": "Optional repository-contained CP-SAT `log_search_progress=true` log file path.",
            },
            "solve_log_text": {
                "type": "string",
                "description": "Optional inline CP-SAT `solve_log` text for direct replay.",
            },
            "cp_model_proto_path": {
                "type": "string",
                "description": "Optional repository-contained `CpModelProto` JSON or `.pbtxt` file path.",
            },
            "cp_solver_response_path": {
                "type": "string",
                "description": "Optional repository-contained `CpSolverResponse` JSON or `.pbtxt` file path.",
            },
            "telemetry_jsonl_path": {
                "type": "string",
                "description": "Optional repository-contained solution-callback JSONL stream path.",
            },
            "phase_index": {
                "type": "integer",
                "minimum": 0,
                "maximum": 5,
                "description": "Optional phase focus override (0=`1.Load` .. 5=`6.Render`).",
            },
            "publish_viewport": {
                "type": "boolean",
                "default": True,
                "description": "Publish `ViewportCommand` and `ChronicleFrame[]` to the loopback viewport bus.",
            },
            "timeline_id": {
                "type": "string",
                "description": "Optional explicit chronicle timeline ID.",
            },
            "session_id": {
                "type": "string",
                "description": "Optional browser session ID for multi-tab viewport scoping.",
            },
            "profile": {
                "type": "string",
                "default": "auto",
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    },
}

_ALLOWED_MCP_KEYS: Final[frozenset[str]] = frozenset(
    MCP_SOLVER_CHRONICLE_DEFINITION["inputSchema"]["properties"].keys()
)
_STRING_ARG_KEYS: Final[tuple[str, ...]] = (
    "target",
    "solve_log_path",
    "solve_log_text",
    "cp_model_proto_path",
    "cp_solver_response_path",
    "telemetry_jsonl_path",
    "timeline_id",
    "session_id",
    "profile",
)


def handle_mcp_solver_chronicle(session: Any, args: dict[str, Any]) -> str:
    """MCP handler for `wythe_solver_chronicle`."""
    if not isinstance(args, dict):
        raise TypeError("`arguments` must be a JSON object.")
    unknown = sorted(set(args) - _ALLOWED_MCP_KEYS)
    if unknown:
        raise ValueError(
            f"Unsupported argument(s) for `wythe_solver_chronicle`: {', '.join(unknown)}."
        )

    for skey in _STRING_ARG_KEYS:
        sval = args.get(skey)
        if sval is not None and not isinstance(sval, str):
            raise ValueError(f"`{skey}` must be a string when provided.")

    raw_pub = args.get("publish_viewport")
    if raw_pub is None:
        publish_vp = True
    elif isinstance(raw_pub, bool):
        publish_vp = raw_pub
    else:
        raise ValueError("`publish_viewport` must be a boolean.")

    raw_phase = args.get("phase_index")
    if raw_phase is not None and (isinstance(raw_phase, bool) or not isinstance(raw_phase, int)):
        raise ValueError("`phase_index` must be an integer in 0..5, not boolean.")

    profile = str(args.get("profile") or "auto")
    target = _resolve_target_for_mcp(session, args.get("target"), profile=profile)
    repo_root = Path(target.repo_path).resolve()
    report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    proto: CpModelProtoSummary | None = None
    if args.get("cp_model_proto_path"):
        proto = parse_cp_model_proto_file(args["cp_model_proto_path"], repo_root=repo_root)

    resp: CpSolverResponseSummary | None = None
    if args.get("cp_solver_response_path"):
        resp = parse_cp_solver_response_file(
            args["cp_solver_response_path"], repo_root=repo_root
        )

    inc_parser = IncrementalSolverLogParser()
    if resp is not None:
        inc_parser.apply_response_summary(resp)
    if args.get("telemetry_jsonl_path"):
        t_text = read_safe_companion_text(args["telemetry_jsonl_path"], repo_root=repo_root)
        for tline in t_text.splitlines():
            inc_parser.feed_telemetry_jsonl_line(tline)
    if args.get("solve_log_path"):
        l_text = read_safe_companion_text(args["solve_log_path"], repo_root=repo_root)
        inc_parser.feed_lines(l_text.splitlines())
    if args.get("solve_log_text"):
        inc_parser.feed_lines(str(args["solve_log_text"]).splitlines())

    has_runtime = any(
        bool(args.get(k))
        for k in ("solve_log_path", "solve_log_text", "cp_solver_response_path", "telemetry_jsonl_path")
    )
    synthesis = synthesize_solver_chronicle(
        repo_root,
        report,
        session=inc_parser.snapshot() if has_runtime else None,
        proto=proto,
        response=resp,
        timeline_id=args.get("timeline_id"),
        phase_index=raw_phase,
    )

    vp_seq: int | None = None
    if publish_vp:
        ack, permalink = publish_chronicle_to_viewport(
            synthesis, session_id=args.get("session_id")
        )
        vp_seq = ack.seq
    else:
        cmd = build_chronicle_viewport_command(synthesis, session_id=args.get("session_id"))
        permalink = build_chronicle_permalink(
            cmd,
            timeline_id=synthesis.timeline_id,
            phase_index=synthesis.active_phase_index,
        )

    payload = serialize_chronicle_payload(
        synthesis,
        permalink=permalink,
        published_to_viewport=publish_vp,
        viewport_seq=vp_seq,
    )
    md_lines = [
        f"# {synthesis.title}",
        (
            f"> Timeline: `{synthesis.timeline_id}` | Active Phase: `{synthesis.active_phase_index}` "
            f"(`{synthesis.frames[synthesis.active_phase_index].phase_key}`) | "
            f"Live Follow: `{synthesis.live_following}` | Viewport Published: `{publish_vp}`"
        ),
        f"- **Canonical Permalink**: `{permalink}`",
    ]
    if synthesis.forensics.forensic_class:
        md_lines.append(
            f"- **Forensic Class**: `{synthesis.forensics.forensic_class}` — {synthesis.forensics.summary}"
        )
    for frame in synthesis.frames:
        md_lines.append(
            f"- `{frame.phase_key}` [{frame.status.upper()} | {frame.tier}]: {frame.caption}"
        )
    md_lines.append("\n## Chronicle Artifact JSON")
    md_lines.append("```json\n" + json.dumps(payload, indent=2) + "\n```")
    return "\n".join(md_lines)


def _invoke_watch_solver_cli(argv: list[str]) -> int:
    from wythe_plugin_solver_chronicle.cli import run_watch_solver_cli

    return run_watch_solver_cli(argv)


class SolverChroniclePlugin:
    """Optional Wythe companion plugin providing 6-phase solver chronicles & forensics."""

    name: str = "solver-chronicle"
    version: str = "0.1.0"
    description: str = (
        "Phase-ordered 3-tier solver chronicle, passive `wythe watch-solver` log watcher, "
        "and `MODEL_INVALID`/`INFEASIBLE` log forensics."
    )
    enabled_by_default: bool = True

    cli_subcommands: ClassVar[dict[str, Callable[[list[str]], int]]] = {
        "watch-solver": _invoke_watch_solver_cli,
    }
    mcp_tools: ClassVar[tuple[dict[str, Any], ...]] = (
        {
            "name": "wythe_solver_chronicle",
            "definition": MCP_SOLVER_CHRONICLE_DEFINITION,
            "handler": handle_mcp_solver_chronicle,
        },
    )

    def check_report(self, repo_root: Path, report: TruthAtlasReport) -> dict[str, object]:
        """Inspect static 6-phase solver lineage readiness without mutating `Z=0` scan digests."""
        isolated = report.model_copy(deep=True)
        synthesis = synthesize_solver_chronicle(repo_root, isolated)
        return {
            "plugin": self.name,
            "version": self.version,
            "has_solver_pipeline": bool(synthesis.ast_profile.solver_node_ids),
            "phase_count": len(synthesis.frames),
            "chronicle_frames": [f.model_dump() for f in synthesis.frames],
            "findings": [],
            "notes": [],
        }


WYTHE_PLUGIN = SolverChroniclePlugin()


def register_wythe_plugin() -> SolverChroniclePlugin:
    """Entry-point hook for `wythe.plugins` (`solver-chronicle`)."""
    return WYTHE_PLUGIN
