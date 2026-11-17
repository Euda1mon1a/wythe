"""`wythe-plugin-solver-chronicle` — 6-phase 3-tier solver chronicle & log forensics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from wythe_plugin_solver_chronicle.forensics import (
    ForensicClassKind,
    ForensicPathology,
    ForensicReport,
    RepoSolverAstProfile,
    Z0BuilderResolution,
    classify_solver_forensics,
    inspect_repo_solver_ast,
)
from wythe_plugin_solver_chronicle.log_parser import (
    CpModelProtoSummary,
    CpSolverResponseSummary,
    IncrementalSolverLogParser,
    IncumbentStep,
    ParsedSolverSession,
    SolverRunSummary,
    ValidationDiagnostic,
    parse_cp_model_proto_file,
    parse_cp_model_proto_text,
    parse_cp_solver_response_file,
    parse_cp_solver_response_text,
    parse_solve_log_text,
    read_safe_companion_bytes,
    read_safe_companion_text,
    resolve_safe_companion_path,
)
from wythe_plugin_solver_chronicle.plugin import (
    MCP_SOLVER_CHRONICLE_DEFINITION,
    WYTHE_PLUGIN,
    SolverChroniclePlugin,
    handle_mcp_solver_chronicle,
    register_wythe_plugin,
)
from wythe_plugin_solver_chronicle.synthesizer import (
    ChronicleSynthesisResult,
    build_chronicle_permalink,
    build_chronicle_viewport_command,
    publish_chronicle_to_viewport,
    serialize_chronicle_payload,
    synthesize_solver_chronicle,
)

if TYPE_CHECKING:
    from wythe_plugin_solver_chronicle.cli import main as watch_solver_main
    from wythe_plugin_solver_chronicle.cli import run_watch_solver_cli


def __getattr__(name: str) -> object:
    if name in ("run_watch_solver_cli", "watch_solver_main"):
        from wythe_plugin_solver_chronicle import cli as _cli_mod

        return _cli_mod.main if name == "watch_solver_main" else _cli_mod.run_watch_solver_cli
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "MCP_SOLVER_CHRONICLE_DEFINITION",
    "WYTHE_PLUGIN",
    "ChronicleSynthesisResult",
    "CpModelProtoSummary",
    "CpSolverResponseSummary",
    "ForensicClassKind",
    "ForensicPathology",
    "ForensicReport",
    "IncrementalSolverLogParser",
    "IncumbentStep",
    "ParsedSolverSession",
    "RepoSolverAstProfile",
    "SolverChroniclePlugin",
    "SolverRunSummary",
    "ValidationDiagnostic",
    "Z0BuilderResolution",
    "build_chronicle_permalink",
    "build_chronicle_viewport_command",
    "classify_solver_forensics",
    "handle_mcp_solver_chronicle",
    "inspect_repo_solver_ast",
    "parse_cp_model_proto_file",
    "parse_cp_model_proto_text",
    "parse_cp_solver_response_file",
    "parse_cp_solver_response_text",
    "parse_solve_log_text",
    "publish_chronicle_to_viewport",
    "read_safe_companion_bytes",
    "read_safe_companion_text",
    "register_wythe_plugin",
    "resolve_safe_companion_path",
    "run_watch_solver_cli",
    "serialize_chronicle_payload",
    "synthesize_solver_chronicle",
    "watch_solver_main",
]
