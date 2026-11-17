"""Pure-Python OR-Tools CP-SAT domain lineage and companion artifact plugin for Wythe."""

from __future__ import annotations

from wythe_plugin_cpsat.ast_extractor import (
    CpSatBuilderDecl,
    CpSatConstraintDecl,
    CpSatModuleModel,
    CpSatObjectiveDecl,
    CpSatObjectiveTerm,
    CpSatRepoExtraction,
    CpSatSolverRunDecl,
    CpSatTruncationHazard,
    CpSatUnguardedLoop,
    CpSatVariableDecl,
    extract_repo_cpsat_models,
)
from wythe_plugin_cpsat.plugin import (
    WYTHE_PLUGIN,
    CpSatLineagePlugin,
    register_wythe_plugin,
)
from wythe_plugin_cpsat.proto_companion import (
    CpModelProtoSummary,
    CpSolverResponseSummary,
    correlate_cpsat_companions,
    parse_cp_model_proto,
    parse_cp_solver_response,
)

__all__ = [
    "WYTHE_PLUGIN",
    "CpModelProtoSummary",
    "CpSatBuilderDecl",
    "CpSatConstraintDecl",
    "CpSatLineagePlugin",
    "CpSatModuleModel",
    "CpSatObjectiveDecl",
    "CpSatObjectiveTerm",
    "CpSatRepoExtraction",
    "CpSatSolverRunDecl",
    "CpSatTruncationHazard",
    "CpSatUnguardedLoop",
    "CpSatVariableDecl",
    "CpSolverResponseSummary",
    "correlate_cpsat_companions",
    "extract_repo_cpsat_models",
    "parse_cp_model_proto",
    "parse_cp_solver_response",
    "register_wythe_plugin",
]
