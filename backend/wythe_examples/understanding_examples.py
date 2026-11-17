"""Self-contained synthetic Wave 6 understanding example investigations.

Provides two complete, domain-generic open-source example investigations:
1. `schedule-policy-to-export` (`duty_roster_planner` / `schedule_policy_engine`)
2. `assistant-context-to-delivery` (`assistant_gateway` / `channel_router`)

Each example supports both zero-disk in-memory evaluation (for `/api/v1/understanding/examples`)
and full 3-tier repository materialization (`materialize_understanding_example`) for CLI, MCP,
and browser E2E verification. Never mounted as a live web application.
"""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any, Literal

from app.services.understanding_service import (
    UnderstandingAnalyzeRequest,
    UnderstandingExampleRead,
    UnderstandingExampleSummary,
    UnderstandingWalkthroughStep,
    analyze_understanding_bundle,
)

EXAMPLE_SCHEDULE_SLUG = "schedule-policy-to-export"
EXAMPLE_ASSISTANT_SLUG = "assistant-context-to-delivery"
EXAMPLE_SLUGS = (EXAMPLE_SCHEDULE_SLUG, EXAMPLE_ASSISTANT_SLUG)

_GIT_AUTHOR_NAME = "Euda1mon1a"
_GIT_AUTHOR_EMAIL = "214782221+Euda1mon1a@users.noreply.github.com"


def list_shipped_understanding_examples() -> list[UnderstandingExampleSummary]:
    """Return summary metadata for both shipped Wave 6 example investigations."""
    return [
        UnderstandingExampleSummary(
            slug=EXAMPLE_SCHEDULE_SLUG,
            title="Schedule Policy -> Solver -> Settlement -> Dated Workbook Export",
            domain_package="duty_roster_planner / schedule_policy_engine",
            question=(
                "Why did the repair preview ignore the scoped shift limit, which standby weight "
                "won, did publication commit after the lost reply, and how are June/July cells "
                "interpreted?"
            ),
            summary=(
                "Traces a scoped database shift cap consumed in solver generation yet bypassed in "
                "repair preview, conflicting scope bindings skipped in favor of global weight, an "
                "orphan penalty channel, sealed vs committed-unacknowledged settlement, dated "
                "workbook vocabulary boundaries, schema/client mismatch, and multi-solution solver "
                "equivalence."
            ),
            covered_cases=[
                "table_read_field_ignored_downstream",
                "conflicting_scope_specific_policy",
                "effective_date_boundary_changes",
                "current_schema_old_client_artifact",
                "committed_action_lost_reply",
                "same_inputs_multiple_valid_solver_outputs",
                "changed_source_stale_explanatory_note",
            ],
        ),
        UnderstandingExampleSummary(
            slug=EXAMPLE_ASSISTANT_SLUG,
            title="Assistant Context & Tools -> Execution -> Answer -> Delivery & Preservation",
            domain_package="assistant_gateway / channel_router",
            question=(
                "Why did owner_text lose memory context while voice and routing tests passed, "
                "did the calendar tool answer actually reach the user, and is the live "
                "gateway running the repaired code?"
            ),
            summary=(
                "Traces a registered memory packet omitted on owner_text while owner_voice passes "
                "and public_counterparty is intentionally excluded, successful tool runs with "
                "missing follow-up data or unrecorded answer grounding/delivery, stale running "
                "process vs disk commit, non-Git sampler drift, and a stale 'not implemented' "
                "architecture header contradicted by current reducer functions."
            ),
            covered_cases=[
                "one_owner_channel_loses_memory_context",
                "correctly_installed_source_stale_process",
                "successful_tool_missing_model_visible_data",
                "tool_data_supplied_final_answer_unsupported",
                "unchanged_code_changed_policy_config_model_settings",
                "changed_source_stale_explanatory_note",
            ],
        ),
    ]


def _schedule_synthetic_files(stage: Literal["baseline", "candidate"]) -> dict[str, str]:
    repair_expr = (
        "row.max_consecutive_shifts"
        if stage == "candidate"
        else "HARDCODED_SHIFT_CAP  # bypasses row.max_consecutive_shifts in baseline"
    )
    objective_terms = (
        "standby_term + handoff_term + weekend_equity_term"
        if stage == "candidate"
        else "standby_term + handoff_term  # weekend_equity_term orphaned in baseline"
    )
    return {
        "backend/schema.sql": (
            "CREATE TABLE shift_policy_bindings (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    policy_key VARCHAR(64) NOT NULL,\n"
            "    scope_label VARCHAR(64) NOT NULL,\n"
            "    max_consecutive_shifts INTEGER NOT NULL,\n"
            "    standby_penalty_weight INTEGER NOT NULL\n"
            ");\n\n"
            "CREATE TABLE workbook_vocabulary_snapshots (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    snapshot_code VARCHAR(32) NOT NULL,\n"
            "    cell_token VARCHAR(16) NOT NULL,\n"
            "    canonical_label VARCHAR(64) NOT NULL\n"
            ");\n"
        ),
        "backend/app/__init__.py": '"""Synthetic duty_roster_planner package."""\n',
        "backend/app/models.py": (
            "from sqlalchemy import Integer, String\n"
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class ShiftPolicyBinding(Base):\n"
            "    __tablename__ = 'shift_policy_bindings'\n"
            "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
            "    policy_key: Mapped[str] = mapped_column(String(64))\n"
            "    scope_label: Mapped[str] = mapped_column(String(64))\n"
            "    max_consecutive_shifts: Mapped[int] = mapped_column(Integer)\n"
            "    standby_penalty_weight: Mapped[int] = mapped_column(Integer)\n\n"
            "class WorkbookVocabularySnapshot(Base):\n"
            "    __tablename__ = 'workbook_vocabulary_snapshots'\n"
            "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
            "    snapshot_code: Mapped[str] = mapped_column(String(32))\n"
            "    cell_token: Mapped[str] = mapped_column(String(16))\n"
            "    canonical_label: Mapped[str] = mapped_column(String(64))\n"
        ),
        "backend/app/services/__init__.py": "",
        "backend/app/services/schedule_policy_engine.py": (
            "from sqlalchemy import select\n"
            "from app.models import ShiftPolicyBinding, WorkbookVocabularySnapshot\n\n"
            "def build_roster_candidate(db):\n"
            "    row = db.scalar(select(ShiftPolicyBinding))\n"
            "    cap = row.max_consecutive_shifts if row is not None else 5\n"
            "    standby_term = (row.standby_penalty_weight if row is not None else 20) * 1\n"
            "    handoff_term = 10\n"
            "    weekend_equity_term = 15\n"
            f"    objective = {objective_terms}\n"
            "    return {'effective_cap': cap, 'objective': objective, 'state': 'candidate_sealed'}\n\n"
            "def export_dated_workbook(db):\n"
            "    snaps = db.scalars(select(WorkbookVocabularySnapshot)).all()\n"
            "    return [{'code': s.snapshot_code, 'token': s.cell_token, 'label': s.canonical_label} for s in snaps]\n"
        ),
        "backend/app/services/repair_preview_service.py": (
            "from sqlalchemy import select\n"
            "from app.models import ShiftPolicyBinding\n\n"
            "HARDCODED_SHIFT_CAP = 6\n\n"
            "def preview_repair_plan(db):\n"
            "    row = db.scalar(select(ShiftPolicyBinding))\n"
            "    _touched = row.id if row is not None else 0\n"
            f"    enforced_cap = {repair_expr}\n"
            "    return {'binding_id': _touched, 'enforced_cap': enforced_cap}\n"
        ),
        "backend/app/api/__init__.py": "",
        "backend/app/api/routes/__init__.py": "",
        "backend/app/api/routes/roster.py": (
            "from fastapi import APIRouter\n"
            "from app.services.repair_preview_service import preview_repair_plan\n"
            "from app.services.schedule_policy_engine import (\n"
            "    build_roster_candidate,\n"
            "    export_dated_workbook,\n"
            ")\n\n"
            "router = APIRouter()\n\n"
            "@router.post('/generate')\n"
            "def generate_roster_route(db=None):\n"
            "    return build_roster_candidate(db)\n\n"
            "@router.get('/repair-preview')\n"
            "def repair_preview_route(db=None):\n"
            "    return preview_repair_plan(db)\n\n"
            "@router.get('/export')\n"
            "def export_workbook_route(db=None):\n"
            "    return export_dated_workbook(db)\n"
        ),
        "backend/app/main.py": (
            "from fastapi import FastAPI\n"
            "from app.api.routes import roster\n\n"
            "app = FastAPI(title='Duty Roster Planner')\n"
            "app.include_router(roster.router, prefix='/api/v1/roster')\n"
        ),
        "frontend/package.json": json.dumps(
            {"name": "duty-roster-ui", "private": True, "dependencies": {"next": "14.2.0", "react": "18.3.0"}},
            indent=2,
        )
        + "\n",
        "frontend/src/app/page.tsx": (
            "export default function RosterPage() {\n"
            "  async function loadPreview() {\n"
            "    await fetch('/api/v1/roster/generate', { method: 'POST' });\n"
            "    await fetch('/api/v1/roster/repair-preview');\n"
            "    await fetch('/api/v1/roster/export');\n"
            "  }\n"
            "  return (\n"
            "    <main aria-label=\"Duty Roster Planner\">\n"
            "      <h1>Duty Roster Planner</h1>\n"
            "      <button type=\"button\" onClick={loadPreview}>Inspect Roster Lineage</button>\n"
            "    </main>\n"
            "  );\n"
            "}\n"
        ),
    }


def _schedule_bundle_dict(stage: Literal["baseline", "candidate"]) -> dict[str, Any]:
    is_cand = stage == "candidate"
    rev = "rev-roster-02" if is_cand else "rev-roster-01"
    consumed_obj = (
        ["standby_penalty_weight", "handoff_continuity_weight", "weekend_equity_penalty"]
        if is_cand
        else ["standby_penalty_weight", "handoff_continuity_weight"]
    )
    repair_state = "demonstrated_effect" if is_cand else "bypassed"
    repair_mech = "field_controls_result" if is_cand else "constant_or_fallback_wins"
    pub_outcome = (
        {
            "outcome_id": "publication-attempt-092",
            "subject_id": "schedule_publication_receipts",
            "evidence_producer": "schedule_policy_engine.acceptance_settlement",
            "authoritative_terminal_state": "committed",
            "delivery_status": "delivered",
            "authenticated_writer_receipt": True,
            "owning_system_reason": (
                "Settlement read under publication lock confirmed committed after-image digest "
                "and workbook export refresh completed."
            ),
            "transitions": [
                {
                    "stage": "candidate_sealed",
                    "producer": "schedule_policy_engine.builder",
                    "request_or_attempt_id": "pub-092",
                    "predecessor_state_digest": "vec-090",
                    "state_digest": "vec-091-sealed",
                },
                {
                    "stage": "authoritatively_settled",
                    "producer": "schedule_policy_engine.acceptance_settlement",
                    "request_or_attempt_id": "pub-092",
                    "predecessor_state_digest": "vec-091-sealed",
                    "state_digest": "vec-092-committed",
                },
                {
                    "stage": "delivered_to_human",
                    "producer": "duty_roster_planner.workbook_exporter",
                    "request_or_attempt_id": "pub-092",
                    "predecessor_state_digest": "vec-092-committed",
                    "state_digest": "vec-092-exported",
                },
            ],
        }
        if is_cand
        else {
            "outcome_id": "publication-attempt-092",
            "subject_id": "schedule_publication_receipts",
            "evidence_producer": "schedule_policy_engine.acceptance_settlement",
            "transport_timeout_or_lost_reply": True,
            "content_equality_only": True,
            "owning_system_reason": (
                "Worker transport timed out during acceptance commit; terminal DB state not yet "
                "reconciled under publication lock."
            ),
            "transitions": [
                {
                    "stage": "candidate_sealed",
                    "producer": "schedule_policy_engine.builder",
                    "request_or_attempt_id": "pub-092",
                    "predecessor_state_digest": "vec-090",
                    "state_digest": "vec-091-sealed",
                },
                {
                    "stage": "committed_unacknowledged",
                    "producer": "schedule_policy_engine.transport",
                    "request_or_attempt_id": "pub-092",
                    "predecessor_state_digest": "vec-091-sealed",
                    "state_digest": "vec-092-unknown",
                },
            ],
        }
    )

    return {
        "source_revision": rev,
        "question": (
            "Why did repair preview ignore max_consecutive_shifts, which standby weight won, "
            "did publication-attempt-092 commit, and how are June/July cells interpreted?"
        ),
        "intent": {
            "intent_id": "ISSUE-ROSTER-2890",
            "authority_ref": "ISSUE-ROSTER-2890",
            "desired_behavior": (
                "Scoped database policy must control both candidate generation and repair preview, "
                "all soft penalties must connect to the objective, and dated workbook cells must "
                "preserve their snapshot meaning."
            ),
        },
        "effective_authority": [
            {
                "item_id": "policy:max_consecutive_shifts",
                "label": "max_consecutive_shifts",
                "owner": "operations_policy_board",
                "legitimate_editor": "shift_policy_bindings",
                "authority_reference": "ISSUE-ROSTER-2890",
                "observed_at": "2026-11-16T12:00:00Z",
                "scope": {
                    "domain_scope": "team:alpha",
                    "effective_from": "2026-01-01",
                    "effective_until": "2026-12-31",
                },
                "winning_binding_id": "bind-team-alpha",
                "selection_rule": "narrowest_unambiguous_scope_over_global_and_default",
                "candidate_bindings": [
                    {
                        "binding_id": "bind-team-alpha",
                        "source_kind": "db_scoped_row",
                        "scope_label": "team:alpha",
                        "value": 4,
                        "disposition": "selected_winner",
                        "reason": "Exact team:alpha row matched",
                    },
                    {
                        "binding_id": "bind-global-cap",
                        "source_kind": "db_global_row",
                        "scope_label": "global",
                        "value": 5,
                        "disposition": "overridden_by_narrower_or_winner",
                        "reason": "Narrower team:alpha row took precedence",
                    },
                    {
                        "binding_id": "bind-py-default-cap",
                        "source_kind": "python_default",
                        "scope_label": "default",
                        "value": 6,
                        "disposition": "overridden_by_narrower_or_winner",
                        "reason": "Database row present",
                    },
                ],
                "consumer_effects": [
                    {
                        "consumer_id": "schedule_policy_engine.build_roster_candidate",
                        "stage": "solver_objective",
                        "effect_state": "demonstrated_effect",
                        "mechanism": "field_controls_result",
                        "reached_compiled_input": True,
                        "source_location": "backend/app/services/schedule_policy_engine.py:6",
                        "note": "Scoped value 4 compiled into candidate builder constraint.",
                    },
                    {
                        "consumer_id": "schedule_policy_engine.preview_repair_plan",
                        "stage": "repair_preview",
                        "effect_state": repair_state,
                        "mechanism": repair_mech,
                        "reached_compiled_input": is_cand,
                        "source_location": "backend/app/services/schedule_policy_engine.py:16",
                        "note": (
                            "Repair preview now consumes row.max_consecutive_shifts."
                            if is_cand
                            else "Table ShiftPolicyBinding read (.id), but max_consecutive_shifts ignored for HARDCODED_SHIFT_CAP=6."
                        ),
                    },
                ],
                "evidence_state": "demonstrated_effect" if is_cand else "bypassed",
            },
            {
                "item_id": "policy:standby_penalty_and_dated_vocab",
                "label": "standby_penalty_weight & workbook_vocabulary_snapshots",
                "owner": "operations_policy_board",
                "legitimate_editor": "shift_policy_bindings",
                "authority_reference": "ISSUE-ROSTER-3284",
                "observed_at": "2026-11-16T12:00:00Z",
                "artifact_effective_date": "2026-06-30",
                "vocabulary_token": "SB",
                "conflict_resolution": "skip_conflicting_scope_retain_broader",
                "selection_rule": "skip_ambiguous_scope_retain_global_weight",
                "emitted_penalty_channels": [
                    "standby_penalty_weight",
                    "handoff_continuity_weight",
                    "weekend_equity_penalty",
                ],
                "consumed_objective_channels": consumed_obj,
                "candidate_bindings": [
                    {
                        "binding_id": "bind-night-crew-a",
                        "source_kind": "db_scoped_row",
                        "scope_label": "rotation_shape:night_crew",
                        "value": 35,
                    },
                    {
                        "binding_id": "bind-night-crew-b",
                        "source_kind": "db_scoped_row",
                        "scope_label": "rotation_shape:night_crew",
                        "value": 50,
                    },
                    {
                        "binding_id": "bind-global-standby",
                        "source_kind": "db_global_row",
                        "scope_label": "global",
                        "value": 20,
                    },
                    {
                        "binding_id": "bind-py-standby",
                        "source_kind": "python_default",
                        "scope_label": "default",
                        "value": 10,
                    },
                ],
                "vocabulary_snapshots": [
                    {
                        "snapshot_id": "vocab-2026-h1",
                        "effective_from": "2026-01-01",
                        "effective_until": "2026-06-30",
                        "meanings": {"SB": "Standby Crew"},
                    },
                    {
                        "snapshot_id": "vocab-2026-h2",
                        "effective_from": "2026-07-01",
                        "effective_until": "2026-12-31",
                        "meanings": {"SB": "Split Shift"},
                    },
                ],
                "dated_cells": [
                    {"cell_id": "B14", "cell_date": "2026-06-30", "raw_token": "SB"},
                    {"cell_id": "C14", "cell_date": "2026-07-01", "raw_token": "SB"},
                ],
                "consumer_effects": [
                    {
                        "consumer_id": "schedule_policy_engine.build_roster_candidate",
                        "stage": "solver_objective",
                        "effect_state": "demonstrated_effect",
                        "mechanism": "field_controls_result",
                        "reached_compiled_input": True,
                    }
                ],
            },
        ],
        "runtime_provenance": [
            {
                "invocation_id": "roster-run-092",
                "subject_id": "duty_roster_planner.worker",
                "evidence_producer": "schedule_policy_engine.candidate_receipt",
                "repo_revision": rev,
                "dirty_digest": "clean",
                "artifact_digest": f"sha256:{rev}-wheel",
                "expected_artifact_digest": f"sha256:{rev}-wheel",
                "installed_path": "/opt/duty_roster_planner/schedule_policy_engine.py",
                "installed_path_hash": f"sha256:{rev}-file",
                "expected_installed_hash": f"sha256:{rev}-file",
                "host": "planner-worker-01",
                "expected_host": "planner-worker-01",
                "process_pid": 31040,
                "process_started_at": "2026-11-16T11:55:00Z",
                "process_startup_revision": rev,
                "schema_revision": "2026.11.v14",
                "client_or_artifact_schema_revision": "2026.11.v14" if is_cand else "2026.06.v12",
                "config_digest": "cfg-roster-v2",
                "expected_config_digest": "cfg-roster-v2",
                "observed_at": "2026-11-16T12:00:00Z",
                "receipt_expires_at": "2026-11-17T12:00:00Z",
                "import_closure": {
                    "coverage": "complete_python_startup_only",
                    "recorded_modules_count": 42,
                    "post_startup_dynamic_loads": [],
                    "frontend_assets_covered": is_cand,
                },
            }
        ],
        "outcome_lifecycles": [
            {
                "outcome_id": "candidate-run-091",
                "subject_id": "roster_candidate_091",
                "evidence_producer": "schedule_policy_engine.builder",
                "candidate_sealed_only": True,
                "owning_system_reason": "Candidate 091 is sealed for review; acceptance has not run.",
            },
            pub_outcome,
        ],
        "preservation_contracts": [
            {
                "contract_id": "roster-solver-preservation",
                "desired_change": "Wire repair preview to ShiftPolicyBinding and connect weekend_equity_penalty.",
                "issue_or_decision_ref": "ISSUE-ROSTER-2890",
                "expected_objective_channels": [
                    "standby_penalty_weight",
                    "handoff_continuity_weight",
                    "weekend_equity_penalty",
                ],
                "required_capabilities_by_lane": {
                    "candidate_generation": ["scoped_shift_cap", "dated_vocab_export"],
                    "repair_preview": ["scoped_shift_cap"],
                },
                "baseline_evidence": {
                    "source_commit": "rev-roster-01",
                    "policy_digest": "pol-v1",
                    "config_digest": "cfg-roster-v2",
                    "consumed_objective_channels": [
                        "standby_penalty_weight",
                        "handoff_continuity_weight",
                        "weekend_equity_penalty",
                    ],
                    "lane_capabilities": {
                        "candidate_generation": ["scoped_shift_cap", "dated_vocab_export"],
                        "repair_preview": ["scoped_shift_cap"],
                    },
                    "solver_run": {
                        "assignments_digest": "grid-solution-A",
                        "hard_constraints_valid": True,
                        "admitted_policy_digest": "pol-v1",
                        "selected_bindings": {"max_consecutive_shifts": 4, "standby_penalty_weight": 20},
                        "locked_facts_digest": "locks-v1",
                        "candidate_complete": True,
                        "active_objective_channels": [
                            "standby_penalty_weight",
                            "handoff_continuity_weight",
                            "weekend_equity_penalty",
                        ],
                        "export_semantic_digest": "export-meaning-v1",
                        "total_objective": 140.0,
                    },
                },
                "candidate_evidence": {
                    "source_commit": rev,
                    "policy_digest": "pol-v1",
                    "config_digest": "cfg-roster-v2",
                    "emitted_penalty_channels": [
                        "standby_penalty_weight",
                        "handoff_continuity_weight",
                        "weekend_equity_penalty",
                    ],
                    "consumed_objective_channels": consumed_obj,
                    "lane_capabilities": {
                        "candidate_generation": ["scoped_shift_cap", "dated_vocab_export"],
                        "repair_preview": ["scoped_shift_cap"] if is_cand else [],
                    },
                    "solver_run": {
                        "assignments_digest": "grid-solution-B-symmetric",
                        "hard_constraints_valid": True,
                        "admitted_policy_digest": "pol-v1",
                        "selected_bindings": {"max_consecutive_shifts": 4, "standby_penalty_weight": 20},
                        "locked_facts_digest": "locks-v1",
                        "candidate_complete": True,
                        "active_objective_channels": consumed_obj,
                        "export_semantic_digest": "export-meaning-v1",
                        "total_objective": 140.0 if is_cand else 125.0,
                    },
                },
            }
        ],
    }


def _assistant_synthetic_files(stage: Literal["baseline", "candidate"]) -> dict[str, str]:
    owner_text_packets = (
        "['memory_context_packet', 'retrieval_enrichment']"
        if stage == "candidate"
        else "[]  # baseline regression: ordinary model_intent omitted memory_context_packet"
    )
    return {
        "backend/schema.sql": (
            "CREATE TABLE capability_policy_records (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    capability_key VARCHAR(64) NOT NULL,\n"
            "    lane_key VARCHAR(32) NOT NULL,\n"
            "    max_context_tokens INTEGER NOT NULL\n"
            ");\n\n"
            "CREATE TABLE turn_execution_records (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    request_id VARCHAR(64) NOT NULL,\n"
            "    lane_key VARCHAR(32) NOT NULL,\n"
            "    answer_grounding VARCHAR(32) NOT NULL,\n"
            "    delivery_state VARCHAR(32) NOT NULL\n"
            ");\n"
        ),
        "config/capabilities.json": json.dumps(
            {
                "capabilities": {
                    "memory_context_packet": {
                        "enabled": True,
                        "scopes": ["owner_text", "owner_voice", "owner_api", "device_read"],
                    },
                    "calendar_lookup": {"enabled": True, "scopes": ["owner_text", "owner_voice"]},
                    "outbound_dispatch_tool": {"enabled": True, "scopes": ["owner_text"]},
                }
            },
            indent=2,
        )
        + "\n",
        "docs/architecture/operational-state-contract.md": (
            "# Operational State Reducer Contract\n\n"
            "Status: proposed, not implemented\n\n"
            "Defines subject reduction and node rollup semantics.\n"
        ),
        "backend/app/__init__.py": '"""Synthetic assistant_gateway package."""\n',
        "backend/app/models.py": (
            "from sqlalchemy import Integer, String\n"
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class CapabilityPolicyRecord(Base):\n"
            "    __tablename__ = 'capability_policy_records'\n"
            "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
            "    capability_key: Mapped[str] = mapped_column(String(64))\n"
            "    lane_key: Mapped[str] = mapped_column(String(32))\n"
            "    max_context_tokens: Mapped[int] = mapped_column(Integer)\n\n"
            "class TurnExecutionRecord(Base):\n"
            "    __tablename__ = 'turn_execution_records'\n"
            "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
            "    request_id: Mapped[str] = mapped_column(String(64))\n"
            "    lane_key: Mapped[str] = mapped_column(String(32))\n"
            "    answer_grounding: Mapped[str] = mapped_column(String(32))\n"
            "    delivery_state: Mapped[str] = mapped_column(String(32))\n"
        ),
        "backend/app/services/__init__.py": "",
        "backend/app/services/channel_router.py": (
            "from sqlalchemy import select\n"
            "from app.models import CapabilityPolicyRecord, TurnExecutionRecord\n\n"
            "def route_channel_turn(db, lane_key: str):\n"
            "    pol = db.scalar(select(CapabilityPolicyRecord))\n"
            "    budget = pol.max_context_tokens if pol is not None else 2048\n"
            "    if lane_key == 'public_counterparty':\n"
            "        packets = []\n"
            "    elif lane_key == 'owner_text':\n"
            f"        packets = {owner_text_packets}\n"
            "    else:\n"
            "        packets = ['memory_context_packet', 'retrieval_enrichment']\n"
            "    return {'lane': lane_key, 'budget': budget, 'offered_packets': packets}\n\n"
            "def read_request_journey(db, request_id: str):\n"
            "    rec = db.scalar(select(TurnExecutionRecord))\n"
            "    return {\n"
            "        'request_id': rec.request_id if rec else request_id,\n"
            "        'answer_grounding': 'not_recorded',\n"
            "        'delivery_state': 'not_recorded',\n"
            "    }\n"
        ),
        "backend/app/services/operational_state_reducer.py": (
            "def reduce_subject(observations: list[dict]) -> dict:\n"
            "    return {'count': len(observations), 'state': 'active' if observations else 'unknown'}\n\n"
            "def compose_subject(parts: list[dict]) -> dict:\n"
            "    return {'parts': len(parts)}\n\n"
            "def rollup_node(subjects: list[dict]) -> dict:\n"
            "    return {'subjects': len(subjects)}\n"
        ),
        "backend/app/api/__init__.py": "",
        "backend/app/api/routes/__init__.py": "",
        "backend/app/api/routes/gateway.py": (
            "from fastapi import APIRouter\n"
            "from app.services.channel_router import read_request_journey, route_channel_turn\n"
            "from app.services.operational_state_reducer import reduce_subject, rollup_node\n\n"
            "router = APIRouter()\n\n"
            "@router.post('/turn')\n"
            "def post_gateway_turn(lane_key: str = 'owner_text', db=None):\n"
            "    return route_channel_turn(db, lane_key)\n\n"
            "@router.get('/journey')\n"
            "def get_gateway_journey(request_id: str = 'turn-402', db=None):\n"
            "    return read_request_journey(db, request_id)\n\n"
            "@router.get('/state')\n"
            "def get_gateway_state():\n"
            "    return rollup_node([reduce_subject([{'ok': True}])])\n"
        ),
        "backend/app/main.py": (
            "from fastapi import FastAPI\n"
            "from app.api.routes import gateway\n\n"
            "app = FastAPI(title='Assistant Gateway')\n"
            "app.include_router(gateway.router, prefix='/api/v1/gateway')\n"
        ),
        "frontend/package.json": json.dumps(
            {"name": "assistant-gateway-ui", "private": True, "dependencies": {"next": "14.2.0", "react": "18.3.0"}},
            indent=2,
        )
        + "\n",
        "frontend/src/app/page.tsx": (
            "export default function GatewayPage() {\n"
            "  async function inspectGateway() {\n"
            "    await fetch('/api/v1/gateway/turn', { method: 'POST' });\n"
            "    await fetch('/api/v1/gateway/journey');\n"
            "    await fetch('/api/v1/gateway/state');\n"
            "  }\n"
            "  return (\n"
            "    <main aria-label=\"Assistant Gateway\">\n"
            "      <h1>Assistant Gateway</h1>\n"
            "      <button type=\"button\" onClick={inspectGateway}>Inspect Channel Journey</button>\n"
            "    </main>\n"
            "  );\n"
            "}\n"
        ),
    }


def _assistant_bundle_dict(stage: Literal["baseline", "candidate"]) -> dict[str, Any]:
    is_cand = stage == "candidate"
    rev = "rev-assistant-02" if is_cand else "rev-assistant-01"
    proc_rev = "rev-assistant-02" if is_cand else "rev-assistant-00-stale"
    owner_text_offered = is_cand

    return {
        "source_revision": rev,
        "question": (
            "Why did owner_text lose memory_context_packet while owner_voice and routing tests "
            "passed, did turn-calendar-402 convey a grounded answer, and is the live gateway "
            "running the repaired revision?"
        ),
        "intent": {
            "intent_id": "DECISION-ROUTER-1115",
            "authority_ref": "DECISION-ROUTER-1115",
            "desired_behavior": (
                "Preserve memory_context_packet across all four owner lanes (owner_text, "
                "owner_voice, owner_api, device_read) while strictly excluding public_counterparty."
            ),
        },
        "effective_authority": [
            {
                "item_id": "capability:memory_context_packet",
                "label": "memory_context_packet",
                "domain_kind": "capability_context",
                "owner": "assistant_gateway_owner",
                "legitimate_editor": "config/capabilities.json",
                "authority_reference": "DECISION-ROUTER-1115",
                "observed_at": "2026-11-16T12:00:00Z",
                "selection_rule": "registry_admission_and_channel_packet_renderer",
                "lane_evaluations": [
                    {
                        "lane": "owner_text",
                        "registered": True,
                        "admitted_by_policy": True,
                        "offered_in_request": owner_text_offered,
                        "selected_by_model": owner_text_offered,
                        "executed": owner_text_offered,
                        "authored_reply_state": "grounded" if is_cand else "not_recorded",
                        "delivery_state": "delivered" if is_cand else "not_recorded",
                    },
                    {
                        "lane": "owner_voice",
                        "registered": True,
                        "admitted_by_policy": True,
                        "offered_in_request": True,
                        "selected_by_model": True,
                        "executed": True,
                        "authored_reply_state": "grounded",
                        "delivery_state": "delivered",
                    },
                    {
                        "lane": "owner_api",
                        "registered": True,
                        "admitted_by_policy": True,
                        "offered_in_request": True,
                    },
                    {
                        "lane": "device_read",
                        "registered": True,
                        "admitted_by_policy": True,
                        "offered_in_request": True,
                    },
                    {
                        "lane": "public_counterparty",
                        "registered": True,
                        "admitted_by_policy": False,
                        "offered_in_request": False,
                        "exclusion_reason": "Counterparty privacy boundary excludes owner memory.",
                    },
                ],
            },
            {
                "item_id": "capability:outbound_dispatch_tool",
                "label": "outbound_dispatch_tool",
                "domain_kind": "capability_context",
                "owner": "assistant_gateway_owner",
                "legitimate_editor": "config/capabilities.json",
                "authority_reference": "BROKER-CONTRACT-01",
                "observed_at": "2026-11-16T12:00:00Z",
                "selection_rule": "tool_schema_offer_requires_separate_broker_grant",
                "lane_evaluations": [
                    {
                        "lane": "owner_text",
                        "registered": True,
                        "admitted_by_policy": True,
                        "offered_in_request": True,
                        "requires_grant": True,
                        "grant_present": is_cand,
                        "executed": is_cand,
                        "authored_reply_state": "grounded" if is_cand else "not_applicable",
                        "delivery_state": "delivered" if is_cand else "not_recorded",
                    }
                ],
            },
        ],
        "runtime_provenance": [
            {
                "invocation_id": "gw-proc-48210",
                "subject_id": "assistant_gateway.daemon",
                "evidence_producer": "assistant_gateway.running_version",
                "repo_revision": rev,
                "dirty_digest": "clean",
                "artifact_digest": f"sha256:{rev}-bundle",
                "expected_artifact_digest": f"sha256:{rev}-bundle",
                "installed_path": "~/.assistant_gateway/services/channel_router.py",
                "installed_path_hash": f"sha256:{rev}-router",
                "expected_installed_hash": f"sha256:{rev}-router",
                "host": "gateway-host-01",
                "expected_host": "gateway-host-01",
                "process_pid": 48210,
                "process_started_at": "2026-11-16T12:05:00Z" if is_cand else "2026-11-14T08:00:00Z",
                "installed_at": "2026-11-16T11:50:00Z",
                "process_startup_revision": proc_rev,
                "schema_revision": "2026.11.v5",
                "client_or_artifact_schema_revision": "2026.11.v5",
                "config_digest": "cfg-gw-v3",
                "expected_config_digest": "cfg-gw-v3",
                "observed_at": "2026-11-16T12:10:00Z",
                "receipt_expires_at": "2026-11-17T12:10:00Z",
                "workflow_touches_frontend": not is_cand,
                "import_closure": {
                    "recorded_modules_count": 38,
                    "post_startup_dynamic_loads": [] if is_cand else ["plugins.voice_vad_loader"],
                    "frontend_assets_covered": is_cand,
                },
            }
        ],
        "outcome_lifecycles": [
            {
                "outcome_id": "turn-search-401",
                "subject_id": "workspace_search",
                "evidence_producer": "assistant_gateway.execution_log",
                "tool_executed": True,
                "tool_result_included_in_followup": is_cand,
                "answer_grounding": "grounded" if is_cand else "unsupported_or_omitted",
                "delivery_status": "delivered" if is_cand else "not_recorded",
                "current_stage": "delivered_to_human" if is_cand else "executed_missing_followup_grounding",
                "owning_system_reason": (
                    "Search tool output included in follow-up prompt and delivered."
                    if is_cand
                    else "Search tool succeeded, but follow-up context truncated its result payload."
                ),
            },
            {
                "outcome_id": "turn-calendar-402",
                "subject_id": "calendar_lookup",
                "evidence_producer": "assistant_gateway.request_journey",
                "tool_executed": True,
                "tool_result_included_in_followup": True,
                "answer_grounding": "grounded" if is_cand else "not_recorded",
                "delivery_status": "delivered" if is_cand else "not_recorded",
                "current_stage": "delivered_to_human" if is_cand else "supplied_answer_unrecorded",
                "owning_system_reason": (
                    "Calendar lookup grounded in reply with verified client delivery receipt."
                    if is_cand
                    else "Request Journey ends at follow-up prompt inclusion; answer grounding and delivery are not_recorded."
                ),
            },
        ],
        "preservation_contracts": [
            {
                "contract_id": "owner-channel-memory-preservation",
                "desired_change": "Restore memory_context_packet on owner_text while keeping counterparty boundary.",
                "issue_or_decision_ref": "DECISION-ROUTER-1115",
                "required_capabilities_by_lane": {
                    "owner_text": ["memory_context_packet"],
                    "owner_voice": ["memory_context_packet"],
                    "owner_api": ["memory_context_packet"],
                    "device_read": ["memory_context_packet"],
                },
                "required_exclusions_by_lane": {
                    "public_counterparty": ["memory_context_packet"],
                },
                "baseline_evidence": {
                    "source_commit": "rev-assistant-00",
                    "model_id": "local-instruct-8b",
                    "sampler_settings": {"temperature": 0.0, "top_p": 1.0},
                    "latency_ms": 420.0,
                    "quality_score": 0.91,
                    "answer_quality_scored": True,
                    "lane_capabilities": {
                        "owner_text": ["memory_context_packet"],
                        "owner_voice": ["memory_context_packet"],
                        "owner_api": ["memory_context_packet"],
                        "device_read": ["memory_context_packet"],
                        "public_counterparty": [],
                    },
                },
                "candidate_evidence": {
                    "source_commit": rev,
                    "model_id": "local-instruct-8b",
                    "sampler_settings": {"temperature": 0.0 if is_cand else 0.7, "top_p": 1.0},
                    "latency_ms": 385.0 if is_cand else 290.0,
                    "quality_score": 0.93 if is_cand else None,
                    "answer_quality_scored": is_cand,
                    "lane_capabilities": {
                        "owner_text": ["memory_context_packet"] if is_cand else [],
                        "owner_voice": ["memory_context_packet"],
                        "owner_api": ["memory_context_packet"],
                        "device_read": ["memory_context_packet"],
                        "public_counterparty": [],
                    },
                },
            }
        ],
        "documentation_claims": [
            {
                "claim_id": "operational-state-header",
                "document_or_note_path": "docs/architecture/operational-state-contract.md",
                "claim_revision": "rev-doc-2026-07",
                "historical_claim": "Status: proposed, not implemented",
                "owning_update_ref": "DECISION-OS-1",
                "owning_update_summary": "Core subject reduction and node rollup shipped; federation phase deferred.",
                "implemented_symbols_found": ["reduce_subject", "compose_subject", "rollup_node"],
                "unverified_remaining_phases": ["cross_region_federation"],
                "current_code_evidence": (
                    "backend/app/services/operational_state_reducer.py implements reduce_subject, "
                    "compose_subject, and rollup_node; header status is overly broad."
                ),
            }
        ],
    }


def get_example_bundle_dict(
    example_slug: str,
    *,
    stage: Literal["baseline", "candidate"] = "baseline",
) -> dict[str, Any]:
    """Return a deep copy of the baseline or candidate JSON bundle for `example_slug`."""
    if example_slug == EXAMPLE_SCHEDULE_SLUG:
        return copy.deepcopy(_schedule_bundle_dict(stage))
    if example_slug == EXAMPLE_ASSISTANT_SLUG:
        return copy.deepcopy(_assistant_bundle_dict(stage))
    raise LookupError(f"Unknown understanding example '{example_slug}'. Expected one of {EXAMPLE_SLUGS}.")


def get_example_synthetic_files(
    example_slug: str,
    *,
    stage: Literal["baseline", "candidate"] = "baseline",
) -> dict[str, str]:
    """Return synthetic 3-tier source files (`fastapi-sqlalchemy-nextjs`) for `example_slug`."""
    if example_slug == EXAMPLE_SCHEDULE_SLUG:
        return dict(_schedule_synthetic_files(stage))
    if example_slug == EXAMPLE_ASSISTANT_SLUG:
        return dict(_assistant_synthetic_files(stage))
    raise LookupError(f"Unknown understanding example '{example_slug}'. Expected one of {EXAMPLE_SLUGS}.")


def _git_head(repo_dir: Path) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None


def materialize_understanding_example(
    example_slug: str,
    dest_dir: Path | str,
    *,
    stage: Literal["baseline", "candidate"] = "baseline",
    init_git: bool = False,
) -> Path:
    """Materialize synthetic 3-tier repo + `.wythe/understanding_bundle.json` into `dest_dir`."""
    root = Path(dest_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    prior_head = _git_head(root) if (root / ".git").exists() else None

    files = get_example_synthetic_files(example_slug, stage=stage)
    bundle = get_example_bundle_dict(example_slug, stage=stage)
    if stage == "candidate" and prior_head:
        bundle["pinned_explanation_revision"] = prior_head
        bundle["prior_explanation_summary"] = (
            f"Baseline explanation recorded at revision {prior_head[:12]} before candidate repair."
        )

    for rel_path, content in files.items():
        out_file = root / rel_path
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content, encoding="utf-8")

    bundle_file = root / ".wythe" / "understanding_bundle.json"
    bundle_file.parent.mkdir(parents=True, exist_ok=True)
    bundle_file.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

    if init_git:
        if not (root / ".git").exists():
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", _GIT_AUTHOR_NAME], check=True
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", _GIT_AUTHOR_EMAIL], check=True
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "commit.gpgsign", "false"], check=True
            )
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                f"chore(fixture): materialize {example_slug} ({stage})",
            ],
            check=True,
        )
    return root


def _walkthrough_for(slug: str) -> list[UnderstandingWalkthroughStep]:
    if slug == EXAMPLE_SCHEDULE_SLUG:
        return [
            UnderstandingWalkthroughStep(
                step_number=1,
                actor="human",
                action="Select unexplained repair-preview shift cap discrepancy and publication-attempt-092.",
                expected_observation="Focus binds to schedule_policy_engine.preview_repair_plan and publication receipt.",
            ),
            UnderstandingWalkthroughStep(
                step_number=2,
                actor="agent",
                action="Run six-link understanding analysis on baseline bundle.",
                expected_observation=(
                    "States last supported cause, bypassed repair_preview field, skipped conflicting "
                    "night_crew bindings, orphan weekend_equity_penalty, indeterminate lost-reply "
                    "settlement (no blind retry), and June/July dated vocabulary boundary."
                ),
            ),
            UnderstandingWalkthroughStep(
                step_number=3,
                actor="human",
                action="Submit correction clarifying global fallback on ambiguous scope is intentional pending review.",
                expected_observation="Correction attaches with promoted_to_policy=False; governance rules stay unchanged.",
            ),
            UnderstandingWalkthroughStep(
                step_number=4,
                actor="system",
                action="Apply candidate repair, settle publication lock, and rescan.",
                expected_observation=(
                    "Prior baseline explanation is marked historical_needs_revalidation; symmetric "
                    "multi-solution solver run passes as equivalent_valid_alternatives."
                ),
            ),
        ]
    return [
        UnderstandingWalkthroughStep(
            step_number=1,
            actor="human",
            action="Select channel_router.route_channel_turn and ask why owner_text lost memory context.",
            expected_observation="Focus binds to capability:memory_context_packet and turn-calendar-402.",
        ),
        UnderstandingWalkthroughStep(
            step_number=2,
            actor="agent",
            action="Evaluate six-link understanding chain across lanes, runtime provenance, and Request Journey.",
            expected_observation=(
                "Shows memory_context_packet missing on owner_text while owner_voice passes and "
                "public_counterparty is excluded, live daemon running stale revision, and "
                "answer_grounding/delivery recorded as not_recorded."
            ),
        ),
        UnderstandingWalkthroughStep(
            step_number=3,
            actor="human",
            action="Submit correction requiring measured answer grounding across all 4 owner lanes before release.",
            expected_observation="Correction persists on investigation session (promoted_to_policy=False).",
        ),
        UnderstandingWalkthroughStep(
            step_number=4,
            actor="system",
            action="Restore owner_text packet, restart daemon on candidate revision, and re-evaluate.",
            expected_observation=(
                "Prior baseline note becomes historical_needs_revalidation, operational-state doc "
                "header remains flagged against reducer symbols, and lane matrix passes."
            ),
        ),
    ]


def build_shipped_understanding_example(example_slug: str) -> UnderstandingExampleRead:
    """Build complete in-memory `UnderstandingExampleRead` for `example_slug`."""
    summaries = {s.slug: s for s in list_shipped_understanding_examples()}
    if example_slug not in summaries:
        raise LookupError(f"Unknown understanding example '{example_slug}'.")
    summary = summaries[example_slug]
    base_bundle = get_example_bundle_dict(example_slug, stage="baseline")
    cand_bundle = get_example_bundle_dict(example_slug, stage="candidate")
    obs_ts = "2026-11-16T12:30:00Z"

    base_report = analyze_understanding_bundle(
        UnderstandingAnalyzeRequest(
            example_slug=example_slug,
            bundle=base_bundle,
            observed_at=obs_ts,
        )
    )
    cand_report = analyze_understanding_bundle(
        UnderstandingAnalyzeRequest(
            example_slug=example_slug,
            bundle=cand_bundle,
            observed_at=obs_ts,
        )
    )
    reval_report = analyze_understanding_bundle(
        UnderstandingAnalyzeRequest(
            example_slug=example_slug,
            bundle=cand_bundle,
            observed_at=obs_ts,
            prior_explanation_revision=str(base_bundle["source_revision"]),
            human_corrections=[
                {
                    "correction_id": f"corr-{example_slug}-1",
                    "actor": "human",
                    "kind": "domain_expectation",
                    "note": "Verify real entrypoint preservation and keep historical notes distinct from current state.",
                }
            ],
        )
    )
    return UnderstandingExampleRead(
        summary=summary,
        synthetic_files=get_example_synthetic_files(example_slug, stage="baseline"),
        baseline_bundle=base_bundle,
        candidate_bundle=cand_bundle,
        baseline_report=base_report,
        candidate_report=cand_report,
        post_change_revalidation_report=reval_report,
        walkthrough_steps=_walkthrough_for(example_slug),
    )
