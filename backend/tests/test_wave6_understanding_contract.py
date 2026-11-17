"""Comprehensive acceptance suite for Wave 6 Understanding Contract & All 12 Cases.

Verifies:
- Shared `UnderstandingReference` and Six-Link Chain (`Intent -> Effective Policy/Context ->
  Execution -> Committed Result -> Human-Visible Result -> Preservation Evidence`)
- All 12 Comparative & Negative Cases (Sections A–E)
- Both complete synthetic example investigations (`schedule-policy-to-export` and
  `assistant-context-to-delivery`), including 3-tier repo materialization, live scan
  integration, human corrections (`promoted_to_policy=False`), and post-change revalidation
- REST router (`/api/v1/understanding/{analyze,explain,examples}`) & path-safety guards
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.routes import understanding as understanding_routes
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target
from app.services.understanding_service import (
    UnderstandingAnalyzeRequest,
    analyze_understanding_bundle,
    evaluate_documentation_claims,
    evaluate_preservation_contract,
    evaluate_runtime_provenance,
    explain_effective_authority,
    explain_outcome_lifecycle,
    read_understanding_bundle_file,
)
from wythe_examples.understanding_examples import (
    EXAMPLE_ASSISTANT_SLUG,
    EXAMPLE_SCHEDULE_SLUG,
    materialize_understanding_example,
)

SIX_LINK_KEYS = (
    "intent",
    "effective_policy_context",
    "execution",
    "committed_result",
    "human_visible_result",
    "preservation_evidence",
)


@pytest.fixture
def understanding_client(db_session: Session) -> TestClient:
    app = FastAPI()
    app.dependency_overrides[understanding_routes.get_db] = lambda: db_session
    app.include_router(understanding_routes.router, prefix="/api/v1/understanding")
    return TestClient(app)


# ---------------------------------------------------------------------------
# Explicit Acceptance Matrix: All 12 Comparative & Negative Cases
# ---------------------------------------------------------------------------


def test_case_01_table_read_field_ignored_downstream() -> None:
    """Case 1: Table read, field ignored downstream -> persisted authority exists; effect bypassed."""
    bypassed = explain_effective_authority(
        {
            "item_id": "policy:shift_cap",
            "label": "max_consecutive_shifts",
            "owner": "operations_board",
            "legitimate_editor": "shift_policy_bindings",
            "winning_binding_id": "bind-1",
            "candidate_bindings": [
                {"binding_id": "bind-1", "source_kind": "db_row", "scope_label": "global", "value": 4}
            ],
            "consumer_effects": [
                {
                    "consumer_id": "preview_repair_plan",
                    "stage": "repair_preview",
                    "effect_state": "bypassed",
                    "mechanism": "constant_or_fallback_wins",
                    "note": "Reads row.id only; enforces hardcoded 6.",
                }
            ],
        }
    )
    assert bypassed.winning_binding is not None and bypassed.winning_binding.value == 4
    assert bypassed.evidence_state == "bypassed"
    assert bypassed.review_candidate is True
    assert bypassed.reference.claim_kind == "source_inference"

    # Resolver-only check must stay `recorded_selection`, never full solve/export proof
    resolver_only = explain_effective_authority(
        {
            "item_id": "policy:resolver_only",
            "winning_binding_id": "bind-1",
            "candidate_bindings": [
                {"binding_id": "bind-1", "source_kind": "db_row", "scope_label": "global", "value": 4}
            ],
            "consumer_effects": [
                {"consumer_id": "policy_resolver", "stage": "resolver", "effect_state": "demonstrated_effect"}
            ],
        }
    )
    assert resolver_only.evidence_state == "recorded_selection"
    assert "resolver_to_compiled_input_and_output" in resolver_only.missing_joins

    # Opaque helper handoff remains `unresolved`
    opaque = explain_effective_authority(
        {
            "item_id": "policy:opaque_handoff",
            "consumer_effects": [
                {"consumer_id": "external_helper", "stage": "helper", "mechanism": "dynamic_or_opaque_flow"}
            ],
        }
    )
    assert opaque.evidence_state == "unresolved"
    assert "opaque_consumer_handoff:external_helper" in opaque.missing_joins


def test_case_02_conflicting_scope_specific_policy() -> None:
    """Case 2: Conflicting scope-specific policy -> broader/refusal/unresolved; never invent precedence."""
    # (a) Domain resolver skips conflicting narrow bindings and retains broader global binding
    retained_global = explain_effective_authority(
        {
            "item_id": "policy:standby_weight",
            "conflict_resolution": "skip_conflicting_scope_retain_broader",
            "candidate_bindings": [
                {"binding_id": "narrow-a", "source_kind": "db_scoped_row", "scope_label": "shape:night", "value": 35},
                {"binding_id": "narrow-b", "source_kind": "db_scoped_row", "scope_label": "shape:night", "value": 50},
                {"binding_id": "global-1", "source_kind": "db_global_row", "scope_label": "global", "value": 20},
                {"binding_id": "py-def", "source_kind": "python_default", "scope_label": "default", "value": 10},
            ],
            "consumer_effects": [
                {"consumer_id": "solver", "stage": "solver_objective", "effect_state": "demonstrated_effect"}
            ],
        }
    )
    assert retained_global.conflict_status == "conflicting_scope_skipped_broader_retained"
    assert retained_global.winning_binding is not None
    assert retained_global.winning_binding.binding_id == "global-1"
    assert retained_global.winning_binding.value == 20
    skipped_ids = {b.binding_id: b.disposition for b in retained_global.skipped_or_overridden_bindings}
    assert skipped_ids["narrow-a"] == "skipped_conflicting_scope"
    assert skipped_ids["narrow-b"] == "skipped_conflicting_scope"
    assert retained_global.review_candidate is True

    # (b) Explicit typed refusal preserved
    refused = explain_effective_authority(
        {
            "item_id": "policy:refused",
            "conflict_resolution": "typed_refusal",
            "refusal_code": "AMBIGUOUS_SCOPE_POLICY",
            "candidate_bindings": [
                {"binding_id": "n1", "scope_label": "team:a", "value": 3},
                {"binding_id": "n2", "scope_label": "team:a", "value": 5},
            ],
        }
    )
    assert refused.conflict_status == "typed_refusal"
    assert refused.refusal_code == "AMBIGUOUS_SCOPE_POLICY"
    assert refused.winning_binding is None

    # (c) No domain selection rule -> Wythe NEVER invents precedence!
    no_rule = explain_effective_authority(
        {
            "item_id": "policy:unadjudicated",
            "candidate_bindings": [
                {"binding_id": "n1", "scope_label": "team:a", "value": 3},
                {"binding_id": "n2", "scope_label": "team:a", "value": 5},
            ],
        }
    )
    assert no_rule.conflict_status == "unresolved_conflict_no_domain_precedence"
    assert no_rule.winning_binding is None
    assert no_rule.evidence_state == "unresolved"
    assert "domain_precedence_selection_record" in no_rule.missing_joins

    # (d) Database sync error falling back to Python default
    db_err = explain_effective_authority(
        {
            "item_id": "policy:db_fallback",
            "db_sync_error": "SQLAlchemyError: connection timeout",
            "candidate_bindings": [
                {"binding_id": "db-1", "source_kind": "db_global_row", "scope_label": "global", "value": 4},
                {"binding_id": "py-1", "source_kind": "python_default", "scope_label": "default", "value": 8},
            ],
        }
    )
    assert db_err.conflict_status == "db_error_python_default_fallback"
    assert db_err.fallback_activated is True
    assert db_err.winning_binding is not None and db_err.winning_binding.value == 8


def test_case_03_effective_date_boundary_changes() -> None:
    """Case 3: Effective-date boundary changes -> dated snapshot per cell; old bytes insufficient."""
    boundary = explain_effective_authority(
        {
            "item_id": "vocab:sb_token",
            "observed_at": "2026-11-16T12:00:00Z",
            "artifact_effective_date": "2026-06-30",
            "vocabulary_token": "SB",
            "vocabulary_snapshots": [
                {
                    "snapshot_id": "vocab-h1",
                    "effective_from": "2026-01-01",
                    "effective_until": "2026-06-30",
                    "meanings": {"SB": "Standby Crew"},
                },
                {
                    "snapshot_id": "vocab-h2",
                    "effective_from": "2026-07-01",
                    "effective_until": "2026-12-31",
                    "meanings": {"SB": "Split Shift"},
                },
            ],
            "dated_cells": [
                {"cell_id": "B10", "cell_date": "2026-06-30", "raw_token": "SB"},
                {"cell_id": "C10", "cell_date": "2026-07-01", "raw_token": "SB"},
            ],
        }
    )
    ti = boundary.temporal_interpretation
    assert ti.interpretation_mode == "boundary_spanning_snapshots"
    assert ti.cell_bindings[0].dated_snapshot_id == "vocab-h1"
    assert ti.cell_bindings[0].dated_meaning == "Standby Crew"
    assert ti.cell_bindings[1].dated_snapshot_id == "vocab-h2"
    assert ti.cell_bindings[1].dated_meaning == "Split Shift"

    # Old workbook bytes read without a pinned historical snapshot warn explicitly
    bytes_only = explain_effective_authority(
        {
            "item_id": "vocab:old_workbook_bytes",
            "observed_at": "2026-11-16T12:00:00Z",
            "artifact_effective_date": "2026-05-15",
            "artifact_bytes_only": True,
            "vocabulary_snapshots": [
                {
                    "snapshot_id": "vocab-h2",
                    "effective_from": "2026-01-01",
                    "effective_until": "2026-12-31",
                    "meanings": {"SB": "Split Shift"},
                }
            ],
        }
    )
    assert (
        bytes_only.temporal_interpretation.interpretation_mode
        == "reinterpreted_under_current_vocabulary_warning"
    )
    assert "pinned_historical_vocabulary_snapshot" in bytes_only.missing_joins


def test_case_04_correctly_installed_source_stale_process_and_provenance_variants() -> None:
    """Case 4 + Section B: Stale process, wrong host, wrong artifact, expired receipt, partial closure."""
    eval_ts = "2026-11-16T15:00:00Z"

    # 1. Correctly installed source, stale running process
    stale_proc = evaluate_runtime_provenance(
        {
            "invocation_id": "inv-stale",
            "repo_revision": "sha-new-02",
            "installed_path_hash": "hash-new",
            "expected_installed_hash": "hash-new",
            "host": "node-a",
            "expected_host": "node-a",
            "process_pid": 9001,
            "process_started_at": "2026-11-15T00:00:00Z",
            "installed_at": "2026-11-16T10:00:00Z",
            "process_startup_revision": "sha-old-01",
            "schema_revision": "v10",
            "config_digest": "cfg-1",
        },
        evaluation_time=eval_ts,
    )
    assert stale_proc.overall_status == "stale_running_process"
    assert stale_proc.verification_badge != "verified"
    assert "installed_disk_to_running_process_reload" in stale_proc.missing_joins

    # 2. Right file, wrong host
    wrong_host = evaluate_runtime_provenance(
        {
            "invocation_id": "inv-host",
            "repo_revision": "sha-02",
            "installed_path_hash": "hash-02",
            "host": "workstation-host",
            "expected_host": "daemon-host",
            "process_startup_revision": "sha-02",
            "schema_revision": "v10",
            "config_digest": "cfg-1",
        },
        evaluation_time=eval_ts,
    )
    assert wrong_host.overall_status == "wrong_host"
    assert wrong_host.verification_badge == "mismatch_detected"

    # 3. Fresh trace, wrong consumer artifact
    wrong_art = evaluate_runtime_provenance(
        {
            "invocation_id": "inv-art",
            "repo_revision": "sha-02",
            "artifact_digest": "art-A",
            "expected_artifact_digest": "art-B",
            "installed_path_hash": "hash-02",
            "host": "daemon-host",
            "process_startup_revision": "sha-02",
            "schema_revision": "v10",
            "config_digest": "cfg-1",
        },
        evaluation_time=eval_ts,
    )
    assert wrong_art.overall_status == "wrong_artifact"

    # 4. Stale / expired receipt
    expired = evaluate_runtime_provenance(
        {
            "invocation_id": "inv-exp",
            "repo_revision": "sha-02",
            "installed_path_hash": "hash-02",
            "host": "daemon-host",
            "process_startup_revision": "sha-02",
            "schema_revision": "v10",
            "config_digest": "cfg-1",
            "receipt_expires_at": "2026-11-16T12:00:00Z",
        },
        evaluation_time=eval_ts,
    )
    assert expired.overall_status == "stale_receipt"
    assert expired.reference.coverage_state == "expired"

    # 5. Incomplete import coverage (post-startup dynamic loads & frontend outside Python closure)
    inc_closure = evaluate_runtime_provenance(
        {
            "invocation_id": "inv-ic",
            "repo_revision": "sha-02",
            "installed_path_hash": "hash-02",
            "host": "daemon-host",
            "process_startup_revision": "sha-02",
            "schema_revision": "v10",
            "config_digest": "cfg-1",
            "workflow_touches_frontend": True,
            "import_closure": {
                "recorded_modules_count": 25,
                "post_startup_dynamic_loads": ["plugins.lazy_worker"],
                "frontend_assets_covered": False,
            },
        },
        evaluation_time=eval_ts,
    )
    assert inc_closure.overall_status == "incomplete_import_coverage"
    assert inc_closure.verification_badge == "partial_coverage"


def test_case_05_current_schema_old_client_or_artifact() -> None:
    """Case 5: Current schema, old client/artifact -> version mismatch stays visible."""
    mismatch = evaluate_runtime_provenance(
        {
            "invocation_id": "inv-schema",
            "repo_revision": "sha-02",
            "installed_path_hash": "hash-02",
            "host": "planner-host",
            "process_startup_revision": "sha-02",
            "schema_revision": "2026.11.v14",
            "client_or_artifact_schema_revision": "2026.06.v12",
            "config_digest": "cfg-1",
            "import_closure": {"recorded_modules_count": 10},
        },
        evaluation_time="2026-11-16T15:00:00Z",
    )
    assert mismatch.overall_status == "schema_client_mismatch"
    assert mismatch.verification_badge == "mismatch_detected"
    assert "schema_revision_to_client_artifact_compatibility" in mismatch.missing_joins


def test_case_06_committed_action_lost_reply_settlement_and_sealed_vs_accepted() -> None:
    """Case 6: Committed action, lost reply -> indeterminate settlement, blind retry prohibited."""
    lost_reply = explain_outcome_lifecycle(
        {
            "outcome_id": "pub-timeout-1",
            "transport_timeout_or_lost_reply": True,
            "content_equality_only": True,
            "temporal_proximity_only": True,
        }
    )
    assert lost_reply.current_stage == "committed_unacknowledged"
    assert lost_reply.settlement_state == "indeterminate_requires_settlement"
    assert lost_reply.blind_retry_prohibited is True
    assert "DO NOT blindly retry" in lost_reply.retry_guidance
    assert lost_reply.proximity_join_rejected is True
    assert lost_reply.authorship_established is False

    sealed = explain_outcome_lifecycle({"outcome_id": "cand-1", "candidate_sealed_only": True})
    assert sealed.current_stage == "candidate_sealed"
    assert sealed.settlement_state == "uncommitted_candidate"

    grant_only = explain_outcome_lifecycle({"outcome_id": "grant-1", "grant_issued_not_executed": True})
    assert grant_only.current_stage == "granted_not_executed"

    queued_only = explain_outcome_lifecycle({"outcome_id": "card-1", "queued_not_rendered": True})
    assert queued_only.current_stage == "queued_not_rendered"
    assert queued_only.delivery_status == "queued_not_rendered"


def test_case_07_successful_tool_missing_model_visible_data() -> None:
    """Case 7: Successful tool, missing model-visible data -> subsequent grounding unestablished."""
    missing_followup = explain_outcome_lifecycle(
        {
            "outcome_id": "tool-run-7",
            "tool_executed": True,
            "tool_result_included_in_followup": False,
        }
    )
    assert missing_followup.last_proven_stage == "executed"
    assert missing_followup.current_stage == "executed_missing_followup_grounding"
    assert "tool_output_to_model_followup_request" in missing_followup.missing_joins


def test_case_08_tool_data_supplied_final_answer_unsupported_or_unrecorded() -> None:
    """Case 8: Tool data supplied, final answer unsupported/unrecorded -> does not certify answer."""
    journey = explain_outcome_lifecycle(
        {
            "outcome_id": "tool-run-8",
            "tool_executed": True,
            "tool_result_included_in_followup": True,
            "answer_grounding": "not_recorded",
            "delivery_status": "not_recorded",
        }
    )
    assert journey.current_stage == "supplied_answer_unrecorded"
    assert journey.answer_grounding == "not_recorded"
    assert journey.delivery_status == "not_recorded"
    assert "authored_answer_grounding_and_human_delivery_receipt" in journey.missing_joins


def test_case_09_one_owner_channel_loses_memory_context() -> None:
    """Case 9: One owner channel loses memory/context -> fails despite sibling channels passing."""
    res = evaluate_preservation_contract(
        {
            "contract_id": "lane-matrix-check",
            "desired_change": "Refactor intent router while preserving owner memory across all owner lanes.",
            "required_capabilities_by_lane": {
                "owner_text": ["memory_packet"],
                "owner_voice": ["memory_packet"],
                "owner_api": ["memory_packet"],
                "device_read": ["memory_packet"],
            },
            "required_exclusions_by_lane": {
                "public_counterparty": ["memory_packet"],
            },
            "baseline_evidence": {
                "source_commit": "rev-1",
                "lane_capabilities": {
                    "owner_text": ["memory_packet"],
                    "owner_voice": ["memory_packet"],
                    "owner_api": ["memory_packet"],
                    "device_read": ["memory_packet"],
                    "public_counterparty": [],
                },
            },
            "candidate_evidence": {
                "source_commit": "rev-2",
                "lane_capabilities": {
                    "owner_text": [],  # regressed on owner_text only!
                    "owner_voice": ["memory_packet"],
                    "owner_api": ["memory_packet"],
                    "device_read": ["memory_packet"],
                    "public_counterparty": [],
                },
            },
        }
    )
    assert res.verdict == "failed_regression"
    assert res.failed_preserved_capabilities == ["owner_text:memory_packet"]
    assert res.violated_exclusions == []


def test_case_10_unchanged_code_changed_policy_config_or_model_settings() -> None:
    """Case 10: Unchanged code, changed policy/config/model settings + 1D speed guard."""
    drift = evaluate_preservation_contract(
        {
            "contract_id": "non-git-drift",
            "desired_change": "Verify repeatable harness behavior.",
            "baseline_evidence": {
                "source_commit": "same-sha-111",
                "policy_digest": "pol-v1",
                "config_digest": "cfg-v1",
                "sampler_settings": {"temperature": 0.0, "top_p": 1.0},
            },
            "candidate_evidence": {
                "source_commit": "same-sha-111",
                "policy_digest": "pol-v2",
                "config_digest": "cfg-v1",
                "sampler_settings": {"temperature": 0.8, "top_p": 1.0},
            },
        }
    )
    assert drift.git_code_unchanged is True
    assert drift.non_git_semantic_drift_detected is True
    assert drift.verdict == "non_git_drift_requires_review"
    assert any("policy_digest" in f for f in drift.changed_non_git_factors)
    assert any("sampler_settings.temperature" in f for f in drift.changed_non_git_factors)

    # Faster latency with degraded accuracy NEVER passes as improved
    faster_worse = evaluate_preservation_contract(
        {
            "contract_id": "speed-vs-grounding",
            "desired_change": "Trim prompt tokens.",
            "baseline_evidence": {
                "source_commit": "sha-1",
                "latency_ms": 500.0,
                "quality_score": 0.92,
                "answer_quality_scored": True,
            },
            "candidate_evidence": {
                "source_commit": "sha-2",
                "latency_ms": 220.0,
                "quality_score": 0.74,
                "answer_quality_scored": True,
            },
        }
    )
    assert faster_worse.quality_latency.status == "faster_but_degraded_quality"
    assert faster_worse.verdict == "failed_regression"


def test_case_11_same_inputs_multiple_valid_solver_outputs_and_orphan_penalty() -> None:
    """Case 11: Multiple valid solver outputs pass on invariants; orphan penalty channel fails."""
    equivalent = evaluate_preservation_contract(
        {
            "contract_id": "multi-solution-equivalence",
            "desired_change": "Upgrade solver worker count while preserving roster semantics.",
            "baseline_evidence": {
                "source_commit": "sha-1",
                "solver_run": {
                    "assignments_digest": "crew-grid-A",
                    "hard_constraints_valid": True,
                    "admitted_policy_digest": "pol-hash-1",
                    "selected_bindings": {"shift_cap": 4, "standby_weight": 20},
                    "locked_facts_digest": "locks-hash-1",
                    "candidate_complete": True,
                    "active_objective_channels": ["standby_weight", "weekend_equity"],
                    "export_semantic_digest": "export-v1",
                    "total_objective": 110.0,
                },
            },
            "candidate_evidence": {
                "source_commit": "sha-2",
                "solver_run": {
                    "assignments_digest": "crew-grid-B-symmetric-swap",
                    "hard_constraints_valid": True,
                    "admitted_policy_digest": "pol-hash-1",
                    "selected_bindings": {"shift_cap": 4, "standby_weight": 20},
                    "locked_facts_digest": "locks-hash-1",
                    "candidate_complete": True,
                    "active_objective_channels": ["standby_weight", "weekend_equity"],
                    "export_semantic_digest": "export-v1",
                    "total_objective": 110.0,
                },
            },
        }
    )
    assert equivalent.solver_comparison is not None
    assert equivalent.solver_comparison.raw_schedule_equal is False
    assert equivalent.solver_comparison.verdict == "equivalent_valid_alternatives"
    assert equivalent.verdict == "equivalent_valid_alternatives"

    # Disconnecting a penalty channel fails even when total_objective looks smaller ("better")
    disconnected = evaluate_preservation_contract(
        {
            "contract_id": "orphan-channel-regression",
            "desired_change": "Refactor constraint manager.",
            "baseline_evidence": {
                "source_commit": "sha-1",
                "solver_run": {
                    "assignments_digest": "grid-A",
                    "active_objective_channels": ["standby_weight", "weekend_equity"],
                    "total_objective": 110.0,
                },
            },
            "candidate_evidence": {
                "source_commit": "sha-2",
                "solver_run": {
                    "assignments_digest": "grid-B",
                    "active_objective_channels": ["standby_weight"],
                    "total_objective": 80.0,
                },
            },
        }
    )
    assert disconnected.verdict == "failed_regression"
    assert disconnected.disconnected_penalty_channels == ["weekend_equity"]


def test_case_12_changed_source_stale_explanatory_note_and_doc_header() -> None:
    """Case 12: Changed source / stale doc header -> historical_needs_revalidation."""
    evals = evaluate_documentation_claims(
        [
            {
                "claim_id": "reducer-doc-header",
                "document_or_note_path": "docs/architecture/operational-state-contract.md",
                "claim_revision": "rev-july",
                "historical_claim": "Status: proposed, not implemented",
                "owning_update_ref": "DECISION-OS-1",
                "check_symbols": ["reduce_subject", "compose_subject", "rollup_node"],
            }
        ],
        current_revision="rev-nov",
        live_defined_symbols={"reduce_subject", "compose_subject", "rollup_node"},
    )
    assert len(evals) == 1
    assert evals[0].status == "historical_needs_revalidation"
    assert evals[0].safe_for_current_guidance is False
    assert evals[0].implemented_symbols_found == ["compose_subject", "reduce_subject", "rollup_node"]
    assert evals[0].reference.claim_kind == "historical_explanation"


# ---------------------------------------------------------------------------
# Complete Synthetic Examples, Live 3-Tier Repo Materialization & REST Routes
# ---------------------------------------------------------------------------


def test_examples_rest_endpoints_and_materialized_repo_lifecycle(
    tmp_path: Path,
    db_session: Session,
    understanding_client: TestClient,
) -> None:
    cat_resp = understanding_client.get("/api/v1/understanding/examples")
    assert cat_resp.status_code == 200
    slugs = [item["slug"] for item in cat_resp.json()]
    assert slugs == [EXAMPLE_SCHEDULE_SLUG, EXAMPLE_ASSISTANT_SLUG]

    for slug in slugs:
        ex_resp = understanding_client.get(f"/api/v1/understanding/examples/{slug}")
        assert ex_resp.status_code == 200
        ex_data = ex_resp.json()
        assert [lnk["link_key"] for lnk in ex_data["baseline_report"]["links"]] == list(SIX_LINK_KEYS)
        assert ex_data["baseline_report"]["target_code_executed"] is False
        assert ex_data["baseline_report"]["automated_security_audit"] is False
        assert any(
            dc["status"] == "historical_needs_revalidation"
            for dc in ex_data["post_change_revalidation_report"]["documentation_claims"]
        )
        assert ex_data["post_change_revalidation_report"]["human_corrections"][0]["promoted_to_policy"] is False

    # Materialize Example 1 (`schedule-policy-to-export`) into a real Git repo, register, scan & evolve
    repo_dir = tmp_path / "duty_roster_repo"
    materialize_understanding_example(EXAMPLE_SCHEDULE_SLUG, repo_dir, stage="baseline", init_git=True)
    register_target(
        db_session,
        TargetProjectCreate(
            slug="duty-roster-lab",
            name="Duty Roster Lab",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )

    base_explain = understanding_client.get(
        "/api/v1/understanding/explain",
        params={"target_slug": "duty-roster-lab", "observed_at": "2026-11-16T15:00:00Z"},
    )
    assert base_explain.status_code == 200
    b_json = base_explain.json()
    assert b_json["overall_missing_joins"]
    assert b_json["outcome_lifecycles"][1]["blind_retry_prohibited"] is True
    assert b_json["preservation_evaluations"][0]["verdict"] == "failed_regression"

    # Mutate repo to `candidate` stage; verify baseline explanation is invalidated as historical!
    materialize_understanding_example(EXAMPLE_SCHEDULE_SLUG, repo_dir, stage="candidate", init_git=True)
    cand_analyze = understanding_client.post(
        "/api/v1/understanding/analyze",
        json={
            "target_slug": "duty-roster-lab",
            "observed_at": "2026-11-16T15:05:00Z",
            "human_corrections": [
                {"note": "Retaining global standby weight on night_crew conflict is under domain review."}
            ],
        },
    )
    assert cand_analyze.status_code == 200
    c_json = cand_analyze.json()
    assert c_json["evidence_revision"] != b_json["evidence_revision"]
    assert c_json["preservation_evaluations"][0]["verdict"] == "equivalent_valid_alternatives"
    assert c_json["human_corrections"][0]["promoted_to_policy"] is False
    assert any(
        dc["status"] == "historical_needs_revalidation" for dc in c_json["documentation_claims"]
    )


def test_bundle_path_symlink_traversal_and_depth_guards(
    tmp_path: Path,
    understanding_client: TestClient,
) -> None:
    real_file = tmp_path / "real.json"
    real_file.write_text(json.dumps({"question": "ok"}), encoding="utf-8")
    sym_file = tmp_path / "sym.json"
    sym_file.symlink_to(real_file)

    with pytest.raises(ValueError, match="Symlink"):
        read_understanding_bundle_file(sym_file)
    with pytest.raises(ValueError, match="traversal"):
        read_understanding_bundle_file("subdir/../real.json", root_dir=tmp_path)

    # Deeply nested JSON (> 64) rejected with 422
    nested: dict[str, object] = {"leaf": 1}
    for _ in range(70):
        nested = {"wrap": nested}
    resp = understanding_client.post("/api/v1/understanding/analyze", json={"bundle": nested})
    assert resp.status_code == 422

    # Direct bare-scan fallback (no companion bundle) extracts static PolicyFieldConsumption
    bare_report = analyze_understanding_bundle(UnderstandingAnalyzeRequest(question="Headless check"))
    assert [lnk.link_key for lnk in bare_report.links] == list(SIX_LINK_KEYS)
    assert bare_report.overall_missing_joins



def test_assistant_example_materialization_and_static_ast_fallback(
    tmp_path: Path,
    db_session: Session,
    understanding_client: TestClient,
) -> None:
    """Verify Example 2 materialization AND static PolicyFieldConsumption fallback without bundle."""
    gw_dir = tmp_path / "assistant_gateway_repo"
    materialize_understanding_example(EXAMPLE_ASSISTANT_SLUG, gw_dir, stage="baseline", init_git=True)
    register_target(
        db_session,
        TargetProjectCreate(
            slug="assistant-gateway-lab",
            name="Assistant Gateway Lab",
            repo_path=str(gw_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )

    gw_explain = understanding_client.get(
        "/api/v1/understanding/explain",
        params={"target_slug": "assistant-gateway-lab", "observed_at": "2026-11-16T15:00:00Z"},
    )
    assert gw_explain.status_code == 200
    gw_json = gw_explain.json()
    assert gw_json["runtime_provenance"][0]["overall_status"] == "stale_running_process"
    assert gw_json["outcome_lifecycles"][0]["current_stage"] == "executed_missing_followup_grounding"
    assert gw_json["outcome_lifecycles"][1]["current_stage"] == "supplied_answer_unrecorded"
    assert gw_json["preservation_evaluations"][0]["failed_preserved_capabilities"] == [
        "owner_text:memory_context_packet"
    ]
    assert gw_json["documentation_claims"][0]["status"] == "historical_needs_revalidation"

    # Remove companion bundle from Example 1 repo to prove static PolicyFieldConsumption fallback
    static_only_dir = tmp_path / "static_roster_repo"
    materialize_understanding_example(EXAMPLE_SCHEDULE_SLUG, static_only_dir, stage="baseline", init_git=False)
    (static_only_dir / ".wythe" / "understanding_bundle.json").unlink()
    register_target(
        db_session,
        TargetProjectCreate(
            slug="static-roster-lab",
            name="Static Roster Lab",
            repo_path=str(static_only_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    static_resp = understanding_client.get(
        "/api/v1/understanding/explain",
        params={"target_slug": "static-roster-lab"},
    )
    assert static_resp.status_code == 200
    st_json = static_resp.json()
    assert st_json["evidence_revision"].startswith("non_git:")
    assert st_json["effective_authority"]
    assert any(a["evidence_state"] == "bypassed" for a in st_json["effective_authority"])

    missing_ex = understanding_client.get("/api/v1/understanding/examples/nonexistent-example")
    assert missing_ex.status_code == 404
