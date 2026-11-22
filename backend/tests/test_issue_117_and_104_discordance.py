"""Regression & acceptance suite for Issue #104 and Issue #117 (Cross-Channel Continuity & Single-View Divergence)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.plugin_registry import discover_plugins
from app.main import create_app, initialize_database
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target
from app.services.scanner_service import run_target_scan
from app.services.understanding_service import (
    UnderstandingAnalyzeRequest,
    analyze_understanding_bundle,
)
from wythe_examples.understanding_examples import (
    EXAMPLE_ASSISTANT_SLUG,
    build_shipped_understanding_example,
)
from wythe_plugin_agent_discordance import evaluate_agent_discordance


def test_issue_104_requires_positive_commit_predecessor_and_delivery_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify #104: empty, rejected, terminal-less settled, & unlinked/unknown-delivery never get `supported`."""
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "state_104"))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{tmp_path / 'issue_104.db'}")
    initialize_database()

    variants = {
        "empty": {},
        "rejected": {"current_stage": "rejected", "delivery_status": "unknown"},
        "missing_terminal_state": {"current_stage": "authoritatively_settled"},
        "unlinked_transitions": {
            "transitions": [
                {"stage": "executed", "state_digest": "state-a"},
                {"stage": "delivered_to_human"},
            ]
        },
        "bare_delivered_without_receipt": {
            "current_stage": "delivered_to_human",
            "delivery_status": "delivered",
        },
    }

    with TestClient(create_app()) as client:
        results: dict[str, dict[str, object]] = {}
        for name, item in variants.items():
            resp = client.post(
                "/api/v1/understanding/analyze",
                json={"bundle": {"outcomes": [item]}},
            )
            assert resp.status_code == 200, resp.text
            results[name] = resp.json()

    # 1. Empty and rejected must never yield committed_result == "supported"
    empty_links = {lnk["link_key"]: lnk["state"] for lnk in results["empty"]["links"]}  # type: ignore[index]
    assert empty_links["committed_result"] != "supported"
    assert empty_links["human_visible_result"] != "supported"

    rej_links = {lnk["link_key"]: lnk["state"] for lnk in results["rejected"]["links"]}  # type: ignore[index]
    rej_out = results["rejected"]["outcome_lifecycles"][0]  # type: ignore[index]
    assert rej_links["committed_result"] == "degraded_or_drifted"
    assert rej_out["producer_claimed_stage"] == "rejected"
    assert rej_out["producer_claimed_delivery_status"] == "unknown"

    # 2. Terminal-less authoritatively_settled must NOT become settled_committed or supported
    mts_out = results["missing_terminal_state"]["outcome_lifecycles"][0]  # type: ignore[index]
    mts_links = {lnk["link_key"]: lnk["state"] for lnk in results["missing_terminal_state"]["links"]}  # type: ignore[index]
    assert mts_out["settlement_state"] == "unknown"
    assert mts_links["committed_result"] == "unverified"
    assert "authoritative_terminal_settlement_state" in mts_out["missing_joins"]

    # 3. Unlinked multi-step transitions must NOT get predecessor_chain_verified=True or supported links
    unl_out = results["unlinked_transitions"]["outcome_lifecycles"][0]  # type: ignore[index]
    unl_links = {lnk["link_key"]: lnk["state"] for lnk in results["unlinked_transitions"]["links"]}  # type: ignore[index]
    assert unl_out["predecessor_chain_verified"] is False
    assert "unlinked_transition_step_2" in unl_out["missing_joins"]
    assert unl_links["committed_result"] == "unverified"
    assert unl_links["human_visible_result"] == "unverified"

    # 4. Bare delivered_to_human without receipt/digest/grounded-tool backing stays unverified
    bare_out = results["bare_delivered_without_receipt"]["outcome_lifecycles"][0]  # type: ignore[index]
    bare_links = {lnk["link_key"]: lnk["state"] for lnk in results["bare_delivered_without_receipt"]["links"]}  # type: ignore[index]
    assert bare_out["positive_delivery_established"] is False
    assert bare_links["human_visible_result"] == "unverified"


def test_issue_117_three_acceptance_criteria_and_linked_verdict_sentence() -> None:
    """Verify #117 AC1, AC2, AC3, and exact linked-clause verdict sentence on shipped example."""
    ex = build_shipped_understanding_example(EXAMPLE_ASSISTANT_SLUG)
    base = ex.baseline_report
    cand = ex.candidate_report

    # Exact target output sentence on baseline, with 4th clause forced unverified by missing receipt
    assert base.verdict_sentence == (
        "AtlasVoice recalled the task by voice. "
        "The app later read the updated value. "
        "SandboxRunner said it could not retrieve the task. "
        "Its storage-access decision is unverified because the authorization receipt is missing."
    )
    assert [c.state for c in base.verdict_clauses] == [
        "supported",
        "supported",
        "supported",
        "unverified",
    ]
    assert base.verdict_clauses[0].evidence_ref == "sdk:continuity-voice-07"
    assert base.verdict_clauses[3].missing_receipt == "sdk:authz-deny-sandbox-07"
    assert [c.state for c in cand.verdict_clauses] == [
        "supported",
        "supported",
        "supported",
        "supported",
    ]

    # AC 1: FaceTime 60-minute limit rule vs 2 predictions vs expiry observation + open delivery join
    comp_base = base.rule_prediction_comparisons[0]
    assert comp_base.owner_rule.source_ref == "docs/policies/voice-session-limits.md:18"
    assert comp_base.refuted_prediction_ids == ["pred-hard-hangup"]
    assert comp_base.matched_prediction_ids == ["pred-soft-advisory"]
    assert comp_base.observed_result is not None
    assert comp_base.observed_result.delivery_verified is False
    assert comp_base.state == "degraded_or_drifted"
    assert "positive_device_delivery_receipt" in comp_base.missing_joins
    assert any("phone" in q for q in comp_base.open_questions)
    assert cand.rule_prediction_comparisons[0].state == "supported"

    # AC 2: Storage != Eligible != Present in Turn + EdgeGateway hop_only vs caller_verified (#105)
    fd_base = base.first_divergence
    assert fd_base is not None
    assert fd_base.exists_in_storage == "present"
    assert fd_base.eligible_for_actor == "present"
    assert fd_base.present_in_turn == "absent"
    assert fd_base.observed_hop == "EdgeGateway"
    assert fd_base.caller_attribution_state == "hop_only"
    assert fd_base.attributed_caller is None
    assert fd_base.unattributed_candidate_callers == ["AtlasVoice", "SandboxRunner"]

    fd_cand = cand.first_divergence
    assert fd_cand is not None
    assert fd_cand.present_in_turn == "present"
    assert fd_cand.caller_attribution_state == "caller_verified"
    assert fd_cand.attributed_caller == "AtlasVoice"

    # AC 3: Single-variable perturbation matrix (text->voice, AtlasVoice->SandboxRunner, strip receipt -> unverified)
    assert len(base.perturbation_matrix) == 3
    assert [p.conclusion_state for p in base.perturbation_matrix] == [
        "supported",
        "supported",
        "unverified",
    ]
    assert all(p.passed for p in base.perturbation_matrix)
    assert base.perturbation_matrix[2].missing_receipt_id == "sdk:authz-deny-sandbox-07"


def test_issue_117_adversarial_clause_and_hop_attribution_guards() -> None:
    """Ensure forged `supported` labels without receipts degrade to `unverified` / `hop_only`."""
    rep = analyze_understanding_bundle(
        UnderstandingAnalyzeRequest(
            bundle={
                "question": "Adversarial receipt & hop check",
                "verdict_clauses": [
                    {
                        "clause_id": "forged-supported-no-ref",
                        "text": "Claimed supported without receipt.",
                        "state": "supported",
                    },
                    {
                        "clause_id": "forged-supported-with-missing",
                        "text": "Claimed supported despite missing receipt.",
                        "state": "supported",
                        "evidence_ref": "sdk:present",
                        "missing_receipt": "sdk:required-authz",
                    },
                ],
                "first_divergence": {
                    "stage_label": "Hop Only Check",
                    "observed_hop": "EdgeGateway",
                    "attributed_caller": "AtlasVoice",  # forged caller without caller_receipt_ref!
                    "exists_in_storage": True,  # forged True without storage_source_ref!
                    "eligible_for_actor": True,
                    "eligibility_source_ref": "config/capabilities.json:4",
                    "present_in_turn": False,
                },
                "rule_prediction_comparisons": [
                    {
                        "comparison_id": "forged-delivery",
                        "owner_rule": {
                            "statement": "60m limit",
                            "source_ref": "docs/rule.md:1",
                        },
                        "implementation_predictions": [
                            {
                                "prediction_id": "p1",
                                "predicted_at_boundary": "continue",
                                "source_ref": "app/router.py:2",
                                "match_state": "consistent_with_observation",
                            }
                        ],
                        "observed_result": {
                            "summary": "continued",
                            "source_ref": "receipt:call:1",
                            "delivery_verified": True,  # forged True without delivery_receipt_ref!
                        },
                    }
                ],
            }
        )
    )
    assert [c.state for c in rep.verdict_clauses] == ["unverified", "unverified"]
    assert rep.first_divergence is not None
    assert rep.first_divergence.caller_attribution_state == "hop_only"
    assert rep.first_divergence.attributed_caller is None
    assert "AtlasVoice" in rep.first_divergence.unattributed_candidate_callers
    assert rep.first_divergence.exists_in_storage == "unverified"
    assert rep.rule_prediction_comparisons[0].observed_result is not None
    assert rep.rule_prediction_comparisons[0].observed_result.delivery_verified is False
    assert rep.rule_prediction_comparisons[0].state != "supported"


def test_agent_discordance_plugin_continuity_isolation_missing_receipts_and_mcp(
    tmp_path: Path,
    db_session,
) -> None:
    """Verify `wythe-plugin-agent-discordance` DISC-001, DISC-002, benign cache/wording, & guardrails."""
    manifest = {
        "routes": [
            {
                "route_id": "assistant_text",
                "agent_id": "primary_voice",
                "principal_scope": "owner",
                "continuity_group": "owner_continuity",
                "expected_policy_version": "pol-v4",
                "canary_task_id": "task-harmless-07",
            },
            {
                "route_id": "assistant_voice",
                "agent_id": "primary_voice",
                "principal_scope": "owner",
                "continuity_group": "owner_continuity",
                "expected_policy_version": "pol-v4",
                "canary_task_id": "task-harmless-07",
            },
            {
                "route_id": "assistant_video_fragmented",
                "agent_id": "primary_voice",
                "principal_scope": "owner",
                "continuity_group": "owner_continuity",
                "expected_policy_version": "pol-v4",
            },
            {
                "route_id": "sandbox_cli_leak",
                "agent_id": "sandbox_runner",
                "principal_scope": "owner",
                "isolated_from_agents": ["primary_voice", "nightly_batch"],
            },
            {
                "route_id": "public_webhook",
                "agent_id": "primary_voice",
                "principal_scope": "counterparty",
                "explicit_privacy_boundary": True,
            },
            {
                "route_id": "edge_hop_only_route",
                "agent_id": "primary_voice",
                "principal_scope": "owner",
            },
            {
                "route_id": "no_receipt_route",
                "agent_id": "nightly_batch",
                "principal_scope": "owner",
            },
        ]
    }
    receipts = {
        "observations": [
            {
                "route_id": "assistant_text",
                "observed_agent_id": "primary_voice",
                "observed_policy_version": "pol-v4",
                "caller_receipt_id": "rcpt-c1",
                "authz_receipt_id": "rcpt-a1",
                "canary_recovered": True,
            },
            {
                "route_id": "assistant_voice",
                "observed_agent_id": "primary_voice",
                "observed_policy_version": "pol-v4",
                "caller_receipt_id": "rcpt-c2",
                "authz_receipt_id": "rcpt-a2",
                "canary_recovered": True,
                "cache_hit": False,  # KV-cache miss must NOT trigger DISC-001
                "wording_differs_from_sibling": True,  # Wording variance must NOT trigger DISC-001
            },
            {
                "route_id": "assistant_video_fragmented",
                "observed_agent_id": "primary_voice",
                "observed_policy_version": "pol-v3-stale",
                "caller_receipt_id": "rcpt-c3",
                "authz_receipt_id": "rcpt-a3",
                "canary_recovered": False,
            },
            {
                "route_id": "sandbox_cli_leak",
                "observed_agent_id": "sandbox_runner",
                "caller_receipt_id": "rcpt-c4",
                "authz_receipt_id": "rcpt-a4",
                "accessed_task_id": "task-harmless-07",
                "canary_recovered": True,  # Cross-agent leak -> DISC-002!
            },
            {
                "route_id": "public_webhook",
                "observed_agent_id": "primary_voice",
                "caller_receipt_id": "rcpt-c5",
                "authz_receipt_id": "rcpt-a5",
                "canary_recovered": False,  # Explicit counterparty boundary -> valid!
            },
            {
                "route_id": "edge_hop_only_route",
                "observed_hop": "EdgeGateway",
                "authz_receipt_id": "rcpt-a6",  # Missing caller_receipt_id -> hop_only!
            },
        ]
    }

    eval_rep = evaluate_agent_discordance(manifest, receipts)
    assert eval_rep.supported_routes == ["assistant_text", "assistant_voice"]
    assert eval_rep.valid_boundary_routes == ["public_webhook"]
    assert eval_rep.hop_only_routes == ["edge_hop_only_route"]
    assert eval_rep.unverified_routes == ["no_receipt_route"]
    assert {v.rule_code for v in eval_rep.violations} == {"DISC-001", "DISC-002"}

    # Forbidden sensitive/transcript payloads fail closed
    with pytest.raises(ValueError, match="transcript"):
        evaluate_agent_discordance(manifest, {"observations": [{"route_id": "assistant_text", "transcript": "hi"}]})

    # Full target scan integration with opt-in local plugin + MCP tool handler
    repo_dir = tmp_path / "discordance_repo"
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "backend" / "schema.sql").write_text("CREATE TABLE items (id INT PRIMARY KEY);\n", encoding="utf-8")
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo_dir / ".wythe").mkdir()
    (repo_dir / ".wythe" / "agent_routes.json").write_text(json.dumps(manifest), encoding="utf-8")
    (repo_dir / ".wythe" / "agent_receipts.json").write_text(json.dumps(receipts), encoding="utf-8")

    plugins = discover_plugins(
        local_plugin_modules=["wythe_plugin_agent_discordance.plugin"],
        allow_local_plugins=True,
    )
    disc_spec = next(p for p in plugins if p.name == "agent-discordance")
    assert [r.rule_code for r in disc_spec.rules] == ["DISC-001", "DISC-002"]
    mcp_res = json.loads(
        disc_spec.mcp_tools[0].handler(
            db_session,
            {"routes_manifest": manifest, "receipts_bundle": receipts},
        )
    )
    assert mcp_res["supported_routes"] == ["assistant_text", "assistant_voice"]
    assert mcp_res["hop_only_routes"] == ["edge_hop_only_route"]

    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="discordance-lab",
            name="Discordance Lab",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    scan_rep = run_target_scan(
        db_session,
        target,
        strict_gate=True,
        persist_snapshot=False,
        allow_local_plugins=True,
        local_plugin_modules=["wythe_plugin_agent_discordance.plugin"],
    )
    codes = {f.rule_code for f in scan_rep.findings}
    assert {"DISC-001", "DISC-002"} <= codes
