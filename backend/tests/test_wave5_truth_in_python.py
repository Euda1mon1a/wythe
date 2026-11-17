"""Wave 5 'Truth in Python' 7-case AST policy precision & cross-surface drift tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_policy_consumption import analyze_module_policy_table_read
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.cli import main as cli_main
from app.core.policy_context import policy_tokens_scope
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target
from app.services.scanner_service import run_target_scan
from wythe_examples.truth_in_python_lab import (
    audit_cross_surface_policy_drift,
    materialize_truth_in_python_fixture,
)


def _edge_for_service(edges, service_stem: str, table_id: str):
    return next(
        e
        for e in edges
        if e.kind == "reads_truth"
        and service_stem in e.source_id
        and e.target_id == table_id
    )


def test_truth_in_python_all_seven_mandatory_cases(tmp_path: Path) -> None:
    """Verify all 7 mandatory 'Truth in Python' policy consumption cases and causal lines."""
    fixture_dir = materialize_truth_in_python_fixture(tmp_path / "warehouse_quota_repo")
    truth = PostgresSqlAlchemyAdapter().extract(fixture_dir, "backend")
    manip = PythonFastApiAdapter().extract(fixture_dir, "backend", truth)

    findings_by_file: dict[str, list] = {}
    for f in manip.findings:
        findings_by_file.setdefault(f.source_file, []).append(f)

    # Case 1: Consumed policy field (`row.max_batch_quota` -> guard, write sink, return)
    e1 = _edge_for_service(manip.edges, "case1_consumed_enforcer", "t:batch_quota_policies")
    assert e1.policy_field_consumption is not None
    assert e1.policy_field_consumption.state == "consumed"
    assert e1.policy_field_consumption.mechanism == "field_controls_result"
    assert e1.policy_field_consumption.consumed_columns == ["max_batch_quota"]
    assert e1.policy_field_consumption.unconsumed_policy_columns == []
    assert e1.policy_field_consumption.substituted_constants == []
    case1_manip = [
        f
        for f in findings_by_file.get("backend/app/services/case1_consumed_enforcer.py", ())
        if f.rule_code == "MANIP-001"
    ]
    assert case1_manip == []

    # Case 2: Bypassed policy field (`.id`/`.name` read, `max_batch_quota` ignored, hardcoded `40`)
    e2 = _edge_for_service(manip.edges, "case2_bypassed_validator", "t:batch_quota_policies")
    assert e2.policy_field_consumption is not None
    assert e2.policy_field_consumption.state == "bypassed"
    assert e2.policy_field_consumption.mechanism == "constant_or_fallback_wins"
    assert e2.policy_field_consumption.unconsumed_policy_columns == ["max_batch_quota"]
    assert e2.policy_field_consumption.substituted_constants == ["40"]
    case2_manip = [
        f
        for f in findings_by_file.get("backend/app/services/case2_bypassed_validator.py", ())
        if f.rule_code == "MANIP-001"
    ]
    assert len(case2_manip) == 1
    assert case2_manip[0].line == 9
    assert "backend/app/services/case2_bypassed_validator.py:9" in case2_manip[0].detail
    assert "`40`" in case2_manip[0].detail

    # Case 3: Explicit missing-value fallback (`is not None else 25`)
    e3 = _edge_for_service(manip.edges, "case3_missing_fallback", "t:batch_quota_policies")
    assert e3.policy_field_consumption is not None
    assert e3.policy_field_consumption.state == "consumed"
    assert e3.policy_field_consumption.mechanism == "field_controls_result"
    assert e3.policy_field_consumption.consumed_columns == ["max_batch_quota"]
    assert e3.policy_field_consumption.substituted_constants == []
    assert e3.policy_field_consumption.fallback_constants == ["25"]
    assert "zero-clobbering" not in e3.policy_field_consumption.note

    # Case 4: Valid zero-valued policy (`is not None else 15`) vs truthiness clobber (`or 15`)
    e4_safe = _edge_for_service(manip.edges, "case4a_zero_preserved", "t:cooldown_policies")
    assert e4_safe.policy_field_consumption is not None
    assert e4_safe.policy_field_consumption.state == "consumed"
    assert e4_safe.policy_field_consumption.fallback_constants == ["15"]
    assert "zero-clobbering" not in e4_safe.policy_field_consumption.note

    e4_clobber = _edge_for_service(manip.edges, "case4b_zero_clobbered", "t:cooldown_policies")
    assert e4_clobber.policy_field_consumption is not None
    assert e4_clobber.policy_field_consumption.state == "consumed"
    assert e4_clobber.policy_field_consumption.fallback_constants == ["15"]
    assert "zero-clobbering" in e4_clobber.policy_field_consumption.note
    assert "`min_cooldown_minutes` -> `15`" in e4_clobber.policy_field_consumption.note
    assert "overwrites valid `0`" in e4_clobber.policy_field_consumption.note

    # Case 5: Shadowed / overwritten local value (`limit = row.max_batch_quota` -> `limit = 50`)
    e5 = _edge_for_service(manip.edges, "case5_shadowed_local", "t:batch_quota_policies")
    assert e5.policy_field_consumption is not None
    assert e5.policy_field_consumption.state == "bypassed"
    assert e5.policy_field_consumption.mechanism == "constant_or_fallback_wins"
    assert e5.policy_field_consumption.unconsumed_policy_columns == ["max_batch_quota"]
    assert e5.policy_field_consumption.substituted_constants == ["50"]
    assert "local `limit` overwritten at line 10" in e5.policy_field_consumption.note
    case5_manip = [
        f
        for f in findings_by_file.get("backend/app/services/case5_shadowed_local.py", ())
        if f.rule_code == "MANIP-001"
    ]
    assert len(case5_manip) == 1
    assert case5_manip[0].line == 10
    assert "backend/app/services/case5_shadowed_local.py:10" in case5_manip[0].detail

    # Case 6: Opaque helper handoff & dynamic `getattr` -> `unresolved`
    e6 = _edge_for_service(manip.edges, "case6_opaque_dynamic", "t:batch_quota_policies")
    assert e6.policy_field_consumption is not None
    assert e6.policy_field_consumption.state == "unresolved"
    assert e6.policy_field_consumption.mechanism == "dynamic_or_opaque_flow"
    case6_manip = [
        f
        for f in findings_by_file.get("backend/app/services/case6_opaque_dynamic.py", ())
        if f.rule_code == "MANIP-001"
    ]
    assert case6_manip == []

    # Case 7: Legitimate algorithmic / unit-conversion / protocol constants + solver constraint
    e7 = _edge_for_service(manip.edges, "case7_solver_and_algorithms", "t:batch_quota_policies")
    assert e7.policy_field_consumption is not None
    assert e7.policy_field_consumption.state == "consumed"
    assert e7.policy_field_consumption.mechanism == "field_controls_result"
    assert e7.policy_field_consumption.consumed_columns == ["max_batch_quota"]
    assert e7.policy_field_consumption.substituted_constants == []
    case7_manip = [
        f
        for f in findings_by_file.get("backend/app/services/case7_solver_and_algorithms.py", ())
        if f.rule_code == "MANIP-001"
    ]
    assert case7_manip == []

    # Even when custom DB vocabulary includes broad tokens like HOUR / RETRY / BYTES, Case 7 stays 0 FPs
    with policy_tokens_scope(("QUOTA", "CAPACITY", "HOUR", "RETRY", "BYTES", "BACKOFF")):
        manip_broad = PythonFastApiAdapter().extract(fixture_dir, "backend", truth)
        broad_case7 = [
            f
            for f in manip_broad.findings
            if f.source_file == "backend/app/services/case7_solver_and_algorithms.py"
            and f.rule_code == "MANIP-001"
        ]
        assert broad_case7 == []


def test_truth_in_python_cross_surface_conflict_and_full_scan(
    tmp_path: Path, monkeypatch, db_session: Session
) -> None:
    """Verify cross-surface drift across SQL (`32`), JSON (`28`), Python (`40`/`50`/`25`), & UI (`36`)."""
    fixture_dir = materialize_truth_in_python_fixture(
        tmp_path / "cross_surface_repo", init_git=True
    )
    drift = audit_cross_surface_policy_drift(fixture_dir)
    assert drift["has_conflict"] is True
    assert drift["distinct_values"] == [25, 28, 32, 36, 40, 50]
    by_surface = {s["surface"]: s["encoded_value"] for s in drift["surfaces"]}
    assert by_surface == {
        "sql_schema_default": 32,
        "json_policy_registry": 28,
        "python_validator_bypass": 40,
        "python_missing_fallback": 25,
        "python_shadowed_local": 50,
        "react_ui_helper": 36,
    }

    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="warehouse-quota-lab",
            name="Warehouse Quota Lab",
            repo_path=str(fixture_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    report = run_target_scan(db_session, target, persist_snapshot=True, strict_gate=True)
    rule_codes = {f.rule_code for f in report.findings}
    assert "MANIP-001" in rule_codes
    assert "DISP-001" in rule_codes
    assert "DISP-005" not in rule_codes
    assert len(report.chains) >= 2
    assert any(n.id == "t:batch_quota_policies" for n in report.nodes)
    assert any(n.id == "t:cooldown_policies" for n in report.nodes)

    ddl_truth = SqlDdlTruthAdapter().extract(fixture_dir, "backend")
    assert any(n.id == "t:registry:config/quota_policy_registry.json" for n in ddl_truth.nodes)

    # Note: CLI scan exits 1 when blocking findings (`MANIP-001` / `DISP-001`) fail strict gate, or 0 on scan!
    sqlite_path = tmp_path / "cli_scan.db"
    out_json = tmp_path / "scan_out.json"
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{sqlite_path}")
    assert cli_main(["scan", "--json", str(out_json), str(fixture_dir)]) == 0
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["summary"]["end_to_end_chains"] >= 2


def test_solver_literal_bypass_and_ternary_truthiness_zero_clobber_variants() -> None:
    """Verify solver `Add(var <= 40)` bypass and ternary/if-not zero-clobbering warnings."""
    solver_bypass_src = (
        "def apply_solver_cap(db, model, x):\n"
        "    row = db.scalars(select(BatchQuotaPolicy)).one()\n"
        "    _ = (row.id, row.name)\n"
        "    model.Add(x <= 40)\n"
        "    return {'id': row.id}\n"
    )
    res_bypass = analyze_module_policy_table_read(
        solver_bypass_src,
        table_label="batch_quota_policies",
        table_columns=["id", "name", "max_batch_quota"],
        policy_columns=["max_batch_quota"],
        active_scopes=["apply_solver_cap"],
        write_scopes=set(),
        func_calls={},
        model_symbols={"BatchQuotaPolicy"},
        sql_table_names={"batch_quota_policies"},
    )
    assert len(res_bypass) == 1
    assert res_bypass[0].state == "bypassed"
    assert res_bypass[0].mechanism == "constant_or_fallback_wins"
    assert res_bypass[0].substituted_constants == ("40",)
    assert res_bypass[0].lineno == 4

    ternary_clobber_src = (
        "def get_cooldown(db):\n"
        "    row = db.scalars(select(CooldownPolicy)).one()\n"
        "    val = row.min_cooldown_minutes if row.min_cooldown_minutes else 15\n"
        "    return val\n"
    )
    res_clob = analyze_module_policy_table_read(
        ternary_clobber_src,
        table_label="cooldown_policies",
        table_columns=["id", "min_cooldown_minutes"],
        policy_columns=["min_cooldown_minutes"],
        active_scopes=["get_cooldown"],
        write_scopes=set(),
        func_calls={},
        model_symbols={"CooldownPolicy"},
        sql_table_names={"cooldown_policies"},
    )
    assert len(res_clob) == 1
    assert res_clob[0].state == "consumed"
    assert res_clob[0].fallback_constants == ("15",)
    assert "zero-clobbering" in res_clob[0].note

