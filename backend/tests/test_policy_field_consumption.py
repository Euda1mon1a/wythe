"""Tests for per-reader / per-edge policy field-to-result consumption lineage."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.cli import main as cli_main
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.scanner_service import run_target_scan


def _write_synthetic_policy_repo(root: Path, service_body: str) -> Path:
    """Create a generic 3-tier repo with `ActivePolicy(id, cap)` and custom `policy_service.py`."""
    (root / "backend/app/models").mkdir(parents=True, exist_ok=True)
    (root / "backend/app/services").mkdir(parents=True, exist_ok=True)
    (root / "backend/app/api/routes").mkdir(parents=True, exist_ok=True)
    (root / "frontend/src/app").mkdir(parents=True, exist_ok=True)

    (root / "backend/app/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/models/__init__.py").write_text(
        "from app.models.policy import ActivePolicy\n__all__ = ['ActivePolicy']\n",
        encoding="utf-8",
    )
    (root / "backend/app/models/policy.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
        "class Base(DeclarativeBase):\n"
        "    pass\n\n"
        "class ActivePolicy(Base):\n"
        "    __tablename__ = 'active_policies'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    cap: Mapped[int]\n",
        encoding="utf-8",
    )
    (root / "backend/app/services/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/services/policy_service.py").write_text(
        service_body,
        encoding="utf-8",
    )
    (root / "backend/app/api/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/api/routes/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/api/routes/policies.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.policy_service import fetch_policies\n\n"
        "router = APIRouter(prefix='/api/policies')\n\n"
        "@router.get('')\n"
        "def list_policies(db=None):\n"
        "    return fetch_policies(db)\n",
        encoding="utf-8",
    )
    (root / "backend/app/main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import policies\n\n"
        "app = FastAPI()\n"
        "app.include_router(policies.router)\n",
        encoding="utf-8",
    )
    (root / "frontend/package.json").write_text(
        json.dumps({"name": "synthetic-ui", "dependencies": {"next": "15.0.0"}}),
        encoding="utf-8",
    )
    (root / "frontend/src/app/page.tsx").write_text(
        "export default async function PoliciesPage() {\n"
        "  const res = await fetch('/api/policies');\n"
        "  return <pre>{JSON.stringify(await res.json())}</pre>;\n"
        "}\n",
        encoding="utf-8",
    )
    return root


def test_cli_constant_wins_vs_database_field_used_triad_parity(
    tmp_path: Path, monkeypatch, capsys, db_session: Session
) -> None:
    """`constant_wins` vs `database_field_used` emit distinct lineage states and MANIP-001 counts."""
    const_repo = _write_synthetic_policy_repo(
        tmp_path / "constant_wins",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "MAX_SHIFT_CAP = 12\n\n"
        "def fetch_policies(db):\n"
        "    rows = db.scalars(select(ActivePolicy)).all()\n"
        "    return [{'id': p.id, 'cap': MAX_SHIFT_CAP} for p in rows]\n",
    )
    db_repo = _write_synthetic_policy_repo(
        tmp_path / "database_field_used",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "MAX_SHIFT_CAP = 12\n\n"
        "def fetch_policies(db):\n"
        "    rows = db.scalars(select(ActivePolicy)).all()\n"
        "    return [{'id': p.id, 'cap': p.cap} for p in rows]\n",
    )

    sqlite_file = tmp_path / "cli_triad.db"
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{sqlite_file}")
    const_json = tmp_path / "constant_wins.json"
    db_json = tmp_path / "database_field_used.json"

    assert cli_main(["scan", "--json", str(const_json), str(const_repo)]) == 0
    assert cli_main(["scan", "--json", str(db_json), str(db_repo)]) == 0

    const_payload = json.loads(const_json.read_text(encoding="utf-8"))
    db_payload = json.loads(db_json.read_text(encoding="utf-8"))

    const_edge = next(e for e in const_payload["edges"] if e["kind"] == "reads_truth")
    db_edge = next(e for e in db_payload["edges"] if e["kind"] == "reads_truth")

    assert const_edge["policy_field_consumption"]["state"] == "bypassed"
    assert const_edge["policy_field_consumption"]["mechanism"] == "constant_or_fallback_wins"
    assert const_edge["policy_field_consumption"]["policy_columns"] == ["cap"]
    assert const_edge["policy_field_consumption"]["consumed_columns"] == ["id"]
    assert const_edge["policy_field_consumption"]["unconsumed_policy_columns"] == ["cap"]
    assert const_edge["policy_field_consumption"]["substituted_constants"] == ["MAX_SHIFT_CAP"]

    assert db_edge["policy_field_consumption"]["state"] == "consumed"
    assert db_edge["policy_field_consumption"]["mechanism"] == "field_controls_result"
    assert db_edge["policy_field_consumption"]["consumed_columns"] == ["cap", "id"]
    assert db_edge["policy_field_consumption"]["unconsumed_policy_columns"] == []
    assert db_edge["policy_field_consumption"]["substituted_constants"] == []

    const_manip = [f for f in const_payload["findings"] if f["rule_code"] == "MANIP-001"]
    db_manip = [f for f in db_payload["findings"] if f["rule_code"] == "MANIP-001"]
    assert len(const_manip) == 2
    assert len(db_manip) == 1
    assert any(f["target_node_id"] == "t:active_policies" for f in const_manip)
    assert not any(f["target_node_id"] == "t:active_policies" for f in db_manip)
    assert any("Overrides database policy column(s)" in f["detail"] for f in const_manip)

    capsys.readouterr()
    assert cli_main(["context", str(const_repo), "t:active_policies"]) == 0
    cli_cone_out = capsys.readouterr().out
    assert "policy_field_consumption=bypassed" in cli_cone_out

    t_const = register_target(
        db_session,
        TargetProjectCreate(
            slug="triad-const",
            name="Triad Constant Wins",
            repo_path=str(const_repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    const_report = run_target_scan(db_session, t_const, persist_snapshot=True, strict_gate=True)
    cone = build_lineage_cone_slice(const_report, "t:active_policies")
    read_cone_edge = next(ce for ce in cone.cone_edge_items if ce.kind == "reads_truth")
    assert read_cone_edge.policy_field_consumption is not None
    assert read_cone_edge.policy_field_consumption.state == "bypassed"
    assert "policy_field_consumption=bypassed" in cone.markdown
    assert "[reader=`m:service:services.policy_service` -> target=`t:active_policies`]" in (
        cone.markdown
    )


def _extract_single_policy_edge_and_findings(repo: Path):
    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)
    read_edge = next(e for e in manip.edges if e.kind == "reads_truth")
    bypass_findings = [
        f
        for f in manip.findings
        if f.rule_code == "MANIP-001" and f.target_node_id == "t:active_policies"
    ]
    return truth, manip, read_edge, bypass_findings


def test_null_or_fallback_vs_unconditional_constant_override(tmp_path: Path) -> None:
    """`policy.cap or FALLBACK_CAP` is `consumed`; unconditional overwrite is `bypassed`."""
    or_repo = _write_synthetic_policy_repo(
        tmp_path / "or_fallback",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "FALLBACK_CAP = 8\n\n"
        "def fetch_policies(db):\n"
        "    row = db.scalars(select(ActivePolicy)).first()\n"
        "    eff = (row.cap if row is not None else FALLBACK_CAP) or FALLBACK_CAP\n"
        "    return {'id': row.id if row is not None else 0, 'cap': eff}\n",
    )
    _, _, or_edge, or_bypasses = _extract_single_policy_edge_and_findings(or_repo)
    assert or_edge.policy_field_consumption is not None
    assert or_edge.policy_field_consumption.state == "consumed"
    assert or_edge.policy_field_consumption.mechanism == "field_controls_result"
    assert "cap" in or_edge.policy_field_consumption.consumed_columns
    assert or_edge.policy_field_consumption.substituted_constants == []
    assert or_edge.policy_field_consumption.fallback_constants == ["FALLBACK_CAP"]
    assert or_bypasses == []

    overwrite_repo = _write_synthetic_policy_repo(
        tmp_path / "local_overwrite",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "HARD_CAP = 16\n\n"
        "def fetch_policies(db):\n"
        "    row = db.scalars(select(ActivePolicy)).first()\n"
        "    eff = row.cap\n"
        "    eff = HARD_CAP\n"
        "    payload = {'id': row.id, 'cap': row.cap}\n"
        "    payload['cap'] = eff\n"
        "    if row.cap is not None:\n"
        "        pass\n"
        "    return payload\n",
    )
    _, _, ov_edge, ov_bypasses = _extract_single_policy_edge_and_findings(overwrite_repo)
    assert ov_edge.policy_field_consumption is not None
    assert ov_edge.policy_field_consumption.state == "bypassed"
    assert ov_edge.policy_field_consumption.mechanism == "constant_or_fallback_wins"
    assert ov_edge.policy_field_consumption.consumed_columns == ["id"]
    assert ov_edge.policy_field_consumption.unconsumed_policy_columns == ["cap"]
    assert ov_edge.policy_field_consumption.substituted_constants == ["HARD_CAP"]
    assert len(ov_bypasses) == 1


def test_dead_branch_policy_column_access_is_bypassed(tmp_path: Path) -> None:
    """Policy columns touched only inside `if False:` or after unconditional `return` are bypassed."""
    dead_repo = _write_synthetic_policy_repo(
        tmp_path / "dead_branch",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "MAX_SHIFT_CAP = 12\n\n"
        "def fetch_policies(db):\n"
        "    row = db.scalars(select(ActivePolicy)).first()\n"
        "    if False:\n"
        "        return {'id': row.id, 'cap': row.cap}\n"
        "    return {'id': row.id, 'cap': MAX_SHIFT_CAP}\n"
        "    return {'id': row.id, 'cap': row.cap}\n",
    )
    _, _, dead_edge, dead_bypasses = _extract_single_policy_edge_and_findings(dead_repo)
    assert dead_edge.policy_field_consumption is not None
    assert dead_edge.policy_field_consumption.state == "bypassed"
    assert dead_edge.policy_field_consumption.consumed_columns == ["id"]
    assert dead_edge.policy_field_consumption.unconsumed_policy_columns == ["cap"]
    assert dead_edge.policy_field_consumption.substituted_constants == ["MAX_SHIFT_CAP"]
    assert len(dead_bypasses) == 1
    assert "dead/unreachable" in dead_bypasses[0].detail


def test_unresolved_dynamic_getattr_and_opaque_row_handoff(tmp_path: Path) -> None:
    """Dynamic `getattr` and opaque whole-row handoff emit `unresolved` with 0 false findings."""
    dyn_repo = _write_synthetic_policy_repo(
        tmp_path / "dynamic_getattr",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "def fetch_policies(db, field_name='cap'):\n"
        "    row = db.scalars(select(ActivePolicy)).first()\n"
        "    return {'id': row.id, 'value': getattr(row, field_name)}\n",
    )
    _, _, dyn_edge, dyn_bypasses = _extract_single_policy_edge_and_findings(dyn_repo)
    assert dyn_edge.policy_field_consumption is not None
    assert dyn_edge.policy_field_consumption.state == "unresolved"
    assert dyn_edge.policy_field_consumption.mechanism == "dynamic_or_opaque_flow"
    assert dyn_bypasses == []

    opaque_repo = _write_synthetic_policy_repo(
        tmp_path / "opaque_handoff",
        "from sqlalchemy import select\n"
        "from external_runtime import evaluate_policy_row\n"
        "from app.models.policy import ActivePolicy\n\n"
        "def fetch_policies(db):\n"
        "    row = db.scalars(select(ActivePolicy)).first()\n"
        "    return evaluate_policy_row(row)\n",
    )
    _, _, op_edge, op_bypasses = _extract_single_policy_edge_and_findings(opaque_repo)
    assert op_edge.policy_field_consumption is not None
    assert op_edge.policy_field_consumption.state == "unresolved"
    assert op_edge.policy_field_consumption.mechanism == "dynamic_or_opaque_flow"
    assert op_bypasses == []


def test_sql_projection_and_solver_guard_consumption(tmp_path: Path) -> None:
    """SQL `SELECT id` without `cap` is bypassed; `SELECT id, cap` feeding solver is consumed."""
    id_only_repo = _write_synthetic_policy_repo(
        tmp_path / "sql_id_only",
        "from sqlalchemy import text\n\n"
        "def fetch_policies(db):\n"
        "    rows = db.execute(text('SELECT id FROM active_policies')).all()\n"
        "    return [r[0] for r in rows]\n",
    )
    _, _, id_edge, id_bypasses = _extract_single_policy_edge_and_findings(id_only_repo)
    assert id_edge.policy_field_consumption is not None
    assert id_edge.policy_field_consumption.state == "bypassed"
    assert id_edge.policy_field_consumption.consumed_columns == ["id"]
    assert id_edge.policy_field_consumption.unconsumed_policy_columns == ["cap"]
    assert len(id_bypasses) == 1

    solver_repo = _write_synthetic_policy_repo(
        tmp_path / "sql_solver_guard",
        "from sqlalchemy import text\n\n"
        "def fetch_policies(db, solver=None):\n"
        "    row_id, row_cap = db.execute(text('SELECT id, cap FROM active_policies')).one()\n"
        "    if solver is not None:\n"
        "        solver.add_constraint(max_shifts=row_cap)\n"
        "    return {'id': row_id, 'applied': True}\n",
    )
    _, _, sol_edge, sol_bypasses = _extract_single_policy_edge_and_findings(solver_repo)
    assert sol_edge.policy_field_consumption is not None
    assert sol_edge.policy_field_consumption.state == "consumed"
    assert sol_edge.policy_field_consumption.consumed_columns == ["cap", "id"]
    assert sol_bypasses == []


def test_inverted_early_return_null_guard_and_coexisting_constant_on_consumed_reader(
    tmp_path: Path,
) -> None:
    """`if policy is not None: return ...` fallback and coexisting constants never falsely claim override."""
    inv_repo = _write_synthetic_policy_repo(
        tmp_path / "inverted_null_guard",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "MAX_SHIFT_CAP = 12\n\n"
        "def fetch_policies(db):\n"
        "    policy = db.scalars(select(ActivePolicy)).first()\n"
        "    if policy is not None:\n"
        "        return {'id': policy.id, 'cap': policy.cap}\n"
        "    return {'id': 0, 'cap': MAX_SHIFT_CAP}\n",
    )
    _, inv_manip, inv_edge, inv_bypasses = _extract_single_policy_edge_and_findings(inv_repo)
    assert inv_edge.policy_field_consumption is not None
    assert inv_edge.policy_field_consumption.state == "consumed"
    assert inv_edge.policy_field_consumption.mechanism == "field_controls_result"
    assert inv_edge.policy_field_consumption.unconsumed_policy_columns == []
    assert inv_edge.policy_field_consumption.substituted_constants == []
    assert inv_edge.policy_field_consumption.fallback_constants == ["MAX_SHIFT_CAP"]
    assert "null/falsy fallback `MAX_SHIFT_CAP`" in inv_edge.policy_field_consumption.note
    assert inv_bypasses == []
    const_findings = [f for f in inv_manip.findings if f.rule_code == "MANIP-001"]
    assert len(const_findings) == 1
    assert "Overrides database policy column(s)" not in const_findings[0].detail
    assert "Used as null/falsy fallback alongside `active_policies`" in const_findings[0].detail

    # Symmetric `if policy is None: pass else: return ...` followed by fallback return
    else_term_repo = _write_synthetic_policy_repo(
        tmp_path / "else_term_null_guard",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "MAX_SHIFT_CAP = 12\n\n"
        "def fetch_policies(db):\n"
        "    policy = db.scalars(select(ActivePolicy)).first()\n"
        "    if policy is None:\n"
        "        missing = True\n"
        "    else:\n"
        "        return {'id': policy.id, 'cap': policy.cap}\n"
        "    return {'id': 0 if missing else 1, 'cap': MAX_SHIFT_CAP}\n",
    )
    _, _, else_edge, else_bypasses = _extract_single_policy_edge_and_findings(else_term_repo)
    assert else_edge.policy_field_consumption is not None
    assert else_edge.policy_field_consumption.state == "consumed"
    assert else_edge.policy_field_consumption.substituted_constants == []
    assert else_edge.policy_field_consumption.fallback_constants == ["MAX_SHIFT_CAP"]
    assert else_bypasses == []

    # Coexisting unrelated constant returned alongside consumed policy column
    coexist_repo = _write_synthetic_policy_repo(
        tmp_path / "coexisting_constant",
        "from sqlalchemy import select\n"
        "from app.models.policy import ActivePolicy\n\n"
        "EXTRA_SHIFT_CAP = 50\n\n"
        "def fetch_policies(db):\n"
        "    policy = db.scalars(select(ActivePolicy)).first()\n"
        "    return {'id': policy.id, 'cap': policy.cap, 'extra_cap': EXTRA_SHIFT_CAP}\n",
    )
    _, co_manip, co_edge, co_bypasses = _extract_single_policy_edge_and_findings(coexist_repo)
    assert co_edge.policy_field_consumption is not None
    assert co_edge.policy_field_consumption.state == "consumed"
    assert co_edge.policy_field_consumption.unconsumed_policy_columns == []
    assert co_edge.policy_field_consumption.substituted_constants == []
    assert co_edge.policy_field_consumption.fallback_constants == []
    assert co_bypasses == []
    co_findings = [f for f in co_manip.findings if f.rule_code == "MANIP-001"]
    assert len(co_findings) == 1
    assert "Overrides database policy column(s)" not in co_findings[0].detail
