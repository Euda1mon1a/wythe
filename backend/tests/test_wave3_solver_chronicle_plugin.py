"""Wave 3 (#88): `wythe-plugin-solver-chronicle` 6-phase chronicle, CLI, MCP & forensics tests."""

from __future__ import annotations

import importlib.metadata
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "plugins" / "wythe-plugin-solver-chronicle" / "src"))

from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    PostScanCheckPlugin,
    discover_plugins,
    run_post_scan_plugins,
)
from app.db.session import get_session_factory
from app.main import initialize_database
from app.models import TargetProject
from app.services.scanner_service import run_target_scan
from app.services.viewport_service import (
    get_viewport_state,
    reset_viewport_bus,
)
from wythe_plugin_solver_chronicle import (
    WYTHE_PLUGIN,
    IncrementalSolverLogParser,
    SolverChroniclePlugin,
    handle_mcp_solver_chronicle,
    parse_cp_model_proto_text,
    parse_cp_solver_response_text,
    parse_solve_log_text,
    register_wythe_plugin,
    resolve_safe_companion_path,
    run_watch_solver_cli,
    synthesize_solver_chronicle,
)


class _FakeDist:
    def __init__(self, version: str = "0.1.0") -> None:
        import sysconfig

        self.version = version
        self._path = Path(sysconfig.get_path("purelib")) / f"wythe_plugin_solver_chronicle-{version}.dist-info"

    def locate_file(self, path: str) -> Path:
        return self._path.parent / path


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, fn: object) -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist("0.1.0")
        self._fn = fn

    def load(self) -> object:
        return self._fn


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    state_dir = tmp_path / "wythe_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    reset_viewport_bus()
    initialize_database()
    yield
    reset_viewport_bus()


def _init_git_repo(repo_dir: Path) -> None:
    env = {
        "GIT_AUTHOR_NAME": "Euda1mon1a",
        "GIT_AUTHOR_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Euda1mon1a",
        "GIT_COMMITTER_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin"),
    }
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True, env=env)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, env=env)
    subprocess.run(
        ["git", "commit", "-q", "-m", "Initialize synthetic warehouse solver repo"],
        cwd=repo_dir,
        check=True,
        env=env,
    )


def _create_warehouse_solver_repo(repo_dir: Path, *, clean_mode: bool = False) -> Path:
    """Create a 3-tier industrial warehouse dock & job-shop CP-SAT repository."""
    (repo_dir / "backend" / "app" / "solvers").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "services").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "api").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True)
    (repo_dir / "artifacts").mkdir(parents=True)

    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE dock_windows (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  dock_code TEXT NOT NULL,\n"
        "  min_slot INTEGER NOT NULL,\n"
        "  max_slot INTEGER NOT NULL,\n"
        "  max_capacity INTEGER NOT NULL\n"
        ");\n\n"
        "CREATE TABLE job_orders (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  order_code TEXT NOT NULL,\n"
        "  demand_units INTEGER NOT NULL,\n"
        "  penalty_weight INTEGER NOT NULL\n"
        ");\n\n"
        "CREATE TABLE solver_runs (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  run_status TEXT NOT NULL,\n"
        "  objective_val DOUBLE PRECISION,\n"
        "  best_bound_val DOUBLE PRECISION\n"
        ");\n",
        encoding="utf-8",
    )

    if clean_mode:
        solver_src = (
            "def add_dock_capacity_constraints(model, dock_slot_start, job_assign, rows):\n"
            "    if not rows:\n"
            "        return\n"
            "    for r in rows:\n"
            "        cap_lit = model.NewBoolVar('assume_dock_cap')\n"
            "        model.Add(dock_slot_start <= r['max_slot'] + r['max_capacity']).OnlyEnforceIf(cap_lit).WithName('dock_capacity_limit')\n"
            "        model.AddAssumptions([cap_lit])\n\n"
            "def add_machine_overlap_constraints(model, dock_slot_start, job_assign):\n"
            "    ov_lit = model.NewBoolVar('assume_overlap')\n"
            "    model.Add(dock_slot_start + job_assign >= 1).OnlyEnforceIf(ov_lit).WithName('machine_no_overlap')\n"
            "    model.AddAssumptions([ov_lit])\n\n"
            "def solve_warehouse_plan(db, cp_model):\n"
            '    docks = db.execute("SELECT id, min_slot, max_slot, max_capacity FROM dock_windows")\n'
            '    orders = db.execute("SELECT id, demand_units, penalty_weight FROM job_orders")\n'
            "    if not docks or not orders:\n"
            "        return {'status': 'EMPTY'}\n"
            "    model = cp_model.CpModel()\n"
            "    dock_slot_start = model.NewIntVar(docks[0]['min_slot'], docks[0]['max_slot'] + docks[0]['max_capacity'], 'dock_slot_start')\n"
            "    job_assign = model.NewBoolVar('job_assign')\n"
            "    machine_interval = model.NewIntervalVar(dock_slot_start, 4, dock_slot_start + 4, 'machine_interval')\n"
            "    add_dock_capacity_constraints(model, dock_slot_start, job_assign, docks)\n"
            "    add_machine_overlap_constraints(model, dock_slot_start, job_assign)\n"
            "    model.Minimize(orders[0]['penalty_weight'] * dock_slot_start + orders[0]['demand_units'] * job_assign)\n"
            "    solver = cp_model.CpSolver()\n"
            "    status = solver.Solve(model)\n"
            "    obj = solver.ObjectiveValue()\n"
            "    bnd = solver.BestObjectiveBound()\n"
            '    db.execute("INSERT INTO solver_runs (run_status, objective_val, best_bound_val) VALUES (\'OPTIMAL\', 10, 10)")\n'
            "    return {'status': status, 'objective': obj, 'best_bound': bnd, 'interval': machine_interval}\n"
        )
        validator_src = (
            "def validate_warehouse_solution(db, plan):\n"
            '    docks = db.execute("SELECT id, min_slot, max_slot, max_capacity FROM dock_windows")\n'
            '    orders = db.execute("SELECT id, demand_units, penalty_weight FROM job_orders")\n'
            "    if not docks or not orders:\n"
            "        return False\n"
            "    return (docks[0]['max_capacity'] + docks[0]['max_slot'] - docks[0]['min_slot']) >= (orders[0]['demand_units'] + orders[0]['penalty_weight'] * 0)\n"
        )
        ui_src = (
            "export default async function WarehouseStatusPage() {\n"
            "  const res = await fetch('/api/v1/solver/runs');\n"
            "  const data = await res.json();\n"
            "  return (\n"
            "    <main>\n"
            "      <span>{data.status === 'FEASIBLE' ? 'FEASIBLE (gap)' : 'Solved'}</span>\n"
            "      <small>{String(data.best_bound)}</small>\n"
            "    </main>\n"
            "  );\n"
            "}\n"
        )
    else:
        solver_src = (
            "HARDCODED_CAP_LIMIT = 25\n"
            "PENALTY_SCALE = 0.05\n"
            "BASE_WEIGHT = 10\n\n"
            "def add_dock_capacity_constraints(model, dock_slot_start, job_assign, rows):\n"
            "    for r in rows:\n"
            "        model.Add(dock_slot_start <= HARDCODED_CAP_LIMIT).WithName('dock_capacity_limit')\n\n"
            "def add_machine_overlap_constraints(model, dock_slot_start, job_assign):\n"
            "    model.Add(dock_slot_start + job_assign >= 1).WithName('machine_no_overlap')\n\n"
            "def add_unwired_pallet_constraints(model, dock_slot_start):\n"
            "    model.Add(dock_slot_start >= 0)\n\n"
            "def solve_warehouse_plan(db, cp_model):\n"
            '    docks = db.execute("SELECT id, dock_code FROM dock_windows")\n'
            '    orders = db.execute("SELECT id, demand_units, penalty_weight FROM job_orders")\n'
            "    model = cp_model.CpModel()\n"
            "    dock_slot_start = model.NewIntVar(0, 24, 'dock_slot_start')\n"
            "    job_assign = model.NewBoolVar('job_assign')\n"
            "    add_dock_capacity_constraints(model, dock_slot_start, job_assign, docks)\n"
            "    add_machine_overlap_constraints(model, dock_slot_start, job_assign)\n"
            "    truncated_w = int(PENALTY_SCALE * BASE_WEIGHT)\n"
            "    model.Minimize(truncated_w * dock_slot_start + orders[0]['penalty_weight'] * job_assign)\n"
            "    primary_solver = cp_model.CpSolver()\n"
            "    run_status = primary_solver.Solve(model)\n"
            "    polish_solver = cp_model.CpSolver()\n"
            "    run_status = polish_solver.Solve(model)\n"
            "    obj = primary_solver.ObjectiveValue()\n"
            '    db.execute("INSERT INTO solver_runs (run_status, objective_val) VALUES (\'OPTIMAL\', 12)")\n'
            "    return {'status': run_status, 'objective': obj}\n"
        )
        validator_src = (
            "def validate_warehouse_solution(db, plan):\n"
            '    docks = db.execute("SELECT id, max_capacity FROM dock_windows")\n'
            "    return bool(docks and plan)\n"
        )
        ui_src = (
            "export default async function WarehouseStatusPage() {\n"
            "  const res = await fetch('/api/v1/solver/runs');\n"
            "  await res.json();\n"
            "  return <main><span>Solved</span></main>;\n"
            "}\n"
        )

    (repo_dir / "backend" / "app" / "solvers" / "dock_solver.py").write_text(solver_src, encoding="utf-8")
    (repo_dir / "backend" / "app" / "services" / "plan_validator.py").write_text(validator_src, encoding="utf-8")
    (repo_dir / "backend" / "app" / "api" / "runs.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.solvers.dock_solver import solve_warehouse_plan\n"
        "from app.services.plan_validator import validate_warehouse_solution\n\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/solver/runs')\n"
        "def get_solver_runs(db=None):\n"
        "    plan = solve_warehouse_plan(db, None)\n"
        "    validate_warehouse_solution(db, plan)\n"
        '    rows = db.execute("SELECT id, run_status, objective_val, best_bound_val FROM solver_runs")\n'
        "    return {'plan': plan, 'runs': rows}\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.runs import router\n\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "page.tsx").write_text(ui_src, encoding="utf-8")
    _init_git_repo(repo_dir)
    return repo_dir


def _scan_repo(repo_dir: Path):
    factory = get_session_factory()
    with factory() as session:
        target = TargetProject(
            id=0,
            slug="warehouse-opt",
            name="Warehouse Optimization",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
            backend_subdir="backend",
            frontend_subdir="frontend",
            legacy_snapshot_relpath=None,
            description="Synthetic warehouse CP-SAT target",
            is_active=True,
        )
        return run_target_scan(session, target, strict_gate=True, persist_snapshot=False)


HEALTHY_OPTIMAL_LOG = """\
Starting CP-SAT solver v9.11.4210
Parameters: log_search_progress: true num_search_workers: 8
Initial optimization model 'warehouse_dock_plan': (model_fingerprint: 0x91ab20f)
#Variables: 48 (#bools: 32 #ints: 16 in objective)
#kLinear1: 20
#kLinear2: 18
#kInterval: 4
Starting presolve at 0.01s
  - rule 'affine_relations' was applied 6 times.
Presolve summary:
  - Presolved model has 28 variables and 22 constraints.
Symmetry detection: 2 generators and 4 orbits detected.
Starting search at 0.03s with 8 workers.
8 full problem subsolvers: [default_lp, no_lp, quick_restart, rins_lns, graph_dec_lns]
#1       0.06s best:180   next:[90,179]   quick_restart
#2       0.11s best:120   next:[105,119]  rins_lns
#Bound   0.14s best:120   next:[120,119]  default_lp
#Done    0.15s default_lp
CpSolverResponse summary:
status: OPTIMAL
objective: 120
best_bound: 120
booleans: 28
conflicts: 14
branches: 62
walltime: 0.152
"""


def test_entry_point_discovery_and_plugin_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = register_wythe_plugin()
    assert isinstance(plugin, SolverChroniclePlugin)
    assert plugin is WYTHE_PLUGIN
    assert isinstance(plugin, PostScanCheckPlugin)
    assert plugin.name == "solver-chronicle"
    assert plugin.version == "0.1.0"
    assert plugin.enabled_by_default is True
    assert "watch-solver" in plugin.cli_subcommands

    assert len(plugin.mcp_tools) == 1
    mcp_entry = plugin.mcp_tools[0]
    assert mcp_entry["name"] == "wythe_solver_chronicle"
    annotations = mcp_entry["definition"]["annotations"]
    assert annotations == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }

    orig_eps = importlib.metadata.entry_points

    def _patched_eps(**kwargs: Any) -> Any:
        if kwargs.get("group") == ENTRY_POINT_GROUP:
            return [
                _FakeEntryPoint(
                    "solver-chronicle",
                    "wythe_plugin_solver_chronicle:register_wythe_plugin",
                    register_wythe_plugin,
                )
            ]
        return orig_eps(**kwargs)

    monkeypatch.setattr(importlib.metadata, "entry_points", _patched_eps)
    discovered = discover_plugins(include_builtins=False, include_entry_points=True, strict_plugins=True)
    assert [s.name for s in discovered] == ["solver-chronicle"]
    assert discovered[0].kind == "post_scan_check"
    assert discovered[0].origin == "entry_point"

    repo_dir = _create_warehouse_solver_repo(tmp_path / "clean_repo", clean_mode=True)
    report = _scan_repo(repo_dir)
    digest_before = report.content_digest
    exec_res = run_post_scan_plugins(repo_dir, report, plugins=discovered, strict_plugins=True)
    assert exec_res.executed_plugins == ["solver-chronicle"]
    assert exec_res.findings == []
    assert report.content_digest == digest_before

    direct_check = plugin.check_report(repo_dir, report)
    assert direct_check["has_solver_pipeline"] is True
    assert direct_check["phase_count"] == 6
    assert report.content_digest == digest_before


def test_six_phase_healthy_chronicle_and_live_vs_replay_parity(tmp_path: Path) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "healthy_repo", clean_mode=True)
    report = _scan_repo(repo_dir)
    digest_before = report.content_digest

    replay_session = parse_solve_log_text(HEALTHY_OPTIMAL_LOG)
    replay_syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=replay_session,
        timeline_id="chron-healthy-test",
    )

    live_parser = IncrementalSolverLogParser()
    intermediate_snapshots = []
    for raw_line in HEALTHY_OPTIMAL_LOG.splitlines():
        live_parser.feed_line(raw_line)
        intermediate_snapshots.append(live_parser.snapshot())
    live_syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=live_parser.snapshot(),
        timeline_id="chron-healthy-test",
    )

    assert len(intermediate_snapshots) >= 15
    assert [f.model_dump() for f in live_syn.frames] == [
        f.model_dump() for f in replay_syn.frames
    ]
    assert [f.phase_key for f in replay_syn.frames] == [
        "1.Load",
        "2.Build",
        "3.Presolve",
        "4.Search",
        "5.Persist",
        "6.Render",
    ]
    assert [f.tier for f in replay_syn.frames] == [
        "truth",
        "manipulate",
        "manipulate",
        "manipulate",
        "truth",
        "display",
    ]
    assert all(f.status == "ok" for f in replay_syn.frames)
    assert replay_syn.live_following is True
    assert replay_syn.halted_reason is None
    assert replay_syn.active_phase_index == 5
    assert report.content_digest == digest_before


def test_six_phase_static_architectural_warnings_and_multi_solver(tmp_path: Path) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "warn_repo", clean_mode=False)
    report = _scan_repo(repo_dir)

    multi_solver_log = (
        "Starting CP-SAT solver v9.11\n"
        "Initial optimization model 'stage1_primary':\n"
        "#1 0.10s best:250 next:[180,249] rins_lns\n"
        "CpSolverResponse summary:\n"
        "status: FEASIBLE\n"
        "objective: 250\n"
        "best_bound: 180\n"
        "conflicts: 40\n"
        "branches: 120\n"
        "walltime: 5.0\n"
        "Starting CP-SAT solver v9.11\n"
        "Initial optimization model 'stage2_aux_polish':\n"
        "CpSolverResponse summary:\n"
        "status: OPTIMAL\n"
        "objective: 10\n"
        "best_bound: 10\n"
        "conflicts: 2\n"
        "branches: 4\n"
        "walltime: 0.05\n"
    )
    syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text(multi_solver_log),
    )
    f_load, f_build, _f_presolve, f_search, f_persist, f_render = syn.frames

    assert f_load.status == "warning"
    assert any("TRUTH-001" in s or "BYPASSED" in s for s in f_load.substeps)

    assert f_build.status == "warning"
    assert any("UNWIRED [MANIP-003]" in s and "add_unwired_pallet_constraints" in s for s in f_build.substeps)
    assert any("TRUNCATION [MANIP-001]" in s for s in f_build.substeps)

    assert any("Solver 1 (FEASIBLE) -> Solver 2 (OPTIMAL)" in s for s in f_search.substeps)

    assert f_persist.status == "warning"
    assert any("ASYMMETRY" in s and "t:job_orders" in s for s in f_persist.substeps)
    assert any("STATUS MASKING" in s for s in f_persist.substeps)
    assert any("GAP OMISSION" in s for s in f_persist.substeps)

    assert f_render.status == "warning"
    assert any("OPTIMISTIC UI" in s and "Solved" in s for s in f_render.substeps)


def test_forensic_class_1_model_invalid_halts_at_build_and_resolves_z0_and_truth(
    tmp_path: Path,
) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "cls1_repo", clean_mode=True)
    report = _scan_repo(repo_dir)

    proto_json = json.dumps(
        {
            "name": "warehouse_dock_plan",
            "variables": [
                {"name": "dock_slot_start[0]", "domain": [120, 60]},
                {"name": "job_assign[0]", "domain": [0, 1]},
                {"name": "machine_interval_size", "domain": [-8, -1]},
            ],
            "constraints": [
                {"name": "dock_capacity_limit", "linear": {"vars": [0], "coeffs": [1]}},
                {"name": "machine_interval_cst", "interval": {"start": 0, "size": 2}},
            ],
        }
    )
    proto = parse_cp_model_proto_text(proto_json)

    inv_log = (
        "Starting CP-SAT solver v9.11\n"
        "ValidateCpModel: Model is invalid:\n"
        "var #0 ('dock_slot_start[0]') has an invalid domain [120, 60] (lb > ub)\n"
        "CpSolverResponse summary:\n"
        "status: MODEL_INVALID\n"
    )
    syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text(inv_log),
        proto=proto,
        timeline_id="chron-cls1",
    )

    assert syn.forensics.forensic_class == "model_invalid"
    assert syn.forensics.submode == "inverted_bounds"
    assert syn.forensics.halted is True
    assert syn.forensics.halt_phase_index == 1
    assert syn.forensics.halt_phase_key == "2.Build"
    assert [f.status for f in syn.frames] == [
        "ok",
        "failed",
        "pending",
        "pending",
        "pending",
        "pending",
    ]
    assert syn.live_following is False
    assert len(syn.forensics.z0_builders) >= 1
    zb = syn.forensics.z0_builders[0]
    assert zb.source_file.endswith("dock_solver.py")
    assert zb.line >= 1
    assert "t:dock_windows" in syn.forensics.upstream_truth_tables
    assert any("min_slot" in c or "max_slot" in c for c in syn.forensics.upstream_truth_columns)

    # Also verify interval & overflow submodes under Class 1
    iv_syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text("ValidateCpModel: constraint #1 ('machine_interval') has negative size -8\n"),
        proto=proto,
    )
    assert iv_syn.forensics.forensic_class == "model_invalid"
    assert iv_syn.forensics.submode == "invalid_interval"
    assert iv_syn.frames[1].status == "failed"

    ov_syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text("ValidateCpModel: constraint #0: Possible integer overflow\n"),
        proto=proto,
    )
    assert ov_syn.forensics.forensic_class == "model_invalid"
    assert ov_syn.forensics.submode == "coefficient_overflow"


def test_forensic_class_2_presolve_infeasible_halts_at_presolve_with_neighborhood(
    tmp_path: Path,
) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "cls2_repo", clean_mode=True)
    report = _scan_repo(repo_dir)
    proto = parse_cp_model_proto_text(
        'name: "warehouse_dock_plan"\n'
        'variables { name: "dock_slot_start" domain: 0 domain: 24 }\n'
        'variables { name: "job_assign" domain: 0 domain: 1 }\n'
        'constraints { name: "dock_capacity_limit" linear { vars: 0 vars: 1 } }\n'
        'constraints { name: "machine_no_overlap" linear { vars: 0 vars: 1 } }\n'
    )
    presolve_log = (
        "Starting CP-SAT solver v9.11\n"
        "Initial optimization model 'warehouse_dock_plan':\n"
        "#Variables: 2\n"
        "Starting presolve at 0.01s\n"
        "  - rule 'linear: empty domain' was applied 1 time.\n"
        "Contradiction in constraint 'dock_capacity_limit' on 'dock_slot_start'\n"
        "Problem closed by presolve.\n"
        "CpSolverResponse summary:\n"
        "status: INFEASIBLE\n"
        "conflicts: 0\n"
        "branches: 0\n"
        "walltime: 0.02\n"
    )
    syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text(presolve_log),
        proto=proto,
    )
    assert syn.forensics.forensic_class == "presolve_infeasible"
    assert syn.forensics.halt_phase_index == 2
    assert [f.status for f in syn.frames] == [
        "ok",
        "ok",
        "failed",
        "pending",
        "pending",
        "pending",
    ]
    assert any("dock_solver.py" in z.source_file for z in syn.forensics.z0_builders)
    assert any("add_machine_overlap_constraints" in nb for nb in syn.forensics.neighborhood_builders)


def test_forensic_class_3_root_lp_infeasible_halts_at_search_root(tmp_path: Path) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "cls3_repo", clean_mode=True)
    report = _scan_repo(repo_dir)
    root_lp_log = (
        "Starting CP-SAT solver v9.11\n"
        "Initial optimization model 'warehouse_dock_plan':\n"
        "#Variables: 36\n"
        "Starting presolve at 0.01s\n"
        "Presolve summary:\n"
        "  - Presolved model has 30 variables and 24 constraints.\n"
        "Starting search at 0.03s with 8 workers.\n"
        "Root LP relaxation is infeasible\n"
        "#Done 0.04s default_lp\n"
        "CpSolverResponse summary:\n"
        "status: INFEASIBLE\n"
        "conflicts: 0\n"
        "branches: 0\n"
        "walltime: 0.042\n"
    )
    syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text(root_lp_log),
    )
    assert syn.forensics.forensic_class == "root_lp_infeasible"
    assert syn.forensics.halt_phase_index == 3
    assert [f.status for f in syn.frames] == [
        "ok",
        "ok",
        "ok",
        "failed",
        "pending",
        "pending",
    ]
    assert "t:dock_windows" in syn.forensics.upstream_truth_tables
    assert "t:job_orders" in syn.forensics.upstream_truth_tables


def test_forensic_class_4_assumption_core_vs_missing_assumptions(tmp_path: Path) -> None:
    clean_repo = _create_warehouse_solver_repo(tmp_path / "cls4_core_repo", clean_mode=True)
    clean_report = _scan_repo(clean_repo)
    proto = parse_cp_model_proto_text(
        json.dumps(
            {
                "name": "warehouse_dock_plan",
                "variables": [
                    {"name": "dock_slot_start", "domain": [0, 24]},
                    {"name": "assume_dock_cap", "domain": [0, 1]},
                    {"name": "assume_overlap", "domain": [0, 1]},
                ],
                "constraints": [
                    {
                        "name": "dock_capacity_limit",
                        "enforcement_literal": [1],
                        "linear": {"vars": [0], "coeffs": [1]},
                    },
                    {
                        "name": "machine_no_overlap",
                        "enforcement_literal": [-3],
                        "linear": {"vars": [0], "coeffs": [1]},
                    },
                ],
                "assumptions": [1, -3],
            }
        )
    )
    resp = parse_cp_solver_response_text(
        json.dumps(
            {
                "status": "INFEASIBLE",
                "num_conflicts": 45,
                "num_branches": 130,
                "sufficient_assumptions_for_infeasibility": [-3],
                "solve_log": (
                    "Starting CP-SAT solver v9.11\n"
                    "Starting presolve at 0.01s\n"
                    "Starting search at 0.02s with 4 workers.\n"
                    "CpSolverResponse summary:\n"
                    "status: INFEASIBLE\n"
                    "conflicts: 45\n"
                    "branches: 130\n"
                ),
            }
        )
    )
    inc_p = IncrementalSolverLogParser()
    inc_p.apply_response_summary(resp)
    core_syn = synthesize_solver_chronicle(
        clean_repo,
        clean_report,
        session=inc_p.snapshot(),
        proto=proto,
        response=resp,
    )
    assert core_syn.forensics.forensic_class == "assumption_core_or_missing_assumptions"
    assert core_syn.forensics.submode == "assumption_core"
    assert core_syn.forensics.halt_phase_index == 3
    assert core_syn.frames[3].status == "failed"
    assert core_syn.frames[4].status == "pending"
    assert any("add_machine_overlap_constraints" == z.func_name for z in core_syn.forensics.z0_builders)

    # 4b: Missing assumptions -> highlights un-assumed hard constraints & recommends soft-slack pass
    unassumed_repo = _create_warehouse_solver_repo(tmp_path / "cls4_noassump_repo", clean_mode=False)
    unassumed_report = _scan_repo(unassumed_repo)
    deep_inf_log = (
        "Starting CP-SAT solver v9.11\n"
        "Starting presolve at 0.01s\n"
        "Starting search at 0.02s with 8 workers.\n"
        "CpSolverResponse summary:\n"
        "status: INFEASIBLE\n"
        "conflicts: 820\n"
        "branches: 2400\n"
        "walltime: 1.85\n"
    )
    miss_syn = synthesize_solver_chronicle(
        unassumed_repo,
        unassumed_report,
        session=parse_solve_log_text(deep_inf_log),
    )
    assert miss_syn.forensics.forensic_class == "assumption_core_or_missing_assumptions"
    assert miss_syn.forensics.submode == "missing_assumptions"
    assert "soft-slack" in miss_syn.forensics.recommended_action
    assert len(miss_syn.forensics.z0_builders) >= 2


def test_forensic_class_5_scaling_expansion_and_stall_pathologies(tmp_path: Path) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "cls5_repo", clean_mode=True)
    report = _scan_repo(repo_dir)
    pathology_log = (
        "Starting CP-SAT solver v9.11\n"
        "Initial optimization model 'warehouse_dock_plan':\n"
        "#Variables: 200\n"
        "#kLinear2: 100\n"
        "Objective coefficient range: [1e+00, 1e+12]\n"
        "Starting presolve at 0.02s\n"
        "Expanded model has 1400 variables and 850 constraints\n"
        "Starting search at 0.10s with 8 workers.\n"
        "#1 0.50s best:9500 next:[100,9499] quick_restart\n"
        "'rins_lns': 0/60 (0.00% accepted)\n"
        "CpSolverResponse summary:\n"
        "status: FEASIBLE\n"
        "objective: 9500\n"
        "best_bound: 100\n"
        "conflicts: 12000\n"
        "branches: 45000\n"
        "walltime: 22.0\n"
    )
    syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text(pathology_log),
    )
    assert syn.forensics.forensic_class == "search_pathology"
    assert syn.forensics.halted is False
    kinds = {p.kind for p in syn.forensics.pathologies}
    assert kinds == {
        "extreme_coefficient_scaling",
        "presolve_expansion_blowup",
        "search_or_lns_stall",
    }
    assert syn.frames[2].status == "warning"
    assert syn.frames[3].status == "warning"
    assert syn.frames[4].status == "ok"
    assert syn.frames[5].status == "ok"


def test_watch_solver_cli_log_stdin_json_and_viewport_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "cli_repo", clean_mode=True)
    log_file = repo_dir / "artifacts" / "solve.log"
    log_file.write_text(HEALTHY_OPTIMAL_LOG, encoding="utf-8")
    tel_file = repo_dir / "artifacts" / "steps.jsonl"
    tel_file.write_text(
        json.dumps({"event": "incumbent", "step": 3, "wall_time": 0.16, "objective": 118, "best_bound": 118, "worker": "graph_dec_lns"})
        + "\n",
        encoding="utf-8",
    )

    rc = run_watch_solver_cli(
        [
            "--target",
            str(repo_dir),
            "--log",
            "artifacts/solve.log",
            "--telemetry-jsonl",
            "artifacts/steps.jsonl",
            "--timeline-id",
            "cli-tl-01",
            "--publish-viewport",
            "--json",
        ]
    )
    assert rc == 0
    out_json = json.loads(capsys.readouterr().out)
    assert out_json["timeline_id"] == "cli-tl-01"
    assert out_json["published_to_viewport"] is True
    assert out_json["viewport_seq"] == 1
    assert "chronicle=cli-tl-01" in out_json["permalink"]
    assert "phase=5" in out_json["permalink"]
    assert len(out_json["chronicle_frames"]) == 6

    vp_state = get_viewport_state(out_json["target_slug"])
    assert vp_state.latest is not None
    assert len(vp_state.latest.command.chronicle_frames) == 6

    # Also verify --stdin + --follow streaming mode
    monkeypatch.setattr(sys, "stdin", io.StringIO(HEALTHY_OPTIMAL_LOG))
    rc_stdin = run_watch_solver_cli(
        [
            "--target",
            str(repo_dir),
            "--stdin",
            "--follow",
            "--timeline-id",
            "cli-stdin-02",
            "--json",
        ]
    )
    assert rc_stdin == 0
    stdin_payload = json.loads(capsys.readouterr().out)
    assert stdin_payload["timeline_id"] == "cli-stdin-02"
    assert stdin_payload["active_phase_index"] == 5
    assert "chronicle=cli-stdin-02&phase=5" in stdin_payload["permalink"]


def test_mcp_solver_chronicle_handler_permalink_and_strict_type_guards(
    tmp_path: Path,
) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "mcp_repo", clean_mode=True)
    baseline_report = _scan_repo(repo_dir)
    digest_before = baseline_report.content_digest

    (repo_dir / "artifacts" / "proto.json").write_text(
        json.dumps(
            {
                "name": "warehouse_dock_plan",
                "variables": [{"name": "dock_slot_start", "domain": [90, 30]}],
                "constraints": [],
            }
        ),
        encoding="utf-8",
    )
    inv_log_text = (
        "ValidateCpModel: var #0 ('dock_slot_start') has invalid domain [90, 30]\n"
        "CpSolverResponse summary:\n"
        "status: MODEL_INVALID\n"
    )

    factory = get_session_factory()
    with factory() as session:
        md_resp = handle_mcp_solver_chronicle(
            session,
            {
                "target": str(repo_dir),
                "solve_log_text": inv_log_text,
                "cp_model_proto_path": "artifacts/proto.json",
                "timeline_id": "mcp-halt-01",
                "publish_viewport": True,
            },
        )

    assert "chronicle=mcp-halt-01&phase=1" in md_resp
    fenced = md_resp.split("```json\n", 1)[1].split("\n```", 1)[0]
    parsed = json.loads(fenced)
    assert parsed["forensics"]["forensic_class"] == "model_invalid"
    assert parsed["active_phase_index"] == 1
    assert parsed["live_following"] is False
    assert parsed["content_digest"] == digest_before

    vp_state = get_viewport_state(parsed["target_slug"])
    assert vp_state.latest is not None
    assert vp_state.latest.command.chronicle_frames[1].status == "failed"

    with factory() as session:
        with pytest.raises(ValueError, match="publish_viewport"):
            handle_mcp_solver_chronicle(
                session, {"target": str(repo_dir), "publish_viewport": "no"}
            )
        with pytest.raises(ValueError, match="phase_index"):
            handle_mcp_solver_chronicle(
                session, {"target": str(repo_dir), "phase_index": True}
            )
        with pytest.raises(ValueError, match="Unsupported argument"):
            handle_mcp_solver_chronicle(
                session, {"target": str(repo_dir), "camera_position": [1, 2, 3]}
            )


def test_symlink_and_path_containment_on_log_and_proto_inputs(tmp_path: Path) -> None:
    repo_dir = _create_warehouse_solver_repo(tmp_path / "contain_repo", clean_mode=True)
    outside_file = tmp_path / "outside_secret.log"
    outside_file.write_text("SECRET_OUTSIDE_CONTENT\n", encoding="utf-8")

    symlink_log = repo_dir / "artifacts" / "evil_symlink.log"
    symlink_log.symlink_to(outside_file)

    symlink_dir = repo_dir / "artifacts" / "linked_dir"
    symlink_dir.symlink_to(tmp_path)

    with pytest.raises(ValueError, match="Symlink"):
        resolve_safe_companion_path(symlink_log, repo_root=repo_dir)
    with pytest.raises(ValueError, match="Symlink"):
        resolve_safe_companion_path("artifacts/evil_symlink.log", repo_root=repo_dir)
    with pytest.raises(ValueError, match="Symlink|escapes"):
        resolve_safe_companion_path(symlink_dir / "outside_secret.log", repo_root=repo_dir)
    with pytest.raises(ValueError, match="traversal"):
        resolve_safe_companion_path("../outside_secret.log", repo_root=repo_dir)
    with pytest.raises(ValueError, match="escapes"):
        resolve_safe_companion_path(outside_file, repo_root=repo_dir)

    factory = get_session_factory()
    with factory() as session:
        with pytest.raises(ValueError, match="Symlink|escapes|traversal"):
            handle_mcp_solver_chronicle(
                session,
                {"target": str(repo_dir), "solve_log_path": "../outside_secret.log"},
            )
        with pytest.raises(ValueError, match="Symlink"):
            handle_mcp_solver_chronicle(
                session,
                {"target": str(repo_dir), "cp_model_proto_path": "artifacts/evil_symlink.log"},
            )

    rc_escape = run_watch_solver_cli(
        ["--target", str(repo_dir), "--log", str(outside_file), "--json"]
    )
    assert rc_escape == 2


def test_registration_call_order_sanitization_and_pyproject_metadata(tmp_path: Path) -> None:
    import tomllib

    pyproject_path = REPO_ROOT / "plugins" / "wythe-plugin-solver-chronicle" / "pyproject.toml"
    meta = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    assert meta["project"]["name"] == "wythe-plugin-solver-chronicle"
    assert meta["project"]["version"] == "0.1.0"
    assert meta["project"]["authors"] == [{"name": "Euda1mon1a"}]
    assert meta["project"]["entry-points"]["wythe.plugins"] == {
        "solver-chronicle": "wythe_plugin_solver_chronicle:register_wythe_plugin"
    }
    assert meta["project"]["scripts"] == {
        "wythe-watch-solver": "wythe_plugin_solver_chronicle.cli:main"
    }
    assert meta["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/wythe_plugin_solver_chronicle"
    ]

    repo_dir = _create_warehouse_solver_repo(tmp_path / "order_repo", clean_mode=True)
    # Define add_second_constraints ABOVE add_first_constraints, but register add_first inside `if` first
    (repo_dir / "backend" / "app" / "solvers" / "dock_solver.py").write_text(
        "def add_second_vehicle_route_constraints(model, x):\n"
        "    model.Add(x <= 20).WithName('second_route_cap')\n\n"
        "def add_first_dock_window_constraints(model, x):\n"
        "    model.Add(x >= 1).WithName('first_dock_window')\n\n"
        "def solve_warehouse_plan(db, cp_model):\n"
        '    docks = db.execute("SELECT id, min_slot, max_slot, max_capacity FROM dock_windows")\n'
        '    orders = db.execute("SELECT id, demand_units, penalty_weight FROM job_orders")\n'
        "    if not docks or not orders:\n"
        "        return {}\n"
        "    model = cp_model.CpModel()\n"
        "    x = model.NewIntVar(docks[0]['min_slot'], docks[0]['max_slot'] + docks[0]['max_capacity'], 'x')\n"
        "    if orders[0]['demand_units'] > 0:\n"
        "        add_first_dock_window_constraints(model, x)\n"
        "    add_second_vehicle_route_constraints(model, x)\n"
        "    model.Minimize(orders[0]['penalty_weight'] * x)\n"
        "    solver = cp_model.CpSolver()\n"
        "    status = solver.Solve(model)\n"
        '    db.execute("INSERT INTO solver_runs (run_status, objective_val, best_bound_val) VALUES (\'OPTIMAL\', 1, 1)")\n'
        "    return {'status': status, 'obj': solver.ObjectiveValue(), 'bnd': solver.BestObjectiveBound()}\n",
        encoding="utf-8",
    )
    report = _scan_repo(repo_dir)

    hostile_log = (
        "Starting CP-SAT solver v9.11\n"
        "ValidateCpModel: var #0 ('<sc\x00ript>evil()</script>') has invalid domain [10, 5]\n"
        "CpSolverResponse summary:\n"
        "status: MODEL_INVALID\n"
    )
    syn = synthesize_solver_chronicle(
        repo_dir,
        report,
        session=parse_solve_log_text(hostile_log),
    )
    cst_steps = [s for s in syn.frames[1].substeps if s.startswith("Constraint #")]
    assert len(cst_steps) == 2
    assert "add_first_dock_window_constraints" in cst_steps[0]
    assert "add_second_vehicle_route_constraints" in cst_steps[1]
    assert "<script" not in syn.frames[1].caption.lower()

    with pytest.raises(ValueError, match="Markup|script"):
        synthesize_solver_chronicle(repo_dir, report, timeline_id="<script>x</script>")


def test_end_to_end_core_cli_watch_solver_mcp_jsonrpc_and_three_plugin_coexistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from fastapi.testclient import TestClient

    from app.cli import main as wythe_cli_main
    from app.main import create_app
    from app.services.mcp_service import MCP_SLM_TOOLS, MCP_TOOLS, dispatch_mcp_request
    from wythe_plugin_agent_harness import register_wythe_plugin as register_harness
    from wythe_plugin_cpsat import register_wythe_plugin as register_cpsat

    repo_dir = _create_warehouse_solver_repo(tmp_path / "e2e_chron_repo", clean_mode=True)
    baseline_report = _scan_repo(repo_dir)

    log_file = repo_dir / "artifacts" / "solve.log"
    log_file.write_text(HEALTHY_OPTIMAL_LOG, encoding="utf-8")
    outside_log = tmp_path / "outside.log"
    outside_log.write_text("OUTSIDE\n", encoding="utf-8")
    sym_log = repo_dir / "artifacts" / "sym.log"
    sym_log.symlink_to(outside_log)

    # 1. Core `wythe watch-solver` CLI dispatch -> ChronicleTimeline + single `&chronicle=...&phase=...`
    rc_cli = wythe_cli_main(
        [
            "watch-solver",
            "--allow-local-plugins",
            "--plugin",
            "wythe_plugin_solver_chronicle",
            "--target",
            str(repo_dir),
            "--log",
            "artifacts/solve.log",
            "--timeline-id",
            "core-cli-tl",
            "--publish-viewport",
            "--json",
        ]
    )
    assert rc_cli == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["permalink"].count("chronicle=") == 1
    assert cli_out["permalink"].count("phase=") == 1
    assert "chronicle=core-cli-tl&phase=5" in cli_out["permalink"]
    vp_cli = get_viewport_state(cli_out["target_slug"])
    assert vp_cli.latest is not None
    assert vp_cli.latest.command.chronicle_timeline is not None
    assert vp_cli.latest.command.chronicle_timeline.timeline_id == "core-cli-tl"
    assert vp_cli.latest.command.chronicle_timeline.live_following is True
    assert vp_cli.latest.command.chronicle_timeline.active_phase_index == 5
    assert len(vp_cli.latest.command.chronicle_timeline.frames) == 6

    # 2. All 3 Wave 3 plugins registered via entry_points: HTTP metadata, Z=0 digest invariance & MCP JSON-RPC
    eps = [
        _FakeEntryPoint("agent-harness", "wythe_plugin_agent_harness:register_wythe_plugin", register_harness),
        _FakeEntryPoint("cpsat", "wythe_plugin_cpsat:register_wythe_plugin", register_cpsat),
        _FakeEntryPoint("solver-chronicle", "wythe_plugin_solver_chronicle:register_wythe_plugin", register_wythe_plugin),
    ]
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_kw: eps if _kw.get("group") == ENTRY_POINT_GROUP else [],
    )

    with TestClient(create_app()) as client:
        plug_res = client.get("/api/v1/adapters/plugins")
        assert plug_res.status_code == 200
        by_name = {p["name"]: p for p in plug_res.json()["plugins"]}
        assert by_name["agent-harness"]["rules"] == ["AGENT-001", "AGENT-002", "AGENT-003"]
        assert by_name["cpsat"]["supported_zooms"] == [2]
        assert by_name["solver-chronicle"]["mcp_tools"] == ["wythe_solver_chronicle"]
        assert by_name["solver-chronicle"]["cli_subcommands"] == ["watch-solver"]

    co_report = _scan_repo(repo_dir)
    assert [n.id for n in co_report.nodes] == [n.id for n in baseline_report.nodes]
    assert any(
        b.key.startswith("cp_")
        for n in co_report.nodes
        for b in (n.stratum_badges or [])
    )
    co_digest_before_mcp = co_report.content_digest

    factory = get_session_factory()
    with factory() as session:
        full_list = dispatch_mcp_request(
            session, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, slice_mode="full"
        )
        assert full_list is not None
        full_names = [t["name"] for t in full_list["result"]["tools"]]
        assert len(MCP_TOOLS) == 11
        assert len(full_names) == 12
        assert "wythe_solver_chronicle" in full_names

        slm_list = dispatch_mcp_request(
            session, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, slice_mode="slm"
        )
        assert slm_list is not None
        slm_tools = slm_list["result"]["tools"]
        assert len(MCP_SLM_TOOLS) == 4
        assert len(slm_tools) == 4
        assert len(json.dumps(slm_tools, separators=(",", ":")).encode("utf-8")) < 2000

        rpc_ok = dispatch_mcp_request(
            session,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "wythe_solver_chronicle",
                    "arguments": {
                        "target": str(repo_dir),
                        "solve_log_text": (
                            "ValidateCpModel: var #0 ('<script>\x00x</script>') has invalid domain [9, 2]\n"
                            "CpSolverResponse summary:\nstatus: MODEL_INVALID\n"
                        ),
                        "timeline_id": "mcp-rpc-tl",
                        "publish_viewport": True,
                    },
                },
            },
            slice_mode="full",
        )
        assert rpc_ok is not None and rpc_ok["result"]["isError"] is False
        rpc_text = rpc_ok["result"]["content"][0]["text"]
        assert "chronicle=mcp-rpc-tl&phase=1" in rpc_text
        assert "<script" not in rpc_text.lower()
        assert "\x00" not in rpc_text

        rpc_json = json.loads(rpc_text.split("```json\n", 1)[1].split("\n```", 1)[0])
        vp_mcp = get_viewport_state(rpc_json["target_slug"])
        assert vp_mcp.latest is not None
        assert vp_mcp.latest.command.chronicle_timeline is not None
        assert vp_mcp.latest.command.chronicle_timeline.timeline_id == "mcp-rpc-tl"
        assert vp_mcp.latest.command.chronicle_timeline.live_following is False
        assert vp_mcp.latest.command.chronicle_timeline.active_phase_index == 1

        for bad_id, bad_msg in (
            (4, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": ["not-dict"]}),
            (5, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "wythe_solver_chronicle", "arguments": "bad"}}),
            (6, {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "wythe_solver_chronicle", "arguments": {"target": str(repo_dir), "phase_index": 99}}}),
            (7, {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "wythe_solver_chronicle", "arguments": {"target": str(repo_dir), "solve_log_path": "artifacts/sym.log"}}}),
        ):
            err_res = dispatch_mcp_request(session, bad_msg, slice_mode="full")
            assert err_res is not None, f"missing response for id={bad_id}"
            assert err_res["error"]["code"] == -32602

    assert _scan_repo(repo_dir).content_digest == co_digest_before_mcp
