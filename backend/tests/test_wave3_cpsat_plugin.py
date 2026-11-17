"""Wave 3 (#84) tests: `wythe-plugin-cpsat` pure-Python CP-SAT lineage, Zoom-2 lattice, & protos."""

from __future__ import annotations

import importlib.metadata
import json
import struct
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "plugins" / "wythe-plugin-cpsat" / "src"))

from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    ManipulatorAugmenterPlugin,
    PostScanCheckPlugin,
    StratumPlugin,
    WythePluginSpec,
    discover_plugins,
    run_manipulator_plugins,
)
from app.adapters.python_ast_inspect import parse_python_module
from app.db.session import get_session_factory
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import get_target_by_slug, register_target
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    attach_zoom1_stratum_badges,
    build_node_stratum_drilldown,
)
from wythe_plugin_cpsat import (
    WYTHE_PLUGIN,
    CpSatLineagePlugin,
    correlate_cpsat_companions,
    extract_repo_cpsat_models,
    parse_cp_model_proto,
    parse_cp_solver_response,
    register_wythe_plugin,
)


class _FakeDist:
    def __init__(self, version: str = "0.1.0") -> None:
        self.version = version


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, obj: object, version: str = "0.1.0") -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist(version)
        self._obj = obj

    def load(self) -> object:
        return self._obj


def _enc_varint(val: int) -> bytes:
    if val < 0:
        val = (1 << 64) + val
    out = bytearray()
    while True:
        bits = val & 0x7F
        val >>= 7
        if val:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _enc_len_field(field_num: int, payload: bytes) -> bytes:
    return _enc_varint((field_num << 3) | 2) + _enc_varint(len(payload)) + payload


def _enc_varint_field(field_num: int, val: int) -> bytes:
    return _enc_varint((field_num << 3) | 0) + _enc_varint(val)


def _enc_double_field(field_num: int, val: float) -> bytes:
    return _enc_varint((field_num << 3) | 1) + struct.pack("<d", val)


def _init_git_repo(repo_dir: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Euda1mon1a"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "config", "user.email", "214782221+Euda1mon1a@users.noreply.github.com"],
        cwd=repo_dir,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init synthetic industrial repo"], cwd=repo_dir, check=True)
    return repo_dir


def _build_clean_industrial_cpsat_repo(repo_dir: Path) -> Path:
    """Create a well-governed 3-tier job-shop & vehicle-routing CP-SAT repository."""
    (repo_dir / "backend" / "app" / "api").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "solvers").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "constraints").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "services").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app" / "dispatch").mkdir(parents=True)

    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE machine_capacities (\n"
        "    id INTEGER PRIMARY KEY,\n"
        "    max_slots INTEGER NOT NULL\n"
        ");\n"
        "CREATE TABLE vehicle_quotas (\n"
        "    id INTEGER PRIMARY KEY,\n"
        "    max_stops INTEGER NOT NULL\n"
        ");\n"
        "CREATE TABLE penalty_policies (\n"
        "    rule_key TEXT PRIMARY KEY,\n"
        "    penalty_points INTEGER NOT NULL,\n"
        "    timeout_seconds INTEGER NOT NULL,\n"
        "    max_workers INTEGER NOT NULL\n"
        ");\n"
        "CREATE TABLE job_allocations (\n"
        "    id INTEGER PRIMARY KEY,\n"
        "    status TEXT NOT NULL,\n"
        "    objective_val DOUBLE PRECISION NOT NULL,\n"
        "    best_bound DOUBLE PRECISION NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "constraints" / "routing_constraints.py").write_text(
        "from ortools.sat.python import cp_model\n\n"
        "def add_machine_interval_constraints(model: cp_model.CpModel, intervals, cap_limit: int):\n"
        "    model.AddNoOverlap(intervals)\n"
        "    model.AddCumulative(intervals, [1 for _ in intervals], cap_limit)\n\n"
        "def add_vehicle_route_constraints(model: cp_model.CpModel, routes, quota_limit: int, assume_lit):\n"
        "    model.AddExactlyOne(routes)\n"
        "    model.Add(sum(routes) <= quota_limit).OnlyEnforceIf(assume_lit).WithName('ct_vehicle_cap_0')\n\n"
        "def add_makespan_channel_constraints(model: cp_model.CpModel, span_var, route_flags):\n"
        "    model.AddMaxEquality(span_var, route_flags)\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "solvers" / "job_shop_solver.py").write_text(
        "import os\n"
        "from ortools.sat.python import cp_model\n"
        "from app.constraints.routing_constraints import (\n"
        "    add_machine_interval_constraints,\n"
        "    add_makespan_channel_constraints,\n"
        "    add_vehicle_route_constraints,\n"
        ")\n\n"
        "def solve_warehouse_plan(db):\n"
        "    cap_rows = db.execute('SELECT id, max_slots FROM machine_capacities').fetchall()\n"
        "    quota_rows = db.execute('SELECT id, max_stops FROM vehicle_quotas').fetchall()\n"
        "    policy_rows = db.execute('SELECT rule_key, penalty_points, timeout_seconds, max_workers FROM penalty_policies').fetchall()\n"
        "    if not cap_rows or not quota_rows or not policy_rows:\n"
        "        raise ValueError('Required industrial policy tables are empty')\n"
        "    model = cp_model.CpModel()\n"
        "    job_starts = [model.NewIntVar(0, 100, f'job_start_{i}') for i in range(2)]\n"
        "    job_ends = [model.NewIntVar(0, 100, f'job_end_{i}') for i in range(2)]\n"
        "    machine_assignments = [model.NewBoolVar(f'machine_assign_{i}') for i in range(2)]\n"
        "    job_intervals = [\n"
        "        model.NewOptionalIntervalVar(job_starts[i], 10, job_ends[i], machine_assignments[i], f'job_interval_{i}')\n"
        "        for i in range(2)\n"
        "    ]\n"
        "    vehicle_routes = [model.NewBoolVar(f'vehicle_route_{v}') for v in range(2)]\n"
        "    makespan = model.NewIntVar(0, 100, 'makespan')\n"
        "    assume_capacity = model.NewBoolVar('assume_capacity')\n"
        "    model.AddAssumptions([assume_capacity])\n"
        "    add_machine_interval_constraints(model, job_intervals, cap_rows[0][1])\n"
        "    add_vehicle_route_constraints(model, vehicle_routes, quota_rows[0][1], assume_capacity)\n"
        "    add_makespan_channel_constraints(model, makespan, job_ends)\n"
        "    obj_terms = []\n"
        "    for row in policy_rows:\n"
        "        obj_terms.append(row[1] * makespan)\n"
        "    model.Minimize(sum(obj_terms))\n"
        "    solver = cp_model.CpSolver()\n"
        "    solver.parameters.max_time_in_seconds = policy_rows[0][2]\n"
        "    solver.parameters.num_search_workers = min(policy_rows[0][3], os.cpu_count() or 1)\n"
        "    status = solver.Solve(model)\n"
        "    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):\n"
        "        obj_val = solver.ObjectiveValue()\n"
        "        best_bnd = solver.BestObjectiveBound()\n"
        "        db.execute('INSERT INTO job_allocations (id, status, objective_val, best_bound) VALUES (1, :s, :o, :b)')\n"
        "        return {'status': solver.StatusName(status), 'objective': obj_val, 'bound': best_bnd}\n"
        "    return {'status': solver.StatusName(status)}\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "services" / "solution_validator.py").write_text(
        "def validate_warehouse_solution(db):\n"
        "    caps = db.execute('SELECT id, max_slots FROM machine_capacities').fetchall()\n"
        "    quotas = db.execute('SELECT id, max_stops FROM vehicle_quotas').fetchall()\n"
        "    policies = db.execute('SELECT rule_key, penalty_points FROM penalty_policies').fetchall()\n"
        "    allocs = db.execute('SELECT id, status, objective_val, best_bound FROM job_allocations').fetchall()\n"
        "    return bool(caps and quotas and policies and allocs is not None)\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "api" / "dispatch.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.solvers.job_shop_solver import solve_warehouse_plan\n"
        "from app.services.solution_validator import validate_warehouse_solution\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/dispatch/solve')\n"
        "def trigger_solve(db=None):\n"
        "    res = solve_warehouse_plan(db)\n"
        "    validate_warehouse_solution(db)\n"
        "    return res\n",
        encoding="utf-8",
    )

    (repo_dir / "frontend" / "src" / "app" / "dispatch" / "page.tsx").write_text(
        "export default async function DispatchPage() {\n"
        "  const res = await fetch('/api/v1/dispatch/solve', { method: 'POST' });\n"
        "  return <main>{String(res.ok)}</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    return _init_git_repo(repo_dir)



def test_plugin_manifest_and_entry_point_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    pyproject_path = REPO_ROOT / "plugins" / "wythe-plugin-cpsat" / "pyproject.toml"
    manifest = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    proj = manifest["project"]
    assert proj["name"] == "wythe-plugin-cpsat"
    assert proj["version"] == "0.1.0"
    assert proj["authors"] == [{"name": "Euda1mon1a"}]
    assert proj["dependencies"] == []
    assert proj["entry-points"]["wythe.plugins"]["cpsat"] == "wythe_plugin_cpsat:register_wythe_plugin"
    assert manifest["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/wythe_plugin_cpsat"
    ]

    plugin = register_wythe_plugin()
    assert isinstance(plugin, CpSatLineagePlugin)
    assert plugin is WYTHE_PLUGIN
    assert plugin.name == "cpsat"
    assert plugin.version == "0.1.0"
    assert plugin.supported_zooms == (2,)
    assert plugin.enabled_by_default is True
    assert isinstance(plugin, ManipulatorAugmenterPlugin)
    assert isinstance(plugin, PostScanCheckPlugin)
    assert isinstance(plugin, StratumPlugin)
    assert plugin.companion_handlers["cpsat"] is correlate_cpsat_companions

    def _fake_eps(**kwargs):
        if kwargs.get("group") == ENTRY_POINT_GROUP:
            return [_FakeEntryPoint("cpsat", "wythe_plugin_cpsat:register_wythe_plugin", register_wythe_plugin)]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", _fake_eps)
    specs = discover_plugins(include_builtins=False, include_entry_points=True, strict_plugins=True)
    cpsat_specs = [s for s in specs if s.name == "cpsat"]
    assert cpsat_specs
    assert all(s.origin == "entry_point" for s in cpsat_specs)


def test_clean_cpsat_repo_digest_invariance_badges_and_zoom2_bipartite_cone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_db_url: str,
) -> None:
    repo_dir = _build_clean_industrial_cpsat_repo(tmp_path / "clean_industrial")
    factory = get_session_factory(isolated_db_url)

    # 1. Baseline scan with zero entry-point plugins
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])
    with factory() as session:
        register_target(
            session,
            TargetProjectCreate(
                slug="clean-cpsat",
                name="Clean Industrial CP-SAT",
                repo_path=str(repo_dir),
                stack_profile_slug="fastapi-sqlalchemy-nextjs",
            ),
        )
        target = get_target_by_slug(session, "clean-cpsat")
        assert target is not None
        baseline_report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    assert baseline_report.findings == []
    baseline_digest = baseline_report.content_digest
    baseline_node_count = len(baseline_report.nodes)

    # 2. Scan with cpsat plugin enabled via entry_points + explicit hook verification
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (
            [_FakeEntryPoint("cpsat", "wythe_plugin_cpsat:register_wythe_plugin", register_wythe_plugin)]
            if kw.get("group") == ENTRY_POINT_GROUP
            else []
        ),
    )
    with factory() as session:
        target = get_target_by_slug(session, "clean-cpsat")
        assert target is not None
        plugin_report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    # Verify negative control across check_report and static extraction
    post_check = WYTHE_PLUGIN.check_report(repo_dir, plugin_report)
    assert post_check["cpsat_detected"] is True
    assert post_check["findings"] == []
    assert post_check["unregistered_builders"] == []
    assert post_check["registration_order"] == [
        "add_machine_interval_constraints",
        "add_vehicle_route_constraints",
        "add_makespan_channel_constraints",
    ]
    assert post_check["validator_asymmetry"] == {
        "builder_only_tables": [],
        "validator_only_tables": [],
    }
    assert plugin_report.findings == []
    assert plugin_report.content_digest == baseline_digest
    assert len(plugin_report.nodes) == baseline_node_count

    attach_zoom1_stratum_badges(repo_dir, plugin_report)
    assert plugin_report.content_digest == baseline_digest

    solver_node = next(
        n for n in plugin_report.nodes if n.subkind == "solver" and "job_shop_solver" in n.id
    )
    badge_map = {b.key: b.count for b in solver_node.stratum_badges}
    assert {"cp_vars", "cp_constraints", "cp_objective_terms", "cp_assumptions"} <= set(badge_map)
    assert badge_map["cp_vars"] >= 6
    assert badge_map["cp_constraints"] == 5
    assert badge_map["cp_objective_terms"] >= 1
    assert badge_map["cp_assumptions"] >= 1

    # 3. Zoom-2 bipartite variable-constraint conflict cone
    drill = build_node_stratum_drilldown(repo_dir, plugin_report, solver_node.id, zoom=2)
    assert "cpsat" in drill.active_plugins
    var_nodes = {n.label: n for n in drill.nodes if n.kind == "cp_var"}
    assert {
        "job_intervals",
        "machine_assignments",
        "vehicle_routes",
        "makespan",
        "assume_capacity",
    } <= set(var_nodes)
    assert var_nodes["job_intervals"].source_file == "backend/app/solvers/job_shop_solver.py"
    assert var_nodes["job_intervals"].line and var_nodes["job_intervals"].line > 1

    edge_kinds_to_var: dict[str, list[tuple[str, str]]] = {}
    for me in drill.edges:
        tgt_lbl = me.target_id.rsplit(":", 1)[-1]
        edge_kinds_to_var.setdefault(tgt_lbl, []).append((me.source_id, me.kind))

    # 1-hop conflict neighborhoods: both NoOverlap and Cumulative constrain `job_intervals`
    assert len([src for src, k in edge_kinds_to_var["job_intervals"] if k == "constrains_var"]) == 2
    assert len([src for src, k in edge_kinds_to_var["vehicle_routes"] if k == "constrains_var"]) == 2
    assert any(k == "enforced_by_literal" for _, k in edge_kinds_to_var["assume_capacity"])
    assert any(k == "channels_var" for _, k in edge_kinds_to_var["makespan"])

    cone = build_lineage_cone_slice(plugin_report, solver_node.id, zoom=2, full=True)
    assert cone.stratum_drilldowns
    assert any("job_intervals" in n.label for d in cone.stratum_drilldowns for n in d.nodes)



def test_cpsat_findings_unregistered_asymmetry_truncation_multisolver_and_unassumed(
    tmp_path: Path,
    isolated_db_url: str,
) -> None:
    repo_dir = tmp_path / "flawed_industrial"
    (repo_dir / "backend" / "app" / "api").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "solvers").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "constraints").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "services").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app" / "routes").mkdir(parents=True)

    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE warehouse_zones (id INTEGER PRIMARY KEY, limit_bins INTEGER NOT NULL);\n"
        "CREATE TABLE carrier_tariffs (id INTEGER PRIMARY KEY, surcharge INTEGER NOT NULL);\n"
        "CREATE TABLE dispatch_runs (id INTEGER PRIMARY KEY, status TEXT NOT NULL);\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "constraints" / "zone_constraints.py").write_text(
        "from ortools.sat.python import cp_model\n\n"
        "def add_active_zone_constraints(model: cp_model.CpModel, bins):\n"
        "    model.AddAllDifferent(bins)\n\n"
        "def add_unwired_dock_constraints(model: cp_model.CpModel, bins):\n"
        "    model.AddExactlyOne(bins)\n\n"
        "class UnwiredConveyorConstraint:\n"
        "    def apply(self, model: cp_model.CpModel, bins):\n"
        "        model.AddAtMostOne(bins)\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "solvers" / "vrp_pipeline.py").write_text(
        "import os\n"
        "from ortools.sat.python import cp_model\n"
        "from app.constraints.zone_constraints import add_active_zone_constraints\n\n"
        "def run_vrp_orchestration(db):\n"
        "    zone_rows = db.execute('SELECT id, limit_bins FROM warehouse_zones').fetchall()\n"
        "    model = cp_model.CpModel()\n"
        "    bins = [model.NewIntVar(0, 10, f'bin_{i}') for i in range(3)]\n"
        "    unmet = model.NewIntVar(0, 10, 'unmet')\n"
        "    late = model.NewIntVar(0, 10, 'late')\n"
        "    idle = model.NewIntVar(0, 10, 'idle')\n"
        "    add_active_zone_constraints(model, bins)\n"
        "    for z in zone_rows:\n"
        "        model.Add(bins[0] <= z[1])\n"
        "    soft_weight = int(0.05 * 10)\n"
        "    model.Minimize(1000 * unmet + 50 * late + soft_weight * idle)\n"
        "    solver1 = cp_model.CpSolver()\n"
        "    solver1.parameters.num_search_workers = os.cpu_count()\n"
        "    status = solver1.Solve(model)\n"
        "    aux_model = cp_model.CpModel()\n"
        "    solver2 = cp_model.CpSolver()\n"
        "    status = solver2.Solve(aux_model)\n"
        "    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):\n"
        "        obj = solver1.ObjectiveValue()\n"
        "        db.execute('INSERT INTO dispatch_runs (id, status) VALUES (1, :s)')\n"
        "        return {'status': solver2.StatusName(status), 'obj': obj}\n"
        "    return {'status': 'FAILED'}\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "services" / "route_validator.py").write_text(
        "def validate_route_solution(db):\n"
        "    tariffs = db.execute('SELECT id, surcharge FROM carrier_tariffs').fetchall()\n"
        "    runs = db.execute('SELECT id, status FROM dispatch_runs').fetchall()\n"
        "    return bool(tariffs and runs)\n",
        encoding="utf-8",
    )

    (repo_dir / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.solvers.vrp_pipeline import run_vrp_orchestration\n"
        "from app.services.route_validator import validate_route_solution\n"
        "router = APIRouter()\n\n"
        "@router.post('/api/v1/vrp/run')\n"
        "def run_vrp(db=None):\n"
        "    out = run_vrp_orchestration(db)\n"
        "    validate_route_solution(db)\n"
        "    return out\n",
        encoding="utf-8",
    )

    (repo_dir / "frontend" / "src" / "app" / "routes" / "page.tsx").write_text(
        "export default async function RoutesPage() {\n"
        "  const res = await fetch('/api/v1/vrp/run', { method: 'POST' });\n"
        "  return <main>{String(res.ok)}</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    _init_git_repo(repo_dir)

    extraction = extract_repo_cpsat_models(repo_dir, "backend")
    assert extraction.registration_order == ("add_active_zone_constraints",)
    unreg_syms = {b.symbol for b in extraction.unregistered_builders}
    assert {"add_unwired_dock_constraints", "UnwiredConveyorConstraint"} <= unreg_syms

    factory = get_session_factory(isolated_db_url)
    with factory() as session:
        register_target(
            session,
            TargetProjectCreate(
                slug="flawed-cpsat",
                name="Flawed Industrial CP-SAT",
                repo_path=str(repo_dir),
                stack_profile_slug="fastapi-sqlalchemy-nextjs",
            ),
        )
        target = get_target_by_slug(session, "flawed-cpsat")
        assert target is not None
        report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    # Also test ManipulatorAugmenter hook directly
    from app.adapters import build_default_registry

    reg = build_default_registry()
    t_res = reg.get_truth("postgres-sqlalchemy").extract(repo_dir, "backend")
    m_res = reg.get_manipulator("python-fastapi").extract(repo_dir, "backend", t_res)
    spec = WythePluginSpec(
        name="cpsat",
        kind="manipulator_augmenter",
        manipulator_hook=WYTHE_PLUGIN.augment_manipulator,
    )
    executed = run_manipulator_plugins(repo_dir, "backend", m_res, plugins=[spec], strict_plugins=True)
    assert executed == ["cpsat"]

    check_out = WYTHE_PLUGIN.check_report(repo_dir, report)
    all_findings = list(check_out["findings"])  # type: ignore[arg-type]
    titles = [f.title for f in all_findings]
    codes = {f.rule_code for f in all_findings}

    assert {"MANIP-001", "MANIP-003", "TRUTH-001"} <= codes
    assert any("add_unwired_dock_constraints" in t and f.rule_code == "MANIP-003" for f, t in zip(all_findings, titles))
    assert any("Float-to-zero integer truncation `int(0.05 * 10)`" in t for t in titles)
    assert any("Hardcoded integer penalty tower" in t for t in titles)
    assert any("empty-table guard" in t and f.rule_code == "TRUTH-001" for f, t in zip(all_findings, titles))
    assert any("masks `FEASIBLE` status" in t for t in titles)
    assert any("omits `(ObjectiveValue(), BestObjectiveBound())` gap" in t for t in titles)
    assert any("os.cpu_count()" in t for t in titles)
    assert any("max_time_in_seconds" in t for t in titles)
    assert any("zero assumption literals" in t and f.rule_code == "MANIP-003" for f, t in zip(all_findings, titles))

    asym = check_out["validator_asymmetry"]
    assert asym == {
        "builder_only_tables": ["t:warehouse_zones"],
        "validator_only_tables": ["t:carrier_tariffs"],
    }
    assert any("validator omits `warehouse_zones`" in t for t in titles)
    assert any("CpModel assembly omits `carrier_tariffs`" in t for t in titles)


def test_cp_model_proto_and_solver_response_json_pbtxt_binary_and_containment(
    tmp_path: Path,
    isolated_db_url: str,
) -> None:
    repo_dir = _build_clean_industrial_cpsat_repo(tmp_path / "proto_corr_repo")
    factory = get_session_factory(isolated_db_url)
    with factory() as session:
        register_target(
            session,
            TargetProjectCreate(
                slug="proto-cpsat",
                name="Proto Industrial CP-SAT",
                repo_path=str(repo_dir),
                stack_profile_slug="fastapi-sqlalchemy-nextjs",
            ),
        )
        target = get_target_by_slug(session, "proto-cpsat")
        assert target is not None
        report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    orig_digest = report.content_digest
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir()

    # 1. JSON format fixtures
    proto_json = art_dir / "model.json"
    proto_json.write_text(
        json.dumps(
            {
                "name": "warehouse_plan_v1",
                "variables": [
                    {"name": "job_interval_0", "domain": [0, 100]},
                    {"name": "job_interval_1", "domain": [0, 100]},
                    {"name": "vehicle_route_0", "domain": [0, 1]},
                    {"name": "assume_capacity", "domain": [0, 1]},
                ],
                "constraints": [
                    {"name": "ct_vehicle_cap_0", "enforcementLiteral": [3], "linear": {}},
                    {"name": "add_machine_interval_constraints_0", "noOverlap": {}},
                ],
                "objective": {"vars": [0, 1], "coeffs": [10, 10], "scalingFactor": 1.0},
                "assumptions": [3],
            }
        ),
        encoding="utf-8",
    )
    resp_json = art_dir / "response_feasible.json"
    resp_json.write_text(
        json.dumps(
            {
                "status": "FEASIBLE",
                "objectiveValue": 1420.0,
                "bestObjectiveBound": 1350.0,
                "numBooleans": 48,
                "numConflicts": 12,
                "wallTime": 2.75,
                "solveLog": "Starting CP-SAT solver v9.11\n#1 0.5s best:1420 next:[1350,1419]\n",
            }
        ),
        encoding="utf-8",
    )

    # 2. .pbtxt text-format fixtures
    proto_pbtxt = art_dir / "model.pbtxt"
    proto_pbtxt.write_text(
        '# Exported CpModelProto\n'
        'name: "warehouse_plan_v1"\n'
        'variables { name: "job_interval_0" domain: [0, 100] }\n'
        'variables { name: "job_interval_1" domain: [0, 100] }\n'
        'variables { name: "vehicle_route_0" domain: 0 domain: 1 }\n'
        'variables { name: "assume_capacity" domain: [0, 1] }\n'
        'constraints { name: "ct_vehicle_cap_0" enforcement_literal: 3 linear {} }\n'
        'constraints { name: "add_machine_interval_constraints_0" no_overlap {} }\n'
        'objective { vars: [0, 1] coeffs: [10, 10] scaling_factor: 1.0 }\n'
        'assumptions: 3\n',
        encoding="utf-8",
    )
    resp_pbtxt = art_dir / "response_infeasible.pbtxt"
    resp_pbtxt.write_text(
        'status: INFEASIBLE\n'
        'sufficient_assumptions_for_infeasibility: 3\n'
        'num_booleans: 16\n'
        'num_conflicts: 4\n'
        'wall_time: 0.125\n'
        'solve_log: "Starting CP-SAT solver\\nProblem closed by presolve.\\n"\n',
        encoding="utf-8",
    )

    # 3. Binary protobuf wire-format fixtures matching ortools/sat/cp_model.proto tags
    def _var_msg(vname: str, lb: int, ub: int) -> bytes:
        return _enc_len_field(1, vname.encode("utf-8")) + _enc_len_field(
            2, _enc_varint(lb) + _enc_varint(ub)
        )

    ct0_msg = (
        _enc_len_field(1, b"ct_vehicle_cap_0")
        + _enc_len_field(2, _enc_varint(3))
        + _enc_len_field(12, b"")
    )
    ct1_msg = _enc_len_field(1, b"add_machine_interval_constraints_0") + _enc_len_field(20, b"")
    obj_msg = (
        _enc_len_field(1, _enc_varint(0) + _enc_varint(1))
        + _enc_double_field(3, 1.0)
        + _enc_len_field(4, _enc_varint(10) + _enc_varint(10))
    )
    proto_bin = art_dir / "model.pb"
    proto_bin.write_bytes(
        _enc_len_field(1, b"warehouse_plan_v1")
        + _enc_len_field(2, _var_msg("job_interval_0", 0, 100))
        + _enc_len_field(2, _var_msg("job_interval_1", -5, 100))
        + _enc_len_field(2, _var_msg("vehicle_route_0", 0, 1))
        + _enc_len_field(2, _var_msg("assume_capacity", 0, 1))
        + _enc_len_field(3, ct0_msg)
        + _enc_len_field(3, ct1_msg)
        + _enc_len_field(4, obj_msg)
        + _enc_len_field(7, _enc_varint(3))
    )

    resp_bin = art_dir / "response_infeasible.pb"
    resp_bin.write_bytes(
        _enc_varint_field(1, 3)  # INFEASIBLE = 3
        + _enc_double_field(3, 0.0)
        + _enc_double_field(4, 0.0)
        + _enc_varint_field(10, 16)
        + _enc_varint_field(11, 4)
        + _enc_double_field(15, 0.125)
        + _enc_len_field(23, _enc_varint(3) + _enc_varint(-4))  # lit 3 (var 3) and -4 (Not var 3)
        + _enc_len_field(26, b"Starting CP-SAT solver\nINFEASIBLE\n")
    )

    # Verify parity across JSON, pbtxt, and binary wire format
    for p_file, expected_fmt in (
        (proto_json, "json"),
        (proto_pbtxt, "pbtxt"),
        (proto_bin, "binary"),
    ):
        pm = parse_cp_model_proto(p_file)
        assert pm.format == expected_fmt
        assert pm.name == "warehouse_plan_v1"
        assert len(pm.variables) == 4
        assert len(pm.constraints) == 2
        assert pm.assumptions == (3,)
        assert pm.objective_coeffs == (10, 10)

    r_feas = parse_cp_solver_response(resp_json)
    assert r_feas.format == "json"
    assert r_feas.status == "FEASIBLE"
    assert r_feas.objective_value == 1420.0
    assert r_feas.best_objective_bound == 1350.0

    r_pbtxt = parse_cp_solver_response(resp_pbtxt)
    assert r_pbtxt.format == "pbtxt"
    assert r_pbtxt.status == "INFEASIBLE"
    assert r_pbtxt.sufficient_assumptions_for_infeasibility == (3,)

    r_bin = parse_cp_solver_response(resp_bin)
    assert r_bin.format == "binary"
    assert r_bin.status == "INFEASIBLE"
    assert r_bin.sufficient_assumptions_for_infeasibility == (3, -4)
    assert r_bin.num_booleans == 16
    assert r_bin.num_conflicts == 4
    assert r_bin.wall_time == pytest.approx(0.125)
    assert "INFEASIBLE" in r_bin.solve_log

    # Correlate Z=0 -> Z=1 -> Z=2 (FEASIBLE gap + INFEASIBLE unsat core)
    corr_feas = correlate_cpsat_companions(repo_dir, report, proto_json, resp_json)
    assert report.content_digest == orig_digest
    assert corr_feas["z0_content_digest"] == orig_digest
    assert corr_feas["target_code_executed"] is False
    assert corr_feas["automated_security_audit"] is False
    z1_f = corr_feas["z1_cp_model_proto"]
    z2_f = corr_feas["z2_cp_solver_response"]
    assert z1_f["variable_count"] == 4  # type: ignore[index]
    assert z1_f["builder_attributions"]  # type: ignore[index]
    assert z2_f["absolute_gap"] == pytest.approx(70.0)  # type: ignore[index]
    assert len(corr_feas["wall_ties"]) >= 2  # type: ignore[arg-type]

    corr_inf = correlate_cpsat_companions(repo_dir, report, proto_bin, resp_bin)
    assert report.content_digest == orig_digest
    core_attrs = corr_inf["z2_cp_solver_response"]["unsat_core_attributions"]  # type: ignore[index]
    assert len(core_attrs) == 2
    assert core_attrs[0]["proto_variable_name"] == "assume_capacity"
    assert core_attrs[0]["z0_source_file"] == "backend/app/solvers/job_shop_solver.py"
    assert core_attrs[1]["polarity"] is False
    assert core_attrs[1]["variable_index"] == 3

    # Containment negative controls: symlink, relative escape, oversize
    sym_proto = art_dir / "symlink_model.pb"
    sym_proto.symlink_to(proto_bin)
    with pytest.raises(ValueError, match="symlink"):
        parse_cp_model_proto(sym_proto)

    with pytest.raises(ValueError, match="escapes repository root"):
        parse_cp_model_proto("../artifacts/model.pb", repo_root=repo_dir)

    with pytest.raises(ValueError, match="exceeds"):
        parse_cp_model_proto(proto_bin, max_bytes=8)


def test_all_cpsat_constraint_and_channeling_families_and_annotated_assignments(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "channel_families_repo"
    (repo_dir / "backend" / "app" / "solvers").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "solvers" / "conveyor_lattice.py").write_text(
        "from typing import Any\n"
        "from ortools.sat.python import cp_model\n\n"
        "def assemble_conveyor_lattice() -> None:\n"
        "    model: Any = cp_model.CpModel()\n"
        "    base_offset: Any = model.NewConstant(5)\n"
        "    flag_a: Any = model.NewBoolVar('flag_a')\n"
        "    flag_b: Any = model.NewBoolVar('flag_b')\n"
        "    lane_idx: Any = model.NewIntVar(0, 2, 'lane_idx')\n"
        "    load_a: Any = model.NewIntVar(-10, 50, 'load_a')\n"
        "    load_b: Any = model.NewIntVar(1, 50, 'load_b')\n"
        "    min_load: Any = model.NewIntVar(-10, 50, 'min_load')\n"
        "    prod_load: Any = model.NewIntVar(-500, 2500, 'prod_load')\n"
        "    abs_load: Any = model.NewIntVar(0, 50, 'abs_load')\n"
        "    div_load: Any = model.NewIntVar(-50, 50, 'div_load')\n"
        "    mod_load: Any = model.NewIntVar(0, 10, 'mod_load')\n"
        "    picked_cost: Any = model.NewIntVar(0, 100, 'picked_cost')\n"
        "    model.AddLinearConstraint(load_a + base_offset, 0, 45)\n"
        "    model.AddCircuit([(0, 1, flag_a), (1, 0, flag_b)])\n"
        "    model.AddReservoirConstraint([load_a, load_b], [2, -1], 0, 20)\n"
        "    model.AddAllowedAssignments([lane_idx, load_b], [(0, 10), (1, 20)])\n"
        "    model.AddImplication(flag_a, flag_b)\n"
        "    model.AddMinEquality(min_load, [load_a, load_b])\n"
        "    model.AddMultiplicationEquality(prod_load, [load_a, load_b])\n"
        "    model.AddAbsEquality(abs_load, load_a)\n"
        "    model.AddDivisionEquality(div_load, load_a, load_b)\n"
        "    model.AddModuloEquality(mod_load, load_a, load_b)\n"
        "    model.AddElement(lane_idx, [10, 25, 40], picked_cost)\n"
        "    scale: float = 0.04\n"
        "    unit_penalty: int = 15\n"
        "    zeroed_coeff: int = int(scale * unit_penalty)\n"
        "    model.Maximize(picked_cost - zeroed_coeff * mod_load)\n",
        encoding="utf-8",
    )

    extraction = extract_repo_cpsat_models(repo_dir)
    mod = extraction.modules["backend/app/solvers/conveyor_lattice.py"]
    assert mod.is_cpsat_module is True
    fams = {v.symbol: v.family for v in mod.variables}
    assert fams["base_offset"] == "constant"
    assert fams["flag_a"] == "bool_var"
    assert fams["picked_cost"] == "int_var"

    ctypes = {c.constraint_type for c in mod.constraints}
    assert {
        "linear_domain",
        "circuit",
        "reservoir",
        "allowed_assignments",
        "implication",
        "min_equality",
        "multiplication_equality",
        "abs_equality",
        "division_equality",
        "modulo_equality",
        "element",
    } <= ctypes
    elem_ct = next(c for c in mod.constraints if c.constraint_type == "element")
    assert elem_ct.is_channeling is True
    assert elem_ct.channel_target_vars == ("picked_cost",)
    assert len(mod.truncations) == 1
    assert mod.truncations[0].evaluated_float == pytest.approx(0.6)
    assert mod.objectives[0].sense == "maximize"


def test_plugin_self_hygiene_and_opsec_cleanliness() -> None:
    plugin_src_dir = REPO_ROOT / "plugins" / "wythe-plugin-cpsat" / "src" / "wythe_plugin_cpsat"
    py_files = sorted(plugin_src_dir.glob("*.py"))
    assert len(py_files) == 4
    for pfile in py_files:
        rel_p = pfile.relative_to(REPO_ROOT).as_posix()
        mod_n = f"wythe_plugin_cpsat.{pfile.stem}"
        parsed = parse_python_module(pfile.read_text(encoding="utf-8"), rel_p, mod_n)
        assert parsed.policy_literals == (), f"MANIP-001 triggered in {rel_p}: {parsed.policy_literals}"
        assert parsed.raw_clock_calls == (), f"MANIP-002 triggered in {rel_p}: {parsed.raw_clock_calls}"



def test_end_to_end_core_spine_cpsat_cli_context_zoom2_http_strata_and_companion_dispatch(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    """Verify full core spine + wythe-plugin-cpsat integration across CLI context --zoom 2, /strata, and wythe companion."""
    from urllib.parse import quote

    from fastapi.testclient import TestClient

    from app.cli import main as cli_main
    from app.main import create_app

    repo_dir = _build_clean_industrial_cpsat_repo(tmp_path / "integrated_cpsat_repo")

    # 1. Multi-protocol coercion via entry_points populates all 4 hooks + companion_handlers["cpsat"]
    fake_ep = _FakeEntryPoint(
        "cpsat",
        "wythe_plugin_cpsat:register_wythe_plugin",
        register_wythe_plugin,
        version="0.1.0",
    )
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: [fake_ep] if kw.get("group") == ENTRY_POINT_GROUP else [],
    )
    specs = discover_plugins()
    cpsat_spec = next(s for s in specs if s.name == "cpsat")
    assert cpsat_spec.manipulator_hook is not None
    assert cpsat_spec.post_scan_hook is not None
    assert cpsat_spec.stratum_badge_hook is not None
    assert cpsat_spec.stratum_expand_hook is not None
    assert cpsat_spec.companion_handlers.get("cpsat") is correlate_cpsat_companions

    # 2. HTTP `GET /api/v1/scans/{slug}/nodes/{nodeId}/strata?zoom=2` + Zoom-1 digest invariance
    factory = get_session_factory(isolated_db_url)
    with factory() as session:
        register_target(
            session,
            TargetProjectCreate(
                slug="integrated-cpsat",
                name="Integrated Industrial CP-SAT",
                repo_path=str(repo_dir),
                stack_profile_slug="fastapi-sqlalchemy-nextjs",
            ),
        )
        target = get_target_by_slug(session, "integrated-cpsat")
        assert target is not None
        report = run_target_scan(session, target, strict_gate=True, persist_snapshot=True)

    solver_node = next(n for n in report.nodes if "job_shop_solver" in n.source_file)
    badge_keys = {b.key for b in solver_node.stratum_badges}
    assert {"cp_vars", "cp_constraints", "cp_objective_terms", "cp_assumptions"} <= badge_keys
    z0_digest = report.content_digest

    app = create_app()
    with TestClient(app) as client:
        strata_resp = client.get(
            f"/api/v1/scans/integrated-cpsat/nodes/{quote(solver_node.id, safe='')}/strata?zoom=2"
        )
        assert strata_resp.status_code == 200
        strata_data = strata_resp.json()
        assert "cpsat" in strata_data["active_plugins"]
        micro_kinds = {n["kind"] for n in strata_data["nodes"]}
        assert {"cp_var", "cp_constraint", "cp_objective"} <= micro_kinds
        micro_edge_kinds = {e["kind"] for e in strata_data["edges"]}
        assert {"constrains_var", "enforced_by_literal", "channels_var"} <= micro_edge_kinds

    # 3. CLI `wythe context <repo> job_shop_solver --zoom 2 --json`
    assert (
        cli_main(
            [
                "context",
                str(repo_dir),
                "job_shop_solver",
                "--zoom",
                "2",
                "--json",
            ]
        )
        == 0
    )
    cone_payload = json.loads(capsys.readouterr().out)
    assert cone_payload["content_digest"] == z0_digest
    assert cone_payload["stratum_drilldowns"]
    assert "cpsat" in cone_payload["stratum_drilldowns"][0]["active_plugins"]

    # 4. CLI `wythe companion --cp-model-proto ... --cp-solver-response ...` -> `companion_handlers["cpsat"]`
    proto_file = repo_dir / "exported_model.json"
    proto_file.write_text(
        json.dumps(
            {
                "name": "warehouse_plan_v1",
                "variables": [
                    {"name": "job_interval_0", "domain": [0, 100]},
                    {"name": "vehicle_route_0", "domain": [0, 1]},
                    {"name": "assume_capacity", "domain": [0, 1]},
                ],
                "constraints": [
                    {"name": "ct_vehicle_cap_0", "enforcementLiteral": [2], "linear": {}},
                ],
                "objective": {"vars": [0], "coeffs": [10], "scalingFactor": 1.0},
                "assumptions": [2],
            }
        ),
        encoding="utf-8",
    )
    resp_file = repo_dir / "exported_response.json"
    resp_file.write_text(
        json.dumps(
            {
                "status": "FEASIBLE",
                "objectiveValue": 210.0,
                "bestObjectiveBound": 180.0,
                "numBooleans": 12,
                "numConflicts": 3,
                "wallTime": 0.4,
            }
        ),
        encoding="utf-8",
    )
    # Remove untracked files from repo_dir? Keep outside repo_dir so git dirty status doesn't affect z0_digest!
    ext_proto = tmp_path / "ext_model.json"
    ext_resp = tmp_path / "ext_response.json"
    ext_proto.write_text(proto_file.read_text(encoding="utf-8"), encoding="utf-8")
    ext_resp.write_text(resp_file.read_text(encoding="utf-8"), encoding="utf-8")
    proto_file.unlink()
    resp_file.unlink()

    comp_out = tmp_path / "cpsat-companion-out.json"
    assert (
        cli_main(
            [
                "companion",
                str(repo_dir),
                "--cp-model-proto",
                str(ext_proto),
                "--cp-solver-response",
                str(ext_resp),
                "--json",
                str(comp_out),
            ]
        )
        == 0
    )
    capsys.readouterr()
    comp_json = json.loads(comp_out.read_text(encoding="utf-8"))
    assert comp_json["content_digest"] == z0_digest
    cpsat_comp = comp_json["cpsat_companion"]
    assert cpsat_comp["z0_content_digest"] == z0_digest
    assert cpsat_comp["z1_cp_model_proto"]["variable_count"] == 3
    assert cpsat_comp["z2_cp_solver_response"]["absolute_gap"] == pytest.approx(30.0)
    assert len(cpsat_comp["wall_ties"]) >= 2
