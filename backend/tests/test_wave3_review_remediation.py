"""Comprehensive regression tests for Wave 2 + Wave 3 review remediation (Findings 1-6)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from app.db.session import get_session_factory
from app.services.mcp_service import _resolve_target_for_mcp
from app.services.scanner_service import run_target_scan
from app.services.viewport_service import get_viewport_state
from wythe_plugin_cpsat.proto_companion import (
    parse_cp_model_proto,
    parse_cp_solver_response,
)
from wythe_plugin_solver_chronicle import (
    parse_cp_model_proto_text,
    parse_cp_solver_response_text,
    parse_solve_log_text,
    run_watch_solver_cli,
    synthesize_solver_chronicle,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC_DIRS = tuple(sorted((REPO_ROOT / "plugins").glob("*/src")))

# Frozen golden wire-format (.pb) and ProtoJSON fixtures serialized by upstream ortools.sat.cp_model_pb2
GOLDEN_MODEL_B64 = (
    "ChJnb2xkZW5fdXBzdHJlYW1fdjESCwoFeF9pbnYSAgoCEggKAmIwEgIAARIICgJiMRICAAEaHgoKY3Rf"
    "Ym9vbF9vchIBARoNCgsB/f//////////ARoPCgtjdF9ib29sX2FuZCIAGg8KC2N0X2Jvb2xfeG9yKgAa"
    "EwoOY3RfYXRfbW9zdF9vbmXSAQAaEwoOY3RfZXhhY3RseV9vbmXqAQAaDgoKY3RfaW50X2RpdjoAGg4K"
    "CmN0X2ludF9tb2RCABoPCgtjdF9pbnRfcHJvZFoAGg8KCmN0X2xpbl9tYXjaAQAaDQoJY3RfbGluZWFy"
    "YgAaDwoLY3RfYWxsX2RpZmZqABoOCgpjdF9lbGVtZW50cgAaDgoKY3RfY2lyY3VpdHoAGg4KCWN0X3Jv"
    "dXRlc7oBABoNCghjdF90YWJsZYIBABoRCgxjdF9hdXRvbWF0b26KAQAaDwoKY3RfaW52ZXJzZZIBABoR"
    "CgxjdF9yZXNlcnZvaXLCAQAaEAoLY3RfaW50ZXJ2YWyaAQAaEgoNY3Rfbm9fb3ZlcmxhcKIBABoVChBj"
    "dF9ub19vdmVybGFwXzJkqgEAGhIKDWN0X2N1bXVsYXRpdmWyAQAaGAoTY3RfZHVtbXlfY29uc3RyYWlu"
    "dPIBACIjCgIAAREAAAAAAAAAQBkAAAAAAAD4PyILCvv//////////wE6CwH9//////////8B"
)
GOLDEN_MODEL_PROTOJSON = (
    '{"name": "golden_upstream_v1", "variables": [{"name": "x_inv", "domain": ["10", "2"]}, '
    '{"name": "b0", "domain": ["0", "1"]}, {"name": "b1", "domain": ["0", "1"]}], '
    '"constraints": [{"name": "ct_bool_or", "enforcementLiteral": [1], "boolOr": {"literals": [1, -3]}}, '
    '{"name": "ct_bool_and", "boolAnd": {}}, {"name": "ct_bool_xor", "boolXor": {}}, '
    '{"name": "ct_at_most_one", "atMostOne": {}}, {"name": "ct_exactly_one", "exactlyOne": {}}, '
    '{"name": "ct_int_div", "intDiv": {}}, {"name": "ct_int_mod", "intMod": {}}, '
    '{"name": "ct_int_prod", "intProd": {}}, {"name": "ct_lin_max", "linMax": {}}, '
    '{"name": "ct_linear", "linear": {}}, {"name": "ct_all_diff", "allDiff": {}}, '
    '{"name": "ct_element", "element": {}}, {"name": "ct_circuit", "circuit": {}}, '
    '{"name": "ct_routes", "routes": {}}, {"name": "ct_table", "table": {}}, '
    '{"name": "ct_automaton", "automaton": {}}, {"name": "ct_inverse", "inverse": {}}, '
    '{"name": "ct_reservoir", "reservoir": {}}, {"name": "ct_interval", "interval": {}}, '
    '{"name": "ct_no_overlap", "noOverlap": {}}, {"name": "ct_no_overlap_2d", "noOverlap2d": {}}, '
    '{"name": "ct_cumulative", "cumulative": {}}, {"name": "ct_dummy_constraint", "dummyConstraint": {}}], '
    '"objective": {"vars": [0, 1], "offset": 2.0, "scalingFactor": 1.5, "coeffs": ["10", "-5"]}, '
    '"assumptions": [1, -3]}'
)
GOLDEN_RESP_B64 = (
    "CAMZAAAAAABARUAhAAAAAAAAREBQ9ANYKGDIAXkAAAAAAAApQIEBAAAAAAAAGUCJAQAAAAAAAAlAogEL"
    "Z29sZGVuX2luZm+6AQsD/P//////////AdIBKlN0YXJ0aW5nIENQLVNBVCBzb2x2ZXIKc3RhdHVzOiBJ"
    "TkZFQVNJQkxFCg=="
)
GOLDEN_RESP_PROTOJSON = (
    '{"status": "INFEASIBLE", "objectiveValue": 42.5, "bestObjectiveBound": 40.0, '
    '"numBooleans": "500", "numConflicts": "40", "numBranches": "200", "wallTime": 12.5, '
    '"userTime": 6.25, "deterministicTime": 3.125, "solutionInfo": "golden_info", '
    '"sufficientAssumptionsForInfeasibility": [3, -4], '
    '"solveLog": "Starting CP-SAT solver\\nstatus: INFEASIBLE\\n"}'
)
EXPECTED_23_CONSTRAINT_KINDS = (
    "bool_or",
    "bool_and",
    "bool_xor",
    "at_most_one",
    "exactly_one",
    "int_div",
    "int_mod",
    "int_prod",
    "lin_max",
    "linear",
    "all_diff",
    "element",
    "circuit",
    "routes",
    "table",
    "automaton",
    "inverse",
    "reservoir",
    "interval",
    "no_overlap",
    "no_overlap_2d",
    "cumulative",
    "dummy_constraint",
)


def test_findings_2_and_4_upstream_golden_pb_and_protojson_parity(tmp_path: Path) -> None:
    """Verify binary .pb wire tags and ProtoJSON int64 strings / lowerCamelCase match upstream cp_model.proto."""
    model_pb = tmp_path / "golden_model.pb"
    model_json = tmp_path / "golden_model.json"
    resp_pb = tmp_path / "golden_resp.pb"
    resp_json = tmp_path / "golden_resp.json"

    model_pb.write_bytes(base64.b64decode(GOLDEN_MODEL_B64))
    model_json.write_text(GOLDEN_MODEL_PROTOJSON, encoding="utf-8")
    resp_pb.write_bytes(base64.b64decode(GOLDEN_RESP_B64))
    resp_json.write_text(GOLDEN_RESP_PROTOJSON, encoding="utf-8")

    for mp_path, expected_fmt in ((model_pb, "binary"), (model_json, "json")):
        pm = parse_cp_model_proto(mp_path)
        assert pm.format == expected_fmt
        assert pm.name == "golden_upstream_v1"
        assert [v.domain for v in pm.variables] == [(10, 2), (0, 1), (0, 1)]
        assert tuple(c.kind for c in pm.constraints) == EXPECTED_23_CONSTRAINT_KINDS
        assert pm.constraints[0].enforcement_literals == (1,)
        assert pm.objective_vars == (0, 1)
        assert pm.objective_coeffs == (10, -5)
        assert pm.objective_scaling_factor == pytest.approx(1.5)
        assert pm.assumptions == (1, -3)

    for rp_path, expected_fmt in ((resp_pb, "binary"), (resp_json, "json")):
        pr = parse_cp_solver_response(rp_path)
        assert pr.format == expected_fmt
        assert pr.status == "INFEASIBLE"
        assert pr.status_code == 3
        assert pr.objective_value == pytest.approx(42.5)
        assert pr.best_objective_bound == pytest.approx(40.0)
        assert pr.sufficient_assumptions_for_infeasibility == (3, -4)
        assert pr.num_booleans == 500
        assert pr.num_conflicts == 40
        assert pr.num_branches == 200
        assert pr.wall_time == pytest.approx(12.5)
        assert pr.user_time == pytest.approx(6.25)
        assert pr.deterministic_time == pytest.approx(3.125)
        assert pr.solution_info == "golden_info"

    chron_m = parse_cp_model_proto_text(GOLDEN_MODEL_PROTOJSON)
    assert chron_m.variable_domains == ((10, 2), (0, 1), (0, 1))
    assert chron_m.constraint_kinds == EXPECTED_23_CONSTRAINT_KINDS
    assert chron_m.constraint_enforcement_literals[0] == (1,)
    assert chron_m.constraint_vars[0] == (1, -3)

    chron_r = parse_cp_solver_response_text(GOLDEN_RESP_PROTOJSON)
    assert chron_r.status == "INFEASIBLE"
    assert chron_r.num_booleans == 500
    assert chron_r.num_conflicts == 40
    assert chron_r.num_branches == 200
    assert chron_r.wall_time == pytest.approx(12.5)
    assert chron_r.user_time == pytest.approx(6.25)
    assert chron_r.deterministic_time == pytest.approx(3.125)
    assert chron_r.solution_info == "golden_info"
    assert chron_r.sufficient_assumptions_for_infeasibility == (3, -4)


def test_finding_3_truthful_forensic_attribution_without_false_fallbacks(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    """Verify constraint #0 and var #999 never blame unrelated builders or unlinked Truth tables."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "forensic-target"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE limits (id INTEGER PRIMARY KEY, lo INTEGER, hi INTEGER);\n"
        "CREATE TABLE linked_quotas (id INTEGER PRIMARY KEY, max_units INTEGER);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "loader.py").write_text(
        "def fetch_quotas(db):\n"
        '    return db.execute("SELECT id, max_units FROM linked_quotas")\n',
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "solver.py").write_text(
        "from app.loader import fetch_quotas\n\n"
        "def build(cp_model, db=None):\n"
        "    rows = fetch_quotas(db)\n"
        "    model = cp_model.CpModel()\n"
        '    first = model.NewIntVar(0, 10, "first")\n'
        '    second = model.NewIntVar(0, rows[0]["max_units"], "second")\n'
        '    model.Add(first + second <= 5).WithName("constraint_bad")\n'
        "    return model\n",
        encoding="utf-8",
    )

    with get_session_factory()() as session:
        target = _resolve_target_for_mcp(session, str(repo), profile="python-services")
        report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    # 1. Unnamed constraint #0 without proto -> unresolved, NEVER blames 'first' or 't:limits'
    syn_c0 = synthesize_solver_chronicle(
        repo,
        report,
        session=parse_solve_log_text("Invalid model: constraint #0 is invalid\nstatus: MODEL_INVALID\n"),
    )
    assert syn_c0.forensics.z0_builders == ()
    assert syn_c0.forensics.z0_truth_nodes == ()
    assert syn_c0.forensics.upstream_truth_tables == ()
    assert "unresolved source builder" in syn_c0.forensics.summary
    assert "first" not in syn_c0.forensics.summary
    assert "t:limits" not in syn_c0.forensics.summary
    assert syn_c0.forensics.unverified_candidates_note is not None

    # 2. Out-of-range var #999 (with or without proto) -> unresolved, NEVER blames line 6 or 't:limits'
    proto_named = parse_cp_model_proto_text(
        json.dumps(
            {
                "variables": [
                    {"name": "first", "domain": ["0", "10"]},
                    {"name": "second", "domain": ["0", "10"]},
                ],
                "constraints": [{"name": "constraint_bad", "linear": {"vars": [0, 1]}}],
            }
        )
    )
    for opt_proto in (None, proto_named):
        syn_v999 = synthesize_solver_chronicle(
            repo,
            report,
            session=parse_solve_log_text(
                "Invalid model: var #999 has invalid domain [10, 2]\nstatus: MODEL_INVALID\n"
            ),
            proto=opt_proto,
        )
        assert syn_v999.forensics.z0_builders == ()
        assert syn_v999.forensics.z0_truth_nodes == ()
        assert "unresolved source builder" in syn_v999.forensics.summary
        assert "first" not in syn_v999.forensics.summary
        assert "t:limits" not in syn_v999.forensics.summary

    # 3. With proto naming constraint #0 == 'constraint_bad', resolves strictly to line 8 & linked_quotas ONLY!
    syn_c0_resolved = synthesize_solver_chronicle(
        repo,
        report,
        session=parse_solve_log_text("Invalid model: constraint #0 is invalid\nstatus: MODEL_INVALID\n"),
        proto=proto_named,
    )
    assert len(syn_c0_resolved.forensics.z0_builders) == 1
    zb = syn_c0_resolved.forensics.z0_builders[0]
    assert zb.symbol == "constraint_bad"
    assert zb.line == 8
    assert syn_c0_resolved.forensics.z0_truth_nodes == ("t:linked_quotas",)
    assert "t:limits" not in syn_c0_resolved.forensics.z0_truth_nodes


def test_findings_1_and_5_live_follow_cadence_zero_runpy_warning_and_sse_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify zero runpy warning, live --follow intermediate updates + idle refresh, and cross-process SSE."""
    state_dir = tmp_path / "chron-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{(state_dir / 'wythe.db').as_posix()}")
    monkeypatch.delenv("WYTHE_SERVER_URL", raising=False)

    repo = tmp_path / "follow-target"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE limits (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "main.py").write_text("def solve():\n    return 1\n", encoding="utf-8")
    solve_log = repo / "solve.log"
    solve_log.write_text("Starting CP-SAT solver v9.15\nStarting search at 0.00s\n", encoding="utf-8")

    # 1. Live --follow keeps alive across active writes > follow_timeout and publishes intermediate updates
    from wythe_plugin_solver_chronicle.log_parser import IncrementalSolverLogParser

    started = threading.Event()
    orig_feed = IncrementalSolverLogParser.feed_line

    def _tracked_feed(self: IncrementalSolverLogParser, line: str) -> None:
        orig_feed(self, line)
        started.set()

    monkeypatch.setattr(IncrementalSolverLogParser, "feed_line", _tracked_feed)
    captured = io.StringIO()
    rc_out: list[int] = []

    def _run_follow() -> None:
        with contextlib.redirect_stdout(captured):
            rc_out.append(
                run_watch_solver_cli(
                    [
                        "--target",
                        str(repo),
                        "--profile",
                        "python-services",
                        "--log",
                        "solve.log",
                        "--follow",
                        "--follow-timeout",
                        "0.8",
                        "--publish-viewport",
                        "--json",
                    ]
                )
            )

    follow_thread = threading.Thread(target=_run_follow)
    follow_thread.start()
    assert started.wait(timeout=5.0)

    seen_seqs: list[int] = []
    seen_timelines: set[str] = set()
    for step in range(6):
        with solve_log.open("a", encoding="utf-8") as fh:
            fh.write(f"# {step + 1} 0.{step + 1}0s best:{100 - step} next:[50,99] rins_lns\n")
        time.sleep(0.2)
        assert follow_thread.is_alive(), f"Watcher exited prematurely at step {step}"
        vp = get_viewport_state("follow-target")
        assert vp.latest is not None
        seen_seqs.append(vp.latest.seq)
        if vp.latest.command.chronicle_timeline is not None:
            seen_timelines.add(vp.latest.command.chronicle_timeline.timeline_id)

    # Emit terminal summary -> watcher stops promptly without waiting full idle timeout!
    with solve_log.open("a", encoding="utf-8") as fh:
        fh.write("CpSolverResponse summary:\nstatus: OPTIMAL\nobjective: 95\n")
    follow_thread.join(timeout=5.0)
    assert not follow_thread.is_alive()
    assert rc_out == [0]
    assert captured.getvalue().count('"published_to_viewport"') == 1
    assert len(set(seen_seqs)) >= 3
    assert len(seen_timelines) == 1

    # 2. Separate OS process `python -m wythe_plugin_solver_chronicle.cli`: zero runpy stderr + live Uvicorn SSE
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    py_paths = os.pathsep.join(str(p) for p in (REPO_ROOT / "backend", *PLUGIN_SRC_DIRS))
    sub_env = {
        **os.environ,
        "PYTHONPATH": py_paths,
        "WYTHE_STATE_DIR": str(state_dir),
        "WYTHE_DATABASE_URL": f"sqlite:///{(state_dir / 'wythe.db').as_posix()}",
    }
    sub_env.pop("WYTHE_SERVER_URL", None)

    no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base_url = f"http://127.0.0.1:{port}"
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
        env=sub_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            try:
                no_proxy.open(f"{base_url}/healthz", timeout=1.0).close()
                break
            except OSError:
                time.sleep(0.05)

        watch_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "wythe_plugin_solver_chronicle.cli",
                "--target",
                str(repo),
                "--profile",
                "python-services",
                "--log",
                "solve.log",
                "--publish-viewport",
                "--json",
            ],
            env=sub_env,
            text=True,
            capture_output=True,
            timeout=30.0,
            check=False,
        )
        assert watch_proc.returncode == 0, watch_proc.stderr
        assert watch_proc.stderr == ""
        watch_json = json.loads(watch_proc.stdout)
        with no_proxy.open(
            f"{base_url}/api/v1/viewport/state?target_slug=follow-target", timeout=5.0
        ) as resp:
            srv_state = json.loads(resp.read().decode("utf-8"))
        assert srv_state["latest"]["seq"] == watch_json["viewport_seq"]
    finally:
        server.terminate()
        server.wait(timeout=10.0)

    # Closed port with --server-url fails closed (exit code 2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
        s2.bind(("127.0.0.1", 0))
        closed_port = int(s2.getsockname()[1])
    bad_watch = subprocess.run(
        [
            sys.executable,
            "-m",
            "wythe_plugin_solver_chronicle.cli",
            "--target",
            str(repo),
            "--profile",
            "python-services",
            "--log",
            "solve.log",
            "--publish-viewport",
            "--server-url",
            f"http://127.0.0.1:{closed_port}",
            "--json",
        ],
        env=sub_env,
        text=True,
        capture_output=True,
        timeout=15.0,
        check=False,
    )
    assert bad_watch.returncode == 2
    assert "unreachable" in bad_watch.stderr.lower()



def test_round2_verifier_edge_cases_mcp_scope_prefix_partial_line_and_pb_parity(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify #127 Round-1 verifier edge cases (Items 1-4): plugin MCP scope, exact/boundary matching, partial line follow, and .pb/ProtoJSON/.pbtxt parity."""
    import importlib.metadata

    from fastapi.testclient import TestClient

    from app.adapters.plugin_registry import ENTRY_POINT_GROUP
    from app.main import create_app
    from app.services.mcp_service import dispatch_mcp_request
    from wythe_plugin_solver_chronicle import (
        handle_mcp_solver_chronicle,
        parse_cp_model_proto_file,
        parse_cp_solver_response_file,
        register_wythe_plugin,
    )

    assert isolated_db_url.startswith("sqlite:")

    # --- Item 1: Plugin MCP `wythe_solver_chronicle` honors `--server-url` & `local_viewport_only` ---
    class _ChronEP:
        name = "solver-chronicle"
        value = "wythe_plugin_solver_chronicle:register_wythe_plugin"
        group = ENTRY_POINT_GROUP

        class dist:
            version = "0.1.0"

        def load(self):
            return register_wythe_plugin

    orig_eps = importlib.metadata.entry_points
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: [_ChronEP()] if kw.get("group") == ENTRY_POINT_GROUP else orig_eps(**kw),
    )

    repo = tmp_path / "r2-repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE docks (id INTEGER PRIMARY KEY, cap INTEGER);\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "solver.py").write_text(
        "def build(cp_model, db=None):\n"
        '    rows = db.execute("SELECT id, cap FROM docks")\n'
        "    model = cp_model.CpModel()\n"
        '    x = model.NewIntVar(0, 10, "x")\n'
        '    x_bad = model.NewIntVar(10, 2, "x_bad")\n'
        '    z_third = model.NewIntVar(0, 5, "z_third")\n'
        '    model.Add(x <= rows[0]["cap"]).WithName("alpha_rule")\n'
        '    model.Add(x_bad <= 10).WithName("build_second_rule")\n'
        '    model.Add(z_third <= 5).WithName("coupled_third_rule")\n'
        "    return model\n",
        encoding="utf-8",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        closed_port = int(s.getsockname()[1])
    closed_url = f"http://127.0.0.1:{closed_port}"

    mcp_call = {
        "jsonrpc": "2.0",
        "id": 77,
        "method": "tools/call",
        "params": {
            "name": "wythe_solver_chronicle",
            "arguments": {
                "target": str(repo),
                "profile": "python-services",
                "publish_viewport": True,
            },
        },
    }
    res_closed = dispatch_mcp_request(db_session, mcp_call, server_url=closed_url)
    assert res_closed is not None
    assert res_closed["result"]["isError"] is True
    assert "unreachable" in res_closed["result"]["content"][0]["text"].lower()
    assert get_viewport_state("r2-repo").latest is None

    # HTTP `/api/v1/mcp` sets `local_viewport_only=True`, ignoring broken `WYTHE_SERVER_URL` in env
    monkeypatch.setenv("WYTHE_SERVER_URL", closed_url)
    with TestClient(create_app()) as client:
        http_mcp = client.post("/api/v1/mcp", json=mcp_call)
        assert http_mcp.status_code == 200
        assert http_mcp.json()["result"]["isError"] is False
    monkeypatch.delenv("WYTHE_SERVER_URL", raising=False)
    assert get_viewport_state("r2-repo").latest is not None

    # --- Item 2: Prefix/substring & container-function false attribution ---
    target = _resolve_target_for_mcp(db_session, str(repo), profile="python-services")
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)

    syn_xbad = synthesize_solver_chronicle(
        repo,
        report,
        session=parse_solve_log_text("Invalid model: var 'x_bad' has invalid domain [10, 2]\nstatus: MODEL_INVALID\n"),
    )
    assert len(syn_xbad.forensics.z0_builders) == 1
    assert syn_xbad.forensics.z0_builders[0].line == 5  # `x_bad`, never `x` at line 4!

    syn_second = synthesize_solver_chronicle(
        repo,
        report,
        session=parse_solve_log_text("Invalid model: constraint #1 'build_second_rule' is invalid\nstatus: MODEL_INVALID\n"),
    )
    assert len(syn_second.forensics.z0_builders) == 1
    assert syn_second.forensics.z0_builders[0].line == 8  # `build_second_rule`, never `alpha_rule` at line 7!

    for missing_cst in ("build_missing", "b", "x"):
        syn_miss = synthesize_solver_chronicle(
            repo,
            report,
            session=parse_solve_log_text(
                f"Invalid model: constraint #99 '{missing_cst}' is invalid\nstatus: MODEL_INVALID\n"
            ),
        )
        assert syn_miss.forensics.z0_builders == (), f"False match for {missing_cst}"

    xray_repo = tmp_path / "xray-repo"
    (xray_repo / "backend" / "app").mkdir(parents=True)
    (xray_repo / "backend" / "app" / "s.py").write_text(
        'def f(cp_model):\n    m = cp_model.CpModel()\n    xray = m.NewIntVar(0, 5, "xray")\n    return xray\n',
        encoding="utf-8",
    )
    xray_t = _resolve_target_for_mcp(db_session, str(xray_repo), profile="python-services")
    xray_rep = run_target_scan(db_session, xray_t, strict_gate=True, persist_snapshot=False)
    syn_x_vs_xray = synthesize_solver_chronicle(
        xray_repo,
        xray_rep,
        session=parse_solve_log_text("Invalid model: var 'x' has invalid domain [10, 2]\nstatus: MODEL_INVALID\n"),
    )
    assert syn_x_vs_xray.forensics.z0_builders == ()

    # --- Item 3: `watch-solver --follow` partial line without trailing `\n` ---
    partial_log = repo / "partial.log"
    partial_log.write_text("Starting CP-SAT solver v9.15\nCpSolverResponse summary:\nstatus: OPT", encoding="utf-8")
    out_buf = io.StringIO()
    rc_box: list[int] = []

    def _tail_partial() -> None:
        with contextlib.redirect_stdout(out_buf):
            rc_box.append(
                run_watch_solver_cli(
                    [
                        "--target",
                        str(repo),
                        "--profile",
                        "python-services",
                        "--log",
                        "partial.log",
                        "--follow",
                        "--follow-timeout",
                        "2.0",
                        "--publish-viewport",
                        "--json",
                    ]
                )
            )

    t0 = time.monotonic()
    th = threading.Thread(target=_tail_partial)
    th.start()
    time.sleep(0.08)
    with partial_log.open("a", encoding="utf-8") as fh:
        fh.write("IMAL\n")
        fh.flush()
    th.join(timeout=3.0)
    elapsed_tail = time.monotonic() - t0
    assert not th.is_alive()
    assert rc_box == [0]
    assert elapsed_tail < 1.2, f"Partial line stalled until timeout ({elapsed_tail:.2f}s)"
    tail_payload = json.loads(out_buf.getvalue())
    assert "(OPTIMAL)" in tail_payload["title"]
    assert "(OPT)" not in tail_payload["title"]

    # --- Item 4: Binary `.pb` companions, ProtoJSON zero-omission Root-LP, non-var exclusion, `.pbtxt`, & `-3` literal ---
    pb_model = repo / "model.pb"
    pb_resp = repo / "resp.pb"
    pb_model.write_bytes(base64.b64decode(GOLDEN_MODEL_B64))
    pb_resp.write_bytes(base64.b64decode(GOLDEN_RESP_B64))
    assert parse_cp_model_proto_file(pb_model).name == "golden_upstream_v1"
    assert parse_cp_solver_response_file(pb_resp).sufficient_assumptions_for_infeasibility == (3, -4)
    mcp_pb_md = handle_mcp_solver_chronicle(
        db_session,
        {
            "target": str(repo),
            "profile": "python-services",
            "cp_model_proto_path": "model.pb",
            "cp_solver_response_path": "resp.pb",
            "publish_viewport": False,
        },
    )
    assert "assumption_core" in mcp_pb_md

    # ProtoJSON zero-omission Root-LP INFEASIBLE parity (`numConflicts=0, numBranches=0` omitted by MessageToJson)
    zero_omit_resp = parse_cp_solver_response_text(
        '{"status": "INFEASIBLE", "numBooleans": "10", "wallTime": 0.01}'
    )
    syn_root_lp = synthesize_solver_chronicle(repo, report, response=zero_omit_resp)
    assert syn_root_lp.forensics.forensic_class == "root_lp_infeasible"

    # Non-variable fields excluded; `.pbtxt` fields & negated `-3` literal (`var 2 == z_third`) coupled!
    nonvar_json = parse_cp_model_proto_text(
        json.dumps(
            {
                "variables": [{"name": "x"}, {"name": "x_bad"}, {"name": "z_third"}],
                "constraints": [
                    {"name": "alpha_rule", "boolOr": {"literals": [0, -3]}},
                    {"name": "coupled_third_rule", "boolOr": {"literals": [-3]}},
                    {"name": "rt", "routes": {"tails": [0, 1], "heads": [1, 0], "demands": ["5", "9"], "capacity": "20", "literals": [0]}},
                    {"name": "ov2d", "noOverlap2d": {"xIntervals": [0], "yIntervals": [1]}},
                ],
            }
        )
    )
    assert nonvar_json.constraint_vars[2] == (0,)  # Only `literals`, never tails/heads/demands/capacity!
    assert nonvar_json.constraint_vars[3] == ()  # `xIntervals`/`yIntervals` are constraint indices!

    syn_neg_lit = synthesize_solver_chronicle(
        repo,
        report,
        session=parse_solve_log_text(
            "Starting presolve at 0.01s\nContradiction in 'alpha_rule'\nProblem closed by presolve.\nstatus: INFEASIBLE\n"
        ),
        proto=nonvar_json,
    )
    assert any("build@" in nb or "coupled" in nb for nb in syn_neg_lit.forensics.neighborhood_builders)

    pbtxt_m = parse_cp_model_proto_text(
        'name: "pbtxt_full"\n'
        'variables { name: "v0" domain: [0, 5] }\n'
        'variables { name: "v1" domain: [0, 5] }\n'
        'constraints { name: "inv" inverse { f_direct: [0] f_inverse: [1] } }\n'
        'constraints { name: "res" reservoir { active_literals: [0] time_exprs { vars: [1] } } }\n'
        'constraints { name: "elem" element { index: 0 vars: [1] } }\n'
        'floating_point_objective { vars: [0, 1] }\n'
    )
    assert pbtxt_m.constraint_vars == ((0, 1), (0, 1), (0, 1))
    assert pbtxt_m.objective_vars == (0, 1)

    pbtxt_r = parse_cp_solver_response_text(
        'status: OPTIMAL\nuser_time: 1.25\ndeterministic_time: 0.75\nsolution_info: "part1 "\n  "part2"\n'
    )
    assert pbtxt_r.user_time == pytest.approx(1.25)
    assert pbtxt_r.deterministic_time == pytest.approx(0.75)
    assert pbtxt_r.solution_info == "part1 part2"
