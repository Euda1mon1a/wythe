"""Adversarial regression tests for Wave 3 review findings (#84, #88, #92)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult
from app.adapters.plugin_registry import WythePluginSpec, run_post_scan_plugins
from app.db.session import get_session_factory
from app.main import initialize_database
from app.models import TargetProject
from app.services.scanner_service import run_target_scan
from wythe_plugin_agent_harness import WYTHE_PLUGIN as HARNESS_PLUGIN
from wythe_plugin_agent_harness.ts_inspector import inspect_ts_source
from wythe_plugin_cpsat import parse_cp_model_proto, parse_cp_solver_response
from wythe_plugin_solver_chronicle import (
    parse_cp_model_proto_text,
    parse_cp_solver_response_text,
    parse_solve_log_text,
    resolve_safe_companion_path,
    synthesize_solver_chronicle,
)
from wythe_plugin_solver_chronicle.synthesizer import (
    _clean_plain,
    build_chronicle_viewport_command,
    publish_chronicle_to_viewport,
)


def _scan_min_repo(repo_dir: Path):
    (repo_dir / "backend" / "app" / "solvers").mkdir(parents=True, exist_ok=True)
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE dock_windows (id INTEGER PRIMARY KEY, min_slot INTEGER, max_slot INTEGER);\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "solvers" / "plan.py").write_text(
        "def solve_plan(db, cp_model):\n"
        '    rows = db.execute("SELECT id, min_slot, max_slot FROM dock_windows")\n'
        "    if not rows:\n"
        "        return {}\n"
        "    model = cp_model.CpModel()\n"
        "    x = model.NewIntVar(rows[0]['min_slot'], rows[0]['max_slot'], 'x_slot')\n"
        "    solver = cp_model.CpSolver()\n"
        "    solver.parameters.max_time_in_seconds = 5.0\n"
        "    solver.Solve(model)\n"
        "    return {'x': x}\n",
        encoding="utf-8",
    )
    initialize_database()
    factory = get_session_factory()
    with factory() as session:
        target = TargetProject(
            slug=f"adv-{repo_dir.name}"[:48],
            name="Adversarial Repo",
            repo_path=str(repo_dir),
            backend_subdir="backend",
            frontend_subdir="",
            stack_profile_slug="python-services",
        )
        return run_target_scan(session, target, strict_gate=False, persist_snapshot=False)


def test_finding1_script_and_split_html_tags_in_halted_reason_and_captions(tmp_path: Path) -> None:
    assert "<script" not in _clean_plain("Symmetry: <sc<b>ript>alert(1)</script>", 390).lower()
    assert "<script" not in _clean_plain("Nested: <sc<sc<i>ript>ript>alert(1)</script>", 390).lower()
    wide_tag = "a" * 300
    assert "<script" not in _clean_plain(
        f"Symmetry: <sc<b {wide_tag}>ript>alert(1)</script>", 390
    ).lower()
    assert "javascript:" not in _clean_plain(
        f"Symmetry: javas<b {wide_tag}>cript:alert(1)", 390
    ).lower()

    repo = tmp_path / "f1_repo"
    report = _scan_min_repo(repo)
    proto = parse_cp_model_proto_text(
        json.dumps({"variables": [{"name": "x_<script>alert(1)</script>", "domain": [10, 2]}]})
    )
    session = parse_solve_log_text(
        "ValidateCpModel: var #0 '<script>alert(1)</script>' has invalid domain [10, 2]\n"
        "CpSolverResponse summary:\nstatus: MODEL_INVALID\n"
    )
    syn = synthesize_solver_chronicle(repo, report, session=session, proto=proto, timeline_id="adv-f1")
    assert syn.halted_reason is not None
    assert "<script" not in syn.halted_reason.lower()
    cmd = build_chronicle_viewport_command(syn)
    assert cmd.chronicle_timeline is not None
    assert cmd.chronicle_timeline.halted_reason is not None
    assert "<script" not in cmd.chronicle_timeline.halted_reason.lower()
    ack, permalink = publish_chronicle_to_viewport(syn)
    assert ack.seq >= 1 and "chronicle=adv-f1&phase=1" in permalink


def test_finding2_no_redos_backtracking_on_unterminated_backslash_strings() -> None:
    slashes = "\\" * 64
    ts_payload = (
        f"const s = `{slashes}unterminated\n"
        f'const r = fetch("{slashes}unterminated\n'
        f'const o = {{ role: "system", content: "{slashes}unterminated\n'
        f'const p = {{ systemPrompt: "{slashes}unterminated\n'
    )
    t0 = time.perf_counter()
    inspect_ts_source("src/bad_unterminated.ts", ts_payload)
    parse_cp_model_proto_text(f'name: "{slashes}unterminated')
    parse_solve_log_text("a " * 3000 + "coefficient " * 500 + "\n")
    parse_solve_log_text("a" * 3000 + "lns" * 500 + "\n")
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.25, f"Regex took {elapsed:.3f}s (expected linear non-backtracking scan)"

    valid_s = parse_solve_log_text(
        "Objective coefficient range: [1e+00, 1e+12]\n"
        "'rins_lns': 0/60 (0.00% accepted)\n"
    )
    assert valid_s.coefficient_ranges == (("Objective coefficient range", 1.0, 1e12),)
    assert valid_s.lns_zero_acceptance_workers == ("rins_lns",)


def test_finding3_pbtxt_solve_log_escaped_quotes_invalid_hex_and_utf8() -> None:
    r1 = parse_cp_solver_response_text(
        'status: MODEL_INVALID\nsolve_log: "ValidateCpModel: var #0 \\"bad_var\\" [10, 2]\\n"'
    )
    assert r1.status == "MODEL_INVALID"
    assert r1.solve_log == 'ValidateCpModel: var #0 "bad_var" [10, 2]\n'

    r2 = parse_cp_solver_response_text(
        'status: OPTIMAL\nsolve_log: "delta=Δ hex=\\xZZ oct=\\101 end=\\\\"'
    )
    assert "delta=Δ" in r2.solve_log
    assert "\\xZZ" in r2.solve_log
    assert "oct=A" in r2.solve_log
    assert r2.solve_log.endswith("\\")


def test_finding4_cpsat_corrupt_deep_pbtxt_and_malformed_json_types(tmp_path: Path) -> None:
    deep_pbtxt = tmp_path / "deep.pbtxt"
    deep_pbtxt.write_text("a { " * 1500 + "}" * 1500, encoding="utf-8")
    with pytest.raises(ValueError, match="nested"):
        parse_cp_model_proto(deep_pbtxt)
    with pytest.raises(ValueError, match="nested"):
        parse_cp_solver_response(deep_pbtxt)

    bad_dom = tmp_path / "bad_dom.json"
    bad_dom.write_text('{"variables": [{"name": "x", "domain": [null, "bad"]}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid integer"):
        parse_cp_model_proto(bad_dom)

    bad_resp = tmp_path / "bad_resp.json"
    bad_resp.write_text('{"status": true, "num_conflicts": "nan"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid|boolean"):
        parse_cp_solver_response(bad_resp)

    deep_json = tmp_path / "deep.json"
    deep_json.write_text('{"a":' * 1500 + "1" + "}" * 1500, encoding="utf-8")
    with pytest.raises(ValueError, match="nested"):
        parse_cp_model_proto(deep_json)
    with pytest.raises(ValueError, match="nested"):
        parse_cp_model_proto_text(deep_json.read_text(encoding="utf-8"))


def test_finding5_symlinked_parent_directory_rejected_across_companion_readers(tmp_path: Path) -> None:
    repo = tmp_path / "f5_repo"
    real_dir = repo / "real_dir"
    real_dir.mkdir(parents=True)
    log_f = real_dir / "solve.log"
    log_f.write_text("status: OPTIMAL\n", encoding="utf-8")
    model_f = real_dir / "model.json"
    model_f.write_text('{"name": "ok"}', encoding="utf-8")

    sym_dir = repo / "sym_dir"
    sym_dir.symlink_to(real_dir)

    ext_real = tmp_path / "ext_real"
    ext_real.mkdir()
    (ext_real / "outside.json").write_text('{"name": "ext"}', encoding="utf-8")
    ext_sym = tmp_path / "ext_sym"
    ext_sym.symlink_to(ext_real)

    candidate_repos = [repo]
    if str(repo).startswith("/private/var/"):
        var_alias = Path(str(repo).replace("/private/var/", "/var/", 1))
        if var_alias.exists():
            candidate_repos.append(var_alias)

    for cand_repo in candidate_repos:
        for root_arg in (repo, repo.resolve()):
            with pytest.raises(ValueError, match="(?i)symlink"):
                resolve_safe_companion_path(str(cand_repo / "sym_dir" / "solve.log"), repo_root=root_arg)
            with pytest.raises(ValueError, match="(?i)symlink"):
                parse_cp_model_proto(str(cand_repo / "sym_dir" / "model.json"), repo_root=root_arg)

    with pytest.raises(ValueError, match="(?i)symlink"):
        parse_cp_model_proto(str(ext_sym / "outside.json"))


def test_finding6_agent001_non_llm_dict_negative_control_and_post_scan_isolation(tmp_path: Path) -> None:
    src = tmp_path / "f6_repo" / "src"
    src.mkdir(parents=True)
    (src / "rbac_audit.py").write_text(
        "def make_event(actor_name: str) -> dict[str, str]:\n"
        '    return {"role": "system", "content": f"Actor {actor_name} initialized subsystem successfully."}\n',
        encoding="utf-8",
    )
    (src / "rbac_audit.ts").write_text(
        "export function makeEvent(actorName: string) {\n"
        '  return { role: "system", content: `Actor ${actorName} initialized subsystem successfully.` };\n'
        "}\n",
        encoding="utf-8",
    )
    (src / "static_template_chat.py").write_text(
        "def build_domain_chat(domain_name: str, question: str) -> list[dict[str, str]]:\n"
        "    messages = [\n"
        '        {"role": "system", "content": f"Domain {domain_name}: enforce deterministic static schema rules."},\n'
        '        {"role": "user", "content": question},\n'
        "    ]\n"
        "    return messages\n",
        encoding="utf-8",
    )
    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    HARNESS_PLUGIN.augment_manipulator(tmp_path / "f6_repo", "src", res)
    assert [f for f in res.findings if f.rule_code == "AGENT-001"] == []

    report = _scan_min_repo(tmp_path / "iso_repo")
    orig_nodes = [n.id for n in report.nodes]
    orig_digest = report.content_digest

    def _mutating_hook(_root: Path, rep) -> list[str]:
        rep.nodes.clear()
        rep.content_digest = "tampered"
        return ["ran-mutating-hook"]

    mut_spec = WythePluginSpec(
        name="mutating-post-test",
        kind="post_scan_check",
        origin="local_opt_in",
        post_scan_hook=_mutating_hook,
    )
    out = run_post_scan_plugins(tmp_path / "iso_repo", report, plugins=[mut_spec])
    assert "ran-mutating-hook" in out.notes
    assert [n.id for n in report.nodes] == orig_nodes
    assert report.content_digest == orig_digest
