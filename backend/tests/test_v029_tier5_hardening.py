"""Milestone M5 Phase 2 Tier 5 adversarial & cross-milestone hardening tests."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.inline_store_truth import scan_inline_stores
from app.adapters.plugin_registry import stratum_artifacts_scope
from app.adapters.python_daemon_routes import _has_external_display_sources
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.service_sources import source_files
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.tach_bridge import augment_tach_boundaries
from app.cli import main as cli_main
from app.main import create_app
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target
from app.services.investigation_service import clear_scan_reuse_cache, get_or_run_cached_scan
from app.services.portable_config_service import sync_portable_bundle_from_disk
from app.services.scanner_service import run_target_scan


def _write(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def _init_git(repo: Path) -> None:
    env = {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        env=env,
        capture_output=True,
    )


def _mkdir_deep_over_1024(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    cur_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    segs = ["d" * 180 for _ in range(7)]
    try:
        for seg in segs:
            try:
                os.mkdir(seg, 0o755, dir_fd=cur_fd)
            except FileExistsError:
                pass
            nxt_fd = os.open(seg, os.O_RDONLY | os.O_DIRECTORY, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
    finally:
        os.close(cur_fd)
    out = base
    for seg in segs:
        out = out / seg
    assert len(str(out)) > 1024
    return out


def test_tier5_item1_sql_ddl_truth_propagates_registry_incomplete_coverage(
    db_session: Session,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Item 1 (P1-13): SqlDdlTruthAdapter & strict gate fail closed on unsafe/unreadable config/*.yaml."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("commands:\n  run:\n    command: main.go\n", encoding="utf-8")

    # 1. Symlinked config/bad.yaml under postgres-go-react -> coverage_complete=False & INCOMPLETE
    go_repo = tmp_path / "go_sym_repo"
    _write(go_repo, "schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    _write(go_repo, "go.mod", "module example.com/app\n\ngo 1.22\n")
    _write(go_repo, "main.go", "package main\nfunc main() {}\n")
    (go_repo / "config").mkdir()
    os.symlink(outside, go_repo / "config" / "bad.yaml")
    _init_git(go_repo)

    ddl_res = SqlDdlTruthAdapter().extract(go_repo, ".")
    assert ddl_res.coverage_complete is False
    assert any("registry" in n.lower() for n in ddl_res.notes)

    tgt_go = register_target(
        db_session,
        TargetProjectCreate(
            slug="tier5-go-sym",
            name="tier5-go-sym",
            repo_path=str(go_repo),
            stack_profile_slug="postgres-go-react",
            backend_subdir=".",
            frontend_subdir=".",
        ),
    )
    rep_go = run_target_scan(db_session, tgt_go, strict_gate=True, persist_snapshot=False)
    assert rep_go.coverage_complete is False
    assert rep_go.gate.verdict == "INCOMPLETE"

    rc_go = cli_main(["gate", str(go_repo), "--profile", "postgres-go-react", "--strict"])
    out_go = capsys.readouterr().out
    assert rc_go != 0
    assert "INCOMPLETE" in out_go

    # 2. Unreadable 0o000 config/secret.yaml under fastapi-sqlalchemy-nextjs (with default agent-harness)
    #    and SqlDdlTruthAdapter -> strict gate != PASS
    py_repo = tmp_path / "py_000_repo"
    _write(py_repo, "schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    _write(py_repo, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(py_repo, "frontend/package.json", '{"dependencies":{"next":"15.0.0"}}\n')
    _write(py_repo, "frontend/src/app/page.tsx", "export default function Page() { return <main />; }\n")
    secret_cfg = _write(py_repo, "config/secret.yaml", "commands:\n  a:\n    command: x.py\n")
    os.chmod(secret_cfg, 0o000)
    try:
        ddl_000 = SqlDdlTruthAdapter().extract(py_repo, "backend")
        assert ddl_000.coverage_complete is False
        assert any("registry" in n.lower() for n in ddl_000.notes)

        rc = cli_main(
            [
                "gate",
                str(py_repo),
                "--profile",
                "fastapi-sqlalchemy-nextjs",
                "--strict",
                "--allow-local-plugins",
                "--plugin",
                "wythe_plugin_agent_harness.plugin:register_wythe_plugin",
            ]
        )
        out = capsys.readouterr().out
        assert rc != 0
        assert "INCOMPLETE" in out
    finally:
        os.chmod(secret_cfg, 0o644)

    # 3. Malformed YAML and FIFO in config/ -> SqlDdlTruthAdapter marks coverage_complete=False
    bad_yaml_repo = tmp_path / "bad_yaml_repo"
    _write(bad_yaml_repo, "schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    _write(bad_yaml_repo, "config/broken.yaml", "commands:\n  a: [unclosed\n")
    ddl_mal = SqlDdlTruthAdapter().extract(bad_yaml_repo, ".")
    assert ddl_mal.coverage_complete is False

    fifo_repo = tmp_path / "fifo_repo"
    _write(fifo_repo, "schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    (fifo_repo / "config").mkdir()
    os.mkfifo(fifo_repo / "config" / "pipe.yaml")
    ddl_fifo = SqlDdlTruthAdapter().extract(fifo_repo, ".")
    assert ddl_fifo.coverage_complete is False


def test_tier5_item2_service_sources_enametoolong_and_tach_bridge_coverage(
    tmp_path: Path,
) -> None:
    """Item 2 (P1-7/P1-8/P1-13): service_sources survives >1024B/0o000/symlinks & tach_bridge fails closed."""
    # 1. >1024B nested dir alongside valid ok.py & store.py
    deep_repo = tmp_path / "deep_svc"
    _write(
        deep_repo,
        "ok.py",
        "import sqlite3\nconn = sqlite3.connect('app.db')\nconn.execute('CREATE TABLE items (id INT)')\n",
    )
    _mkdir_deep_over_1024(deep_repo / "deep_sub")

    skipped: list[str] = []
    found, excluded = source_files(deep_repo, {".py"}, skipped_out=skipped)
    assert [p.name for p in found] == ["ok.py"]
    assert excluded >= 1
    assert skipped

    inline = scan_inline_stores(deep_repo, ".")
    assert any(s.table_name == "items" for s in inline)

    py_res = PythonServicesAdapter().extract(
        deep_repo, ".", TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    )
    assert py_res.coverage_complete is False
    assert any(n.source_file == "ok.py" for n in py_res.nodes)

    # 2. python_daemon_routes._has_external_display_sources does not flip on >1024B subdir
    pdr_repo = tmp_path / "pdr_repo"
    for i in range(9):
        _write(pdr_repo, f"apps/app{i}/index.tsx", "export default function A() { return <div />; }\n")
    for i in range(10):
        _write(pdr_repo, f"svc/mod{i}.py", "def run() -> int:\n    return 1\n")
    before_cls = _has_external_display_sources(pdr_repo)
    _mkdir_deep_over_1024(pdr_repo / "deep_pdr")
    after_cls = _has_external_display_sources(pdr_repo)
    assert before_cls is False
    assert after_cls is before_cls

    # 3. tach_bridge marks coverage_complete=False on symlinked .py, 0o000 dir, and >1024B subdir
    #    while still inspecting valid sibling modules.
    outside_py = tmp_path / "outside.py"
    outside_py.write_text("X = 1\n", encoding="utf-8")

    tach_sym = tmp_path / "tach_sym"
    _write(
        tach_sym,
        "tach.toml",
        'source_roots = ["."]\n[[modules]]\npath = "pkg.a"\ndepends_on = []\n[[modules]]\npath = "pkg.b"\ndepends_on = []\n',
    )
    _write(tach_sym, "pkg/__init__.py", "")
    _write(tach_sym, "pkg/b.py", "VAL = 1\n")
    _write(tach_sym, "pkg/a.py", "from pkg.b import VAL\n")
    os.symlink(outside_py, tach_sym / "pkg" / "sym.py")
    sym_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_tach_boundaries(tach_sym, ".", sym_res)
    assert sym_res.coverage_complete is False
    assert any(f.rule_code == "MANIP-006" for f in sym_res.findings)

    tach_000 = tmp_path / "tach_000"
    _write(
        tach_000,
        "tach.toml",
        'source_roots = ["."]\n[[modules]]\npath = "pkg.a"\ndepends_on = []\n[[modules]]\npath = "pkg.b"\ndepends_on = []\n',
    )
    _write(tach_000, "pkg/__init__.py", "")
    _write(tach_000, "pkg/b.py", "VAL = 1\n")
    _write(tach_000, "pkg/a.py", "from pkg.b import VAL\n")
    locked_dir = tach_000 / "locked"
    locked_dir.mkdir()
    os.chmod(locked_dir, 0o000)
    try:
        res_000 = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        augment_tach_boundaries(tach_000, ".", res_000)
        assert res_000.coverage_complete is False
        assert any(f.rule_code == "MANIP-006" for f in res_000.findings)
    finally:
        os.chmod(locked_dir, 0o755)

    tach_deep = tmp_path / "tach_deep_siblings"
    _write(
        tach_deep,
        "tach.toml",
        'source_roots = ["."]\n[[modules]]\npath = "pkg.a"\ndepends_on = []\n[[modules]]\npath = "pkg.b"\ndepends_on = []\n',
    )
    _write(tach_deep, "pkg/__init__.py", "")
    _write(tach_deep, "pkg/b.py", "VAL = 1\n")
    _write(tach_deep, "pkg/a.py", "from pkg.b import VAL\n")
    _mkdir_deep_over_1024(tach_deep / "deep_branch")
    res_deep = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_tach_boundaries(tach_deep, ".", res_deep)
    assert res_deep.coverage_complete is False
    assert any(f.rule_code == "MANIP-006" for f in res_deep.findings)


def test_tier5_item3_wiretap_heap_memgraph_and_compiler_ir_usr_index_hardening(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Item 3 (P1-7/P1-12): heap_memgraph & usr_index reject malformed/overlong inputs without crashing scans."""
    from wythe_plugin_compiler_ir.usr_index import (
        iter_safe_repo_files,
        load_bounded_json_or_yaml,
        parse_usr_index,
        read_safe_bytes,
        validate_safe_path,
    )
    from wythe_plugin_wiretap.heap_memgraph import (
        parse_byte_size_token,
        parse_memgraph_artifact,
        parse_vmmap_artifact,
    )

    # 1. heap_memgraph.parse_byte_size_token rejects non-finite floats & oversized tokens with ValueError
    for bad_tok in (float("inf"), float("-inf"), float("nan"), 1e309, "1e500", "inf", "9" * 400 + "B", 10**100):
        with pytest.raises(ValueError):
            parse_byte_size_token(bad_tok)

    # 2. parse_memgraph_artifact & parse_vmmap_artifact reject 1e309, non-list fields, & 5000-digit ints
    mg_inf = tmp_path / "mg_inf.json"
    mg_inf.write_text('{"classes": [{"class_name": "Foo", "total_bytes": 1e309}]}', encoding="utf-8")
    with pytest.raises(ValueError):
        parse_memgraph_artifact(mg_inf)

    for bad_key in ("classes", "nodes", "edges"):
        mg_bad = tmp_path / f"mg_bad_{bad_key}.json"
        mg_bad.write_text(json.dumps({bad_key: 123}), encoding="utf-8")
        with pytest.raises(ValueError):
            parse_memgraph_artifact(mg_bad)

    mg_huge = tmp_path / "mg_huge.json"
    mg_huge.write_text('{"classes": [{"class_name": "Foo", "total_bytes": ' + ("9" * 5000) + "}]}", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_memgraph_artifact(mg_huge)

    vm_bad = tmp_path / "vm_bad.json"
    vm_bad.write_text('{"regions": 123}', encoding="utf-8")
    with pytest.raises(ValueError):
        parse_vmmap_artifact(vm_bad)

    vm_inf = tmp_path / "vm_inf.json"
    vm_inf.write_text('{"regions": [{"region_type": "MALLOC", "virtual_bytes": 1e309}]}', encoding="utf-8")
    with pytest.raises(ValueError):
        parse_vmmap_artifact(vm_inf)

    # 3. usr_index handles >1024B ENAMETOOLONG paths, FIFO O_NONBLOCK, & hex-int YAML bombs
    cir_repo = tmp_path / "cir_repo"
    _write(cir_repo, "valid.json", json.dumps({"symbols": [{"usr": "c:@F@ok", "name": "ok"}]}))
    deep_dir = _mkdir_deep_over_1024(cir_repo / "deep_cir")
    with pytest.raises(ValueError):
        validate_safe_path(deep_dir / "idx.json", repo_root=cir_repo)

    found_cir = iter_safe_repo_files(cir_repo, suffixes=(".json",))
    assert [rel for _, rel in found_cir] == ["valid.json"]

    parsed_cir = parse_usr_index(cir_repo, repo_root=cir_repo)
    assert "c:@F@ok" in parsed_cir.symbols_by_usr

    fifo_p = tmp_path / "usr_pipe.json"
    os.mkfifo(fifo_p)
    with pytest.raises(ValueError):
        read_safe_bytes(fifo_p, allow_external=True)

    with pytest.raises(ValueError, match="YAML|bit length"):
        load_bounded_json_or_yaml("x: 0x" + ("f" * 5000))

    # 4. Neither wiretap nor compiler-ir plugin hooks crash run_target_scan on bad/deep artifacts
    app_repo = tmp_path / "scan_plugin_repo"
    _write(app_repo, "schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    _write(app_repo, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(app_repo, "frontend/package.json", '{"dependencies":{"next":"15.0.0"}}\n')
    _write(app_repo, "frontend/src/app/page.tsx", "export default function Page() { return <main />; }\n")
    _init_git(app_repo)

    tgt = register_target(
        db_session,
        TargetProjectCreate(
            slug="tier5-plugin-resilience",
            name="tier5-plugin-resilience",
            repo_path=str(app_repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
            backend_subdir="backend",
            frontend_subdir="frontend",
        ),
    )

    with stratum_artifacts_scope(memgraph=[str(mg_inf)]):
        rep_wt = run_target_scan(
            db_session,
            tgt,
            strict_gate=True,
            persist_snapshot=False,
            allow_local_plugins=True,
            local_plugin_modules=["wythe_plugin_wiretap.plugin:WIRETAP_PLUGIN"],
        )
        assert rep_wt.target_slug == "tier5-plugin-resilience"

    with stratum_artifacts_scope(index_store=[str(cir_repo)]):
        rep_ir = run_target_scan(
            db_session,
            tgt,
            strict_gate=True,
            persist_snapshot=False,
            allow_local_plugins=True,
            local_plugin_modules=["wythe_plugin_compiler_ir.plugin:COMPILER_IR_PLUGIN"],
        )
        assert rep_ir.target_slug == "tier5-plugin-resilience"


def test_tier5_item4_governance_db_signature_invalidates_cached_scan_on_allowlist_change(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Item 4 (P0-3/P1-12/A1): get_or_run_cached_scan invalidates when allowlist/exemplars change."""
    repo = tmp_path / "allowlist_cache_repo"
    _write(repo, "backend/schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    _write(
        repo,
        "backend/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/api/items')\ndef items():\n    return []\n",
    )
    _write(repo, "frontend/package.json", '{"dependencies":{"next":"15.0.0"}}\n')
    _write(
        repo,
        "frontend/src/demo.tsx",
        "export async function loadDemo() {\n"
        "  const res = await fetch('/api/items');\n"
        "  const payload = await res.json();\n"
        "  const href = payload.href ?? '/fallback-action';\n"
        "  return <div>{href}</div>;\n"
        "}\n",
    )
    _write(
        repo,
        ".wythe/governance.json",
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "tier5-allowlist-cache",
                "exported_at": "2026-11-21T00:00:00Z",
                "fabricated_fallback_allowlist": ["frontend/src/demo.tsx"],
            }
        ),
    )
    _init_git(repo)

    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="tier5-allowlist-cache",
            name="tier5-allowlist-cache",
            repo_path=str(repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
            backend_subdir="backend",
            frontend_subdir="frontend",
        ),
    )

    # First scan with allowlist synced -> PASS
    sync_portable_bundle_from_disk(db_session, target)
    rep_allowed = get_or_run_cached_scan(db_session, target, strict_gate=False)
    assert rep_allowed.gate.verdict == "PASS"

    # Revoke allowlist and clear in-memory cache -> persisted snapshot must invalidate to FAIL (DISP-010)
    _write(
        repo,
        ".wythe/governance.json",
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "tier5-allowlist-cache",
                "exported_at": "2026-11-21T00:00:00Z",
                "fabricated_fallback_allowlist": [],
            }
        ),
    )
    sync_portable_bundle_from_disk(db_session, target)
    clear_scan_reuse_cache()
    rep_revoked = get_or_run_cached_scan(db_session, target, strict_gate=False)
    assert rep_revoked.gate.verdict == "FAIL"
    assert any(f.rule_code == "DISP-010" and f.blocks_gate for f in rep_revoked.findings)

    # Now verify reference_exemplars change also invalidates persisted snapshot
    _write(
        repo,
        ".wythe/governance.json",
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "tier5-allowlist-cache",
                "exported_at": "2026-11-21T00:00:00Z",
                "reference_exemplars": [
                    {
                        "title": "Fixture demo DISP-010",
                        "pointer": "frontend/src/demo.tsx",
                        "rationale": "Explicit fixture example for DISP-010",
                    }
                ],
            }
        ),
    )
    sync_portable_bundle_from_disk(db_session, target)
    clear_scan_reuse_cache()
    rep_ex = get_or_run_cached_scan(db_session, target, strict_gate=False)
    assert rep_ex.gate.verdict == "PASS"

    _write(
        repo,
        ".wythe/governance.json",
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "tier5-allowlist-cache",
                "exported_at": "2026-11-21T00:00:00Z",
                "reference_exemplars": [],
            }
        ),
    )
    sync_portable_bundle_from_disk(db_session, target)
    clear_scan_reuse_cache()
    rep_ex_revoked = get_or_run_cached_scan(db_session, target, strict_gate=False)
    assert rep_ex_revoked.gate.verdict == "FAIL"


def test_tier5_item5_agent_harness_yaml_dedup_and_registry_hardening(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Item 5 (P1-7/P1-13): agent-harness avoids duplicate YAML registry nodes & marks bad config/ incomplete."""
    from wythe_plugin_agent_harness.plugin import register_wythe_plugin
    from wythe_plugin_agent_harness.registry_reconciler import discover_tool_registries

    # 1. YAML-only registry in config/tools.yaml produces zero duplicate t:registry:config/tools.yaml nodes
    yaml_repo = tmp_path / "yaml_harness_repo"
    _write(yaml_repo, "schema.sql", "CREATE TABLE sessions (id INT PRIMARY KEY);\n")
    _write(
        yaml_repo,
        "config/tools.yaml",
        "capabilities:\n  allowlist:\n    - lookup_session\ntools:\n  lookup_session:\n    enabled: true\n",
    )
    _write(yaml_repo, "app.py", "def run():\n    return 'ok'\n")
    _init_git(yaml_repo)

    tgt = register_target(
        db_session,
        TargetProjectCreate(
            slug="tier5-yaml-harness",
            name="tier5-yaml-harness",
            repo_path=str(yaml_repo),
            stack_profile_slug="python-services",
            backend_subdir=".",
            frontend_subdir=".",
        ),
    )
    rep = run_target_scan(
        db_session,
        tgt,
        strict_gate=True,
        persist_snapshot=False,
        allow_local_plugins=True,
        local_plugin_modules=["wythe_plugin_agent_harness.plugin:register_wythe_plugin"],
    )
    reg_nodes = [n for n in rep.nodes if n.id == "t:registry:config/tools.yaml"]
    assert len(reg_nodes) == 1

    # 2. Hex integer bomb (? 0x<5000 f's>: 1) in config/tools.yaml is caught cleanly & sets coverage_complete=False
    hex_repo = tmp_path / "hex_yaml_repo"
    _write(
        hex_repo,
        "config/tools.yaml",
        "tools:\n  a:\n    ? 0x" + ("f" * 5000) + "\n    : 1\n",
    )
    regs, errs = discover_tool_registries(hex_repo)
    assert regs == []
    assert errs

    spec = register_wythe_plugin()
    mres_hex = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    spec.augment_manipulator(hex_repo, ".", mres_hex)
    assert mres_hex.coverage_complete is False

    # 3. Broken JSON, symlinked YAML, FIFO, and 0o000 subdir in config/ record errors & set coverage_complete=False
    bad_repo = tmp_path / "bad_cfg_repo"
    outside_yaml = tmp_path / "outside_tools.yaml"
    outside_yaml.write_text("tools:\n  x:\n    enabled: true\n", encoding="utf-8")
    _write(bad_repo, "config/broken.json", "{not valid json")
    _write(
        bad_repo,
        "config/good.yaml",
        "tools:\n  valid_tool:\n    enabled: true\n",
    )
    os.symlink(outside_yaml, bad_repo / "config" / "sym.yaml")
    os.mkfifo(bad_repo / "config" / "pipe.yaml")
    sub000 = bad_repo / "config" / "sub000"
    sub000.mkdir()
    _write(sub000, "hidden.yaml", "tools:\n  h:\n    enabled: true\n")
    os.chmod(sub000, 0o000)
    try:
        good_regs, bad_errs = discover_tool_registries(bad_repo)
        assert [r.rel_path for r in good_regs] == ["config/good.yaml"]
        assert len(bad_errs) >= 4

        mres_bad = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        spec.augment_manipulator(bad_repo, ".", mres_bad)
        assert mres_bad.coverage_complete is False
    finally:
        os.chmod(sub000, 0o755)


def test_tier5_item6_targets_governance_sync_allowlist_roundtrip_and_400_errors(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Item 6 (P0-3/A1 API contract): governance-sync imports allowlist & returns 400 (never 500) on bad bundles."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "api_gov_repo"
    _write(repo, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(
        repo,
        ".wythe/governance.json",
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "tier5-api-gov",
                "exported_at": "2026-11-21T00:00:00Z",
                "fabricated_fallback_allowlist": ["frontend/src/demo.tsx"],
            }
        ),
    )

    register_target(
        db_session,
        TargetProjectCreate(
            slug="tier5-api-gov",
            name="tier5-api-gov",
            repo_path=str(repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
            backend_subdir="backend",
            frontend_subdir="frontend",
        ),
    )

    with TestClient(create_app(), raise_server_exceptions=False) as client:
        # 1. Valid fabricated_fallback_allowlist round-trips via import -> GET governance-bundle
        imp_ok = client.post("/api/v1/targets/tier5-api-gov/governance-sync?direction=import")
        assert imp_ok.status_code == 200
        bundle_resp = client.get("/api/v1/targets/tier5-api-gov/governance-bundle")
        assert bundle_resp.status_code == 200
        assert bundle_resp.json()["fabricated_fallback_allowlist"] == ["frontend/src/demo.tsx"]

        # 2. Malformed JSON -> HTTP 400 (not 500)
        _write(repo, ".wythe/governance.json", "{malformed json")
        imp_bad_json = client.post("/api/v1/targets/tier5-api-gov/governance-sync?direction=import")
        assert imp_bad_json.status_code == 400

        # 3. Pydantic validation failure -> HTTP 400 (not 500)
        _write(
            repo,
            ".wythe/governance.json",
            json.dumps({"schema_version": "1.0", "rule_overrides": "not-a-list"}),
        )
        imp_bad_model = client.post("/api/v1/targets/tier5-api-gov/governance-sync?direction=import")
        assert imp_bad_model.status_code == 400

        # 4. Symlinked .wythe/governance.json -> HTTP 400 (not 500)
        outside_gov = tmp_path / "outside_gov.json"
        outside_gov.write_text('{"schema_version": "1.0"}', encoding="utf-8")
        gov_path = repo / ".wythe" / "governance.json"
        gov_path.unlink()
        os.symlink(outside_gov, gov_path)
        imp_sym = client.post("/api/v1/targets/tier5-api-gov/governance-sync?direction=import")
        assert imp_sym.status_code == 400
