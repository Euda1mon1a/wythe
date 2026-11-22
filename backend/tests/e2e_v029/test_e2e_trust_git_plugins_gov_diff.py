"""Opaque-box E2E tests for Wythe v0.2.9: Git containment, plugins, governance, diff & CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from .conftest import (
    init_git_repo,
    run_cli,
    run_cli_subprocess,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_BACKEND_DIR = _REPO_ROOT / "backend"
_RUFF_BIN = Path("/opt/homebrew/bin/ruff")


def _subproc_pythonpath(*extra: Path) -> str:
    parts = [str(_BACKEND_DIR), *(str(p) for p in extra)]
    return os.pathsep.join(parts)


def _git_cmd(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Euda1mon1a",
        "GIT_AUTHOR_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Euda1mon1a",
        "GIT_COMMITTER_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        capture_output=True,
        text=True,
        check=check,
    )


def _git_commit_all(repo: Path, message: str = "update") -> str:
    _git_cmd(repo, "add", "-A")
    _git_cmd(repo, "-c", "commit.gpgsign=false", "commit", "-m", message)
    return _git_cmd(repo, "rev-parse", "HEAD").stdout.strip()


_NOW_SERVICE_CODE = (
    "from datetime import datetime\n"
    "def now_val():\n"
    "    return datetime.now()\n"
)


def _base_app_files(service_code: str | None = None) -> dict[str, str]:
    svc = service_code or (
        "def compute_quota(limit: int) -> int:\n"
        "    return limit\n"
    )
    return {
        "backend/schema.sql": "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);\n",
        "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "backend/app/services/svc.py": svc,
        "frontend/src/app/page.tsx": "export default function Page() { return <main>ok</main>; }\n",
    }


def _disp010_files() -> dict[str, str]:
    return {
        "backend/schema.sql": "CREATE TABLE items (id INTEGER PRIMARY KEY);\n",
        "backend/app/main.py": (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/api/items')\n"
            "def list_items():\n"
            "    return {'items': []}\n"
        ),
        "frontend/src/demo.js": "export const demoItem = { id: 'demo-1', label: 'Demo' };\n",
        "frontend/src/page.js": (
            "import { demoItem } from './demo';\n"
            "export async function loadItems() {\n"
            "  const res = await fetch('/api/items');\n"
            "  const payload = await res.json();\n"
            "  const href = payload.href ?? '/fallback-action';\n"
            "  return { href, demoItem };\n"
            "}\n"
        ),
    }


def _create_user_site_plugin(
    userbase: Path,
    dist_name: str,
    ep_name: str,
    mod_name: str,
    attr_name: str,
    module_source: str,
) -> Path:
    py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_dir = userbase / "lib" / py_ver / "site-packages"
    site_dir.mkdir(parents=True, exist_ok=True)
    dist_info = site_dir / f"{dist_name.replace('-', '_')}-0.1.0.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {dist_name}\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[wythe.plugins]\n{ep_name} = {mod_name}:{attr_name}\n",
        encoding="utf-8",
    )
    mod_parts = mod_name.split(".")
    if len(mod_parts) == 1:
        (site_dir / f"{mod_parts[0]}.py").write_text(module_source, encoding="utf-8")
    else:
        pkg_dir = site_dir.joinpath(*mod_parts[:-1])
        pkg_dir.mkdir(parents=True, exist_ok=True)
        for idx in range(1, len(mod_parts)):
            init_file = site_dir.joinpath(*mod_parts[:idx], "__init__.py")
            if not init_file.exists():
                init_file.write_text("", encoding="utf-8")
        (pkg_dir / f"{mod_parts[-1]}.py").write_text(module_source, encoding="utf-8")
    return site_dir


# ---------------------------------------------------------------------------
# F01: Safe Git Containment & RCE Prevention (P0-1)
# ---------------------------------------------------------------------------


def test_f01_t1_clean_git_repo_scan_gate_diff(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "clean_repo"
    init_git_repo(repo, _base_app_files())

    rc_scan, _, err_scan = run_cli(["scan", str(repo)])
    rc_gate, out_gate, err_gate = run_cli(["gate", str(repo)])
    rc_diff, out_diff, err_diff = run_cli(["diff", str(repo), "--base", "HEAD"])

    assert rc_scan == 0, err_scan
    assert rc_gate == 0, err_gate
    assert "PASS" in out_gate
    assert rc_diff == 0, err_diff
    assert "PASS" in out_diff


def test_f01_t1_valid_worktree_backed_repo_scan_and_diff(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    main_repo = tmp_path / "main_repo"
    head_sha = init_git_repo(main_repo, _base_app_files())
    wt_dir = tmp_path / "wt_checkout"
    _git_cmd(main_repo, "worktree", "add", "-b", "feature/wt", str(wt_dir), head_sha)

    scan_json = tmp_path / "wt_scan.json"
    rc_scan, _, err_scan = run_cli(["scan", str(wt_dir), "--json", str(scan_json)])
    rc_diff, out_diff, err_diff = run_cli(["diff", str(wt_dir), "--base", "HEAD"])

    assert rc_scan == 0, err_scan
    assert json.loads(scan_json.read_text(encoding="utf-8"))["source_commit"] == head_sha
    assert rc_diff == 0, err_diff
    assert "PASS" in out_diff


def test_f01_t1_scan_with_untracked_files_succeeds(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "untracked_repo"
    init_git_repo(repo, _base_app_files())
    nested_dir = repo / "backend" / "app" / "extra"
    nested_dir.mkdir(parents=True, exist_ok=True)
    (nested_dir / "untracked_one.py").write_text("VALUE = 1\n", encoding="utf-8")
    (nested_dir / "untracked_two.py").write_text("VALUE = 2\n", encoding="utf-8")

    scan_json = tmp_path / "untracked_scan.json"
    rc_scan, _, err_scan = run_cli(["scan", str(repo), "--json", str(scan_json)])
    rc_gate, _, err_gate = run_cli(["gate", str(repo)])

    assert rc_scan == 0, err_scan
    assert scan_json.is_file()
    assert rc_gate == 0, err_gate


def test_f01_t1_diff_clean_config_detects_modified_file(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "modified_repo"
    init_git_repo(repo, _base_app_files())
    svc = repo / "backend" / "app" / "services" / "svc.py"
    svc.write_text(
        "def compute_quota(limit: int) -> int:\n    return limit + 1\n",
        encoding="utf-8",
    )

    diff_json = tmp_path / "mod_diff.json"
    rc, _, err = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    payload = json.loads(diff_json.read_text(encoding="utf-8"))

    assert rc == 0, err
    assert payload["base_graph_status"] == "available"
    assert "backend/app/services/svc.py" in payload["changed_files"]


def test_f01_t1_read_only_git_inspection_preserves_clean_status(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "ro_repo"
    init_git_repo(repo, _base_app_files())
    before_status = _git_cmd(repo, "status", "--porcelain").stdout

    assert run_cli(["scan", str(repo)])[0] == 0
    assert run_cli(["gate", str(repo)])[0] == 0
    after_status = _git_cmd(repo, "status", "--porcelain").stdout
    assert before_status == ""
    assert after_status == ""


def test_f01_t2_git_filter_clean_rce_blocked(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "filter_clean_repo"
    files = {**_base_app_files(), ".gitattributes": "* filter=pwn\n"}
    init_git_repo(repo, files)
    sentinel = tmp_path / "FILTER_CLEAN_RCE"

    _git_cmd(repo, "config", "filter.pwn.clean", f"touch {sentinel}")
    svc = repo / "backend" / "app" / "services" / "svc.py"
    svc.write_text(
        "def compute_quota(limit: int) -> int:\n    return limit + 2\n",
        encoding="utf-8",
    )

    scan_json = tmp_path / "filter_clean_scan.json"
    rc_scan, _, _ = run_cli(["scan", str(repo), "--json", str(scan_json)])
    rc_diff, _, _ = run_cli(["diff", str(repo), "--base", "HEAD"])

    assert not sentinel.exists()
    assert rc_diff == 2
    assert rc_scan in (0, 2)
    if rc_scan == 0 and scan_json.is_file():
        assert json.loads(scan_json.read_text(encoding="utf-8"))["source_commit"] == "unavailable"


def test_f01_t2_git_filter_process_rce_blocked(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "filter_proc_repo"
    files = {**_base_app_files(), ".gitattributes": "* filter=pwnproc\n"}
    init_git_repo(repo, files)
    sentinel = tmp_path / "FILTER_PROCESS_RCE"

    _git_cmd(repo, "config", "filter.pwnproc.process", f"touch {sentinel}")
    svc = repo / "backend" / "app" / "services" / "svc.py"
    svc.write_text(
        "def compute_quota(limit: int) -> int:\n    return limit + 3\n",
        encoding="utf-8",
    )

    scan_json = tmp_path / "filter_proc_scan.json"
    rc_scan, _, _ = run_cli(["scan", str(repo), "--json", str(scan_json)])
    rc_diff, _, _ = run_cli(["diff", str(repo), "--base", "HEAD"])

    assert not sentinel.exists()
    assert rc_diff == 2
    assert rc_scan in (0, 2)
    if rc_scan == 0 and scan_json.is_file():
        assert json.loads(scan_json.read_text(encoding="utf-8"))["source_commit"] == "unavailable"


def test_f01_t2_log_show_signature_gpg_program_rce_blocked(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "gpg_sig_repo"
    base_sha = init_git_repo(repo, _base_app_files())
    svc = repo / "backend" / "app" / "services" / "svc.py"
    svc.write_text(
        "def compute_quota(limit: int) -> int:\n    return limit + 1\n",
        encoding="utf-8",
    )
    head_sha = _git_commit_all(repo, "second commit")

    raw_commit = _git_cmd(repo, "cat-file", "commit", head_sha).stdout
    header, msg = raw_commit.split("\n\n", 1)
    signed_commit = (
        f"{header}\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " iQIz\n"
        " -----END PGP SIGNATURE-----\n\n"
        f"{msg}"
    )
    new_sha = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=signed_commit,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    _git_cmd(repo, "update-ref", "HEAD", new_sha)

    sentinel = tmp_path / "GPG_RCE"
    gpg_script = tmp_path / "evil_gpg.sh"
    gpg_script.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 0\n", encoding="utf-8")
    gpg_script.chmod(0o755)
    _git_cmd(repo, "config", "log.showSignature", "true")
    _git_cmd(repo, "config", "gpg.program", str(gpg_script))

    rc_diff, _, _ = run_cli(["diff", str(repo), "--base", base_sha])
    assert rc_diff == 0
    assert not sentinel.exists()


def test_f01_t2_core_worktree_escape_blocked(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "worktree_escape_repo"
    init_git_repo(repo, _base_app_files())
    outside = tmp_path / "outside_host"
    (outside / "backend" / "app" / "services").mkdir(parents=True)
    (outside / "backend" / "schema.sql").write_text(
        "CREATE TABLE secrets (id INT PRIMARY KEY);\n", encoding="utf-8"
    )
    (outside / "backend" / "app" / "services" / "host_secret.py").write_text(
        "from datetime import datetime\nNOW = datetime.now()\n", encoding="utf-8"
    )
    _git_cmd(repo, "config", "core.worktree", str(outside))

    scan_json = tmp_path / "escape_scan.json"
    rc_scan, _, _ = run_cli(["scan", str(repo), "--json", str(scan_json)])
    rc_diff, _, _ = run_cli(["diff", str(repo), "--base", "HEAD"])

    assert rc_diff == 2
    assert rc_scan in (0, 2)
    if rc_scan == 0 and scan_json.is_file():
        rep = json.loads(scan_json.read_text(encoding="utf-8"))
        assert rep["source_commit"] == "unavailable"
        assert all("host_secret.py" not in (n.get("source_file") or "") for n in rep["nodes"])
        assert all("host_secret.py" not in (f.get("source_file") or "") for f in rep["findings"])


def test_f01_t2_symlink_git_config_and_fake_worktrees_blocked(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    sym_repo = tmp_path / "sym_config_repo"
    init_git_repo(sym_repo, _base_app_files())
    ext_cfg = tmp_path / "ext_config"
    ext_cfg.write_text("[core]\n\trepositoryformatversion = 0\n", encoding="utf-8")
    git_cfg = sym_repo / ".git" / "config"
    git_cfg.unlink()
    git_cfg.symlink_to(ext_cfg)

    sym_scan_json = tmp_path / "sym_scan.json"
    rc_sym_scan, _, _ = run_cli(["scan", str(sym_repo), "--json", str(sym_scan_json)])
    assert run_cli(["diff", str(sym_repo), "--base", "HEAD"])[0] == 2
    assert rc_sym_scan in (0, 2)
    if rc_sym_scan == 0 and sym_scan_json.is_file():
        sym_rep = json.loads(sym_scan_json.read_text(encoding="utf-8"))
        assert sym_rep["source_commit"] == "unavailable"

    fake_wt_repo = tmp_path / "fake_wt_repo"
    fake_wt_repo.mkdir(parents=True)
    for rel, content in _base_app_files().items():
        p = fake_wt_repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    fake_gitdir = tmp_path / "worktrees" / "decoy"
    fake_gitdir.mkdir(parents=True)
    (fake_gitdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (fake_gitdir / "commondir").write_text("../..\n", encoding="utf-8")
    (fake_gitdir / "gitdir").write_text(str(tmp_path / "unrelated_repo" / ".git"), encoding="utf-8")
    (fake_wt_repo / ".git").write_text(f"gitdir: {fake_gitdir}\n", encoding="utf-8")

    fake_scan_json = tmp_path / "fake_wt_scan.json"
    rc_fake_scan, _, _ = run_cli(["scan", str(fake_wt_repo), "--json", str(fake_scan_json)])
    assert run_cli(["diff", str(fake_wt_repo), "--base", "HEAD"])[0] == 2
    assert rc_fake_scan in (0, 2)
    if rc_fake_scan == 0 and fake_scan_json.is_file():
        fake_rep = json.loads(fake_scan_json.read_text(encoding="utf-8"))
        assert fake_rep["source_commit"] == "unavailable"


def test_f01_t2_git_config_include_and_include_if_blocked(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    sentinel = tmp_path / "INCLUDE_RCE"
    inc_cfg = tmp_path / "included.cfg"
    inc_cfg.write_text(f'[core]\n\tfsmonitor = "touch {sentinel} && echo"\n', encoding="utf-8")

    repo_inc = tmp_path / "repo_include"
    init_git_repo(repo_inc, _base_app_files())
    with (repo_inc / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(f"\n[include]\n\tpath = {inc_cfg}\n")

    assert run_cli(["diff", str(repo_inc), "--base", "HEAD"])[0] == 2
    assert run_cli(["scan", str(repo_inc)])[0] in (0, 2)
    assert not sentinel.exists()

    repo_inc_if = tmp_path / "repo_include_if"
    init_git_repo(repo_inc_if, _base_app_files())
    with (repo_inc_if / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(f'\n[includeIf "gitdir:/"]\n\tpath = {inc_cfg}\n')

    assert run_cli(["diff", str(repo_inc_if), "--base", "HEAD"])[0] == 2
    assert run_cli(["scan", str(repo_inc_if)])[0] in (0, 2)
    assert not sentinel.exists()


# ---------------------------------------------------------------------------
# F02: Plugin Entry-Point Loading & Fail-Closed (P0-2, P1-12)
# ---------------------------------------------------------------------------


def test_f02_t1_plugins_json_lists_builtins(e2e_env: dict[str, Any]) -> None:
    del e2e_env
    rc, out, err = run_cli(["plugins", "--json"])
    assert rc == 0, err
    data = json.loads(out)
    assert data["entry_point_group"] == "wythe.plugins"
    assert data["allow_local_plugins"] is False
    names = {p["name"]: p for p in data["plugins"]}
    assert "container-sources" in names
    assert "tach-boundaries" in names
    assert names["container-sources"]["origin"] == "builtin"


def test_f02_t1_allow_local_plugins_loads_companion_plugin(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "plugin_repo"
    init_git_repo(repo, _base_app_files())
    plugin_py = tmp_path / "companion_ok.py"
    plugin_py.write_text(
        "class SyntheticPlugin:\n"
        "    name = 'synthetic-companion'\n"
        "    version = '0.1.0'\n"
        "    description = 'Synthetic post-scan plugin'\n"
        "    def check_report(self, repo_root, report):\n"
        "        return []\n"
        "PLUGIN = SyntheticPlugin()\n",
        encoding="utf-8",
    )

    rc_p, out_p, err_p = run_cli(
        ["plugins", "--json", "--allow-local-plugins", "--plugin", f"{plugin_py}:PLUGIN"]
    )
    assert rc_p == 0, err_p
    pdata = json.loads(out_p)
    matched = [p for p in pdata["plugins"] if p["name"] == "synthetic-companion"]
    assert len(matched) == 1
    assert matched[0]["origin"] == "local_opt_in"

    rc_s, _, err_s = run_cli(
        ["scan", str(repo), "--allow-local-plugins", "--plugin", f"{plugin_py}:PLUGIN"]
    )
    assert rc_s == 0, err_s


def test_f02_t1_valid_entry_point_discovery_external_site_subprocess(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    repo = tmp_path / "ep_clean_repo"
    init_git_repo(repo, _base_app_files())
    userbase = tmp_path / "userbase_ok"
    site_dir = _create_user_site_plugin(
        userbase,
        dist_name="wythe-test-ep-ok",
        ep_name="test-ep-ok",
        mod_name="wythe_test_ep_ok",
        attr_name="PLUGIN",
        module_source=(
            "class OkPlugin:\n"
            "    name = 'test-ep-ok'\n"
            "    version = '0.1.0'\n"
            "    description = 'Valid external entry point'\n"
            "    def check_report(self, repo_root, report):\n"
            "        return []\n"
            "PLUGIN = OkPlugin()\n"
        ),
    )

    rc, out, err = run_cli_subprocess(
        ["plugins", "--json"],
        cwd=repo,
        env_overrides={
            "WYTHE_DATABASE_URL": e2e_env["db_url"],
            "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
            "PYTHONUSERBASE": str(userbase),
            "PYTHONPATH": _subproc_pythonpath(site_dir),
        },
    )
    assert rc == 0, err
    pdata = json.loads(out)
    matched = [p for p in pdata["plugins"] if p["name"] == "test-ep-ok"]
    assert len(matched) == 1
    assert matched[0]["origin"] == "entry_point"


def test_f02_t1_builtin_container_sources_and_tach_boundaries_scan(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "builtin_repo"
    files = {
        **_base_app_files(),
        "Dockerfile": "FROM python:3.12-slim\nCMD [\"python\", \"-m\", \"app\"]\n",
        "tach.toml": "exact = true\n[[modules]]\npath = \"backend.app\"\ndepends_on = []\n",
    }
    init_git_repo(repo, files)

    scan_json = tmp_path / "builtin_scan.json"
    rc, _, err = run_cli(["scan", str(repo), "--json", str(scan_json)])
    assert rc == 0, err
    report = json.loads(scan_json.read_text(encoding="utf-8"))
    assert report["coverage_complete"] is True
    assert len(report["nodes"]) >= 1


def test_f02_t1_multiple_plugin_flags_loaded(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    p1 = tmp_path / "plug_one.py"
    p2 = tmp_path / "plug_two.py"
    p1.write_text(
        "class P1:\n    name = 'multi-one'\n"
        "    def check_report(self, r, rep): return []\nP = P1()\n",
        encoding="utf-8",
    )
    p2.write_text(
        "class P2:\n    name = 'multi-two'\n"
        "    def check_report(self, r, rep): return []\nP = P2()\n",
        encoding="utf-8",
    )

    rc, out, err = run_cli(
        [
            "plugins",
            "--json",
            "--allow-local-plugins",
            "--plugin",
            f"{p1}:P",
            "--plugin",
            f"{p2}:P",
        ]
    )
    assert rc == 0, err
    names = {p["name"] for p in json.loads(out)["plugins"]}
    assert {"multi-one", "multi-two"} <= names


def test_f02_t2_sys_path_shadowing_attack_blocked_in_subprocess(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    repo = tmp_path / "shadow_repo"
    init_git_repo(repo, _base_app_files())
    sentinel = tmp_path / "SHADOW_PLUGIN_RCE"
    (repo / "wythe_plugin_binary.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('pwned', encoding='utf-8')\n",
        encoding="utf-8",
    )

    userbase = tmp_path / "userbase_shadow"
    site_dir = _create_user_site_plugin(
        userbase,
        dist_name="wythe-plugin-binary",
        ep_name="binary",
        mod_name="wythe_plugin_binary.plugin",
        attr_name="BINARY_INSPECTION_PLUGIN",
        module_source=(
            "class CleanBinaryPlugin:\n"
            "    name = 'binary'\n"
            "    version = '0.1.0'\n"
            "    description = 'Trusted binary stub'\n"
            "    def check_report(self, repo_root, report):\n"
            "        return []\n"
            "BINARY_INSPECTION_PLUGIN = CleanBinaryPlugin()\n"
        ),
    )

    env_ov = {
        "WYTHE_DATABASE_URL": e2e_env["db_url"],
        "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
        "PYTHONUSERBASE": str(userbase),
        "PYTHONPATH": _subproc_pythonpath(site_dir),
    }
    rc_p, out_p, err_p = run_cli_subprocess(["plugins", "--json"], cwd=repo, env_overrides=env_ov)
    assert rc_p == 0, err_p
    assert "Traceback" not in err_p
    assert isinstance(json.loads(out_p)["plugins"], list)

    rc, _, err = run_cli_subprocess(["scan", "."], cwd=repo, env_overrides=env_ov)
    assert rc in (0, 2), err
    assert "Traceback" not in err
    assert not sentinel.exists()


def test_f02_t2_plugin_flag_without_allow_local_plugins_fails_closed(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "no_optin_repo"
    init_git_repo(repo, _base_app_files())
    sentinel = tmp_path / "NO_OPTIN_EXEC"
    plugin_py = tmp_path / "local_mod.py"
    plugin_py.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('ran', encoding='utf-8')\n",
        encoding="utf-8",
    )

    rc_p, _, _ = run_cli(["plugins", "--json", "--plugin", f"{plugin_py}:PLUGIN"])
    rc_s, _, _ = run_cli(["scan", str(repo), "--plugin", f"{plugin_py}:PLUGIN"])

    assert rc_p == 2
    assert rc_s == 2
    assert not sentinel.exists()


def test_f02_t2_symlinked_local_plugin_rejected(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "sym_plugin_repo"
    init_git_repo(repo, _base_app_files())
    sentinel = tmp_path / "SYM_PLUGIN_EXEC"
    real_py = tmp_path / "real_plugin.py"
    real_py.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('ran', encoding='utf-8')\n"
        "class SymP:\n    name = 'sym-p'\n"
        "    def check_report(self, r, rep): return []\nP = SymP()\n",
        encoding="utf-8",
    )
    sym_py = tmp_path / "sym_plugin.py"
    sym_py.symlink_to(real_py)

    rc_p, out_p, _ = run_cli(
        ["plugins", "--json", "--allow-local-plugins", "--plugin", f"{sym_py}:P"]
    )
    rc_s, _, _ = run_cli(
        ["scan", str(repo), "--allow-local-plugins", "--plugin", f"{sym_py}:P"]
    )

    assert not sentinel.exists()
    assert rc_p in (0, 2)
    if rc_p == 0:
        assert all(p["name"] != "sym-p" for p in json.loads(out_p)["plugins"])
    assert rc_s in (0, 2)


def test_f02_t2_entry_point_plugin_runtime_exception_sets_incomplete(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    repo = tmp_path / "ep_boom_repo"
    init_git_repo(repo, _base_app_files())
    userbase = tmp_path / "userbase_boom"
    site_dir = _create_user_site_plugin(
        userbase,
        dist_name="wythe-test-ep-boom",
        ep_name="test-ep-boom",
        mod_name="wythe_test_ep_boom",
        attr_name="PLUGIN",
        module_source=(
            "class BoomPlugin:\n"
            "    name = 'test-ep-boom'\n"
            "    version = '0.1.0'\n"
            "    description = 'Raises during post-scan'\n"
            "    def check_report(self, repo_root, report):\n"
            "        raise RuntimeError('synthetic entry_point boom')\n"
            "PLUGIN = BoomPlugin()\n"
        ),
    )

    env_ov = {
        "WYTHE_DATABASE_URL": e2e_env["db_url"],
        "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
        "PYTHONUSERBASE": str(userbase),
        "PYTHONPATH": _subproc_pythonpath(site_dir),
    }
    rc_gate, out_gate, _ = run_cli_subprocess(["gate", str(repo)], cwd=repo, env_overrides=env_ov)
    scan_json = tmp_path / "ep_boom_scan.json"
    rc_scan, _, err_scan = run_cli_subprocess(
        ["scan", str(repo), "--json", str(scan_json)], cwd=repo, env_overrides=env_ov
    )

    assert rc_gate == 2
    assert "INCOMPLETE" in out_gate
    assert rc_scan == 0, err_scan
    report = json.loads(scan_json.read_text(encoding="utf-8"))
    assert report["coverage_complete"] is False
    assert report["gate"]["verdict"] == "INCOMPLETE"


def test_f02_t2_untrusted_dist_info_and_ep_dist_none_fail_closed(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    repo = tmp_path / "evil_dist_repo"
    init_git_repo(repo, _base_app_files())
    sentinel_repo = tmp_path / "REPO_DIST_RCE"
    dist_info = repo / "evil_repo_plug-0.1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: evil-repo-plug\nVersion: 0.1.0\n", encoding="utf-8"
    )
    (dist_info / "entry_points.txt").write_text(
        "[wythe.plugins]\nevil-repo = evil_repo_mod:PLUGIN\n", encoding="utf-8"
    )
    (repo / "evil_repo_mod.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel_repo)!r}).write_text('pwn', encoding='utf-8')\n",
        encoding="utf-8",
    )

    rc_p, out_p, err_p = run_cli_subprocess(
        ["plugins", "--json"],
        cwd=repo,
        env_overrides={
            "WYTHE_DATABASE_URL": e2e_env["db_url"],
            "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
            "PYTHONPATH": _subproc_pythonpath(repo),
        },
    )
    assert rc_p == 0, err_p
    assert not sentinel_repo.exists()
    assert all(p["name"] != "evil-repo" for p in json.loads(out_p)["plugins"])

    ghost_site = tmp_path / "ghost_site"
    ghost_site.mkdir(parents=True)
    sentinel_ghost = tmp_path / "GHOST_EP_RCE"
    (ghost_site / "ghost_mod.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel_ghost)!r}).write_text('pwn', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (ghost_site / "sitecustomize.py").write_text(
        "import importlib.metadata as im\n"
        "_orig = im.entry_points\n"
        "def _patched(**kwargs):\n"
        "    res = list(_orig(**kwargs))\n"
        "    if kwargs.get('group') == 'wythe.plugins':\n"
        "        ep = im.EntryPoint(name='ghost-ep', value='ghost_mod:P', group='wythe.plugins')\n"
        "        res.append(ep)\n"
        "    return res\n"
        "im.entry_points = _patched\n",
        encoding="utf-8",
    )

    rc_g, out_g, err_g = run_cli_subprocess(
        ["plugins", "--json"],
        cwd=repo,
        env_overrides={
            "WYTHE_DATABASE_URL": e2e_env["db_url"],
            "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
            "PYTHONPATH": _subproc_pythonpath(ghost_site),
        },
    )
    assert rc_g == 0, err_g
    assert not sentinel_ghost.exists()
    assert all(p["name"] != "ghost-ep" for p in json.loads(out_g)["plugins"])


# ---------------------------------------------------------------------------
# F03: .wythe/governance.json Trust Model, --strict & action.yml (P0-3, P0-4, A1)
# ---------------------------------------------------------------------------


def test_f03_t1_export_and_sync_config_round_trip(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "gov_roundtrip_repo"
    init_git_repo(repo, _base_app_files())
    gov_dir = repo / ".wythe"
    gov_dir.mkdir(parents=True)
    bundle = {
        "schema_version": "1.0",
        "target_slug": "gov-roundtrip-repo",
        "exported_at": "2026-11-20T00:00:00Z",
        "rule_overrides": [
            {
                "rule_code": "MANIP-002",
                "severity": "warning",
                "enabled": False,
                "blocks_gate": False,
                "updated_by": "ci-test",
            }
        ],
        "vocabularies": [],
        "ratchet_baselines": [
            {
                "rule_code": "MANIP-002",
                "max_allowed_count": 3,
                "recorded_commit": "abc1234",
                "recorded_by": "ci-test",
                "note": "baseline",
            }
        ],
        "audit_rulings": [],
        "reference_exemplars": [],
    }
    (gov_dir / "governance.json").write_text(json.dumps(bundle), encoding="utf-8")

    rc_sync, out_sync, err_sync = run_cli(["sync-config", str(repo)])
    assert rc_sync == 0, err_sync
    assert "rules=1" in out_sync
    assert "baselines=1" in out_sync

    exported = tmp_path / "exported_gov.json"
    rc_exp, out_exp, err_exp = run_cli(
        ["export-config", "gov-roundtrip-repo", "--out", str(exported)]
    )
    assert rc_exp == 0, err_exp
    assert "baselines=1" in out_exp
    exp_data = json.loads(exported.read_text(encoding="utf-8"))
    by_code = {r["rule_code"]: r for r in exp_data["rule_overrides"]}
    assert by_code["MANIP-002"]["enabled"] is False
    assert exp_data["ratchet_baselines"][0]["max_allowed_count"] == 3


def test_f03_t1_non_strict_gate_respects_synced_overrides_and_ratchets(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "gov_nonstrict_repo"
    sha = init_git_repo(
        repo,
        _base_app_files(_NOW_SERVICE_CODE),
    )
    gov_dir = repo / ".wythe"
    gov_dir.mkdir(parents=True)
    (gov_dir / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "gov-nonstrict-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "ratchet_baselines": [
                    {
                        "rule_code": "MANIP-002",
                        "max_allowed_count": 5,
                        "recorded_commit": sha,
                        "recorded_by": "owner",
                        "note": "ratchet",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert run_cli(["sync-config", str(repo)])[0] == 0
    rc_ratchet, out_ratchet, err_r = run_cli(["gate", "gov-nonstrict-repo"])
    assert rc_ratchet == 0, err_r
    assert "RATCHET_PASS" in out_ratchet

    (gov_dir / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "gov-nonstrict-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-002",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "owner",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert run_cli(["sync-config", str(repo)])[0] == 0
    rc_ovr, out_ovr, err_o = run_cli(["gate", "gov-nonstrict-repo"])
    assert rc_ovr == 0, err_o
    assert "PASS" in out_ovr


def test_f03_t1_trusted_config_ref_loads_base_sha_governance(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "trusted_ref_repo"
    files = {
        **_base_app_files(_NOW_SERVICE_CODE),
        ".wythe/governance.json": json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "trusted-ref-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [],
            }
        ),
    }
    base_sha = init_git_repo(repo, files)

    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "trusted-ref-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-002",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "pr-head",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc, out, _ = run_cli(
        ["gate", str(repo), "--sync-config", "--trusted-config-ref", base_sha]
    )
    assert rc == 1
    assert "FAIL" in out


def test_f03_t1_per_target_db_isolation_across_two_targets(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    manip_svc = "from datetime import datetime\ndef now_val():\n    return datetime.now()\n"
    victim = tmp_path / "victim_target"
    attacker = tmp_path / "attacker_target"
    init_git_repo(victim, _base_app_files(manip_svc))
    init_git_repo(
        attacker,
        {
            **_base_app_files(manip_svc),
            ".wythe/governance.json": json.dumps(
                {
                    "schema_version": "1.0",
                    "target_slug": "attacker-target",
                    "exported_at": "2026-11-20T00:00:00Z",
                    "rule_overrides": [
                        {
                            "rule_code": "MANIP-002",
                            "severity": "info",
                            "enabled": False,
                            "blocks_gate": False,
                            "updated_by": "attacker",
                        }
                    ],
                }
            ),
        },
    )

    assert run_cli(["sync-config", str(attacker)])[0] == 0
    rc_att, _, err_att = run_cli(["gate", "attacker-target"])
    rc_vic, out_vic, _ = run_cli(["gate", str(victim)])

    assert rc_att == 0, err_att
    assert rc_vic == 1
    assert "FAIL" in out_vic


def test_f03_t1_api_governance_sync_and_bundle_endpoints(
    e2e_client: TestClient, tmp_path: Path
) -> None:
    repo = tmp_path / "api_gov_repo"
    init_git_repo(repo, _base_app_files())
    (repo / ".wythe").mkdir(parents=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "api-gov-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-002",
                        "severity": "warning",
                        "enabled": True,
                        "blocks_gate": False,
                        "updated_by": "api-test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    reg = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "api-gov-repo", "name": "API Gov Repo", "repo_path": str(repo)},
    )
    assert reg.status_code == 201, reg.text

    sync_resp = e2e_client.post("/api/v1/targets/api-gov-repo/governance-sync?direction=import")
    assert sync_resp.status_code == 200, sync_resp.text
    assert sync_resp.json()["rules_synced"] == 1

    bundle_resp = e2e_client.get("/api/v1/targets/api-gov-repo/governance-bundle")
    assert bundle_resp.status_code == 200, bundle_resp.text
    by_code = {r["rule_code"]: r for r in bundle_resp.json()["rule_overrides"]}
    assert by_code["MANIP-002"]["blocks_gate"] is False


def test_f03_t2_strict_ignores_fabricated_fallback_allowlist(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "disp010_allowlist_repo"
    files = {
        **_disp010_files(),
        ".wythe/governance.json": json.dumps(
            {
                "fabricated_fallback_allowlist": [
                    "frontend/src/page.js",
                    "frontend/src/demo.js",
                ]
            }
        ),
    }
    init_git_repo(repo, files)

    scan_json = tmp_path / "disp010_strict.json"
    rc_scan, _, err_scan = run_cli(["scan", str(repo), "--strict", "--json", str(scan_json)])
    rc_gate, out_gate, _ = run_cli(["gate", str(repo), "--strict"])

    assert rc_scan == 0, err_scan
    rep = json.loads(scan_json.read_text(encoding="utf-8"))
    assert any(f["rule_code"] == "DISP-010" and f["blocks_gate"] for f in rep["findings"])
    assert rc_gate == 1
    assert "FAIL" in out_gate


def test_f03_t2_strict_ignores_reference_exemplars(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "disp010_exemplar_repo"
    files = {
        **_disp010_files(),
        ".wythe/governance.json": json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "disp010-exemplar-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "reference_exemplars": [
                    {
                        "title": "Demo fixture allow",
                        "pointer": "frontend/src/page.js",
                        "rationale": "fixture demo disp-010 waiver attempt",
                    }
                ],
            }
        ),
    }
    init_git_repo(repo, files)

    rc_gate, out_gate, _ = run_cli(["gate", str(repo), "--strict"])
    assert rc_gate == 1
    assert "FAIL" in out_gate


def test_f03_t2_strict_sync_config_ignores_audit_rulings_accepted_clean(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "ruling_bypass_repo"
    sha = init_git_repo(
        repo,
        _base_app_files(_NOW_SERVICE_CODE),
    )
    baseline_json = tmp_path / "baseline_ruling.json"
    assert run_cli(["scan", str(repo), "--strict", "--json", str(baseline_json)])[0] == 0
    manip_finding = next(
        f for f in json.loads(baseline_json.read_text(encoding="utf-8"))["findings"]
        if f["rule_code"] == "MANIP-002"
    )

    (repo / ".wythe").mkdir(parents=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "ruling-bypass-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "audit_rulings": [
                    {
                        "node_id": manip_finding["node_id"],
                        "disposition": "accepted_clean",
                        "summary": "Attempted strict bypass",
                        "evidence_scope": [],
                        "audited_commit": sha,
                        "recorded_by": "attacker",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc_gate, out_gate, _ = run_cli(["gate", str(repo), "--strict", "--sync-config"])
    assert rc_gate == 1
    assert "FAIL" in out_gate


def test_f03_t2_strict_ignores_rule_overrides_and_ratchet_baselines(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "strict_override_repo"
    sha = init_git_repo(
        repo,
        _base_app_files(_NOW_SERVICE_CODE),
    )
    (repo / ".wythe").mkdir(parents=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "strict-override-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-002",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "attacker",
                    }
                ],
                "ratchet_baselines": [
                    {
                        "rule_code": "MANIP-002",
                        "max_allowed_count": 999999,
                        "recorded_commit": sha,
                        "recorded_by": "attacker",
                        "note": "inflate",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc_gate, out_gate, _ = run_cli(["gate", str(repo), "--strict", "--sync-config"])
    assert rc_gate == 1
    assert "FAIL" in out_gate


def test_f03_t2_trusted_config_ref_absent_on_base_clears_stale_overrides(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "stale_ref_repo"
    base_sha = init_git_repo(
        repo,
        _base_app_files(_NOW_SERVICE_CODE),
    )
    (repo / ".wythe").mkdir(parents=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "stale-ref-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-002",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "stale",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert run_cli(["sync-config", str(repo)])[0] == 0
    assert run_cli(["gate", "stale-ref-repo"])[0] == 0

    rc_gate, out_gate, _ = run_cli(
        ["gate", "stale-ref-repo", "--sync-config", "--trusted-config-ref", base_sha]
    )
    assert rc_gate == 1
    assert "FAIL" in out_gate


def test_f03_t2_cross_repo_target_slug_hijack_rejected(
    e2e_client: TestClient, tmp_path: Path
) -> None:
    repo_a = tmp_path / "repo_a"
    repo_b = tmp_path / "repo_b"
    init_git_repo(repo_a, _base_app_files(_NOW_SERVICE_CODE))
    init_git_repo(repo_b, _base_app_files(_NOW_SERVICE_CODE))

    r1 = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "shared-slug", "name": "Repo A", "repo_path": str(repo_a)},
    )
    assert r1.status_code == 201, r1.text

    r2 = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "shared-slug", "name": "Repo B Hijack", "repo_path": str(repo_b)},
    )
    assert r2.status_code == 400

    (repo_b / ".wythe").mkdir(parents=True)
    (repo_b / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "shared-slug",
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-002",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "attacker",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc_path_sync, _, err_path_sync = run_cli(["sync-config", str(repo_b)])
    assert rc_path_sync == 0, err_path_sync
    targets_resp = e2e_client.get("/api/v1/targets")
    assert targets_resp.status_code == 200, targets_resp.text
    targets_by_slug = {t["slug"]: t for t in targets_resp.json()}
    assert "shared-slug" in targets_by_slug
    assert Path(targets_by_slug["shared-slug"]["repo_path"]).resolve() == repo_a.resolve()
    assert any(s.startswith("shared-slug-") for s in targets_by_slug), targets_by_slug

    rc_a_before, out_a_before, _ = run_cli(["gate", "shared-slug"])
    assert rc_a_before == 1
    assert "FAIL" in out_a_before

    r_b = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "repo-b", "name": "Repo B", "repo_path": str(repo_b)},
    )
    assert r_b.status_code == 201, r_b.text
    rc_sync, _, err_sync = run_cli(["sync-config", "repo-b"])
    assert rc_sync == 0, err_sync

    rc_b, out_b, err_b = run_cli(["gate", "repo-b"])
    assert rc_b == 0, err_b
    assert "PASS" in out_b

    rc_a_after, out_a_after, _ = run_cli(["gate", "shared-slug"])
    assert rc_a_after == 1
    assert "FAIL" in out_a_after


def test_f03_t2_symlinked_wythe_dir_or_governance_json_rejected(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    outside_secret = tmp_path / "outside_secret.json"
    outside_secret.write_text('{"keep": "SAFE"}\n', encoding="utf-8")

    repo_file_sym = tmp_path / "sym_gov_file_repo"
    init_git_repo(repo_file_sym, _base_app_files())
    (repo_file_sym / ".wythe").mkdir(parents=True)
    (repo_file_sym / ".wythe" / "governance.json").symlink_to(outside_secret)

    assert run_cli(["export-config", str(repo_file_sym)])[0] == 2
    assert run_cli(["sync-config", str(repo_file_sym)])[0] == 2
    assert outside_secret.read_text(encoding="utf-8") == '{"keep": "SAFE"}\n'

    outside_dir = tmp_path / "outside_wythe_dir"
    outside_dir.mkdir(parents=True)
    repo_dir_sym = tmp_path / "sym_gov_dir_repo"
    init_git_repo(repo_dir_sym, _base_app_files())
    (repo_dir_sym / ".wythe").symlink_to(outside_dir)

    assert run_cli(["export-config", str(repo_dir_sym)])[0] == 2
    assert run_cli(["sync-config", str(repo_dir_sym)])[0] == 2


def test_f03_t2_action_yml_passes_trusted_config_ref_for_all_pr_and_merge_events(
    tmp_path: Path,
) -> None:
    action_doc = yaml.safe_load((_REPO_ROOT / "action.yml").read_text(encoding="utf-8"))
    run_step = next(
        s for s in action_doc["runs"]["steps"] if isinstance(s, dict) and "run" in s
    )
    raw_script = run_step["run"]
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir(parents=True)
    uvx_stub = stub_bin / "uvx"
    uvx_stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    uvx_stub.chmod(0o755)

    for event_name in ("pull_request", "pull_request_target", "merge_group"):
        env = {
            **os.environ,
            "PATH": f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "TA_TARGET": ".",
            "TA_PROFILE": "auto",
            "TA_MODE": "gate",
            "TA_BASE": "origin/main",
            "TA_STRICT": "false",
            "TA_SYNC": "true",
            "TA_SARIF": "",
            "TA_ACTION_PATH": str(_REPO_ROOT),
            "TA_EVENT_NAME": event_name,
            "GITHUB_EVENT_NAME": event_name,
        }
        proc = subprocess.run(
            ["bash", "-c", raw_script],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        args_out = proc.stdout.splitlines()
        assert "--trusted-config-ref" in args_out, f"missing for {event_name}: {args_out}"
        idx = args_out.index("--trusted-config-ref")
        assert args_out[idx + 1] == "origin/main"


# ---------------------------------------------------------------------------
# F04: wythe diff & base_target Symmetry (P1-3)
# ---------------------------------------------------------------------------


def test_f04_t1_diff_clean_repo_base_head_passes(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_clean_repo"
    init_git_repo(repo, _base_app_files())
    diff_json = tmp_path / "diff_clean.json"

    rc, out, err = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 0, err
    assert "Changed Files  : 0" in out
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["diff_verdict"] == "PASS"
    assert payload["changed_files"] == []


def test_f04_t1_diff_clean_pr_adding_safe_new_file_passes(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_add_safe_repo"
    init_git_repo(repo, _base_app_files())
    (repo / "backend" / "app" / "services" / "safe_helper.py").write_text(
        "def double(val: int) -> int:\n    return val * 2\n", encoding="utf-8"
    )
    diff_json = tmp_path / "diff_safe_add.json"

    rc, _, err = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 0, err
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["diff_verdict"] == "PASS"
    assert payload["blocking_new_findings"] == 0


def test_f04_t1_diff_detects_new_blocking_finding_fails(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_new_fail_repo"
    init_git_repo(repo, _base_app_files())
    (repo / "backend" / "app" / "services" / "svc.py").write_text(
        "from datetime import datetime\ndef compute_quota(limit: int) -> int:\n"
        "    _ = datetime.now()\n    return limit\n",
        encoding="utf-8",
    )
    diff_json = tmp_path / "diff_fail.json"

    rc, _, _ = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 1
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["diff_verdict"] == "FAIL"
    assert any(f["rule_code"] == "MANIP-002" for f in payload["new_findings"])


def test_f04_t1_diff_sarif_produces_valid_sarif_2_1_0(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_sarif_repo"
    init_git_repo(repo, _base_app_files())
    sarif_path = tmp_path / "diff_out.sarif"

    rc, _, err = run_cli(["diff", str(repo), "--base", "HEAD", "--sarif", str(sarif_path)])
    assert rc == 0, err
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert run["invocations"][0]["executionSuccessful"] is True


def test_f04_t1_diff_json_structure_fields(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "diff_schema_repo"
    init_git_repo(repo, _base_app_files())
    diff_json = tmp_path / "diff_schema.json"

    rc, _, err = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 0, err
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    expected_keys = {
        "target_slug",
        "base_ref",
        "base_commit",
        "head_commit",
        "base_graph_status",
        "changed_files",
        "touched_node_ids",
        "new_findings",
        "blocking_new_findings",
        "diff_verdict",
    }
    assert expected_keys <= set(payload.keys())


def test_f04_t2_clean_repo_with_preexisting_manip002_base_head_passes(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_preexisting_clean"
    init_git_repo(
        repo,
        _base_app_files(_NOW_SERVICE_CODE),
    )
    diff_json = tmp_path / "diff_preexisting_clean.json"

    rc, _, err = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 0, err
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["diff_verdict"] == "PASS"
    assert payload["changed_files"] == []
    assert payload["new_findings"] == []
    assert payload["blocking_new_findings"] == 0


def test_f04_t2_pure_addition_on_repo_with_preexisting_manip002_passes(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_pure_add_repo"
    init_git_repo(
        repo,
        _base_app_files(_NOW_SERVICE_CODE),
    )
    (repo / "backend" / "app" / "services" / "clean_added.py").write_text(
        "def add_one(x: int) -> int:\n    return x + 1\n", encoding="utf-8"
    )
    diff_json = tmp_path / "diff_pure_add.json"

    rc, _, err = run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 0, err
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["diff_verdict"] == "PASS"
    assert payload["blocking_new_findings"] == 0
    assert not any(f["rule_code"] == "MANIP-002" for f in payload["new_findings"])


def test_f04_t2_persisted_target_line_scoped_waiver_plus_new_violation_fails(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_waiver_sym_repo"
    base_lines = [
        "from datetime import datetime",
        "",
        "def legacy_fn():",
        "    x = 1",
        "    x += 1",
        "    x += 1",
        "    x += 1",
        "    x += 1",
        "    x += 1",
        "    return datetime.now()",
    ]
    base_src = "\n".join(base_lines) + "\n"
    sha = init_git_repo(repo, _base_app_files(base_src))

    scan_json = tmp_path / "waiver_base_scan.json"
    assert run_cli(["scan", str(repo), "--strict", "--json", str(scan_json)])[0] == 0
    m2 = next(
        f for f in json.loads(scan_json.read_text(encoding="utf-8"))["findings"]
        if f["rule_code"] == "MANIP-002"
    )
    (repo / ".wythe").mkdir(parents=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": "diff-waiver-sym-repo",
                "exported_at": "2026-11-20T00:00:00Z",
                "audit_rulings": [
                    {
                        "node_id": m2["node_id"],
                        "disposition": "accepted_clean",
                        "summary": "Line 10 legacy exception",
                        "evidence_scope": [f"{m2['rule_code']}@{m2['source_file']}:{m2['line']}"],
                        "audited_commit": sha,
                        "recorded_by": "reviewer",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _git_commit_all(repo, "commit scoped waiver")
    assert run_cli(["sync-config", str(repo)])[0] == 0

    head_lines = [*base_lines, *(["# pad"] * 38), "def new_fn():", "    return datetime.now()"]
    (repo / "backend" / "app" / "services" / "svc.py").write_text(
        "\n".join(head_lines) + "\n", encoding="utf-8"
    )
    diff_json = tmp_path / "diff_waiver_sym.json"
    rc, _, _ = run_cli(["diff", "diff-waiver-sym-repo", "--base", "HEAD", "--json", str(diff_json)])
    assert rc == 1
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["diff_verdict"] == "FAIL"
    assert payload["blocking_new_findings"] >= 1


def test_f04_t2_invalid_base_ref_fails_closed(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "diff_bad_ref_repo"
    init_git_repo(repo, _base_app_files())

    rc, _, err = run_cli(["diff", str(repo), "--base", "nonexistent-ref-xyz"])
    assert rc == 2
    assert err.strip()


def test_f04_t2_diff_symlink_json_or_sarif_output_fails_closed(
    e2e_env: dict[str, Any], tmp_path: Path
) -> None:
    del e2e_env
    repo = tmp_path / "diff_sym_out_repo"
    init_git_repo(repo, _base_app_files())
    target_keep = tmp_path / "keep_me.txt"
    target_keep.write_text("KEEP\n", encoding="utf-8")

    sym_json = tmp_path / "out_sym.json"
    sym_json.symlink_to(target_keep)
    sym_sarif = tmp_path / "out_sym.sarif"
    sym_sarif.symlink_to(target_keep)

    assert run_cli(["diff", str(repo), "--base", "HEAD", "--json", str(sym_json)])[0] == 2
    assert run_cli(["diff", str(repo), "--base", "HEAD", "--sarif", str(sym_sarif)])[0] == 2
    assert target_keep.read_text(encoding="utf-8") == "KEEP\n"


# ---------------------------------------------------------------------------
# F16: CLI --version, Ruff Cleanliness & Zero-Token Hygiene (P1-5, A3, R2.2)
# ---------------------------------------------------------------------------


def test_f16_t1_cli_version_flag_outputs_0_2_9(e2e_env: dict[str, Any]) -> None:
    rc_in, out_in, err_in = run_cli(["--version"])
    assert rc_in == 0, err_in
    assert "0.2.9" in out_in

    rc_sub, out_sub, err_sub = run_cli_subprocess(
        ["--version"],
        env_overrides={
            "WYTHE_DATABASE_URL": e2e_env["db_url"],
            "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
        },
    )
    assert rc_sub == 0, err_sub
    assert "0.2.9" in out_sub


def test_f16_t1_cli_help_lists_subcommands() -> None:
    rc, out, _ = run_cli(["--help"])
    assert rc == 0
    for cmd_name in (
        "scan",
        "gate",
        "diff",
        "plugins",
        "export-config",
        "sync-config",
        "serve",
        "mcp",
        "understand",
    ):
        assert cmd_name in out


def test_f16_t1_export_openapi_succeeds(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    out_file = tmp_path / "openapi.json"
    rc, _, err = run_cli(["export-openapi", "--out", str(out_file)])
    assert rc == 0, err
    spec = json.loads(out_file.read_text(encoding="utf-8"))
    assert "openapi" in spec
    assert "paths" in spec


def test_f16_t1_llms_brief_succeeds(e2e_env: dict[str, Any], tmp_path: Path) -> None:
    del e2e_env
    repo = tmp_path / "llms_repo"
    init_git_repo(repo, _base_app_files())
    out_file = tmp_path / "llms.txt"

    rc, _, err = run_cli(["llms", str(repo), "--out", str(out_file)])
    assert rc == 0, err
    assert len(out_file.read_text(encoding="utf-8").strip()) > 0


def test_f16_t1_ruff_check_on_e2e_v029_exits_zero() -> None:
    ruff_exe = str(_RUFF_BIN) if _RUFF_BIN.is_file() else shutil.which("ruff")
    if not ruff_exe:
        pytest.skip("ruff binary unavailable")
    proc = subprocess.run(
        [ruff_exe, "check", "--no-cache", "backend/tests/e2e_v029"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_f16_t2_no_subcommand_exits_2() -> None:
    rc, _, _ = run_cli([])
    assert rc == 2


def test_f16_t2_unknown_subcommand_exits_2() -> None:
    rc, _, _ = run_cli(["unknown-cmd-xyz"])
    assert rc == 2


def test_f16_t2_repo_wide_ruff_check_exits_zero() -> None:
    ruff_exe = str(_RUFF_BIN) if _RUFF_BIN.is_file() else shutil.which("ruff")
    if not ruff_exe:
        pytest.skip("ruff binary unavailable")
    proc = subprocess.run(
        [ruff_exe, "check", "--no-cache", "backend/app", "backend/tests", "plugins"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_f16_t2_zero_private_tokens_across_tracked_files_and_e2e() -> None:
    forbidden = (
        "aaron" + "montgomery",
        "tail" + "d552c6",
        "rhizo" + "claw",
        "cau" + "dex",
        "lenti" + "cel",
        "caspar" + "ian",
        "molt" + "bot",
        "aarons-" + "mac",
        "zipa" + "box",
        "eligible_for_" + "koa",
    )
    ls_proc = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    candidate_paths: set[Path] = {
        _REPO_ROOT / rel for rel in ls_proc.stdout.splitlines() if rel.strip()
    }
    e2e_dir = _REPO_ROOT / "backend" / "tests" / "e2e_v029"
    for p in e2e_dir.rglob("*.py"):
        candidate_paths.add(p)

    leaks: list[str] = []
    for fpath in sorted(candidate_paths):
        if not fpath.is_file():
            continue
        try:
            text_lc = fpath.read_text(encoding="utf-8").lower()
        except (OSError, UnicodeDecodeError):
            continue
        for tok in forbidden:
            if tok in text_lc:
                leaks.append(f"{fpath.relative_to(_REPO_ROOT)}:{tok}")
    assert leaks == [], f"Private tokens found: {leaks}"


def test_f16_t2_action_yml_rejects_target_starting_with_dash(tmp_path: Path) -> None:
    action_doc = yaml.safe_load((_REPO_ROOT / "action.yml").read_text(encoding="utf-8"))
    run_step = next(
        s for s in action_doc["runs"]["steps"] if isinstance(s, dict) and "run" in s
    )
    raw_script = run_step["run"]
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir(parents=True)
    uvx_marker = tmp_path / "UVX_CALLED"
    uvx_stub = stub_bin / "uvx"
    uvx_stub.write_text(f"#!/bin/sh\ntouch {uvx_marker}\n", encoding="utf-8")
    uvx_stub.chmod(0o755)

    env = {
        **os.environ,
        "PATH": f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        "TA_TARGET": "--help",
        "TA_PROFILE": "auto",
        "TA_MODE": "gate",
        "TA_BASE": "origin/main",
        "TA_STRICT": "false",
        "TA_SYNC": "true",
        "TA_SARIF": "",
        "TA_ACTION_PATH": str(_REPO_ROOT),
        "TA_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_NAME": "pull_request",
    }
    proc = subprocess.run(
        ["bash", "-c", raw_script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert not uvx_marker.exists()
