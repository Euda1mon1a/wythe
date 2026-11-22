"""Shared opaque-box fixtures and helpers for Wythe v0.2.9 E2E tests."""

from __future__ import annotations

import contextlib
import importlib.metadata
import io
import os
import subprocess
import sys
from collections.abc import Generator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.db.session import get_session_factory
from app.main import create_app, initialize_database
from app.services.investigation_service import clear_scan_reuse_cache
from app.services.viewport_service import reset_viewport_bus

_REPO_ROOT = Path(__file__).resolve().parents[3]
_BACKEND_DIR = _REPO_ROOT / "backend"
_PLUGIN_SRC_DIRS = tuple(sorted((_REPO_ROOT / "plugins").glob("*/src")))

for _plugin_src in _PLUGIN_SRC_DIRS:
    if str(_plugin_src) not in sys.path:
        sys.path.insert(0, str(_plugin_src))

PLUGIN_SPECS: dict[str, str] = {
    "agent-discordance": "wythe_plugin_agent_discordance.plugin:PLUGIN_SPEC",
    "agent-harness": "wythe_plugin_agent_harness:register_wythe_plugin",
    "apple-ipc": "wythe_plugin_apple_ipc.plugin:APPLE_IPC_PLUGIN",
    "binary": "wythe_plugin_binary.plugin:BINARY_INSPECTION_PLUGIN",
    "compiler-ir": "wythe_plugin_compiler_ir.plugin:COMPILER_IR_PLUGIN",
    "cpsat": "wythe_plugin_cpsat:register_wythe_plugin",
    "solver-chronicle": "wythe_plugin_solver_chronicle:register_wythe_plugin",
    "solver-internals": "wythe_plugin_solver_internals.plugin:SOLVER_INTERNALS_PLUGIN",
    "wiretap": "wythe_plugin_wiretap.plugin:WIRETAP_PLUGIN",
}
_SPEC_TO_NAME: dict[str, str] = {spec: name for name, spec in PLUGIN_SPECS.items()}


@pytest.fixture
def e2e_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[dict[str, Any], None, None]:
    """Isolate Wythe DB, state directory, host/CORS env vars, and in-process caches."""
    db_file = tmp_path / "wythe_e2e.db"
    db_url = f"sqlite:///{db_file.as_posix()}"
    state_dir = tmp_path / "wythe_state"
    state_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("WYTHE_DATABASE_URL", db_url)
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    for var in (
        "TRUTH_ATLAS_DATABASE_URL",
        "TRUTH_ATLAS_STATE_DIR",
        "WYTHE_ALLOWED_HOSTS",
        "WYTHE_CORS_ORIGINS",
        "TRUTH_ATLAS_CORS_ORIGINS",
    ):
        monkeypatch.delenv(var, raising=False)

    get_session_factory.cache_clear()
    clear_scan_reuse_cache()
    reset_viewport_bus()
    initialize_database(db_url)
    try:
        yield {
            "db_url": db_url,
            "state_dir": state_dir,
            "tmp_path": tmp_path,
        }
    finally:
        clear_scan_reuse_cache()
        get_session_factory.cache_clear()
        reset_viewport_bus()


@pytest.fixture
def e2e_client(e2e_env: dict[str, Any]) -> Generator[TestClient, None, None]:
    """Yield an isolated FastAPI TestClient wired to the per-test environment."""
    del e2e_env
    with TestClient(create_app()) as client:
        yield client


def run_cli(argv: Sequence[str]) -> tuple[int, str, str]:
    """Invoke ``app.cli.main`` in-process and return ``(returncode, stdout, stderr)``."""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        try:
            rc = int(cli_main(list(argv)))
        except SystemExit as exc:
            code = exc.code
            if code is None:
                rc = 0
            elif isinstance(code, int):
                rc = code
            else:
                print(code, file=sys.stderr)
                rc = 1
    return rc, stdout_buf.getvalue(), stderr_buf.getvalue()


def run_cli_subprocess(
    argv: Sequence[str],
    cwd: Path | str | None = None,
    env_overrides: Mapping[str, str | None] | None = None,
    timeout: float = 60.0,
) -> tuple[int, str, str]:
    """Run ``python -m app.cli`` in a subprocess with isolated PYTHONPATH and env."""
    env = os.environ.copy()
    for legacy_var in ("TRUTH_ATLAS_DATABASE_URL", "TRUTH_ATLAS_STATE_DIR"):
        env.pop(legacy_var, None)

    py_paths = [str(_BACKEND_DIR), *(str(p) for p in _PLUGIN_SRC_DIRS)]
    existing_pp = env.get("PYTHONPATH", "")
    if existing_pp:
        py_paths.append(existing_pp)
    env["PYTHONPATH"] = os.pathsep.join(py_paths)

    if env_overrides:
        for key, value in env_overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value

    proc = subprocess.run(
        [sys.executable, "-m", "app.cli", *argv],
        cwd=str(cwd) if cwd is not None else str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def init_git_repo(
    repo_dir: Path | str,
    files: Mapping[str, str],
    commit_msg: str = "init",
) -> str:
    """Create a synthetic git repository with ``files`` committed and return HEAD SHA."""
    repo = Path(repo_dir)
    repo.mkdir(parents=True, exist_ok=True)
    for rel_path, content in files.items():
        target = repo / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def _git(*args: str) -> str:
        res = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()

    _git("init", "-b", "main")
    _git("config", "user.name", "Euda1mon1a")
    _git("config", "user.email", "214782221+Euda1mon1a@users.noreply.github.com")
    _git("config", "commit.gpgsign", "false")
    _git("add", "-A")
    commit_args = ["-c", "commit.gpgsign=false", "commit"]
    if not files:
        commit_args.append("--allow-empty")
    _git(*commit_args, "-m", commit_msg)
    return _git("rev-parse", "HEAD")


def plugin_cli_args(*specs: str) -> list[str]:
    """Return ``--allow-local-plugins --plugin ...`` args for plugins absent from entry points."""
    installed = {ep.name for ep in importlib.metadata.entry_points(group="wythe.plugins")}
    missing_specs: list[str] = []
    for item in specs:
        ep_name = _SPEC_TO_NAME.get(item, item)
        if ep_name not in installed:
            missing_specs.append(PLUGIN_SPECS.get(item, item))
    if not missing_specs:
        return []
    args = ["--allow-local-plugins"]
    for spec in missing_specs:
        args.extend(["--plugin", spec])
    return args
