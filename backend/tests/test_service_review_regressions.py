"""Reproduce service graph review findings against the released 0.1.5 behavior."""

from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path

import pytest

from app.adapters.base import TruthExtractionResult
from app.adapters.python_services import PythonServicesAdapter


def put(root: Path, rel: str, text: str):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def scan(root):
    return PythonServicesAdapter().extract(root, ".", TruthExtractionResult([], {}, {}))


def test_shell_wrapper_uses_declared_install_destination(tmp_path):
    put(tmp_path, "scripts/sys/job.py", "pass\n")
    put(
        tmp_path,
        "installer.py",
        """from pathlib import Path
class File:
    repo_path: str
    live_path: Path
FILES = [File('scripts/sys/job.py', Path('/opt/example/worker.py'))]
""",
    )
    put(tmp_path, "scripts/run.sh", "exec python3 /opt/example/worker.py\n")
    result = scan(tmp_path)
    assert any(
        e.source_id == "m:script:scripts/run.sh" and e.target_id == "m:script:scripts/sys/job.py"
        for e in result.edges
    )


@pytest.mark.parametrize("dirname", ["config", "configs"])
def test_symlinked_registry_root_is_never_read(tmp_path, dirname, monkeypatch):
    root = tmp_path / "repo"
    put(root, "scripts/job.py", "pass\n")
    external = tmp_path / "installed"
    secret = put(external, "private.json", '{"command": "scripts/job.py"}')
    (root / dirname).symlink_to(external, target_is_directory=True)
    original = Path.read_text
    attempts = []

    def guarded_read(path, *args, **kwargs):
        if path.resolve() == secret.resolve():
            attempts.append(str(path))
            raise AssertionError("installed configuration must not be read")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    result = scan(root)
    assert not attempts
    assert not any(n.id.startswith("m:registry:") for n in result.nodes)
    assert any("1 directories or links excluded" in n for n in result.notes)


@pytest.mark.parametrize(
    "rel,statement",
    [
        ("pkg/worker.py", "from . import *\n"),
        ("pkg/inner/worker.py", "from .. import *\n"),
    ],
)
def test_relative_wildcard_retains_package_initializer(tmp_path, rel, statement):
    put(tmp_path, "pkg/__init__.py", "from . import helper\n")
    put(tmp_path, "pkg/helper.py", "pass\n")
    put(tmp_path, rel, statement)
    result = scan(tmp_path)
    assert any(
        e.source_id == f"m:script:{rel}" and e.target_id == "m:script:pkg/__init__.py"
        for e in result.edges
    )


def test_argument_only_edit_is_visible_in_diff(tmp_path, isolated_db_url):
    from app.cli import _resolve_cli_target
    from app.db.session import get_session_factory
    from app.services.diff_and_sarif_service import run_target_diff
    from app.services.scanner_service import run_target_scan

    put(tmp_path, "scripts/job.py", "pass\n")
    path = tmp_path / "launchagents/job.plist"
    path.parent.mkdir()
    data = {"Label": "com.example.job", "ProgramArguments": ["/usr/bin/python3", "scripts/job.py"]}
    path.write_bytes(plistlib.dumps(data))
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Example",
            "-c",
            "user.email=user@example.com",
            "commit",
            "-qm",
            "initial",
        ],
        check=True,
    )
    path.write_text(path.read_text().replace("scripts/job.py", "~/scripts/job.py"))
    expected = next(
        i for i, line in enumerate(path.read_text().splitlines(), 1) if "~/scripts/job.py" in line
    )
    with get_session_factory(isolated_db_url)() as session:
        target, _ = _resolve_cli_target(session, str(tmp_path), "python-services")
        current = run_target_scan(session, target, persist_snapshot=False)
        diff = run_target_diff(session, target, current, base_ref="HEAD")
    finding = next(f for f in current.findings if f.rule_code == "MANIP-004")
    assert finding.line == expected
    assert any(f.rule_code == "MANIP-004" for f in diff.new_findings)


@pytest.mark.parametrize(
    "data,marker",
    [
        (
            {"Program": "$HOME/bin/job", "EnvironmentVariables": {"PATH_EXAMPLE": "$HOME/bin/job"}},
            "$HOME/bin/job",
        ),
        ({"ProgramArguments": ["python3", 7]}, "<integer>7</integer>"),
    ],
)
def test_command_warning_points_to_value_not_nested_environment(tmp_path, data, marker):
    put(tmp_path, "scripts/job.py", "pass\n")
    path = tmp_path / "launchagents/job.plist"
    path.parent.mkdir()
    path.write_bytes(plistlib.dumps({"Label": "com.example.job", **data}))
    expected = max(i for i, line in enumerate(path.read_text().splitlines(), 1) if marker in line)
    assert scan(tmp_path).findings[0].line == expected


def test_duplicate_plist_key_locations_follow_last_value(tmp_path):
    put(tmp_path, "scripts/job.py", "pass\n")
    path = put(
        tmp_path,
        "launchagents/job.plist",
        """<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.job</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>scripts/job.py</string></array>
<key>ProgramArguments</key><array>
<string>/usr/bin/python3</string>
<string>~/scripts/job.py</string>
</array></dict></plist>
""",
    )
    expected = next(
        i for i, line in enumerate(path.read_text().splitlines(), 1) if "~/scripts/job.py" in line
    )
    assert scan(tmp_path).findings[0].line == expected
