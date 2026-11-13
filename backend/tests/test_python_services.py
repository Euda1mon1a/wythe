"""Service source graphs must preserve dependencies without pretending to observe runtime."""

from __future__ import annotations

import json
import plistlib
import subprocess
from pathlib import Path

import pytest

from app.adapters.autodetect import detect_repository_stack
from app.adapters.base import TruthExtractionResult
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.service_sources import source_reference
from app.cli import main


def put(root: Path, path: str, text: str) -> Path:
    dest = root / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text)
    return dest


def scan(root: Path):
    return PythonServicesAdapter().extract(root, ".", TruthExtractionResult([], {}, {}))


def plist(root: Path, args=None, **values) -> None:
    path = root / "launchagents/job.plist"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"Label": "com.example.job", **values}
    if args is not None:
        data["ProgramArguments"] = args
    path.write_bytes(plistlib.dumps(data))


def test_script_imports_initializers_and_unknown_state(tmp_path):
    put(
        tmp_path,
        "scripts/main.py",
        "from pkg.worker import run\nif __name__ == '__main__':\n run()\n",
    )
    put(tmp_path, "scripts/pkg/__init__.py", "from . import registration\n")
    put(tmp_path, "scripts/pkg/worker.py", "from . import helper\ndef run(): pass\n")
    put(tmp_path, "scripts/pkg/helper.py", "value = 3\n")
    put(tmp_path, "scripts/pkg/registration.py", "value = 4\n")
    put(tmp_path, "scripts/unused.py", "def useful_idea(): pass\n")
    result = scan(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in result.edges}
    assert ("m:script:scripts/main.py", "m:script:scripts/pkg/__init__.py") in pairs
    assert ("m:script:scripts/main.py", "m:script:scripts/pkg/worker.py") in pairs
    assert ("m:script:scripts/pkg/worker.py", "m:script:scripts/pkg/helper.py") in pairs
    assert ("m:script:scripts/pkg/__init__.py", "m:script:scripts/pkg/registration.py") in pairs
    assert all(e.verification == "declared" for e in result.edges)
    assert not result.findings  # no safe-removal inference from missing callers
    assert any(n.source_file == "scripts/main.py" and n.subkind == "cli" for n in result.nodes)


def test_launchd_and_shell_sources_do_not_execute(tmp_path):
    put(tmp_path, "scripts/job.py", "raise RuntimeError('must not execute')\n")
    put(tmp_path, "scripts/run.sh", "# ignored.py\npython3 job.py\n")
    plist(tmp_path, ["/bin/sh", "-lc", 'exec "$HOME/.example/scripts/run.sh"'])
    result = scan(tmp_path)
    assert {(e.source_id, e.target_id) for e in result.edges} >= {
        ("m:launchd:launchagents/job.plist", "m:script:scripts/run.sh"),
        ("m:script:scripts/run.sh", "m:script:scripts/job.py"),
    }
    assert not result.findings


@pytest.mark.parametrize(
    "args,program,expected",
    [
        (["$HOME/bin/job"], None, True),
        (["/usr/bin/python3", "~/scripts/job.py"], None, True),
        (["/usr/bin/python3", "scripts/job.py", "$HOME/input"], None, False),
        (["$HOME/name", "scripts/job.py"], "/usr/bin/python3", False),
        ("not-an-array", None, True),
        ([], None, True),
    ],
)
def test_launchd_argument_semantics(tmp_path, args, program, expected):
    put(tmp_path, "scripts/job.py", "pass\n")
    plist(tmp_path, args, **({"Program": program} if program else {}))
    assert bool(scan(tmp_path).findings) is expected


def test_exclusions_and_parse_failures_remain_explicit(tmp_path):
    put(
        tmp_path,
        "scripts/ok.py",
        "import broken\nimport importlib\nimportlib.import_module(name)\n",
    )
    put(tmp_path, "scripts/broken.py", "def broken(\n")
    put(tmp_path, "tests/test_hidden.py", "raise RuntimeError('excluded')\n")
    put(tmp_path, "docs/demo.py", "pass\n")
    (tmp_path / "scripts/link.py").symlink_to(tmp_path / "tests/test_hidden.py")
    result = scan(tmp_path)
    assert len(result.nodes) == 2
    assert any(
        n.source_file == "scripts/broken.py" and n.status == "gray_zone" for n in result.nodes
    )
    assert any(e.target_id == "m:script:scripts/broken.py" for e in result.edges)
    assert any("1 dynamic import" in n for n in result.notes)
    assert any("1/2 Python files" in n for n in result.notes)
    assert any("Unparsed source: scripts/broken.py" == n for n in result.notes)


def test_ambiguous_suffixes_do_not_select_one_file():
    paths = {"one/scripts/job.py", "two/scripts/job.py"}
    assert source_reference("/installed/scripts/job.py", "launchagents/job.plist", paths) is None
    assert source_reference("../../scripts/job.py", "launchagents/job.plist", paths) is None


def test_deployment_mapping_connects_renamed_destination_and_disabled_registry(tmp_path):
    put(tmp_path, "scripts/sys/job.py", "pass\n")
    put(
        tmp_path,
        "scripts/install.py",
        """from pathlib import Path
from dataclasses import dataclass
HOME = Path.home()
ROOT = HOME / '.example'
@dataclass
class File:
    repo_path: str
    live_path: Path
FILES = [File('scripts/sys/job.py', ROOT / 'scripts' / 'pa' / 'worker.py')]
raise RuntimeError('the installer must never run')
""",
    )
    plist(tmp_path, ["/usr/bin/python3", "/Users/example/.example/scripts/pa/worker.py"])
    put(
        tmp_path,
        "config/jobs.json",
        json.dumps(
            {
                "jobs": [
                    {
                        "enabled": False,
                        "command": ["python3", "~/.example/scripts/pa/worker.py"],
                    }
                ]
            }
        ),
    )
    result = scan(tmp_path)
    pairs = {(e.source_id, e.target_id) for e in result.edges}
    assert ("m:launchd:launchagents/job.plist", "m:script:scripts/sys/job.py") in pairs
    assert ("m:registry:config/jobs.json", "m:script:scripts/sys/job.py") in pairs
    assert ("m:script:scripts/install.py", "m:script:scripts/sys/job.py") in pairs
    assert any("disabled entries are retained" in n for n in result.notes)


def test_deployment_missing_source_and_dynamic_path_are_distinct(tmp_path):
    put(
        tmp_path,
        "installer.py",
        """from pathlib import Path
class File:
    repo_path: str
    live_path: Path
FILES = [File('scripts/missing.py', Path('/opt/example/job.py')),
         File(source(), target())]
""",
    )
    result = scan(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].rule_code == "MANIP-005"
    assert result.findings[0].line == 5
    assert any("1 unresolved declarations" in n for n in result.notes)


def test_shell_assignment_and_semicolon_do_not_hide_reference(tmp_path):
    put(tmp_path, "scripts/job.py", "pass\n")
    plist(tmp_path, ["/bin/sh", "-c", 'job="$HOME/.example/scripts/job.py"; exec python3 "$job"'])
    result = scan(tmp_path)
    assert any(e.target_id == "m:script:scripts/job.py" for e in result.edges)


def test_malformed_launchd_does_not_abort_remaining_sources(tmp_path):
    put(tmp_path, "scripts/job.py", "pass\n")
    put(tmp_path, "launchagents/broken.plist", "<?xml version='1.0'?><plist><dict>")
    result = scan(tmp_path)
    assert any("Could not parse launchd" in n for n in result.notes)


def test_detector_and_cli_expose_service_coverage(tmp_path, db_session, isolated_db_url, capsys):
    put(tmp_path, "scripts/job.py", "if __name__ == '__main__':\n pass\n")
    plist(tmp_path, ["/usr/bin/python3", "scripts/job.py"])
    detected = detect_repository_stack(db_session, str(tmp_path))
    assert detected.recommended_profile_slug == "python-services"
    output = tmp_path / "report.json"
    assert main(["scan", str(tmp_path), "--json", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["stack_profile_status"] == "experimental"
    assert any("Launchd source coverage: 1" in n for n in report["scan_notes"])
    assert "runtime registration" in capsys.readouterr().out


def test_fastapi_missing_layout_is_not_silent(tmp_path):
    result = PythonFastApiAdapter().extract(tmp_path, ".", TruthExtractionResult([], {}, {}))
    assert any("backend coverage is absent" in n for n in result.notes)


def test_literal_dynamic_imports_retain_local_modules_and_unknown_selectors(tmp_path):
    put(
        tmp_path,
        "scripts/main.py",
        """import importlib as loader
from importlib import import_module as load
loader.import_module('helper')
load('pkg.worker')
__import__('helper')
loader.import_module(name)
""",
    )
    put(tmp_path, "scripts/helper.py", "pass\n")
    put(tmp_path, "scripts/pkg/__init__.py", "pass\n")
    put(tmp_path, "scripts/pkg/worker.py", "pass\n")
    result = scan(tmp_path)
    targets = {e.target_id for e in result.edges if e.source_id == "m:script:scripts/main.py"}
    assert targets == {
        "m:script:scripts/helper.py",
        "m:script:scripts/pkg/__init__.py",
        "m:script:scripts/pkg/worker.py",
    }
    assert any("1 dynamic import" in n for n in result.notes)
    assert len({e.id for e in result.edges}) == len(result.edges)


def test_deleted_script_blast_radius_retains_launchd_parent(tmp_path, isolated_db_url):
    from app.cli import _resolve_cli_target
    from app.db.session import get_session_factory
    from app.services.diff_and_sarif_service import run_target_diff
    from app.services.scanner_service import run_target_scan

    put(tmp_path, "scripts/job.py", "pass\n")
    plist(tmp_path, ["/usr/bin/python3", "scripts/job.py"])
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
    (tmp_path / "scripts/job.py").unlink()
    with get_session_factory(isolated_db_url)() as session:
        target, _ = _resolve_cli_target(session, str(tmp_path), "python-services")
        current = run_target_scan(session, target, persist_snapshot=False)
        report = run_target_diff(session, target, current, base_ref="HEAD")
    assert "m:launchd:launchagents/job.plist" in report.impacted_manipulator_nodes
    assert any(n.source_file == "scripts/job.py" for n in report.removed_nodes)
