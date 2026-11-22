"""Real Git + CLI regressions for removal evidence and fail-closed base handling."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.git_diff import collect_git_changes, materialize_base_tree


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "user@example.com",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "user@example.com"}
    return subprocess.check_output(["git", *args], cwd=repo, env=env, text=True).strip()


def _commit(repo: Path) -> str:
    _git(repo, "add", ".")
    tree = _git(repo, "write-tree")
    # Synthetic fixture snapshots use plumbing; no product branch or hook is changed.
    sha = _git(repo, "commit-tree", tree, "-m", "synthetic fixture")
    _git(repo, "update-ref", "HEAD", sha)
    return sha


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    files = {
        "backend/schema.sql": "CREATE TABLE widgets (id INTEGER PRIMARY KEY);\n",
        "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "frontend/src/app/page.tsx": (
            "import dynamic from 'next/dynamic';\n"
            "const Active = dynamic(() => import('../widgets').then(m => m.Active));\n"
            "export default function Page() { return <Active/>; }\n"
        ),
        "frontend/src/widgets/index.ts": (
            "export { Active } from './active';\n"
            "export { Unused } from './unused';\n"
            "export { registered } from './registration';\n"
        ),
        "frontend/src/widgets/active.tsx": "export function Active() { return <div/>; }\n",
        "frontend/src/widgets/unused.tsx": "export function Unused() { return <span/>; }\n",
        "frontend/src/widgets/registration.ts": "export const registered = register();\n",
        ".gitattributes": "frontend/src/widgets/active.tsx export-ignore\n",
    }
    for name, contents in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    _git(root, "init", "-q")
    _commit(root)
    return root


def _cli(repo: Path, tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess, dict]:
    output = tmp_path / "diff.json"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
           "WYTHE_DATABASE_URL": f"sqlite:///{tmp_path / 'state.db'}"}
    proc = subprocess.run(
        [sys.executable, "-m", "app.cli", "diff", str(repo), "--base", "HEAD",
         "--json", str(output), *extra], check=False, env=env, capture_output=True, text=True, timeout=30,
    )
    return proc, json.loads(output.read_text()) if output.exists() else {}


@pytest.mark.parametrize("module,has_page", [("active.tsx", True), ("unused.tsx", False),
                                             ("registration.ts", True)])
def test_deleted_component_retains_old_callers_and_eager_effects(
    repo: Path, tmp_path: Path, module: str, has_page: bool,
) -> None:
    source = f"frontend/src/widgets/{module}"
    (repo / source).unlink()
    proc, result = _cli(repo, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert result["changed_files"] == [source]
    assert result["base_commit"] == _git(repo, "rev-parse", "HEAD")
    assert result["base_graph_status"] == "available"
    assert any(n["source_file"] == source for n in result["removed_nodes"])
    assert any(n.startswith("d:page:") for n in result["base_impacted_node_ids"]) is has_page
    assert "not proof of safe deletion" in proc.stdout


def test_rename_and_deletion_only_hunk_keep_both_sides(repo: Path, tmp_path: Path) -> None:
    old = "frontend/src/widgets/active.tsx"
    new = "frontend/src/widgets/renamed.tsx"
    _git(repo, "mv", old, new)
    path = repo / "frontend/src/app/page.tsx"
    path.write_text(path.read_text().replace("const Active =", "const Changed ="))
    proc, result = _cli(repo, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert {old, new} <= set(result["changed_files"])
    assert any(n["source_file"] == old for n in result["removed_nodes"])
    assert any(n.endswith("widgets.renamed") for n in result["touched_node_ids"])
    # Removing a line without adding a replacement still has base-side ranges.
    path.write_text("\n".join(path.read_text().splitlines()[1:]) + "\n")
    changes = collect_git_changes(repo, "HEAD")
    assert changes.before["frontend/src/app/page.tsx"]


def test_invalid_base_is_rejected_not_replaced_with_head(repo: Path, tmp_path: Path) -> None:
    proc, result = _cli(repo, tmp_path, "--base", "does-not-exist")
    assert proc.returncode == 2
    assert not result
    assert "Cannot read Git evidence" in proc.stderr


def test_unavailable_before_image_is_explicit_in_json_and_sarif(repo: Path, tmp_path: Path) -> None:
    (repo / "link").symlink_to("frontend")
    _commit(repo)
    (repo / "frontend/src/widgets/active.tsx").unlink()
    sarif = tmp_path / "result.sarif"
    proc, result = _cli(repo, tmp_path, "--sarif", str(sarif))
    assert proc.returncode == 2, proc.stderr
    assert result["diff_verdict"] == "INCOMPLETE"
    assert result["base_graph_status"] == "unavailable"
    assert any("symlink" in note for note in result["analysis_notes"])
    run = json.loads(sarif.read_text())["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["properties"]["diffVerdict"] == "INCOMPLETE"


def test_raw_paths_and_exact_base_materialization(repo: Path, tmp_path: Path) -> None:
    name = 'odd \t"café.ts'
    (repo / name).write_text("one\ntwo\n")
    sha = _commit(repo)
    (repo / name).unlink()
    changes = collect_git_changes(repo, "HEAD")
    assert changes.before[name] == [(1, 2)]
    assert name not in changes.after
    destination = tmp_path / "snapshot"
    destination.mkdir()
    materialize_base_tree(repo, sha, destination)
    assert (destination / name).read_text() == "one\ntwo\n"
    assert (destination / "frontend/src/widgets/active.tsx").is_file()  # export-ignore


def test_untracked_names_are_preserved_and_unknown_base_cannot_pass(repo: Path) -> None:
    name = "new\tfile.ts"
    (repo / name).write_text("export const x = 1;\n")
    assert name in collect_git_changes(repo, "WORKING").after
    with pytest.raises(ValueError):
        collect_git_changes(repo, "--no-index")


def test_binary_diff_attributes_cannot_hide_changed_code(repo: Path) -> None:
    attrs = repo / ".gitattributes"
    attrs.write_text(attrs.read_text() + "frontend/src/widgets/unused.tsx -diff\n")
    _commit(repo)
    (repo / "frontend/src/widgets/unused.tsx").write_text("export const WORKLOAD_CAP = 80;\n")
    assert collect_git_changes(repo, "HEAD").after["frontend/src/widgets/unused.tsx"] == [(1, 1_000_000)]


def test_issue_99_intra_repo_relative_file_symlinks_succeed_while_escaping_fail_closed(
    repo: Path,
    tmp_path: Path,
) -> None:
    """Issue #99: intra-repo relative file symlinks (`120000`) materialize safely; escaping/dangling fail closed."""
    target_script = repo / "scripts" / "sys" / "cli_entry.swift"
    target_script.parent.mkdir(parents=True, exist_ok=True)
    target_script.write_text("struct AppCLIMain {}\n", encoding="utf-8")

    xcode_link = repo / "xcode" / "AppCLI" / "Sources" / "main.swift"
    xcode_link.parent.mkdir(parents=True, exist_ok=True)
    xcode_link.symlink_to("../../../scripts/sys/cli_entry.swift")

    chained_link = repo / "xcode" / "AppCLI" / "alias.swift"
    chained_link.symlink_to("Sources/main.swift")
    sha = _commit(repo)

    snap = tmp_path / "snap_ok"
    snap.mkdir()
    materialize_base_tree(repo, sha, snap)
    mat_file = snap / "xcode" / "AppCLI" / "Sources" / "main.swift"
    assert mat_file.is_file() and not mat_file.is_symlink()
    assert mat_file.read_text(encoding="utf-8") == "struct AppCLIMain {}\n"
    assert (snap / "xcode" / "AppCLI" / "alias.swift").read_text(encoding="utf-8") == (
        "struct AppCLIMain {}\n"
    )

    (repo / "frontend/src/widgets/unused.tsx").unlink()
    proc, result = _cli(repo, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert result["base_graph_status"] == "available"
    assert result["diff_verdict"] == "PASS"

    for bad_name, bad_target in (
        ("escape_bounce.swift", "../../outside/../app/scripts/sys/cli_entry.swift"),
        ("abs_link.swift", "/etc/hosts"),
        ("dangling.swift", "scripts/sys/does_not_exist.swift"),
    ):
        sub_repo = tmp_path / f"bad_{bad_name}"
        subprocess.run(["cp", "-R", str(repo), str(sub_repo)], check=True)
        (sub_repo / bad_name).symlink_to(bad_target)
        bad_sha = _commit(sub_repo)
        bad_dest = tmp_path / f"dest_{bad_name}"
        bad_dest.mkdir()
        with pytest.raises(ValueError, match="unresolved symlink or submodule"):
            materialize_base_tree(sub_repo, bad_sha, bad_dest)
