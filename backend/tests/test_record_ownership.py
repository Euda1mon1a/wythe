"""Ownership evidence stays separate from actual, state-checked regression results."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import socket
from pathlib import Path

import pytest

from app.adapters.python_ownership import inspect_ownership_source
from app.cli import main as cli_main
from app.services.ownership_service import inspect_record_ownership, read_ownership_source
from wythe_examples import ownership_repaired, ownership_vulnerable
from wythe_examples.ownership_lab import run_example, run_ownership_demo

EXAMPLES = Path(ownership_repaired.__file__).parent


def inspect(source: str):
    return inspect_ownership_source(
        source, source_file="routes.py", handler="update_record", record="record",
        principal="user.id", owner_field="owner_id",
    )


def test_same_regression_fails_before_repair_and_passes_after() -> None:
    report = run_ownership_demo()
    assert report.regression_passed
    assert report.before.invariant_result == "violated"
    assert report.after.invariant_result == "holds_for_tested_cases"
    assert len(report.before.cases) == len(report.after.cases) == 8
    failed = [c for c in report.before.cases if not c.passed]
    assert {c.name for c in failed} == {"user_2_cannot_update_1", "user_1_cannot_update_2"}
    for case in failed:
        assert case.observed_status == 200
        assert case.observed_records != case.expected_records
    assert all(c.passed for c in report.after.cases)
    assert report.before.source_evidence.invariant_result == "unknown"
    assert report.after.source_evidence.invariant_result == "unknown"
    assert report.source_hashes["ownership_repaired.py"] == hashlib.sha256(
        Path(ownership_repaired.__file__).read_bytes()
    ).hexdigest()


def test_repair_changes_only_the_ownership_rejection() -> None:
    before = ast.parse(Path(ownership_vulnerable.__file__).read_text())
    after = ast.parse(Path(ownership_repaired.__file__).read_text())
    # Ignore module docstrings; the repair is the only executable difference.
    before.body.pop(0)
    after.body.pop(0)
    handler = next(n for n in after.body if isinstance(n, ast.FunctionDef))
    guard = handler.body.pop(2)
    assert isinstance(guard, ast.If)
    assert ast.unparse(guard.test) == "record.owner_id != user.id"
    assert ast.dump(before) == ast.dump(after)


def test_state_check_detects_write_even_when_handler_returns_forbidden(monkeypatch) -> None:
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient

    from wythe_examples import ownership_lab
    from wythe_examples.ownership_common import Record

    original = ownership_lab.example_client
    from contextlib import contextmanager

    @contextmanager
    def misleading_client(variant):
        with original(variant) as (_, factory):
            application = FastAPI()

            @application.patch("/records/{record_id}")
            def mutate_then_reject(record_id: int):
                with factory() as db:
                    record = db.get(Record, record_id)
                    if record is not None:
                        record.title = "Changed despite 403"
                        db.commit()
                raise HTTPException(status_code=403)

            with TestClient(application) as client:
                yield client, factory

    monkeypatch.setattr(ownership_lab, "example_client", misleading_client)
    report = run_example("repaired")
    case = next(c for c in report.cases if c.name == "user_2_cannot_update_1")
    assert case.observed_status == case.expected_status == 403
    assert not case.passed
    assert report.invariant_result == "violated"


def test_source_maps_declared_boundary_without_asserting_enforcement() -> None:
    report = inspect_record_ownership(
        EXAMPLES, handler="ownership_repaired.py:update_record", record="record",
        principal="user.id", owner_field="owner_id",
    )
    kinds = {e.kind for e in report.evidence}
    assert kinds == {"route", "dependency", "record_lookup", "record_write",
                     "persistence_call", "owner_comparison", "ownership_rejection"}
    evidence = {e.kind: e for e in report.evidence}
    assert evidence["record_lookup"].line < evidence["ownership_rejection"].line
    assert evidence["ownership_rejection"].line < evidence["record_write"].line
    assert evidence["persistence_call"].expression == "db.commit()"
    assert report.invariant_result == "unknown"
    assert not report.target_code_executed and not report.target_database_contacted
    assert any("guard dominance" in note for note in report.unknowns)


def test_import_aliases_and_annotated_async_session() -> None:
    source = '''
from fastapi import APIRouter as Router, Depends as Inject, HTTPException as Reject
from typing import Annotated
from sqlalchemy.ext.asyncio import AsyncSession as DB
router = Router()
@router.patch("/records/{record_id}")
async def update_record(record_id, user=Inject(current_user), db: Annotated[DB, Inject(session)]=None):
    record = await db.get(Record, record_id)
    if user.id != record.owner_id:
        raise Reject(404)
    record.title = "Changed"
    await db.commit()
'''
    report = inspect(source)
    assert len([e for e in report.evidence if e.kind == "dependency"]) == 2
    assert any(e.kind == "record_lookup" for e in report.evidence)
    assert any(e.kind == "ownership_rejection" for e in report.evidence)
    assert report.invariant_result == "unknown"


@pytest.mark.parametrize("guard", [
    "if record.owner_id == user.id:\n        raise HTTPException(403)",
    "if other.owner_id != user.id:\n        raise HTTPException(403)",
    "if record.owner_id != user.id:\n        log_warning()",
    "if record.owner_id != user.id:\n        raise HTTPException(500)",
    "if record.owner_id != user.id or bypass:\n        raise HTTPException(403)",
])
def test_other_comparisons_are_not_ownership_rejections(guard: str) -> None:
    source = "from fastapi import HTTPException\ndef update_record():\n    " + guard + "\n"
    report = inspect(source)
    assert not any(e.kind == "ownership_rejection" for e in report.evidence)
    assert report.invariant_result == "unknown"


def test_inactive_and_conditional_checks_remain_distinct_and_nested_defs_are_excluded() -> None:
    report = inspect('''
from fastapi import HTTPException
def update_record():
    def never_called():
        record.title = "Hidden write"
    if False:
        if record.owner_id != user.id:
            raise HTTPException(403)
    if flag:
        if record.owner_id != user.id:
            raise HTTPException(403)
    record.title = "Visible write"
''')
    guards = [e for e in report.evidence if e.kind == "ownership_rejection"]
    assert [e.placement for e in guards] == ["inactive", "conditional"]
    writes = [e for e in report.evidence if e.kind == "record_write"]
    assert len(writes) == 1 and "Visible write" in writes[0].expression
    assert report.invariant_result == "unknown"


def test_missing_checks_and_unsupported_lookups_are_unknown_not_vulnerabilities() -> None:
    report = inspect('''
def update_record():
    record = repository.fetch_one()
    record.title = "Changed"
    repository.save(record)
''')
    assert not any(e.kind == "record_lookup" for e in report.evidence)
    assert any("No supported active Session.get" in note for note in report.unknowns)
    assert any("No supported active ownership rejection" in note for note in report.unknowns)
    assert report.invariant_result == "unknown"


@pytest.mark.parametrize("condition", ["False", "None", "0", "''"])
def test_literal_dead_guard_is_retained_as_inactive(condition) -> None:
    report = inspect(
        "from fastapi import HTTPException\ndef update_record():\n"
        f"    if {condition}:\n        if record.owner_id != user.id:\n"
        "            raise HTTPException(403)\n"
    )
    guards = [e for e in report.evidence if e.kind == "ownership_rejection"]
    assert len(guards) == 1 and guards[0].placement == "inactive"
    assert any("No supported active ownership rejection" in n for n in report.unknowns)


def test_scan_never_imports_target_or_initializes_wythe_database(tmp_path, monkeypatch, capsys) -> None:
    marker = tmp_path / "executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\ndef update_record():\n    pass\n"
    (tmp_path / "routes.py").write_text(source)

    def forbidden(*args, **kwargs):
        pytest.fail("Static ownership evidence must not execute a target or initialize a database")

    monkeypatch.setattr("app.cli.initialize_database", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    code = cli_main(["security", "ownership", str(tmp_path), "--handler", "routes.py:update_record",
                     "--record", "record", "--principal", "user.id"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["invariant_result"] == "unknown"
    assert not marker.exists()
    assert {p.name for p in tmp_path.iterdir()} == {"routes.py"}


@pytest.mark.parametrize("relative", ["../outside.py", "/outside.py", "nested/../../outside.py", "routes.txt"])
def test_source_path_must_stay_under_the_selected_root(tmp_path, relative) -> None:
    with pytest.raises(ValueError):
        read_ownership_source(tmp_path, relative)


def test_source_symlinks_directories_fifos_and_oversized_files_are_refused(tmp_path) -> None:
    (tmp_path / "real.py").write_text("pass\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    (tmp_path / "directory.py").mkdir()
    (tmp_path / "parent").symlink_to(tmp_path, target_is_directory=True)
    (tmp_path / "large.py").write_bytes(b" " * 1_048_577)
    os.mkfifo(tmp_path / "pipe.py")
    for relative in ("link.py", "directory.py", "parent/real.py", "large.py", "pipe.py"):
        with pytest.raises((ValueError, OSError)):
            read_ownership_source(tmp_path, relative)


def test_hash_is_of_exact_bytes_with_declared_python_encoding(tmp_path) -> None:
    data = b'# coding: latin-1\n# caf\xe9\ndef update_record():\n    pass\n'
    (tmp_path / "routes.py").write_bytes(data)
    report = inspect_record_ownership(
        tmp_path, handler="routes.py:update_record", record="record",
        principal="user.id", owner_field="owner_id",
    )
    assert report.source_sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("source", ["def update_record(:", "def other(): pass",
                                       "def update_record(): pass\ndef update_record(): pass"])
def test_invalid_or_ambiguous_handlers_are_errors(source) -> None:
    with pytest.raises((ValueError, SyntaxError)):
        inspect(source)


@pytest.mark.parametrize("principal", ["user.id()", "user['id']", "record.owner_id", "user.id or bypass"])
def test_selector_is_data_not_code(principal) -> None:
    with pytest.raises(ValueError):
        inspect_ownership_source(
            "def update_record(): pass", source_file="routes.py", handler="update_record",
            record="record", principal=principal, owner_field="owner_id",
        )


def test_cli_errors_do_not_create_or_overwrite_evidence(tmp_path, capsys) -> None:
    output = tmp_path / "receipt.json"
    output.write_text("Keep existing evidence\n")
    common = ["security", "ownership", str(EXAMPLES), "--record", "record", "--principal", "user.id"]
    assert cli_main([*common, "--handler", "missing.py:update_record"]) == 2
    assert cli_main([*common, "--handler", "ownership_repaired.py:update_record", "--json", str(output)]) == 2
    assert output.read_text() == "Keep existing evidence\n"
    assert "security error" in capsys.readouterr().err


def test_demo_cli_has_no_target_argument_and_uses_no_network(tmp_path, monkeypatch, capsys) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("The shipped example must not open network connections or initialize Wythe state")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr("app.cli.initialize_database", forbidden)
    output = tmp_path / "demo.json"
    assert cli_main(["security", "ownership-demo", "--json", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report == json.loads(capsys.readouterr().out)
    assert report["regression_passed"]
    with pytest.raises(SystemExit) as error:
        cli_main(["security", "ownership-demo", str(tmp_path)])
    assert error.value.code == 2


def test_broken_repair_makes_demo_exit_nonzero(monkeypatch, capsys) -> None:
    from wythe_examples import ownership_lab
    original = ownership_lab.run_example
    monkeypatch.setattr(ownership_lab, "run_example", lambda variant: original("vulnerable"))
    assert cli_main(["security", "ownership-demo"]) == 1
    assert not json.loads(capsys.readouterr().out)["regression_passed"]
