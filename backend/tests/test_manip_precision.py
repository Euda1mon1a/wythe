"""Manipulation-tier precision: policy tokens on name segments, and every naive host clock."""

from __future__ import annotations

from pathlib import Path

from app.adapters.base import TruthExtractionResult
from app.adapters.python_ast_inspect import ParsedPythonModule, parse_python_module
from app.adapters.python_fastapi import PythonFastApiAdapter

_EMPTY_TRUTH = TruthExtractionResult(
    nodes=[], table_symbol_map={}, function_symbol_map={}, findings=[], observation_source="static_ast"
)


def _parse(tmp_path: Path, source: str) -> ParsedPythonModule:
    parsed = parse_python_module(source, "backend/app/services/mod.py", "app.services.mod")
    assert parsed is not None
    return parsed


def test_policy_tokens_match_whole_name_segments(tmp_path: Path) -> None:
    pm = _parse(
        tmp_path,
        "EXPORT_DURATION_HOURS = 2\n"
        "SOLVER_MAX_ITERATIONS = 200\n"
        "JOB_GENERATION_ID = 7\n"
        "REVIEW_RATIO = 0.5\n"
        "TEAM_RATIOS = 3\n"
        "LATE_PENALTIES = 4\n"
        "ACTIVITY_CODES = ('A', 'B', 'C')\n"
        "CODES = ('A', 'B', 'C')\n",
    )
    flagged = {name for name, _line, _sample in pm.policy_literals}
    assert flagged == {"REVIEW_RATIO", "TEAM_RATIOS", "LATE_PENALTIES", "ACTIVITY_CODES"}


def test_every_naive_host_clock_is_seen_through_aliases(tmp_path: Path) -> None:
    pm = _parse(
        tmp_path,
        "import datetime as dt\n"
        "from dataclasses import dataclass, field\n"
        "from datetime import UTC, date as d, datetime\n"
        "from functools import partial\n"
        "def a():\n    return d.today()\n"
        "def b():\n    return dt.datetime.now()\n"
        "def c():\n    return datetime.now(tz=None)\n"
        "def e(ts):\n    return datetime.fromtimestamp(ts)\n"
        "def f():\n    return datetime.today()\n"
        "def g():\n    return dt.date.today()\n"
        "@dataclass\n"
        "class R:\n"
        "    at: datetime = field(default_factory=datetime.now)\n"
        "def ok():\n"
        "    return (\n"
        "        datetime.now(UTC),\n"
        "        datetime.now(tz=UTC),\n"
        "        datetime.fromtimestamp(0, UTC),\n"
        "        partial(datetime.now, UTC),\n"
        "    )\n",
    )
    lines = sorted(line for _expr, line in pm.raw_clock_calls)
    assert lines == [6, 8, 10, 12, 14, 16, 19], pm.raw_clock_calls


def test_other_modules_named_date_are_not_the_stdlib_clock(tmp_path: Path) -> None:
    pm = _parse(
        tmp_path,
        "from pendulum import date\n"
        "def a():\n    return date.today()\n",
    )
    assert pm.raw_clock_calls == ()


def test_clock_authority_is_exempt_by_file_name_not_suffix(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    services = repo / "backend" / "app" / "services"
    services.mkdir(parents=True)
    (services / "stopclock.py").write_text("from datetime import date\ndef lap():\n    return date.today()\n")
    (services / "clock.py").write_text("from datetime import date\ndef today():\n    return date.today()\n")
    res = PythonFastApiAdapter().extract(repo, "backend", _EMPTY_TRUTH)
    hits = sorted(f.source_file for f in res.findings if f.rule_code == "MANIP-002")
    assert hits == ["backend/app/services/stopclock.py"]
