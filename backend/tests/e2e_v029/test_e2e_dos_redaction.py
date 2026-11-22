"""Opaque-box E2E tests for Wythe v0.2.9 F14 (DoS bounds) and F15 (redaction & binary plist)."""

from __future__ import annotations

import json
import os
import plistlib
import struct
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from wythe_plugin_wiretap import (
    parse_otel_traces,
    redact_attributes,
    redact_url_target,
)

from .conftest import plugin_cli_args, run_cli

_BASE_MAIN_PY = (
    "from fastapi import FastAPI\n"
    "\n"
    "app = FastAPI()\n"
    "\n"
    "@app.get('/api/health')\n"
    "def health() -> dict[str, bool]:\n"
    "    return {'ok': True}\n"
)


def _write_repo_files(repo: Path, files: Mapping[str, str | bytes]) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    for rel_path, content in files.items():
        target = repo / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return repo


def _build_deep_bplist00(depth: int = 1200) -> bytes:
    """Build a valid binary plist containing a single ``depth``-level nested array."""
    objs = [b"\xA1" + struct.pack(">H", idx + 1) for idx in range(depth)] + [b"\x10\x01"]
    buf = bytearray(b"bplist00")
    offsets: list[int] = []
    for obj in objs:
        offsets.append(len(buf))
        buf.extend(obj)
    off_table_offset = len(buf)
    for off in offsets:
        buf.extend(struct.pack(">H", off))
    trailer = struct.pack(">BBQQQ", 2, 2, len(objs), 0, off_table_offset)
    buf.extend(b"\x00" * 6 + trailer)
    return bytes(buf)


def _scan_repo(
    repo: Path,
    out_json: Path,
    *,
    plugins: tuple[str, ...] = (),
    extra_args: tuple[str, ...] = (),
) -> tuple[int, str, str, float, dict[str, Any]]:
    argv: list[str] = ["scan", str(repo), "--json", str(out_json)]
    if plugins:
        argv.extend(plugin_cli_args(*plugins))
    argv.extend(extra_args)
    t0 = time.perf_counter()
    rc, stdout, stderr = run_cli(argv)
    elapsed = time.perf_counter() - t0
    report = json.loads(out_json.read_text(encoding="utf-8")) if out_json.is_file() else {}
    return rc, stdout, stderr, elapsed, report


def _companion_repo(
    repo: Path,
    out_json: Path,
    *,
    plugins: tuple[str, ...] = (),
    extra_args: tuple[str, ...] = (),
) -> tuple[int, str, str, dict[str, Any]]:
    argv: list[str] = ["companion", str(repo), "--json", str(out_json)]
    if plugins:
        argv.extend(plugin_cli_args(*plugins))
    argv.extend(extra_args)
    rc, stdout, stderr = run_cli(argv)
    payload = json.loads(out_json.read_text(encoding="utf-8")) if out_json.is_file() else {}
    return rc, stdout, stderr, payload


def _clean_sarif_payload() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [
                            {
                                "id": "CVE-2025-0001",
                                "shortDescription": {"text": "Sample dependency vulnerability"},
                                "properties": {"tags": ["vulnerability", "HIGH"]},
                            },
                            {
                                "id": "AVD-DS-0002",
                                "shortDescription": {"text": "Sample container misconfiguration"},
                                "properties": {"tags": ["misconfiguration", "MEDIUM"]},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2025-0001",
                        "level": "error",
                        "message": {"text": "Upgrade sample package to 1.2.3"},
                    },
                    {
                        "ruleId": "AVD-DS-0002",
                        "level": "warning",
                        "message": {"text": "Specify non-root USER in Dockerfile"},
                    },
                ],
            }
        ],
    }


def _clean_trivy_json_payload() -> dict[str, Any]:
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-0002",
                        "PkgName": "fastapi",
                        "Severity": "HIGH",
                        "Title": "Sample vulnerability advisory",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Severity": "MEDIUM",
                        "Status": "FAIL",
                        "Title": "Image user should not be root",
                    }
                ],
            }
        ],
    }


def _clean_otel_payload() -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "orders-api"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "GET /api/health",
                                "attributes": {
                                    "http.method": "GET",
                                    "http.route": "/api/health",
                                    "url.full": "https://service.example.com:8443/api/health",
                                },
                            },
                            {
                                "name": "SELECT items",
                                "attributes": {
                                    "db.system": "postgresql",
                                    "db.operation": "SELECT",
                                    "db.sql.table": "items",
                                    "db.statement": "SELECT id, name FROM items",
                                },
                            },
                        ]
                    }
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# F14 (P1-7): Default-Scan DoS Bounds — Tier 1 (Normal Bounded Inputs)
# ---------------------------------------------------------------------------


def test_f14_tier1_valid_cpsat_solver_scan(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_cpsat_ok",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "backend/app/solver.py": (
                "from ortools.sat.python import cp_model\n"
                "\n"
                "def solve_schedule() -> int:\n"
                "    model = cp_model.CpModel()\n"
                "    shift = model.NewIntVar(0, 10, 'shift')\n"
                "    limit = 2 * 5\n"
                "    model.Add(shift <= limit)\n"
                "    solver = cp_model.CpSolver()\n"
                "    return int(solver.Solve(model))\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(
        repo, tmp_path / "cpsat_ok.json", plugins=("cpsat",)
    )
    assert rc == 0, err
    assert elapsed < 2.0
    assert report["coverage_complete"] is True


def test_f14_tier1_valid_agent_harness_prompt_scan(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_harness_ok",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "backend/app/prompts.py": (
                "SYSTEM_PROMPT = 'You are a concise reviewer.'\n"
                "TASK_PROMPT = SYSTEM_PROMPT + '\\nCheck status.'\n"
                "ALLOWED_TOOLS = ['status_lookup']\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(
        repo, tmp_path / "harness_ok.json", plugins=("agent-harness",)
    )
    assert rc == 0, err
    assert elapsed < 2.0
    assert report["coverage_complete"] is True


def test_f14_tier1_valid_tools_yaml_registry_scan(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_yaml_ok",
        {
            "schema.sql": "CREATE TABLE jobs (id INT PRIMARY KEY);\n",
            "services/worker.py": "def run_job() -> str:\n    return 'done'\n",
            "config/tools.yaml": (
                "tools:\n"
                "  - name: job_runner\n"
                "    command: services/worker.py\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "yaml_ok.json")
    assert rc == 0, err
    assert elapsed < 2.0
    assert report["stack_profile"] == "python-services"
    assert report["coverage_complete"] is True


def test_f14_tier1_valid_dockerfile_and_dockerignore_scan(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_docker_ok",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "Dockerfile": (
                "FROM python:3.12-slim\n"
                "WORKDIR /app\n"
                "COPY backend /app/backend\n"
                'CMD ["python", "/app/backend/app/main.py"]\n'
            ),
            ".dockerignore": "__pycache__/\n*.pyc\n.venv/\n",
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "docker_ok.json")
    assert rc == 0, err
    assert elapsed < 2.0
    assert report["coverage_complete"] is True


def test_f14_tier1_valid_tach_plist_and_ts_scan(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    xml_plist = plistlib.dumps(
        {
            "Label": "com.example.wythe.worker",
            "ProgramArguments": ["/usr/bin/python3", "backend/app/mod.py"],
        },
        fmt=plistlib.FMT_XML,
    )
    repo = _write_repo_files(
        tmp_path / "repo_tach_plist_ts_ok",
        {
            "backend/app/__init__.py": "",
            "backend/app/main.py": _BASE_MAIN_PY,
            "backend/app/mod.py": "VALUE = 42\n",
            "tach.toml": (
                'source_roots = ["backend"]\n'
                'exclude = ["tests/**"]\n'
                "[[modules]]\n"
                'path = "app.mod"\n'
                "depends_on = []\n"
            ),
            "launchd/app.plist": xml_plist,
            "frontend/src/app/page.tsx": (
                "export default function Page() {\n"
                "  const val = ((1 + 2) * (3 + 4));\n"
                "  return <div>{val}</div>;\n"
                "}\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "tach_plist_ts_ok.json")
    assert rc == 0, err
    assert elapsed < 2.0
    assert report["coverage_complete"] is True


# ---------------------------------------------------------------------------
# F14 (P1-7): Default-Scan DoS Bounds — Tier 2 (Adversarial DoS Vectors)
# ---------------------------------------------------------------------------


def test_f14_tier2_dos_cpsat_chained_mult_and_float_overflow(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    chain = "\n".join(f"x{idx} = x{idx - 1} * x{idx - 1}" for idx in range(1, 31))
    repo = _write_repo_files(
        tmp_path / "repo_cpsat_dos",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "backend/app/solver_dos.py": (
                "from ortools.sat.python import cp_model\n"
                "x0 = 2\n"
                f"{chain}\n"
                "overflow_val = int(1e200 * 1e200)\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(
        repo, tmp_path / "cpsat_dos.json", plugins=("cpsat",)
    )
    assert rc == 0, err
    assert elapsed < 3.0
    assert isinstance(report.get("gate"), dict)


def test_f14_tier2_dos_agent_harness_string_doubling(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    doubling = "\n".join(f"s{idx} = s{idx - 1} + s{idx - 1}" for idx in range(1, 26))
    repo = _write_repo_files(
        tmp_path / "repo_harness_dos",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "backend/app/prompts_dos.py": f's0 = "x"\n{doubling}\n',
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(
        repo, tmp_path / "harness_dos.json", plugins=("agent-harness",)
    )
    assert rc == 0, err
    assert elapsed < 3.0
    assert isinstance(report.get("gate"), dict)


def test_f14_tier2_dos_registry_yaml_anchor_dag(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    dag_lines = ['a0: &a0 {command: "echo ok"}']
    for idx in range(1, 26):
        dag_lines.append(f"a{idx}: &a{idx} [*a{idx - 1}, *a{idx - 1}]")
    dag_lines.append("tools: *a25")
    repo = _write_repo_files(
        tmp_path / "repo_yaml_dag_dos",
        {
            "schema.sql": "CREATE TABLE jobs (id INT PRIMARY KEY);\n",
            "services/worker.py": "def run_job() -> str:\n    return 'done'\n",
            "config/tools.yaml": "\n".join(dag_lines) + "\n",
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "yaml_dag_dos.json")
    assert rc == 0, err
    assert elapsed < 3.0
    assert report["stack_profile"] == "python-services"
    assert isinstance(report.get("gate"), dict)


def test_f14_tier2_dos_dockerignore_exponential_glob(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    glob_pattern = ("**/" * 18) + "target.py"
    repo = _write_repo_files(
        tmp_path / "repo_dockerignore_dos",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "Dockerfile": (
                "FROM python:3.12-slim\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                'CMD ["python", "/app/backend/a/b/c/d/e/f/g/h/target.py"]\n'
            ),
            ".dockerignore": f"{glob_pattern}\n",
            "backend/a/b/c/d/e/f/g/h/target.py": "X = 1\n",
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "dockerignore_dos.json")
    assert rc == 0, err
    assert elapsed < 3.0
    assert isinstance(report.get("gate"), dict)


def test_f14_tier2_dos_tach_toml_redos(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    evil_name = ("a" * 26) + "c.py"
    repo = _write_repo_files(
        tmp_path / "repo_tach_redos",
        {
            "backend/app/__init__.py": "",
            "backend/app/main.py": _BASE_MAIN_PY,
            f"backend/app/{evil_name}": "X = 1\n",
            "tach.toml": (
                'source_roots = ["backend"]\n'
                'exclude = ["backend/app/(a+)+b"]\n'
                "[[modules]]\n"
                'path = "app"\n'
                "depends_on = []\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "tach_redos.json")
    assert rc == 0, err
    assert elapsed < 3.0
    assert isinstance(report.get("gate"), dict)


def test_f14_tier2_dos_launchd_deep_bplist00(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_bplist_dos",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "launchd/deep.plist": _build_deep_bplist00(1200),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "bplist_dos.json")
    assert rc == 0, err
    assert elapsed < 3.0
    assert isinstance(report.get("gate"), dict)


def test_f14_tier2_dos_typescript_deep_parentheses(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    deep_expr = ("(" * 1100) + "1" + (")" * 1100)
    repo = _write_repo_files(
        tmp_path / "repo_ts_paren_dos",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "frontend/src/app/page.tsx": (
                "export default function Page() {\n"
                f"  const v = {deep_expr};\n"
                "  return <div>{v}</div>;\n"
                "}\n"
            ),
        },
    )
    rc, _out, err, elapsed, report = _scan_repo(repo, tmp_path / "ts_paren_dos.json")
    assert rc == 0, err
    assert elapsed < 3.0
    assert isinstance(report.get("gate"), dict)


# ---------------------------------------------------------------------------
# F15 (P1-11): Trivy & Wiretap Secret Redaction + Binary `.plist` — Tier 1
# ---------------------------------------------------------------------------


def test_f15_tier1_companion_clean_trivy_sarif(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(tmp_path / "repo_f15_sarif", {"backend/app/main.py": _BASE_MAIN_PY})
    sarif_path = tmp_path / "clean.sarif"
    sarif_path.write_text(json.dumps(_clean_sarif_payload()), encoding="utf-8")

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_sarif.json",
        extra_args=("--trivy-report", str(sarif_path)),
    )
    assert rc == 0, err
    trivy = comp["crate_stage"]["trivy_report"]
    assert trivy["present"] is True
    assert trivy["format"] == "sarif"
    assert trivy["vulnerability_count"] == 1
    assert trivy["misconfiguration_count"] == 1
    assert trivy["secret_count"] == 0


def test_f15_tier1_companion_clean_trivy_json(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(tmp_path / "repo_f15_tjson", {"backend/app/main.py": _BASE_MAIN_PY})
    trivy_path = tmp_path / "clean_trivy.json"
    trivy_path.write_text(json.dumps(_clean_trivy_json_payload()), encoding="utf-8")

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_tjson.json",
        extra_args=("--trivy-report", str(trivy_path)),
    )
    assert rc == 0, err
    trivy = comp["crate_stage"]["trivy_report"]
    assert trivy["present"] is True
    assert trivy["format"] == "trivy-json"
    assert trivy["vulnerability_count"] == 1
    assert trivy["misconfiguration_count"] == 1
    assert trivy["secret_count"] == 0


def test_f15_tier1_companion_clean_otel_and_port_listeners(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(tmp_path / "repo_f15_otel", {"backend/app/main.py": _BASE_MAIN_PY})
    otel_path = tmp_path / "clean_otel.json"
    otel_path.write_text(json.dumps(_clean_otel_payload()), encoding="utf-8")
    lsof_path = tmp_path / "lsof.txt"
    lsof_path.write_text(
        "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        "uvicorn  1234 appu   5u  IPv4    0x1      0t0  TCP 127.0.0.1:8000 (LISTEN)\n",
        encoding="utf-8",
    )

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_otel.json",
        plugins=("wiretap",),
        extra_args=("--otel-traces", str(otel_path), "--port-listeners", str(lsof_path)),
    )
    assert rc == 0, err
    wt = comp["wiretap_companion"]
    assert wt["present"] is True
    assert wt["traces_and_flows"]["transition_count"] >= 2
    assert wt["port_occupancy"]["present"] is True
    assert wt["port_occupancy"]["observed_listener_count"] == 1


def test_f15_tier1_wiretap_public_api_preserves_clean_telemetry(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    cleaned, r_cnt = redact_attributes(
        {
            "http.method": "GET",
            "http.route": "/api/items",
            "db.system": "postgresql",
            "db.operation": "SELECT",
        }
    )
    assert r_cnt == 0
    assert cleaned["http.method"] == "GET"
    assert cleaned["http.route"] == "/api/items"
    assert cleaned["db.system"] == "postgresql"

    clean_path, red_url, was_red = redact_url_target("https://service.example.com:8443/api/items")
    assert clean_path == "/api/items"
    assert red_url == "https://service.example.com:8443/api/items"
    assert was_red is False

    otel_path = tmp_path / "clean_api_otel.json"
    otel_path.write_text(json.dumps(_clean_otel_payload()), encoding="utf-8")
    transitions, total_red = parse_otel_traces(otel_path, allow_external=True)
    assert len(transitions) >= 2
    assert total_red == 0


def test_f15_tier1_scan_with_trivy_and_companion_out(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(tmp_path / "repo_f15_scan", {"backend/app/main.py": _BASE_MAIN_PY})
    sarif_path = tmp_path / "scan_clean.sarif"
    sarif_path.write_text(json.dumps(_clean_sarif_payload()), encoding="utf-8")
    scan_out = tmp_path / "scan_report.json"
    comp_out = tmp_path / "companion_out.json"

    rc, _out, err, _elapsed, report = _scan_repo(
        repo,
        scan_out,
        extra_args=("--trivy-report", str(sarif_path), "--companion-out", str(comp_out)),
    )
    assert rc == 0, err
    assert isinstance(report.get("gate"), dict)
    assert comp_out.is_file()
    comp = json.loads(comp_out.read_text(encoding="utf-8"))
    assert comp["crate_stage"]["trivy_report"]["format"] == "sarif"
    assert comp["crate_stage"]["trivy_report"]["vulnerability_count"] == 1
    assert "non_certification_disclaimer" in comp


# ---------------------------------------------------------------------------
# F15 (P1-11): Trivy & Wiretap Secret Redaction + Binary `.plist` — Tier 2
# ---------------------------------------------------------------------------


def test_f15_tier2_trivy_sarif_secret_redaction(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_f15_sarif_sec",
        {"backend/app/main.py": _BASE_MAIN_PY},
    )
    sarif_path = tmp_path / "secret.sarif"
    sarif_payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy", "rules": []}},
                "results": [
                    {
                        "ruleId": "custom-secret-rule",
                        "level": "error",
                        "properties": {"tags": ["secret", "CRITICAL"]},
                        "message": {"text": f"Secret CUSTOM_LEAK_999\nMatch: {'AKIA' + 'IOSFODNN7EXAMPLE'}"},
                    }
                ],
            }
        ],
    }
    sarif_path.write_text(json.dumps(sarif_payload), encoding="utf-8")

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_sarif_sec.json",
        extra_args=("--trivy-report", str(sarif_path)),
    )
    assert rc == 0, err
    assert comp["crate_stage"]["trivy_report"]["secret_count"] == 1
    serialized = json.dumps(comp)
    assert "CUSTOM_LEAK_999" not in serialized
    fake_aws = f"{'AKIA'}{'IOSFODNN7EXAMPLE'}"
    assert fake_aws not in serialized


def test_f15_tier2_trivy_json_secrets_title_redaction(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(
        tmp_path / "repo_f15_tjson_sec",
        {"backend/app/main.py": _BASE_MAIN_PY},
    )
    trivy_path = tmp_path / "secret_trivy.json"
    trivy_payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "config.py",
                "Secrets": [
                    {
                        "RuleID": "generic-api-key",
                        "Severity": "CRITICAL",
                        "Title": "Exposed credential RAW_TRIVY_SECRET_ABC",
                        "Match": "RAW_TRIVY_SECRET_ABC",
                    }
                ],
            }
        ],
    }
    trivy_path.write_text(json.dumps(trivy_payload), encoding="utf-8")

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_tjson_sec.json",
        extra_args=("--trivy-report", str(trivy_path)),
    )
    assert rc == 0, err
    assert comp["crate_stage"]["trivy_report"]["secret_count"] == 1
    serialized = json.dumps(comp)
    assert "RAW_TRIVY_SECRET_ABC" not in serialized


def test_f15_tier2_trivy_rejects_symlink_oversize_and_non_dict(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(tmp_path / "repo_f15_fail", {"backend/app/main.py": _BASE_MAIN_PY})

    real_trivy = tmp_path / "real_trivy.json"
    real_trivy.write_text(json.dumps(_clean_trivy_json_payload()), encoding="utf-8")
    sym_trivy = tmp_path / "sym_trivy.json"
    os.symlink(real_trivy, sym_trivy)
    rc_sym, _out, _err, _comp = _companion_repo(
        repo,
        tmp_path / "out_sym.json",
        extra_args=("--trivy-report", str(sym_trivy)),
    )
    assert rc_sym == 2

    oversize_trivy = tmp_path / "oversize_trivy.json"
    with oversize_trivy.open("wb") as fh:
        fh.seek(33 * 1024 * 1024)
        fh.write(b"{}")
    rc_big, _out, _err, _comp = _companion_repo(
        repo,
        tmp_path / "out_big.json",
        extra_args=("--trivy-report", str(oversize_trivy)),
    )
    assert rc_big == 2

    non_dict_trivy = tmp_path / "list_trivy.json"
    non_dict_trivy.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    rc_list, _out, _err, _comp = _companion_repo(
        repo,
        tmp_path / "out_list.json",
        extra_args=("--trivy-report", str(non_dict_trivy)),
    )
    assert rc_list == 2


def test_f15_tier2_wiretap_otel_redaction_and_invalid_port(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    repo = _write_repo_files(tmp_path / "repo_f15_wt_sec", {"backend/app/main.py": _BASE_MAIN_PY})
    secret_tokens = (
        "SPAN_NAME_SECRET",
        "MULTILINE_SQL_SECRET",
        "VALUES_LIST_SECRET",
        "RAW_SECRET_TOKEN",
        "BADPORT_SECRET",
    )

    attrs_in = {
        "exception.message": (
            "Query failed:\nSELECT * FROM users\nWHERE pw = 'MULTILINE_SQL_SECRET'"
        ),
        "headers": [{"key": "Authorization", "values": ["VALUES_LIST_SECRET"]}],
        "url.full": "https://api.example.com/v1/x?RAW_SECRET_TOKEN",
        "http.url": "https://api.example.com:badport/v1/x?token=BADPORT_SECRET",
    }
    cleaned_attrs, _cnt = redact_attributes(attrs_in)
    _cp1, red_url_raw, _r1 = redact_url_target("https://api.example.com/v1/x?RAW_SECRET_TOKEN")
    _cp2, red_url_bad, _r2 = redact_url_target(
        "https://api.example.com:badport/v1/x?token=BADPORT_SECRET"
    )
    api_dump = json.dumps({"attrs": cleaned_attrs, "u1": red_url_raw, "u2": red_url_bad})
    for token in secret_tokens[1:]:
        assert token not in api_dump, f"Secret token {token} leaked in public wiretap API"

    otel_payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "auth-api"}}]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "DB SELECT users WHERE pw = 'SPAN_NAME_SECRET'",
                                "attributes": {
                                    "db.system": "postgresql",
                                    "exception.message": attrs_in["exception.message"],
                                    "headers": attrs_in["headers"],
                                    "url.full": attrs_in["url.full"],
                                },
                            },
                            {
                                "name": "HTTP POST",
                                "attributes": {
                                    "http.method": "POST",
                                    "http.url": attrs_in["http.url"],
                                },
                            },
                        ]
                    }
                ],
            }
        ]
    }
    otel_path = tmp_path / "adversarial_otel.json"
    otel_path.write_text(json.dumps(otel_payload), encoding="utf-8")

    transitions, _red_total = parse_otel_traces(otel_path, allow_external=True)
    traces_dump = json.dumps([t.__dict__ for t in transitions], default=str)
    for token in secret_tokens:
        assert token not in traces_dump, f"Secret token {token} leaked in parse_otel_traces"

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_wt_sec.json",
        plugins=("wiretap",),
        extra_args=("--otel-traces", str(otel_path)),
    )
    assert rc == 0, err
    comp_dump = json.dumps(comp)
    for token in secret_tokens:
        assert token not in comp_dump, f"Secret token {token} leaked in companion JSON"


def test_f15_tier2_wiretap_binary_plist_in_repo(e2e_env: dict[str, Any]) -> None:
    tmp_path: Path = e2e_env["tmp_path"]
    bplist_bytes = plistlib.dumps(
        {"Label": "com.example.worker", "ProgramArguments": ["/bin/echo", "ok"]},
        fmt=plistlib.FMT_BINARY,
    )
    assert bplist_bytes.startswith(b"bplist00")
    repo = _write_repo_files(
        tmp_path / "repo_f15_bplist",
        {
            "backend/app/main.py": _BASE_MAIN_PY,
            "launchd/worker.plist": bplist_bytes,
        },
    )
    lsof_path = tmp_path / "lsof_bplist.txt"
    lsof_path.write_text(
        "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        "uvicorn  2345 appu   5u  IPv4    0x1      0t0  TCP 127.0.0.1:8000 (LISTEN)\n",
        encoding="utf-8",
    )

    rc, _out, err, comp = _companion_repo(
        repo,
        tmp_path / "comp_bplist.json",
        plugins=("wiretap",),
        extra_args=("--port-listeners", str(lsof_path)),
    )
    assert rc == 0, err
    assert comp["wiretap_companion"]["present"] is True
