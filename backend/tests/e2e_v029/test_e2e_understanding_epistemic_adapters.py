"""Opaque-box E2E tests for Wythe v0.2.9 (F09, F11, F12, F13)."""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from tests.e2e_v029.conftest import init_git_repo, plugin_cli_args, run_cli
from wythe_plugin_agent_discordance import evaluate_agent_discordance


def _write_files(root: Path, files: dict[str, str]) -> None:
    for rel_path, content in files.items():
        fp = root / rel_path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")


def _scan_json(
    repo: Path,
    out_path: Path,
    *,
    profile: str = "auto",
    strict: bool = False,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    argv = ["scan", str(repo), "--profile", profile, "--json", str(out_path)]
    if strict:
        argv.append("--strict")
    if extra_args:
        argv.extend(extra_args)
    rc, _stdout, stderr = run_cli(argv)
    assert rc == 0, f"wythe scan failed (rc={rc}): {stderr}"
    return json.loads(out_path.read_text(encoding="utf-8"))


def _gate_strict(
    repo: Path,
    *,
    profile: str = "auto",
    extra_args: list[str] | None = None,
) -> tuple[int, str, str]:
    argv = ["gate", str(repo), "--profile", profile, "--strict"]
    if extra_args:
        argv.extend(extra_args)
    return run_cli(argv)


def _mcp_call(
    client: TestClient,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    req_id: int = 1,
) -> dict[str, Any]:
    resp = client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _finding_codes(report: dict[str, Any]) -> set[str]:
    return {str(f.get("rule_code")) for f in report.get("findings") or []}


# ---------------------------------------------------------------------------
# F09 (P1-2): Understanding Chain (#104) & Agent Discordance (#117)
# ---------------------------------------------------------------------------


def test_f09_t1_http_understanding_examples_and_detail(e2e_client: TestClient) -> None:
    """F09 Tier 1: List shipped understanding examples and fetch example detail over HTTP."""
    list_resp = e2e_client.get("/api/v1/understanding/examples")
    assert list_resp.status_code == 200, list_resp.text
    summaries = list_resp.json()
    slugs = {item["slug"] for item in summaries}
    assert {"schedule-policy-to-export", "assistant-context-to-delivery"} <= slugs

    detail_resp = e2e_client.get("/api/v1/understanding/examples/schedule-policy-to-export")
    assert detail_resp.status_code == 200, detail_resp.text
    detail = detail_resp.json()
    assert detail["summary"]["slug"] == "schedule-policy-to-export"
    assert len(detail["baseline_report"]["links"]) == 6
    assert len(detail["candidate_report"]["links"]) == 6
    assert len(detail["walkthrough_steps"]) >= 1

    missing_resp = e2e_client.get("/api/v1/understanding/examples/no-such-example-slug")
    assert missing_resp.status_code == 404


def test_f09_t1_http_analyze_valid_bundle(e2e_client: TestClient) -> None:
    """F09 Tier 1: Analyze an inline bundle via POST /api/v1/understanding/analyze."""
    bundle = {
        "question": "Did the notification settle and render to the owner?",
        "outcome_lifecycles": [
            {
                "outcome_id": "out-clean-1",
                "current_stage": "delivered_to_human",
                "authoritative_terminal_state": "committed",
                "settlement_digest": "dig-clean-1",
                "answer_grounding": "grounded",
                "delivery_status": "delivered",
                "delivery_receipt": "rcpt-str-001",
            }
        ],
        "verdict_clauses": [
            {
                "clause_id": "clause-1",
                "text": "Notification was delivered cleanly.",
                "evidence_ref": "sdk:delivery-001",
                "state": "supported",
            }
        ],
    }
    resp = e2e_client.post(
        "/api/v1/understanding/analyze",
        json={"bundle": bundle},
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["links"]) == 6
    assert data["outcome_lifecycles"][0]["positive_delivery_established"] is True
    assert data["verdict_clauses"][0]["state"] == "supported"
    assert "[Notification was delivered cleanly.](#evidence:sdk:delivery-001)" in data["verdict_markdown"]


def test_f09_t1_cli_understand_example_json(e2e_env: dict[str, Any]) -> None:
    """F09 Tier 1: `wythe understand --example ... --json` exits 0 with valid JSON."""
    del e2e_env
    rc, stdout, stderr = run_cli(
        ["understand", "--example", "schedule-policy-to-export", "--json"]
    )
    assert rc == 0, stderr
    parsed = json.loads(stdout)
    assert parsed["example_slug"] == "schedule-policy-to-export"
    assert len(parsed["links"]) == 6
    assert len(parsed["outcome_lifecycles"]) >= 1


def test_f09_t1_mcp_explain_understanding_and_alias(e2e_client: TestClient) -> None:
    """F09 Tier 1: MCP `wythe_investigation` and `wythe_understanding` explain succeed."""
    res_inv = _mcp_call(
        e2e_client,
        "wythe_investigation",
        {
            "action": "explain_understanding",
            "example_slug": "assistant-context-to-delivery",
        },
        req_id=10,
    )
    inv_result = res_inv["result"]
    assert inv_result["isError"] is False
    inv_text = inv_result["content"][0]["text"]
    assert "assistant-context-to-delivery" in inv_text
    assert "## Six-Link Chain" in inv_text

    res_alias = _mcp_call(
        e2e_client,
        "wythe_understanding",
        {
            "action": "explain_understanding",
            "example_slug": "schedule-policy-to-export",
        },
        req_id=11,
    )
    alias_result = res_alias["result"]
    assert alias_result["isError"] is False
    alias_text = alias_result["content"][0]["text"]
    assert "schedule-policy-to-export" in alias_text
    assert "## Six-Link Chain" in alias_text


def test_f09_t1_agent_discordance_clean_manifest_passes(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F09 Tier 1: Clean agent_routes & agent_receipts emit zero DISC violations."""
    del e2e_env
    repo = tmp_path / "disc_clean"
    manifest = {
        "routes": [
            {
                "route_id": "owner_text",
                "agent_id": "primary_agent",
                "principal_scope": "owner",
                "continuity_group": "owner_grp",
                "expected_policy_version": "pol-v1",
                "canary_task_id": "canary-01",
            },
            {
                "route_id": "owner_voice",
                "agent_id": "primary_agent",
                "principal_scope": "owner",
                "continuity_group": "owner_grp",
                "expected_policy_version": "pol-v1",
                "canary_task_id": "canary-01",
            },
        ]
    }
    receipts = {
        "observations": [
            {
                "route_id": "owner_text",
                "observed_agent_id": "primary_agent",
                "observed_policy_version": "pol-v1",
                "caller_receipt_id": "rcpt-c1",
                "authz_receipt_id": "rcpt-a1",
                "canary_recovered": True,
            },
            {
                "route_id": "owner_voice",
                "observed_agent_id": "primary_agent",
                "observed_policy_version": "pol-v1",
                "caller_receipt_id": "rcpt-c2",
                "authz_receipt_id": "rcpt-a2",
                "canary_recovered": True,
            },
        ]
    }
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            ".wythe/agent_routes.json": json.dumps(manifest),
            ".wythe/agent_receipts.json": json.dumps(receipts),
        },
    )
    out = tmp_path / "disc_clean.json"
    rep = _scan_json(repo, out, extra_args=plugin_cli_args("agent-discordance"))
    assert "DISC-001" not in _finding_codes(rep)
    assert "DISC-002" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo, extra_args=plugin_cli_args("agent-discordance"))
    assert rc == 0, stderr

    eval_report = evaluate_agent_discordance(manifest, receipts)
    assert eval_report.violations == []
    assert eval_report.supported_routes == ["owner_text", "owner_voice"]


def test_f09_t2_positive_dict_delivery_receipt_http_and_cli(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """F09 Tier 2: Positive dict delivery_receipt succeeds (200 / CLI exit 0, no TypeError)."""
    bundle = {
        "question": "Verify dict delivery_receipt succeeds",
        "outcome_lifecycles": [
            {
                "outcome_id": "out-dict-ok",
                "current_stage": "delivered_to_human",
                "authoritative_terminal_state": "committed",
                "settlement_digest": "dig-dict-ok",
                "answer_grounding": "grounded",
                "delivery_status": "delivered",
                "delivery_receipt": {"id": "rcpt-123"},
            }
        ],
    }
    resp = e2e_client.post(
        "/api/v1/understanding/analyze",
        json={"bundle": bundle},
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    report = resp.json()
    assert report["outcome_lifecycles"][0]["positive_delivery_established"] is True
    links = {lnk["link_key"]: lnk["state"] for lnk in report["links"]}
    assert links["human_visible_result"] == "supported"

    bundle_file = tmp_path / "dict_receipt_bundle.json"
    bundle_file.write_text(json.dumps(bundle), encoding="utf-8")
    rc, stdout, stderr = run_cli(["understand", "--bundle", str(bundle_file), "--json"])
    assert rc == 0, stderr
    cli_report = json.loads(stdout)
    assert cli_report["outcome_lifecycles"][0]["positive_delivery_established"] is True


def test_f09_t2_nested_failure_dict_delivery_receipt_rejected(e2e_client: TestClient) -> None:
    """F09 Tier 2: Nested failure dict inside delivery_receipt rejects positive delivery."""
    bundle = {
        "question": "Verify nested failure delivery_receipt is rejected",
        "outcome_lifecycles": [
            {
                "outcome_id": "out-dict-fail",
                "current_stage": "delivered_to_human",
                "authoritative_terminal_state": "committed",
                "settlement_digest": "dig-dict-fail",
                "answer_grounding": "grounded",
                "delivery_status": "delivered",
                "delivery_receipt": {
                    "id": "r1",
                    "detail": {"status": "failed", "delivered": False},
                },
            }
        ],
    }
    resp = e2e_client.post(
        "/api/v1/understanding/analyze",
        json={"bundle": bundle},
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    report = resp.json()
    out = report["outcome_lifecycles"][0]
    assert out["positive_delivery_established"] is False
    assert "positive_human_delivery_receipt" in out["missing_joins"]
    links = {lnk["link_key"]: lnk["state"] for lnk in report["links"]}
    assert links["human_visible_result"] != "supported"


def test_f09_t2_markdown_link_injection_in_verdict_clauses_neutralized(
    e2e_client: TestClient,
) -> None:
    """F09 Tier 2: Markdown link injection via clause_id / missing_receipt is neutralized."""
    bundle = {
        "question": "Verify verdict_markdown neutralizes link injection",
        "verdict_clauses": [
            {
                "clause_id": "x)[click](javascript:alert(1))(",
                "text": "Escape trailing backslash\\]",
                "state": "supported",
            },
            {
                "clause_id": "c2",
                "text": "Missing receipt injection",
                "missing_receipt": "m)[evil](javascript:alert(2))(",
                "state": "supported",
            },
        ],
    }
    resp = e2e_client.post(
        "/api/v1/understanding/analyze",
        json={"bundle": bundle},
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    md = resp.json()["verdict_markdown"]
    assert "javascript:" not in md.lower()
    assert ")[click](" not in md
    assert ")[evil](" not in md
    assert "\\\\\\]" in md


def test_f09_t2_perturbation_matrix_contradiction_flagged_failed(
    e2e_client: TestClient,
) -> None:
    """F09 Tier 2: Contradictory perturbation with passed=True flags failed_regression."""
    bundle = {
        "question": "Verify perturbation_matrix flags contradictory outcomes even when passed=True",
        "perturbation_matrix": [
            {
                "case_id": "p-contradict",
                "label": "Isolation perturbation",
                "varied_factor": "channel",
                "held_fixed": ["policy_version"],
                "expected_outcome": "blocked",
                "observed_outcome": "leaked",
                "passed": True,
                "decisive_receipt_ref": "sdk:rcpt-p1",
            }
        ],
    }
    resp = e2e_client.post(
        "/api/v1/understanding/analyze",
        json={"bundle": bundle},
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    pcase = resp.json()["perturbation_matrix"][0]
    assert pcase["passed"] is False
    assert pcase["conclusion_state"] == "failed_regression"


def test_f09_t2_agent_discordance_string_bool_bypass_emits_disc002(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F09 Tier 2: String bools ('false'/'true') bypass check emits DISC-002."""
    del e2e_env
    repo = tmp_path / "disc_bypass"
    manifest = {
        "routes": [
            {
                "route_id": "owner_route",
                "agent_id": "primary_agent",
                "principal_scope": "owner",
                "continuity_group": "owner_grp",
                "canary_task_id": "task-unauthorized-99",
            },
            {
                "route_id": "sandbox_route",
                "agent_id": "sandbox_runner",
                "principal_scope": "owner",
                "explicit_privacy_boundary": "false",
                "isolated_from_agents": ["primary_agent"],
            },
        ]
    }
    receipts = {
        "observations": [
            {
                "route_id": "owner_route",
                "observed_agent_id": "primary_agent",
                "caller_receipt_id": "rcpt-c1",
                "authz_receipt_id": "rcpt-a1",
                "canary_recovered": True,
            },
            {
                "route_id": "sandbox_route",
                "observed_agent_id": "sandbox_runner",
                "caller_receipt_id": "rcpt-c2",
                "authz_receipt_id": "rcpt-a2",
                "accessed_task_id": "task-unauthorized-99",
                "unauthorized_task": True,
                "canary_recovered": "true",
            },
        ]
    }
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            ".wythe/agent_routes.json": json.dumps(manifest),
            ".wythe/agent_receipts.json": json.dumps(receipts),
        },
    )
    out = tmp_path / "disc_bypass.json"
    rep = _scan_json(repo, out, extra_args=plugin_cli_args("agent-discordance"))
    assert "DISC-002" in _finding_codes(rep)
    rc, _stdout, _stderr = _gate_strict(repo, extra_args=plugin_cli_args("agent-discordance"))
    assert rc == 1


def test_f09_t2_http_unrooted_bundle_path_returns_422(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """F09 Tier 2: Unrooted bundle_path without target_slug returns 422 over HTTP."""
    bundle_file = tmp_path / "unrooted.json"
    bundle_file.write_text(json.dumps({"question": "unrooted"}), encoding="utf-8")
    for bad_path in (str(bundle_file), "/etc/passwd", "../outside.json"):
        resp = e2e_client.post(
            "/api/v1/understanding/analyze",
            json={"bundle_path": bad_path},
            headers={"X-Wythe-Client": "1"},
        )
        assert resp.status_code == 422, f"Expected 422 for {bad_path}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# F11 (P1-4): Cross-Tier Route Matching (`DYNAMIC` fetch, HEAD/OPTIONS, Daemon)
# ---------------------------------------------------------------------------


def test_f11_t1_fastapi_nextjs_get_post_matching_passes_strict(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 1: Matching FastAPI + Next.js GET/POST routes pass `wythe gate --strict`."""
    del e2e_env
    repo = tmp_path / "f11_get_post"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE orders (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/orders')\n"
                "def list_orders(): return []\n"
                "@app.post('/api/orders')\n"
                "def create_order(): return {'id': 1}\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Page() {\n"
                "  void fetch('/api/orders');\n"
                "  void fetch('/api/orders', { method: 'POST' });\n"
                "  return <main>Orders</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_get_post.json")
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f11_t1_dynamic_ternary_fetch_matches_put_post_without_disp004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 1: Ternary DYNAMIC fetch method matches PUT/POST FastAPI routes without DISP-004."""
    del e2e_env
    repo = tmp_path / "f11_dyn_ternary"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE orders (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.put('/api/orders')\n"
                "def update_order(): return {'ok': True}\n"
                "@app.post('/api/orders')\n"
                "def create_order(): return {'ok': True}\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Page({ isEdit }: { isEdit: boolean }) {\n"
                "  void fetch('/api/orders', { method: isEdit ? 'PUT' : 'POST' });\n"
                "  return <main>Edit</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_dyn_ternary.json")
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f11_t1_dynamic_shorthand_method_does_not_emit_disp004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 1: Shorthand `{ method }` DYNAMIC fetch matches existing route without DISP-004."""
    del e2e_env
    repo = tmp_path / "f11_dyn_shorthand"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE orders (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/orders')\n"
                "def list_orders(): return []\n"
                "@app.post('/api/orders')\n"
                "def create_order(): return {'id': 1}\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Page({ method }: { method: string }) {\n"
                "  void fetch('/api/orders', { method });\n"
                "  return <main>Orders</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_dyn_shorthand.json")
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f11_t1_head_and_options_routes_match_cleanly(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 1: HEAD and OPTIONS fetch calls match @app.head / @app.options without DISP-004."""
    del e2e_env
    repo = tmp_path / "f11_head_opts"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE health_log (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.head('/api/health')\n"
                "def head_health(): return None\n"
                "@app.options('/api/health')\n"
                "def options_health(): return {'allow': 'GET,HEAD,OPTIONS'}\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Health() {\n"
                "  void fetch('/api/health', { method: 'HEAD' });\n"
                "  void fetch('/api/health', { method: 'OPTIONS' });\n"
                "  return <main>OK</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_head_opts.json")
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f11_t1_python_daemon_do_get_matches_api_alive(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 1: python_daemon_routes BaseHTTPRequestHandler.do_GET matches /api/alive cleanly."""
    del e2e_env
    repo = tmp_path / "f11_daemon_alive"
    _write_files(
        repo,
        {
            "schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "daemons/server.py": (
                "from http.server import BaseHTTPRequestHandler\n"
                "class Handler(BaseHTTPRequestHandler):\n"
                "    def do_GET(self):\n"
                "        if self.path == '/api/alive':\n"
                "            self.send_response(200)\n"
                "            self.end_headers()\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Alive() {\n"
                "  void fetch('/api/alive');\n"
                "  return <main>Alive</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_daemon_alive.json")
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f11_t2_dynamic_method_nonexistent_route_blocks_disp004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 2: DYNAMIC fetch to a nonexistent path emits blocking DISP-004 (gate exit 1)."""
    del e2e_env
    repo = tmp_path / "f11_dyn_missing"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE orders (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/orders')\n"
                "def list_orders(): return []\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Missing({ isEdit }: { isEdit: boolean }) {\n"
                "  void fetch('/api/nonexistent', { method: isEdit ? 'PUT' : 'POST' });\n"
                "  return <main>Missing</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_dyn_missing.json")
    disp004 = [f for f in rep["findings"] if f["rule_code"] == "DISP-004"]
    assert disp004 and any(f["blocks_gate"] for f in disp004)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f11_t2_daemon_root_prefix_guard_does_not_mask_disp004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 2: `startswith('/')` guard does not synthesize catch-all route."""
    del e2e_env
    repo = tmp_path / "f11_daemon_guard"
    _write_files(
        repo,
        {
            "schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "daemons/server.py": (
                "from http.server import BaseHTTPRequestHandler\n"
                "class Handler(BaseHTTPRequestHandler):\n"
                "    def do_GET(self):\n"
                "        if not self.path.startswith('/'):\n"
                "            self.send_error(400)\n"
                "            return\n"
                "        if self.path == '/api/alive':\n"
                "            return\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Ghost() {\n"
                "  void fetch('/api/broken-ghost');\n"
                "  return <main>Ghost</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_daemon_guard.json")
    assert "DISP-004" in _finding_codes(rep)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f11_t2_decoy_fastapi_and_cache_delete_not_verified_route(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 2: Decoy FastAPI import + `@cache.delete('session_key')` registers no route."""
    del e2e_env
    repo = tmp_path / "f11_decoy_cache"
    _write_files(
        repo,
        {
            "schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "daemons/worker.py": (
                "from fastapi import FastAPI\n"
                "class Cache:\n"
                "    def delete(self, key):\n"
                "        return lambda fn: fn\n"
                "cache = Cache()\n"
                "@cache.delete('session_key')\n"
                "def drop_cache():\n"
                "    return None\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function DropSession() {\n"
                "  void fetch('/session_key');\n"
                "  return <main>Session</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_decoy_cache.json")
    assert "DISP-004" in _finding_codes(rep)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f11_t2_logger_info_does_not_emit_verified_reads_truth_edge(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 2: `logger.info('config/tools.yaml')` does not emit verified `reads_truth` edge."""
    del e2e_env
    repo = tmp_path / "f11_logger_truth"
    _write_files(
        repo,
        {
            "schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "config/tools.yaml": "tools:\n  - name: demo\n    command: run.py\n",
            "daemons/worker.py": (
                "import logging\n"
                "logger = logging.getLogger(__name__)\n"
                "def run_job():\n"
                "    logger.info('config/tools.yaml')\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_logger_truth.json")
    verified_reg_edges = [
        e
        for e in rep["edges"]
        if e["kind"] == "reads_truth"
        and e["target_id"] == "t:registry:config/tools.yaml"
        and e["verification"] == "verified"
    ]
    assert verified_reg_edges == []


def test_f11_t2_mismatched_http_method_delete_triggers_disp004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 Tier 2: `fetch('/api/only-get', DELETE)` against GET route emits DISP-004."""
    del e2e_env
    repo = tmp_path / "f11_method_mismatch"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/only-get')\n"
                "def only_get(): return {'ok': True}\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default function Mismatch() {\n"
                "  void fetch('/api/only-get', { method: 'DELETE' });\n"
                "  return <main>Delete</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f11_method_mismatch.json")
    assert "DISP-004" in _finding_codes(rep)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


# ---------------------------------------------------------------------------
# F12 (P0-3, P1-10, P1-13): Epistemic (#119-#121) & Adapter Soundness
# ---------------------------------------------------------------------------


def test_f12_t1_clean_epistemic_slice_builder_passes_strict(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 1: Clean #119-#121 FastAPI+JS slice builder passes `wythe gate --strict`."""
    del e2e_env
    repo = tmp_path / "f12_clean_epistemic"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE slice_logs (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "import json\n"
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/v1/slices/status')\n"
                "def get_status():\n"
                "    return {'observed_at': '2026-11-20T00:00:00Z', 'healthy': True}\n"
                "def build_honest(state_path, ref_now):\n"
                "    src = json.loads(state_path.read_text())\n"
                "    obs = src.get('observed_at')\n"
                "    vu = src.get('valid_until')\n"
                "    return {\n"
                "        'observed_at': obs,\n"
                "        'valid_until': vu,\n"
                "        'stale': bool(vu and vu < ref_now),\n"
                "        'evidence_state': src.get('evidence_state', 'unknown'),\n"
                "    }\n"
                "SLICE_BUILDERS = {'health': build_honest}\n"
            ),
            "frontend/views/status.js": (
                "export async function renderStatus(client, nowMs) {\n"
                "  const data = await client.fetchSlice('health');\n"
                "  if (\n"
                "    data.evidence_state === 'source_error'\n"
                "    || data.evidence_state === 'could_not_measure'\n"
                "  ) {\n"
                "    return { status: 'degraded' };\n"
                "  }\n"
                "  const isStale = data.valid_until ? Date.parse(data.valid_until) < nowMs\n"
                "    : true;\n"
                "  return { observedAt: data.observed_at, stale: isStale };\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_clean_epistemic.json")
    assert not (_finding_codes(rep) & {"MANIP-007", "DISP-009", "DISP-010", "DISP-011", "DISP-014"})
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f12_t1_non_action_disp009_warning_without_disp010(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 1: Non-action fallback literal emits DISP-009 warning without blocking DISP-010."""
    del e2e_env
    repo = tmp_path / "f12_disp009_warn"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/v1/slices/info')\n"
                "def get_info():\n"
                "    return {'label': 'ok'}\n"
            ),
            "frontend/views/info.js": (
                "export async function renderInfo(client) {\n"
                "  const data = await client.fetchSlice('info');\n"
                "  const lbl = data.label ?? 'Standard';\n"
                "  return { lbl };\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_disp009_warn.json")
    disp009 = [f for f in rep["findings"] if f["rule_code"] == "DISP-009"]
    assert disp009 and all(f["severity"] == "warning" and not f["blocks_gate"] for f in disp009)
    assert "DISP-010" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f12_t1_clean_policy_consumption_with_len_guard_abs_round(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 1: Consuming min_cap/max_cap via abs()/round() + len guard emits 0 MANIP-001."""
    del e2e_env
    repo = tmp_path / "f12_clean_policy"
    _write_files(
        repo,
        {
            "backend/schema.sql": (
                "CREATE TABLE policy_limits (\n"
                "    id INTEGER PRIMARY KEY,\n"
                "    min_cap INTEGER NOT NULL,\n"
                "    max_cap INTEGER NOT NULL\n"
                ");\n"
            ),
            "backend/app/models/pol.py": (
                "from sqlalchemy import Column, Integer\n"
                "from sqlalchemy.orm import declarative_base\n"
                "Base = declarative_base()\n"
                "class PolicyLimits(Base):\n"
                "    __tablename__ = 'policy_limits'\n"
                "    id = Column(Integer, primary_key=True)\n"
                "    min_cap = Column(Integer, nullable=False)\n"
                "    max_cap = Column(Integer, nullable=False)\n"
            ),
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "backend/app/services/check.py": (
                "from app.models.pol import PolicyLimits\n"
                "def check_bounds(session, items):\n"
                "    if len(items) > 100:\n"
                "        return []\n"
                "    row = session.get(PolicyLimits, 1)\n"
                "    return [abs(row.min_cap), round(row.max_cap)]\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_clean_policy.json")
    assert "MANIP-001" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f12_t1_clean_postgres_sqlalchemy_schema_and_orm(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 1: Matching non-public PostgreSQL schema & ORM model emits 0 TRUTH-002."""
    del e2e_env
    repo = tmp_path / "f12_clean_pg"
    _write_files(
        repo,
        {
            "backend/schema.sql": (
                "CREATE SCHEMA billing;\n"
                "CREATE TABLE billing.invoices (id INTEGER PRIMARY KEY);\n"
            ),
            "backend/app/models.py": (
                "from sqlalchemy import Column, Integer\n"
                "from sqlalchemy.orm import declarative_base\n"
                "Base = declarative_base()\n"
                "class Invoice(Base):\n"
                "    __tablename__ = 'invoices'\n"
                "    __table_args__ = {'schema': 'billing'}\n"
                "    id = Column(Integer, primary_key=True)\n"
            ),
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_clean_pg.json")
    assert "TRUTH-002" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f12_t1_clean_ruling_metadata_valid_on_current_commit(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 1: Valid accepted_clean ruling on current commit waives TRUTH-004 cleanly."""
    del e2e_env
    repo = tmp_path / "ruling-clean"
    files = {
        "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
        "backend/app/main.py": (
            "from fastapi import FastAPI\n"
            "from app.services.cache import put_cfg\n"
            "app = FastAPI()\n"
            "@app.post('/api/cfg')\n"
            "def set_cfg():\n"
            "    put_cfg('1')\n"
            "    return {'ok': True}\n"
        ),
        "backend/app/services/cache.py": (
            "import redis\n"
            "redis_client = redis.Redis()\n"
            "def put_cfg(val: str) -> None:\n"
            "    redis_client.set('cfg_store:k', val)\n"
        ),
    }
    head_sha = init_git_repo(repo, files)
    gov_bundle = {
        "schema_version": "1.0",
        "target_slug": "ruling-clean",
        "exported_at": "2026-11-20T00:00:00Z",
        "audit_rulings": [
            {
                "node_id": "t:redis:cfg_store",
                "disposition": "accepted_clean",
                "summary": "Intentional persistent config seeded at startup",
                "store_purpose": {
                    "intended_use": "persistent_config",
                    "recovery_expectation": "seeded",
                    "keyspace_scope": "cfg_store:",
                },
                "evidence_scope": ["keyspace:cfg_store:"],
                "audited_commit": head_sha,
                "recorded_by": "reviewer",
            }
        ],
    }
    _write_files(repo, {".wythe/governance.json": json.dumps(gov_bundle)})
    sync_rc, _out, sync_err = run_cli(["sync-config", str(repo)])
    assert sync_rc == 0, sync_err

    out_path = tmp_path / "ruling_clean.json"
    scan_rc, _s_out, scan_err = run_cli(["scan", "ruling-clean", "--json", str(out_path)])
    assert scan_rc == 0, scan_err
    rep = json.loads(out_path.read_text(encoding="utf-8"))
    assert "TRUTH-004" not in _finding_codes(rep)
    redis_nodes = [n for n in rep["nodes"] if n["id"] == "t:redis:cfg_store"]
    assert redis_nodes and redis_nodes[0]["status"] == "clean"


def test_f12_t2_p0_3_strict_ignores_fabricated_fallback_allowlist_on_disp010(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P0-3): `wythe gate --strict` ignores fabricated_fallback_allowlist."""
    del e2e_env
    repo = tmp_path / "f12_p0_3_allowlist"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE tasks (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/v1/slices/tasks')\n"
                "def get_tasks():\n"
                "    return {'items': []}\n"
            ),
            "frontend/views/action-view.js": (
                "export async function renderTasks(client) {\n"
                "  const data = await client.fetchSlice('tasks');\n"
                "  const cards = [];\n"
                "  if (!data.items.length) {\n"
                "    cards.push({ id: 'fb-1', title: 'Approve pending', href: '/decide/fb-1' });\n"
                "  }\n"
                "  return { cards };\n"
                "}\n"
            ),
            ".wythe/governance.json": json.dumps(
                {"fabricated_fallback_allowlist": ["frontend/views/action-view.js"]}
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_p0_3.json", strict=True)
    disp010 = [f for f in rep["findings"] if f["rule_code"] == "DISP-010"]
    assert disp010 and any(f["blocks_gate"] for f in disp010)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_10_manip007_isoformat_replace_z(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-10): MANIP-007 blocks `datetime.now(...).isoformat().replace(...)`."""
    del e2e_env
    repo = tmp_path / "f12_manip007_replace"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "backend/app/builders.py": (
                "import json\n"
                "from datetime import datetime, timezone\n"
                "def build_slice(state_path):\n"
                "    src = json.loads(state_path.read_text())\n"
                "    ts = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')\n"
                "    return {\n"
                "        'observed_at': ts,\n"
                "        'value': src.get('value'),\n"
                "    }\n"
                "SLICE_BUILDERS = {'s1': build_slice}\n"
            ),
            "frontend/views/v.js": (
                "export async function render(c) {\n"
                "  const d = await c.fetchSlice('s1');\n"
                "  return d.value;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_manip007_replace.json", strict=True)
    m7 = [f for f in rep["findings"] if f["rule_code"] == "MANIP-007"]
    assert m7 and any(f["blocks_gate"] and "builders.py" in f["source_file"] for f in m7)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_10_manip007_daemon_do_get_and_nested_create_app(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-10): MANIP-007 fires on daemon `do_GET` and nested `create_app()`."""
    del e2e_env
    repo = tmp_path / "f12_manip007_nested"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "backend/app/daemon.py": (
                "import json\n"
                "from datetime import datetime, timezone\n"
                "from http.server import BaseHTTPRequestHandler\n"
                "class Handler(BaseHTTPRequestHandler):\n"
                "    def do_GET(self, state_path):\n"
                "        _src = json.loads(state_path.read_text())\n"
                "        return {\n"
                "            'observed_at': datetime.now(timezone.utc).isoformat(),\n"
                "            'stale': False,\n"
                "            'items': [],\n"
                "        }\n"
            ),
            "backend/app/factory.py": (
                "import json\n"
                "from datetime import datetime, timezone\n"
                "from fastapi import FastAPI\n"
                "def create_app(state_path):\n"
                "    app = FastAPI()\n"
                "    @app.get('/api/v1/slices/nested')\n"
                "    def get_nested():\n"
                "        _raw = json.loads(state_path.read_text(encoding='utf-8'))\n"
                "        ts = datetime.now(timezone.utc).isoformat()\n"
                "        return {'observed_at': ts, 'count': 1}\n"
                "    return app\n"
            ),
            "frontend/views/v.js": (
                "export async function render(c) {\n"
                "  const d = await c.fetchSlice('nested');\n"
                "  return d.missing_count;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_manip007_nested.json", strict=True)
    m7_files = {f["source_file"] for f in rep["findings"] if f["rule_code"] == "MANIP-007"}
    assert "backend/app/daemon.py" in m7_files
    assert "backend/app/factory.py" in m7_files
    assert "DISP-011" in _finding_codes(rep)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_10_disp009_transaction_label_not_disp010(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-10): `transactionLabel ?? 'Standard'` emits DISP-009 only (0 DISP-010)."""
    del e2e_env
    repo = tmp_path / "f12_tx_label"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE tx (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/v1/slices/tx')\n"
                "def get_tx():\n"
                "    return {'transactionLabel': 'ok'}\n"
            ),
            "frontend/views/tx.js": (
                "export async function renderTx(client) {\n"
                "  const data = await client.fetchSlice('tx');\n"
                "  const lbl = data.transactionLabel ?? 'Standard';\n"
                "  return { lbl };\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_tx_label.json", strict=True)
    assert "DISP-009" in _finding_codes(rep)
    assert "DISP-010" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f12_t2_p1_10_disp011_mixed_jsonresponse_and_pydantic_zero_fp(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-10): Mixed JSONResponse/Pydantic return emits 0 DISP-011 false positives."""
    del e2e_env
    repo = tmp_path / "f12_mixed_resp"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "from fastapi.responses import JSONResponse\n"
                "from pydantic import BaseModel\n"
                "class ItemOut(BaseModel):\n"
                "    status: str\n"
                "app = FastAPI()\n"
                "@app.get('/api/items')\n"
                "def get_items(ok: bool = True):\n"
                "    if not ok:\n"
                "        return JSONResponse({'error': 'bad'}, status_code=400)\n"
                "    return ItemOut(status='ok')\n"
            ),
            "frontend/src/app/page.tsx": (
                "export default async function Page() {\n"
                "  const res = await fetch('/api/items');\n"
                "  const data = await res.json();\n"
                "  return <span>{data.status}</span>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_mixed_resp.json", strict=True)
    assert "DISP-011" not in _finding_codes(rep)


def test_f12_t2_p1_10_disp011_reused_const_data_across_functions_zero_fp(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-10): Two functions reusing `const data = await res.json()` emit 0 DISP-011."""
    del e2e_env
    repo = tmp_path / "f12_two_fns"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/a')\n"
                "def get_a(): return {'alpha_status': 'ok'}\n"
                "@app.get('/api/b')\n"
                "def get_b(): return {'beta_status': 'ok'}\n"
            ),
            "frontend/views/two.js": (
                "export async function fnA() {\n"
                "  const res = await fetch('/api/a');\n"
                "  const data = await res.json();\n"
                "  return data.alpha_status;\n"
                "}\n"
                "export async function fnB() {\n"
                "  const res = await fetch('/api/b');\n"
                "  const data = await res.json();\n"
                "  return data.beta_status;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_two_fns.json", strict=True)
    assert "DISP-011" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f12_t2_p1_13_adapters_policy_shim_triggers_manip001(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-13): `adapters/policy_shim.py` hardcoded cap triggers blocking MANIP-001."""
    del e2e_env
    repo = tmp_path / "f12_adapters_shim"
    _write_files(
        repo,
        {
            "schema.sql": "CREATE TABLE policy_cfg (id INT PRIMARY KEY, max_cap INT);\n",
            "adapters/policy_shim.py": (
                "HARDCODED_SHIFT_CAP = 99\n"
                "def get_cap():\n"
                "    return HARDCODED_SHIFT_CAP\n"
            ),
            "services/main.py": (
                "import sqlite3\n"
                "def read_cap(conn):\n"
                "    return conn.execute('SELECT max_cap FROM policy_cfg').fetchone()\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_adapters_shim.json", strict=True)
    m1 = [f for f in rep["findings"] if f["rule_code"] == "MANIP-001"]
    assert any("adapters/policy_shim.py" in f["source_file"] and f["blocks_gate"] for f in m1)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_13_typescript_react_lib_api_and_main_tsx_disp004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-13): React adapter scans `lib/api.ts` & `main.tsx` for DISP-004."""
    del e2e_env
    repo = tmp_path / "f12_react_api"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/package.json": json.dumps(
                {"dependencies": {"react": "18.0.0", "vite": "5.0.0"}}
            ),
            "frontend/src/main.tsx": (
                "import { callGhost } from './lib/api';\n"
                "void fetch('/api/missing-from-main');\n"
                "void callGhost();\n"
            ),
            "frontend/src/lib/api.ts": (
                "export const callGhost = () => fetch('/api/missing-from-lib-api');\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_react_api.json", strict=True)
    disp004_files = {f["source_file"] for f in rep["findings"] if f["rule_code"] == "DISP-004"}
    assert "frontend/src/main.tsx" in disp004_files
    assert "frontend/src/lib/api.ts" in disp004_files
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_13_python_policy_consumption_pg_array_bracket_manip001(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-13): `SELECT ARRAY[']'], max_cap` + bypass triggers MANIP-001."""
    del e2e_env
    repo = tmp_path / "f12_pg_array"
    _write_files(
        repo,
        {
            "backend/schema.sql": (
                "CREATE TABLE policy_configs (id INTEGER PRIMARY KEY, max_cap INTEGER NOT NULL);\n"
            ),
            "backend/app/models/pol.py": (
                "from sqlalchemy import Column, Integer\n"
                "from sqlalchemy.orm import declarative_base\n"
                "Base = declarative_base()\n"
                "class PolicyConfig(Base):\n"
                "    __tablename__ = 'policy_configs'\n"
                "    id = Column(Integer, primary_key=True)\n"
                "    max_cap = Column(Integer, nullable=False)\n"
            ),
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "backend/app/services/pg.py": (
                "from sqlalchemy import text\n"
                "from app.models.pol import PolicyConfig\n"
                "HARDCODED_CAP = 50\n"
                "def resolve_cap(session):\n"
                "    _ = PolicyConfig\n"
                "    sql = text(\"SELECT ARRAY[']'], max_cap FROM policy_configs\")\n"
                "    _rows = session.execute(sql).fetchall()\n"
                "    return HARDCODED_CAP\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_pg_array.json", strict=True)
    m1 = [f for f in rep["findings"] if f["rule_code"] == "MANIP-001"]
    assert m1 and any(f["blocks_gate"] for f in m1)
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_13_postgres_sqlalchemy_unseen_schema_create_all_secondary_base_truth002(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-13): Declared schema + create_all -> TRUTH-002; unseen/secondary -> notes."""
    del e2e_env
    repo = tmp_path / "f12_pg_truth002"
    _write_files(
        repo,
        {
            "backend/schema.sql": (
                "CREATE SCHEMA billing;\n"
                "CREATE SCHEMA IF NOT EXISTS analytics;\n"
                "CREATE TABLE billing.invoices (id INTEGER PRIMARY KEY);\n"
            ),
            "backend/app/models.py": (
                "from sqlalchemy import Column, Integer\n"
                "from sqlalchemy.orm import declarative_base\n"
                "PrimaryBase = declarative_base()\n"
                "SecondaryBase = declarative_base()\n"
                "class Invoice(PrimaryBase):\n"
                "    __tablename__ = 'invoices'\n"
                "    __table_args__ = {'schema': 'billing'}\n"
                "    id = Column(Integer, primary_key=True)\n"
                "class AnalyticsMetric(PrimaryBase):\n"
                "    __tablename__ = 'metrics'\n"
                "    __table_args__ = {'schema': 'analytics'}\n"
                "    id = Column(Integer, primary_key=True)\n"
                "class AuditEvent(PrimaryBase):\n"
                "    __tablename__ = 'audit_events'\n"
                "    __table_args__ = {'schema': 'audit'}\n"
                "    id = Column(Integer, primary_key=True)\n"
                "class MissingTbl(PrimaryBase):\n"
                "    __tablename__ = 'missing_tbl'\n"
                "    id = Column(Integer, primary_key=True)\n"
                "class SecModel(SecondaryBase):\n"
                "    __tablename__ = 'sec_missing'\n"
                "    id = Column(Integer, primary_key=True)\n"
            ),
            "backend/alembic/versions/001.py": (
                "from app.models import PrimaryBase\n"
                "def upgrade(conn):\n"
                "    PrimaryBase.metadata.create_all(bind=conn)\n"
            ),
            "backend/alembic/versions/002.py": (
                "import sqlalchemy as sa\n"
                "from alembic import op\n"
                "def upgrade():\n"
                "    op.add_column('invoices', sa.Column('note', sa.String()), schema='billing')\n"
            ),
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        },
    )
    rep = _scan_json(repo, tmp_path / "f12_pg_truth002.json", strict=True)
    t2_nodes = {f["node_id"] for f in rep["findings"] if f["rule_code"] == "TRUTH-002"}
    assert "t:missing_tbl" in t2_nodes
    assert "t:analytics.metrics" in t2_nodes
    assert "t:audit.audit_events" not in t2_nodes
    assert "t:sec_missing" not in t2_nodes
    notes_text = "\n".join(str(n) for n in rep.get("scan_notes", []))
    assert "audit" in notes_text
    assert "SecondaryBase" in notes_text
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 1


def test_f12_t2_p1_13_ruling_metadata_revoked_and_stale_commit_on_truth004(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 Tier 2 (P1-13): Newer 'revoked' ruling & stale audited_commit keep TRUTH-004 active."""
    del e2e_env
    repo_revoked = tmp_path / "ruling-revoked"
    files = {
        "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
        "backend/app/main.py": (
            "from fastapi import FastAPI\n"
            "from app.services.cache import put_cfg\n"
            "app = FastAPI()\n"
            "@app.post('/api/cfg')\n"
            "def set_cfg():\n"
            "    put_cfg('1')\n"
            "    return {'ok': True}\n"
        ),
        "backend/app/services/cache.py": (
            "import redis\n"
            "redis_client = redis.Redis()\n"
            "def put_cfg(val: str) -> None:\n"
            "    redis_client.set('cfg_store:k', val)\n"
        ),
    }
    head_sha = init_git_repo(repo_revoked, files)
    gov_revoked = {
        "schema_version": "1.0",
        "target_slug": "ruling-revoked",
        "exported_at": "2026-11-20T00:00:00Z",
        "audit_rulings": [
            {
                "node_id": "t:redis:cfg_store",
                "disposition": "accepted_clean",
                "summary": "Previously accepted config",
                "store_purpose": {
                    "intended_use": "persistent_config",
                    "recovery_expectation": "seeded",
                    "keyspace_scope": "cfg_store:",
                },
                "evidence_scope": ["keyspace:cfg_store:"],
                "audited_commit": head_sha,
                "recorded_by": "reviewer",
            },
            {
                "node_id": "t:redis:cfg_store",
                "disposition": "revoked",
                "summary": "Revoked persistent_config waiver",
                "audited_commit": head_sha,
                "recorded_by": "reviewer",
            },
        ],
    }
    _write_files(repo_revoked, {".wythe/governance.json": json.dumps(gov_revoked)})
    rc_sync, _out, err_sync = run_cli(["sync-config", str(repo_revoked)])
    assert rc_sync == 0, err_sync

    rev_out = tmp_path / "ruling_revoked.json"
    rc_scan_rev, _s_out1, err_scan_rev = run_cli(
        ["scan", "ruling-revoked", "--json", str(rev_out)]
    )
    assert rc_scan_rev == 0, err_scan_rev
    rep_rev = json.loads(rev_out.read_text(encoding="utf-8"))
    assert "TRUTH-004" in _finding_codes(rep_rev)
    redis_nodes = [n for n in rep_rev["nodes"] if n["id"] == "t:redis:cfg_store"]
    assert redis_nodes and redis_nodes[0]["status"] != "clean"

    repo_stale = tmp_path / "ruling-stale"
    old_sha = init_git_repo(repo_stale, files, commit_msg="base")
    _ = init_git_repo(
        repo_stale,
        {"backend/app/services/cache.py": files["backend/app/services/cache.py"] + "\n# updated\n"},
        commit_msg="advance",
    )
    gov_stale = {
        "schema_version": "1.0",
        "target_slug": "ruling-stale",
        "exported_at": "2026-11-20T00:00:00Z",
        "audit_rulings": [
            {
                "node_id": "t:redis:cfg_store",
                "disposition": "accepted_clean",
                "summary": "Stale commit waiver",
                "store_purpose": {
                    "intended_use": "persistent_config",
                    "recovery_expectation": "seeded",
                    "keyspace_scope": "cfg_store:",
                },
                "evidence_scope": ["keyspace:cfg_store:"],
                "audited_commit": old_sha,
                "recorded_by": "reviewer",
            }
        ],
    }
    _write_files(repo_stale, {".wythe/governance.json": json.dumps(gov_stale)})
    rc_sync2, _out2, err_sync2 = run_cli(["sync-config", str(repo_stale)])
    assert rc_sync2 == 0, err_sync2
    stale_out = tmp_path / "ruling_stale.json"
    rc_scan_stale, _s_out2, err_scan_stale = run_cli(
        ["scan", "ruling-stale", "--json", str(stale_out)]
    )
    assert rc_scan_stale == 0, err_scan_stale
    rep_stale = json.loads(stale_out.read_text(encoding="utf-8"))
    assert "TRUTH-004" in _finding_codes(rep_stale)


# ---------------------------------------------------------------------------
# F13 (P1-8): Frontend Containment, Symlinks, SyntaxError & macOS /tmp
# ---------------------------------------------------------------------------


def test_f13_t1_relative_and_alias_frontend_imports_resolve_cleanly(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 1: Contained relative (`./helper`) & alias (`@/lib/ok`) imports scan cleanly."""
    del e2e_env
    repo = tmp_path / "f13_imports_ok"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/ok')\n"
                "def ok(): return {'ok': True}\n"
                "@app.get('/api/helper')\n"
                "def helper(): return {'helper': True}\n"
            ),
            "frontend/tsconfig.json": json.dumps(
                {"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"]}}}
            ),
            "frontend/src/lib/ok.ts": "export const OK_URL = '/api/ok';\n",
            "frontend/src/app/helper.ts": "export function helperUrl() { return '/api/helper'; }\n",
            "frontend/src/app/page.tsx": (
                "import { OK_URL } from '@/lib/ok';\n"
                "import { helperUrl } from './helper';\n"
                "export default function Page() {\n"
                "  void fetch(OK_URL);\n"
                "  void fetch(helperUrl());\n"
                "  return <main>OK</main>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f13_imports_ok.json")
    assert rep["coverage_complete"] is True
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f13_t1_valid_python_and_ts_coverage_complete(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 1: Valid Python and TypeScript files report `coverage_complete=True`."""
    del e2e_env
    repo = tmp_path / "f13_cov_complete"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/src/app/page.tsx": "export default function P() { return <div>Hi</div>; }\n",
        },
    )
    rep = _scan_json(repo, tmp_path / "f13_cov_complete.json")
    assert rep["coverage_complete"] is True
    assert rep["gate"]["coverage_complete"] is True


def test_f13_t1_valid_scan_under_tmp_path_exits_zero(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 1: `wythe scan` on a valid repo under `tmp_path` exits 0."""
    del e2e_env
    repo = tmp_path / "f13_scan_ok"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/src/app/page.tsx": "export default function P() { return <main />; }\n",
        },
    )
    rc, _stdout, stderr = run_cli(["scan", str(repo)])
    assert rc == 0, stderr


def test_f13_t1_scan_json_writes_valid_report(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 1: `wythe scan --json` writes a valid JSON report with core schema fields."""
    del e2e_env
    repo = tmp_path / "f13_json_report"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/src/app/page.tsx": "export default function P() { return <main />; }\n",
        },
    )
    out = tmp_path / "out_report.json"
    rep = _scan_json(repo, out)
    assert out.is_file()
    for key in ("stack_profile", "coverage_complete", "nodes", "edges", "findings", "gate"):
        assert key in rep


def test_f13_t1_clean_react_spa_with_package_json_exits_zero(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 1: Clean React/Vite SPA with package.json exits 0 on `wythe gate --strict`."""
    del e2e_env
    repo = tmp_path / "f13_react_clean"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/items')\n"
                "def list_items(): return []\n"
            ),
            "frontend/package.json": json.dumps(
                {"dependencies": {"react": "18.0.0", "vite": "5.0.0"}}
            ),
            "frontend/src/lib/api.ts": "export const getItems = () => fetch('/api/items');\n",
            "frontend/src/main.tsx": "import { getItems } from './lib/api';\nvoid getItems();\n",
        },
    )
    rep = _scan_json(repo, tmp_path / "f13_react_clean.json")
    assert rep["coverage_complete"] is True
    assert "DISP-004" not in _finding_codes(rep)
    rc, _stdout, stderr = _gate_strict(repo)
    assert rc == 0, stderr


def test_f13_t2_traversal_and_alias_escape_imports_never_read_outside_repo(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 2: Traversal (`../../etc/hosts`, `@/../../../../etc/hosts`) never reads outside."""
    del e2e_env
    outside_secret = tmp_path / "outside_secret.ts"
    outside_secret.write_text(
        "export const LEAK_URL = '/api/leak';\n"
        "export function triggerLeak() { return fetch('/api/leak'); }\n",
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/tsconfig.json": json.dumps(
                {"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"]}}}
            ),
            "frontend/src/app/page.tsx": (
                "import x from '../../../../../../../../etc/hosts';\n"
                "import y from '@/../../../../etc/hosts';\n"
                "import { LEAK_URL, triggerLeak } from '../../../outside_secret';\n"
                "export default function P() {\n"
                "  void x; void y; void triggerLeak();\n"
                "  return <div>{LEAK_URL}</div>;\n"
                "}\n"
            ),
        },
    )
    rep = _scan_json(repo, tmp_path / "f13_escape.json")
    serialized = json.dumps(rep)
    assert "/api/leak" not in serialized
    assert "outside_secret.ts" not in serialized


def test_f13_t2_symlinked_frontend_file_outside_repo_not_read(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 2: Symlinked `evil_link.tsx` pointing outside repo is never read."""
    del e2e_env
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir(parents=True, exist_ok=True)
    secret_tsx = outside_dir / "secret.tsx"
    secret_tsx.write_text(
        "export default function Secret() { return fetch('/api/from-symlink'); }\n",
        encoding="utf-8",
    )
    repo = tmp_path / "repo_symlink"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/src/app/page.tsx": "export default function P() { return <main />; }\n",
        },
    )
    evil_link = repo / "frontend" / "src" / "app" / "evil_link.tsx"
    evil_link.symlink_to(secret_tsx)

    rep = _scan_json(repo, tmp_path / "f13_symlink.json")
    serialized = json.dumps(rep)
    assert "/api/from-symlink" not in serialized
    assert all("evil_link.tsx" not in str(n.get("source_file", "")) for n in rep["nodes"])


def test_f13_t2_python_syntax_error_sets_coverage_incomplete(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 2: Python SyntaxError sets `coverage_complete=False` & `gate --strict` exits 2."""
    del e2e_env
    repo = tmp_path / "f13_py_syntax"
    _write_files(
        repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "backend/app/services/broken.py": "def oops(:\n",
            "frontend/src/app/page.tsx": "export default function P() { return <div />; }\n",
        },
    )
    rep = _scan_json(repo, tmp_path / "f13_py_syntax.json", strict=True)
    assert rep["coverage_complete"] is False
    assert rep["gate"]["coverage_complete"] is False
    rc, _stdout, _stderr = _gate_strict(repo)
    assert rc == 2


def test_f13_t2_ts_and_react_api_syntax_error_sets_coverage_incomplete(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 2: TS/JS SyntaxError (Next.js & React `lib/api.ts`) sets incomplete."""
    del e2e_env
    next_repo = tmp_path / "f13_next_syntax"
    _write_files(
        next_repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/src/app/page.tsx": "export default function P( { return <div\n",
        },
    )
    rep_next = _scan_json(next_repo, tmp_path / "f13_next_syntax.json", strict=True)
    assert rep_next["coverage_complete"] is False
    assert rep_next["gate"]["coverage_complete"] is False
    rc_next, _out1, _err1 = _gate_strict(next_repo)
    assert rc_next == 2

    react_repo = tmp_path / "f13_react_syntax"
    _write_files(
        react_repo,
        {
            "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
            "backend/app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/package.json": json.dumps(
                {"dependencies": {"react": "18.0.0", "vite": "5.0.0"}}
            ),
            "frontend/src/main.tsx": "export const ok = 1;\n",
            "frontend/src/lib/api.ts": "export function brokenApi( { return 1\n",
        },
    )
    rep_react = _scan_json(react_repo, tmp_path / "f13_react_syntax.json", strict=True)
    assert rep_react["coverage_complete"] is False
    assert rep_react["gate"]["coverage_complete"] is False
    rc_react, _out2, _err2 = _gate_strict(react_repo)
    assert rc_react == 2


def test_f13_t2_macos_tmp_symlink_repo_and_json_out_scans_cleanly(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F13 Tier 2: Repo directly under `/tmp/wythe_e2e_tmp_<uuid>/` scans cleanly."""
    del e2e_env
    suffix = uuid.uuid4().hex[:12]
    repo = Path(f"/tmp/wythe_e2e_tmp_{suffix}")
    out_json = tmp_path / f"wythe_e2e_out_{suffix}.json"
    try:
        _write_files(
            repo,
            {
                "backend/schema.sql": "CREATE TABLE items (id INT PRIMARY KEY);\n",
                "backend/app/main.py": (
                    "from fastapi import FastAPI\n"
                    "app = FastAPI()\n"
                    "@app.get('/api/v1/slices/s1')\n"
                    "def get_s1():\n"
                    "    return {'ok': True}\n"
                ),
                "frontend/views/v.js": (
                    "export async function renderV(client) {\n"
                    "  const d = await client.fetchSlice('s1');\n"
                    "  return d.ok;\n"
                    "}\n"
                ),
            },
        )
        rep = _scan_json(repo, out_json)
        assert rep["coverage_complete"] is True
        assert out_json.is_file()
    finally:
        shutil.rmtree(repo, ignore_errors=True)
        out_json.unlink(missing_ok=True)
