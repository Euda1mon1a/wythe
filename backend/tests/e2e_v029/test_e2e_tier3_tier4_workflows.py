"""Tier 3 (Cross-Feature Pairwise) and Tier 4 (Real-World Scenarios) opaque-box E2E tests."""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from .conftest import (
    init_git_repo,
    plugin_cli_args,
    run_cli,
    run_cli_subprocess,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_BACKEND_DIR = _REPO_ROOT / "backend"
_PLUGIN_SRC_DIRS = tuple(sorted((_REPO_ROOT / "plugins").glob("*/src")))

_SECURITY_HEADER_EXPECTATIONS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "content-security-policy": "frame-ancestors 'none'",
}


def _forbidden_internal_tokens() -> tuple[str, ...]:
    """Build restricted internal token list dynamically so zero literal tokens appear in tests."""
    return (
        "aaron" + "montgomery",
        "tail" + "d552c6",
        "rhizo" + "claw",
        "cau" + "dex",
        "len" + "ticel",
        "cas" + "parian",
        "molt" + "bot",
        "aarons-" + "mac",
        "zipa" + "box",
        "eligible_for_" + "koa",
    )


def _assert_security_headers(resp: Any) -> None:
    lowered = {k.lower(): v for k, v in resp.headers.items()}
    for header_name, expected_val in _SECURITY_HEADER_EXPECTATIONS.items():
        assert lowered.get(header_name) == expected_val


def _register_target_http(
    client: TestClient,
    slug: str,
    repo: Path,
    *,
    profile: str = "fastapi-sqlalchemy-nextjs",
    backend_subdir: str = "backend",
    frontend_subdir: str = "frontend",
) -> dict[str, Any]:
    resp = client.post(
        "/api/v1/targets",
        json={
            "slug": slug,
            "name": f"Target {slug}",
            "repo_path": str(repo),
            "stack_profile_slug": profile,
            "backend_subdir": backend_subdir,
            "frontend_subdir": frontend_subdir,
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 201, resp.text
    _assert_security_headers(resp)
    return resp.json()


def _create_user_site_plugin(
    userbase: Path,
    *,
    dist_name: str,
    ep_name: str,
    mod_name: str,
    attr_name: str,
    module_source: str,
) -> Path:
    """Create a user-site `.dist-info` and module under ``PYTHONUSERBASE``."""
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


def _encode_mcp_frame(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _decode_mcp_frames(raw: bytes) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    pos = 0
    while pos < len(raw):
        if raw[pos : pos + 15].lower() == b"content-length:":
            hdr_end = raw.find(b"\r\n\r\n", pos)
            if hdr_end == -1:
                break
            header_block = raw[pos:hdr_end].decode("ascii")
            length = 0
            for line in header_block.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip())
                    break
            body_start = hdr_end + 4
            body_end = body_start + length
            frames.append(json.loads(raw[body_start:body_end].decode("utf-8")))
            pos = body_end
        else:
            nl = raw.find(b"\n", pos)
            if nl == -1:
                line_bytes = raw[pos:].strip()
                pos = len(raw)
            else:
                line_bytes = raw[pos:nl].strip()
                pos = nl + 1
            if line_bytes:
                frames.append(json.loads(line_bytes.decode("utf-8")))
    return frames


def _run_mcp_stdio(
    requests: list[dict[str, Any]],
    *,
    e2e_env: dict[str, Any],
    extra_pythonpaths: list[Path] | None = None,
    slice_mode: str = "full",
) -> list[dict[str, Any]]:
    env = os.environ.copy()
    env["WYTHE_DATABASE_URL"] = e2e_env["db_url"]
    env["WYTHE_STATE_DIR"] = str(e2e_env["state_dir"])
    for var in ("TRUTH_ATLAS_DATABASE_URL", "TRUTH_ATLAS_STATE_DIR"):
        env.pop(var, None)

    py_paths = [str(_BACKEND_DIR), *(str(p) for p in _PLUGIN_SRC_DIRS)]
    if extra_pythonpaths:
        py_paths.extend(str(p) for p in extra_pythonpaths)
    env["PYTHONPATH"] = os.pathsep.join(py_paths)

    stdin_bytes = b"".join(_encode_mcp_frame(req) for req in requests)
    proc = subprocess.run(
        [sys.executable, "-m", "app.cli", "mcp", "--slice", slice_mode],
        cwd=str(_REPO_ROOT),
        env=env,
        input=stdin_bytes,
        capture_output=True,
        check=False,
        timeout=60.0,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")
    return _decode_mcp_frames(proc.stdout)


def _extract_embedded_json(markdown_text: str) -> dict[str, Any]:
    match = re.search(r"```json\s*(\{.*?\})\s*```", markdown_text, re.DOTALL)
    assert match is not None, f"No embedded JSON found in:\n{markdown_text}"
    return json.loads(match.group(1))


def _write_minimal_fastapi_nextjs_repo(
    repo: Path,
    *,
    backend_main: str = "from fastapi import FastAPI\napp = FastAPI()\n",
    schema_sql: str = "CREATE TABLE items (id INT PRIMARY KEY);\n",
    frontend_tsx: str = "export default function Page() { return <main>ok</main>; }\n",
    extra_files: dict[str, str] | None = None,
) -> None:
    files = {
        "backend/schema.sql": schema_sql,
        "backend/app/main.py": backend_main,
        "frontend/src/app/page.tsx": frontend_tsx,
    }
    if extra_files:
        files.update(extra_files)
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Tier 3 — Cross-Feature Pairwise Combinations (>=16 tests)
# ---------------------------------------------------------------------------


def test_tier3_f01_f04_diff_malicious_git_config_fails_closed(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F01 + F04: `wythe diff` on repo with malicious .git/config fails closed without RCE."""
    del e2e_env
    repo = tmp_path / "malicious_git_diff"
    _write_minimal_fastapi_nextjs_repo(repo)
    init_git_repo(repo, {})

    rce_marker = tmp_path / "git_rce_executed.txt"
    git_cfg = repo / ".git" / "config"
    git_cfg.write_text(
        git_cfg.read_text(encoding="utf-8")
        + f'\n[filter "pwn"]\n\tclean = touch {rce_marker}\n'
        + f'[log]\n\tshowSignature = true\n[gpg]\n\tprogram = touch {rce_marker}\n',
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n# modified\n",
        encoding="utf-8",
    )

    rc, _out, err = run_cli(["diff", str(repo), "--base", "HEAD"])
    assert rc == 2, err
    assert not rce_marker.exists()


def test_tier3_f02_f03_shadowed_plugin_and_governance_waiver_under_strict(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F02 + F03: `sys.path`-shadowed plugin + governance waiver under `wythe gate --strict`."""
    repo = tmp_path / "shadow_gov_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        schema_sql="CREATE TABLE policy_configs (id INT PRIMARY KEY, max_cap INT);\n",
        extra_files={
            "backend/app/models/policy.py": (
                "from sqlalchemy import Column, Integer\n"
                "from sqlalchemy.orm import declarative_base\n"
                "Base = declarative_base()\n"
                "class PolicyConfig(Base):\n"
                "    __tablename__ = 'policy_configs'\n"
                "    id = Column(Integer, primary_key=True)\n"
                "    max_cap = Column(Integer, nullable=False)\n"
            ),
            "backend/app/adapters/policy_shim.py": (
                "from app.models.policy import PolicyConfig\n"
                "HARDCODED_MAX_CAP = 42\n"
                "def get_cap(session):\n"
                "    _row = session.get(PolicyConfig, 1)\n"
                "    return HARDCODED_MAX_CAP\n"
            ),
        },
    )
    marker = tmp_path / "shadow_plugin_executed.txt"
    (repo / "wythe_shadow_mod.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('pwned', encoding='utf-8')\n"
        "def register_wythe_plugin():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (repo / ".wythe").mkdir(parents=True, exist_ok=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "MANIP-001",
                        "severity": "warning",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "pr-author",
                    }
                ],
                "audit_rulings": [
                    {
                        "node_id": "m:service:backend/app/adapters/policy_shim.py",
                        "disposition": "accepted_clean",
                        "summary": "Untrusted PR waiver",
                        "evidence_scope": ["backend/app/adapters/policy_shim.py:2"],
                        "audited_commit": "HEAD",
                        "recorded_by": "pr-author",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    userbase = tmp_path / "userbase_shadow"
    site_dir = _create_user_site_plugin(
        userbase,
        dist_name="wythe-plugin-shadow",
        ep_name="shadow",
        mod_name="wythe_shadow_mod",
        attr_name="register_wythe_plugin",
        module_source=(
            "class CleanShadowPlugin:\n"
            "    name = 'shadow'\n"
            "    version = '0.1.0'\n"
            "    description = 'Trusted shadow stub'\n"
            "    def check_report(self, repo_root, report):\n"
            "        return []\n"
            "def register_wythe_plugin():\n"
            "    return CleanShadowPlugin()\n"
        ),
    )
    py_path = os.pathsep.join(
        [str(_BACKEND_DIR), str(site_dir), *(str(p) for p in _PLUGIN_SRC_DIRS)]
    )
    rc, out, err = run_cli_subprocess(
        ["gate", "--strict", "--sync-config", "."],
        cwd=repo,
        env_overrides={
            "PYTHONUSERBASE": str(userbase),
            "PYTHONPATH": py_path,
            "WYTHE_DATABASE_URL": e2e_env["db_url"],
            "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
        },
    )
    assert not marker.exists()
    assert rc in (1, 2), f"Expected fail-closed non-zero exit, got {rc}\n{out}\n{err}"


def test_tier3_f03_f04_strict_sync_config_and_diff_trusted_ref_symmetry(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F03 + F04: `gate --strict --sync-config` + `diff` with `--trusted-config-ref`."""
    del e2e_env
    repo = tmp_path / "trusted_ref_diff"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        schema_sql="CREATE TABLE policy_configs (id INT PRIMARY KEY, max_cap INT);\n",
        extra_files={
            "backend/app/models/policy.py": (
                "from sqlalchemy import Column, Integer\n"
                "from sqlalchemy.orm import declarative_base\n"
                "Base = declarative_base()\n"
                "class PolicyConfig(Base):\n"
                "    __tablename__ = 'policy_configs'\n"
                "    id = Column(Integer, primary_key=True)\n"
                "    max_cap = Column(Integer, nullable=False)\n"
            ),
            "backend/app/adapters/policy_shim.py": (
                "from app.models.policy import PolicyConfig\n"
                "HARDCODED_MAX_CAP = 7\n"
                "def get_cap(session):\n"
                "    _row = session.get(PolicyConfig, 1)\n"
                "    return HARDCODED_MAX_CAP\n"
            ),
        },
    )
    base_sha = init_git_repo(repo, {}, commit_msg="base")

    gov_dir = repo / ".wythe"
    gov_dir.mkdir(parents=True, exist_ok=True)
    (gov_dir / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "audit_rulings": [
                    {
                        "node_id": "m:service:backend/app/adapters/policy_shim.py",
                        "disposition": "accepted_clean",
                        "summary": "Reviewed line 2 constant",
                        "evidence_scope": ["backend/app/adapters/policy_shim.py:2"],
                        "audited_commit": base_sha,
                        "recorded_by": "reviewer",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "add ruling"],
        check=True,
        capture_output=True,
    )
    ruled_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    rc_sync, _out, err = run_cli(
        ["sync-config", str(repo), "--trusted-config-ref", ruled_sha]
    )
    assert rc_sync == 0, err

    rc_gate, _out, _err = run_cli(
        [
            "gate",
            "--strict",
            "--sync-config",
            "--trusted-config-ref",
            ruled_sha,
            str(repo),
        ]
    )
    assert rc_gate == 1

    (repo / "README.md").write_text("# benign doc change\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "docs"],
        check=True,
        capture_output=True,
    )
    diff_out = tmp_path / "diff_symmetry.json"
    rc_diff, _out, err = run_cli(
        ["diff", str(repo), "--base", ruled_sha, "--json", str(diff_out)]
    )
    assert rc_diff == 0, err
    diff_data = json.loads(diff_out.read_text(encoding="utf-8"))
    assert diff_data["diff_verdict"] == "PASS"
    assert diff_data["blocking_new_findings"] == 0


def test_tier3_f03_f08_non_strict_rule_override_does_not_hydrate_strict_pass(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """F03 + F08: `strict=False` cached override never hydrates `strict=True` PASS."""
    repo = tmp_path / "hydration_strict"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        frontend_tsx=(
            "export default function Page() {\n"
            "  void fetch('/api/nonexistent-endpoint');\n"
            "  return <main>missing</main>;\n"
            "}\n"
        ),
    )
    slug = "hydration-strict"
    _register_target_http(e2e_client, slug, repo)

    (repo / ".wythe").mkdir(parents=True, exist_ok=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": slug,
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "DISP-004",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "operator",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sync_resp = e2e_client.post(
        f"/api/v1/targets/{slug}/governance-sync?direction=import",
        headers={"X-Wythe-Client": "1"},
    )
    assert sync_resp.status_code == 200, sync_resp.text

    relaxed = e2e_client.post(
        f"/api/v1/scans/{slug}?strict=false",
        headers={"X-Wythe-Client": "1"},
    )
    assert relaxed.status_code == 200, relaxed.text
    assert relaxed.json()["gate"]["verdict"] == "PASS"

    strict = e2e_client.post(
        f"/api/v1/scans/{slug}?strict=true",
        headers={"X-Wythe-Client": "1"},
    )
    assert strict.status_code == 200, strict.text
    assert strict.json()["gate"]["verdict"] == "FAIL"
    assert strict.json()["gate"]["blocking_violations"] >= 1

    rc_gate, _out, _err = run_cli(["gate", "--strict", slug])
    assert rc_gate == 1


def test_tier3_f05_f06_ipv6_csrf_passes_and_ssrf_6to4_blocked(
    e2e_client: TestClient,
) -> None:
    """F05 + F06: IPv6 `[::1]:8780` Origin passes CSRF while `2002::/16` SSRF returns `422`."""
    resp = e2e_client.post(
        "/api/v1/ask",
        json={
            "question": "What routes exist?",
            "engine": "local",
            "local_base_url": "http://[2002:0808:0808::1]:8080",
        },
        headers={
            "Host": "[::1]:8780",
            "Origin": "http://[::1]:8780",
            "X-Wythe-Client": "1",
        },
    )
    assert resp.status_code == 422, resp.text
    _assert_security_headers(resp)


def test_tier3_f05_f08_get_scans_persist_rejected_cross_target_viewport_and_headers(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """F05 + F08: `GET ?persist=true` -> 400, cross-target viewport -> 422, headers."""
    repo_a = tmp_path / "repo_alpha"
    repo_b = tmp_path / "repo_beta"
    _write_minimal_fastapi_nextjs_repo(repo_a)
    _write_minimal_fastapi_nextjs_repo(repo_b)
    _register_target_http(e2e_client, "alpha", repo_a)
    _register_target_http(e2e_client, "beta", repo_b)

    inv_resp = e2e_client.post(
        "/api/v1/investigations",
        json={"target_slug": "alpha", "session_id": "sess-alpha", "title": "Alpha"},
        headers={"X-Wythe-Client": "1"},
    )
    assert inv_resp.status_code == 200, inv_resp.text
    _assert_security_headers(inv_resp)

    get_persist = e2e_client.get("/api/v1/scans/alpha?persist=true")
    assert get_persist.status_code == 400
    _assert_security_headers(get_persist)

    vp_resp = e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "beta",
            "session_id": "sess-alpha",
            "lens": "status",
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert vp_resp.status_code == 422, vp_resp.text
    _assert_security_headers(vp_resp)


def test_tier3_f07_f08_packed_refs_gt32_citations_paused_expiry_and_basename_isolation(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """F07 + F08: packed-refs `#103` >32 citations, `#106` paused expiry, and basename isolation."""
    repo = tmp_path / "target-a"
    main_lines = "\n".join(
        ["from fastapi import FastAPI", "app = FastAPI()", *[f"CONST_{i} = {i}" for i in range(40)]]
    )
    _write_minimal_fastapi_nextjs_repo(repo, backend_main=main_lines + "\n")
    init_git_repo(repo, {})
    subprocess.run(["git", "-C", str(repo), "pack-refs", "--all"], check=True, capture_output=True)
    assert (repo / ".git" / "packed-refs").is_file()

    _register_target_http(e2e_client, "target-a", repo)
    inv_resp = e2e_client.post(
        "/api/v1/investigations",
        json={"target_slug": "target-a", "session_id": "sess-packed", "title": "Packed"},
        headers={"X-Wythe-Client": "1"},
    )
    assert inv_resp.status_code == 200, inv_resp.text

    cites = " ".join(f"`backend/app/main.py:{idx}`" for idx in range(1, 36))
    turn_resp = e2e_client.post(
        "/api/v1/investigations/sess-packed/turns",
        json={
            "actor": "agent",
            "question": "Cite all lines",
            "answer_markdown": f"Verified lines: {cites}",
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert turn_resp.status_code == 200, turn_resp.text
    refs = {r["ref_id"]: r["validation_state"] for r in turn_resp.json()["validated_references"]}
    assert len(refs) == 33
    assert refs.get("backend/app/main.py:32") == "validated"
    assert refs.get("citation:truncated") == "unresolved"

    exp_ts = (datetime.now(UTC) + timedelta(milliseconds=150)).isoformat()
    cmd_resp = e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "target-a",
            "session_id": "sess-packed",
            "command_id": "cmd_pause_exp",
            "expires_at": exp_ts,
            "lens": "status",
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert cmd_resp.status_code == 200, cmd_resp.text
    pause_resp = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_pause_exp",
            "target_slug": "target-a",
            "session_id": "sess-packed",
            "client_id": "browser-1",
            "outcome": "paused_by_human",
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert pause_resp.status_code == 200, pause_resp.text
    time.sleep(0.25)

    state_resp = e2e_client.get(
        "/api/v1/viewport/state",
        params={"target_slug": "target-a", "session_id": "sess-packed"},
    )
    assert state_resp.status_code == 200
    assert state_resp.json()["latest"]["delivery_state"] == "expired"

    apply_after_exp = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_pause_exp",
            "target_slug": "target-a",
            "session_id": "sess-packed",
            "client_id": "browser-1",
            "outcome": "applied",
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert apply_after_exp.status_code == 422

    evil_dir = tmp_path / "evil_parent" / "target-a"
    _write_minimal_fastapi_nextjs_repo(evil_dir)
    mcp_resp = e2e_client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wythe_investigation",
                "arguments": {
                    "action": "record_turn",
                    "target": str(evil_dir),
                    "answer_markdown": "forged foreign turn",
                },
            },
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert mcp_resp.status_code == 200
    sess_after = e2e_client.get("/api/v1/investigations/sess-packed").json()
    assert all(t["answer_markdown"] != "forged foreign turn" for t in sess_after["turns"])


def test_tier3_f07_f10_mcp_record_turn_packed_refs_blocks_secret_allows_source(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """F07 + F10: MCP `record_turn` on packed-refs repo blocks secret files and validates source."""
    repo = tmp_path / "packed_secrets"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        extra_files={
            "secrets.yaml": "api_key: supersecret\n",
            "config/.pgpass": "localhost:5432:db:user:pass\n",
            "prod.env.local": "SECRET_TOKEN=xyz\n",
        },
    )
    init_git_repo(repo, {})
    subprocess.run(["git", "-C", str(repo), "pack-refs", "--all"], check=True, capture_output=True)
    _register_target_http(e2e_client, "packed-sec", repo)

    mcp_resp = e2e_client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wythe_investigation",
                "arguments": {
                    "action": "record_turn",
                    "target": "packed-sec",
                    "answer_markdown": (
                        "Checked `backend/app/main.py:1`, `secrets.yaml:1`, "
                        "`config/.pgpass:1`, and `prod.env.local:1`."
                    ),
                },
            },
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert mcp_resp.status_code == 200
    result = mcp_resp.json()["result"]
    assert not result.get("isError"), result
    receipt = _extract_embedded_json(result["content"][0]["text"])
    by_ref = {r["ref_id"]: r["validation_state"] for r in receipt["validated_references"]}
    assert by_ref["backend/app/main.py:1"] == "validated"
    assert by_ref["secrets.yaml:1"] == "unresolved"
    assert by_ref["config/.pgpass:1"] == "unresolved"
    assert by_ref["prod.env.local:1"] == "unresolved"


def test_tier3_f09_f10_mcp_agent_discordance_and_understanding_string_bool_and_dict_receipt(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F09 + F10: `wythe mcp` dict receipt + agent-discordance string-bool DISC-002."""
    repo = tmp_path / "disc_mcp_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        extra_files={
            ".wythe/agent_routes.json": json.dumps(
                {
                    "routes": [
                        {
                            "route_id": "owner_route",
                            "agent_id": "agent_a",
                            "principal_scope": "owner",
                            "canary_task_id": "task_secret_a",
                            "explicit_privacy_boundary": "false",
                        },
                        {
                            "route_id": "guest_route",
                            "agent_id": "agent_b",
                            "principal_scope": "guest",
                            "explicit_privacy_boundary": "false",
                        },
                    ]
                }
            ),
            ".wythe/agent_receipts.json": json.dumps(
                {
                    "observations": [
                        {
                            "route_id": "guest_route",
                            "caller_receipt_id": "rcpt-b",
                            "authz_receipt_id": "authz-b",
                            "observed_agent_id": "agent_b",
                            "canary_recovered": "true",
                            "accessed_task_id": "task_secret_a",
                        }
                    ]
                }
            ),
        },
    )
    scan_out = tmp_path / "disc_scan.json"
    rc_scan, _out, err = run_cli(
        [
            "scan",
            str(repo),
            "--json",
            str(scan_out),
            *plugin_cli_args("agent-discordance"),
        ]
    )
    assert rc_scan == 0, err
    scan_rep = json.loads(scan_out.read_text(encoding="utf-8"))
    assert any(f["rule_code"] == "DISC-002" and f["blocks_gate"] for f in scan_rep["findings"])

    frames = _run_mcp_stdio(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "wythe_understanding",
                    "arguments": {
                        "action": "analyze_understanding",
                        "bundle": {
                            "source_revision": "rev-1",
                            "question": "Did delivery succeed?",
                            "outcome_lifecycles": [
                                {
                                    "outcome_id": "out-1",
                                    "subject_id": "sub-1",
                                    "delivery_status": "delivered",
                                    "delivery_receipt": {"id": "rcpt-dict-1"},
                                    "transitions": [
                                        {
                                            "stage": "delivered_to_human",
                                            "producer": "gateway",
                                            "state_digest": "d1",
                                        }
                                    ],
                                }
                            ],
                        },
                    },
                },
            },
        ],
        e2e_env=e2e_env,
    )
    assert len(frames) == 2
    und_res = frames[1]["result"]
    assert not und_res.get("isError"), und_res


def test_tier3_f11_f12_dynamic_fetch_head_options_manip007_replace_and_disp009_txlabel(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 + F12: DYNAMIC fetch + HEAD/OPTIONS + MANIP-007 .replace() + DISP-009."""
    del e2e_env
    repo = tmp_path / "epistemic_routes"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        backend_main=(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/api/orders')\n"
            "def list_orders():\n"
            "    return {'ok': True}\n"
            "@app.put('/api/orders')\n"
            "def put_orders():\n"
            "    return {'ok': True}\n"
            "@app.head('/api/health')\n"
            "@app.options('/api/health')\n"
            "def health():\n"
            "    return {'status': 'ok'}\n"
            "@app.get('/api/v1/slices/tx')\n"
            "def slice_tx():\n"
            "    return {'transactionLabel': 'Posted'}\n"
        ),
        frontend_tsx=(
            "export default function Page({ isEdit }: { isEdit: boolean }) {\n"
            "  void fetch('/api/orders', { method: isEdit ? 'PUT' : 'POST' });\n"
            "  void fetch('/api/health', { method: 'HEAD' });\n"
            "  void fetch('/api/health', { method: 'OPTIONS' });\n"
            "  return <main>orders</main>;\n"
            "}\n"
        ),
        extra_files={
            "backend/app/builders.py": (
                "import json\n"
                "from datetime import datetime, timezone\n"
                "def build_tx(state_path):\n"
                "    src = json.loads(state_path.read_text())\n"
                "    ts = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')\n"
                "    return {\n"
                "        'observed_at': ts,\n"
                "        'transactionLabel': src.get('label'),\n"
                "    }\n"
                "SLICE_BUILDERS = {'tx': build_tx}\n"
            ),
            "frontend/views/tx.js": (
                "export async function renderTx(client) {\n"
                "  const data = await client.fetchSlice('tx');\n"
                "  return data.transactionLabel ?? 'Standard';\n"
                "}\n"
            ),
        },
    )
    out_json = tmp_path / "scan_epistemic.json"
    rc, _out, err = run_cli(["scan", str(repo), "--json", str(out_json)])
    assert rc == 0, err
    report = json.loads(out_json.read_text(encoding="utf-8"))
    rules = [f["rule_code"] for f in report["findings"]]
    assert "MANIP-007" in rules
    assert "DISP-009" in rules
    assert "DISP-004" not in rules
    assert "DISP-010" not in rules


def test_tier3_f11_f13_daemon_startswith_guard_react_lib_api_and_out_of_repo_containment(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F11 + F13: daemon startswith('/') guard + React lib/api.ts + containment."""
    del e2e_env
    (tmp_path / "outside_secret.ts").write_text(
        "export const leak = () => fetch('/api/outside-secret-leak');\n",
        encoding="utf-8",
    )
    repo = tmp_path / "nested_area" / "daemon_react_repo"
    repo.mkdir(parents=True)
    (repo / "schema.sql").write_text("CREATE TABLE items (id INT PRIMARY KEY);\n", encoding="utf-8")
    (repo / "daemons").mkdir(parents=True)
    (repo / "daemons" / "server.py").write_text(
        "from http.server import BaseHTTPRequestHandler\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if not self.path.startswith('/'):\n"
        "            self.send_error(400)\n"
        "            return\n"
        "        if self.path == '/api/alive':\n"
        "            return\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "lib").mkdir(parents=True)
    (repo / "frontend" / "package.json").write_text(
        json.dumps({"dependencies": {"react": "18.0.0", "vite": "5.0.0"}}),
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "main.tsx").write_text(
        "import { callGhost } from './lib/api';\n"
        "export const App = () => {\n"
        "    void callGhost();\n"
        "    return null;\n"
        "};\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "lib" / "api.ts").write_text(
        "import x from '../../../../../../etc/hosts';\n"
        "import { leak } from '../../../../outside_secret';\n"
        "export const callGhost = () => fetch('/api/ghost-from-lib');\n"
        "export { x, leak };\n",
        encoding="utf-8",
    )

    out_json = tmp_path / "daemon_react.json"
    rc, _out, err = run_cli(["scan", str(repo), "--json", str(out_json)])
    assert rc == 0, err
    report = json.loads(out_json.read_text(encoding="utf-8"))
    disp004_targets = [
        f["detail"] + " " + f["title"]
        for f in report["findings"]
        if f["rule_code"] == "DISP-004"
    ]
    assert any("/api/ghost-from-lib" in txt for txt in disp004_targets)
    serialized = json.dumps(report)
    assert "/api/outside-secret-leak" not in serialized


def test_tier3_f12_f13_macos_tmp_syntax_error_and_slices_incomplete(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F12 + F13: macOS `/tmp` repo with SyntaxError & slice route is incomplete."""
    del e2e_env
    tmp_root = Path("/tmp") / f"wythe_t3_mac_{uuid.uuid4().hex[:10]}"
    out_json = tmp_path / f"wythe_t3_mac_out_{uuid.uuid4().hex[:10]}.json"
    try:
        _write_minimal_fastapi_nextjs_repo(
            tmp_root,
            backend_main=(
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/v1/slices/s1')\n"
                "def s1():\n"
                "    return {'ok': True}\n"
            ),
            extra_files={
                "frontend/src/views/broken.js": (
                    "export async function f( { return fetchSlice('s1');\n"
                ),
            },
        )
        rc_scan, _out, err = run_cli(["scan", str(tmp_root), "--json", str(out_json)])
        assert rc_scan == 0, err
        report = json.loads(out_json.read_text(encoding="utf-8"))
        assert report["coverage_complete"] is False

        rc_gate, _out, _err = run_cli(["gate", "--strict", str(tmp_root)])
        assert rc_gate == 2
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
        out_json.unlink(missing_ok=True)


def test_tier3_f14_f15_dos_dockerignore_redos_bplist_and_trivy_redaction(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F14 + F15: .dockerignore glob + tach ReDoS + binary plist + Trivy SARIF secret redaction."""
    del e2e_env
    repo = tmp_path / "dos_companion_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        extra_files={
            "Dockerfile": (
                "FROM python:3.12-slim\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                'CMD ["python", "/app/backend/a/b/c/d/e/f/g/h/target.py"]\n'
            ),
            ".dockerignore": ("**/" * 18) + "target.py\n",
            "backend/a/b/c/d/e/f/g/h/target.py": "X = 1\n",
            "tach.toml": (
                'source_roots = ["backend"]\n'
                'exclude = ["backend/app/(a+)+b"]\n'
                "[[modules]]\n"
                'path = "app"\n'
                "depends_on = []\n"
            ),
            "backend/app/aaaaaaaaaaaaaaaaaaaaaaaaaac.py": "X = 1\n",
        },
    )
    (repo / "launchd").mkdir(parents=True, exist_ok=True)
    (repo / "launchd" / "bin.plist").write_bytes(
        plistlib.dumps(
            {"Label": "com.example.bin", "ProgramArguments": ["/bin/echo"]},
            fmt=plistlib.FMT_BINARY,
        )
    )

    trivy_sarif = tmp_path / "trivy.sarif.json"
    trivy_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "Trivy",
                                "rules": [
                                    {
                                        "id": "aws-access-key-id",
                                        "shortDescription": {"text": "AWS Access Key ID"},
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "aws-access-key-id",
                                "level": "error",
                                "properties": {"category": "secret"},
                                "message": {
                                    "text": f"Secret CUSTOM_LEAK_999\nMatch: {'AKIA'}{'IOSFODNN7EXAMPLE'}"
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    scan_out = tmp_path / "dos_scan.json"
    comp_out = tmp_path / "dos_companion.json"
    t0 = time.monotonic()
    rc, _out, err = run_cli(
        [
            "scan",
            str(repo),
            "--trivy-report",
            str(trivy_sarif),
            "--companion-out",
            str(comp_out),
            "--json",
            str(scan_out),
        ]
    )
    elapsed = time.monotonic() - t0
    assert rc == 0, err
    assert elapsed < 3.0, f"Scan took too long: {elapsed:.2f}s"
    comp_text = comp_out.read_text(encoding="utf-8")
    assert "CUSTOM_LEAK_999" not in comp_text
    assert f"{'AKIA'}{'IOSFODNN7EXAMPLE'}" not in comp_text


def test_tier3_f02_f14_cpsat_and_agent_harness_via_plugin_cli_args_bounded(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F02 + F14: cpsat chained ast.Mult & agent-harness string doubling complete boundedly."""
    del e2e_env
    solver_lines = ["from ortools.sat.python import cp_model", "x0 = 2"]
    for idx in range(1, 31):
        solver_lines.append(f"x{idx} = x{idx - 1} * x{idx - 1}")
    solver_lines.append("y = int(1e200 * 1e200)")

    prompt_lines = ['s0 = "x"']
    for idx in range(1, 26):
        prompt_lines.append(f"s{idx} = s{idx - 1} + s{idx - 1}")

    repo = tmp_path / "plugin_dos_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        extra_files={
            "backend/app/solver.py": "\n".join(solver_lines) + "\n",
            "backend/app/prompts.py": "\n".join(prompt_lines) + "\n",
        },
    )

    out_json = tmp_path / "plugin_dos.json"
    t0 = time.monotonic()
    rc, _out, err = run_cli(
        [
            "scan",
            str(repo),
            "--json",
            str(out_json),
            *plugin_cli_args("cpsat", "agent-harness"),
        ]
    )
    elapsed = time.monotonic() - t0
    assert rc == 0, err
    assert elapsed < 3.0, f"Plugin scan took too long: {elapsed:.2f}s"
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["coverage_complete"] is True


def test_tier3_f03_f12_revoked_ruling_on_truth004_and_strict_ignores_fallback_allowlist(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """F03 + F12: revoked ruling keeps TRUTH-004 & --strict ignores allowlist."""
    del e2e_env
    repo = tmp_path / "revoked_allowlist_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        backend_main=(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/api/v1/slices/tx')\n"
            "def tx():\n"
            "    return {'items': []}\n"
        ),
        extra_files={
            "backend/app/services/cache.py": (
                "import redis\n"
                "redis_client = redis.Redis()\n"
                "def put_cfg():\n"
                "    redis_client.set('cfg:mode', 'active')\n"
            ),
            "frontend/views/tx.js": (
                "export async function renderActions(c) {\n"
                "  const d = await c.fetchSlice('tx');\n"
                "  if (!d.items.length) {\n"
                "    return [{ id: '1', title: 'Approve', action: 'approve' }];\n"
                "  }\n"
                "  return d.items;\n"
                "}\n"
            ),
        },
    )
    old_sha = init_git_repo(repo, {}, commit_msg="initial")
    (repo / "README.md").write_text("# v2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "v2"],
        check=True,
        capture_output=True,
    )
    head_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    (repo / ".wythe").mkdir(parents=True, exist_ok=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "fabricated_fallback_allowlist": ["frontend/views/tx.js"],
                "audit_rulings": [
                    {
                        "node_id": "t:redis:cfg",
                        "disposition": "accepted_clean",
                        "summary": "Old persistent config ruling",
                        "store_purpose": {
                            "intended_use": "persistent_config",
                            "recovery_expectation": "seeded",
                        },
                        "audited_commit": old_sha,
                        "recorded_by": "reviewer",
                    },
                    {
                        "node_id": "t:redis:cfg",
                        "disposition": "revoked",
                        "summary": "Revoked after audit",
                        "audited_commit": head_sha,
                        "recorded_by": "reviewer",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    rc_sync, _out, err = run_cli(["sync-config", str(repo)])
    assert rc_sync == 0, err

    scan_out = tmp_path / "strict_revoked.json"
    rc_scan, _out, err = run_cli(["scan", str(repo), "--strict", "--json", str(scan_out)])
    assert rc_scan == 0, err
    report = json.loads(scan_out.read_text(encoding="utf-8"))
    rules = {f["rule_code"] for f in report["findings"]}
    assert "TRUTH-004" in rules
    assert "DISP-010" in rules

    rc_gate, _out, _err = run_cli(["gate", "--strict", "--sync-config", str(repo)])
    assert rc_gate == 1


def test_tier3_f05_f16_tailnet_host_allowlist_cross_port_csrf_tokens_and_version(
    e2e_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F05 + F16: Tailnet Host allowlist + cross-port CSRF + zero internal tokens + `--version`."""
    monkeypatch.setenv("WYTHE_ALLOWED_HOSTS", "tailnet")
    ok_resp = e2e_client.get("/healthz", headers={"Host": "devnode.ts.net:8780"})
    assert ok_resp.status_code == 200
    _assert_security_headers(ok_resp)

    bad_host = e2e_client.get("/healthz", headers={"Host": "evil.example:8780"})
    assert bad_host.status_code == 400
    _assert_security_headers(bad_host)

    csrf_resp = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "x", "name": "x", "repo_path": "/tmp/x"},
        headers={
            "Host": "127.0.0.1:8780",
            "Origin": "http://127.0.0.1:9999",
            "Sec-Fetch-Site": "same-site",
        },
    )
    assert csrf_resp.status_code == 403
    _assert_security_headers(csrf_resp)

    rc_ver, out_ver, err_ver = run_cli(["--version"])
    assert rc_ver == 0, err_ver
    assert "0.2.9" in out_ver

    e2e_dir = Path(__file__).resolve().parent
    forbidden = _forbidden_internal_tokens()
    for py_file in e2e_dir.glob("*.py"):
        text = py_file.read_text(encoding="utf-8").lower()
        for tok in forbidden:
            assert tok not in text, f"Forbidden token {tok!r} found in {py_file.name}"


# ---------------------------------------------------------------------------
# Tier 4 — Real-World Application Scenarios (>=8 full end-to-end workloads)
# ---------------------------------------------------------------------------


def test_tier4_scenario1_hostile_untrusted_pr_ci_gate(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Scenario 1: Hostile untrusted PR CI gate blocks git RCE, shadowed plugin, and waivers."""
    repo = tmp_path / "hostile_pr_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        schema_sql="CREATE TABLE policy_cfg (id INT PRIMARY KEY, max_cap INT);\n",
        backend_main=(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/api/v1/slices/tx')\n"
            "def tx():\n"
            "    return {'items': []}\n"
        ),
        extra_files={
            "backend/adapters/policy_shim.py": "HARDCODED_MAX_CAP = 88\n",
            "frontend/views/tx.js": (
                "export async function renderActions(c) {\n"
                "  const d = await c.fetchSlice('tx');\n"
                "  if (!d.items.length) {\n"
                "    return [{ id: '1', title: 'Override', action: 'override' }];\n"
                "  }\n"
                "  return d.items;\n"
                "}\n"
            ),
        },
    )
    (repo / ".wythe").mkdir(parents=True, exist_ok=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "fabricated_fallback_allowlist": ["frontend/views/tx.js"],
                "ratchet_baselines": [
                    {
                        "rule_code": "MANIP-001",
                        "max_allowed_count": 50,
                        "recorded_commit": "HEAD",
                        "recorded_by": "pr-author",
                    }
                ],
                "audit_rulings": [
                    {
                        "node_id": "m:service:backend/adapters/policy_shim.py",
                        "disposition": "accepted_clean",
                        "summary": "Waive in PR",
                        "audited_commit": "HEAD",
                        "recorded_by": "pr-author",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    plugin_rce_marker = tmp_path / "hostile_plugin_rce.txt"
    (repo / "wythe_plugin_binary.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(plugin_rce_marker)!r}).write_text('pwned', encoding='utf-8')\n"
        "def register_wythe_plugin():\n"
        "    return None\n",
        encoding="utf-8",
    )
    init_git_repo(repo, {}, commit_msg="hostile pr")

    git_rce_marker = tmp_path / "hostile_git_rce.txt"
    git_cfg = repo / ".git" / "config"
    orig_git_cfg = git_cfg.read_text(encoding="utf-8")
    git_cfg.write_text(
        orig_git_cfg
        + f'\n[filter "pwn"]\n\tclean = touch {git_rce_marker}\n'
        + f'[log]\n\tshowSignature = true\n[gpg]\n\tprogram = touch {git_rce_marker}\n',
        encoding="utf-8",
    )

    userbase = tmp_path / "userbase_hostile"
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
    py_path = os.pathsep.join(
        [str(_BACKEND_DIR), str(site_dir), *(str(p) for p in _PLUGIN_SRC_DIRS)]
    )
    sub_env = {
        "PYTHONUSERBASE": str(userbase),
        "PYTHONPATH": py_path,
        "WYTHE_DATABASE_URL": e2e_env["db_url"],
        "WYTHE_STATE_DIR": str(e2e_env["state_dir"]),
    }

    rc_diff, _out, _err = run_cli_subprocess(
        ["diff", ".", "--base", "HEAD"], cwd=repo, env_overrides=sub_env
    )
    rc_gate_git, _out, _err = run_cli_subprocess(
        ["gate", "--strict", "."], cwd=repo, env_overrides=sub_env
    )
    assert rc_diff == 2
    assert rc_gate_git in (1, 2)
    assert not git_rce_marker.exists()

    git_cfg.write_text(orig_git_cfg, encoding="utf-8")
    rc_gate, _out, _err = run_cli_subprocess(
        ["gate", "--strict", "--sync-config", "."],
        cwd=repo,
        env_overrides=sub_env,
    )
    assert not plugin_rce_marker.exists()
    assert rc_gate in (1, 2)


def test_tier4_scenario2_multi_ref_ci_governance_lifecycle(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Scenario 2: Multi-ref CI `--trusted-config-ref`, cleanup & pure-addition diff."""
    del e2e_env
    repo = tmp_path / "multi_ref_ci"
    _write_minimal_fastapi_nextjs_repo(repo)
    empty_cfg_sha = init_git_repo(repo, {}, commit_msg="no gov yet")

    (repo / ".wythe").mkdir(parents=True, exist_ok=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "TRUTH-004",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "base-maintainer",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "trusted base"],
        check=True,
        capture_output=True,
    )
    base_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "rule_overrides": [
                    {
                        "rule_code": "DISP-004",
                        "severity": "info",
                        "enabled": False,
                        "blocks_gate": False,
                        "updated_by": "pr-attacker",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P(){ void fetch('/api/unbacked'); return <div/>; }\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "pr head"],
        check=True,
        capture_output=True,
    )
    head_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    rc_gate, _out, _err = run_cli(
        ["gate", "--sync-config", "--trusted-config-ref", base_sha, str(repo)]
    )
    assert rc_gate == 1

    rc_clear, _out, err = run_cli(
        ["sync-config", str(repo), "--trusted-config-ref", empty_cfg_sha]
    )
    assert rc_clear == 0, err
    exported_cfg = tmp_path / "exported_after_clear.json"
    rc_exp, _out, err = run_cli(["export-config", str(repo), "--out", str(exported_cfg)])
    assert rc_exp == 0, err
    bundle = json.loads(exported_cfg.read_text(encoding="utf-8"))
    truth004_rows = [r for r in bundle["rule_overrides"] if r["rule_code"] == "TRUTH-004"]
    assert truth004_rows and truth004_rows[0]["enabled"] is True

    (repo / "backend" / "app" / "new_pure_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "pure addition"],
        check=True,
        capture_output=True,
    )
    diff_json = tmp_path / "pure_add_diff.json"
    rc_diff, _out, err = run_cli(
        ["diff", str(repo), "--base", head_sha, "--json", str(diff_json)]
    )
    assert rc_diff == 0, err
    assert json.loads(diff_json.read_text(encoding="utf-8"))["diff_verdict"] == "PASS"

    action_text = (_REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    for event_name in ("pull_request", "pull_request_target", "merge_group"):
        assert event_name in action_text
    assert "--trusted-config-ref" in action_text


def test_tier4_scenario3_live_wythe_serve_tailnet_and_ipv6_browser_session(
    e2e_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Scenario 3: Tailnet + IPv6 `[::1]:8780` session, CSRF, GET guard, SSRF & LLM."""
    monkeypatch.setenv("WYTHE_ALLOWED_HOSTS", "tailnet")
    repo = tmp_path / "serve_session_repo"
    _write_minimal_fastapi_nextjs_repo(repo)
    ipv6_headers = {
        "Host": "[::1]:8780",
        "Origin": "http://[::1]:8780",
        "X-Wythe-Client": "1",
    }

    reg_resp = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "live-serve", "name": "Live Serve", "repo_path": str(repo)},
        headers=ipv6_headers,
    )
    assert reg_resp.status_code == 201, reg_resp.text
    _assert_security_headers(reg_resp)

    scan_post = e2e_client.post("/api/v1/scans/live-serve", headers=ipv6_headers)
    assert scan_post.status_code == 200, scan_post.text
    _assert_security_headers(scan_post)

    scan_get_persist = e2e_client.get(
        "/api/v1/scans/live-serve?persist=true",
        headers={"Host": "[::1]:8780"},
    )
    assert scan_get_persist.status_code == 400
    _assert_security_headers(scan_get_persist)

    assert e2e_client.get("/api/v1/targets", headers={"Host": "dev.ts.net:8780"}).status_code == 200
    assert e2e_client.get("/api/v1/targets", headers={"Host": "100.64.0.5:8780"}).status_code == 200
    bad_host_resp = e2e_client.get("/api/v1/targets", headers={"Host": "attacker.com:8780"})
    assert bad_host_resp.status_code == 400

    cross_port = e2e_client.post(
        "/api/v1/scans/live-serve",
        headers={"Host": "127.0.0.1:8780", "Origin": "http://127.0.0.1:9999"},
    )
    assert cross_port.status_code == 403

    ssrf_ask = e2e_client.post(
        "/api/v1/ask",
        json={
            "question": "Explain routes",
            "engine": "local",
            "target_slug": "live-serve",
            "local_base_url": "http://[2002:0808:0808::1]:8080",
        },
        headers=ipv6_headers,
    )
    assert ssrf_ask.status_code == 422

    class _NonDictLlmHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            body = b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _NonDictLlmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        local_url = f"http://127.0.0.1:{server.server_port}/v1"
        engines_resp = e2e_client.get(
            "/api/v1/ask/engines",
            params={"local_base_url": local_url},
            headers={"Host": "[::1]:8780"},
        )
        assert engines_resp.status_code == 200
        ask_resp = e2e_client.post(
            "/api/v1/ask",
            json={
                "question": "Explain routes",
                "engine": "local",
                "target_slug": "live-serve",
                "local_base_url": local_url,
                "local_model_id": "test-model",
            },
            headers=ipv6_headers,
        )
        assert ask_resp.status_code != 500
    finally:
        server.shutdown()
        server.server_close()


def test_tier4_scenario4_full_fastapi_nextjs_epistemic_and_route_audit(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Scenario 4: FastAPI+Next.js app passes strict gate, then .replace() flips PASS->FAIL."""
    del e2e_env
    repo = tmp_path / "full_epistemic_app"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        backend_main=(
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
            "@app.get('/api/a')\n"
            "def get_a():\n"
            "    return {'alpha_status': 'ok'}\n"
            "@app.get('/api/b')\n"
            "def get_b():\n"
            "    return {'beta_status': 'ok'}\n"
            "@app.get('/api/orders')\n"
            "@app.put('/api/orders')\n"
            "def orders():\n"
            "    return {'ok': True}\n"
            "@app.head('/api/health')\n"
            "@app.options('/api/health')\n"
            "def health():\n"
            "    return {'ok': True}\n"
            "@app.get('/api/v1/slices/tx')\n"
            "def tx():\n"
            "    return {'transactionLabel': 'Posted'}\n"
        ),
        frontend_tsx=(
            "export default function App({ isEdit }: { isEdit: boolean }) {\n"
            "  void fetch('/api/orders', { method: isEdit ? 'PUT' : 'POST' });\n"
            "  void fetch('/api/health', { method: 'HEAD' });\n"
            "  void fetch('/api/health', { method: 'OPTIONS' });\n"
            "  return <main>ok</main>;\n"
            "}\n"
            "export async function loadItems() {\n"
            "  const r = await fetch('/api/items');\n"
            "  const d = await r.json();\n"
            "  return d.status;\n"
            "}\n"
        ),
        extra_files={
            "backend/app/builders.py": (
                "import json\n"
                "def build_tx(state_path):\n"
                "    src = json.loads(state_path.read_text())\n"
                "    return {\n"
                "        'observed_at': src.get('observed_at'),\n"
                "        'transactionLabel': src.get('label'),\n"
                "    }\n"
                "SLICE_BUILDERS = {'tx': build_tx}\n"
            ),
            "frontend/views/two.js": (
                "export async function fnA() {\n"
                "  const data = await (await fetch('/api/a')).json();\n"
                "  return data.alpha_status;\n"
                "}\n"
                "export async function fnB() {\n"
                "  const data = await (await fetch('/api/b')).json();\n"
                "  return data.beta_status;\n"
                "}\n"
            ),
            "frontend/views/tx.js": (
                "export async function renderTx(client) {\n"
                "  const data = await client.fetchSlice('tx');\n"
                "  return data.transactionLabel ?? 'Standard';\n"
                "}\n"
            ),
        },
    )

    clean_json = tmp_path / "scenario4_clean.json"
    rc_scan1, _out, err = run_cli(["scan", str(repo), "--strict", "--json", str(clean_json)])
    assert rc_scan1 == 0, err
    rep1 = json.loads(clean_json.read_text(encoding="utf-8"))
    rules1 = [f["rule_code"] for f in rep1["findings"]]
    assert "DISP-009" in rules1
    assert "DISP-004" not in rules1
    assert "DISP-010" not in rules1
    assert "DISP-011" not in rules1

    rc_gate1, _out, _err = run_cli(["gate", "--strict", str(repo)])
    assert rc_gate1 == 0

    (repo / "backend" / "app" / "builders.py").write_text(
        "import json\n"
        "from datetime import datetime, timezone\n"
        "def build_tx(state_path):\n"
        "    src = json.loads(state_path.read_text())\n"
        "    return {\n"
        "        'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),\n"
        "        'transactionLabel': src.get('label'),\n"
        "    }\n"
        "SLICE_BUILDERS = {'tx': build_tx}\n",
        encoding="utf-8",
    )
    fail_json = tmp_path / "scenario4_fail.json"
    rc_scan2, _out, err = run_cli(["scan", str(repo), "--strict", "--json", str(fail_json)])
    assert rc_scan2 == 0, err
    rep2 = json.loads(fail_json.read_text(encoding="utf-8"))
    assert any(f["rule_code"] == "MANIP-007" and f["blocks_gate"] for f in rep2["findings"])
    rc_gate2, _out, _err = run_cli(["gate", "--strict", str(repo)])
    assert rc_gate2 == 1


def test_tier4_scenario5_live_investigation_packed_refs_viewport_and_mcp_stdio(
    e2e_client: TestClient,
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Scenario 5: Packed-refs repo + MCP stdio session + `#103`/`#106` lifecycle & isolation."""
    repo_a = tmp_path / "proj-a"
    repo_b = tmp_path / "proj-b"
    main_lines = "\n".join(
        ["from fastapi import FastAPI", "app = FastAPI()", *[f"LINE_{i} = {i}" for i in range(40)]]
    )
    _write_minimal_fastapi_nextjs_repo(
        repo_a,
        backend_main=main_lines + "\n",
        extra_files={"secrets.yaml": "token: secret\n"},
    )
    _write_minimal_fastapi_nextjs_repo(repo_b)
    init_git_repo(repo_a, {})
    subprocess.run(
        ["git", "-C", str(repo_a), "pack-refs", "--all"],
        check=True,
        capture_output=True,
    )
    _register_target_http(e2e_client, "proj-a", repo_a)
    _register_target_http(e2e_client, "proj-b", repo_b)

    cites = " ".join(f"`backend/app/main.py:{i}`" for i in range(1, 36))
    frames = _run_mcp_stdio(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "wythe_investigation",
                    "arguments": {
                        "action": "create_session",
                        "target": "proj-a",
                        "session_id": "sess-mcp-a",
                        "title": "Scenario 5",
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "wythe_investigation",
                    "arguments": {
                        "action": "record_turn",
                        "target": "proj-a",
                        "session_id": "sess-mcp-a",
                        "answer_markdown": f"Citations: {cites}",
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "wythe_focus_camera",
                    "arguments": {
                        "target": "proj-a",
                        "session_id": "sess-mcp-a",
                        "lens": "status",
                    },
                },
            },
        ],
        e2e_env=e2e_env,
    )
    tool_names = {t["name"] for t in frames[1]["result"]["tools"]}
    assert {"wythe_investigation", "wythe_focus_camera"}.issubset(tool_names)
    turn_receipt = _extract_embedded_json(frames[3]["result"]["content"][0]["text"])
    ref_map = {r["ref_id"]: r["validation_state"] for r in turn_receipt["validated_references"]}
    assert len(ref_map) == 33
    assert ref_map.get("backend/app/main.py:32") == "validated"
    assert ref_map.get("citation:truncated") == "unresolved"

    # #106 expired paused_by_human
    exp_ts = (datetime.now(UTC) + timedelta(milliseconds=150)).isoformat()
    e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "proj-a",
            "session_id": "sess-mcp-a",
            "command_id": "cmd_s5_pause",
            "expires_at": exp_ts,
            "lens": "status",
        },
        headers={"X-Wythe-Client": "1"},
    )
    e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_s5_pause",
            "target_slug": "proj-a",
            "session_id": "sess-mcp-a",
            "client_id": "ui-1",
            "outcome": "paused_by_human",
        },
        headers={"X-Wythe-Client": "1"},
    )
    time.sleep(0.25)
    vp_state = e2e_client.get(
        "/api/v1/viewport/state",
        params={"target_slug": "proj-a", "session_id": "sess-mcp-a"},
    ).json()
    assert vp_state["latest"]["delivery_state"] == "expired"

    # #106 applied_by_browser non-downgrade
    e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "proj-a",
            "session_id": "sess-mcp-a",
            "command_id": "cmd_s5_apply",
            "lens": "gravity",
        },
        headers={"X-Wythe-Client": "1"},
    )
    e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_s5_apply",
            "target_slug": "proj-a",
            "session_id": "sess-mcp-a",
            "client_id": "ui-1",
            "outcome": "applied",
        },
        headers={"X-Wythe-Client": "1"},
    )
    downgrade = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_s5_apply",
            "target_slug": "proj-a",
            "session_id": "sess-mcp-a",
            "client_id": "ui-1",
            "outcome": "rejected",
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert downgrade.status_code in (200, 422)
    if downgrade.status_code == 200:
        assert downgrade.json()["delivery_state"] == "applied_by_browser"

    # Cross-target isolation
    cross = e2e_client.post(
        "/api/v1/viewport/command",
        json={"target_slug": "proj-b", "session_id": "sess-mcp-a", "lens": "status"},
        headers={"X-Wythe-Client": "1"},
    )
    assert cross.status_code == 422


def test_tier4_scenario6_full_understanding_and_agent_discordance_pipeline(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """Scenario 6: `#104` dict receipt, nested failure, injection & `#117` string-bool."""
    resp = e2e_client.post(
        "/api/v1/understanding/analyze",
        json={
            "bundle": {
                "source_revision": "rev-s6",
                "question": "Did delivery and perturbation checks pass?",
                "outcome_lifecycles": [
                    {
                        "outcome_id": "out-ok",
                        "subject_id": "sub-ok",
                        "delivery_status": "delivered",
                        "delivery_receipt": {"id": "rcpt-ok-1"},
                        "transitions": [
                            {"stage": "delivered_to_human", "producer": "gw", "state_digest": "d1"}
                        ],
                    },
                    {
                        "outcome_id": "out-bad",
                        "subject_id": "sub-bad",
                        "delivery_status": "delivered",
                        "delivery_receipt": {
                            "id": "rcpt-bad-1",
                            "detail": {"status": "failed", "delivered": False},
                        },
                        "transitions": [
                            {
                                "stage": "committed_unacknowledged",
                                "producer": "gw",
                                "state_digest": "d2",
                            }
                        ],
                    },
                ],
                "verdict_clauses": [
                    {
                        "clause_id": "c)[evil](javascript:alert(1))(",
                        "text": "Unverified [link] injection",
                        "state": "unverified",
                        "evidence_ref": "javascript:alert(1)",
                    }
                ],
                "perturbation_matrix": [
                    {
                        "case_id": "p-1",
                        "label": "Isolation perturbation",
                        "varied_factor": "principal_scope",
                        "expected_outcome": "blocked",
                        "observed_outcome": "leaked",
                        "decisive_receipt_ref": "rcpt-pert-1",
                        "passed": True,
                    }
                ],
            }
        },
        headers={"X-Wythe-Client": "1"},
    )
    assert resp.status_code == 200, resp.text
    report = resp.json()
    assert "javascript:" not in report["verdict_markdown"].lower()
    assert report["perturbation_matrix"][0]["passed"] is False
    assert report["perturbation_matrix"][0]["conclusion_state"] == "failed_regression"
    bad_lc = next(lc for lc in report["outcome_lifecycles"] if lc["outcome_id"] == "out-bad")
    assert bad_lc["current_stage"] != "delivered_to_human"

    repo = tmp_path / "discordance_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        extra_files={
            ".wythe/agent_routes.json": json.dumps(
                {
                    "routes": [
                        {
                            "route_id": "r-owner",
                            "agent_id": "agent-alpha",
                            "principal_scope": "owner",
                            "canary_task_id": "task-owner-secret",
                            "explicit_privacy_boundary": "false",
                        },
                        {
                            "route_id": "r-guest",
                            "agent_id": "agent-beta",
                            "principal_scope": "guest",
                            "explicit_privacy_boundary": "false",
                        },
                    ]
                }
            ),
            ".wythe/agent_receipts.json": json.dumps(
                {
                    "observations": [
                        {
                            "route_id": "r-guest",
                            "caller_receipt_id": "rcpt-g",
                            "authz_receipt_id": "authz-g",
                            "observed_agent_id": "agent-beta",
                            "canary_recovered": "true",
                            "accessed_task_id": "task-owner-secret",
                        }
                    ]
                }
            ),
        },
    )
    scan_out = tmp_path / "discordance_scan.json"
    rc, _out, err = run_cli(
        [
            "scan",
            str(repo),
            "--json",
            str(scan_out),
            *plugin_cli_args("agent-discordance"),
        ]
    )
    assert rc == 0, err
    scan_rep = json.loads(scan_out.read_text(encoding="utf-8"))
    assert any(f["rule_code"] == "DISC-002" and f["blocks_gate"] for f in scan_rep["findings"])


def test_tier4_scenario7_hostile_dos_companion_security_and_wiretap_redaction(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Scenario 7: All DoS vectors + binary plist + Trivy SARIF/JSON + Wiretap OTel redaction."""
    del e2e_env
    dag_lines = ['a0: &a0 {command: "echo ok"}']
    for idx in range(1, 26):
        dag_lines.append(f"a{idx}: &a{idx} [*a{idx - 1}, *a{idx - 1}]")
    dag_lines.append("tools: *a25")

    repo = tmp_path / "hostile_dos_wiretap"
    deep_paren = ("(" * 1100) + "1" + (")" * 1100)
    _write_minimal_fastapi_nextjs_repo(
        repo,
        frontend_tsx=(
            f"export default function P() {{ const v = {deep_paren}; return <div>{{v}}</div>; }}\n"
        ),
        extra_files={
            "schema.sql": "CREATE TABLE jobs (id INT PRIMARY KEY);\n",
            "services/worker.py": "def run_job() -> str:\n    return 'ok'\n",
            "config/dag.yaml": "\n".join(dag_lines) + "\n",
            "Dockerfile": (
                "FROM python:3.12-slim\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                'CMD ["python", "/app/backend/a/b/c/d/e/f/g/h/target.py"]\n'
            ),
            ".dockerignore": ("**/" * 18) + "target.py\n",
            "backend/a/b/c/d/e/f/g/h/target.py": "X = 1\n",
            "tach.toml": (
                'source_roots = ["backend"]\n'
                'exclude = ["backend/app/(a+)+b"]\n'
                "[[modules]]\n"
                'path = "app"\n'
                "depends_on = []\n"
            ),
            "backend/app/aaaaaaaaaaaaaaaaaaaaaaaaaac.py": "X = 1\n",
        },
    )
    (repo / "launchd").mkdir(parents=True, exist_ok=True)
    (repo / "launchd" / "bin.plist").write_bytes(
        plistlib.dumps(
            {"Label": "com.example.dos", "ProgramArguments": ["/bin/echo"]},
            fmt=plistlib.FMT_BINARY,
        )
    )

    trivy_sarif = tmp_path / "s7.sarif.json"
    trivy_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Trivy", "rules": []}},
                        "results": [
                            {
                                "ruleId": "generic-secret",
                                "level": "error",
                                "properties": {"category": "secret"},
                                "message": {
                                    "text": f"Secret CUSTOM_LEAK_999\nMatch: {'AKIA'}{'IOSFODNN7EXAMPLE'}"
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    trivy_json = tmp_path / "s7.trivy.json"
    trivy_json.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "app.env",
                        "Secrets": [
                            {
                                "RuleID": "generic-api-key",
                                "Severity": "HIGH",
                                "Title": "Secret Leak Match: TRIVY_JSON_SECRET_TOKEN",
                                "Match": "TRIVY_JSON_SECRET_TOKEN",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    otel_json = tmp_path / "s7.otel.json"
    otel_json.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "traceId": "0123456789abcdef0123456789abcdef",
                                        "spanId": "0123456789abcdef",
                                        "name": "DB SELECT users WHERE pw = 'SPAN_NAME_SECRET'",
                                        "attributes": [
                                            {
                                                "key": "exception.message",
                                                "value": {
                                                    "stringValue": (
                                                        "Fail:\nSELECT * FROM users\n"
                                                        "WHERE pw = 'MULTILINE_SQL_SECRET'"
                                                    )
                                                },
                                            },
                                            {
                                                "key": "headers",
                                                "value": {
                                                    "arrayValue": {
                                                        "values": [
                                                            {
                                                                "stringValue": (
                                                                    "Authorization: Bearer "
                                                                    "VALUES_LIST_SECRET"
                                                                )
                                                            }
                                                        ]
                                                    }
                                                },
                                            },
                                            {
                                                "key": "url.full",
                                                "value": {
                                                    "stringValue": "https://api.example.com/v1/x?RAW_SECRET_TOKEN"
                                                },
                                            },
                                            {
                                                "key": "http.url",
                                                "value": {
                                                    "stringValue": "https://api.example.com:badport/v1/x?token=BADPORT_SECRET"
                                                },
                                            },
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    comp1 = tmp_path / "comp_sarif.json"
    comp2 = tmp_path / "comp_trivy_json.json"
    comp3 = tmp_path / "comp_otel.json"
    t0 = time.monotonic()
    rc1, _o1, e1 = run_cli(
        [
            "scan",
            str(repo),
            "--profile",
            "python-services-nextjs",
            "--trivy-report",
            str(trivy_sarif),
            "--companion-out",
            str(comp1),
        ]
    )
    rc2, _o2, e2 = run_cli(
        ["companion", str(repo), "--trivy-report", str(trivy_json), "--json", str(comp2)]
    )
    rc3, _o3, e3 = run_cli(
        [
            "companion",
            str(repo),
            "--otel-traces",
            str(otel_json),
            "--json",
            str(comp3),
            *plugin_cli_args("wiretap"),
        ]
    )
    elapsed = time.monotonic() - t0
    assert rc1 == 0, e1
    assert rc2 == 0, e2
    assert rc3 == 0, e3
    assert elapsed < 5.0, f"Hostile DoS/companion pipeline exceeded budget: {elapsed:.2f}s"

    combined_out = "\n".join(p.read_text(encoding="utf-8") for p in (comp1, comp2, comp3))
    for secret in (
        "CUSTOM_LEAK_999",
        f"{'AKIA'}{'IOSFODNN7EXAMPLE'}",
        "TRIVY_JSON_SECRET_TOKEN",
        "SPAN_NAME_SECRET",
        "MULTILINE_SQL_SECRET",
        "VALUES_LIST_SECRET",
        "RAW_SECRET_TOKEN",
        "BADPORT_SECRET",
    ):
        assert secret not in combined_out, f"Secret leaked in companion output: {secret}"


def test_tier4_scenario8_sqlalchemy_alembic_policy_consumption_and_ruling_lifecycle(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Scenario 8: SQLAlchemy + Alembic + ARRAY[']'] + ruling revocation."""
    del e2e_env
    repo = tmp_path / "sqlalchemy_ruling_repo"
    _write_minimal_fastapi_nextjs_repo(
        repo,
        schema_sql=(
            "CREATE SCHEMA billing;\n"
            "CREATE TABLE billing.invoices (id INT PRIMARY KEY);\n"
            "CREATE TABLE policy_configs (id INT PRIMARY KEY, max_cap INT);\n"
        ),
        extra_files={
            "backend/app/models.py": (
                "from sqlalchemy import Column, Integer, String\n"
                "from sqlalchemy.orm import declarative_base\n"
                "PrimaryBase = declarative_base()\n"
                "SecondaryBase = declarative_base()\n"
                "class Invoice(PrimaryBase):\n"
                "    __tablename__ = 'invoices'\n"
                "    __table_args__ = {'schema': 'billing'}\n"
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
                "class PolicyConfig(PrimaryBase):\n"
                "    __tablename__ = 'policy_configs'\n"
                "    id = Column(Integer, primary_key=True)\n"
                "    max_cap = Column(Integer)\n"
            ),
            "backend/alembic/versions/001.py": (
                "from app.models import PrimaryBase\n"
                "def upgrade(bind):\n"
                "    PrimaryBase.metadata.create_all(bind=bind)\n"
            ),
            "backend/alembic/versions/002.py": (
                "import sqlalchemy as sa\n"
                "from alembic import op\n"
                "def upgrade():\n"
                "    op.add_column('invoices', sa.Column('note', sa.String()), schema='billing')\n"
            ),
            "backend/app/services/pg.py": (
                "from sqlalchemy import text\n"
                "from app.models import PolicyConfig\n"
                "HARDCODED_CAP = 50\n"
                "def load_cap(session):\n"
                "    _row = session.get(PolicyConfig, 1)\n"
                "    session.execute(text(\"SELECT ARRAY[']'], max_cap FROM policy_configs\"))\n"
                "    return HARDCODED_CAP\n"
            ),
            "backend/app/adapters/policy_shim.py": (
                "from app.models import PolicyConfig\n"
                "HARDCODED_ADAPTER_CAP = 99\n"
                "def resolve_cap(session):\n"
                "    _row = session.get(PolicyConfig, 1)\n"
                "    return HARDCODED_ADAPTER_CAP\n"
            ),
            "backend/app/services/cache.py": (
                "import redis\n"
                "redis_client = redis.Redis()\n"
                "def put_cfg():\n"
                "    redis_client.set('cfg:mode', 'active')\n"
            ),
        },
    )
    old_sha = init_git_repo(repo, {}, commit_msg="v1")
    (repo / "README.md").write_text("# v2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "-m", "v2"],
        check=True,
        capture_output=True,
    )
    head_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    (repo / ".wythe").mkdir(parents=True, exist_ok=True)
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target_slug": repo.name,
                "exported_at": "2026-11-20T00:00:00Z",
                "audit_rulings": [
                    {
                        "node_id": "t:redis:cfg",
                        "disposition": "accepted_clean",
                        "summary": "Initial persistent config waiver",
                        "store_purpose": {
                            "intended_use": "persistent_config",
                            "recovery_expectation": "seeded",
                        },
                        "audited_commit": old_sha,
                        "recorded_by": "reviewer",
                    },
                    {
                        "node_id": "t:redis:cfg",
                        "disposition": "revoked",
                        "summary": "Revoked after audit",
                        "audited_commit": head_sha,
                        "recorded_by": "reviewer",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    out_json = tmp_path / "scenario8_scan.json"
    rc_sync, _out, err = run_cli(["sync-config", str(repo)])
    assert rc_sync == 0, err
    rc_scan, _out, err = run_cli(["scan", str(repo), "--json", str(out_json)])
    assert rc_scan == 0, err
    rep = json.loads(out_json.read_text(encoding="utf-8"))
    found_rules = {f["rule_code"] for f in rep["findings"]}
    assert "TRUTH-002" in found_rules
    assert "MANIP-001" in found_rules
    assert "TRUTH-004" in found_rules

    rc_gate, _out, _err = run_cli(["gate", "--strict", "--sync-config", str(repo)])
    assert rc_gate == 1
