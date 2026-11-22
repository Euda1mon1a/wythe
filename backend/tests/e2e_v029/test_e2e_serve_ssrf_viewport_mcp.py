"""Opaque-box E2E tests for Wythe v0.2.9: F05, F06, F07, F08, and F10.

Covers:
- F05 (A2, P1-6): wythe serve Host allowlist, CSRF, security headers & GET read-only
- F06 (P1-9): SSRF CIDR allowlist, gzip bomb & non-dict JSON handling
- F07 (P1-1, P1-13): #103 citations, .git/packed-refs & secret path blocking
- F08 (P1-12, P1-13): #106 viewport bus, cross-target isolation & snapshot hydration
- F10 (P1-7): MCP tools (11 full / 4 slm) & stdio framing DoS protection
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.e2e_v029.conftest import init_git_repo, run_cli
from wythe_plugin_wiretap import wiretap_inspection_scope

_REPO_ROOT = Path(__file__).resolve().parents[3]
_BACKEND_DIR = _REPO_ROOT / "backend"
_PLUGIN_SRC_DIRS = tuple(sorted((_REPO_ROOT / "plugins").glob("*/src")))

_SEC_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "frame-ancestors 'none'",
}

_CLEAN_MAIN_PY = (
    "from fastapi import FastAPI\n"
    "app = FastAPI()\n"
    "@app.get('/api/items')\n"
    "def get_items():\n"
    "    return {'ok': True}\n"
)

_CLEAN_MODELS_PY = (
    "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
    "class Base(DeclarativeBase):\n"
    "    pass\n"
    "class Item(Base):\n"
    "    __tablename__ = 'items'\n"
    "    id: Mapped[int] = mapped_column(primary_key=True)\n"
)


def _assert_security_headers(headers: Any) -> None:
    for hdr, expected in _SEC_HEADERS.items():
        actual = headers.get(hdr)
        assert actual == expected, f"Expected {hdr}={expected!r}, got {actual!r}"


def _make_clean_repo(repo_dir: Path, extra_files: dict[str, str] | None = None) -> Path:
    files = {
        "backend/app/main.py": _CLEAN_MAIN_PY,
        "backend/app/models.py": _CLEAN_MODELS_PY,
    }
    if extra_files:
        files.update(extra_files)
    init_git_repo(repo_dir, files)
    return repo_dir


def _make_blocking_repo(
    repo_dir: Path,
    slug: str,
    *,
    with_disabled_override: bool = False,
) -> Path:
    files: dict[str, str] = {
        "backend/app/main.py": _CLEAN_MAIN_PY,
        "backend/app/models.py": _CLEAN_MODELS_PY,
        "frontend/package.json": json.dumps({"name": "fe", "dependencies": {"react": "18.3.0"}}),
        "frontend/src/app/page.tsx": (
            "export default function Page() { return fetch('/api/missing-endpoint'); }\n"
        ),
    }
    if with_disabled_override:
        bundle = {
            "schema_version": "1.0",
            "target_slug": slug,
            "exported_at": "2026-11-20T00:00:00Z",
            "rule_overrides": [
                {
                    "rule_code": "DISP-004",
                    "severity": "warning",
                    "enabled": False,
                    "blocks_gate": False,
                    "updated_by": "e2e-test",
                }
            ],
        }
        files[".wythe/governance.json"] = json.dumps(bundle, indent=2)
    init_git_repo(repo_dir, files)
    return repo_dir


def _register_target(
    client: TestClient,
    slug: str,
    repo_dir: Path,
    *,
    name: str | None = None,
) -> dict[str, Any]:
    resp = client.post(
        "/api/v1/targets",
        json={
            "slug": slug,
            "name": name or slug,
            "repo_path": str(repo_dir),
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


class _IPv6ThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


@contextlib.contextmanager
def _local_http_server(
    handler_cls: type[BaseHTTPRequestHandler],
    *,
    ipv6: bool = False,
) -> Iterator[tuple[str, int]]:
    server_cls = _IPv6ThreadingHTTPServer if ipv6 else ThreadingHTTPServer
    bind_host = "::1" if ipv6 else "127.0.0.1"
    srv = server_cls((bind_host, 0), handler_cls)
    port = int(srv.server_address[1])
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        host_fmt = "[::1]" if ipv6 else "127.0.0.1"
        yield f"http://{host_fmt}:{port}", port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2.0)


def _run_mcp_stdio(
    stdin_bytes: bytes,
    e2e_env: dict[str, Any],
    *,
    slice_mode: str = "full",
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    for legacy_var in ("TRUTH_ATLAS_DATABASE_URL", "TRUTH_ATLAS_STATE_DIR"):
        env.pop(legacy_var, None)
    env["WYTHE_DATABASE_URL"] = str(e2e_env["db_url"])
    env["WYTHE_STATE_DIR"] = str(e2e_env["state_dir"])
    py_paths = [str(_BACKEND_DIR), *(str(p) for p in _PLUGIN_SRC_DIRS)]
    existing_pp = env.get("PYTHONPATH", "")
    if existing_pp:
        py_paths.append(existing_pp)
    env["PYTHONPATH"] = os.pathsep.join(py_paths)
    return subprocess.run(
        [sys.executable, "-m", "app.cli", "mcp", "--slice", slice_mode],
        cwd=str(_REPO_ROOT),
        env=env,
        input=stdin_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _frame_content_length(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _parse_mcp_stdio_frames(raw: bytes) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    idx = 0
    n = len(raw)
    while idx < n:
        while idx < n and raw[idx : idx + 1] in (b"\r", b"\n", b" ", b"\t"):
            idx += 1
        if idx >= n:
            break
        if raw[idx : idx + 15].lower() == b"content-length:":
            hdr_end = raw.find(b"\r\n\r\n", idx)
            sep_len = 4
            if hdr_end == -1:
                hdr_end = raw.find(b"\n\n", idx)
                sep_len = 2
            assert hdr_end != -1, f"Malformed MCP header frame in {raw[idx:idx + 120]!r}"
            hdr_text = raw[idx:hdr_end].decode("ascii", errors="replace")
            length = None
            for line in hdr_text.splitlines():
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip())
                    break
            assert length is not None
            body_start = hdr_end + sep_len
            body_end = body_start + length
            messages.append(json.loads(raw[body_start:body_end].decode("utf-8")))
            idx = body_end
        else:
            nl = raw.find(b"\n", idx)
            line_bytes = raw[idx:] if nl == -1 else raw[idx:nl]
            idx = n if nl == -1 else nl + 1
            if line_bytes.strip():
                messages.append(json.loads(line_bytes.decode("utf-8")))
    return messages


# ---------------------------------------------------------------------------
# F05 (A2, P1-6): wythe serve Host Allowlist, CSRF, Security Headers & GET Read-Only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host_hdr", ["127.0.0.1:8780", "localhost:8780", "[::1]:8780"])
def test_f05_t1_loopback_hosts_allowed_on_healthz(e2e_client: TestClient, host_hdr: str) -> None:
    resp = e2e_client.get("/healthz", headers={"Host": host_hdr})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ok"


def test_f05_t1_tailnet_allowed_hosts_accepts_ts_net_and_cgnat(
    e2e_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del e2e_env
    monkeypatch.setenv("WYTHE_ALLOWED_HOSTS", "tailnet")
    with TestClient(create_app()) as client:
        for host_hdr in ("node.ts.net:8780", "100.64.1.2:8780"):
            resp = client.get("/healthz", headers={"Host": host_hdr})
            assert resp.status_code == 200, f"Host {host_hdr} failed: {resp.text}"
            assert resp.json()["status"] == "ok"


def test_f05_t1_same_origin_post_with_wythe_client_header_succeeds(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f05_same_origin")
    resp = e2e_client.post(
        "/api/v1/targets",
        headers={
            "Host": "127.0.0.1:8780",
            "Origin": "http://127.0.0.1:8780",
            "X-Wythe-Client": "1",
        },
        json={"slug": "f05-same-origin", "name": "F05 Same Origin", "repo_path": str(repo)},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["slug"] == "f05-same-origin"


def test_f05_t1_security_headers_present_on_get_and_post(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    get_resp = e2e_client.get("/healthz")
    assert get_resp.status_code == 200
    _assert_security_headers(get_resp.headers)

    repo = _make_clean_repo(tmp_path / "f05_sec_hdrs")
    post_resp = e2e_client.post(
        "/api/v1/targets",
        json={"slug": "f05-sec-hdrs", "name": "F05 Sec", "repo_path": str(repo)},
    )
    assert post_resp.status_code == 201
    _assert_security_headers(post_resp.headers)


def test_f05_t1_get_scans_readonly_and_post_scans_persists(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f05_ro_rw")
    _register_target(e2e_client, "f05-ro-rw", repo)

    get_scan = e2e_client.get("/api/v1/scans/f05-ro-rw")
    assert get_scan.status_code == 200, get_scan.text
    assert get_scan.json()["snapshot_id"] is None

    hist_before = e2e_client.get("/api/v1/scans/f05-ro-rw/history")
    assert hist_before.status_code == 200
    assert hist_before.json() == []

    post_scan = e2e_client.post("/api/v1/scans/f05-ro-rw")
    assert post_scan.status_code == 200, post_scan.text
    assert post_scan.json()["snapshot_id"] is not None

    hist_after = e2e_client.get("/api/v1/scans/f05-ro-rw/history")
    assert hist_after.status_code == 200
    assert len(hist_after.json()) == 1


def test_f05_t2_disallowed_host_returns_400_with_security_headers(e2e_client: TestClient) -> None:
    for path in ("/healthz", "/api/v1/targets"):
        resp = e2e_client.get(path, headers={"Host": "evil.example:8780"})
        assert resp.status_code == 400, f"{path}: {resp.status_code} {resp.text}"
        _assert_security_headers(resp.headers)


def test_f05_t2_ipv6_bracketed_host_and_origin_not_blocked_on_mcp_post(
    e2e_client: TestClient,
) -> None:
    resp = e2e_client.post(
        "/api/v1/mcp",
        headers={
            "Host": "[::1]:8780",
            "Origin": "http://[::1]:8780",
            "X-Wythe-Client": "1",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert resp.status_code != 403, f"IPv6 bracketed Origin falsely blocked: {resp.text}"
    assert resp.status_code == 200, resp.text
    assert resp.json()["id"] == 1


def test_f05_t2_cross_port_same_site_without_client_header_blocked_403(
    e2e_client: TestClient,
) -> None:
    resp = e2e_client.post(
        "/api/v1/mcp",
        headers={
            "Host": "127.0.0.1:8780",
            "Origin": "http://127.0.0.1:9999",
            "Sec-Fetch-Site": "same-site",
        },
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    assert resp.status_code == 403, f"Cross-port CSRF bypassed: {resp.status_code} {resp.text}"
    _assert_security_headers(resp.headers)


def test_f05_t2_sec_fetch_site_cross_site_blocked_403(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f05_cross_site")
    resp = e2e_client.post(
        "/api/v1/targets",
        headers={"Sec-Fetch-Site": "cross-site"},
        json={"slug": "f05-cross-site", "name": "Blocked", "repo_path": str(repo)},
    )
    assert resp.status_code == 403, resp.text
    _assert_security_headers(resp.headers)


@pytest.mark.parametrize(
    "content_type",
    [
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=----wythe",
        "text/plain",
    ],
)
def test_f05_t2_form_content_type_mutating_request_blocked_403(
    e2e_client: TestClient,
    content_type: str,
) -> None:
    resp = e2e_client.post(
        "/api/v1/targets",
        headers={"Content-Type": content_type},
        content=b"slug=evil&name=evil&repo_path=/tmp",
    )
    assert resp.status_code == 403, f"{content_type}: {resp.status_code} {resp.text}"
    _assert_security_headers(resp.headers)


def test_f05_t2_get_scans_persist_true_returns_400_and_no_snapshot(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f05_persist_get")
    _register_target(e2e_client, "f05-persist-get", repo)

    resp = e2e_client.get("/api/v1/scans/f05-persist-get?persist=true")
    assert resp.status_code == 400, resp.text
    hist = e2e_client.get("/api/v1/scans/f05-persist-get/history")
    assert hist.status_code == 200
    assert hist.json() == []


# ---------------------------------------------------------------------------
# F06 (P1-9): SSRF CIDR Allowlist, Gzip Bomb & Non-Dict JSON
# ---------------------------------------------------------------------------


def _make_mock_v1_handler(
    models_body: bytes,
    chat_body: bytes | None = None,
    *,
    models_headers: dict[str, str] | None = None,
    tracker: dict[str, Any] | None = None,
) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_GET(self) -> None:
            if tracker is not None:
                tracker["hits"] = int(tracker.get("hits", 0)) + 1
                accept_enc = self.headers.get("Accept-Encoding", "")
                tracker.setdefault("accept_encodings", []).append(accept_enc)
            if self.path.rstrip("/") == "/v1/models":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                for k, v in (models_headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(models_body)))
                self.end_headers()
                self.wfile.write(models_body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            if tracker is not None:
                tracker["hits"] = int(tracker.get("hits", 0)) + 1
            clen = int(self.headers.get("Content-Length") or "0")
            if clen > 0:
                _ = self.rfile.read(clen)
            if self.path.rstrip("/") == "/v1/chat/completions" and chat_body is not None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(chat_body)))
                self.end_headers()
                self.wfile.write(chat_body)
                return
            self.send_response(404)
            self.end_headers()

    return _Handler


def test_f06_t1_ask_engines_discovers_live_loopback_v1_models(e2e_client: TestClient) -> None:
    handler = _make_mock_v1_handler(json.dumps({"data": [{"id": "m1"}]}).encode("utf-8"))
    with _local_http_server(handler) as (base_url, _port):
        resp = e2e_client.get("/api/v1/ask/engines", params={"local_base_url": base_url})
    assert resp.status_code == 200, resp.text
    engines = {e["engine"]: e for e in resp.json()["engines"]}
    assert engines["local"]["state"] == "ready"
    assert engines["local"]["model_id"] == "m1"


@pytest.mark.parametrize(
    "allowed_url",
    [
        "http://10.0.0.1:8080",
        "http://192.168.1.10:8080",
        "http://[::1]:8080",
        "http://[fc00::1]:8080",
        "http://100.64.0.5:8080",
    ],
)
def test_f06_t1_private_and_tailnet_cidrs_accepted_by_url_validator(
    e2e_env: dict[str, Any],
    tmp_path: Path,
    allowed_url: str,
) -> None:
    del e2e_env
    repo = _make_clean_repo(tmp_path / "f06_cidr_ok")
    rc, _out, err = run_cli(["scan", str(repo), "--probe-url", allowed_url])
    assert rc == 0, f"Allowed private/Tailnet URL {allowed_url} rejected: {err}"


def test_f06_t1_post_ask_against_local_mock_chat_completions(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f06_ask_chat")
    _register_target(e2e_client, "f06-ask-chat", repo)
    chat_payload = {
        "id": "chatcmpl-1",
        "model": "m1",
        "choices": [{"message": {"role": "assistant", "content": "Items table holds truth."}}],
    }
    handler = _make_mock_v1_handler(
        json.dumps({"data": [{"id": "m1"}]}).encode("utf-8"),
        json.dumps(chat_payload).encode("utf-8"),
    )
    with _local_http_server(handler) as (base_url, _port):
        resp = e2e_client.post(
            "/api/v1/ask",
            json={
                "question": "Where is truth stored?",
                "engine": "local",
                "target_slug": "f06-ask-chat",
                "local_base_url": base_url,
                "include_vision_snapshot": False,
            },
        )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["engine_used"] == "local"
    assert data["model_id"] == "m1"
    assert "Items table holds truth." in data["answer_markdown"]


def test_f06_t1_wythe_scan_probe_url_against_local_http_server(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    del e2e_env
    repo = _make_clean_repo(
        tmp_path / "f06_probe_srv",
        extra_files={
            "frontend/src/App.tsx": "export function App() { return fetch('/api/live_ok'); }\n"
        },
    )

    class _ProbeHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_GET(self) -> None:
            code = 200 if self.path == "/api/live_ok" else 404
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with _local_http_server(_ProbeHandler) as (base_url, _port):
        rc, _out, err = run_cli(["scan", str(repo), "--probe-url", base_url])
    assert rc == 0, err


def test_f06_t1_ask_engines_discovers_ipv6_loopback_server(e2e_client: TestClient) -> None:
    handler = _make_mock_v1_handler(json.dumps({"data": [{"id": "m1-v6"}]}).encode("utf-8"))
    with _local_http_server(handler, ipv6=True) as (base_url, _port):
        resp = e2e_client.get("/api/v1/ask/engines", params={"local_base_url": base_url})
    assert resp.status_code == 200, resp.text
    engines = {e["engine"]: e for e in resp.json()["engines"]}
    assert engines["local"]["state"] == "ready"
    assert engines["local"]["model_id"] == "m1-v6"


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://[2002:0808:0808::1]:8080",
        "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]:8080",
    ],
)
def test_f06_t2_6to4_and_teredo_ipv6_rejected_cleanly(
    e2e_client: TestClient,
    tmp_path: Path,
    bad_url: str,
) -> None:
    repo = _make_clean_repo(tmp_path / "f06_v6_reject")
    _register_target(e2e_client, "f06-v6-reject", repo)

    eng_resp = e2e_client.get("/api/v1/ask/engines", params={"local_base_url": bad_url})
    assert eng_resp.status_code == 200
    local_eng = next(e for e in eng_resp.json()["engines"] if e["engine"] == "local")
    assert local_eng["state"] == "unavailable"
    assert "Nothing answered" not in local_eng["note"]

    ask_resp = e2e_client.post(
        "/api/v1/ask",
        json={
            "question": "Test",
            "engine": "local",
            "target_slug": "f06-v6-reject",
            "local_base_url": bad_url,
        },
    )
    assert ask_resp.status_code == 422, ask_resp.text

    rc_focus, _o1, _e1 = run_cli(["focus", "--remote", bad_url])
    assert rc_focus == 2

    rc_scan, _o2, _e2 = run_cli(["scan", str(repo), "--probe-url", bad_url])
    assert rc_scan == 2


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://0.1.2.3:8080",
        "http://169.254.169.254:80",
    ],
)
def test_f06_t2_unspecified_and_link_local_rejected_cleanly(
    e2e_client: TestClient,
    tmp_path: Path,
    bad_url: str,
) -> None:
    repo = _make_clean_repo(tmp_path / "f06_v4_reject")
    _register_target(e2e_client, "f06-v4-reject", repo)

    eng_resp = e2e_client.get("/api/v1/ask/engines", params={"local_base_url": bad_url})
    assert eng_resp.status_code == 200
    local_eng = next(e for e in eng_resp.json()["engines"] if e["engine"] == "local")
    assert local_eng["state"] == "unavailable"
    assert "Nothing answered" not in local_eng["note"]

    ask_resp = e2e_client.post(
        "/api/v1/ask",
        json={
            "question": "Test",
            "engine": "local",
            "target_slug": "f06-v4-reject",
            "local_base_url": bad_url,
        },
    )
    assert ask_resp.status_code == 422, ask_resp.text

    rc_focus, _o1, _e1 = run_cli(["focus", "--remote", bad_url])
    assert rc_focus == 2

    rc_scan, _o2, _e2 = run_cli(["scan", str(repo), "--probe-url", bad_url])
    assert rc_scan == 2


def test_f06_t2_userinfo_url_rejected_with_zero_ssrf_hits(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    """Verify P1-9: strip userinfo without Auth leaks and reject `@`-authority confusion."""
    captured_requests: list[dict[str, Any]] = []
    tracker: dict[str, Any] = {"hits": 0}
    models_body = json.dumps({"data": [{"id": "m1"}]}).encode("utf-8")
    chat_body = json.dumps(
        {
            "id": "chatcmpl-userinfo",
            "model": "m1",
            "choices": [{"message": {"role": "assistant", "content": "Items table ok."}}],
        }
    ).encode("utf-8")
    focus_body = json.dumps({"markdown_brief": "Focus brief ok."}).encode("utf-8")

    class _UserinfoSpyHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def _record(self, method: str) -> None:
            tracker["hits"] = int(tracker["hits"]) + 1
            captured_requests.append(
                {
                    "method": method,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                }
            )

        def do_GET(self) -> None:
            self._record("GET")
            if self.path.rstrip("/") == "/v1/models":
                body = models_body
            elif self.path.split("?", 1)[0].rstrip("/") == "/api/v1/ui-focus":
                body = focus_body
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            self._record("POST")
            clen = int(self.headers.get("Content-Length") or "0")
            if clen > 0:
                _ = self.rfile.read(clen)
            if self.path.rstrip("/") == "/v1/chat/completions":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(chat_body)))
                self.end_headers()
                self.wfile.write(chat_body)
                return
            self.send_response(404)
            self.end_headers()

    repo = _make_clean_repo(tmp_path / "f06_userinfo")
    _register_target(e2e_client, "f06-userinfo", repo)

    with _local_http_server(_UserinfoSpyHandler) as (_base_url, port):
        # 1) Loopback URL with userinfo strips `user:pass@` and leaks zero Authorization/credentials
        userinfo_v1_url = f"http://user:pass@127.0.0.1:{port}/v1"
        eng_resp = e2e_client.get("/api/v1/ask/engines", params={"local_base_url": userinfo_v1_url})
        assert eng_resp.status_code == 200, eng_resp.text
        local_eng = next(e for e in eng_resp.json()["engines"] if e["engine"] == "local")
        assert local_eng["state"] == "ready"
        assert local_eng["base_url"] == f"http://127.0.0.1:{port}/v1"
        assert "user:pass" not in json.dumps(eng_resp.json())

        ask_resp = e2e_client.post(
            "/api/v1/ask",
            json={
                "question": "Explain items.",
                "engine": "local",
                "target_slug": "f06-userinfo",
                "local_base_url": userinfo_v1_url,
                "include_vision_snapshot": False,
            },
        )
        assert ask_resp.status_code == 200, ask_resp.text
        ask_data = ask_resp.json()
        assert ask_data["endpoint_origin"] == f"http://127.0.0.1:{port}"
        assert "user:pass" not in json.dumps(ask_data)

        rc_focus_ok, focus_out, focus_err = run_cli(
            ["focus", "--remote", f"http://user:pass@127.0.0.1:{port}"]
        )
        assert rc_focus_ok == 0, focus_err
        assert "Focus brief ok." in focus_out
        assert "user:pass" not in focus_out
        assert "user:pass" not in focus_err

        captured_paths = [req["path"].split("?", 1)[0] for req in captured_requests]
        assert "/v1/models" in captured_paths
        assert "/v1/chat/completions" in captured_paths
        assert "/api/v1/ui-focus" in captured_paths
        for req in captured_requests:
            hdrs = req["headers"]
            assert "authorization" not in hdrs, f"Authorization header leaked: {req}"
            assert "proxy-authorization" not in hdrs, f"Proxy-Authorization leaked: {req}"
            assert all(
                "user:pass" not in val and "dXNlcjpwYXNz" not in val for val in hdrs.values()
            ), f"Userinfo credentials leaked in request headers: {req}"

        # 2) `@`-authority confusion against link-local host is rejected with 0 SSRF hits
        tracker["hits"] = 0
        captured_requests.clear()
        for confused_url in (
            "http://127.0.0.1@169.254.169.254/v1",
            f"http://127.0.0.1:{port}@169.254.169.254/v1",
        ):
            bad_eng_resp = e2e_client.get(
                "/api/v1/ask/engines", params={"local_base_url": confused_url}
            )
            assert bad_eng_resp.status_code == 200, bad_eng_resp.text
            bad_local_eng = next(
                e for e in bad_eng_resp.json()["engines"] if e["engine"] == "local"
            )
            assert bad_local_eng["state"] == "unavailable"
            assert bad_local_eng["base_url"] is None
            assert "Nothing answered" not in bad_local_eng["note"]

            bad_ask_resp = e2e_client.post(
                "/api/v1/ask",
                json={
                    "question": "Test",
                    "engine": "local",
                    "target_slug": "f06-userinfo",
                    "local_base_url": confused_url,
                    "include_vision_snapshot": False,
                },
            )
            assert bad_ask_resp.status_code == 422, bad_ask_resp.text

            rc_focus_bad, _out_bad, err_bad = run_cli(["focus", "--remote", confused_url])
            assert rc_focus_bad == 2
            assert err_bad.strip()

            rc_scan_bad, _scan_out, _scan_err = run_cli(
                ["scan", str(repo), "--probe-url", confused_url]
            )
            assert rc_scan_bad == 2

        assert tracker["hits"] == 0, (
            f"SSRF connection made despite @-authority confusion: hits={tracker['hits']}, "
            f"requests={captured_requests}"
        )
        assert captured_requests == []


def test_f06_t2_gzip_bomb_rejected_and_accept_encoding_identity_sent(
    e2e_client: TestClient,
) -> None:
    tracker: dict[str, Any] = {"accept_encodings": []}
    bomb_bytes = gzip.compress(b"\x00" * (12 * 1024 * 1024))
    handler = _make_mock_v1_handler(
        bomb_bytes,
        models_headers={"Content-Encoding": "gzip"},
        tracker=tracker,
    )
    with _local_http_server(handler) as (base_url, _port):
        resp = e2e_client.get("/api/v1/ask/engines", params={"local_base_url": base_url})
    assert resp.status_code == 200, resp.text
    local_eng = next(e for e in resp.json()["engines"] if e["engine"] == "local")
    assert local_eng["state"] == "unavailable"
    assert tracker["accept_encodings"], "No request reached local server"
    assert any("identity" in enc.lower() for enc in tracker["accept_encodings"]), (
        f"Expected Accept-Encoding: identity, got {tracker['accept_encodings']!r}"
    )


@pytest.mark.parametrize("raw_json", [b"[]", b"null"])
def test_f06_t2_non_dict_json_from_models_handled_without_500(
    e2e_env: dict[str, Any],
    raw_json: bytes,
) -> None:
    del e2e_env
    handler = _make_mock_v1_handler(raw_json)
    with (
        TestClient(create_app(), raise_server_exceptions=False) as client,
        _local_http_server(handler) as (base_url, _port),
    ):
        resp = client.get("/api/v1/ask/engines", params={"local_base_url": base_url})
    assert resp.status_code == 200, resp.text
    local_eng = next(e for e in resp.json()["engines"] if e["engine"] == "local")
    assert local_eng["state"] == "unavailable"


@pytest.mark.parametrize("raw_chat_json", [b"[]", b"null"])
def test_f06_t2_non_dict_json_from_chat_completions_handled_without_500(
    e2e_env: dict[str, Any],
    tmp_path: Path,
    raw_chat_json: bytes,
) -> None:
    del e2e_env
    repo = _make_clean_repo(tmp_path / f"f06_nondict_{len(raw_chat_json)}")
    handler = _make_mock_v1_handler(
        json.dumps({"data": [{"id": "m1"}]}).encode("utf-8"),
        raw_chat_json,
    )
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        _register_target(client, f"f06-nd-{len(raw_chat_json)}", repo)
        with _local_http_server(handler) as (base_url, _port):
            resp = client.post(
                "/api/v1/ask",
                json={
                    "question": "Explain items",
                    "engine": "local",
                    "target_slug": f"f06-nd-{len(raw_chat_json)}",
                    "local_base_url": base_url,
                    "include_vision_snapshot": False,
                },
            )
    assert resp.status_code != 500, f"Non-dict JSON crashed /api/v1/ask with 500: {resp.text}"
    assert resp.status_code in (422, 502, 503)


# ---------------------------------------------------------------------------
# F07 (P1-1, P1-13): #103 Citations, .git/packed-refs & Secret Path Blocking
# ---------------------------------------------------------------------------


def _create_session(client: TestClient, slug: str, session_id: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"target_slug": slug, "client_id": "e2e-tester"}
    if session_id is not None:
        payload["session_id"] = session_id
    resp = client.post("/api/v1/investigations", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_f07_t1_turn_validates_explicit_node_id(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f07_node_id")
    _register_target(e2e_client, "f07-node-id", repo)
    scan_data = e2e_client.get("/api/v1/scans/f07-node-id").json()
    node_ids = [n["id"] for n in scan_data["nodes"]]
    assert "t:items" in node_ids

    sess = _create_session(e2e_client, "f07-node-id")
    resp = e2e_client.post(
        f"/api/v1/investigations/{sess['session_id']}/turns",
        json={
            "actor": "agent",
            "question": "Which table stores items?",
            "answer_markdown": "Table `t:items` holds the rows.",
            "referenced_ids": ["t:items"],
        },
    )
    assert resp.status_code == 200, resp.text
    refs = {r["ref_id"]: r for r in resp.json()["validated_references"]}
    assert refs["t:items"]["validation_state"] == "validated"
    assert refs["t:items"]["kind"] == "node"


def test_f07_t1_turn_validates_multiple_markdown_citations(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f07_multi_cite")
    _register_target(e2e_client, "f07-multi-cite", repo)
    sess = _create_session(e2e_client, "f07-multi-cite")

    resp = e2e_client.post(
        f"/api/v1/investigations/{sess['session_id']}/turns",
        json={
            "actor": "agent",
            "question": "Show citations",
            "answer_markdown": (
                "See `t:items`, `backend/app/main.py:1`, and `backend/app/models.py:1`."
            ),
        },
    )
    assert resp.status_code == 200, resp.text
    refs = {r["ref_id"]: r for r in resp.json()["validated_references"]}
    for expected in ("t:items", "backend/app/main.py:1", "backend/app/models.py:1"):
        assert expected in refs
        assert refs[expected]["validation_state"] == "validated"


def test_f07_t1_source_peek_returns_200_for_repo_file(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f07_src_200")
    _register_target(e2e_client, "f07-src-200", repo)

    resp = e2e_client.get(
        "/api/v1/scans/f07-src-200/source",
        params={"rel_path": "backend/app/main.py", "line": 1},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["rel_path"] == "backend/app/main.py"
    joined = "\n".join(line["text"] for line in data["lines"])
    assert "FastAPI" in joined


def test_f07_t1_loose_ref_git_repo_record_turn_validates_file_line(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f07_loose_ref")
    assert (repo / ".git" / "refs" / "heads" / "main").is_file()
    _register_target(e2e_client, "f07-loose-ref", repo)
    sess = _create_session(e2e_client, "f07-loose-ref")

    mcp_resp = e2e_client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "wythe_investigation",
                "arguments": {
                    "action": "record_turn",
                    "target": "f07-loose-ref",
                    "session_id": sess["session_id"],
                    "question": "Check entrypoint",
                    "answer_markdown": "Entrypoint at `backend/app/main.py:1`.",
                },
            },
        },
    )
    assert mcp_resp.status_code == 200, mcp_resp.text
    assert mcp_resp.json()["result"]["isError"] is False

    inv = e2e_client.get(f"/api/v1/investigations/{sess['session_id']}").json()
    refs = {r["ref_id"]: r for r in inv["turns"][-1]["validated_references"]}
    assert refs["backend/app/main.py:1"]["validation_state"] == "validated"


def test_f07_t1_source_peek_blocks_dot_env_403(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    env_k = "SECRET_KEY"
    repo = _make_clean_repo(tmp_path / "f07_dotenv", extra_files={".env": f"{env_k}=abc\n"})
    _register_target(e2e_client, "f07-dotenv", repo)
    resp = e2e_client.get(
        "/api/v1/scans/f07-dotenv/source",
        params={"rel_path": ".env", "line": 1},
    )
    assert resp.status_code == 403, resp.text


def test_f07_t2_packed_refs_git_repo_validates_file_line(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f07_packed_refs")
    subprocess.run(["git", "-C", str(repo), "pack-refs", "--all"], check=True, capture_output=True)
    assert (repo / ".git" / "packed-refs").is_file()
    assert not (repo / ".git" / "refs" / "heads" / "main").exists()

    _register_target(e2e_client, "f07-packed-refs", repo)
    sess = _create_session(e2e_client, "f07-packed-refs")

    resp = e2e_client.post(
        f"/api/v1/investigations/{sess['session_id']}/turns",
        json={
            "actor": "agent",
            "question": "Verify packed-refs citation",
            "answer_markdown": "Entrypoint is `backend/app/main.py:1`.",
        },
    )
    assert resp.status_code == 200, resp.text
    refs = {r["ref_id"]: r for r in resp.json()["validated_references"]}
    assert refs["backend/app/main.py:1"]["validation_state"] == "validated", refs


def test_f07_t2_more_than_32_backticked_citations_all_validated(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    extra = {f"backend/app/mod_{idx:02d}.py": f"VAL_{idx} = {idx}\n" for idx in range(40)}
    repo = _make_clean_repo(tmp_path / "f07_gt32", extra_files=extra)
    _register_target(e2e_client, "f07-gt32", repo)
    sess = _create_session(e2e_client, "f07-gt32")

    citations = [f"backend/app/mod_{idx:02d}.py:1" for idx in range(40)]
    md = "Files: " + ", ".join(f"`{c}`" for c in citations)
    resp = e2e_client.post(
        f"/api/v1/investigations/{sess['session_id']}/turns",
        json={
            "actor": "agent",
            "question": "List all 40 files",
            "answer_markdown": md,
        },
    )
    assert resp.status_code == 200, resp.text
    refs = {r["ref_id"]: r for r in resp.json()["validated_references"]}
    assert len(refs) == 33, refs
    for head_cite in citations[:32]:
        assert head_cite in refs, f"Citation {head_cite} missing within 32-item budget"
        assert refs[head_cite]["validation_state"] == "validated"
    trunc_ref = refs.get("citation:truncated")
    assert trunc_ref is not None, refs
    assert trunc_ref["validation_state"] == "unresolved"
    assert "32" in trunc_ref["note"]


def test_f07_t2_z3_citation_spoofing_not_falsely_validated(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(
        tmp_path / "f07_z3_spoof",
        extra_files={"backend/app/nonexistent.py": "def placeholder():\n    return 1\n"},
    )
    listeners_file = tmp_path / "listeners.json"
    listeners_file.write_text(
        json.dumps([{"port": 8000, "process": "python", "pid": 1234}]),
        encoding="utf-8",
    )
    _register_target(e2e_client, "f07-z3-spoof", repo)
    scan_data = e2e_client.get("/api/v1/scans/f07-z3-spoof").json()
    node_ids = {n["id"] for n in scan_data["nodes"]}
    assert "m:service:nonexistent" in node_ids
    assert "m:fastapi:nonexistent" not in node_ids

    sess = _create_session(e2e_client, "f07-z3-spoof")
    spoof_id = "z3:m:fastapi:nonexistent:port:1:8000"
    valid_id = "z3:m:service:nonexistent:port:1:8000"
    with wiretap_inspection_scope(port_listeners=listeners_file):
        resp = e2e_client.post(
            f"/api/v1/investigations/{sess['session_id']}/turns",
            json={
                "actor": "agent",
                "question": "Check z3 spoof",
                "answer_markdown": f"Spoofed `{spoof_id}` vs real `{valid_id}`.",
                "referenced_ids": [spoof_id, valid_id],
            },
        )
    assert resp.status_code == 200, resp.text
    refs = {r["ref_id"]: r for r in resp.json()["validated_references"]}
    assert refs[spoof_id]["validation_state"] == "unresolved", refs[spoof_id]
    assert refs[valid_id]["validation_state"] == "validated", refs[valid_id]


@pytest.mark.parametrize(
    "secret_relpath",
    [".env", "secrets.yaml", "prod.env.local", ".pgpass", "kubeconfig.yaml"],
)
def test_f07_t2_source_peek_blocks_secret_variants_403(
    e2e_client: TestClient,
    tmp_path: Path,
    secret_relpath: str,
) -> None:
    repo = _make_clean_repo(
        tmp_path / f"f07_sec_{secret_relpath.strip('.').replace('.', '_')}",
        extra_files={secret_relpath: "TOKEN=supersecret\n"},
    )
    slug = f"f07-sec-{secret_relpath.strip('.').replace('.', '-')}"
    _register_target(e2e_client, slug, repo)

    resp = e2e_client.get(
        f"/api/v1/scans/{slug}/source",
        params={"rel_path": secret_relpath, "line": 1},
    )
    assert resp.status_code == 403, f"{secret_relpath} not blocked: {resp.status_code} {resp.text}"


def test_f07_t2_citation_referencing_secret_or_traversal_marked_unresolved(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(
        tmp_path / "f07_cite_secret",
        extra_files={"secrets.yaml": "api_key: secret\n"},
    )
    _register_target(e2e_client, "f07-cite-secret", repo)
    sess = _create_session(e2e_client, "f07-cite-secret")

    resp = e2e_client.post(
        f"/api/v1/investigations/{sess['session_id']}/turns",
        json={
            "actor": "agent",
            "question": "Secret citations",
            "answer_markdown": "Inspect `secrets.yaml:1` and `../../etc/passwd:1`.",
            "referenced_ids": ["secrets.yaml:1", "../../etc/passwd:1"],
        },
    )
    assert resp.status_code == 200, resp.text
    refs = {r["ref_id"]: r for r in resp.json()["validated_references"]}
    assert refs["secrets.yaml:1"]["validation_state"] == "unresolved", refs["secrets.yaml:1"]
    trav_ref = refs["../../etc/passwd:1"]
    assert trav_ref["validation_state"] == "unresolved", trav_ref


def test_f07_t2_source_peek_blocks_symlink_escape_403(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("SECRET = 'outside'\n", encoding="utf-8")
    repo = _make_clean_repo(tmp_path / "f07_symlink")
    link_path = repo / "backend" / "app" / "escape_link.py"
    link_path.symlink_to(outside_file)
    _register_target(e2e_client, "f07-symlink", repo)

    resp = e2e_client.get(
        "/api/v1/scans/f07-symlink/source",
        params={"rel_path": "backend/app/escape_link.py", "line": 1},
    )
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# F08 (P1-12, P1-13): #106 Viewport Bus, Cross-Target Isolation & Snapshot Hydration
# ---------------------------------------------------------------------------


def test_f08_t1_viewport_command_state_and_sse_events_once(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f08_vp_sse")
    _register_target(e2e_client, "f08-vp-sse", repo)

    cmd_resp = e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "f08-vp-sse",
            "command_id": "cmd_f08_sse_1",
            "focus_node_ids": ["t:items"],
            "caption": "Focus items",
        },
    )
    assert cmd_resp.status_code == 200, cmd_resp.text
    ack = cmd_resp.json()
    assert ack["delivery_state"] == "accepted_by_service"

    state_resp = e2e_client.get("/api/v1/viewport/state", params={"target_slug": "f08-vp-sse"})
    assert state_resp.status_code == 200
    assert state_resp.json()["latest"]["command"]["command_id"] == "cmd_f08_sse_1"

    ev_resp = e2e_client.get(
        "/api/v1/viewport/events",
        params={"target_slug": "f08-vp-sse", "once": "true"},
    )
    assert ev_resp.status_code == 200
    assert "text/event-stream" in ev_resp.headers.get("content-type", "")
    assert "viewport_command" in ev_resp.text
    assert "cmd_f08_sse_1" in ev_resp.text


def test_f08_t1_viewport_receipt_applied_transitions_to_applied_by_browser(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f08_vp_apply")
    _register_target(e2e_client, "f08-vp-apply", repo)
    ack = e2e_client.post(
        "/api/v1/viewport/command",
        json={"target_slug": "f08-vp-apply", "command_id": "cmd_f08_apply_1"},
    ).json()

    rcpt = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_f08_apply_1",
            "seq": ack["seq"],
            "target_slug": "f08-vp-apply",
            "client_id": "browser-1",
            "outcome": "applied",
        },
    )
    assert rcpt.status_code == 200, rcpt.text
    assert rcpt.json()["delivery_state"] == "applied_by_browser"
    assert "browser-1" in rcpt.json()["applied_by_client_ids"]

    state = e2e_client.get("/api/v1/viewport/state", params={"target_slug": "f08-vp-apply"}).json()
    assert state["latest"]["delivery_state"] == "applied_by_browser"
    assert "browser-1" in state["latest"]["applied_by_client_ids"]


def test_f08_t1_investigations_crud_create_get_export_reset_delete(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f08_inv_crud")
    _register_target(e2e_client, "f08-inv-crud", repo)

    created = _create_session(e2e_client, "f08-inv-crud")
    sid = created["session_id"]

    fetched = e2e_client.get(f"/api/v1/investigations/{sid}")
    assert fetched.status_code == 200
    assert fetched.json()["session_id"] == sid

    e2e_client.post(
        f"/api/v1/investigations/{sid}/turns",
        json={"actor": "human", "question": "Check items", "answer_markdown": "Look at `t:items`."},
    )
    exported = e2e_client.get(f"/api/v1/investigations/{sid}/export")
    assert exported.status_code == 200
    assert exported.json()["session"]["session_id"] == sid

    reset = e2e_client.post(f"/api/v1/investigations/{sid}/reset")
    assert reset.status_code == 200
    assert reset.json()["turns"] == []

    deleted = e2e_client.delete(f"/api/v1/investigations/{sid}")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    after_del = e2e_client.get(f"/api/v1/investigations/{sid}")
    assert after_del.status_code == 404


def test_f08_t1_scans_strict_true_vs_strict_false_independent_verdicts(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    baseline_repo = _make_blocking_repo(
        tmp_path / "f08_blocking_baseline",
        "f08-blocking-baseline",
        with_disabled_override=False,
    )
    _register_target(e2e_client, "f08-blocking-baseline", baseline_repo)
    baseline_strict = e2e_client.post("/api/v1/scans/f08-blocking-baseline?strict=true")
    assert baseline_strict.status_code == 200, baseline_strict.text
    baseline_payload = baseline_strict.json()
    assert baseline_payload["gate"]["verdict"] == "FAIL"
    assert any(
        f["rule_code"] == "DISP-004" and f["blocks_gate"]
        for f in baseline_payload["findings"]
    )

    repo = _make_blocking_repo(
        tmp_path / "f08_strict_vs_non",
        "f08-strict-vs-non",
        with_disabled_override=True,
    )
    _register_target(e2e_client, "f08-strict-vs-non", repo)
    sync_resp = e2e_client.post(
        "/api/v1/targets/f08-strict-vs-non/governance-sync?direction=import"
    )
    assert sync_resp.status_code == 200, sync_resp.text

    non_strict = e2e_client.post("/api/v1/scans/f08-strict-vs-non?strict=false")
    assert non_strict.status_code == 200, non_strict.text
    assert non_strict.json()["gate"]["verdict"] in ("PASS", "RATCHET_PASS")

    strict_rep = e2e_client.post("/api/v1/scans/f08-strict-vs-non?strict=true")
    assert strict_rep.status_code == 200, strict_rep.text
    strict_payload = strict_rep.json()
    assert strict_payload["gate"]["verdict"] == "FAIL"
    assert any(
        f["rule_code"] == "DISP-004" and f["blocks_gate"]
        for f in strict_payload["findings"]
    )


def test_f08_t1_list_investigations_filtered_by_target_slug(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo_a = _make_clean_repo(tmp_path / "f08_list_a")
    repo_b = _make_clean_repo(tmp_path / "f08_list_b")
    _register_target(e2e_client, "f08-list-a", repo_a)
    _register_target(e2e_client, "f08-list-b", repo_b)

    sess_a = _create_session(e2e_client, "f08-list-a")
    sess_b = _create_session(e2e_client, "f08-list-b")

    listed = e2e_client.get("/api/v1/investigations", params={"target_slug": "f08-list-a"}).json()
    sids = [s["session_id"] for s in listed["sessions"]]
    assert sess_a["session_id"] in sids
    assert sess_b["session_id"] not in sids


def test_f08_t2_strict_false_persisted_snapshot_does_not_poison_strict_true(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_blocking_repo(
        tmp_path / "f08_no_poison",
        "f08-no-poison",
        with_disabled_override=True,
    )
    _register_target(e2e_client, "f08-no-poison", repo)
    sync_resp = e2e_client.post(
        "/api/v1/targets/f08-no-poison/governance-sync?direction=import"
    )
    assert sync_resp.status_code == 200, sync_resp.text

    non_strict = e2e_client.post("/api/v1/scans/f08-no-poison?strict=false")
    assert non_strict.status_code == 200
    assert non_strict.json()["gate"]["verdict"] in ("PASS", "RATCHET_PASS")

    strict_get = e2e_client.get("/api/v1/scans/f08-no-poison?strict=true")
    assert strict_get.status_code == 200
    assert strict_get.json()["gate"]["verdict"] == "FAIL", (
        "strict=false snapshot poisoned GET strict=true"
    )

    strict_post = e2e_client.post("/api/v1/scans/f08-no-poison?strict=true")
    assert strict_post.status_code == 200
    assert strict_post.json()["gate"]["verdict"] == "FAIL", (
        "strict=false snapshot poisoned POST strict=true"
    )

    mcp_findings = e2e_client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 88,
            "method": "tools/call",
            "params": {"name": "wythe_findings", "arguments": {"target": "f08-no-poison"}},
        },
    ).json()
    assert mcp_findings["result"]["isError"] is False
    assert "DISP-004" in mcp_findings["result"]["content"][0]["text"]


def test_f08_t2_expired_paused_by_human_becomes_expired_and_does_not_replay_or_apply(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f08_exp_paused")
    _register_target(e2e_client, "f08-exp-paused", repo)

    exp_ts = (datetime.now(UTC) + timedelta(seconds=0.35)).isoformat()
    ack = e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "f08-exp-paused",
            "command_id": "cmd_f08_exp_1",
            "expires_at": exp_ts,
        },
    ).json()

    paused = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_f08_exp_1",
            "seq": ack["seq"],
            "target_slug": "f08-exp-paused",
            "client_id": "browser-1",
            "outcome": "paused_by_human",
        },
    )
    assert paused.status_code == 200, paused.text
    assert paused.json()["delivery_state"] == "paused_by_human"

    time.sleep(0.5)

    state = e2e_client.get(
        "/api/v1/viewport/state",
        params={"target_slug": "f08-exp-paused"},
    ).json()
    assert state["latest"]["delivery_state"] == "expired"

    sse = e2e_client.get(
        "/api/v1/viewport/events",
        params={"target_slug": "f08-exp-paused", "once": "true"},
    )
    assert sse.status_code == 200
    assert "cmd_f08_exp_1" not in sse.text

    late_apply = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_f08_exp_1",
            "seq": ack["seq"],
            "target_slug": "f08-exp-paused",
            "client_id": "browser-1",
            "outcome": "applied",
        },
    )
    assert late_apply.status_code == 422, late_apply.text


def test_f08_t2_rejected_or_stale_revision_must_not_downgrade_applied_by_browser(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f08_no_downgrade")
    _register_target(e2e_client, "f08-no-downgrade", repo)

    ack = e2e_client.post(
        "/api/v1/viewport/command",
        json={"target_slug": "f08-no-downgrade", "command_id": "cmd_f08_nodown"},
    ).json()

    applied = e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_f08_nodown",
            "seq": ack["seq"],
            "target_slug": "f08-no-downgrade",
            "client_id": "browser-1",
            "outcome": "applied",
        },
    )
    assert applied.status_code == 200
    assert applied.json()["delivery_state"] == "applied_by_browser"

    for outcome in ("rejected", "stale_revision"):
        resp = e2e_client.post(
            "/api/v1/viewport/receipts",
            json={
                "command_id": "cmd_f08_nodown",
                "seq": ack["seq"],
                "target_slug": "f08-no-downgrade",
                "client_id": "browser-2",
                "outcome": outcome,
            },
        )
        assert resp.status_code in (200, 422), resp.text
        if resp.status_code == 200:
            assert resp.json()["delivery_state"] == "applied_by_browser", (
                f"{outcome} downgraded applied_by_browser to {resp.json()['delivery_state']}"
            )
        state = e2e_client.get(
            "/api/v1/viewport/state",
            params={"target_slug": "f08-no-downgrade"},
        ).json()
        assert state["latest"]["delivery_state"] == "applied_by_browser"


def test_f08_t2_cross_target_session_id_rejected_across_surfaces(
    e2e_env: dict[str, Any],
    tmp_path: Path,
) -> None:
    del e2e_env
    repo_a = _make_clean_repo(tmp_path / "f08_xtarget_a")
    repo_b = _make_clean_repo(tmp_path / "f08_xtarget_b")

    with TestClient(create_app(), raise_server_exceptions=False) as client:
        _register_target(client, "f08-xt-a", repo_a)
        _register_target(client, "f08-xt-b", repo_b)
        sess_a = _create_session(client, "f08-xt-a")
        sid_a = sess_a["session_id"]

        inv_resp = client.post(
            "/api/v1/investigations",
            json={"target_slug": "f08-xt-b", "session_id": sid_a},
        )
        assert inv_resp.status_code == 422, inv_resp.text

        vp_resp = client.post(
            "/api/v1/viewport/command",
            json={"target_slug": "f08-xt-b", "session_id": sid_a},
        )
        assert vp_resp.status_code == 422, (
            f"Expected 422, got {vp_resp.status_code}: {vp_resp.text}"
        )

        ask_resp = client.post(
            "/api/v1/ask",
            json={"question": "Hello", "target_slug": "f08-xt-b", "session_id": sid_a},
        )
        assert ask_resp.status_code == 422, ask_resp.text

        mcp_resp = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 91,
                "method": "tools/call",
                "params": {
                    "name": "wythe_what_is_this",
                    "arguments": {"target": "f08-xt-b", "session_id": sid_a},
                },
            },
        )
        assert mcp_resp.status_code == 200, mcp_resp.text
        body = mcp_resp.json()
        assert (
            body.get("result", {}).get("isError") is True
            or body.get("error", {}).get("code") == -32602
        )


def test_f08_t2_basename_collision_unregistered_path_does_not_write_to_target_a(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo_a = _make_clean_repo(tmp_path / "repos" / "app_alpha")
    evil_dir = _make_clean_repo(
        tmp_path / "evil" / "app_alpha",
        extra_files={"backend/app/poison.py": "POISON = True\n"},
    )
    _register_target(e2e_client, "app_alpha", repo_a)
    sess_a = _create_session(e2e_client, "app_alpha")
    sid_a = sess_a["session_id"]

    mcp_resp = e2e_client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 92,
            "method": "tools/call",
            "params": {
                "name": "wythe_investigation",
                "arguments": {
                    "action": "record_turn",
                    "target": str(evil_dir),
                    "question": "Poisoned question",
                    "answer_markdown": "Poisoned `backend/app/poison.py:1`",
                },
            },
        },
    )
    assert mcp_resp.status_code == 200, mcp_resp.text
    inv_a = e2e_client.get(f"/api/v1/investigations/{sid_a}").json()
    assert inv_a["turns"] == [], f"Basename collision wrote into Target A session: {inv_a['turns']}"


def test_f08_t2_duplicate_command_id_across_targets_does_not_leak_applied_clients(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo_a = _make_clean_repo(tmp_path / "f08_dup_a")
    repo_b = _make_clean_repo(tmp_path / "f08_dup_b")
    _register_target(e2e_client, "f08-dup-a", repo_a)
    _register_target(e2e_client, "f08-dup-b", repo_b)

    sess_a = _create_session(e2e_client, "f08-dup-a")
    sess_b = _create_session(e2e_client, "f08-dup-b")

    ack_a = e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "f08-dup-a",
            "session_id": sess_a["session_id"],
            "command_id": "cmd_shared_dup",
        },
    ).json()
    ack_b = e2e_client.post(
        "/api/v1/viewport/command",
        json={
            "target_slug": "f08-dup-b",
            "session_id": sess_b["session_id"],
            "command_id": "cmd_shared_dup",
        },
    ).json()

    e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_shared_dup",
            "seq": ack_a["seq"],
            "target_slug": "f08-dup-a",
            "session_id": sess_a["session_id"],
            "client_id": "client_A",
            "outcome": "applied",
        },
    )
    e2e_client.post(
        "/api/v1/viewport/receipts",
        json={
            "command_id": "cmd_shared_dup",
            "seq": ack_b["seq"],
            "target_slug": "f08-dup-b",
            "session_id": sess_b["session_id"],
            "client_id": "client_B",
            "outcome": "applied",
        },
    )

    inv_a = e2e_client.get(f"/api/v1/investigations/{sess_a['session_id']}").json()
    inv_b = e2e_client.get(f"/api/v1/investigations/{sess_b['session_id']}").json()
    clients_a = {c for r in inv_a["recent_receipts"] for c in r["applied_by_client_ids"]}
    clients_b = {c for r in inv_b["recent_receipts"] for c in r["applied_by_client_ids"]}
    assert clients_a == {"client_A"}, f"Leaked clients into Target A: {clients_a}"
    assert clients_b == {"client_B"}, f"Leaked clients into Target B: {clients_b}"


# ---------------------------------------------------------------------------
# F10 (P1-7): MCP Tools & Stdio Framing DoS Protection
# ---------------------------------------------------------------------------


def test_f10_t1_get_mcp_full_lists_11_core_tools_and_5_resource_templates(
    e2e_client: TestClient,
) -> None:
    resp = e2e_client.get("/api/v1/mcp", params={"slice": "full"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    expected_core = {
        "wythe_list_targets",
        "wythe_overview",
        "wythe_lineage_cone",
        "wythe_blast_radius",
        "wythe_findings",
        "wythe_what_is_this",
        "wythe_plugins",
        "wythe_openlineage",
        "wythe_focus_camera",
        "wythe_camera_tour",
        "wythe_investigation",
    }
    tool_names = {t["name"] for t in data["tools"]}
    assert expected_core.issubset(tool_names), f"Missing core tools: {expected_core - tool_names}"
    assert len(data["resourceTemplates"]) == 5


def test_f10_t1_get_mcp_slm_lists_4_tools(e2e_client: TestClient) -> None:
    resp = e2e_client.get("/api/v1/mcp", params={"slice": "slm"})
    assert resp.status_code == 200, resp.text
    names = [t["name"] for t in resp.json()["tools"]]
    assert names == [
        "wythe_context",
        "wythe_lineage_cone",
        "wythe_check_change",
        "wythe_what_is_this",
    ]


def test_f10_t1_post_mcp_initialize_ping_and_tools_call(
    e2e_client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_clean_repo(tmp_path / "f10_tools")
    _register_target(e2e_client, "f10-tools", repo)

    init_r = e2e_client.post(
        "/api/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init_r.status_code == 200
    assert init_r.json()["result"]["serverInfo"]["name"] == "wythe"

    ping_r = e2e_client.post("/api/v1/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert ping_r.status_code == 200
    assert ping_r.json()["result"] == {}

    for req_id, tool_name, args in (
        (3, "wythe_list_targets", {}),
        (4, "wythe_findings", {"target": "f10-tools"}),
        (5, "wythe_overview", {"target": "f10-tools"}),
    ):
        call_r = e2e_client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            },
        )
        assert call_r.status_code == 200, call_r.text
        res = call_r.json()["result"]
        assert res["isError"] is False, f"{tool_name} failed: {res}"
        assert res["content"]


def test_f10_t1_post_mcp_notification_returns_202(e2e_client: TestClient) -> None:
    resp = e2e_client.post(
        "/api/v1/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert resp.status_code == 202, resp.text


def test_f10_t1_stdio_subprocess_content_length_and_json_lines(
    e2e_env: dict[str, Any],
) -> None:
    stdin_payload = (
        _frame_content_length({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _frame_content_length({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        + (json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}) + "\n").encode("utf-8")
    )
    proc = _run_mcp_stdio(stdin_payload, e2e_env)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")
    msgs = _parse_mcp_stdio_frames(proc.stdout)
    by_id = {m["id"]: m for m in msgs}
    assert by_id[1]["result"]["serverInfo"]["name"] == "wythe"
    assert by_id[2]["result"] == {}
    assert len(by_id[3]["result"]["tools"]) >= 11


def test_f10_t2_stdio_oversize_content_length_returns_32600(e2e_env: dict[str, Any]) -> None:
    payload = b"Content-Length: 99999999\r\n\r\n{}"
    proc = _run_mcp_stdio(payload, e2e_env)
    msgs = _parse_mcp_stdio_frames(proc.stdout)
    assert msgs and msgs[0]["error"]["code"] == -32600


@pytest.mark.parametrize("raw_len", [b"0", b"abc"])
def test_f10_t2_stdio_zero_and_non_numeric_content_length_return_32600(
    e2e_env: dict[str, Any],
    raw_len: bytes,
) -> None:
    payload = b"Content-Length: " + raw_len + b"\r\n\r\n"
    proc = _run_mcp_stdio(payload, e2e_env)
    msgs = _parse_mcp_stdio_frames(proc.stdout)
    assert msgs and msgs[0]["error"]["code"] == -32600


def test_f10_t2_stdio_excessive_dummy_headers_fails_closed_quickly(
    e2e_env: dict[str, Any],
) -> None:
    ping_body = json.dumps({"jsonrpc": "2.0", "id": 77, "method": "ping"}).encode("utf-8")
    dummy_headers = b"X-Dummy: a\r\n" * 200
    payload = (
        f"Content-Length: {len(ping_body)}\r\n".encode("ascii")
        + dummy_headers
        + b"\r\n"
        + ping_body
    )
    started = time.monotonic()
    proc = _run_mcp_stdio(payload, e2e_env, timeout=5.0)
    elapsed = time.monotonic() - started
    assert elapsed < 5.0
    msgs = _parse_mcp_stdio_frames(proc.stdout)
    assert all(m.get("id") != 77 for m in msgs), "Excessive dummy headers were NOT rejected"
    assert msgs and msgs[0]["error"]["code"] == -32600


def test_f10_t2_stdio_oversize_newline_free_frame_fails_closed_without_oom(
    e2e_env: dict[str, Any],
) -> None:
    payload = b"a" * (4 * 1024 * 1024 + 65536)
    proc = _run_mcp_stdio(payload, e2e_env, timeout=8.0)
    assert proc.returncode in (0, 1, 2)
    msgs = _parse_mcp_stdio_frames(proc.stdout)
    assert msgs and msgs[0]["error"]["code"] == -32600


def test_f10_t2_slm_slice_rejects_wythe_investigation_with_is_error(
    e2e_client: TestClient,
) -> None:
    resp = e2e_client.post(
        "/api/v1/mcp",
        params={"slice": "slm"},
        json={
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "wythe_investigation", "arguments": {"action": "list_sessions"}},
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"]["isError"] is True


def test_f10_t2_unknown_tool_and_unknown_method_return_errors(e2e_client: TestClient) -> None:
    bad_method = e2e_client.post(
        "/api/v1/mcp",
        json={"jsonrpc": "2.0", "id": 11, "method": "nonexistent/method"},
    ).json()
    assert bad_method["error"]["code"] == -32601

    bad_params = e2e_client.post(
        "/api/v1/mcp",
        json={"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"arguments": "bad"}},
    ).json()
    assert bad_params["error"]["code"] == -32602

    unknown_tool = e2e_client.post(
        "/api/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "wythe_no_such_tool", "arguments": {}},
        },
    ).json()
    assert (
        unknown_tool.get("result", {}).get("isError") is True
        or unknown_tool.get("error", {}).get("code") == -32602
    )
