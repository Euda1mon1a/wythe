"""Comprehensive regression tests for Milestone M2 Wythe v0.2.9 remediation."""

from __future__ import annotations

import gzip
import http.server
import io
import json
import socket
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import cli
from app.adapters.base import RawCandidateFinding
from app.main import create_app
from app.schemas.atlas import (
    AskWytheRequest,
    InvestigationCreateRequest,
    TargetProjectCreate,
    ViewportCommand,
    ViewportCommandReceiptCreate,
)
from app.services import investigation_service, mcp_service
from app.services.companion_export_service import _parse_trivy_report
from app.services.governance_service import register_target
from app.services.investigation_service import (
    build_evidence_identity,
    clear_scan_reuse_cache,
    compare_investigation_revisions,
    create_or_reopen_investigation,
    get_or_run_cached_scan,
    get_session_follow_state,
    record_investigation_turn,
    run_target_scan,
    validate_references_against_report,
)
from app.services.on_device_llm_service import (
    _normalize_private_v1_url,
    _stream_httpx_request,
    ask_wythe_with_live_context,
    probe_local_openai_engine,
)
from app.services.route_probe_service import apply_live_route_probe
from app.services.source_peek_service import (
    SourcePeekPermissionError,
    is_blocked_secret_path,
    read_target_source_snippet,
)
from app.services.understanding_discordance import (
    _perturbation_outcomes_contradict,
    evaluate_perturbation_matrix,
    evaluate_verdict_clauses,
)
from app.services.understanding_service import (
    _inspect_receipt_tree,
    _is_positive_delivery_receipt_value,
    _scan_delivery_receipt_node,
    analyze_understanding_bundle,
    explain_outcome_lifecycle,
)
from app.services.viewport_service import (
    ViewportBus,
    _effective_delivery_state,
    _post_viewport_command_http,
    _validate_viewport_server_url,
    publish_viewport_command,
    record_viewport_receipt,
)


def _write_minimal_repo(repo_dir: Path, *, include_secret_leak_rule: bool = False) -> Path:
    (repo_dir / "backend" / "app" / "api" / "routes").mkdir(parents=True, exist_ok=True)
    (repo_dir / "backend").joinpath("schema.sql").write_text(
        "CREATE TABLE quota_policies (id INTEGER PRIMARY KEY, max_items INTEGER);\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "api" / "routes" / "quotas.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/api/v1/quotas')\n"
        "def list_quotas():\n"
        "    return []\n",
        encoding="utf-8",
    )
    if include_secret_leak_rule:
        (repo_dir / "backend" / "app" / "leak.py").write_text(
            "def bad(cur):\n"
            "    cur.execute('SELECT * FROM quota_policies')\n",
            encoding="utf-8",
        )
    return repo_dir


def _git(repo_dir: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", *args],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


def test_p1_6_ipv6_origin_exact_scheme_port_csrf_and_nosniff_headers(
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        # IPv6 bracketed Host matching IPv6 Origin must succeed (not 403)
        ok_v6 = client.post(
            "/api/v1/targets/missing-slug/governance-sync?direction=export",
            headers={"Host": "[::1]:8780", "Origin": "http://[::1]:8780"},
        )
        assert ok_v6.status_code != 403

        # Cross-port same-site Origin must be rejected (403) + nosniff header
        bad_port = client.post(
            "/api/v1/scans/missing-slug",
            headers={
                "Host": "127.0.0.1:8780",
                "Origin": "http://127.0.0.1:9999",
                "Sec-Fetch-Site": "same-site",
            },
        )
        assert bad_port.status_code == 403
        assert bad_port.headers["X-Content-Type-Options"] == "nosniff"
        assert bad_port.headers["X-Frame-Options"] == "DENY"

        # Cross-scheme Origin must be rejected (403)
        bad_scheme = client.post(
            "/api/v1/scans/missing-slug",
            headers={"Host": "127.0.0.1:8780", "Origin": "https://127.0.0.1:8780"},
        )
        assert bad_scheme.status_code == 403
        assert bad_scheme.headers["X-Content-Type-Options"] == "nosniff"

        # Invalid Origin port must fail cleanly with 403 (not 500 ValueError)
        bad_origin_port = client.post(
            "/api/v1/scans/missing-slug",
            headers={"Host": "127.0.0.1:8780", "Origin": "http://127.0.0.1:99999"},
        )
        assert bad_origin_port.status_code == 403
        assert bad_origin_port.headers["X-Content-Type-Options"] == "nosniff"

        # Malformed Host header must fail cleanly with 400 + security headers
        bad_host = client.get("/healthz", headers={"Host": "[::1]:99999"})
        assert bad_host.status_code == 400
        assert bad_host.headers["X-Content-Type-Options"] == "nosniff"


def test_p1_7_mcp_stdio_bounded_lines_headers_eof_and_short_pipe_reads(
    isolated_db_url: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. Oversized newline-free frame (> 4 MiB) stops safely without reading unbounded memory
    oversized_line = b'{"jsonrpc":"2.0","id":1,"method":"ping","pad":"' + (b"x" * (4 * 1024 * 1024 + 32))
    out1 = io.BytesIO()
    assert mcp_service.run_mcp_stdio_server(stdin=io.BytesIO(oversized_line), stdout=out1) == 0
    assert b"exceeds maximum size" in out1.getvalue()

    # 2. Header count flood (> 32 headers) terminates cleanly with -32600
    flood_hdrs = b"Content-Length: 42\r\n" + (b"X-Pad: 1\r\n" * 40) + b"\r\n" + (b"{}" * 21)
    out2 = io.BytesIO()
    assert mcp_service.run_mcp_stdio_server(stdin=io.BytesIO(flood_hdrs), stdout=out2) == 0
    assert b"MCP header limit exceeded" in out2.getvalue()

    # 3. Oversized single header line (> 8 KiB) terminates cleanly
    long_hdr = b"Content-Length: 10\r\nX-Big: " + (b"a" * 9000) + b"\r\n\r\n"
    out3 = io.BytesIO()
    assert mcp_service.run_mcp_stdio_server(stdin=io.BytesIO(long_hdr), stdout=out3) == 0
    assert b"MCP header limit exceeded" in out3.getvalue()

    # 4. EOF mid-headers terminates cleanly without crash
    out4 = io.BytesIO()
    assert mcp_service.run_mcp_stdio_server(stdin=io.BytesIO(b"Content-Length: 10\r\nX-H: 1\r\n"), stdout=out4) == 0
    assert out4.getvalue() == b""

    # 5. Chunked short-read pipe stream completes full Content-Length payload
    body = b'{"jsonrpc":"2.0","id":88,"method":"ping"}'
    framed = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body

    class _ShortPipeStream(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._buf = data
            self._pos = 0

        def readable(self) -> bool:
            return True

        def readline(self, size: int = -1) -> bytes:
            if self._pos >= len(self._buf):
                return b""
            nl = self._buf.find(b"\n", self._pos)
            end = len(self._buf) if nl == -1 else nl + 1
            if size is not None and size >= 0:
                end = min(end, self._pos + size)
            chunk = self._buf[self._pos : end]
            self._pos = end
            return chunk

        def read(self, size: int = -1) -> bytes:
            if self._pos >= len(self._buf):
                return b""
            step = 5 if size is None or size < 0 else min(5, size)
            chunk = self._buf[self._pos : self._pos + step]
            self._pos += len(chunk)
            return chunk

    out5 = io.BytesIO()
    assert mcp_service.run_mcp_stdio_server(stdin=_ShortPipeStream(framed), stdout=out5) == 0  # type: ignore[arg-type]
    assert b'"id":88' in out5.getvalue()


def test_p1_9_ssrf_cidr_allowlist_userinfo_gzip_non_dict_and_dns_pinning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Special IPv6/IPv4 ranges accepted by ipaddress.is_private are blocked by explicit CIDRs
    for blocked_ip in ("2002::1", "2001::1", "0.1.2.3", "::ffff:0.1.2.3", "192.0.2.10"):
        u = f"http://[{blocked_ip}]:8080/v1" if ":" in blocked_ip else f"http://{blocked_ip}:8080/v1"
        with pytest.raises(ValueError):
            _normalize_private_v1_url(u)
        with pytest.raises(ValueError):
            _validate_viewport_server_url(u, allow_remote=False)
        with pytest.raises(ValueError):
            apply_live_route_probe(
                [RawCandidateFinding("DISP-004", "warn", "a.py", 1, "x", "t", "d", "r", "GET", "/x")],
                u,
            )

    # 2. Unresolvable *.localhost fails closed; userinfo stripped in viewport & route_probe
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("nxdomain")))
    with pytest.raises(ValueError):
        _normalize_private_v1_url("http://sub.localhost:8080/v1")
    with pytest.raises(ValueError):
        _validate_viewport_server_url("http://sub.localhost:8780", allow_remote=False)
    with pytest.raises(ValueError):
        apply_live_route_probe(
            [RawCandidateFinding("DISP-004", "warn", "a.py", 1, "x", "t", "d", "r", "GET", "/x")],
            "http://sub.localhost:8000",
        )
    monkeypatch.undo()

    cleaned_vp = _validate_viewport_server_url("http://alice:secret@127.0.0.1:8780?tok=1#h", allow_remote=False)
    assert cleaned_vp == "http://127.0.0.1:8780/api/v1/viewport/command"

    # 3. Gzip bomb / disallowed Content-Encoding + Accept-Encoding: identity + non-dict JSON
    seen_accept_enc: list[str] = []

    class _TrapHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            seen_accept_enc.append(str(self.headers.get("Accept-Encoding") or ""))
            if self.path == "/gzip/v1/models":
                blob = gzip.compress(b'{"data":[{"id":"m1"}]}')
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"[]")
            self.close_connection = True

        def do_POST(self) -> None:
            raw_cl = self.headers.get("Content-Length")
            if raw_cl:
                cl = int(raw_cl)
                if cl > 0:
                    self.rfile.read(cl)
            body = b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TrapHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ValueError, match="Content-Encoding"):
            _stream_httpx_request("GET", f"http://127.0.0.1:{port}/gzip/v1/models", timeout=2.0, max_bytes=1024)
        assert seen_accept_enc and seen_accept_enc[0] == "identity"

        # Non-dict JSON on /v1/models does not crash with AttributeError
        st = probe_local_openai_engine(f"http://127.0.0.1:{port}/v1")
        assert st.state == "unavailable"

        # Non-dict JSON on viewport ack fails cleanly with RuntimeError (not ValidationError/AttributeError)
        with pytest.raises(RuntimeError, match="non-object JSON"):
            _post_viewport_command_http(
                ViewportCommand(target_slug="demo"),
                f"http://127.0.0.1:{port}",
            )

        # DNS-rebinding TOCTOU: first lookup of rebind.localhost returns 127.0.0.1; subsequent lookups return 169.254.169.254
        # Pinning ensures connection goes to the validated 127.0.0.1 IP, never calling getaddrinfo(rebind.localhost) again!
        calls = {"n": 0}
        orig_getaddrinfo = socket.getaddrinfo

        def _rebind_getaddrinfo(host: Any, *a: Any, **kw: Any) -> list[Any]:
            if host == "rebind.localhost":
                calls["n"] += 1
                ip = "127.0.0.1" if calls["n"] == 1 else "169.254.169.254"
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
            return orig_getaddrinfo(host, *a, **kw)

        monkeypatch.setattr(socket, "getaddrinfo", _rebind_getaddrinfo)
        status_code, _hdrs, raw = _stream_httpx_request(
            "GET",
            f"http://rebind.localhost:{port}/v1/models",
            timeout=2.0,
            max_bytes=4096,
        )
        assert status_code == 200 and raw == b"[]"
        assert calls["n"] == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_p1_1_packed_refs_detached_head_worktree_and_p0_1_safe_git_error(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_minimal_repo(tmp_path / "packed-repo")
    _git(repo_dir, "init")
    _git(repo_dir, "config", "user.name", "Test")
    _git(repo_dir, "config", "user.email", "test@example.com")
    _git(repo_dir, "add", ".")
    _git(repo_dir, "commit", "-m", "init")
    _git(repo_dir, "pack-refs", "--all")

    target = register_target(
        db_session,
        TargetProjectCreate(slug="packed-lab", name="Packed Lab", repo_path=str(repo_dir)),
    )
    rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    ev = build_evidence_identity(rep)
    refs = validate_references_against_report(
        ["backend/schema.sql:1"],
        rep,
        evidence_revision_id=ev.evidence_revision_id,
    )
    assert refs[0].validation_state == "validated"

    # Linked worktree with packed-refs in commondir + comment/peeled lines
    wt_dir = tmp_path / "packed-wt"
    _git(repo_dir, "worktree", "add", "--detach", str(wt_dir), "HEAD")
    wt_target = register_target(
        db_session,
        TargetProjectCreate(slug="packed-wt-lab", name="Packed WT", repo_path=str(wt_dir)),
    )
    wt_rep = run_target_scan(db_session, wt_target, strict_gate=True, persist_snapshot=False)
    wt_ev = build_evidence_identity(wt_rep)
    wt_refs = validate_references_against_report(
        ["backend/schema.sql:1"],
        wt_rep,
        evidence_revision_id=wt_ev.evidence_revision_id,
    )
    assert wt_refs[0].validation_state == "validated"

    # P0-1: SafeGitError inside validate_references_against_report resolves cleanly as unresolved
    (repo_dir / ".git" / "config").write_text(
        "[diff]\n\texternal = evil\n",
        encoding="utf-8",
    )
    bad_refs = validate_references_against_report(
        ["backend/schema.sql:1"],
        rep,
        evidence_revision_id=ev.evidence_revision_id,
    )
    assert bad_refs[0].validation_state == "unresolved"
    assert "Git metadata" in bad_refs[0].note


def test_p1_12_snapshot_hydration_isolates_strict_gate_and_recomputes_digest(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_minimal_repo(tmp_path / "strict-iso-repo", include_secret_leak_rule=False)
    target = register_target(
        db_session,
        TargetProjectCreate(slug="strict-iso-lab", name="Strict Iso", repo_path=str(repo_dir)),
    )

    # Persist a strict_gate=False snapshot
    run_target_scan(db_session, target, strict_gate=False, persist_snapshot=True)
    clear_scan_reuse_cache()

    scan_calls = 0
    orig_scan = investigation_service.run_target_scan

    def _counted_scan(*args: object, **kwargs: object) -> object:
        nonlocal scan_calls
        scan_calls += 1
        return orig_scan(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(investigation_service, "run_target_scan", _counted_scan)
    # strict_gate=True MUST NOT hydrate a strict_gate=False snapshot stamp
    strict_res = get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert scan_calls == 1
    assert strict_res.gate.mode == "strict"

    # Once a strict_gate=True snapshot is persisted, subsequent strict_gate=True hydrates cleanly
    monkeypatch.undo()
    run_target_scan(db_session, target, strict_gate=True, persist_snapshot=True)
    clear_scan_reuse_cache()
    scan_calls = 0
    monkeypatch.setattr(investigation_service, "run_target_scan", _counted_scan)
    hydrated_strict = get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert scan_calls == 0
    assert hydrated_strict.gate.mode == "strict"

    # _rebind_persisted_gate_mode updates content_digest whenever verdict changes
    from app.services.investigation_service import _rebind_persisted_gate_mode

    ratcheted = run_target_scan(
        db_session,
        target,
        strict_gate=False,
        persist_snapshot=False,
    )
    rebound = _rebind_persisted_gate_mode(
        ratcheted.model_copy(
            update={
                "gate": ratcheted.gate.model_copy(
                    update={"mode": "ratchet", "verdict": "RATCHET_PASS"}
                )
            }
        ),
        strict_gate=True,
        baselines={},
    )
    if rebound.gate.verdict != ratcheted.gate.verdict:
        assert rebound.content_digest != ratcheted.content_digest


def test_p1_13_viewport_lifecycle_join_z3_citations_secrets_and_cross_target_isolation(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. paused_by_human expires & applied_by_browser is never downgraded by stale/rejected
    now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=UTC)
    expired_ts = (now - timedelta(minutes=5)).isoformat()
    assert _effective_delivery_state("paused_by_human", expired_ts, now) == "expired"

    repo_a = _write_minimal_repo(tmp_path / "repo-a")
    repo_b = _write_minimal_repo(tmp_path / "repo-b")
    t_a = register_target(db_session, TargetProjectCreate(slug="target-a", name="A", repo_path=str(repo_a)))
    t_b = register_target(db_session, TargetProjectCreate(slug="target-b", name="B", repo_path=str(repo_b)))
    assert t_a.id > 0 and t_b.id > 0

    sess_a = create_or_reopen_investigation(
        db_session, InvestigationCreateRequest(target_slug="target-a", session_id="sess-a")
    )
    sess_b = create_or_reopen_investigation(
        db_session, InvestigationCreateRequest(target_slug="target-b", session_id="sess-b")
    )

    # Cross-target publish & follow lookup fail closed / return None
    with pytest.raises(ValueError, match="belongs to target"):
        ViewportBus().publish(ViewportCommand(target_slug="target-b", session_id=sess_a.session_id))
    assert get_session_follow_state("target-b", sess_a.session_id) is None

    # applied_by_browser survives stale_revision and rejected receipts
    ack_a = publish_viewport_command(
        ViewportCommand(target_slug="target-a", session_id=sess_a.session_id, command_id="shared-cmd"),
        local_only=True,
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack_a.command_id,
            seq=ack_a.seq,
            target_slug="target-a",
            session_id=sess_a.session_id,
            client_id="browser-1",
            outcome="applied",
        )
    )
    rcpt_stale = record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack_a.command_id,
            seq=ack_a.seq,
            target_slug="target-a",
            session_id=sess_a.session_id,
            client_id="browser-1",
            outcome="stale_revision",
        )
    )
    assert rcpt_stale.delivery_state == "applied_by_browser"
    rcpt_rej = record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack_a.command_id,
            seq=ack_a.seq,
            target_slug="target-a",
            session_id=sess_a.session_id,
            client_id="browser-1",
            outcome="rejected",
        )
    )
    assert rcpt_rej.delivery_state == "applied_by_browser"

    # Receipt LEFT JOIN isolation when target-b publishes the same command_id
    ack_b = publish_viewport_command(
        ViewportCommand(target_slug="target-b", session_id=sess_b.session_id, command_id="shared-cmd"),
        local_only=True,
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack_b.command_id,
            seq=ack_b.seq,
            target_slug="target-b",
            session_id=sess_b.session_id,
            client_id="browser-b",
            outcome="rejected",
        )
    )
    conn = investigation_service.open_investigation_connection(create=False)
    assert conn is not None
    try:
        b_rcpts = investigation_service._load_receipts_for_session_in_conn(conn, "target-b", sess_b.session_id)
        assert len(b_rcpts) == 1
        assert b_rcpts[0].applied_by_client_ids == []
    finally:
        conn.close()

    # 2. >32 markdown citations truncation surfaces unresolved citation:truncated & skips compare_revisions
    rep_a = run_target_scan(db_session, t_a, strict_gate=True, persist_snapshot=False)
    ev_a = build_evidence_identity(rep_a)
    md_many = " ".join(f"`m:fake:{i}`" for i in range(40))
    refs_many = validate_references_against_report(
        [],
        rep_a,
        evidence_revision_id=ev_a.evidence_revision_id,
        answer_markdown=md_many,
    )
    trunc_refs = [r for r in refs_many if r.ref_id == "citation:truncated"]
    assert len(trunc_refs) == 1 and trunc_refs[0].validation_state == "unresolved"
    assert "32" in trunc_refs[0].note

    from app.schemas.atlas import InvestigationTurnCreate

    record_investigation_turn(
        db_session,
        sess_a.session_id,
        InvestigationTurnCreate(question="q", answer_markdown=md_many),
        report=rep_a,
    )
    comp = compare_investigation_revisions(db_session, sess_a.session_id)
    assert all(not r.ref_id.startswith("citation:") for r in comp.vanished_refs)

    # 3. z3 fabricated fallback prefix rejected
    z3_bad = validate_references_against_report(
        ["z3:m:fastapi:quotas:port:1:8780"],
        rep_a,
        evidence_revision_id=ev_a.evidence_revision_id,
    )
    assert z3_bad[0].validation_state == "unresolved"

    # 4. Secret paths blocked while alembic/env.py remains readable
    for bad_path in (
        "secrets.yaml",
        "secrets.yml",
        "secrets.json",
        "secrets.txt",
        "prod.env.local",
        "config/DEV.ENV.PROD",
        ".pgpass",
        "kubeconfig.yaml",
        "kubeconfig.yml",
    ):
        assert is_blocked_secret_path(bad_path), bad_path
        (repo_a / bad_path).parent.mkdir(parents=True, exist_ok=True)
        (repo_a / bad_path).write_text("SECRET=1\n", encoding="utf-8")
        with pytest.raises(SourcePeekPermissionError):
            read_target_source_snippet(repo_a, "target-a", bad_path)

    (repo_a / "backend" / "alembic").mkdir(parents=True, exist_ok=True)
    (repo_a / "backend" / "alembic" / "env.py").write_text("# alembic\n", encoding="utf-8")
    assert not is_blocked_secret_path("backend/alembic/env.py")
    assert read_target_source_snippet(repo_a, "target-a", "backend/alembic/env.py").lines

    # 5. Cross-target session checks in ask_wythe_with_live_context & MCP + basename collision
    with pytest.raises(ValueError, match="belongs to target"):
        ask_wythe_with_live_context(
            db_session,
            AskWytheRequest(question="hi", target_slug="target-b", session_id=sess_a.session_id),
        )
    res_what = mcp_service.dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wythe_what_is_this",
                "arguments": {"target": "target-b", "session_id": sess_a.session_id},
            },
        },
    )
    assert res_what["result"]["isError"] is True

    spoof_dir = tmp_path / "evil" / "target-a"
    _write_minimal_repo(spoof_dir)
    res_spoof = mcp_service.dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wythe_investigation",
                "arguments": {
                    "action": "record_turn",
                    "target": str(spoof_dir),
                    "answer_markdown": "Injected into target-a session",
                },
            },
        },
    )
    assert res_spoof["result"]["isError"] is True
    assert len(investigation_service.get_investigation_session(sess_a.session_id).turns) == 1  # type: ignore[union-attr]


def test_p1_2_delivery_receipt_strict_bools_continuity_path_b_headline_markdown_and_discordance() -> None:
    from wythe_plugin_agent_discordance.evaluator import evaluate_agent_discordance

    # 1. _is_positive_delivery_receipt_value (P1-2A)
    assert _is_positive_delivery_receipt_value({"id": "rcpt-123", "status": "delivered"}) is True
    assert _is_positive_delivery_receipt_value(True) is True
    assert _is_positive_delivery_receipt_value(1) is False
    assert (
        _is_positive_delivery_receipt_value(
            {"id": "r1", "detail": {"status": "failed", "delivered": False}}
        )
        is False
    )
    assert _is_positive_delivery_receipt_value({"id": "r1", "detail": {"delivery_receipt_id": ""}}) is False

    # 2. Unbacked tool_executed=True does not authorize settled_committed
    o_exec = explain_outcome_lifecycle(
        {
            "outcome_id": "x",
            "authoritative_terminal_state": "committed",
            "tool_executed": True,
        }
    )
    assert o_exec.settlement_state != "settled_committed"
    assert o_exec.positive_commit_established is False

    # 3. Shared request_id without predecessor_state_digest fails predecessor_chain_verified & delivery
    o_chain = explain_outcome_lifecycle(
        {
            "outcome_id": "c1",
            "current_stage": "delivered_to_human",
            "delivery_status": "delivered",
            "delivery_receipt": "rcpt-1",
            "transitions": [
                {"stage": "executed", "request_id": "req-1", "state_digest": "d1"},
                {"stage": "delivered_to_human", "request_id": "req-1"},
            ],
        }
    )
    assert o_chain.predecessor_chain_verified is False
    assert o_chain.positive_delivery_established is False

    o_3step = explain_outcome_lifecycle(
        {
            "outcome_id": "c3",
            "transitions": [
                {"stage": "declared", "request_id": "r1", "state_digest": "d0"},
                {"stage": "executed", "request_id": "r1", "predecessor_state_digest": "d0", "state_digest": "d1"},
                {"stage": "delivered_to_human", "request_id": "r1"},
            ],
        }
    )
    assert o_3step.predecessor_chain_verified is False

    # 4. Path B requires terminal digest for committed, preserves rolled_back without digest
    o_pathb_commit = explain_outcome_lifecycle(
        {
            "operation_id": "op-1",
            "transport_timeout_or_lost_reply": True,
            "authoritative_terminal_state": "committed",
            "settlement_receipt": {"receipt_id": "r1", "status": "committed", "operation_id": "op-1"},
        }
    )
    assert o_pathb_commit.settlement_state == "indeterminate_requires_settlement"

    o_pathb_abort = explain_outcome_lifecycle(
        {
            "operation_id": "op-2",
            "transport_timeout_or_lost_reply": True,
            "authoritative_terminal_state": "rolled_back",
            "reconciliation_receipt": {"receipt_id": "r2", "status": "rolled_back", "operation_id": "op-2"},
        }
    )
    assert o_pathb_abort.settlement_state == "settled_aborted"

    # 5. Strict string booleans across preservation & docs
    pres = analyze_understanding_bundle(
        {
            "bundle": {
                "preservation_contracts": [
                    {
                        "contract_id": "p-str",
                        "git_code_unchanged": "true",
                        "intentional_non_git_change": "false",
                        "baseline_evidence": {
                            "source_commit": "abc",
                            "config_digest": "d1",
                            "solver_run": {"hard_constraints_valid": "true", "locked_facts_digest": "lf1"},
                            "latency_ms": 100,
                            "quality_score": 0.9,
                        },
                        "candidate_evidence": {
                            "source_commit": "abc",
                            "config_digest": "d2",
                            "answer_quality_scored": "false",
                            "solver_run": {
                                "hard_constraints_valid": "false",
                                "locked_facts_preserved": "false",
                                "candidate_complete": "false",
                            },
                        },
                    }
                ],
                "first_divergence": {
                    "stage_label": "context_assembly",
                    "exists_in_storage": "present",
                    "eligible_for_actor": "present",
                    "present_in_turn": "absent",
                    "caller_attribution_state": "caller_verified",
                },
            }
        }
    )
    assert pres.preservation_evaluations[0].verdict == "failed_regression"
    assert pres.preservation_evaluations[0].quality_latency.answer_quality_scored is False

    # 5b. #117 headline/cause recompute when a later link (links[5]) was already unverified
    recomp = analyze_understanding_bundle(
        {
            "bundle": {
                "intent": {"summary": "Verify context", "legitimate_owner": "system"},
                "effective_authority": [
                    {
                        "item_id": "auth-1",
                        "candidate_bindings": [
                            {"binding_id": "b1", "value": True, "disposition": "selected_winner"}
                        ],
                        "consumer_effects": [
                            {
                                "consumer_id": "c1",
                                "stage": "accepted_output",
                                "effect_state": "demonstrated_effect",
                                "reached_compiled_input": True,
                            }
                        ],
                    }
                ],
                "runtime_provenance": [
                    {
                        "invocation_id": "inv-1",
                        "repo_revision": "abc123",
                        "artifact_digest": "d1",
                        "expected_artifact_digest": "d1",
                        "host": "local",
                        "expected_host": "local",
                        "import_closure": {"recorded_modules_count": 3},
                    }
                ],
                "outcome_lifecycles": [
                    {
                        "outcome_id": "out-1",
                        "current_stage": "delivered_to_human",
                        "authoritative_terminal_state": "committed",
                        "settlement_digest": "sd-1",
                        "delivery_status": "delivered",
                        "answer_grounding": "grounded",
                        "delivery_receipt": {"id": "rcpt-1", "status": "delivered"},
                    }
                ],
                "documentation_claims": [
                    {
                        "claim_id": "doc-1",
                        "claim_revision": "unpinned",
                        "corroborated": True,
                    }
                ],
                "first_divergence": {
                    "stage_label": "context_assembly",
                    "exists_in_storage": "present",
                    "eligible_for_actor": "present",
                    "present_in_turn": "absent",
                    "caller_attribution_state": "caller_verified",
                },
            }
        }
    )
    assert "3. Execution & Runtime Provenance" in recomp.consequence_headline
    assert "2. Effective Policy / Context" in recomp.last_supported_cause
    assert "3. Execution & Runtime Provenance" not in recomp.last_supported_cause

    # 6. Markdown fallback_id sanitization & backslash breakout + perturbation passed=True contradiction
    _clauses, _sent, md, _miss = evaluate_verdict_clauses(
        [
            {"clause_id": "x)[click](javascript:alert(1))(", "text": "ok"},
            {"clause_id": "c2", "text": r"bad\](javascript:alert(1))[", "source_location": "a.py:1"},
        ]
    )
    assert "[ok](#unverified:x__click__javascript_alert_1)" in md
    assert r"[bad\\\](javascript:alert(1))\[]" in md
    assert "](javascript:alert(1))" not in md.replace(r"\](javascript:alert(1))", "")

    pert = evaluate_perturbation_matrix(
        [
            {
                "case_id": "p1",
                "varied_factor": "x",
                "expected_outcome": "blocked",
                "observed_outcome": "leaked",
                "decisive_receipt_ref": "rcpt:1",
                "passed": True,
            },
            {
                "case_id": "p2",
                "varied_factor": "y",
                "expected_outcome": "blocked",
                "observed_outcome": "blocked",
                "receipt_present": False,
                "expects_unverified_on_missing_receipt": True,
                "passed": "false",
            },
        ]
    )
    assert pert[0].conclusion_state == "failed_regression" and pert[0].passed is False
    assert pert[1].conclusion_state == "unverified" and pert[1].passed is False

    # 7. Discordance evaluator string booleans
    disc = evaluate_agent_discordance(
        {
            "routes": [
                {
                    "route_id": "r1",
                    "agent_id": "agent-a",
                    "principal_scope": "owner",
                    "continuity_group": "g1",
                    "canary_task_id": "canary-1",
                    "explicit_privacy_boundary": "false",
                }
            ]
        },
        {
            "observations": [
                {
                    "route_id": "r1",
                    "caller_receipt_id": "c1",
                    "authz_receipt_id": "a1",
                    "observed_agent_id": "agent-a",
                    "canary_recovered": "false",
                }
            ]
        },
    )
    assert any(v.rule_code == "DISC-001" for v in disc.violations)


def test_p1_11_trivy_sarif_and_json_secret_title_redaction(tmp_path: Path) -> None:
    sarif_p = tmp_path / "trivy.sarif"
    sarif_p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "generic-rule", "shortDescription": {"text": "Generic Secret"}}]}},
                        "results": [
                            {
                                "ruleId": "generic-rule",
                                "level": "error",
                                "properties": {"tags": ["secret"]},
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
    fake_aws = f"{'AKIA'}{'IOSFODNN7EXAMPLE'}"
    sarif_summary = json.dumps(_parse_trivy_report(sarif_p))
    assert "CUSTOM_LEAK_999" not in sarif_summary
    assert fake_aws not in sarif_summary

    tjson_p = tmp_path / "trivy.json"
    tjson_p.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "app",
                        "Secrets": [
                            {
                                "RuleID": "generic-secret",
                                "Severity": "HIGH",
                                "Title": f"Secret CUSTOM_LEAK_999\nMatch: {fake_aws}",
                                "Match": fake_aws,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    tjson_summary = json.dumps(_parse_trivy_report(tjson_p))
    assert "CUSTOM_LEAK_999" not in tjson_summary
    assert fake_aws not in tjson_summary


def test_r2_trivy_no_match_secret_titles_redacted(tmp_path: Path) -> None:
    sarif_p = tmp_path / "trivy-nomatch.sarif"
    sarif_p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "generic-rule", "shortDescription": {"text": "Secret CUSTOM_LEAK_999"}}]}},
                        "results": [
                            {
                                "ruleId": "generic-rule",
                                "level": "error",
                                "properties": {"tags": ["secret"]},
                                "message": {"text": "Secret CUSTOM_LEAK_999"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert "CUSTOM_LEAK_999" not in json.dumps(_parse_trivy_report(sarif_p))

    tjson_p = tmp_path / "trivy-nomatch.json"
    tjson_p.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "app",
                        "Secrets": [
                            {
                                "RuleID": "generic-secret",
                                "Severity": "HIGH",
                                "Title": "Secret CUSTOM_LEAK_999",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert "CUSTOM_LEAK_999" not in json.dumps(_parse_trivy_report(tjson_p))


def test_r2_p1_9_slow_chunk_wall_clock_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.viewport_service as vp_mod

    class _SlowDripHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _drip(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "250")
            self.end_headers()
            try:
                for _ in range(25):
                    self.wfile.write(b"0123456789")
                    self.wfile.flush()
                    time.sleep(0.12)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def do_GET(self) -> None:
            self._drip()

        def do_POST(self) -> None:
            raw_cl = self.headers.get("Content-Length")
            if raw_cl and int(raw_cl) > 0:
                self.rfile.read(int(raw_cl))
            self._drip()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SlowDripHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            _stream_httpx_request("GET", f"http://127.0.0.1:{port}/v1/models", timeout=0.35, max_bytes=1048576)
        assert time.monotonic() - t0 < 1.2

        monkeypatch.setattr(vp_mod, "_HTTP_TIMEOUT_SEC", 0.35)
        t1 = time.monotonic()
        with pytest.raises(RuntimeError, match="deadline"):
            _post_viewport_command_http(ViewportCommand(target_slug="demo"), f"http://127.0.0.1:{port}")
        assert time.monotonic() - t1 < 1.2
    finally:
        srv.shutdown()
        srv.server_close()


def test_r2_p1_13_investigation_cross_target_actions_rejected(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    repo_a = _write_minimal_repo(tmp_path / "repo-a")
    repo_b = _write_minimal_repo(tmp_path / "repo-b")
    register_target(db_session, TargetProjectCreate(slug="repo-a", name="Repo A", repo_path=str(repo_a)))
    register_target(db_session, TargetProjectCreate(slug="repo-b", name="Repo B", repo_path=str(repo_b)))
    create_or_reopen_investigation(
        db_session,
        InvestigationCreateRequest(target_slug="repo-a", session_id="sess-a"),
    )

    for action_args in (
        {"action": "get_session", "target": "repo-b", "session_id": "sess-a"},
        {"action": "record_correction", "target": "repo-b", "session_id": "sess-a", "note": "x"},
        {"action": "set_follow", "target": "repo-b", "session_id": "sess-a", "follow_state": "paused"},
        {"action": "compare_revisions", "target": "repo-b", "session_id": "sess-a"},
        {"action": "create_session", "target": "repo-b", "session_id": "sess-a"},
        {"action": "get_receipts", "target": "repo-b", "session_id": "sess-a"},
    ):
        res = mcp_service.dispatch_mcp_request(
            db_session,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "wythe_investigation", "arguments": action_args},
            },
        )
        assert res["result"]["isError"] is True, action_args
        assert "Cross-target mismatch" in res["result"]["content"][0]["text"]


def test_r2_p1_2_understanding_and_discordance_bypasses_closed() -> None:
    from app.services.understanding_discordance import _strict_bool as ud_strict_bool
    from app.services.understanding_service import _strict_bool as us_strict_bool
    from wythe_plugin_agent_discordance.evaluator import _strict_bool as ev_strict_bool

    # 1. declared-only transition with state_digest cannot settle as settled_committed
    decl_only = explain_outcome_lifecycle(
        {
            "outcome_id": "decl-only",
            "authoritative_terminal_state": "committed",
            "transitions": [{"stage": "declared", "state_digest": "d0"}],
        }
    )
    assert decl_only.settlement_state != "settled_committed"
    assert decl_only.settlement_state == "indeterminate_requires_settlement"
    assert decl_only.positive_commit_established is False

    # 2. broken 3-step request_id chain (lost_reply=False) cannot settle as settled_committed
    broken_3step = explain_outcome_lifecycle(
        {
            "outcome_id": "3step",
            "authoritative_terminal_state": "committed",
            "transitions": [
                {"stage": "declared", "request_id": "r1", "state_digest": "d0"},
                {"stage": "executed", "request_id": "r1", "predecessor_state_digest": "d0", "state_digest": "d1"},
                {"stage": "authoritatively_settled", "request_id": "r1", "state_digest": "d2"},
            ],
        }
    )
    assert broken_3step.predecessor_chain_verified is False
    assert broken_3step.settlement_state == "indeterminate_requires_settlement"

    # 3. _scan_delivery_receipt_node negative/error/nullish/status values
    for bad_rcpt in (
        {"id": "r1", "detail": {"error_code": 500}},
        {"id": "r1", "detail": {"failed": 1}},
        {"id": "r1", "delivered": "none"},
        {"id": "r1", "delivered": 0.0},
        {"id": "r1", "status": "cancelled"},
        {"id": "r1", "status": "canceled"},
        {"id": "r1", "status": "bounced"},
        {"id": "r1", "status": "expired"},
        {"id": "r1", "status": "nack"},
    ):
        assert _is_positive_delivery_receipt_value(bad_rcpt) is False, bad_rcpt

    # 4. settlement_receipt=0 / 0.0 and _strict_bool(0.0, default=True)
    for zero_val in (0, 0.0):
        assert us_strict_bool(zero_val, default=True) is False
        assert ud_strict_bool(zero_val, default=True) is False
        assert ev_strict_bool(zero_val, default=True) is False
        rcpt_zero = explain_outcome_lifecycle(
            {
                "outcome_id": "rcpt-0",
                "authoritative_terminal_state": "committed",
                "settlement_digest": "sd-1",
                "settlement_receipt": zero_val,
            }
        )
        assert rcpt_zero.settlement_state != "settled_committed"
        assert rcpt_zero.settlement_state == "indeterminate_requires_settlement"

    # 5. #117 link propagation upgrades unresolved links[4] and historical/unresolved links[5]
    prop_rep = analyze_understanding_bundle(
        {
            "bundle": {
                "question": "Check #117 link propagation onto unresolved & historical links",
                "rule_prediction_comparisons": [
                    {
                        "comparison_id": "rc1",
                        "owner_rule": {"rule_id": "R-1", "statement": "rule", "source_ref": "a.py:1"},
                        "implementation_predictions": [
                            {
                                "prediction_id": "p1",
                                "predicted_at_boundary": "block",
                                "source_ref": "a.py:2",
                                "match_state": "refuted_by_observation",
                            }
                        ],
                        "observed_result": {"summary": "exposed", "source_ref": "obs:1"},
                    }
                ],
                "documentation_claims": [
                    {
                        "claim_id": "dc1",
                        "path": "README.md",
                        "claim_revision": "old-sha",
                        "source_or_evidence_changed": True,
                    }
                ],
                "perturbation_matrix": [
                    {
                        "case_id": "p3",
                        "varied_factor": "z",
                        "expected_outcome": "blocked",
                        "observed_outcome": "bypassed_and_exposed",
                        "decisive_receipt_ref": "r1",
                        "passed": True,
                    }
                ],
            }
        }
    )
    assert prop_rep.links[4].state == "degraded_or_drifted"
    assert prop_rep.links[5].state == "regression_detected"
    assert prop_rep.perturbation_matrix[0].conclusion_state == "failed_regression"
    assert prop_rep.perturbation_matrix[0].passed is False


def test_r3_viewport_422_and_userinfo_authority_confusion(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    repo_a = _write_minimal_repo(tmp_path / "r3-repo-a")
    repo_b = _write_minimal_repo(tmp_path / "r3-repo-b")
    register_target(db_session, TargetProjectCreate(slug="r3-a", name="R3 A", repo_path=str(repo_a)))
    register_target(db_session, TargetProjectCreate(slug="r3-b", name="R3 B", repo_path=str(repo_b)))
    create_or_reopen_investigation(
        db_session,
        InvestigationCreateRequest(target_slug="r3-a", session_id="r3-sess-a"),
    )

    app = create_app()
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/viewport/command",
            json={"target_slug": "r3-b", "session_id": "r3-sess-a"},
        )
        assert resp.status_code == 422, resp.text
        assert "r3-a" in resp.json()["detail"]

    # Userinfo authority-confusion URLs fail closed; stripped URLs never forward Authorization
    confusion_url = "http://127.0.0.1@169.254.169.254/v1"
    with pytest.raises(ValueError):
        _normalize_private_v1_url(confusion_url)
    with pytest.raises(ValueError):
        _validate_viewport_server_url(confusion_url, allow_remote=False)
    with pytest.raises(ValueError):
        apply_live_route_probe(
            [RawCandidateFinding("DISP-004", "warn", "a.py", 1, "x", "t", "d", "r", "GET", "/x")],
            confusion_url,
        )

    seen_auth: list[str | None] = []

    class _AuthCheckHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            seen_auth.append(self.headers.get("Authorization"))
            body = json.dumps({"data": [{"id": "m1"}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AuthCheckHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        stripped = _normalize_private_v1_url(f"http://alice:secret@{srv.server_address[0]}:{port}")
        assert stripped == f"http://127.0.0.1:{port}/v1"
        status_code, _hdrs, _raw = _stream_httpx_request(
            "GET",
            f"http://alice:secret@127.0.0.1:{port}/v1/models",
            timeout=2.0,
            max_bytes=4096,
        )
        assert status_code == 200
        assert seen_auth == [None]
    finally:
        srv.shutdown()
        srv.server_close()


def test_r3_p1_2_and_p1_11_challenger2_regressions(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    from app.services.understanding_discordance import _strict_bool as ud_strict_bool
    from app.services.understanding_service import _strict_bool as us_strict_bool
    from wythe_plugin_agent_discordance.evaluator import (
        _strict_bool as ev_strict_bool,
    )
    from wythe_plugin_agent_discordance.evaluator import (
        evaluate_agent_discordance,
    )

    assert isolated_db_url.startswith("sqlite:")

    # 1. Challenger 2 #1: _scan_delivery_receipt_node rejects negative strings/numbers & error keys
    bad_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": "undelivered"},
        {"id": "r1", "delivered": "rejected"},
        {"id": "r1", "delivered": -1},
        {"id": "r1", "rendered": "failed"},
        {"id": "r1", "detail": {"error_message": "boom"}},
        {"id": "r1", "detail": {"reason": "failed"}},
        {"id": "r1", "detail": {"status_code": 500}},
        {"id": "r1", "http_status": 500},
    )
    for bad in bad_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad

    for good in (
        {"id": "r1", "delivered": 1},
        {"id": "r1", "delivered": "ok"},
        {"id": "r1", "delivered": "sent"},
        {"id": "r1", "delivered": "delivered"},
        {"id": "r1", "detail": {"reason": "user_requested", "status_code": 200}},
    ):
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        for bad in bad_rcpts:
            resp = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r3",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "sd-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        # 2. Challenger 2 #2 + Reviewer 2 Minor 1 + Reviewer 1 note via API & evaluator
        resp_pert = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": "nb",
                            "varied_factor": "x",
                            "expected_outcome": "blocked",
                            "observed_outcome": "not blocked",
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                    ]
                }
            },
        )
        assert resp_pert.status_code == 200
        pert_item = resp_pert.json()["perturbation_matrix"][0]
        assert pert_item["conclusion_state"] == "failed_regression"
        assert pert_item["passed"] is False

    bad_pairs = (
        ("blocked", "not blocked"),
        ("blocked", "never_denied"),
        ("blocked", "unblocked"),
        ("denied", "executed"),
        ("denied", "returned_secret"),
        ("isolated", "shared_memory_read"),
        ("redacted", "plaintext_emitted"),
        ("refused", "completed"),
        ("blocked", "no error; request allowed"),
        ("no error", "error"),
    )
    for exp_s, obs_s in bad_pairs:
        res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert res[0].passed is False, (exp_s, obs_s)

    for ok_obs in ("fail_closed_blocked", "blocked_without_error"):
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": ok_obs,
                    "varied_factor": "v",
                    "expected_outcome": "blocked",
                    "observed_outcome": ok_obs,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", ok_obs
        assert ok_res[0].passed is True, ok_obs

    # 3. Challenger 2 #3: SARIF plural "secrets" tag + webhook ruleId scrubbed unconditionally
    sarif_wh = tmp_path / "trivy-webhook.sarif"
    sarif_wh.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "slack-webhook",
                                        "shortDescription": {"text": "Secret CUSTOM_LEAK_999"},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "slack-webhook",
                                "level": "error",
                                "properties": {"tags": ["secrets"]},
                                "message": {"text": "Secret CUSTOM_LEAK_999"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    parsed_wh = _parse_trivy_report(sarif_wh)
    assert parsed_wh["secret_count"] == 1
    assert parsed_wh["misconfiguration_count"] == 0
    assert "CUSTOM_LEAK_999" not in json.dumps(parsed_wh)
    assert parsed_wh["sample_findings"][0]["category"] == "secret"  # type: ignore[index]

    # 4. Challenger 2 #4: broken 4-step chain with rolled_back -> indeterminate_requires_settlement
    broken_4step_rb = explain_outcome_lifecycle(
        {
            "outcome_id": "4step-rb",
            "authoritative_terminal_state": "rolled_back",
            "transitions": [
                {"stage": "declared", "request_id": "r1", "state_digest": "d0"},
                {"stage": "granted_not_executed", "request_id": "r1", "predecessor_state_digest": "d0", "state_digest": "d1"},
                {"stage": "executed", "request_id": "r1", "predecessor_state_digest": "d1", "state_digest": "d2"},
                {"stage": "authoritatively_settled", "request_id": "r1", "state_digest": "d3"},
            ],
        }
    )
    assert broken_4step_rb.predecessor_chain_verified is False
    assert broken_4step_rb.settlement_state == "indeterminate_requires_settlement"

    # 5. Challenger 2 #5: canary_recovered=1/1.0 triggers DISC-002 + _strict_bool("0.0", default=True)
    for truthy_one in (1, 1.0, "1"):
        disc_one = evaluate_agent_discordance(
            {
                "routes": [
                    {"route_id": "r_owner", "agent_id": "agent_a", "canary_task_id": "t1"},
                    {"route_id": "r_other", "agent_id": "agent_b"},
                ]
            },
            {
                "observations": [
                    {
                        "route_id": "r_owner",
                        "caller_receipt_id": "c1",
                        "authz_receipt_id": "a1",
                        "observed_agent_id": "agent_a",
                    },
                    {
                        "route_id": "r_other",
                        "caller_receipt_id": "c2",
                        "authz_receipt_id": "a2",
                        "observed_agent_id": "agent_b",
                        "accessed_task_id": "t1",
                        "canary_recovered": truthy_one,
                    },
                ]
            },
        )
        assert disc_one.mismatched_routes == ["r_other"], truthy_one
        assert any(v.rule_code == "DISC-002" for v in disc_one.violations), truthy_one

    for zero_str in ("0.0", 0, 0.0):
        assert us_strict_bool(zero_str, default=True) is False
        assert ud_strict_bool(zero_str, default=True) is False
        assert ev_strict_bool(zero_str, default=True) is False


def test_r4_p1_2_and_p1_11_challenger2_reviewer2_regressions(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. Challenger 2 #1: proximity_rejected (req-1 -> req-2 & temporal_proximity_only=True) forces indeterminate
    cross_req_payload = {
        "outcome_id": "cross-req",
        "authoritative_terminal_state": "committed",
        "settlement_digest": "d3",
        "settlement_receipt": "sr-1",
        "lost_reply": False,
        "transitions": [
            {"stage": "declared", "request_id": "req-1", "state_digest": "d1"},
            {"stage": "executed", "request_id": "req-1", "predecessor_state_digest": "d1", "state_digest": "d2"},
            {
                "stage": "authoritatively_settled",
                "request_id": "req-2",
                "predecessor_state_digest": "d2",
                "state_digest": "d3",
            },
        ],
    }
    prox_only_payload = {
        "outcome_id": "prox-only",
        "authoritative_terminal_state": "committed",
        "settlement_digest": "d3",
        "settlement_receipt": "sr-1",
        "temporal_proximity_only": True,
        "lost_reply": False,
    }
    for payload in (cross_req_payload, prox_only_payload):
        out = explain_outcome_lifecycle(payload)
        assert out.proximity_join_rejected is True
        assert out.predecessor_chain_verified is False
        assert out.positive_commit_established is False
        assert out.current_stage == "committed_unacknowledged"
        assert out.settlement_state == "indeterminate_requires_settlement"

    # Non-settlement unlinked transitions still remain not_applicable
    non_settle = explain_outcome_lifecycle(
        {
            "outcome_id": "non-settle",
            "transitions": [
                {"stage": "executed", "request_id": "req-1", "state_digest": "d1"},
                {"stage": "delivered_to_human", "request_id": "req-2"},
            ],
        }
    )
    assert non_settle.settlement_state == "not_applicable"
    assert non_settle.positive_commit_established is False

    # 2. Challenger 2 #2 + Reviewer 2 Minor 2: _scan_delivery_receipt_node edge cases
    bad_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "status_code": "500 Internal Server Error"},
        {"id": "r1", "delivered": True, "detail": {"status_code": "503 Service Unavailable"}},
        {"id": "r1", "status_code": "404.0"},
        {"id": "r1", "http_status": "-1"},
        {"id": "r1", "detail": {"error_msg": "boom"}},
        {"id": "r1", "detail": {"err_reason": "timeout"}},
        {"id": "r1", "detail": {"error_desc": "bad gateway"}},
        {"id": "r1", "detail": {"error_description": "failed"}},
        {"id": "r1", "detail": {"reason": "not_delivered"}},
        {"id": "r1", "detail": {"reason": "not delivered"}},
        {"id": "r1", "detail": {"reason": "not rendered"}},
        {"id": "r1", "detail": {"reason": "not acknowledged"}},
        {"id": "r1", "detail": {"reason": "not sent"}},
        {"id": "r1", "detail": {"reason": "declined"}},
        {"id": "r1", "detail": {"reason": "throttled"}},
        {"id": "r1", "status": "not_delivered"},
        {"id": "r1", "delivered": [False]},
        {"id": "r1", "delivered": [0]},
        {"id": "r1", "delivered": [None]},
        {"id": "r1", "delivered": ["undelivered"]},
        {"id": "r1", "delivered": [True, False]},
    )
    for bad in bad_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad

    for good in (
        {"id": "r1", "status_code": "200"},
        {"id": "r1", "status_code": "204"},
        {"id": "r1", "status_code": 200},
        {"id": "r1", "delivered": [True]},
        {"id": "r1", "delivered": [1]},
    ):
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        for payload in (cross_req_payload, prox_only_payload):
            r_life = client.post(
                "/api/v1/understanding/analyze",
                json={"bundle": {"outcomes": [payload]}},
            )
            assert r_life.status_code == 200, r_life.text
            lc = r_life.json()["outcome_lifecycles"][0]
            assert lc["current_stage"] == "committed_unacknowledged"
            assert lc["settlement_state"] == "indeterminate_requires_settlement"

        for bad in (
            {"id": "r1", "status_code": "500 Internal Server Error"},
            {"id": "r1", "detail": {"error_msg": "boom"}},
            {"id": "r1", "detail": {"reason": "not_delivered"}},
            {"id": "r1", "delivered": [False]},
        ):
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r4",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "sd-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        # 3. Challenger 2 #3 + Reviewer 2 Minor 1 via API & evaluator
        api_contradictions = (
            ("blocked", "200 ok"),
            ("blocked", "served"),
            ("request allowed", "request blocked"),
            ("isolated", "cross_tenant_data_served"),
            ("redacted", "unmasked_token_logged"),
        )
        r_pert = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(api_contradictions)
                    ]
                }
            },
        )
        assert r_pert.status_code == 200, r_pert.text
        for item in r_pert.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

    extra_contradictions = (
        ("blocked", "200"),
        ("blocked", "http 200"),
        ("blocked", "wasn't blocked"),
        ("blocked", "wasnt blocked"),
        ("blocked", "isn't blocked"),
        ("blocked", "didn't block"),
        ("blocked", "couldn't block"),
        ("blocked", "can't block"),
        ("blocked", "cannot block"),
        ("blocked", "permitted"),
        ("blocked", "granted"),
        ("blocked", "accepted"),
        ("blocked", "succeeded"),
        ("blocked", "passed"),
        ("request_allowed", "request_blocked"),
        ("request allowed", "not allowed"),
        ("request permitted", "denied"),
        ("request accepted", "rejected"),
        ("request granted", "refused"),
        ("request succeeded", "failed"),
        ("request passed", "wasn't allowed"),
    )
    for exp_s, obs_s in extra_contradictions:
        res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"c-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert res[0].passed is False, (exp_s, obs_s)

    defensive_non_contradictions = (
        ("blocked", "fail_closed_blocked"),
        ("blocked", "blocked_without_error"),
        ("blocked", "blocked, leak-free"),
        ("blocked", "blocked; zero leak"),
        ("blocked", "blocked; not allowed"),
        ("blocked", "error_free"),
        ("blocked", "blocked task-200"),
        ("request allowed", "not blocked; request allowed"),
    )
    for exp_s, obs_s in defensive_non_contradictions:
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"ok-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    # 4. Challenger 2 #4: SARIF tags=["credential"] and tags=["token"] scrub unconditionally
    for tag_name in ("credential", "token"):
        sarif_tag = tmp_path / f"trivy-{tag_name}.sarif"
        sarif_tag.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "rules": [
                                        {
                                            "id": "custom-rule-id",
                                            "shortDescription": {"text": "Secret CUSTOM_LEAK_999"},
                                        }
                                    ]
                                }
                            },
                            "results": [
                                {
                                    "ruleId": "custom-rule-id",
                                    "level": "error",
                                    "properties": {"tags": [tag_name]},
                                    "message": {"text": "Secret CUSTOM_LEAK_999"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        parsed_tag = _parse_trivy_report(sarif_tag)
        assert parsed_tag["secret_count"] == 1, tag_name
        assert parsed_tag["misconfiguration_count"] == 0, tag_name
        assert "CUSTOM_LEAK_999" not in json.dumps(parsed_tag), tag_name
        assert parsed_tag["sample_findings"][0]["title"] == "Detected secret rule match", tag_name  # type: ignore[index]


def test_r5_p1_2_and_p1_11_challenger2_regressions(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. Challenger 2 #1: compound failure statuses, status_code=0, HTTP/1.x 500, and "500, ..."
    bad_r5_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "status": "delivery_failed"},
        {"id": "r1", "status": "send_failed"},
        {"id": "r1", "status": "render_failed"},
        {"id": "r1", "status": "undeliverable"},
        {"id": "r1", "delivery_status": "delivery_failed"},
        {"id": "r1", "status_code": 0},
        {"id": "r1", "status_code": "0"},
        {"id": "r1", "status_code": "HTTP/1.1 500 Internal Server Error"},
        {"id": "r1", "status_code": "HTTP/1.0 503 Service Unavailable"},
        {"id": "r1", "status_code": "500, Internal Server Error"},
        {"id": "r1", "http_status": 199},
    )
    for bad in bad_r5_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad

    good_r5_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "status": "delivered"},
        {"id": "r1", "status": "ok"},
        {"id": "r1", "status": "completed", "delivered": True},
        {"id": "r1", "status_code": "HTTP/1.1 200 OK"},
        {"id": "r1", "status_code": "200"},
        {"id": "r1", "status_code": "204"},
        {"id": "r1", "status_code": "201 Created"},
        {"id": "r1", "status_code": "200, OK"},
    )
    for good in good_r5_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    # 2. Challenger 2 #2 + Reviewer 2 Minor 2: _perturbation_outcomes_contradict & evaluate_perturbation_matrix
    r5_contradictions: tuple[tuple[str, str], ...] = (
        ("redacted", "unmasked_token_logged"),
        ("redacted", "secret_logged"),
        ("redacted", "plaintext_logged"),
        ("isolated", "cross_tenant_read"),
        ("isolated", "cross_tenant_access"),
        ("isolated", "cross tenant access"),
        ("blocked", "201 created"),
        ("blocked", "204 no content"),
        ("blocked", "200, ok"),
        ("blocked", "200 ok"),
        ("request allowed", "403 forbidden"),
        ("request allowed", "forbidden"),
        ("request allowed", "unauthorized"),
        ("request allowed", "timed_out"),
        ("request allowed", "timeout"),
        ("request allowed", "throttled"),
        ("request allowed", "unavailable"),
        ("request allowed", "401"),
        ("request allowed", "404"),
        ("request allowed", "429"),
        ("request allowed", "500"),
        ("request allowed", "502"),
        ("request allowed", "503"),
        ("request allowed", "504"),
    )
    for exp_s, obs_s in r5_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r5-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert res[0].passed is False, (exp_s, obs_s)

    r5_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; audit_logged"),
        ("redacted", "redacted; event_logged"),
        ("blocked", "blocked; wasn't served"),
        ("blocked", "blocked; not 200 ok"),
        ("blocked", "blocked task-200"),
        ("isolated", "cross_tenant_blocked"),
        ("isolated", "isolated; no cross_tenant_access"),
        ("request allowed", "not forbidden; request allowed"),
        ("request allowed", "not 403; request allowed"),
        ("request allowed", "not timed_out; request allowed"),
        ("request allowed", "wasn't throttled; request allowed"),
        ("request allowed", "request allowed; task-403"),
    )
    for exp_s, obs_s in r5_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r5-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    app = create_app()
    with TestClient(app) as client:
        for bad in (
            {"id": "r1", "status": "delivery_failed"},
            {"id": "r1", "status": "send_failed"},
            {"id": "r1", "status": "undeliverable"},
            {"id": "r1", "status_code": 0},
            {"id": "r1", "status_code": "HTTP/1.1 500 Internal Server Error"},
            {"id": "r1", "status_code": "500, Internal Server Error"},
        ):
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r5",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "sd-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        api_fail_cases = (
            ("request allowed", "403 forbidden"),
            ("request allowed", "timed_out"),
            ("isolated", "cross_tenant_read"),
            ("blocked", "201 created"),
            ("blocked", "200, ok"),
            ("redacted", "secret_logged"),
        )
        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(api_fail_cases)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok_cases = (
            ("blocked", "blocked; audit_logged"),
            ("redacted", "redacted; event_logged"),
            ("blocked", "blocked; wasn't served"),
            ("request allowed", "not forbidden; request allowed"),
        )
        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(api_ok_cases)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

    # 3. Challenger 2 #3: SARIF tags secret matching and unconditional scrubbing even with "vulnerability" tag
    for tag_list, expected_cat in (
        (["password"], "secret"),
        (["api-key"], "secret"),
        (["api_key"], "secret"),
        (["bearer"], "secret"),
        (["oauth"], "secret"),
        (["jwt"], "secret"),
        (["private-key"], "secret"),
        (["webhook"], "secret"),
        (["secret", "vulnerability"], "vulnerability"),
    ):
        sarif_r5 = tmp_path / f"trivy-{'-'.join(tag_list)}.sarif"
        sarif_r5.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "rules": [
                                        {
                                            "id": "custom-rule-id",
                                            "shortDescription": {"text": "Secret CUSTOM_LEAK_999"},
                                        }
                                    ]
                                }
                            },
                            "results": [
                                {
                                    "ruleId": "custom-rule-id",
                                    "level": "error",
                                    "properties": {"tags": tag_list},
                                    "message": {"text": "Secret CUSTOM_LEAK_999"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        parsed_r5 = _parse_trivy_report(sarif_r5)
        assert "CUSTOM_LEAK_999" not in json.dumps(parsed_r5), tag_list
        sample = parsed_r5["sample_findings"][0]  # type: ignore[index]
        assert sample["category"] == expected_cat, (tag_list, sample)
        assert sample["title"] == "Detected secret rule match", (tag_list, sample)


def test_r6_p1_2_and_p1_11_challenger2_regressions(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. P1-2 Delivery Receipts: scalar strings, sequence items, delivery_state, descriptive keys, HTTP/status prefixes
    bad_r6_rcpts: tuple[Any, ...] = (
        "delivery_failed",
        "send_failed",
        "not_ok",
        "rate_limited",
        ["r1", "delivery_failed"],
        ["r1", "rate_limited"],
        {"id": "r1", "receipts": ["r2", "delivery_failed"]},
        {"id": "r1", "delivery_state": "failed"},
        {"id": "r1", "detail": "delivery failed"},
        {"id": "r1", "message": "not delivered"},
        {"id": "r1", "note": "rate_limited"},
        {"id": "r1", "description": "bad gateway"},
        {"id": "r1", "summary": "not ok"},
        {"id": "r1", "status": "not_ok"},
        {"id": "r1", "status": "rate_limited"},
        {"id": "r1", "reason": "forbidden"},
        {"id": "r1", "reason": "unauthorized"},
        {"id": "r1", "reason": "not ok"},
        {"id": "r1", "status_code": "HTTP 403 Forbidden"},
        {"id": "r1", "status_code": "HTTP 502 Bad Gateway"},
        {"id": "r1", "status_code": "status=500"},
        {"id": "r1", "status_code": "code=503"},
    )
    for bad in bad_r6_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
    assert _scan_delivery_receipt_node(["r1", "delivery_failed"]) == (False, True)
    assert _scan_delivery_receipt_node({"id": "r1", "detail": "delivery failed"}) == (False, True)
    assert _scan_delivery_receipt_node({"id": "r1", "message": "not delivered"}) == (False, True)

    good_r6_rcpts: tuple[Any, ...] = (
        "r1",
        "receipt-123",
        "receipt-rate-1",
        {"id": "r1", "detail": "ok"},
        {"id": "r1", "message": "delivered"},
        {"id": "r1", "delivery_state": "delivered"},
        {"id": "r1", "status_code": "200"},
        {"id": "r1", "status_code": "201 Created"},
        {"id": "r1", "status_code": "204"},
        {"id": "r1", "status_code": "200, OK"},
        {"id": "r1", "status_code": "HTTP/1.1 200 OK"},
        {"id": "r1", "status_code": "HTTP 200 OK"},
        {"id": "r1", "status_code": "status=200"},
    )
    for good in good_r6_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    # 2. P1-2 Perturbation Discordance: normalization order, 0-2 word negator lookback, delivered/response/abort/drop/409
    r6_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "delivered_to_user"),
        ("blocked", "response 200"),
        ("blocked", "no auth and delivered_to_user"),
        ("request allowed", "dropped"),
        ("request allowed", "aborted"),
        ("request allowed", "cancelled"),
        ("request allowed", "canceled"),
        ("request allowed", "rate_limited"),
        ("request allowed", "409 conflict"),
        ("request allowed", "unauthorized"),
        ("blocked", "blocked; not unauthorized"),
    )
    for exp_s, obs_s in r6_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r6-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert res[0].passed is False, (exp_s, obs_s)

    r6_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; didn't leak"),
        ("blocked", "blocked; no_data_shared"),
        ("blocked", "blocked; no_records_returned"),
        ("blocked", "blocked; zero_writes_executed"),
        ("blocked", "blocked; couldn't be served"),
        ("blocked", "blocked; didn't get served"),
        ("blocked", "blocked; no_data_delivered"),
        ("blocked", "blocked; not 202 accepted"),
        ("blocked", "blocked task-200"),
        ("request allowed", "request allowed; not unauthorized"),
        ("granted", "granted; wasn't unauthorized; ticket-500"),
        ("request allowed", "request allowed; task-409"),
        ("request allowed", "not rate_limited; request allowed"),
        ("request allowed", "allowed; high_rate"),
    )
    for exp_s, obs_s in r6_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r6-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    # 3. Live FastAPI POST /api/v1/understanding/analyze checks
    app = create_app()
    with TestClient(app) as client:
        for bad in (
            "delivery_failed",
            "send_failed",
            ["r1", "delivery_failed"],
            {"id": "r1", "delivery_state": "failed"},
            {"id": "r1", "detail": "delivery failed"},
            {"id": "r1", "message": "not delivered"},
            {"id": "r1", "status": "not_ok"},
            {"id": "r1", "status": "rate_limited"},
            {"id": "r1", "reason": "forbidden"},
            {"id": "r1", "status_code": "HTTP 403 Forbidden"},
            {"id": "r1", "status_code": "HTTP 502 Bad Gateway"},
            {"id": "r1", "status_code": "status=500"},
        ):
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r6",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "sd-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r6-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(
                            (
                                ("blocked", "delivered_to_user"),
                                ("request allowed", "dropped"),
                                ("request allowed", "aborted"),
                                ("request allowed", "rate_limited"),
                                ("request allowed", "409 conflict"),
                            )
                        )
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r6-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(
                            (
                                ("blocked", "blocked; no_data_shared"),
                                ("blocked", "blocked; no_records_returned"),
                                ("blocked", "blocked; zero_writes_executed"),
                                ("blocked", "blocked; couldn't be served"),
                                ("blocked", "blocked; didn't leak"),
                                ("blocked", "blocked; not 202 accepted"),
                                ("request allowed", "request allowed; not unauthorized"),
                            )
                        )
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

    # 4. P1-11 SARIF secret tag scrubbing vs benign DB/structural tags
    for tag_list, expected_cat, expect_scrubbed in (
        (["signing-key"], "secret", True),
        (["signing_key"], "secret", True),
        (["access-key"], "secret", True),
        (["access_key"], "secret", True),
        (["ssh-key"], "secret", True),
        (["ssh_key"], "secret", True),
        (["pat"], "secret", True),
        (["github-pat"], "secret", True),
        (["primary-key"], "misconfiguration", False),
        (["foreign-key"], "misconfiguration", False),
        (["broken-authentication"], "misconfiguration", False),
    ):
        sarif_r6 = tmp_path / f"trivy-r6-{'-'.join(tag_list)}.sarif"
        sarif_r6.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "rules": [
                                        {
                                            "id": "custom-rule-id",
                                            "shortDescription": {"text": "Secret CUSTOM_LEAK_999"},
                                        }
                                    ]
                                }
                            },
                            "results": [
                                {
                                    "ruleId": "custom-rule-id",
                                    "level": "error",
                                    "properties": {"tags": tag_list},
                                    "message": {"text": "Secret CUSTOM_LEAK_999"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        parsed_r6 = _parse_trivy_report(sarif_r6)
        sample = parsed_r6["sample_findings"][0]  # type: ignore[index]
        assert sample["category"] == expected_cat, (tag_list, sample)
        if expect_scrubbed:
            assert "CUSTOM_LEAK_999" not in json.dumps(parsed_r6), tag_list
            assert sample["title"] == "Detected secret rule match", (tag_list, sample)
        else:
            assert sample["title"] == "Secret CUSTOM_LEAK_999", (tag_list, sample)


def test_r7_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. P1-2 Perturbation Discordance: clause-local negator preservation, negated markers, bare 2xx
    r7_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; not allowed to be served"),
        ("blocked", "blocked; not permitted to execute"),
        ("blocked", "blocked; wasn't permitted to share data"),
        ("blocked", "blocked; not allowed"),
        ("blocked", "blocked; no_pii_disclosed"),
        ("blocked", "blocked; no_secrets_exposed"),
        ("blocked", "blocked; zero_data_exfiltrated"),
        ("blocked", "blocked; never got leaked; without any records shared"),
        ("blocked", "blocked; wasn't leaking"),
        ("request allowed", "request allowed; couldn't fail"),
        ("blocked", "blocked; not status: 200"),
        ("blocked", "blocked; not 200"),
        ("blocked", "blocked task-200"),
        ("blocked", "blocked; ref-200"),
        ("blocked", "blocked; build_200"),
        ("request allowed", "request allowed; not unauthorized"),
        ("granted", "granted; wasn't unauthorized; ticket-500"),
    )
    for exp_s, obs_s in r7_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r7-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    r7_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "not allowed"),
        ("blocked", "no auth and data_disclosed"),
        ("blocked", "pii_exposed"),
        ("blocked", "secrets_exfiltrated"),
        ("request allowed", "fail"),
        ("request allowed", "request allowed; fail"),
        ("blocked", "blocked; not unauthorized"),
        ("request allowed", "not unauthorized"),
        ("blocked", "blocked; 200"),
        ("blocked", "blocked; 201"),
        ("blocked", "blocked; 202"),
        ("blocked", "blocked; 204"),
    )
    for exp_s, obs_s in r7_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r7-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    # 2. P1-2 Delivery Receipt Scanning: rate limit exceeded, negated auth/deliver, sequence False/0/None, negative IDs
    bad_r7_rcpts: tuple[Any, ...] = (
        {"id": "r1", "status": "rate limit exceeded"},
        {"id": "r1", "detail": "rate limit exceeded"},
        {"id": "r1", "detail": "not_authorized"},
        {"id": "r1", "detail": "not authorized"},
        {"id": "r1", "detail": "couldn't deliver"},
        {"id": "r1", "detail": "unable to deliver"},
        {"id": "r1", "events": ["ok", False]},
        {"id": "r1", "events": ["ok", 0]},
        {"id": "r1", "events": ["ok", None]},
        {"id": "delivery_failed"},
        {"receipt_id": "send_failed"},
    )
    for bad in bad_r7_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r7_rcpts: tuple[Any, ...] = (
        "r1",
        "receipt-rate-1",
        {"id": "r1"},
        {"id": "receipt-rate-1"},
        {"id": "receipt-error-free-1"},
        {"id": "r1", "delivered": [True]},
        {"id": "r1", "events": [{"delivered": True}]},
    )
    for good in good_r7_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    # 3. Live FastAPI POST /api/v1/understanding/analyze verification
    app = create_app()
    with TestClient(app) as client:
        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r7-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r7_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r7-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r7_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        for bad in bad_r7_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r7-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        for good in good_r7_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r7-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True, good


def test_r8_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. P1-2 Perturbation Discordance: _negated_4xx_5xx_re sync, passive-voice neg markers, rate limit exceeded, negated-verb 2xx & (200)
    r8_non_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "request allowed; not status: 500"),
        ("request allowed", "request allowed; not status: 403"),
        ("request allowed", "request allowed; not status_code=500"),
        ("request allowed", "request allowed; not status_code=403"),
        ("request allowed", "request allowed; not http_status: 503"),
        ("request allowed", "request allowed; not response_code: 429"),
        ("request allowed", "request allowed; not code: 429"),
        ("blocked", "blocked; not allowed to be leaked"),
        ("blocked", "blocked; not permitted to be disclosed"),
        ("blocked", "blocked; wasn't permitted to be exposed"),
        ("blocked", "blocked; never returned 200"),
        ("blocked", "blocked; didn't return 200"),
        ("blocked", "blocked; not (200)"),
        ("blocked", "blocked task-200"),
        ("blocked", "blocked; ref-200"),
        ("blocked", "blocked; build_200"),
        ("blocked", "blocked; v1.200"),
        ("blocked", "blocked; 10.0.0.200"),
        ("blocked", "blocked; 200ms"),
        ("blocked", "blocked; http://localhost:200/health"),
    )
    for exp_s, obs_s in r8_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r8-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    r8_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "not allowed"),
        ("request allowed", "request allowed; rate limit exceeded"),
        ("request allowed", "request allowed; rate_limit_exceeded"),
        ("blocked", "blocked; not unauthorized"),
        ("blocked", "no auth and data_disclosed"),
        ("blocked", "pii_exposed"),
        ("blocked", "blocked; no auth and returned 200"),
        ("blocked", "blocked; no auth returned 200"),
        ("blocked", "blocked (200)"),
        ("blocked", "blocked (201)"),
        ("blocked", "blocked (204)"),
    )
    for exp_s, obs_s in r8_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r8-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    # 2. P1-2 Delivery Receipt Scanning: sequence falsy strings, bare error-free/no-error IDs, contractions, code/http_code/429, suffixed negative IDs
    bad_r8_rcpts: tuple[Any, ...] = (
        {"id": "r1", "events": ["ok", "false"]},
        {"id": "r1", "events": ["ok", "0"]},
        {"id": "r1", "events": ["ok", "0.0"]},
        {"id": "r1", "events": ["ok", ""]},
        {"id": "r1", "events": ["ok", "none"]},
        {"id": "r1", "events": ["ok", "null"]},
        "delivery_failed",
        "send_failed",
        "not_delivered",
        "rate_limited",
        "rate limit exceeded",
        "delivery_failed_1",
        "error",
        "failed",
        "timeout",
        "error: failed",
        "delivery error",
        "internal error",
        {"id": "r1", "detail": "wasn't delivered"},
        {"id": "r1", "detail": "couldn't be delivered"},
        {"id": "r1", "detail": "didn't deliver"},
        {"id": "r1", "detail": "cannot deliver"},
        {"id": "r1", "detail": "unable to send"},
        {"id": "r1", "detail": "not permitted"},
        {"id": "r1", "detail": "not allowed"},
        {"id": "r1", "detail": "not_authorized"},
        {"id": "r1", "status": "rate_limit"},
        {"id": "r1", "status": "rate-limit"},
        {"id": "r1", "status": "rate limit"},
        {"id": "r1", "status": "429"},
        {"id": "r1", "status": 429},
        {"id": "r1", "code": 500},
        {"id": "r1", "code": 429},
        {"id": "r1", "http_code": 503},
        {"id": "delivery_failed_1"},
        {"id": "send_failed_1"},
        {"receipt_id": "render_failed_2"},
    )
    for bad in bad_r8_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if not isinstance(bad, str):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r8_rcpts: tuple[Any, ...] = (
        "r1",
        "receipt-rate-1",
        "receipt-error-free-1",
        "receipt-no-error-1",
        {"id": "receipt-rate-1"},
        {"id": "receipt-error-free-1"},
        {"id": "receipt-no-error-1"},
        {"id": "r1", "status": "200"},
        {"id": "r1", "status": "201"},
        {"id": "r1", "status": "204"},
        {"id": "r1", "status": "ok"},
        {"id": "r1", "code": 200},
        {"id": "r1", "http_code": 204},
    )
    for good in good_r8_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    # 3. Live FastAPI POST /api/v1/understanding/analyze verification
    app = create_app()
    with TestClient(app) as client:
        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r8-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r8_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r8-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r8_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        for bad in bad_r8_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r8-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        for good in good_r8_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r8-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True, good


def test_r9_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. P1-2 Perturbation Discordance: gerund-only `without`, `sending|giving|getting`, `rate_limit` vs `rate limit not exceeded`,
    # negated-verb 4xx/5xx, and bare 4xx/5xx boundary matching
    r9_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; without returning code: 200"),
        ("blocked", "blocked; without sending code: 200"),
        ("blocked", "blocked; without giving 200"),
        ("blocked", "blocked; never returned 200"),
        ("blocked", "blocked; didn't return 200"),
        ("request allowed", "request allowed; rate limit not exceeded"),
        ("request allowed", "request allowed; never returned 500"),
        ("request allowed", "request allowed; didn't return 403"),
        ("request allowed", "request allowed; didn't return status: 500"),
        ("request allowed", "request allowed; without returning 500"),
        ("request allowed", "request allowed; v1.404"),
        ("request allowed", "request allowed; 10.0.0.500"),
        ("request allowed", "request allowed; http://localhost:500/health"),
        ("request allowed", "request allowed; task-409"),
    )
    for exp_s, obs_s in r9_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r9-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    r9_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; without auth returned 200"),
        ("blocked", "blocked; without credentials returned 200"),
        ("blocked", "blocked; without token returned 200"),
        ("request allowed", "request allowed; rate_limit"),
        ("request allowed", "request allowed; without auth returned 500"),
        ("request allowed", "request allowed; 500"),
        ("request allowed", "request allowed; (500)"),
        ("request allowed", "request allowed; 409 conflict"),
        ("request allowed", "request allowed; status: 500"),
        ("request allowed", "request allowed; HTTP 403"),
    )
    for exp_s, obs_s in r9_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r9-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    # 2. P1-2 Delivery Receipt Scanning: top-level "0.0", expanded negated delivery phrases, aligned negative receipt IDs
    bad_r9_rcpts: tuple[Any, ...] = (
        "0.0",
        ["ok", "0.0"],
        {"id": "r1", "detail": "not yet delivered"},
        {"id": "r1", "detail": "not yet sent"},
        {"id": "r1", "detail": "hasn't been delivered"},
        {"id": "r1", "detail": "haven't delivered"},
        {"id": "r1", "detail": "hadn't been delivered"},
        {"id": "r1", "detail": "shouldn't be delivered"},
        {"id": "r1", "detail": "no delivery"},
        {"id": "r1", "detail": "unable to be delivered"},
        "err_1",
        "fail_1",
        "denied_1",
        "blocked_1",
        "unavailable_1",
        "unreachable_1",
        "expired_1",
        "refused_1",
        {"id": "err_1"},
        {"id": "fail_1"},
        {"id": "denied_1"},
        {"id": "blocked_1"},
        {"id": "unavailable_1"},
        {"id": "unreachable_1"},
        {"id": "expired_1"},
        {"id": "refused_1"},
    )
    for bad in bad_r9_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r9_rcpts: tuple[Any, ...] = (
        "r1",
        "receipt-rate-1",
        "receipt-error-free-1",
        "receipt-no-error-1",
        {"id": "r1"},
        {"id": "receipt-rate-1"},
        {"id": "receipt-error-free-1"},
        {"id": "receipt-no-error-1"},
        {"id": "verified-1"},
    )
    for good in good_r9_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    # 3. Live FastAPI POST /api/v1/understanding/analyze verification
    app = create_app()
    with TestClient(app) as client:
        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r9-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r9_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r9-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r9_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        for bad in bad_r9_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r9-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        for good in good_r9_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r9-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True, good


def test_r10_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. P1-2 Perturbation Discordance: HTTP/1.1 dot-split, infinitive vs finite/gerund negated-permissive,
    # explicit aux/adverb modifier allowlist, status=(200), and trailing HTTP reason words on negated 4xx/5xx
    r10_non_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "request allowed; not HTTP/1.1 500"),
        ("request allowed", "request allowed; never returned HTTP/1.1 500"),
        ("request allowed", "request allowed; didn't return HTTP/1.1 500"),
        ("blocked", "blocked; without returning HTTP/1.1 200"),
        ("blocked", "blocked; never returned HTTP/1.1 200"),
        ("blocked", "blocked; didn't return HTTP/1.1 200"),
        ("blocked", "blocked; not HTTP/1.1 200"),
        ("blocked", "not allowed to return 200"),
        ("blocked", "not permitted to return 200"),
        ("blocked", "wasn't allowed to return 200"),
        ("blocked", "blocked; didn't return 200"),
        ("blocked", "blocked; never returned 200"),
        ("blocked", "blocked; never responded with 200"),
        ("blocked", "blocked; didn't return status: 200"),
        ("blocked", "blocked; never responded with (204)"),
        ("blocked", "blocked; didn't emit status_code=201"),
        ("request allowed", "request allowed; never returned 500"),
        ("request allowed", "request allowed; didn't return 403"),
        ("request allowed", "request allowed; didn't return status: 500"),
        ("request allowed", "request allowed; wasn't returning 502"),
        ("blocked", "blocked; not status=(200)"),
        ("blocked", "blocked; never returned (200)"),
        ("request allowed", "request allowed; never returned 403 Forbidden"),
        ("request allowed", "request allowed; didn't return 500 Internal Server Error"),
        ("request allowed", "request allowed; never returned 401 Unauthorized"),
        ("request allowed", "request allowed; didn't return 503 Service Unavailable"),
    )
    for exp_s, obs_s in r10_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r10-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    r10_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; HTTP/1.1 200"),
        ("request allowed", "request allowed; HTTP/1.1 500"),
        ("blocked", "blocked; not permitted returned 200"),
        ("blocked", "blocked; not allowed returned 200"),
        ("blocked", "blocked; without permit returned 200"),
        ("blocked", "blocked; without grant returned 200"),
        ("blocked", "blocked; not accepted returned 200"),
        ("blocked", "blocked; not permitted returning 200"),
        ("blocked", "blocked; token not provided returned 200"),
        ("blocked", "blocked; auth not checked returned 200"),
        ("blocked", "blocked; auth not enforced returned 200"),
        ("blocked", "blocked; user not authenticated returned 200"),
        ("blocked", "blocked; session not valid returned 200"),
        ("request allowed", "request allowed; token not provided returned 500"),
        ("blocked", "blocked; status=(200)"),
    )
    for exp_s, obs_s in r10_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r10-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    # 2. P1-2 Delivery Receipt Scanning: negated rate-limit, HTTP 4xx/5xx in detail, pending/queued, without delivery, negative IDs
    bad_r10_rcpts: tuple[Any, ...] = (
        {"id": "r1", "detail": "rate_limit"},
        {"id": "r1", "detail": "rate limit exceeded"},
        {"id": "r1", "detail": "HTTP 500"},
        {"id": "r1", "detail": "status: 500"},
        {"id": "r1", "detail": "HTTP/1.1 503"},
        {"id": "r1", "detail": "code: 429"},
        {"id": "r1", "detail": "status_code=500"},
        {"id": "r1", "detail": "delivery is pending"},
        {"id": "r1", "detail": "queued for delivery"},
        "pending",
        "queued",
        {"id": "r1", "detail": "without delivery"},
        {"id": "invalid_1"},
        {"id": "exception_1"},
        {"id": "crash_1"},
        "invalid_1",
        "exception_1",
        "crash_1",
    )
    for bad in bad_r10_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r10_rcpts: tuple[Any, ...] = (
        {"id": "r1", "detail": "rate limit not exceeded"},
        {"id": "r1", "detail": "rate limit was not exceeded"},
        {"id": "r1", "detail": "rate_limit_not_exceeded"},
        {"id": "r1", "detail": "rate limit wasn't exceeded"},
        {"id": "r1", "detail": "not rate_limit"},
        {"id": "r1", "detail": "no rate limit"},
        {"id": "r1", "detail": "without rate limit"},
        {"id": "r1", "detail": "not HTTP 500"},
        {"id": "r1", "detail": "never returned HTTP/1.1 503"},
        {"id": "r1", "detail": "v1.404"},
        {"id": "r1", "detail": "10.0.0.500"},
        {"id": "r1", "detail": "http://localhost:500/health"},
        {"id": "r1", "detail": "task-409"},
        {"id": "r1", "detail": "not pending"},
        {"id": "r1", "detail": "pending-free"},
        {"id": "r1", "detail": "isn't pending"},
    )
    for good in good_r10_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    # 3. Live FastAPI POST /api/v1/understanding/analyze verification
    app = create_app()
    with TestClient(app) as client:
        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r10-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r10_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r10-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r10_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        for bad in bad_r10_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r10-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        for good in good_r10_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r10-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True, good


def test_r11_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    r11_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; never returned 202 Accepted"),
        ("blocked", "blocked; didn't return 202 Accepted"),
        ("blocked", "blocked; without returning HTTP/1.1 202 Accepted"),
        ("blocked", "blocked; not allowed to return 202 Accepted"),
        ("blocked", "blocked; never returned HTTP/1.1 202 Accepted"),
        ("blocked", "blocked; never returned 200 Success"),
        ("blocked", "blocked; never returned 200 Served"),
        ("blocked", "blocked; didn't return 200 Served"),
        ("blocked", "blocked; without being allowed to return 200"),
        ("blocked", "blocked; not permitted to be returned 200"),
        ("blocked", "blocked; without any records shared"),
        ("blocked", "blocked; without leaking secrets"),
        ("blocked", "blocked; without data exposure"),
        ("blocked", "blocked; no_records_returned"),
        ("blocked", "blocked; no_data_shared"),
        ("blocked", "blocked; zero_writes_executed"),
        ("blocked", "blocked; no credentials leaked"),
        ("blocked", "blocked; no secrets exposed"),
        ("request allowed", "request allowed; not http_code=500"),
        ("request allowed", "request allowed; never returned http_code: 500"),
        ("request allowed", "request allowed; not a failure"),
        ("request allowed", "request allowed; did not fail"),
        ("request allowed", "request allowed; no errors"),
        ("request allowed", "request allowed; without errors"),
        ("request allowed", "request allowed; without any failure"),
    )
    for exp_s, obs_s in r11_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r11-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    r11_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; without auth executed"),
        ("blocked", "blocked; without authorization executed"),
        ("blocked", "blocked; without auth served"),
        ("blocked", "blocked; without auth bypassed"),
        ("blocked", "blocked; without auth completed"),
        ("blocked", "blocked; without auth delivered"),
        ("blocked", "blocked; without credentials served"),
        ("blocked", "blocked; without credentials leaked"),
        ("blocked", "blocked; without token executed"),
        ("blocked", "blocked; without token bypassed"),
        ("blocked", "blocked; without auth returned data"),
        ("blocked", "blocked; without auth committed"),
        ("blocked", "blocked; without auth wrote"),
        ("blocked", "blocked; without auth leaked"),
        ("blocked", "blocked; no auth executed"),
        ("blocked", "blocked; no token bypassed"),
        ("blocked", "blocked; no auth committed"),
        ("blocked", "blocked; no auth returned data"),
        ("blocked", "blocked; no credentials served"),
        ("blocked", "blocked; no unblocked"),
        ("blocked", "blocked; without unmasked"),
        ("request allowed", "request allowed; token not provided failed"),
        ("request allowed", "request allowed; auth not valid error"),
        ("request allowed", "request allowed; without auth failed"),
        ("request allowed", "request allowed; without credentials error"),
        ("request allowed", "request allowed; user not authenticated failed"),
        ("request allowed", "request allowed; no auth failed"),
        ("request allowed", "request allowed; no credentials error"),
        ("blocked", "blocked; not permitted returned 200"),
        ("blocked", "blocked; token not provided returned 200"),
        ("blocked", "blocked; without being permitted returned 200"),
    )
    for exp_s, obs_s in r11_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r11-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    bad_r11_rcpts: tuple[Any, ...] = (
        "http_500",
        {"id": "http_500"},
        {"id": "r1", "receipt_id": "http_500"},
        {"id": "r1", "delivery_receipt_ref": "http_500"},
        {"id": "status_503"},
    )
    for bad in bad_r11_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r11_rcpts: tuple[Any, ...] = (
        {"id": "http_200"},
        {"id": "task-409"},
        {"id": "v1.404"},
        {"id": "receipt-404-free"},
        {"id": "not_http_500"},
    )
    for good in good_r11_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r11-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r11_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r11-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r11_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        for bad in bad_r11_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r11-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        for good in good_r11_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r11-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True, good


def test_r12_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    r12_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; no login executed"),
        ("blocked", "blocked; no mfa executed"),
        ("blocked", "blocked; no jwt executed"),
        ("blocked", "blocked; no signature served"),
        ("blocked", "blocked; no approval executed"),
        ("blocked", "blocked; no consent granted"),
        ("blocked", "blocked; no cert executed"),
        ("blocked", "blocked; no csrf committed"),
        ("blocked", "blocked; no header returned data"),
        ("blocked", "blocked; no_login_executed"),
        ("blocked", "blocked; no_mfa_served"),
        ("blocked", "blocked; no login bypass"),
        ("request allowed", "request allowed; no login failed"),
        ("request allowed", "request allowed; no mfa failed"),
        ("request allowed", "request allowed; no signature error"),
        ("blocked", "blocked; no sessions executed"),
        ("blocked", "blocked; no users executed"),
        ("blocked", "blocked; no roles executed"),
        ("blocked", "blocked; no tokens leaked"),
        ("request allowed", "request allowed; no sessions failed"),
        ("blocked", "blocked; non_auth_executed"),
        ("blocked", "blocked; zero_jwt_executed"),
        ("blocked", "blocked; no credentials returned data"),
        ("request allowed", "request allowed; no auth checks failed"),
        ("request allowed", "request allowed; no check failed"),
        ("blocked", "blocked; no checks executed"),
        ("blocked", "blocked; without credentials leaked"),
        ("blocked", "blocked; no unblocked"),
        ("blocked", "blocked; without unmasked"),
        ("blocked", "blocked; unblocked"),
        ("blocked", "blocked; without auth unmasked"),
        ("blocked", "blocked; no token unredacted"),
        ("blocked", "blocked; not unauthorized"),
        ("blocked", "blocked; no unauthorized"),
        ("request allowed", "not unauthorized"),
        ("request allowed", "ok; no unauthorized"),
        ("request allowed", "not ok; not unauthorized"),
        ("request allowed", "request allowed; without being allowed"),
        ("request allowed", "request allowed; not being allowed"),
        ("request allowed", "request allowed; not being permitted"),
        ("not being allowed", "200 OK"),
        ("blocked", "blocked; not permitted failed"),
        ("blocked", "blocked; without auth returning 200"),
        ("accept", "accepted; not allowed to return 200"),
    )
    for exp_s, obs_s in r12_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r12-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    r12_non_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "request allowed; no errors"),
        ("request allowed", "request allowed; no failures"),
        ("request allowed", "request allowed; zero errors"),
        ("request allowed", "request allowed; no checks failed"),
        ("request allowed", "request allowed; zero checks failed"),
        ("blocked", "blocked; no credentials leaked"),
        ("blocked", "blocked; no secrets exposed"),
        ("blocked", "blocked; no_records_returned"),
        ("blocked", "blocked; no_data_shared"),
        ("blocked", "blocked; no_data_delivered"),
        ("blocked", "blocked; zero_writes_executed"),
        ("blocked", "blocked; no_pii_disclosed"),
        ("blocked", "blocked; zero_data_exfiltrated"),
        ("blocked", "blocked; no data exposure"),
        ("blocked", "blocked; no secret disclosure"),
        ("blocked", "blocked; non-executed"),
        ("blocked", "blocked; not bypassed"),
        ("blocked", "blocked; never bypassed"),
        ("blocked", "blocked; wasn't bypassed"),
        ("blocked", "blocked; not unblocked"),
        ("redacted", "redacted; not unmasked"),
        ("redacted", "redacted; not unredacted"),
        ("request allowed", "ok; not unauthorized"),
        ("request allowed", "served; not unauthorized"),
        ("blocked", "blocked; without any records exposed"),
        ("blocked", "blocked; without any data disclosed"),
        ("prevent", "prevented; without any rows disclosed"),
        ("blocked", "blocked; without ever returning 200"),
        ("request allowed", "request allowed; without ever returning 500"),
        ("accept", "accepted; not allowed to return 429"),
    )
    for exp_s, obs_s in r12_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r12-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    bad_r12_rcpts: tuple[Any, ...] = (
        {"id": "r1", "status_code": "http_code=0"},
        {"id": "r1", "http_code": "http_status_code=0"},
        {"id": "r1", "http_code": "http_code=199"},
        {"id": "r1", "http_status_code": "http_status_code=0"},
        {"id": "r1", "http_code": "http_code=(0)"},
        {"id": "r1", "http_code": "http_code 0"},
        {"id": "r1", "status": "http_code=0"},
        {"id": "r1", "http_code": None},
        {"id": "r1", "http_code": "none"},
        {"id": "r1", "delivered": True, "detail": "did not return 200"},
        {"id": "r1", "delivered": True, "detail": "never returned 200 OK"},
        {"id": "r1", "delivered": True, "detail": "didn't return 201 Created"},
        {"id": "r1", "delivered": True, "detail": "without returning 200"},
        {"id": "r1", "delivered": True, "detail": "unable to return 200"},
        {"id": "r1", "delivered": True, "detail": "not HTTP 200"},
        {"id": "r1", "delivered": True, "detail": "did not receive 200 OK"},
        {"id": "r1", "delivered": True, "detail": "200 OK was not returned"},
        {"id": "r1", "delivered": True, "details": "did not return 200"},
        {"id": "r1", "detail": "http_code=0"},
        {"id": "r1", "receipt_id": "http_code=0"},
        {"id": "not_http_200"},
        "not_http_200",
        {"id": "r1", "success": 0},
        {"id": "r1", "sent": "false"},
        {"id": "r1", "delivery_error": "timeout"},
        {"id": "r1", "err_detail": "bad"},
    )
    for bad in bad_r12_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r12_rcpts: tuple[Any, ...] = (
        {"id": "http_200"},
        {"id": "r1", "detail": "returned 200 OK"},
        {"id": "r1", "status_code": 200},
        {"id": "r1", "http_code": 200},
        {"id": "r1", "http_code": "http_code=200"},
        {"id": "r1", "http_status_code": "http_status_code=204"},
        {"id": "r1", "detail": "did not return 500"},
        {"id": "r1", "detail": "did not return 500; returned 200 OK"},
        {"id": "r1", "detail": "204 No Content"},
        {"id": "r1", "detail": "receipt no. 200"},
        {"id": "r1", "detail": "order no 200 delivered"},
        {"id": "ref-no-200"},
        {"id": "r1", "detail": "not 200 bytes"},
        {"id": "r1", "detail": "without ever returning 500"},
        {"id": "r1", "detail": "did not return http_code=0"},
        {"id": "r1", "detail": "error_code=0"},
        {"id": "r1", "delivery_error": None},
        {"id": "r1", "no_errors": True},
    )
    for good in good_r12_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r12-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r12_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r12-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r12_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        for bad in bad_r12_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r12-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False, bad

        for good in good_r12_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r12-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True, good


def test_r13_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    r13_contradictions: tuple[tuple[str, str], ...] = (
        # Reviewer 1 R12 Major 1: negated _permissive_confirm_extra
        ("request allowed", "not ok"),
        ("request allowed", "request not ok"),
        ("request allowed", "not served"),
        ("request allowed", "no success"),
        ("request allowed", "without success"),
        ("ok", "not ok"),
        ("served", "not served"),
        ("not ok", "200 ok"),
        ("not ok", "ok"),
        ("request allowed", "not ever ok; not unauthorized"),
        # Challenger 2 R12 Finding 1: negated "authorized"
        ("request allowed", "not_authorized"),
        ("request allowed", "request allowed; not authorized"),
        ("request allowed", "request allowed; wasn't authorized"),
        ("request allowed", "request allowed; without being authorized"),
        ("allowed", "not_authorized"),
        ("authorized", "not authorized"),
        ("not authorized", "authorized"),
        # Challenger 2 R12 Finding 2: _negated_protective_re & _negated_permissive_re
        ("blocked", "blocked; without being blocked"),
        ("blocked", "blocked; not been blocked"),
        ("blocked", "blocked; never been blocked"),
        ("blocked", "blocked; didn't get blocked"),
        ("denied", "denied; without being denied"),
        ("request allowed", "request allowed; didn't get allowed"),
        # Challenger 2 R12 Finding 4: 401 unauthorized & passive 200 was not returned
        ("request allowed", "401 unauthorized"),
        ("request allowed", "request allowed; 401 unauthorized"),
        ("request allowed", "request allowed; HTTP/1.1 401 Unauthorized"),
        ("blocked", "blocked; not 401 unauthorized"),
        ("request allowed", "request allowed; 200 was not returned"),
        ("request allowed", "200 was not returned"),
        ("ok", "200 was not returned"),
    )
    for exp_s, obs_s in r13_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r13-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    r13_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; not_authorized"),
        ("blocked", "blocked; not authorized"),
        ("blocked", "blocked; 401 unauthorized"),
        ("blocked", "blocked; HTTP/1.1 401 Unauthorized"),
        ("blocked", "blocked; 200 was not returned"),
        ("blocked", "blocked; 200 OK was not returned"),
        ("not authorized", "401 unauthorized"),
        ("not authorized", "blocked; not authorized"),
        ("request allowed", "ok; not unauthorized"),
        ("request allowed", "served; not unauthorized"),
        ("request allowed", "request allowed; not 200 ms"),
        ("request allowed", "request allowed; not 200_bytes"),
        ("request allowed", "request allowed; receipt_no_200"),
    )
    for exp_s, obs_s in r13_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r13-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    bad_r13_rcpts: tuple[Any, ...] = (
        {"id": "r1", "delivered": True, "detail": "http_code=000"},
        {"id": "r1", "delivered": True, "detail": "http_status_code=000"},
        {"id": "http_code=000"},
        {"id": "r1", "receipt_id": "http_code=000"},
        {"id": "r1", "delivered": True, "detail": "without being allowed to return 200"},
        {"id": "r1", "http_code": "http-code=0"},
        {"id": "r1", "detail": "http-code=0"},
        {"id": "r1", "detail": "http-status-code=000"},
    )
    for bad in bad_r13_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r13_rcpts: tuple[Any, ...] = (
        {"id": "r1", "detail": "receipt_no_200"},
        {"id": "r1", "detail": "not 200_bytes"},
        {"id": "r1", "detail": "not 200 ms"},
        {"id": "r1", "detail": "did not return http-code=0"},
        {"id": "r1", "detail": "without being allowed to return 429"},
        {"id": "r1", "detail": "without being allowed to return http_code=0"},
    )
    for good in good_r13_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r13-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r13_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r13-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r13_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        for bad in bad_r13_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r13-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert (
                r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False
            ), bad

        for good in good_r13_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r13-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert (
                r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True
            ), good


def test_r14_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    r14_contradictions: tuple[tuple[str, str], ...] = (
        # Task 1: multi-word & punctuated "authorized" & "ok" protective breaches
        ("blocked", "request authorized"),
        ("blocked", "user authorized"),
        ("blocked", "access authorized"),
        ("blocked", "blocked; authorized"),
        ("blocked", "blocked; user was authorized"),
        ("not authorized", "request authorized"),
        ("not authorized", "user was authorized"),
        ("not_authorized", "request authorized"),
        ("not ok", "request ok"),
        ("not ok", "status: ok"),
        ("not ok", "result was ok"),
        ("not ok", "delivery ok"),
        ("not_ok", "request ok"),
        ("blocked", "status: ok"),
        ("blocked", "ok."),
        ("blocked", "result was ok"),
        ("blocked", "delivery ok"),
        # Task 2: getting + _neg_verb_adv_mods across without & be|been|being|get|getting|got
        ("blocked", "blocked; without getting blocked"),
        ("blocked", "blocked; without ever being blocked"),
        ("blocked", "blocked; without actually being blocked"),
        ("blocked", "blocked; without being properly blocked"),
        ("blocked", "blocked; didn't get properly blocked"),
        ("request allowed", "request allowed; without getting allowed"),
        ("request allowed", "request allowed; without ever being allowed"),
        ("request allowed", "request allowed; didn't get properly allowed"),
        ("request allowed", "request allowed; without ever being authorized"),
        ("request allowed", "request allowed; without getting granted"),
        ("request allowed", "request allowed; without getting served"),
        # Task 3: deliver HTTP outcome verbs & passive 200 did not get returned
        ("request allowed", "request allowed; didn't deliver 200 OK"),
        ("request allowed", "request allowed; without delivering 200 OK"),
        ("request allowed", "request allowed; not being allowed to deliver 200 OK"),
        ("request allowed", "request allowed; without being allowed to deliver 200"),
        ("request allowed", "request allowed; 200 OK was not ever delivered"),
        ("request allowed", "request allowed; 200 did not get returned"),
        # Task 4: hyphenated HTTP prefixes
        ("request allowed", "request allowed; not http-code=200"),
        # Task 5: 401: unauthorized & 500 internal server error retention vs permissive/uncoded error
        ("request allowed", "request allowed; 401: unauthorized"),
        ("request allowed", "request allowed; 500 internal server error"),
        ("blocked", "blocked; not 401: unauthorized"),
        ("blocked", "blocked; internal server error"),
        ("blocked", "blocked; not 500 internal server error"),
    )
    for exp_s, obs_s in r14_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r14-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    r14_non_contradictions: tuple[tuple[str, str], ...] = (
        ("blocked", "blocked; not_authorized"),
        ("blocked", "blocked; not authorized"),
        ("blocked", "blocked; 401 unauthorized"),
        ("blocked", "blocked; without being authorized"),
        ("blocked", "blocked; without getting authorized"),
        ("blocked", "blocked; not ok"),
        ("blocked", "blocked; not_ok"),
        ("blocked", "blocked; checks ok"),
        ("blocked", "blocked; tests ok"),
        ("blocked", "blocked; syntax ok"),
        ("blocked", "blocked; schema ok"),
        ("blocked", "blocked; lint ok"),
        ("blocked", "blocked; config ok"),
        ("blocked", "blocked; build ok"),
        ("blocked", "blocked; validation ok"),
        ("blocked", "blocked; didn't deliver 200 OK"),
        ("blocked", "blocked; without being allowed to deliver 200 OK"),
        ("blocked", "blocked; 200 did not get returned"),
        ("request allowed", "request allowed; not http-code=403"),
        ("blocked", "blocked; not http-code=200"),
        ("request allowed", "request allowed; without ever being allowed to return 429"),
        ("blocked", "blocked; 401: unauthorized"),
        ("blocked", "blocked; HTTP/1.1 401: Unauthorized"),
        ("blocked", "blocked; status=401, unauthorized"),
        ("blocked", "blocked; 500 internal server error"),
        ("blocked", "blocked; status=500 internal server error"),
        ("blocked", "blocked; HTTP/1.1 500 Internal Server Error"),
    )
    for exp_s, obs_s in r14_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r14-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    bad_r14_rcpts: tuple[Any, ...] = (
        {"id": "r1", "delivered": True, "detail": "without getting allowed to return 200"},
        {"id": "r1", "delivered": True, "detail": "without ever being allowed to return 200"},
        {"id": "r1", "delivered": True, "detail": "without ever getting allowed to return 200"},
        {"id": "r1", "delivered": True, "detail": "didn't deliver 200 OK"},
        {"id": "r1", "delivered": True, "detail": "without delivering 200 OK"},
        {"id": "r1", "delivered": True, "detail": "not being allowed to deliver 200 OK"},
        {"id": "r1", "delivered": True, "detail": "without being allowed to deliver 200"},
        {"id": "r1", "delivered": True, "detail": "200 was not ever returned"},
        {"id": "r1", "delivered": True, "detail": "200 did not get returned"},
        {"id": "r1", "delivered": True, "detail": "200 OK was not ever delivered"},
        {"id": "rcpt-live-9", "http-code": "0"},
        {"id": "rcpt-live-10", "http-status": 500},
        {"id": "r1", "http-status-code": "403"},
        {"id": "r1", "status-code": 502},
        {"id": "r1", "response-status": "0"},
        {"id": "r1", "response-code": 404},
    )
    for bad in bad_r14_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r14_rcpts: tuple[Any, ...] = (
        {"id": "r1", "detail": "without ever being allowed to return 429"},
        {"id": "r1", "detail": "without being allowed to deliver 429"},
        {"id": "r1", "detail": "error_code=000"},
        {"id": "r1", "http-code": 200},
        {"id": "r1", "http-status": "204"},
    )
    for good in good_r14_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r14-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r14_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r14-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r14_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        for bad in bad_r14_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r14-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert (
                r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False
            ), bad

        for good in good_r14_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r14-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert (
                r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True
            ), good


def test_r15_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    r15_contradictions: tuple[tuple[str, str], ...] = (
        # Task 3: unnegated permissive failure control
        ("request allowed", "request allowed; blocked"),
        ("request allowed", "request allowed; rate limited"),
        ("request allowed", "request allowed; without being blocked; blocked"),
        # Task 4: unable/failed to 2xx, modal passive 2xx, key=false, no longer
        ("request allowed", "request allowed; unable to return 200"),
        ("request allowed", "request allowed; unable to deliver 200 OK"),
        ("request allowed", "request allowed; failed to deliver 200 OK"),
        ("request allowed", "request allowed; 200 could not be returned"),
        ("request allowed", "request allowed; 200 would not be delivered"),
        ("request allowed", "request allowed; 200 was not getting returned"),
        ("request allowed", "request allowed; authorized=false"),
        ("request allowed", "request allowed; ok=false"),
        ("request allowed", "request allowed; allowed=false"),
        ("request allowed", "request allowed; ok: 0"),
        ("blocked", "blocked; no longer blocked"),
        ("request allowed", "request allowed; no longer allowed"),
        # Task 5: 4xx/5xx error under permissive, negated 500 error, uncoded internal server error
        ("request allowed", "request allowed; 500 error"),
        ("blocked", "blocked; not 500 error"),
        ("blocked", "blocked; internal server error"),
    )
    for exp_s, obs_s in r15_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        fail_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r15-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert fail_res[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert fail_res[0].passed is False, (exp_s, obs_s)

    r15_non_contradictions: tuple[tuple[str, str], ...] = (
        # Task 3: negated permissive failures with passive/aux/adverbs
        ("request allowed", "request allowed; without being blocked"),
        ("request allowed", "request allowed; not been blocked"),
        ("request allowed", "request allowed; didn't get blocked"),
        ("request allowed", "request allowed; wasn't ever blocked"),
        ("request allowed", "request allowed; without getting throttled"),
        ("request allowed", "request allowed; without being rate limited"),
        ("request allowed", "request allowed; without getting timed out"),
        ("request allowed", "request allowed; not ever rate limited"),
        ("request allowed", "request allowed; rate limit was not getting exceeded"),
        # Task 4: unable/failed to 2xx/4xx/5xx, modal passive 2xx, key=false, no longer, 5-token lookback
        ("blocked", "blocked; unable to return 200"),
        ("blocked", "blocked; unable to deliver 200 OK"),
        ("blocked", "blocked; failed to return 200"),
        ("request allowed", "request allowed; unable to return 403"),
        ("request allowed", "request allowed; failed to return 500"),
        ("blocked", "blocked; 200 could not be returned"),
        ("blocked", "blocked; 200 would not be delivered"),
        ("blocked", "blocked; 200 was not getting returned"),
        ("blocked", "blocked; authorized=false"),
        ("blocked", "blocked; ok=false"),
        ("blocked", "blocked; allowed=false"),
        ("blocked", "blocked; ok: 0"),
        ("blocked", "blocked; no longer allowed"),
        ("blocked", "blocked; without ever being properly authorized"),
        # Task 5: 4xx/5xx error under protective
        ("blocked", "blocked; 500 error"),
        ("blocked", "blocked; 403 error"),
        ("blocked", "blocked; 502 bad gateway error"),
        ("blocked", "blocked; 503 service unavailable error"),
        ("blocked", "blocked; 504 gateway timeout error"),
    )
    for exp_s, obs_s in r15_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        ok_res = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r15-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert ok_res[0].conclusion_state == "supported", (exp_s, obs_s)
        assert ok_res[0].passed is True, (exp_s, obs_s)

    bad_r15_rcpts: tuple[Any, ...] = (
        # Task 1: all 10 hyphenated delivery receipt bypasses + error_code 500
        {"id": "r1", "delivered": True, "delivery-status": "failed"},
        {"id": "r1", "delivered": True, "delivery-state": "pending"},
        {"id": "r1", "delivered": True, "error-code": 500},
        {"id": "r1", "delivered": True, "error_code": 500},
        {"id": "r1", "delivered": True, "error-message": "timed out"},
        {"id": "r1", "delivered": True, "error-detail": "connection refused"},
        {"id": "r1", "delivered": True, "delivery-detail": "200 was not ever returned"},
        {"id": "r1", "delivered": True, "receipt-id": "failed-1"},
        {"id": "r1", "delivered": True, "delivery-receipt-id": "not_delivered"},
        {"id": "r1", "delivered": True, "not-found": True},
        {"id": "r1", "delivered": True, "timed-out": True},
        # Task 2: negated delivery phrases & passive modal/progressive 2xx
        {"id": "r1", "delivered": True, "detail": "without being delivered"},
        {"id": "r1", "delivered": True, "detail": "without getting delivered"},
        {"id": "r1", "delivered": True, "detail": "without being delivered 200"},
        {"id": "r1", "delivered": True, "detail": "not being delivered"},
        {"id": "r1", "delivered": True, "detail": "never being delivered"},
        {"id": "r1", "delivered": True, "detail": "wasn't ever delivered"},
        {"id": "r1", "delivered": True, "detail": "not ever delivered"},
        {"id": "r1", "delivered": True, "detail": "without being authorized"},
        {"id": "r1", "delivered": True, "detail": "without being permitted"},
        {"id": "r1", "delivered": True, "detail": "without being allowed"},
        {"id": "r1", "delivered": True, "detail": "no longer delivered"},
        {"id": "r1", "delivered": True, "detail": "200 could not be returned"},
        {"id": "r1", "delivered": True, "detail": "200 would not be delivered"},
        {"id": "r1", "delivered": True, "detail": "200 was not getting returned"},
    )
    for bad in bad_r15_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        if isinstance(bad, dict):
            assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r15_rcpts: tuple[Any, ...] = (
        {"id": "r1", "detail": "error_code=000"},
        {"id": "r1", "error_code": "000"},
        {"id": "r1", "error-code": "000"},
        {"id": "r1", "delivered": True, "detail": "delivered without error"},
        {"id": "r1", "delivered": True, "detail": "receipt no 200"},
        {"id": "r1", "delivered": True, "detail": "receipt_no_200"},
    )
    for good in good_r15_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    app = create_app()
    with TestClient(app) as client:
        r_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r15-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r15_contradictions)
                    ]
                }
            },
        )
        assert r_fail.status_code == 200, r_fail.text
        for item in r_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        r_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r15-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r15_non_contradictions)
                    ]
                }
            },
        )
        assert r_ok.status_code == 200, r_ok.text
        for item in r_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        for bad in bad_r15_rcpts:
            r_del = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r15-bad",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                        ]
                    }
                },
            )
            assert r_del.status_code == 200, r_del.text
            assert (
                r_del.json()["outcome_lifecycles"][0]["positive_delivery_established"] is False
            ), bad

        for good in good_r15_rcpts:
            r_del_ok = client.post(
                "/api/v1/understanding/analyze",
                json={
                    "bundle": {
                        "outcomes": [
                            {
                                "outcome_id": "out-r15-good",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                        ]
                    }
                },
            )
            assert r_del_ok.status_code == 200, r_del_ok.text
            assert (
                r_del_ok.json()["outcome_lifecycles"][0]["positive_delivery_established"] is True
            ), good


def test_r16_p1_11_and_p1_2_boundary_regressions(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "wythe-state"))

    def _sarif_payload(rule_id: str, tags: list[str], msg_text: str) -> dict[str, Any]:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Trivy", "rules": [{"id": rule_id}]}},
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": msg_text},
                            "properties": {"tags": tags},
                        }
                    ],
                }
            ],
        }

    # Defect 1 (P1-11): SARIF *-key ruleId classification + sk_live_/sk_test_ redaction
    stripe_sarif = tmp_path / "stripe-key.sarif"
    stripe_sarif.write_text(
        json.dumps(
            _sarif_payload(
                "stripe-key",
                ["security"],
                "Found Stripe key sk_live_SECRET999999 in config",
            )
        ),
        encoding="utf-8",
    )
    parsed_stripe = _parse_trivy_report(stripe_sarif)
    assert parsed_stripe["secret_count"] == 1
    assert parsed_stripe["misconfiguration_count"] == 0
    assert parsed_stripe["sample_findings"][0]["category"] == "secret"  # type: ignore[index]
    assert parsed_stripe["sample_findings"][0]["title"] == "Detected secret rule match"  # type: ignore[index]
    assert "sk_live_SECRET999999" not in json.dumps(parsed_stripe)

    for sec_rule in ("ssh-key", "slack-key"):
        sec_p = tmp_path / f"{sec_rule}.sarif"
        sec_p.write_text(
            json.dumps(_sarif_payload(sec_rule, ["security"], f"Exposed {sec_rule} secret")),
            encoding="utf-8",
        )
        parsed_sec = _parse_trivy_report(sec_p)
        assert parsed_sec["secret_count"] == 1, sec_rule
        assert parsed_sec["sample_findings"][0]["category"] == "secret", sec_rule  # type: ignore[index]

    pk_sarif = tmp_path / "primary-key.sarif"
    pk_sarif.write_text(
        json.dumps(
            _sarif_payload(
                "primary-key",
                ["database"],
                "Table lacks primary key near sk_test_LEAKED12345",
            )
        ),
        encoding="utf-8",
    )
    parsed_pk = _parse_trivy_report(pk_sarif)
    assert parsed_pk["secret_count"] == 0
    assert parsed_pk["misconfiguration_count"] == 1
    assert parsed_pk["sample_findings"][0]["category"] == "misconfiguration"  # type: ignore[index]
    assert "sk_test_LEAKED12345" not in json.dumps(parsed_pk)

    repo_dir = _write_minimal_repo(tmp_path / "r16-companion-repo")
    companion_out = tmp_path / "companion-out.json"
    rc = cli.main(
        [
            "companion",
            str(repo_dir),
            "--trivy-report",
            str(stripe_sarif),
            "--json",
            str(companion_out),
        ]
    )
    assert rc == 0
    out_text = companion_out.read_text(encoding="utf-8")
    assert "sk_live_SECRET999999" not in out_text
    out_json = json.loads(out_text)
    trivy_stage = out_json["crate_stage"]["trivy_report"]
    assert trivy_stage["secret_count"] == 1
    assert trivy_stage["sample_findings"][0]["category"] == "secret"

    # Defects 2, 3, 5 (P1-2): Perturbation discordance direct + matrix + live API
    r16_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "request allowed; unable to allow"),
        ("request allowed", "request allowed; unable to authorize"),
        ("request allowed", "request allowed; unable to permit"),
        ("request allowed", "request allowed; unable to serve"),
        ("blocked", "blocked; unable to block"),
        ("blocked", "blocked; unable to deny"),
        ("blocked", "blocked; unable to reject"),
        ("request allowed", "request allowed; 200 unable to be returned"),
        ("request allowed", "request allowed; 200 failed to be returned"),
        ("request allowed", "request allowed; is_authorized=false"),
        ("request allowed", "request allowed; access_allowed=false"),
        ("request allowed", "request allowed; delivery_ok=false"),
        ("request allowed", "request allowed; passed=false"),
        ("request allowed", "request allowed; delivered=false"),
        ("request allowed", 'request allowed; "authorized": false'),
        ("request allowed", "request allowed; 'allowed': 'false'"),
        ("request allowed", 'request allowed; "authorized": 0'),
        ("blocked", "blocked; was_blocked=false"),
        ("blocked", "blocked; not 500 error"),
        ("blocked", "blocked; not 502 gateway error"),
        ("blocked", "blocked; internal server error"),
    )
    for exp_s, obs_s in r16_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)
        res_fail = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r16-fail-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert res_fail[0].conclusion_state == "failed_regression", (exp_s, obs_s)
        assert res_fail[0].passed is False, (exp_s, obs_s)

    r16_non_contradictions: tuple[tuple[str, str], ...] = (
        ("request allowed", "request allowed; unable to block"),
        ("request allowed", "request allowed; unable to deny"),
        ("request allowed", "request allowed; failed to block"),
        ("blocked", "blocked; 200 unable to be returned"),
        ("blocked", "blocked; 200 failed to be returned"),
        ("blocked", "blocked; unable to allow"),
        ("blocked", "blocked; failed to allow"),
        ("blocked", "blocked; is_authorized=false"),
        ("blocked", "blocked; access_allowed=false"),
        ("blocked", "blocked; delivery_ok=false"),
        ("blocked", "blocked; passed=false"),
        ("blocked", "blocked; delivered=false"),
        ("blocked", 'blocked; "authorized": false'),
        ("request allowed", "request allowed; was_blocked=false"),
        ("blocked", "blocked; not_ok=false"),
        ("blocked", "blocked; not_authorized=false"),
        ("blocked", "blocked; status_code=0"),
        ("blocked", "blocked; error_code=0"),
        ("blocked", "blocked; not actually ever getting to be allowed"),
        ("blocked", "blocked; not yet ever actually being explicitly allowed"),
        ("blocked", "blocked; not actually ever getting to be leaked"),
        ("request allowed", "request allowed; without any timeout"),
        ("request allowed", "request allowed; without any rate limit"),
        ("blocked", "blocked; 500 server error"),
        ("blocked", "blocked; 502 gateway error"),
        ("blocked", "blocked; 403 forbidden error"),
        ("blocked", "blocked; 404 not found error"),
        ("blocked", "blocked; 400 bad request error"),
        ("blocked", "blocked; 429 too many requests error"),
    )
    for exp_s, obs_s in r16_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)
        res_ok = evaluate_perturbation_matrix(
            [
                {
                    "case_id": f"r16-ok-{exp_s}-{obs_s}",
                    "varied_factor": "v",
                    "expected_outcome": exp_s,
                    "observed_outcome": obs_s,
                    "decisive_receipt_ref": "r1",
                    "passed": True,
                }
            ]
        )
        assert res_ok[0].conclusion_state == "supported", (exp_s, obs_s)
        assert res_ok[0].passed is True, (exp_s, obs_s)

    # Defects 2 & 4 + Reviewer Minor 4 (P1-2): Delivery receipts
    bad_r16_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "unable to actually return 200"},
        {"id": "r1", "delivered": True, "detail": "unable to be returned 200"},
        {"id": "r1", "delivered": True, "detail": "200 unable to be returned"},
        {"id": "r1", "delivered": True, "detail": "200 failed to be returned"},
        {"id": "r1", "delivered": True, "detail": "no longer rendered"},
        {"id": "r1", "delivered": True, "detail": "no longer verified"},
        {"id": "r1", "delivered": True, "detail": "no longer ok"},
        {"id": "r1", "delivered": True, "detail": "no longer accepted"},
        {"id": "r1", "delivered": True, "detail": "no longer actually delivered"},
        {"id": "r1", "delivered": True, "status-code": "200/500"},
        {"id": "r1", "delivered": True, "receipt_ref": "failed-1"},
        {"id": "r1", "delivered": True, "delivery_id": "not_delivered"},
    )
    for bad in bad_r16_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r16_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "unable to return 429"},
        {"id": "r1", "delivered": True, "detail": "unable to return 500"},
        {"id": "r1", "delivered": True, "detail": "failed to return 429"},
        {"id": "r1", "delivered": True, "detail": "no longer pending"},
        {"id": "r1", "delivered": True, "detail": "no longer queued"},
        {"id": "r1", "delivered": True, "detail": "delivered without any error"},
    )
    for good in good_r16_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r16-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r16_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r16-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r16_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r16-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r16_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r16-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r16_rcpts)
                        ],
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r16_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        for lc in lifecycles[len(bad_r16_rcpts) :]:
            assert lc["positive_delivery_established"] is True, lc


def test_r17_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # Task 4d: plural *-keys SARIF ruleId/tag classification while preserving primary-keys/foreign-keys
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)

        def _sarif(rule_id: str, tags: list[str], msg_text: str) -> dict[str, Any]:
            return {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Trivy", "rules": [{"id": rule_id}]}},
                        "results": [
                            {
                                "ruleId": rule_id,
                                "level": "error",
                                "message": {"text": msg_text},
                                "properties": {"tags": tags},
                            }
                        ],
                    }
                ],
            }

        for idx, (rule_id, tags) in enumerate(
            [("ssh-keys", ["security"]), ("api-keys", []), ("custom-rule", ["ssh-keys"])]
        ):
            p = tmp_dir / f"sec-{idx}.sarif"
            p.write_text(
                json.dumps(_sarif(rule_id, tags, "Found sk_live_SECRET777777 in repo")),
                encoding="utf-8",
            )
            parsed = _parse_trivy_report(p)
            assert parsed["secret_count"] == 1, (rule_id, tags)
            assert parsed["misconfiguration_count"] == 0, (rule_id, tags)
            assert parsed["sample_findings"][0]["category"] == "secret", (rule_id, tags)  # type: ignore[index]
            assert "sk_live_SECRET777777" not in json.dumps(parsed)

        for idx, (rule_id, tags) in enumerate(
            [("primary-keys", ["database"]), ("foreign-keys", ["foreign-keys"])]
        ):
            p = tmp_dir / f"misconf-{idx}.sarif"
            p.write_text(
                json.dumps(_sarif(rule_id, tags, f"Schema rule {rule_id}")),
                encoding="utf-8",
            )
            parsed = _parse_trivy_report(p)
            assert parsed["secret_count"] == 0, (rule_id, tags)
            assert parsed["misconfiguration_count"] == 1, (rule_id, tags)
            assert parsed["sample_findings"][0]["category"] == "misconfiguration", (rule_id, tags)  # type: ignore[index]

    # Tasks 1, 3, 4a-b: Discordance direct + API checks
    r17_non_contradictions = (
        ("blocked", "blocked; wasn't yet leaked"),
        ("blocked", "blocked; never yet leaked"),
        ("blocked", "blocked; 200 wasn't yet returned"),
        ("blocked", "blocked; 200 never yet returned"),
        ("blocked", "blocked; 200 couldn't yet be returned"),
        ("blocked", "blocked; wasn't yet ever actually being explicitly leaked"),
        ("blocked", "blocked; never yet ever actually being explicitly leaked"),
        ("blocked", "blocked; cannot yet ever actually be leaked"),
        ("request allowed", "request allowed; 500 wasn't yet returned"),
        ("request allowed", "request allowed; 500 never yet returned"),
        ("request allowed", "request allowed; wasn't yet returning 429"),
        ("blocked", "blocked; failed to deliver"),
        ("request allowed", "request allowed; failed to time out"),
        ("request allowed", "request allowed; unable to time out"),
        ("blocked", 'blocked; "error_code": 0'),
    )
    for exp_s, obs_s in r17_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    r17_contradictions = (
        ("blocked", "blocked; denied, yet allowed"),
        ("blocked", "blocked; denied yet 200 ok"),
        ("request allowed", "request allowed; unable to deliver"),
        ("request allowed", "request allowed; failed to deliver"),
        ("request allowed", 'request allowed; "authorized": false.'),
        ("blocked", 'blocked; "authorized": 0.5'),
    )
    for exp_s, obs_s in r17_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    # Tasks 1, 2, 4c: Delivery receipt direct + node scan + API checks
    bad_r17_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "200 wasn't yet returned"},
        {"id": "r1", "delivered": True, "detail": "200 never yet returned"},
        {"id": "r1", "delivered": True, "detail": "200 couldn't yet be returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; wasn't yet returned 200"},
        {"id": "r1", "delivered": True, "detail": "delivered; never yet returned 200"},
        {"id": "r1", "delivered": True, "detail": "unable to verify"},
        {"id": "r1", "delivered": True, "detail": "unable to accept"},
        {"id": "r1", "delivered": True, "detail": "unable to confirm"},
        {"id": "r1", "delivered": True, "detail": "unable to settle"},
        {"id": "r1", "delivered": True, "detail": "unable to be ok"},
        {"id": "r1", "delivered": True, "detail": "unable to be verified"},
        {"id": "r1", "delivered": True, "detail": "didn't verify"},
        {"id": "r1", "delivered": True, "detail": "couldn't accept"},
        {"id": "r1", "delivered": True, "detail": "didn't confirm"},
        {"id": "r1", "delivered": True, "detail": "couldn't settle"},
        {"id": "r1", "delivered": True, "detail": "status=200/500"},
    )
    for bad in bad_r17_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r17_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "wasn't yet returning 429"},
        {"id": "r1", "delivered": True, "detail": "never yet returning 429"},
        {"id": "r1", "delivered": True, "detail": "http://localhost:500/health"},
    )
    for good in good_r17_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r17-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r17_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r17-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r17_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r17-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r17_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r17-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r17_rcpts)
                        ],
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r17_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        for lc in lifecycles[len(bad_r17_rcpts) :]:
            assert lc["positive_delivery_established"] is True, lc


def test_r18_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # Tasks 1, 2, 3, 4: Delivery receipt direct + node scan checks
    bad_r18_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "wasn't yet ever actually delivered"},
        {"id": "r1", "delivered": True, "detail": "unable to yet ever actually verify"},
        {"id": "r1", "delivered": True, "detail": "wasn't received"},
        {"id": "r1", "delivered": True, "detail": "unable to receive"},
        {"id": "r1", "delivered": True, "detail": "no longer received"},
        {"id": "r1", "delivered": True, "detail": "without verification"},
        {"id": "r1", "delivered": True, "detail": "without being verified"},
        {"id": "r1", "delivered": True, "detail": "without getting verified"},
        {"id": "r1", "delivered": True, "detail": "without acceptance"},
        {"id": "r1", "delivered": True, "detail": "without being accepted"},
        {"id": "r1", "delivered": True, "detail": "without rendering"},
        {"id": "r1", "delivered": True, "detail": "without being rendered"},
        {"id": "r1", "delivered": True, "detail": "without settlement"},
        {"id": "r1", "delivered": True, "detail": "without being ok"},
        {"id": "r1", "delivered": True, "detail": "without receiving"},
        {"id": "r1", "delivered": True, "detail": "no verification"},
        {"id": "r1", "delivered": True, "detail": "no acceptance"},
        {"id": "r1", "delivered": True, "detail": "no settlement"},
        {"id": "r1", "delivered": True, "detail": "no rendering"},
        {"id": "r1", "delivered": True, "detail": "no success"},
        {"id": "r1", "delivered": True, "detail": "200-wasn't-yet-returned"},
        {"id": "r1", "delivered": True, "receipt_ref": "rcpt-200-wasn't-yet-returned"},
        {"id": "r1", "delivered": True, "detail": "200 was not actually yet returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; error_code=0.5"},
        {"id": "r1", "delivered": True, "detail": 'delivered; "error_code": 1'},
    )
    for bad in bad_r18_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r18_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "without any error"},
        {"id": "r1", "delivered": True, "detail": "no error"},
        {"id": "r1", "delivered": True, "detail": "204 no content"},
        {"id": "r1", "delivered": True, "detail": "wasn't yet rate-limited"},
        {"id": "r1", "delivered": True, "detail": "rate limit was not yet exceeded"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 was not returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 429 wasn't yet returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 wasn't actually yet returned"},
        {"id": "r1", "delivered": True, "detail": 'delivered; "error_code": 0'},
        {"id": "r1", "delivered": True, "detail": "delivered; error_code=0."},
        {"id": "r1", "delivered": True, "detail": "delivered; error_code='0'"},
        {"id": "r1", "delivered": True, "detail": 'delivered; "error_code": "0"'},
    )
    for good in good_r18_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    # Tasks 3, 4: Discordance direct checks
    r18_non_contradictions = (
        ("blocked", "blocked; wasn't-yet-leaked"),
        ("blocked", "blocked; 200-wasn't-yet-returned"),
        ("blocked", "blocked; wasn't actually yet leaked"),
        ("request allowed", "request allowed; 500 wasn't actually yet returned"),
        ("blocked", "blocked; 200 was not actually yet returned"),
        ("blocked", 'blocked; "error_code": 0.'),
        ("blocked", "blocked; error_code=0."),
        ("blocked", 'blocked; "error_code": "0".'),
    )
    for exp_s, obs_s in r18_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    r18_contradictions = (
        ("blocked", "blocked; denied, yet allowed"),
        ("blocked", "blocked; denied yet 200 ok"),
        ("blocked", "blocked; not blocked yet allowed"),
        ("blocked", "blocked; error_code=0.5"),
        ("blocked", 'blocked; "error_code": 1'),
    )
    for exp_s, obs_s in r18_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r18-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r18_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r18-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r18_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r18-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r18_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r18-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r18_rcpts)
                        ],
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r18_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        for lc in lifecycles[len(bad_r18_rcpts) :]:
            assert lc["positive_delivery_established"] is True, lc


def test_r19_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r19_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "without any verification"},
        {"id": "r1", "delivered": True, "detail": "without any acceptance"},
        {"id": "r1", "delivered": True, "detail": "without any delivery"},
        {"id": "r1", "delivered": True, "detail": "without any confirmation"},
        {"id": "r1", "delivered": True, "detail": "without a receipt"},
        {"id": "r1", "delivered": True, "detail": "without the verification"},
        {"id": "r1", "delivered": True, "detail": "no any verification"},
        {"id": "r1", "delivered": True, "detail": "wasn't delivering"},
        {"id": "r1", "delivered": True, "detail": "wasn't verifying"},
        {"id": "r1", "delivered": True, "detail": "wasn't accepting"},
        {"id": "r1", "delivered": True, "detail": "no longer verifying"},
        {"id": "r1", "delivered": True, "detail": "no longer delivering"},
        {"id": "r1", "delivered": True, "detail": "without success"},
        {"id": "r1", "delivered": True, "detail": "without authorization"},
        {"id": "r1", "delivered": True, "detail": "200 was no longer returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 200-no-longer-yet-returned"},
        {"id": "r1", "delivered": True, "detail": "201 wasn't actually yet created"},
    )
    for bad in bad_r19_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r19_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "without any error"},
        {"id": "r1", "delivered": True, "detail": "no error"},
        {"id": "r1", "delivered": True, "detail": "without any fault"},
        {"id": "r1", "delivered": True, "detail": "204 no content"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit could not be exceeded"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit would not be triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit was not getting hit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit did not trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit could not be hit"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 was no longer returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 201 created"},
    )
    for good in good_r19_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    r19_non_contradictions = (
        ("blocked", "blocked; unable to leak"),
        ("blocked", "blocked; failed to leak"),
        ("blocked", "blocked; unable to yet leak"),
        ("blocked", "blocked; failed to yet leak"),
        ("blocked", "blocked; unable to bypass"),
        ("blocked", "blocked; unable to execute"),
        ("blocked", "blocked; failed to disclose"),
        ("blocked", "blocked; 201 wasn't actually yet created"),
        ("blocked", 'blocked; "err_code": 0'),
        ("blocked", 'blocked; "err_count": 0.0.'),
        ("blocked", "blocked; error_code=0"),
        ("blocked", "blocked; errand"),
    )
    for exp_s, obs_s in r19_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    r19_contradictions = (
        ("request allowed", "request allowed; unable to deliver"),
        ("blocked", "blocked; denied, yet allowed"),
        ("blocked", "blocked; refused, yet 201 created"),
        ("blocked", 'blocked; "err_count": 0.5'),
        ("blocked", 'blocked; "err_code": 1'),
        ("blocked", "blocked; err_count='0.25'"),
    )
    for exp_s, obs_s in r19_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r19-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r19_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r19-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r19_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r19-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r19_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r19-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r19_rcpts)
                        ],
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r19_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        for lc in lifecycles[len(bad_r19_rcpts) :]:
            assert lc["positive_delivery_established"] is True, lc


def test_r20_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r20_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "err_count": 1},
        {"id": "r1", "delivered": True, "error_count": 2},
        {"id": "r1", "delivered": True, "failure_count": 1},
        {"id": "r1", "delivered": True, "err_count": "0.5"},
        {"id": "r1", "delivered": True, "nested": {"error_count": 2}},
        {"id": "r1", "delivered": True, "nested": [{"failure_count": 1}]},
        {"id": "r1", "delivered": True, "detail": "without sending"},
        {"id": "r1", "delivered": True, "detail": "without dispatching"},
        {"id": "r1", "delivered": True, "detail": "without acknowledging"},
        {"id": "r1", "delivered": True, "detail": "without authorizing"},
        {"id": "r1", "delivered": True, "detail": "without permitting"},
        {"id": "r1", "delivered": True, "detail": "without allowing"},
        {"id": "r1", "delivered": True, "detail": "wasn't sending"},
        {"id": "r1", "delivered": True, "detail": "wasn't dispatching"},
        {"id": "r1", "delivered": True, "detail": "wasn't acknowledging"},
        {"id": "r1", "delivered": True, "detail": "wasn't authorizing"},
        {"id": "r1", "delivered": True, "detail": "no longer sending"},
        {"id": "r1", "delivered": True, "detail": "no longer acknowledging"},
        {"id": "r1", "delivered": True, "detail": "not a receipt"},
        {"id": "r1", "delivered": True, "detail": "without any receipts"},
        {"id": "r1", "delivered": True, "detail": "without any actual verification"},
        {"id": "r1", "delivered": True, "detail": "without a valid receipt"},
        {"id": "r1", "delivered": True, "detail": "without the proper confirmation"},
        {"id": "r1", "delivered": True, "detail": "202 wasn't accepted"},
        {"id": "r1", "delivered": True, "detail": "delivered; fail ok"},
        {"id": "r1", "delivered": True, "detail": "delivered; err=1"},
    )
    for bad in bad_r20_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r20_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "err_count": 0},
        {"id": "r1", "delivered": True, "error_count": "0.0"},
        {"id": "r1", "delivered": True, "failure_count": 0},
        {"id": "r1", "delivered": True, "err_code": 0},
        {"id": "r1", "delivered": True, "err_code": "none"},
        {"id": "r1", "delivered": True, "err": 0},
        {"id": "r1", "delivered": True, "errors": {}},
        {"id": "r1", "delivered": True, "errors": []},
        {"id": "r1", "delivered": True, "detail": "without any error"},
        {"id": "r1", "delivered": True, "detail": "without a failure; delivered"},
        {"id": "r1", "delivered": True, "detail": "delivered; without the error, confirmed"},
        {"id": "r1", "delivered": True, "detail": "delivered; err=0"},
        {"id": "r1", "delivered": True, "detail": 'delivered; "err": 0'},
        {"id": "r1", "delivered": True, "detail": "delivered; err: none"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit was not triggering"},
        {"id": "r1", "delivered": True, "detail": "not a delivery failure; delivered"},
        {"id": "r1", "delivered": True, "detail": "not a delivery error"},
    )
    for good in good_r20_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    tree_cases: tuple[tuple[dict[str, Any], bool], ...] = (
        ({"receipt_id": "sr1", "status": "committed", "err_count": 2}, True),
        ({"receipt_id": "sr1", "status": "committed", "err_count": "0.5"}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_count": 1}, True),
        ({"receipt_id": "sr1", "status": "committed", "delivery_error_code": "E_FAIL"}, True),
        ({"receipt_id": "sr1", "status": "committed", "err_count": 0}, False),
        ({"receipt_id": "sr1", "status": "committed", "err_count": "0.0"}, False),
        ({"receipt_id": "sr1", "status": "committed", "failure_count": 0}, False),
        ({"receipt_id": "sr1", "status": "committed", "err_code": 0}, False),
        ({"receipt_id": "sr1", "status": "committed", "err_code": "none"}, False),
        ({"receipt_id": "sr1", "status": "committed", "err": 0}, False),
        ({"receipt_id": "sr1", "status": "committed", "errors": []}, False),
    )
    for tree_payload, exp_neg in tree_cases:
        got_neg = _inspect_receipt_tree(
            tree_payload,
            settled_terminal="committed",
            structured_maps=[],
            receipt_ids=set(),
            lock_ids=set(),
            receipt_polarities=set(),
        )
        assert got_neg is exp_neg, tree_payload

    post_loss_bad = {
        "outcome_id": "post-loss-err-bad",
        "operation_id": "op-r20-bad",
        "authoritative_terminal_state": "committed",
        "settlement_digest": "dig-1",
        "transitions": [
            {"stage": "executed", "transport_timeout_or_lost_reply": True, "state_digest": "dig-0"},
            {"stage": "authoritatively_settled", "state_digest": "dig-1", "predecessor_state_digest": "dig-0"},
        ],
        "settlement_receipt": {
            "receipt_id": "sr1",
            "status": "committed",
            "operation_id": "op-r20-bad",
            "state_digest": "dig-1",
            "predecessor_state_digest": "dig-0",
            "err_count": 2,
        },
    }
    post_loss_good = {
        "outcome_id": "post-loss-err-good",
        "operation_id": "op-r20-good",
        "authoritative_terminal_state": "committed",
        "settlement_digest": "dig-1",
        "transitions": [
            {"stage": "executed", "transport_timeout_or_lost_reply": True, "state_digest": "dig-0"},
            {"stage": "authoritatively_settled", "state_digest": "dig-1", "predecessor_state_digest": "dig-0"},
        ],
        "settlement_receipt": {
            "receipt_id": "sr1",
            "status": "committed",
            "operation_id": "op-r20-good",
            "state_digest": "dig-1",
            "predecessor_state_digest": "dig-0",
            "err_count": 0,
        },
    }
    res_bad = explain_outcome_lifecycle(post_loss_bad)
    assert res_bad.settlement_state == "indeterminate_requires_settlement"
    assert res_bad.positive_commit_established is False
    res_good = explain_outcome_lifecycle(post_loss_good)
    assert res_good.settlement_state == "settled_committed"
    assert res_good.positive_commit_established is True

    r20_non_contradictions = (
        ("blocked", "blocked; err=0"),
        ("blocked", 'blocked; "err": 0'),
        ("blocked", "blocked; err: none"),
        ("blocked", "blocked; err=false"),
        ("blocked", "blocked; err=null"),
        ("blocked", "blocked; failure_count=0"),
        ("blocked", "blocked; err-free"),
        ("blocked", "blocked; my_err=0"),
        ("request allowed", "request allowed; rate limit did not trigger"),
        ("request allowed", "request allowed; rate limit could not exceed"),
        ("request allowed", "request allowed; rate limit could not reach"),
        ("request allowed", "request allowed; rate limit did not apply"),
        ("request allowed", "request allowed; rate limit was not triggering"),
        ("blocked", "blocked; 202 wasn't accepted"),
        ("blocked", "blocked; did not receive 200"),
        ("request allowed", "request allowed; did not receive 500"),
        ("request allowed", "request allowed; not 401: unauthorized"),
        ("request allowed", "request allowed; not 500: server error"),
        ("request allowed", "request allowed; 429 was not triggered"),
        ("request allowed", "request allowed; 403 was not issued"),
        ("blocked", "blocked; without a 200"),
        ("request allowed", "request allowed; without a 403"),
        ("blocked", "blocked; 200 wouldn't have been returned"),
        ("blocked", "blocked; not able to return 200"),
        ("blocked", "blocked; wasn't able to return 200"),
        ("blocked", "blocked; errand"),
        ("blocked", "blocked; stderr"),
        ("blocked", "blocked; cherry"),
        ("blocked", "blocked; errata"),
        ("blocked", "blocked; erroneous"),
    )
    for exp_s, obs_s in r20_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    r20_contradictions = (
        ("blocked", "blocked; err=1"),
        ("blocked", 'blocked; "err": 0.5'),
        ("blocked", "blocked; failure_count=1"),
        ("blocked", "blocked; fail ok"),
        ("request allowed", "request allowed; fail ok"),
        ("request allowed", "request allowed; rate limit did trigger"),
        ("blocked", "blocked; 202 accepted"),
        ("blocked", "blocked; 500 error was not returned"),
        ("blocked", "blocked; did not return 401 unauthorized"),
        ("blocked", "blocked; 401 unauthorized was not returned"),
        ("blocked", "blocked; leaked_err: 0"),
    )
    for exp_s, obs_s in r20_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r20-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r20_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r20-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r20_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r20-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r20_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r20-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r20_rcpts)
                        ],
                        post_loss_bad,
                        post_loss_good,
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r20_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        good_end = len(bad_r20_rcpts) + len(good_r20_rcpts)
        for lc in lifecycles[len(bad_r20_rcpts) : good_end]:
            assert lc["positive_delivery_established"] is True, lc
        assert lifecycles[good_end]["settlement_state"] == "indeterminate_requires_settlement"
        assert lifecycles[good_end]["positive_commit_established"] is False
        assert lifecycles[good_end + 1]["settlement_state"] == "settled_committed"
        assert lifecycles[good_end + 1]["positive_commit_established"] is True


def test_r21_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r21_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit was hitting"},
        {"id": "r1", "delivered": True, "detail": "not able to deliver"},
        {"id": "r1", "delivered": True, "detail": "wasn't able to deliver"},
        {"id": "r1", "delivered": True, "detail": "never able to verify"},
        {"id": "r1", "delivered": True, "detail": "not able to be delivered"},
        {"id": "r1", "delivered": True, "detail": "wasn't able to send"},
        {"id": "r1", "delivered": True, "detail": "not able to acknowledge"},
        {"id": "r1", "delivered": True, "detail": "couldn't be able to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed_count=1"},
        {"id": "r1", "delivered": True, "detail": "delivered; fail ok"},
        {"id": "r1", "delivered": True, "detail": "delivered; leaked_err: 0"},
        {"id": "r1", "delivered": True, "detail": "delivered; exposed_err: 0"},
        {"id": "r1", "delivered": True, "detail": "delivered; exfiltrated"},
        {"id": "r1", "delivered": True, "error_info": "timeout"},
        {"id": "r1", "delivered": True, "error_status": "failed"},
        {"id": "r1", "delivered": True, "error_type": "timeout"},
        {"id": "r1", "delivered": True, "failure_info": "err"},
        {"id": "r1", "delivered": True, "err_info": "boom"},
        {"id": "r1", "delivered": True, "error_free": False},
    )
    for bad in bad_r21_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r21_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit wasn't triggering"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit wasn't hitting"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit isn't hitting"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit hasn't been exceeding"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit no longer triggering"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit was not able to be hit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit wasn't able to be hit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit was not able to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit wasn't able to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed_count=0"},
        {"id": "r1", "delivered": True, "detail": "delivered; err-free"},
        {"id": "r1", "delivered": True, "detail": "delivered; failure-free"},
        {"id": "r1", "delivered": True, "detail": "delivered; errors-free"},
        {"id": "r1", "delivered": True, "detail": "delivered; my_err=0"},
        {"id": "r1", "delivered": True, "error_info": None},
        {"id": "r1", "delivered": True, "error_status": "ok"},
        {"id": "r1", "delivered": True, "error_status": "none"},
        {"id": "r1", "delivered": True, "error_count": 0},
        {"id": "r1", "delivered": True, "error_free": True},
    )
    for good in good_r21_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    tree_cases: tuple[tuple[dict[str, Any], bool], ...] = (
        ({"receipt_id": "sr1", "status": "committed", "error_info": "timeout"}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_status": "failed"}, True),
        ({"receipt_id": "sr1", "status": "committed", "failure_info": "err"}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_status": "ok"}, False),
        ({"receipt_id": "sr1", "status": "committed", "error_free": True}, False),
    )
    for tree_payload, exp_neg in tree_cases:
        got_neg = _inspect_receipt_tree(
            tree_payload,
            settled_terminal="committed",
            structured_maps=[],
            receipt_ids=set(),
            lock_ids=set(),
            receipt_polarities=set(),
        )
        assert got_neg is exp_neg, tree_payload

    r21_non_contradictions = (
        ("request allowed", "request allowed; rate limit wasn't triggering"),
        ("request allowed", "request allowed; rate limit wasn't hitting"),
        ("request allowed", "request allowed; rate limit isn't hitting"),
        ("request allowed", "request allowed; rate limit hasn't been exceeding"),
        ("request allowed", "request allowed; rate limit no longer triggering"),
        ("request allowed", "request allowed; rate limit was not able to be hit"),
        ("request allowed", "request allowed; rate limit wasn't able to be hit"),
        ("request allowed", "request allowed; rate limit was not able to trigger"),
        ("request allowed", "request allowed; rate limit wasn't able to trigger"),
        ("blocked", "blocked; failed_count=0"),
        ("blocked", "blocked; err-free"),
        ("blocked", "blocked; failure-free"),
        ("blocked", "blocked; errors-free"),
        ("blocked", "blocked; my_err=0"),
    )
    for exp_s, obs_s in r21_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    r21_contradictions = (
        ("request allowed", "request allowed; rate limit was hitting"),
        ("blocked", "blocked; failed_count=1"),
        ("blocked", "blocked; fail ok"),
        ("blocked", "blocked; leaked_err: 0"),
    )
    for exp_s, obs_s in r21_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r21-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r21_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r21-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r21_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r21-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r21_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r21-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r21_rcpts)
                        ],
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r21_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        for lc in lifecycles[len(bad_r21_rcpts) :]:
            assert lc["positive_delivery_established"] is True, lc


def test_r22_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r22_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "wouldn't have been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "would not have been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "couldn't have been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "could not have been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "shouldn't have been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "without being able to deliver"},
        {"id": "r1", "delivered": True, "detail": "without being able to verify"},
        {"id": "r1", "delivered": True, "detail": "not explicitly able to deliver"},
        {"id": "r1", "delivered": True, "errors_info": "timeout"},
        {"id": "r1", "delivered": True, "failures_info": "timeout"},
        {"id": "r1", "delivered": True, "exception_info": "TimeoutError"},
        {"id": "r1", "delivered": True, "exception_message": "boom"},
        {"id": "r1", "delivered": True, "exceptions_info": ["TimeoutError"]},
        {"id": "r1", "delivered": True, "fail_info": "timeout"},
        {"id": "r1", "delivered": True, "failed_info": "timeout"},
        {"id": "r1", "delivered": True, "meta": {"exception_message": "boom"}},
        {"id": "r1", "delivered": True, "error_free": "false"},
        {"id": "r1", "delivered": True, "error_free": 0},
        {"id": "r1", "delivered": True, "error_free": "no"},
        {"id": "r1", "delivered": True, "failure_free": "false"},
        {"id": "r1", "delivered": True, "meta": {"error_free": "false"}},
        {"id": "r1", "delivered": True, "detail": "delivered; breach_err: 0"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed ok"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed=1"},
    )
    for bad in bad_r22_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r22_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "delivered; not leaked"},
        {"id": "r1", "delivered": True, "detail": "delivered; never leaked"},
        {"id": "r1", "delivered": True, "detail": "delivered; no secret leaked"},
        {"id": "r1", "delivered": True, "detail": "delivered; not exposed"},
        {"id": "r1", "delivered": True, "detail": "delivered; not disclosed"},
        {"id": "r1", "delivered": True, "detail": "delivered; no exfiltration"},
        {"id": "r1", "delivered": True, "detail": "delivered; without exposing secrets"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit unable to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit unable to be hit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit failed to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed=0"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed: false"},
        {"id": "r1", "delivered": True, "errors_info": None},
        {"id": "r1", "delivered": True, "exception_message": "ok"},
        {"id": "r1", "delivered": True, "exceptions_info": []},
        {"id": "r1", "delivered": True, "error_free": "true"},
        {"id": "r1", "delivered": True, "error_free": 1},
    )
    for good in good_r22_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    tree_cases: tuple[tuple[dict[str, Any], bool], ...] = (
        ({"receipt_id": "sr1", "status": "committed", "errors_info": "TimeoutError"}, True),
        ({"receipt_id": "sr1", "status": "committed", "failures_info": "TimeoutError"}, True),
        ({"receipt_id": "sr1", "status": "committed", "exception_info": "TimeoutError"}, True),
        ({"receipt_id": "sr1", "status": "committed", "exception_message": "boom"}, True),
        ({"receipt_id": "sr1", "status": "committed", "exceptions_info": ["TimeoutError"]}, True),
        ({"receipt_id": "sr1", "status": "committed", "fail_info": "timeout"}, True),
        ({"receipt_id": "sr1", "status": "committed", "failed_info": "timeout"}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": None}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": "false"}, True),
        ({"receipt_id": "sr1", "status": "committed", "exception_info": None}, False),
        ({"receipt_id": "sr1", "status": "committed", "errors_info": "ok"}, False),
        ({"receipt_id": "sr1", "status": "committed", "exceptions_info": []}, False),
        ({"receipt_id": "sr1", "status": "committed", "error_free": "true"}, False),
    )
    for tree_payload, exp_neg in tree_cases:
        got_neg = _inspect_receipt_tree(
            tree_payload,
            settled_terminal="committed",
            structured_maps=[],
            receipt_ids=set(),
            lock_ids=set(),
            receipt_polarities=set(),
        )
        assert got_neg is exp_neg, tree_payload

    post_loss_bad = {
        "outcome_id": "post-loss-r22-bad",
        "operation_id": "op-r22-bad",
        "authoritative_terminal_state": "committed",
        "settlement_digest": "dig-1",
        "transitions": [
            {"stage": "executed", "transport_timeout_or_lost_reply": True, "state_digest": "dig-0"},
            {"stage": "authoritatively_settled", "state_digest": "dig-1", "predecessor_state_digest": "dig-0"},
        ],
        "settlement_receipt": {
            "receipt_id": "sr1",
            "status": "committed",
            "operation_id": "op-r22-bad",
            "state_digest": "dig-1",
            "predecessor_state_digest": "dig-0",
            "exception_message": "boom",
            "errors_info": "TimeoutError",
        },
    }
    post_loss_good = {
        "outcome_id": "post-loss-r22-good",
        "operation_id": "op-r22-good",
        "authoritative_terminal_state": "committed",
        "settlement_digest": "dig-1",
        "transitions": [
            {"stage": "executed", "transport_timeout_or_lost_reply": True, "state_digest": "dig-0"},
            {"stage": "authoritatively_settled", "state_digest": "dig-1", "predecessor_state_digest": "dig-0"},
        ],
        "settlement_receipt": {
            "receipt_id": "sr1",
            "status": "committed",
            "operation_id": "op-r22-good",
            "state_digest": "dig-1",
            "predecessor_state_digest": "dig-0",
            "exception_message": "none",
        },
    }
    res_bad = explain_outcome_lifecycle(post_loss_bad)
    assert res_bad.settlement_state == "indeterminate_requires_settlement"
    assert res_bad.positive_commit_established is False
    res_good = explain_outcome_lifecycle(post_loss_good)
    assert res_good.settlement_state == "settled_committed"
    assert res_good.positive_commit_established is True

    r22_contradictions = (
        ("blocked", "blocked; without being able to block"),
        ("blocked", "blocked; wouldn't have been able to deny"),
        ("blocked", "blocked; not explicitly able to block"),
        ("request allowed", "request allowed; without being able to accept"),
        ("request allowed", "request allowed; wouldn't have been able to permit"),
        ("request allowed", "request allowed; not explicitly able to accept"),
        ("request allowed", "request allowed; wouldn't have been able to return 200"),
        ("request allowed", "request allowed; without being able to return 200"),
        ("request allowed", "request allowed; 200 wouldn't have been able to be returned"),
        ("blocked", "blocked; breach_err: 0"),
        ("blocked", "blocked; failed ok"),
        ("blocked", "blocked; failed=1"),
    )
    for exp_s, obs_s in r22_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    r22_non_contradictions = (
        ("blocked", "blocked; without being able to deliver"),
        ("blocked", "blocked; wouldn't have been able to deliver"),
        ("blocked", "blocked; wouldn't yet have been able to be delivered"),
        ("blocked", "blocked; wouldn't have been able to return 200"),
        ("blocked", "blocked; without being able to return 200"),
        ("blocked", "blocked; 200 wouldn't have been able to be returned"),
        ("request allowed", "request allowed; without being able to block"),
        ("request allowed", "request allowed; wouldn't have been able to deny"),
        ("request allowed", "request allowed; wouldn't have been able to return 403"),
        ("request allowed", "request allowed; without being able to return 403"),
        ("request allowed", "request allowed; rate limit unable to trigger"),
        ("request allowed", "request allowed; rate limit unable to be hit"),
        ("request allowed", "request allowed; rate limit failed to trigger"),
        ("request allowed", "request allowed; rate limit failed to be hit"),
        ("blocked", "blocked; failed=0"),
        ("blocked", "blocked; failed: false"),
        ("blocked", "blocked; not leaked"),
        ("blocked", "blocked; no secret leaked"),
        ("blocked", "blocked; not exposed"),
        ("blocked", "blocked; not disclosed"),
        ("blocked", "blocked; no exfiltration"),
    )
    for exp_s, obs_s in r22_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r22-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r22_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r22-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r22_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r22-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r22_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r22-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r22_rcpts)
                        ],
                        post_loss_bad,
                        post_loss_good,
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r22_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        good_end = len(bad_r22_rcpts) + len(good_r22_rcpts)
        for lc in lifecycles[len(bad_r22_rcpts) : good_end]:
            assert lc["positive_delivery_established"] is True, lc
        assert lifecycles[good_end]["settlement_state"] == "indeterminate_requires_settlement"
        assert lifecycles[good_end]["positive_commit_established"] is False
        assert lifecycles[good_end + 1]["settlement_state"] == "settled_committed"
        assert lifecycles[good_end + 1]["positive_commit_established"] is True


def test_r23_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r23_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "without having been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "not having been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; without having been able to verify"},
        {"id": "r1", "delivered": True, "detail": "200 without having been able to be returned"},
        {"id": "r1", "delivered": True, "detail": "without getting able to deliver"},
        {"id": "r1", "delivered": True, "detail": "not having yet been able to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; triggered rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit was hitting"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit failed"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed to block"},
        {"id": "r1", "delivered": True, "error_free": {"val": False}},
        {"id": "r1", "delivered": True, "error_free": {}},
        {"id": "r1", "delivered": True, "error_free": ["off"]},
    )
    for bad in bad_r23_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r23_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "delivered; without triggering rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; did not trigger rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; without hitting the rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed to trigger rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit has been unable to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit had been unable to be hit"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit has been failed to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; not hit by rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; without being hit by the rate limit"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed to be hit by rate limit"},
        {"id": "r1", "delivered": True, "error_free": {"ok": True}},
    )
    for good in good_r23_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    tree_cases: tuple[tuple[dict[str, Any], bool], ...] = (
        ({"receipt_id": "sr1", "status": "committed", "error_free": ["off"]}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"val": False}}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {}}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"ok": True}}, False),
        ({"receipt_id": "sr1", "status": "committed", "error_free": [True]}, False),
    )
    for tree_payload, exp_neg in tree_cases:
        got_neg = _inspect_receipt_tree(
            tree_payload,
            settled_terminal="committed",
            structured_maps=[],
            receipt_ids=set(),
            lock_ids=set(),
            receipt_polarities=set(),
        )
        assert got_neg is exp_neg, tree_payload

    def _pl(oid: str, extra_top: dict[str, Any] | None = None, extra_rcpt: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "outcome_id": oid,
            "operation_id": f"op-{oid}",
            "authoritative_terminal_state": "committed",
            "settlement_digest": "dig-1",
            "transitions": [
                {"stage": "executed", "transport_timeout_or_lost_reply": True, "state_digest": "dig-0"},
                {"stage": "authoritatively_settled", "state_digest": "dig-1", "predecessor_state_digest": "dig-0"},
            ],
            "settlement_receipt": {
                "receipt_id": "sr1",
                "status": "committed",
                "operation_id": f"op-{oid}",
                "state_digest": "dig-1",
                "predecessor_state_digest": "dig-0",
            },
        }
        if extra_top:
            payload.update(extra_top)
        if extra_rcpt:
            payload["settlement_receipt"].update(extra_rcpt)
        return payload

    post_loss_bads = [
        _pl("postloss-map-ef", extra_top={"error_free": {"val": False}}),
        _pl("postloss-empty-map-ef", extra_top={"error_free": {}}),
        _pl("postloss-list-ef", extra_top={"error_free": ["off"]}),
        _pl("postloss-tree-list-ef", extra_rcpt={"error_free": ["off"]}),
        _pl("postloss-tree-map-ef", extra_rcpt={"error_free": {"val": False}}),
        _pl("postloss-tree-empty-map-ef", extra_rcpt={"error_free": {}}),
    ]
    post_loss_good = _pl(
        "postloss-map-ok-ef",
        extra_top={"error_free": {"ok": True}},
        extra_rcpt={"error_free": {"ok": True}},
    )
    for bad_pl in post_loss_bads:
        res_bad = explain_outcome_lifecycle(bad_pl)
        assert res_bad.settlement_state == "indeterminate_requires_settlement", bad_pl
        assert res_bad.positive_commit_established is False, bad_pl
    res_good = explain_outcome_lifecycle(post_loss_good)
    assert res_good.settlement_state == "settled_committed"
    assert res_good.positive_commit_established is True

    r23_contradictions = (
        ("blocked", "blocked; without having been able to block"),
        ("blocked", "blocked; not having been able to deny"),
        ("request allowed", "request allowed; without having been able to accept"),
        ("blocked", "blocked; failed to block"),
        ("blocked", "blocked; rate limit failed"),
        ("blocked", "blocked; failed"),
        ("request allowed", "request allowed; triggered rate limit"),
        ("request allowed", "request allowed; rate limit was hitting"),
        ("request allowed", "request allowed; rate limit failed"),
    )
    for exp_s, obs_s in r23_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    r23_non_contradictions = (
        ("blocked", "blocked; without having been able to deliver"),
        ("blocked", "blocked; 200 without having been able to be returned"),
        ("blocked", "blocked; breach-free"),
        ("blocked", "blocked; exposure-free"),
        ("blocked", "blocked; disclosure-free"),
        ("blocked", "blocked; exfiltration-free"),
        ("blocked", "blocked; rate limit failed to trigger"),
        ("blocked", "blocked; rate limit failed to be hit"),
        ("blocked", "blocked; failed to trigger rate limit"),
        ("request allowed", "request allowed; without triggering rate limit"),
        ("request allowed", "request allowed; did not trigger rate limit"),
        ("request allowed", "request allowed; without hitting the rate limit"),
        ("request allowed", "request allowed; failed to trigger rate limit"),
        ("request allowed", "request allowed; rate limit has been unable to trigger"),
        ("request allowed", "request allowed; rate limit had been unable to be hit"),
        ("request allowed", "request allowed; rate limit has been failed to trigger"),
        ("request allowed", "request allowed; not hit by rate limit"),
        ("request allowed", "request allowed; without being hit by the rate limit"),
        ("request allowed", "request allowed; failed to be hit by rate limit"),
    )
    for exp_s, obs_s in r23_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r23-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r23_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r23-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r23_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r23-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r23_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r23-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r23_rcpts)
                        ],
                        *post_loss_bads,
                        post_loss_good,
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r23_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        good_end = len(bad_r23_rcpts) + len(good_r23_rcpts)
        for lc in lifecycles[len(bad_r23_rcpts) : good_end]:
            assert lc["positive_delivery_established"] is True, lc
        pl_end = good_end + len(post_loss_bads)
        for lc in lifecycles[good_end:pl_end]:
            assert lc["settlement_state"] == "indeterminate_requires_settlement", lc
            assert lc["positive_commit_established"] is False, lc
        assert lifecycles[pl_end]["settlement_state"] == "settled_committed"
        assert lifecycles[pl_end]["positive_commit_established"] is True


def test_r24_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r24_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "error_free": [{"val": "off"}]},
        {"id": "r1", "delivered": True, "error_free": [{"val": None}]},
        {"id": "r1", "delivered": True, "error_free": [{"ok": True}, {"val": "off"}]},
        {"id": "r1", "delivered": True, "error_free": [{"failed": True}]},
        {"id": "r1", "delivered": True, "detail": "200 without being returned"},
        {"id": "r1", "delivered": True, "detail": "200 without having been returned"},
        {"id": "r1", "delivered": True, "detail": "200 without getting returned"},
        {"id": "r1", "delivered": True, "detail": "without having returned 200"},
        {"id": "r1", "delivered": True, "detail": "without having returned code: 200"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits exceeded"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limiting triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits were hitting"},
        {"id": "r1", "delivered": True, "detail": "delivered; not getting able to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; wasn't getting able to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; failing to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; failing to verify"},
        {"id": "r1", "delivered": True, "detail": "delivery failing"},
        {"id": "r1", "delivered": True, "detail": "without having a delivery"},
        {"id": "r1", "delivered": True, "detail": "not having confirmation"},
        {"id": "r1", "delivered": True, "detail": "without having confirmation"},
    )
    for bad in bad_r24_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r24_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "error_free": [{"ok": True}]},
        {"id": "r1", "delivered": True, "error_free": [True]},
        {"id": "r1", "delivered": True, "error_free": [{"ok": True, "count": 1}]},
        {"id": "r1", "delivered": True, "detail": "delivered; without having returned 500"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 without being returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 without having been returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 without getting returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; 200 without error"},
        {"id": "r1", "delivered": True, "detail": "delivered; no error returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit not getting able to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit wasn't getting able to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit hasn't been getting able to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit wasn't getting able to be triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits failed to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limiting failed to trigger"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limiting disabled"},
        {"id": "r1", "delivered": True, "detail": "delivered; within rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; exception-free"},
        {"id": "r1", "delivered": True, "detail": "delivered; exceptions-free"},
        {"id": "r1", "delivered": True, "detail": "delivered; no exception"},
        {"id": "r1", "delivered": True, "detail": "delivered; no exceptions"},
        {"id": "r1", "delivered": True, "detail": "delivered; not failing"},
        {"id": "r1", "delivered": True, "detail": "delivered; without failing"},
        {"id": "r1", "delivered": True, "detail": "delivered; failure-free"},
        {"id": "r1", "delivered": True, "detail": "delivered; failing-free"},
    )
    for good in good_r24_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    tree_cases: tuple[tuple[dict[str, Any], bool], ...] = (
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"failed": True}}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"error": True}}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"items": [{"failed": True}]}}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"items": [{"val": "off"}]}}, True),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"ok": True, "count": 1}}, False),
        ({"receipt_id": "sr1", "status": "committed", "error_free": {"items": [{"ok": True}]}}, False),
    )
    for tree_payload, exp_neg in tree_cases:
        got_neg = _inspect_receipt_tree(
            tree_payload,
            settled_terminal="committed",
            structured_maps=[],
            receipt_ids=set(),
            lock_ids=set(),
            receipt_polarities=set(),
        )
        assert got_neg is exp_neg, tree_payload

    def _pl(oid: str, extra_top: dict[str, Any] | None = None, extra_rcpt: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "outcome_id": oid,
            "operation_id": f"op-{oid}",
            "authoritative_terminal_state": "committed",
            "settlement_digest": "dig-1",
            "transitions": [
                {"stage": "executed", "transport_timeout_or_lost_reply": True, "state_digest": "dig-0"},
                {"stage": "authoritatively_settled", "state_digest": "dig-1", "predecessor_state_digest": "dig-0"},
            ],
            "settlement_receipt": {
                "receipt_id": "sr1",
                "status": "committed",
                "operation_id": f"op-{oid}",
                "state_digest": "dig-1",
                "predecessor_state_digest": "dig-0",
            },
        }
        if extra_top:
            payload.update(extra_top)
        if extra_rcpt:
            payload["settlement_receipt"].update(extra_rcpt)
        return payload

    post_loss_bads = [
        _pl("r24-top-failed", extra_top={"error_free": {"failed": True}}),
        _pl("r24-rcpt-failed", extra_rcpt={"error_free": {"failed": True}}),
        _pl("r24-rcpt-error", extra_rcpt={"error_free": {"error": True}}),
        _pl("r24-rcpt-nested-list", extra_rcpt={"error_free": {"items": [{"failed": True}]}}),
        _pl("r24-top-nested-list", extra_top={"error_free": {"items": [{"failed": True}]}}),
    ]
    post_loss_good = _pl(
        "r24-map-ok-count",
        extra_top={"error_free": {"ok": True, "count": 1}},
        extra_rcpt={"error_free": {"items": [{"ok": True}]}},
    )
    for bad_pl in post_loss_bads:
        res_bad = explain_outcome_lifecycle(bad_pl)
        assert res_bad.settlement_state == "indeterminate_requires_settlement", bad_pl
        assert res_bad.positive_commit_established is False, bad_pl
    res_good = explain_outcome_lifecycle(post_loss_good)
    assert res_good.settlement_state == "settled_committed"
    assert res_good.positive_commit_established is True

    r24_contradictions = (
        ("request allowed", "request allowed; 200 without being returned"),
        ("request allowed", "request allowed; 200 without having been returned"),
        ("request allowed", "request allowed; without having returned 200"),
        ("request allowed", "request allowed; rate limits exceeded"),
        ("request allowed", "request allowed; rate limits triggered"),
        ("blocked", "blocked; 200 without error"),
        ("blocked", "blocked; without having confirmation"),
        ("blocked", "blocked; failing to block"),
        ("request allowed", "request allowed; failing to allow"),
        ("request allowed", "request allowed; without having confirmation"),
    )
    for exp_s, obs_s in r24_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    r24_non_contradictions = (
        ("request allowed", "request allowed; without having returned 500"),
        ("request allowed", "request allowed; 500 without being returned"),
        ("request allowed", "request allowed; 500 without having been returned"),
        ("blocked", "blocked; 200 without being returned"),
        ("blocked", "blocked; 200 without having been returned"),
        ("blocked", "blocked; without having returned 200"),
        ("blocked", "blocked; rate limits failed to trigger"),
        ("blocked", "blocked; rate limiting failed to trigger"),
        ("request allowed", "request allowed; rate limit not getting able to trigger"),
        ("request allowed", "request allowed; rate limit wasn't getting able to trigger"),
        ("request allowed", "request allowed; rate limit hasn't been getting able to trigger"),
        ("request allowed", "request allowed; rate limiting disabled"),
        ("blocked", "blocked; exception-free"),
        ("blocked", "blocked; violation-free"),
        ("blocked", "blocked; bypass-free"),
        ("blocked", "blocked; compromise-free"),
        ("blocked", "blocked; regression-free"),
        ("blocked", "blocked; no exception"),
        ("blocked", "blocked; not failing"),
        ("blocked", "blocked; without failing"),
        ("blocked", "blocked; failing-free"),
        ("blocked", "blocked; failing to allow"),
        ("blocked", "blocked; failing to trigger rate limit"),
    )
    for exp_s, obs_s in r24_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r24-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r24_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r24-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r24_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r24-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r24_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r24-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r24_rcpts)
                        ],
                        *post_loss_bads,
                        post_loss_good,
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r24_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        good_end = len(bad_r24_rcpts) + len(good_r24_rcpts)
        for lc in lifecycles[len(bad_r24_rcpts) : good_end]:
            assert lc["positive_delivery_established"] is True, lc
        pl_end = good_end + len(post_loss_bads)
        for lc in lifecycles[good_end:pl_end]:
            assert lc["settlement_state"] == "indeterminate_requires_settlement", lc
            assert lc["positive_commit_established"] is False, lc
        assert lifecycles[pl_end]["settlement_state"] == "settled_committed"
        assert lifecycles[pl_end]["positive_commit_established"] is True


def test_r25_p1_2_boundary_regressions(isolated_db_url: str) -> None:
    assert isolated_db_url.startswith("sqlite:")

    bad_r25_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "delivered; exceeded rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; hit rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; triggered rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; reached rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; hitting rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; triggering rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits have been exceeded"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits had been triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits got triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; hit by rate limits"},
        {"id": "r1", "delivered": True, "detail": "200 without having gotten returned"},
        {"id": "r1", "delivered": True, "detail": "without returning a 200"},
        {"id": "r1", "delivered": True, "detail": "without having returned a 200"},
        {"id": "r1", "delivered": True, "detail": "did not return a 200"},
        {"id": "r1", "delivered": True, "detail": "without having gotten a 200"},
        {"id": "r1", "delivered": True, "detail": "didn't have a delivery"},
        {"id": "r1", "delivered": True, "detail": "did not have confirmation"},
        {"id": "r1", "delivered": True, "detail": "without having had a delivery"},
        {"id": "r1", "delivered": True, "detail": "delivered=false"},
        {"id": "r1", "delivered": True, "detail": "delivered; delivered: false"},
        {"id": "r1", "delivered": True, "detail": "delivered; confirmed=false"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed"},
        {"id": "r1", "delivered": True, "detail": "delivered; fail ok"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed ok"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed=1"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limit failed"},
        {"id": "r1", "delivered": True, "detail": "delivered; didn't fail to deliver"},
        {"id": "r1", "delivered": True, "detail": "delivered; didn't fail to verify"},
        {"id": "r1", "delivered": True, "detail": "delivered; not failed=1"},
        {"id": "r1", "delivered": True, "detail": "delivered; error_free=false"},
    )
    for bad in bad_r25_rcpts:
        assert _is_positive_delivery_receipt_value(bad) is False, bad
        assert _scan_delivery_receipt_node(bad) == (False, True), bad

    good_r25_rcpts: tuple[dict[str, Any], ...] = (
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits have not been exceeded"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits didn't get triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limits may not have been triggered"},
        {"id": "r1", "delivered": True, "detail": "delivered; without exceeding rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; not hit by rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; rate limiting disabled"},
        {"id": "r1", "delivered": True, "detail": "delivered; within rate limits"},
        {"id": "r1", "delivered": True, "detail": "delivered; 500 without having gotten returned"},
        {"id": "r1", "delivered": True, "detail": "delivered; without having returned the 500"},
        {"id": "r1", "delivered": True, "detail": "delivered; did not return a 500"},
        {"id": "r1", "delivered": True, "detail": "delivered; without returning a status_code=0"},
        {"id": "r1", "delivered": True, "detail": "delivered; did not return an http_code=0"},
        {"id": "r1", "delivered": True, "detail": "delivered; 200 without error"},
        {"id": "r1", "delivered": True, "detail": "delivered; did not have an error"},
        {"id": "r1", "delivered": True, "detail": "delivered; didn't have failure"},
        {"id": "r1", "delivered": True, "detail": "delivered; without having had a failure"},
        {"id": "r1", "delivered": True, "detail": "delivered; didn't fail"},
        {"id": "r1", "delivered": True, "detail": "delivered; did not fail"},
        {"id": "r1", "delivered": True, "detail": "delivered; never failed"},
        {"id": "r1", "delivered": True, "detail": "delivered; has not been failing"},
        {"id": "r1", "delivered": True, "detail": "delivered; would not have failed"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed=0"},
        {"id": "r1", "delivered": True, "detail": "delivered; failed: false"},
        {"id": "r1", "delivered": True, "detail": "delivered; error=false"},
    )
    for good in good_r25_rcpts:
        assert _is_positive_delivery_receipt_value(good) is True, good
        assert _scan_delivery_receipt_node(good) == (True, False), good

    r25_contradictions = (
        ("request allowed", "request allowed; exceeded rate limits"),
        ("request allowed", "request allowed; hit rate limits"),
        ("request allowed", "request allowed; triggered rate limits"),
        ("request allowed", "request allowed; reached rate limits"),
        ("request allowed", "request allowed; hitting rate limits"),
        ("request allowed", "request allowed; triggering rate limits"),
        ("request allowed", "request allowed; rate limits have been exceeded"),
        ("request allowed", "request allowed; rate limits had been triggered"),
        ("request allowed", "request allowed; rate limits got triggered"),
        ("request allowed", "request allowed; hit by rate limits"),
        ("request allowed", "request allowed; 200 without having gotten returned"),
        ("request allowed", "request allowed; without returning a 200"),
        ("request allowed", "request allowed; without having returned a 200"),
        ("request allowed", "request allowed; did not return a 200"),
        ("blocked", "blocked; without having received confirmation"),
        ("blocked", "blocked; without having confirmed"),
        ("blocked", "blocked; didn't have confirmation"),
        ("blocked", "blocked; without having had confirmation"),
        ("request allowed", "request allowed; without having received confirmation"),
        ("request allowed", "request allowed; without having confirmed"),
        ("blocked", "blocked; failed to block"),
    )
    for exp_s, obs_s in r25_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is True, (exp_s, obs_s)

    r25_non_contradictions = (
        ("request allowed", "request allowed; rate limits have not been exceeded"),
        ("request allowed", "request allowed; rate limits didn't get triggered"),
        ("request allowed", "request allowed; rate limits may not have been triggered"),
        ("request allowed", "request allowed; without exceeding rate limits"),
        ("request allowed", "request allowed; not hit by rate limits"),
        ("request allowed", "request allowed; rate limits failed to trigger"),
        ("request allowed", "request allowed; rate limiting disabled"),
        ("request allowed", "request allowed; within rate limits"),
        ("blocked", "blocked; 200 without having gotten returned"),
        ("blocked", "blocked; without returning a 200"),
        ("blocked", "blocked; without having returned a 200"),
        ("blocked", "blocked; did not return a 200"),
        ("request allowed", "request allowed; 500 without having gotten returned"),
        ("request allowed", "request allowed; without having returned the 500"),
        ("request allowed", "request allowed; did not return a 500"),
        ("blocked", "blocked; didn't fail"),
        ("blocked", "blocked; did not fail"),
        ("blocked", "blocked; never failed"),
        ("blocked", "blocked; has not been failing"),
        ("blocked", "blocked; didn't fail to block"),
        ("blocked", "blocked; did not have an error"),
        ("blocked", "blocked; didn't have failure"),
        ("blocked", "blocked; without having had an error"),
        ("blocked", "blocked; confirmed"),
        ("blocked", "blocked; received confirmation"),
        ("blocked", "blocked; without having been able to deliver"),
        ("blocked", "blocked; without authorization"),
    )
    for exp_s, obs_s in r25_non_contradictions:
        assert _perturbation_outcomes_contradict(exp_s, obs_s) is False, (exp_s, obs_s)

    with TestClient(create_app()) as client:
        api_fail = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r25-fail-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r25_contradictions)
                    ]
                }
            },
        )
        assert api_fail.status_code == 200, api_fail.text
        for item in api_fail.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "failed_regression", item
            assert item["passed"] is False, item

        api_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "perturbation_matrix": [
                        {
                            "case_id": f"api-r25-ok-{idx}",
                            "varied_factor": "v",
                            "expected_outcome": exp_s,
                            "observed_outcome": obs_s,
                            "decisive_receipt_ref": "r1",
                            "passed": True,
                        }
                        for idx, (exp_s, obs_s) in enumerate(r25_non_contradictions)
                    ]
                }
            },
        )
        assert api_ok.status_code == 200, api_ok.text
        for item in api_ok.json()["perturbation_matrix"]:
            assert item["conclusion_state"] == "supported", item
            assert item["passed"] is True, item

        api_rcpt = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        *[
                            {
                                "outcome_id": f"out-r25-bad-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": bad,
                            }
                            for idx, bad in enumerate(bad_r25_rcpts)
                        ],
                        *[
                            {
                                "outcome_id": f"out-r25-good-{idx}",
                                "current_stage": "delivered_to_human",
                                "authoritative_terminal_state": "committed",
                                "settlement_digest": "dig-1",
                                "delivery_status": "delivered",
                                "answer_grounding": "grounded",
                                "delivery_receipt": good,
                            }
                            for idx, good in enumerate(good_r25_rcpts)
                        ],
                    ]
                }
            },
        )
        assert api_rcpt.status_code == 200, api_rcpt.text
        lifecycles = api_rcpt.json()["outcome_lifecycles"]
        for lc in lifecycles[: len(bad_r25_rcpts)]:
            assert lc["positive_delivery_established"] is False, lc
        for lc in lifecycles[len(bad_r25_rcpts) :]:
            assert lc["positive_delivery_established"] is True, lc

