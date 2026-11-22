"""Regression suite for Wythe v0.2.9 post-bd2a609 Lane B (P0-4, P1-2, P1-3, P1-4, P1-9, P1-10)."""

from __future__ import annotations

import io
import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from app.adapters.base import RawCandidateFinding
from app.schemas.atlas import (
    InvestigationCorrectionCreate,
    InvestigationCreateRequest,
    TargetProjectCreate,
    ViewportCommand,
    ViewportCommandReceiptCreate,
)
from app.services import (
    companion_export_service,
    investigation_service,
    mcp_service,
    on_device_llm_service,
    route_probe_service,
    viewport_service,
)
from app.services.companion_export_service import (
    _parse_trivy_report,
    _read_bounded_json,
    _scrub_trivy_title,
)
from app.services.governance_service import register_target
from app.services.investigation_service import (
    _read_git_head_identity,
    add_investigation_correction,
    create_or_reopen_investigation,
)
from app.services.on_device_llm_service import _normalize_private_v1_url
from app.services.route_probe_service import (
    _validate_and_resolve_probe_host,
    apply_live_route_probe,
)
from app.services.understanding_discordance import (
    _perturbation_outcomes_contradict,
    _split_clauses,
    evaluate_verdict_clauses,
)
from app.services.understanding_service import (
    _BARE_4XX_5XX_DELIVERY_RE,
    _BENIGN_DELIVERY_FAILURE_NEGATION_RE,
    UnderstandingAnalyzeRequest,
    _has_negative_delivery_text,
    _is_positive_delivery_receipt_value,
    _split_delivery_clauses,
    analyze_understanding_bundle,
)
from app.services.viewport_service import (
    _validate_viewport_server_url,
    list_viewport_receipts,
    publish_viewport_command,
    record_viewport_receipt,
)
from wythe_plugin_agent_discordance.evaluator import load_repo_discordance_artifacts


def _write_minimal_repo(repo_dir: Path) -> Path:
    (repo_dir / "backend" / "app" / "api" / "routes").mkdir(parents=True, exist_ok=True)
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT);\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "api" / "routes" / "items.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/api/v1/items')\n"
        "def list_items():\n"
        "    return []\n",
        encoding="utf-8",
    )
    return repo_dir


def test_p0_4_redos_linear_time_and_field_length_caps() -> None:
    slash_evil = "400/ " * 600 + "x"
    t0 = time.perf_counter()
    assert _BARE_4XX_5XX_DELIVERY_RE.search(slash_evil) is None
    assert _has_negative_delivery_text(slash_evil) is False
    assert _has_negative_delivery_text("200/ " * 600 + "x") is False
    assert (time.perf_counter() - t0) < 0.250

    assert _has_negative_delivery_text("200/503") is True
    assert _has_negative_delivery_text("status=403") is True
    assert _has_negative_delivery_text("(500)") is True
    assert _has_negative_delivery_text("400 ms") is False

    ident_evil = "a_" * 8000 + "x"
    t1 = time.perf_counter()
    assert _BENIGN_DELIVERY_FAILURE_NEGATION_RE.search(ident_evil) is None
    assert _has_negative_delivery_text(ident_evil) is False
    assert _has_negative_delivery_text('"' + "a_" * 8000 + 'x"') is False
    assert (time.perf_counter() - t1) < 0.250

    yet_evil = "not " + "yet " * 4000
    t2_a = time.perf_counter()
    assert len(_split_clauses(yet_evil)) >= 3999
    assert (time.perf_counter() - t2_a) < 0.250

    t2_b = time.perf_counter()
    assert len(_split_delivery_clauses(yet_evil)) >= 3999
    assert (time.perf_counter() - t2_b) < 0.250

    t2_c = time.perf_counter()
    assert _perturbation_outcomes_contradict("blocked", yet_evil) is False
    assert (time.perf_counter() - t2_c) < 0.250

    assert _perturbation_outcomes_contradict("blocked", "blocked; 404 not found error") is False
    assert _perturbation_outcomes_contradict("blocked", "blocked; my_err=0") is False
    assert _perturbation_outcomes_contradict("blocked", "blocked; leaked_err: 0") is True

    oversized = "ok " * 6000
    t3 = time.perf_counter()
    assert _has_negative_delivery_text(oversized) is True
    assert _perturbation_outcomes_contradict("allowed", oversized) is True
    assert (time.perf_counter() - t3) < 0.250


def test_p1_4_verdict_uri_sanitization_and_unverified_src_loc_clearing() -> None:
    clauses, _sent, md, missing = evaluate_verdict_clauses(
        [
            {
                "clause_id": "c-unver-shortcut",
                "text": "Click me",
                "state": "supported",
                "missing_receipt": "rcpt_missing",
                "source_location": "shortcuts://run-shortcut?name=pwn",
            },
            {
                "clause_id": "c-unver-https",
                "text": "Unverified https",
                "state": "unverified",
                "source_location": "https://example.com/r1",
            },
            {
                "clause_id": "c-supp-ev",
                "text": "Verified receipt ref",
                "state": "supported",
                "evidence_ref": "sdk:delivery-001",
            },
            {
                "clause_id": "c-supp-file",
                "text": "Verified repo file",
                "state": "supported",
                "source_location": "backend/app/main.py:42",
            },
        ]
    )
    assert clauses[0].state == "unverified"
    assert clauses[0].source_location is None
    assert "[Click me](#unverified:rcpt_missing)" in md
    assert "shortcuts:" not in md

    assert clauses[1].state == "unverified"
    assert clauses[1].source_location is None
    assert "[Unverified https](#unverified:c-unver-https)" in md
    assert "[Verified receipt ref](#evidence:sdk:delivery-001)" in md
    assert "[Verified repo file](backend/app/main.py#L42)" in md
    assert "missing_receipt:rcpt_missing" in missing

    for bad_uri in (
        "shortcuts://run-shortcut?name=pwn",
        "shortcuts:run",
        "file:///etc/passwd",
        "https://example.com/r1",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "//evil.example/pwn",
        "/etc/passwd",
        "../secret.py",
    ):
        cs, _s, bad_md, _m = evaluate_verdict_clauses(
            [{"clause_id": "c-bad", "text": "X", "state": "supported", "source_location": bad_uri}]
        )
        assert cs[0].source_location is None
        assert cs[0].state == "unverified"
        assert bad_md == "[X](#unverified:c-bad)"


def test_p1_4_http_status_contradiction_polarity_list_status_and_gateway_timed_phrases() -> None:
    assert _perturbation_outcomes_contradict("HTTP 403 Forbidden", "HTTP 200 OK") is True
    assert _perturbation_outcomes_contradict("HTTP 200", "HTTP 500") is True
    assert _perturbation_outcomes_contradict("HTTP 500", "HTTP 200") is True
    assert _perturbation_outcomes_contradict("blocked", "blocked with 403 validation error") is False
    assert _perturbation_outcomes_contradict("blocked", "blocked with 422 schema error") is False

    assert _is_positive_delivery_receipt_value({"status": "delivered", "http_status": [500]}) is False
    assert _is_positive_delivery_receipt_value({"status": "delivered", "status_code": (403,)}) is False
    assert _is_positive_delivery_receipt_value({"status": "delivered", "code": {502}}) is False
    assert _is_positive_delivery_receipt_value({"status": "delivered", "http_status": []}) is False
    assert _is_positive_delivery_receipt_value({"status": "delivered", "http_status": [200, 500]}) is False
    assert _is_positive_delivery_receipt_value({"status": "delivered", "http_status": [200]}) is True

    assert _is_positive_delivery_receipt_value("rcpt-gateway-12345") is True
    assert _is_positive_delivery_receipt_value("rcpt-timed-12345") is True
    assert _is_positive_delivery_receipt_value({"id": "rcpt-gateway-12345", "status": "delivered"}) is True
    assert _is_positive_delivery_receipt_value({"id": "r1", "status": "delivered", "note": "bad gateway"}) is False
    assert _is_positive_delivery_receipt_value({"id": "r1", "status": "delivered", "note": "gateway timeout"}) is False
    assert _is_positive_delivery_receipt_value({"id": "r1", "status": "delivered", "note": "timed out"}) is False


def test_p1_2_cloud_imds_6to4_teredo_and_route_probe_join_authority_pivot() -> None:
    # Teredo: 2001:0000:<server_v4>:0000:0000:<~client_v4>
    # 169.254.169.254 = a9fe:a9fe; ~169.254.169.254 = 5601:5601; 8.8.8.8 = 0808:0808; ~8.8.8.8 = f7f7:f7f7
    teredo_srv_imds = "2001:0000:a9fe:a9fe:0000:0000:f7f7:f7f7"
    teredo_cli_imds = "2001:0000:0808:0808:0000:0000:5601:5601"
    sixtofour_imds = "2002:a9fe:a9fe::1"
    sixtofour_alibaba = "2002:6464:64c8::1"

    for fn in (
        on_device_llm_service._unwrap_ip,
        route_probe_service._unwrap_ip,
        viewport_service._unwrap_ip,
    ):
        assert fn(ipaddress.ip_address(sixtofour_imds)) == ipaddress.ip_address("169.254.169.254")
        assert fn(ipaddress.ip_address(teredo_srv_imds)) == ipaddress.ip_address("169.254.169.254")
        assert fn(ipaddress.ip_address(teredo_cli_imds)) == ipaddress.ip_address("169.254.169.254")

    for bad_host in (
        "fd00:ec2::254",
        "100.100.100.200",
        "::ffff:100.100.100.200",
        sixtofour_imds,
        sixtofour_alibaba,
        "2002:7f00:0001::1",
        teredo_srv_imds,
        teredo_cli_imds,
    ):
        url = f"http://[{bad_host}]:8080/v1" if ":" in bad_host else f"http://{bad_host}:8080/v1"
        with pytest.raises(ValueError):
            _normalize_private_v1_url(url)
        for remote_flag in (False, True):
            with pytest.raises(ValueError):
                _validate_viewport_server_url(url, allow_remote=remote_flag)
            with pytest.raises(ValueError):
                _validate_and_resolve_probe_host(bad_host, allow_remote=remote_flag)

    for bad_path in (
        ":6379/keys",
        "@evil.example/pwn",
        "//evil.example/pwn",
        "https://evil.example/pwn",
        "\\evil.example\\pwn",
        "api/missing-leading-slash",
    ):
        with pytest.raises(ValueError):
            route_probe_service._join("http://127.0.0.1:8000", bad_path)
        with pytest.raises(ValueError):
            route_probe_service._join("http://127.0.0.1", bad_path)

    seen_urls: list[str] = []

    def _mock_handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(_mock_handler)) as mock_client:
        adjusted, _note = apply_live_route_probe(
            [
                RawCandidateFinding("DISP-004", "n", "a.ts", 1, "t", "d", "r", "GET", ":6379/keys"),
                RawCandidateFinding("DISP-004", "n", "a.ts", 2, "t", "d", "r", "GET", "@evil.example/pwn"),
                RawCandidateFinding("DISP-004", "n", "a.ts", 3, "t", "d", "r", "GET", "/api/ok"),
            ],
            "http://127.0.0.1:8000",
            client=mock_client,
        )
    assert len(adjusted) == 3
    assert all(u.startswith("http://127.0.0.1:8000/") for u in seen_urls)
    assert not any("6379" in u or "evil.example" in u for u in seen_urls)


def test_p1_3_trivy_secret_redaction_symlink_nofollow_fifo_and_json_depth(tmp_path: Path) -> None:
    jwt_hdr, gcp_pfx = "eyJhbGciOiJIUzI1NiJ9", "AIza"
    slk_base = "https://hooks.slack.com/services"
    dsc_base = "https://discord.com/api/webhooks"
    jwt_tok = f"{jwt_hdr}.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    slack_wh = f"{slk_base}/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    discord_wh = f"{dsc_base}/1234567890/abcdefghijklmnopqrstuvwxyz"
    gcp_key = f"{gcp_pfx}SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
    npm_tok = "npm_1234567890abcdefghij1234567890"
    pref_stripe = "my_app_sk_live_9876543210abcdef"

    for raw_secret in (
        f"Leak {jwt_tok}",
        f"Hook {slack_wh}",
        f"Hook {discord_wh}",
        f"GCP {gcp_key}",
        f"NPM {npm_tok}",
        "Authorization: Token secret_tok_999",
        "ENV DB_PASSWORD=super_secret_pw",
        f"Key {pref_stripe}",
    ):
        scrubbed = _scrub_trivy_title(raw_secret, fallback="clean")
        assert "[REDACTED]" in scrubbed
        for needle in (
            "eyJhbGci",
            "hooks.slack.com",
            "discord.com/api/webhooks",
            "AIzaSy",
            "npm_12345",
            "secret_tok_999",
            "super_secret_pw",
            "sk_live_9876",
        ):
            assert needle not in scrubbed

    tjson = tmp_path / "trivy-secrets.json"
    tjson.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": f"CVE-2026-1-{npm_tok}",
                                "PkgName": f"pkg-{pref_stripe}",
                                "Severity": "HIGH",
                                "Title": f"Leak {jwt_tok}",
                            }
                        ],
                        "Secrets": [
                            {
                                "RuleID": f"custom-unlisted-rule-{gcp_key}",
                                "Severity": "CRITICAL",
                                "Title": f"Raw secret {slack_wh}",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    t_out = json.dumps(_parse_trivy_report(tjson))
    for needle in ("eyJhbGci", "hooks.slack.com", "AIzaSy", "npm_12345", "sk_live_9876"):
        assert needle not in t_out

    sarif_rules = (
        "slack-web-hook",
        "discord-web-hook",
        "sentry-dsn",
        "postgres-dsn",
        "jwt-token",
        "gcp-api-key",
        "npm-access-token",
    )
    sarif_p = tmp_path / "rules.sarif"
    sarif_p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": rid} for rid in sarif_rules]}},
                        "results": [
                            {"ruleId": rid, "level": "error", "message": {"text": f"RAW_SECRET_{rid}"}}
                            for rid in sarif_rules
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    parsed_sarif = _parse_trivy_report(sarif_p)
    assert parsed_sarif["secret_count"] == len(sarif_rules)
    assert parsed_sarif["misconfiguration_count"] == 0
    assert "RAW_SECRET_" not in json.dumps(parsed_sarif)


def test_p1_3_bounded_json_rejects_symlink_ancestors_fifo_and_deep_nesting(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_json = outside / "trivy.json"
    secret_json.write_text('{"SchemaVersion": 2, "Results": []}', encoding="utf-8")

    sym_dir = repo_root / "linked_parent"
    sym_dir.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        _read_bounded_json(sym_dir / "trivy.json", repo_root=repo_root)
    with pytest.raises(ValueError, match="escapes"):
        _read_bounded_json(repo_root / ".." / "outside" / "trivy.json", repo_root=repo_root)

    fifo_p = repo_root / "pipe.json"
    os.mkfifo(fifo_p)
    t0 = time.perf_counter()
    with pytest.raises(ValueError):
        _read_bounded_json(fifo_p, repo_root=repo_root)
    assert (time.perf_counter() - t0) < 0.5

    deep_p = repo_root / "deep.json"
    deep_p.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(ValueError, match="nesting depth"):
        companion_export_service._parse_trivy_report(deep_p, repo_root=repo_root)


def test_p1_9_cross_target_receipts_corrections_and_git_commondir_containment(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    repo_a = _write_minimal_repo(tmp_path / "repo-a")
    repo_b = _write_minimal_repo(tmp_path / "repo-b")
    register_target(db_session, TargetProjectCreate(slug="target-a", name="A", repo_path=str(repo_a)))
    register_target(db_session, TargetProjectCreate(slug="target-b", name="B", repo_path=str(repo_b)))

    sess_a = create_or_reopen_investigation(
        db_session, InvestigationCreateRequest(target_slug="target-a", session_id="sess-a")
    )
    add_investigation_correction(
        sess_a.session_id,
        InvestigationCorrectionCreate(note="PRIVATE_TARGET_A_CORRECTION"),
    )

    # Publish an unscoped command + receipt on target-b, and a scoped command + receipt on target-a
    ack_b_unscoped = publish_viewport_command(
        ViewportCommand(target_slug="target-b", command_id="cmd-b-unscoped"),
        local_only=True,
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack_b_unscoped.command_id,
            seq=ack_b_unscoped.seq,
            target_slug="target-b",
            client_id="cli-b",
            outcome="applied",
            note="LEAKED_FROM_TARGET_B",
        )
    )
    ack_a_scoped = publish_viewport_command(
        ViewportCommand(target_slug="target-a", session_id=sess_a.session_id, command_id="cmd-a-scoped"),
        local_only=True,
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack_a_scoped.command_id,
            seq=ack_a_scoped.seq,
            target_slug="target-a",
            session_id=sess_a.session_id,
            client_id="cli-a",
            outcome="applied",
            note="SCOPED_TO_SESS_A",
        )
    )

    rcpts = list_viewport_receipts(target_slug=None, session_id=sess_a.session_id)
    assert [r.command_id for r in rcpts] == ["cmd-a-scoped"]
    assert all(r.target_slug == "target-a" and r.session_id == sess_a.session_id for r in rcpts)
    assert list_viewport_receipts(target_slug="target-b", session_id=sess_a.session_id) == []

    mcp_rcpts = mcp_service.dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "wythe_investigation",
                "arguments": {"action": "get_receipts", "session_id": sess_a.session_id},
            },
        },
    )
    assert mcp_rcpts is not None and mcp_rcpts["result"]["isError"] is False
    mcp_text = mcp_rcpts["result"]["content"][0]["text"]
    assert "SCOPED_TO_SESS_A" in mcp_text
    assert "LEAKED_FROM_TARGET_B" not in mcp_text

    # Understanding cross-target session_id rejected / omitted
    with pytest.raises(ValueError, match="Cross-target mismatch"):
        analyze_understanding_bundle(
            UnderstandingAnalyzeRequest(target_slug="target-b", session_id=sess_a.session_id),
            db=db_session,
        )
    unscoped_rep = analyze_understanding_bundle(
        UnderstandingAnalyzeRequest(session_id=sess_a.session_id, bundle={"question": "q"}),
        db=db_session,
    )
    assert unscoped_rep.human_corrections == []

    same_target_rep = analyze_understanding_bundle(
        UnderstandingAnalyzeRequest(target_slug="target-a", session_id=sess_a.session_id),
        db=db_session,
    )
    assert len(same_target_rep.human_corrections) == 1
    assert same_target_rep.human_corrections[0].note == "PRIVATE_TARGET_A_CORRECTION"

    mcp_und_cross = mcp_service.dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "resources/read",
            "params": {"uri": f"wythe://target-b/understanding?session_id={sess_a.session_id}"},
        },
    )
    assert mcp_und_cross is not None and mcp_und_cross["error"]["code"] == -32602
    assert "PRIVATE_TARGET_A_CORRECTION" not in json.dumps(mcp_und_cross)

    # .git/commondir in regular .git directory pointing outside repo_root MUST be rejected
    victim = tmp_path / "victim_repo"
    victim.mkdir()
    subprocess.run(["git", "init"], cwd=str(victim), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=str(victim), check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=str(victim), check=True)
    (victim / "f.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(victim), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(victim), check=True, capture_output=True)
    subprocess.run(["git", "pack-refs", "--all"], cwd=str(victim), check=True, capture_output=True)
    victim_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(victim), check=True, capture_output=True, text=True
    ).stdout.strip()

    evil_repo = tmp_path / "evil_commondir_repo"
    (evil_repo / ".git").mkdir(parents=True)
    (evil_repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (evil_repo / ".git" / "commondir").write_text(str(victim / ".git") + "\n", encoding="utf-8")

    sha, ident = _read_git_head_identity(evil_repo / ".git")
    assert sha == "" and ident == b""
    assert victim_sha.encode() not in ident
    tree_sha, _ = investigation_service.compute_repo_tree_fingerprint(evil_repo)
    assert tree_sha


def test_p1_10_mcp_stdio_and_agent_discordance_deep_json_nesting_guard(
    isolated_db_url: str,
    tmp_path: Path,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    deep_bomb = b"[" * 100_000 + b"]" * 100_000
    benign_str_brackets = (
        b'{"jsonrpc":"2.0","id":42,"method":"ping","params":{"_ignored":"'
        + (b"[" * 300)
        + b'"}}\n'
    )
    ping_line = b'{"jsonrpc":"2.0","id":99,"method":"ping"}\n'

    # 1. JSON-lines framing: 200 KB bomb returns -32700 parse error without crashing server loop
    out_jl = io.BytesIO()
    rc = mcp_service.run_mcp_stdio_server(
        stdin=io.BytesIO(deep_bomb + b"\n" + benign_str_brackets[:0] + ping_line),
        stdout=out_jl,
    )
    assert rc == 0
    lines = [json.loads(line) for line in out_jl.getvalue().decode("utf-8").splitlines() if line.strip()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["id"] == 99

    # 2. Content-Length framing + string-aware check (300 '[' inside a JSON string is depth 1, not 301)
    string_ping = b'{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"' + (b"[" * 300) + b'"}}'
    framed_stream = (
        f"Content-Length: {len(deep_bomb)}\r\n\r\n".encode("ascii")
        + deep_bomb
        + f"Content-Length: {len(string_ping)}\r\n\r\n".encode("ascii")
        + string_ping
    )
    out_cl = io.BytesIO()
    assert mcp_service.run_mcp_stdio_server(stdin=io.BytesIO(framed_stream), stdout=out_cl) == 0
    raw_cl_out = out_cl.getvalue().decode("utf-8")
    assert '"code":-32700' in raw_cl_out
    assert '"id":42' in raw_cl_out

    # 3. wythe-plugin-agent-discordance handles 200 KB bracket bomb cleanly without RecursionError
    disc_repo = tmp_path / "disc_deep"
    (disc_repo / ".wythe").mkdir(parents=True)
    (disc_repo / ".wythe" / "agent_routes.json").write_bytes(deep_bomb)
    routes_doc, receipts_doc, _rel, notes = load_repo_discordance_artifacts(disc_repo)
    assert routes_doc is None and receipts_doc is None
    assert any("nesting depth" in n for n in notes)
