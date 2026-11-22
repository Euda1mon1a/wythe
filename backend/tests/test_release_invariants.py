"""Fast (<3s) adversarial RCE, git containment, secret-redaction, and O(N) timing invariants."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from app.adapters.base import DisplayExtractionResult
from app.adapters.compose_sources import parse_compose_file
from app.adapters.dockerfile_sources import _load_bounded_yaml, _safe_glob, parse_dockerfile
from app.adapters.epistemic_display_checks import analyze_display_confabulation_and_reads
from app.adapters.inline_store_truth import _collect_str_bindings
from app.adapters.plugin_registry import (
    _pep660_editable_roots_for_dist,
    _reject_untrusted_symlinks_before_resolve,
)
from app.adapters.python_policy_consumption import _const_bool
from app.cli import main as cli_main
from app.core.safe_git import SafeGitError, run_safe_git
from app.schemas.atlas import ViewportCommand, ViewportCommandReceiptCreate
from app.services.companion_export_service import (
    _SARIF_SECRET_VALUE_RE,
    _scrub_trivy_title,
    _validate_companion_path,
)
from app.services.on_device_llm_service import (
    _loads_bounded_json,
    _normalize_private_v1_url,
)
from app.services.route_probe_service import _validate_and_resolve_probe_host
from app.services.ruling_metadata import _is_ruling_commit_stale
from app.services.understanding_discordance import (
    _perturbation_outcomes_contradict,
    evaluate_verdict_clauses,
)
from app.services.understanding_service import (
    UnderstandingAnalyzeRequest,
    _is_positive_delivery_receipt_value,
    analyze_understanding_bundle,
)
from app.services.viewport_service import (
    _ensure_json_nesting_bounded,
    _validate_viewport_server_url,
    list_viewport_receipts,
    publish_viewport_command,
    record_viewport_receipt,
)


def _git_init_commit(repo: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init"],
        cwd=repo,
        check=True,
    )
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def test_p0_1_submodule_filter_rce_blocked_in_gate_and_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "wythe.sqlite3"
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{db_file}")

    sub_src = tmp_path / "sub_src"
    sub_src.mkdir()
    (sub_src / "data.txt").write_text("hello", encoding="utf-8")
    (sub_src / ".gitattributes").write_text("* filter=evil\n", encoding="utf-8")
    _git_init_commit(sub_src)

    parent = tmp_path / "parent_repo"
    (parent / "backend" / "app").mkdir(parents=True)
    (parent / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (parent / "backend" / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (parent / "frontend" / "src" / "app").mkdir(parents=True)
    (parent / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    _git_init_commit(parent)
    subprocess.run(
        ["git", "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub_src), "sub"],
        cwd=parent,
        check=True,
    )
    subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-q", "-m", "add sub"],
        cwd=parent,
        check=True,
    )

    marker = tmp_path / "SUBMODULE_RCE_MARKER"
    sub_cfg = parent / ".git" / "modules" / "sub" / "config"
    with sub_cfg.open("a", encoding="utf-8") as fh:
        fh.write(f'\n[filter "evil"]\n\tclean = touch {marker} && cat\n')
    with (parent / ".gitmodules").open("a", encoding="utf-8") as fh:
        fh.write("\tignore = none\n")

    # Modify sub/data.txt with identical byte length so git status/diff would run clean filter if not ignored
    time.sleep(0.02)
    (parent / "sub" / "data.txt").write_text("world", encoding="utf-8")

    rc_gate = cli_main(["gate", "--strict", str(parent)])
    assert rc_gate == 0
    assert not marker.exists()

    rc_diff = cli_main(["diff", "--base", "HEAD", str(parent)])
    assert rc_diff == 0
    assert not marker.exists()


def test_p0_2_transitive_and_whitespace_hash_alternates_blocked(tmp_path: Path) -> None:
    priv = tmp_path / "priv"
    priv.mkdir()
    (priv / "secret.txt").write_text("SECRET_FROM_OTHER_REPO_99\n", encoding="utf-8")
    _git_init_commit(priv)
    blob_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD:secret.txt"], cwd=priv, text=True
    ).strip()

    # Vector 1: 1-hop transitive alternates inside .git/objects_hop/info/alternates
    evil1 = tmp_path / "evil_hop"
    evil1.mkdir()
    (evil1 / "readme.txt").write_text("ok\n", encoding="utf-8")
    _git_init_commit(evil1)
    hop_info = evil1 / ".git" / "objects_hop" / "info"
    hop_info.mkdir(parents=True)
    (hop_info / "alternates").write_text(f"{priv / '.git' / 'objects'}\n", encoding="utf-8")
    (evil1 / ".git" / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (evil1 / ".git" / "objects" / "info" / "alternates").write_text(
        "../objects_hop\n", encoding="utf-8"
    )
    with pytest.raises(SafeGitError):
        run_safe_git(evil1, "cat-file", "-p", blob_sha)

    # Vector 2: leading-space `#` relative path & trailing-space symlink entry
    evil2 = tmp_path / "evil_ws"
    evil2.mkdir()
    (evil2 / "readme.txt").write_text("ok\n", encoding="utf-8")
    _git_init_commit(evil2)
    (evil2 / ".git" / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (evil2 / ".git" / "objects" / "info" / "alternates").write_text(
        f" #{priv / '.git' / 'objects'}\n", encoding="utf-8"
    )
    with pytest.raises(SafeGitError):
        run_safe_git(evil2, "rev-parse", "HEAD")

    (evil2 / ".git" / "objects" / "info" / "alternates").write_text(
        "../objects \n", encoding="utf-8"
    )
    with pytest.raises(SafeGitError):
        run_safe_git(evil2, "rev-parse", "HEAD")


def test_p0_3_and_p1_7_trivy_sarif_redos_secrets_and_ancestor_symlink(tmp_path: Path) -> None:
    t0 = time.perf_counter()
    assert _scrub_trivy_title("a" * 20000) == "a" * 140
    assert (time.perf_counter() - t0) < 0.050

    t1 = time.perf_counter()
    assert _SARIF_SECRET_VALUE_RE.sub("[REDACTED]", "ENV PASS" + " " * 2000).startswith("ENV PASS")
    assert (time.perf_counter() - t1) < 0.050

    for raw_secret, leaked_sub in (
        ('{"password": "MyProdPassword!2026"}', "MyProdPassword!2026"),
        ("api_key: super_secret_api_99", "super_secret_api_99"),
        ("X-API-Key: header_secret_88", "header_secret_88"),
        ("Token opaque_tok_1234567890", "opaque_tok_1234567890"),
        ("hf_AbCdEfGhIjKlMnOpQrStUvWxYz12", "hf_AbCdEf"),
        ("SG.abcdefghijklmnop_12345.qrstuvwxyzABCDEF_67890", "SG.abcdef"),
        ("hvs.CAESIJ1234567890abcdefghij", "hvs.CAESIJ"),
        ("xapp-1-A0123456789-9876543210-abcdef", "xapp-1-"),
    ):
        scrubbed = _scrub_trivy_title(raw_secret)
        assert leaked_sub not in scrubbed
        assert "[REDACTED]" in scrubbed

    real_dir = tmp_path / "real_repo"
    real_dir.mkdir()
    report_f = real_dir / "trivy.json"
    report_f.write_text("{}", encoding="utf-8")
    sym_parent = tmp_path / "sym_anc"
    sym_parent.symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlink"):
        _validate_companion_path("trivy.json", repo_root=sym_parent / "real_repo")


def test_p0_4_minified_js_ternary_shadow_decls_linear_time(tmp_path: Path) -> None:
    minified_ternary = "var x=[" + ",".join(["e?t(n):r(n)"] * 2000) + "];\n"
    minified_cmp = "var y=[" + ";".join(["e?t(n):a<b"] * 2000) + "];\n"
    fe_dir = tmp_path / "frontend" / "dist"
    fe_dir.mkdir(parents=True)
    for idx, payload in enumerate((minified_ternary, minified_cmp)):
        assert len(payload) >= 20000
        js_file = fe_dir / f"app_{idx}.js"
        js_file.write_text(payload, encoding="utf-8")
    t0 = time.perf_counter()
    analyze_display_confabulation_and_reads(
        tmp_path,
        "frontend",
        DisplayExtractionResult(nodes=[], edges=[], http_calls=[], findings=[]),
    )
    assert (time.perf_counter() - t0) < 0.080


def test_p0_5_and_p1_12_p1_13_default_scan_dos_and_recursion_guards(tmp_path: Path) -> None:
    # 1. 45-byte Dockerfile self-COPY loop + deep wildcard glob
    df_repo = tmp_path / "df_self_copy"
    df_repo.mkdir()
    (df_repo / "f.txt").write_text("x", encoding="utf-8")
    df_path = df_repo / "Dockerfile"
    df_path.write_text("FROM scratch AS s0\nCOPY . /a\nCOPY --from=s0 /a /a\n", encoding="utf-8")
    t0 = time.perf_counter()
    parsed_df = parse_dockerfile(df_path, df_repo)
    assert parsed_df is not None
    assert len(parsed_df.stages) == 1
    assert len(_safe_glob(df_repo, "**/**/**/**/**/**")) >= 1
    assert (time.perf_counter() - t0) < 0.050

    # 2. Compose YAML alias DAG in volumes[].type + YAML flatten_mapping merge burst
    comp_repo = tmp_path / "comp_dag"
    comp_repo.mkdir()
    comp_file = comp_repo / "docker-compose.yml"
    comp_file.write_text(
        "x-0: &a0 [1,2,3,4,5,6,7,8,9,10]\n"
        "x-1: &a1 [*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0]\n"
        "x-2: &a2 [*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1]\n"
        "x-3: &a3 [*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2,*a2]\n"
        "x-4: &a4 [*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3,*a3]\n"
        "x-5: &a5 [*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4,*a4]\n"
        "x-6: &a6 [*a5,*a5,*a5,*a5,*a5,*a5,*a5,*a5,*a5,*a5]\n"
        "services:\n"
        "  app:\n"
        "    image: alpine\n"
        "    volumes:\n"
        "      - type: *a6\n"
        "        source: ./src\n"
        "        target: /app\n",
        encoding="utf-8",
    )
    t1 = time.perf_counter()
    parsed_comp, _note = parse_compose_file(comp_file, comp_repo)
    assert parsed_comp is not None
    assert parsed_comp.services[0].bind_mounts == ()
    assert (time.perf_counter() - t1) < 0.050

    merge_bomb = "m0: &m0 {" + ", ".join(f"k{i}: {i}" for i in range(60)) + "}\n"
    merge_bomb += "big:\n  <<: [" + ", ".join(["*m0"] * 120) + "]\n"
    t_merge = time.perf_counter()
    with pytest.raises(yaml.YAMLError):
        _load_bounded_yaml(merge_bomb, max_nodes=4096)
    assert (time.perf_counter() - t_merge) < 0.050

    # 3. inline_store_truth string-doubling OOM guard
    doubling_src = 'a = "0123456789"\n' + ("a = a + a\n" * 26)
    t2 = time.perf_counter()
    env = _collect_str_bindings(ast.parse(doubling_src).body, {})
    assert len(env.get("a", "")) <= 4096
    assert (time.perf_counter() - t2) < 0.050

    # 4. _const_bool iterative UnaryOp(Not) & agent-harness _dotted_name
    from wythe_plugin_agent_harness.python_inspector import _dotted_name
    from wythe_plugin_agent_harness.ts_inspector import inspect_ts_source
    from wythe_plugin_compiler_ir.usr_index import UsrIndexBundle, _ingest_entry_dict
    from wythe_plugin_cpsat.ast_extractor import _analyze_module_ast
    from wythe_plugin_wiretap.port_occupancy import parse_safe_plist_xml

    deep_not_expr = ast.NodeVisitor()  # build AST iteratively to avoid Python parser stack limit
    _ = deep_not_expr
    expr_node: ast.expr = ast.Constant(value=True)
    for _ in range(1500):
        expr_node = ast.UnaryOp(op=ast.Not(), operand=expr_node)
    assert _const_bool(expr_node) is True

    attr_node: ast.expr = ast.Name(id="a", ctx=ast.Load())
    for _ in range(1500):
        attr_node = ast.Attribute(value=attr_node, attr="b", ctx=ast.Load())
    call_node = ast.Call(func=attr_node, args=[], keywords=[])
    assert _dotted_name(call_node).endswith(".b")

    # 5. ts_inspector huge int + cpsat cumulative objective term cap + usr_index + port_occupancy
    huge_digits = "9" * 6000
    ts_bundle = inspect_ts_source(
        "agent.ts",
        f"const BIG = {huge_digits};\nconst T = Array.from({{ length: {huge_digits} }}, () => ({{}}));\n",
    )
    assert ts_bundle.manifests == []

    cpsat_src = (
        "from ortools.sat.python import cp_model\n"
        "def build():\n"
        "    m = cp_model.CpModel()\n"
        "    x = m.NewIntVar(0, 1, 'x')\n"
        "    a0 = x + x\n"
        + "".join(f"    a{i} = a{i-1} + a{i-1}\n" for i in range(1, 12))
        + ("    m.Minimize(a11)\n" * 60)
    )
    t_cp = time.perf_counter()
    cp_mod, _ = _analyze_module_ast(ast.parse(cpsat_src), "solver.py")
    assert sum(len(o.terms) for o in cp_mod.objectives) <= 1024
    assert (time.perf_counter() - t_cp) < 0.150

    nested_dag: list[object] = [1, 2, 3, 4, 5]
    for _ in range(8):
        nested_dag = [nested_dag] * 10
    usr_bundle = UsrIndexBundle()
    _ingest_entry_dict({"usr": nested_dag, "name": nested_dag}, usr_bundle, tmp_path)
    assert usr_bundle.symbols_by_usr == {}

    hex_plist = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<plist version="1.0"><dict><key>Label</key><string>demo</string>'
        b"<key>Sockets</key><dict><key>s</key><dict><key>SockServiceName</key>"
        b"<integer>0x1f90</integer></dict></dict></dict></plist>"
    )
    parsed_plist = parse_safe_plist_xml(hex_plist)
    assert parsed_plist["Label"] == "demo"


def test_p0_6_otel_ebpf_recursion_redos_and_six_secret_vectors(tmp_path: Path) -> None:
    from wythe_plugin_wiretap.otel_ebpf import (
        parse_otel_traces,
        redact_attributes,
        redact_url_target,
    )

    trace_file = tmp_path / "traces.json"
    trace_file.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "api"}}]},
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "GET / " * 1500,
                                        "attributes": [
                                            {"key": "http.method", "value": {"stringValue": "GET"}},
                                            {"key": "http.route", "value": {"stringValue": "/health"}},
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    t0 = time.perf_counter()
    transitions, _rcnt = parse_otel_traces(trace_file, allow_external=True)
    assert len(transitions) == 1
    assert (time.perf_counter() - t0) < 0.050

    t1 = time.perf_counter()
    _cp, _ru, _wr = redact_url_target("/@" + "a:" * 15000)
    assert (time.perf_counter() - t1) < 0.050

    pg_u = "postgres://u"
    rd_u = "redis://"
    jwt_h = "eyJhbGciOiJIUzI1NiJ9"
    cleaned, r_total = redact_attributes(
        {
            "db.uri": f"{pg_u}:SUPER_SECRET_1@h/d?token=T_SECRET_1",
            "db.url": f"{pg_u}:SUPER_SECRET_2@h/d?token=T_SECRET_2",
            "redis.uri": f"{rd_u}:SUPER_SECRET_3@h:6379/0",
            "exception.message": f"Failed on {pg_u}:SUPER_SECRET_4@h/d?token=T_SECRET_4",
            "http.target": "/cb#access_token=FRAG_SECRET_5",
            "db.statement": f"SET sess {jwt_h}.eyJzdWIiOiIxIn0.JWT_SECRET_6",
            "http.request.headers": [["Authorization", "ASGI_SECRET_7"]],
            "nested_kv": {
                "key": "db.connection_string",
                "value": {"stringValue": f"{pg_u}:NEST_SECRET_8@h/d"},
            },
            "http.response.headers": [{"X-Amz-Security": "AMZ_SECRET_9"}],
        }
    )
    dumped = json.dumps(cleaned)
    assert r_total >= 8
    for secret_canary in (
        "SUPER_SECRET_1",
        "T_SECRET_1",
        "SUPER_SECRET_2",
        "T_SECRET_2",
        "SUPER_SECRET_3",
        "SUPER_SECRET_4",
        "T_SECRET_4",
        "FRAG_SECRET_5",
        "JWT_SECRET_6",
        "ASGI_SECRET_7",
        "NEST_SECRET_8",
        "AMZ_SECRET_9",
    ):
        assert secret_canary not in dumped


def test_p1_1_p1_2_p1_4_p1_5_p1_6_p1_8_core_regressions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # P1-1: Simulated Homebrew symlinked prefix (`opt/py -> Cellar/python/3.12`) + AnnAssign PEP 660
    cellar_py = tmp_path / "Cellar" / "python" / "3.12"
    site_pkgs = cellar_py / "lib" / "python3.12" / "site-packages"
    dist_info = site_pkgs / "demo_plugin-0.1.0.dist-info"
    dist_info.mkdir(parents=True)
    opt_dir = tmp_path / "opt"
    opt_dir.mkdir()
    opt_py = opt_dir / "py"
    opt_py.symlink_to(cellar_py)

    scanned_repo = tmp_path / "scanned_repo"
    scanned_repo.mkdir()
    evil_target = scanned_repo / "evil_mod.py"
    evil_target.write_text("x = 1\n", encoding="utf-8")
    evil_link = site_pkgs / "evil_mod.py"
    evil_link.symlink_to(evil_target)

    with monkeypatch.context() as mp:
        mp.setattr(sys, "prefix", str(opt_py))
        resolved_dist = _reject_untrusted_symlinks_before_resolve(
            opt_py / "lib" / "python3.12" / "site-packages" / "demo_plugin-0.1.0.dist-info",
            label="dist-info",
            repo_root=scanned_repo,
        )
        assert resolved_dist == dist_info.resolve()
        with pytest.raises(PermissionError):
            _reject_untrusted_symlinks_before_resolve(
                opt_py / "lib" / "python3.12" / "site-packages" / "evil_mod.py",
                label="module origin",
                repo_root=scanned_repo,
            )

    ed_src = tmp_path / "ext_plugin" / "src" / "my_pkg"
    ed_src.mkdir(parents=True)
    finder_py = site_pkgs / "__editable___demo_plugin_0_1_0_finder.py"
    finder_py.write_text(
        f"MAPPING: dict[str, str] = {{'my_pkg': {str(ed_src)!r}}}\n"
        f"NAMESPACES: dict[str, list[str]] = {{'my_ns': [{str(ed_src)!r}]}}\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "__editable___demo_plugin_0_1_0_finder.py,sha256=x,10\n", encoding="utf-8"
    )
    ed_roots = _pep660_editable_roots_for_dist(
        SimpleNamespace(_path=dist_info), repo_root=scanned_repo
    )
    assert (tmp_path / "ext_plugin" / "src").resolve() in ed_roots

    # P1-2: git_present=False fails closed on stale SHA and empty audited_commit
    assert (
        _is_ruling_commit_stale(
            SimpleNamespace(audited_commit="deadbeef0000"), "unavailable", git_present=False
        )
        is True
    )
    assert (
        _is_ruling_commit_stale(
            SimpleNamespace(audited_commit=""), "unavailable", git_present=False
        )
        is True
    )

    # P1-4: GET / 500 and http_status dict short-circuit
    assert _is_positive_delivery_receipt_value("GET / 500") is False
    assert (
        _is_positive_delivery_receipt_value(
            {"receipt_id": "r1", "http_status": {"delivered": True, "raw": 500}}
        )
        is False
    )

    # P1-5: blocked vs 500 FN, 403 vs returned 403 FP, & RFC 3986 scheme / evidence_ref injection
    assert _perturbation_outcomes_contradict("blocked", "500 Internal Server Error") is True
    assert _perturbation_outcomes_contradict("403", "returned 403") is False
    clauses, _s, md, _m = evaluate_verdict_clauses(
        [
            {
                "clause_id": "c1",
                "text": "x",
                "evidence_ref": "shortcuts://run-shortcut?name=pwn",
                "source_location": "javascript.js:1#alert",
            }
        ]
    )
    assert clauses[0].evidence_ref is None
    assert "shortcuts:" not in md
    assert "javascript.js:" not in md
    assert md == "[x](javascript.js#alert)"

    # P1-6: SSRF 0.0.0.0/8, fec0::/10, and AWS IPv6 fd00:ec2::/32
    for bad_host, bad_url in (
        ("0.0.0.1", "http://0.0.0.1/x"),
        ("::ffff:0.0.0.1", "http://[::ffff:0.0.0.1]/x"),
        ("fd00:ec2::253", "http://[fd00:ec2::253]/x"),
        ("fec0::1", "http://[fec0::1]/x"),
    ):
        with pytest.raises(ValueError):
            _validate_and_resolve_probe_host(bad_host, allow_remote=True)
        with pytest.raises(ValueError):
            _validate_viewport_server_url(bad_url, allow_remote=True)
    for bad_v1_url in (
        "http://0.0.0.1/v1",
        "http://[fd00:ec2::253]/v1",
        "http://[fec0::1]/v1",
    ):
        with pytest.raises(ValueError):
            _normalize_private_v1_url(bad_v1_url)

    # P1-8: raw_bundle["target_slug"] bleed, evicted-session receipt bleed, & JSON depth guard
    from app.services import investigation_service

    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "state"))
    fake_sess_b = SimpleNamespace(
        session_id="sess-b",
        target_slug="target-b",
        corrections=[
            SimpleNamespace(
                correction_id="c1",
                actor="human",
                target_ref_id=None,
                kind="disagreement",
                note="PRIVATE_TARGET_B_CORRECTION",
                created_at="2026-11-21T00:00:00Z",
                evidence_revision_id="rev1",
            )
        ],
    )
    with monkeypatch.context() as mp:
        mp.setattr(
            investigation_service,
            "get_investigation_session",
            lambda sid: fake_sess_b if sid == "sess-b" else None,
        )
        und_rep = analyze_understanding_bundle(
            UnderstandingAnalyzeRequest(
                session_id="sess-b",
                bundle={"target_slug": "target-b", "question": "Spoof attempt"},
            )
        )
    assert all("PRIVATE_TARGET_B_CORRECTION" not in c.note for c in und_rep.human_corrections)

    ack = publish_viewport_command(
        ViewportCommand(
            target_slug="target-b",
            session_id="browser-only-sid",
            focus_node_ids=["t:users"],
        )
    )
    record_viewport_receipt(
        ViewportCommandReceiptCreate(
            command_id=ack.command_id,
            seq=ack.seq,
            target_slug="target-b",
            session_id="browser-only-sid",
            client_id="tab-1",
            outcome="applied",
        )
    )
    assert len(list_viewport_receipts(target_slug="target-b", session_id="browser-only-sid")) == 1
    assert list_viewport_receipts(target_slug=None, session_id="browser-only-sid") == []

    deep_json = "[" * 2000 + "]" * 2000
    with pytest.raises(ValueError, match="nesting depth"):
        _ensure_json_nesting_bounded(deep_json)
    with pytest.raises(ValueError, match="nesting depth"):
        _loads_bounded_json(deep_json)
