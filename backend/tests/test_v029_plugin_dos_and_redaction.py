"""Adversarial regression tests for Wythe v0.2.9 P1-3, P1-4, P2-3, and P2-6 plugin fixes."""

from __future__ import annotations

import ast
import json
import plistlib
import struct
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AtlasSummaryStats,
    GateEvaluation,
    LegacyBridgeSummary,
    StratumMicroEdge,
    StratumMicroNode,
    TruthAtlasReport,
)
from app.services.companion_export_service import (
    build_openlineage_static_bundle,
    summarize_companion_security_artifacts,
)
from app.services.stratum_service import (
    compact_stratum_subgraph,
)


def _make_report(repo_path: str, *, nodes: list[AtlasNode] | None = None) -> TruthAtlasReport:
    ts = datetime(2026, 11, 20, 0, 0, 0, tzinfo=UTC)
    return TruthAtlasReport(
        target_slug="demo",
        target_name="Demo",
        repo_path=repo_path,
        stack_profile="python-services",
        source_commit="deadbeef",
        observed_at=ts,
        valid_until=ts,
        observation_source="static_ast",
        content_digest="deadbeef",
        summary=AtlasSummaryStats(
            truth_tables=len(nodes or []),
            sql_functions=0,
            ephemeral_stores=0,
            manipulator_routes=0,
            manipulator_services=0,
            display_pages=0,
            display_hooks_and_clients=0,
            verified_edges=0,
            end_to_end_chains=0,
            clean_nodes=len(nodes or []),
            flagged_nodes=0,
            blocking_findings=0,
            warning_findings=0,
        ),
        nodes=nodes or [],
        edges=[],
        chains=[],
        findings=[],
        gate=GateEvaluation(verdict="PASS", mode="strict", blocking_violations=0, evaluated_at=ts),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )


def test_p1_3_python_inspector_nested_comprehension_budget() -> None:
    from wythe_plugin_agent_harness.python_inspector import _eval_static_ast_value

    bomb_expr = "[[[[1 for _ in range(250)] for _ in range(250)] for _ in range(250)] for _ in range(250)]"
    dict_bomb = "{str(i): {str(j): [1 for _ in range(250)] for j in range(250)} for i in range(250)}"
    t0 = time.perf_counter()
    res_list = _eval_static_ast_value(ast.parse(bomb_expr, mode="eval").body)
    res_dict = _eval_static_ast_value(ast.parse(dict_bomb, mode="eval").body)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5
    assert res_list is None
    assert res_dict is None

    small = _eval_static_ast_value(ast.parse("[i for i in range(5)]", mode="eval").body)
    assert small == [0, 1, 2, 3, 4]


def test_p1_3_container_dag_and_yaml_alias_budgets(tmp_path: Path) -> None:
    from wythe_plugin_agent_harness.registry_reconciler import _load_bounded_yaml
    from wythe_plugin_apple_ipc.swift_extractor import _check_python_container_depth
    from wythe_plugin_compiler_ir.usr_index import check_object_depth, parse_usr_index_text
    from wythe_plugin_wiretap.port_occupancy import _load_yaml_docs

    # Build a 40-level diamond DAG (~2^40 paths if visited without deduplication)
    dag: list[object] = ["leaf"]
    for _ in range(40):
        dag = [dag, dag]
    t0 = time.perf_counter()
    _check_python_container_depth({"root": dag}, max_depth=64)
    check_object_depth({"root": dag}, max_depth=64)
    assert time.perf_counter() - t0 < 0.2

    # Build binary plist DAG payload from shared refs
    bplist_raw = plistlib.dumps({"root": dag}, fmt=plistlib.FMT_BINARY)
    parsed_bplist = plistlib.loads(bplist_raw)
    t1 = time.perf_counter()
    _check_python_container_depth(parsed_bplist, max_depth=64)
    assert time.perf_counter() - t1 < 0.2

    # YAML billion-laughs alias bomb via merge and sequence aliases
    yaml_lines = ["a0: &a0 {x0: 1, x1: 2, x2: 3, x3: 4, x4: 5, x5: 6, x6: 7, x7: 8, x8: 9, x9: 10}"]
    for i in range(1, 10):
        prev = f"a{i - 1}"
        yaml_lines.append(f"a{i}: &a{i} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]")
    yaml_bomb = "\n".join(yaml_lines)

    # Also test huge repeated alias list exceeding 4096 references
    big_alias_yaml = "base: &b {k: 1}\ntools:\n" + ("  - *b\n" * 4200)
    with pytest.raises(yaml.YAMLError):
        _load_bounded_yaml(big_alias_yaml)
    assert _load_yaml_docs(big_alias_yaml) == []
    with pytest.raises(ValueError):
        parse_usr_index_text(big_alias_yaml, format_hint="bomb.yaml")
    # Ensure wide distinct-key merge exceeding 4096 nodes/pairs is rejected
    wide_merge_lines = [
        f"b{b}: &b{b} {{" + ", ".join(f"k_{b}_{j}: 1" for j in range(35)) + "}"
        for b in range(70)
    ]
    wide_merge_lines.append("merged: {<<: [" + ", ".join(f"*b{b}" for b in range(70)) + "]}")
    with pytest.raises(yaml.YAMLError):
        _load_bounded_yaml("\n".join(wide_merge_lines))
    # Ensure nested duplicate-key merge bomb never hangs (either raises YAMLError or deduplicates in O(N))
    merge_bomb = "m0: &m0 {k0: 1, k1: 2, k2: 3, k3: 4}\n" + "\n".join(
        f"m{i}: &m{i} {{<<: [*m{i-1}, *m{i-1}]}}" for i in range(1, 16)
    )
    t2 = time.perf_counter()
    try:
        merged_doc = _load_bounded_yaml(merge_bomb)
        assert isinstance(merged_doc, dict)
    except yaml.YAMLError:
        pass
    assert time.perf_counter() - t2 < 0.5
    assert _load_bounded_yaml("tools:\n  - search\n") == {"tools": ["search"]}
    assert isinstance(yaml_bomb, str)


def test_p1_3_cpsat_pow_and_binary_dos_budgets() -> None:
    from wythe_plugin_binary.elf_parser import _extract_rodata_strings
    from wythe_plugin_binary.macho_parser import _extract_printable_cstrings, parse_macho_bytes
    from wythe_plugin_cpsat.ast_extractor import _eval_numeric_expr

    for bad_expr in ("1e200 ** 2", "(2 ** 60) ** 16", "(-1) ** 0.5"):
        node = ast.parse(bad_expr, mode="eval").body
        val, trunc = _eval_numeric_expr(node, {})
        assert val is None and trunc is None

    # Lazy cstring/rodata scanning on large NUL-padded section stops at max_items in < 0.5s
    padded = (b"\x00" * (16 * 1024 * 1024)) + b"alpha\x00beta\x00gamma\x00"
    t0 = time.perf_counter()
    assert _extract_printable_cstrings(padded, max_items=2) == ["alpha", "beta"]
    assert _extract_rodata_strings(padded, max_items=2) == ["alpha", "beta"]
    assert time.perf_counter() - t0 < 0.5

    # Universal Mach-O overlapping slice amplification defense
    fat_header = struct.pack(">II", 0xCAFEBABE, 4)
    # 4 overlapping slices pointing to the same 64-byte dummy region (first fails overlap)
    arches = b"".join(struct.pack(">iiIII", 0x0100000C, 0, 128, 128, 3) for _ in range(4))
    buf = fat_header + arches + b"\x00" * 256
    with pytest.raises(ValueError, match="Overlapping|cumulative|Mach-O"):
        parse_macho_bytes(buf, source_name="overlap_fat")


def test_p1_4_trivy_sarif_secret_detection_and_redaction(tmp_path: Path) -> None:
    sarif = tmp_path / "trivy-secrets.sarif"
    ghp_pfx, akia_pfx = "ghp_", "AKIA"
    pat_val = f"{ghp_pfx}SYNTHETIC_PAT_SECRET_999"
    aws_val = f"{akia_pfx}IOSFODNN7EXAMPLE"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "custom-rule", "shortDescription": {"text": "Token leak"}}]}},
                        "results": [
                            {
                                "ruleId": "custom-rule",
                                "level": "error",
                                "properties": {"tags": ["secret", "CRITICAL"]},
                                "message": {"text": f"Exposed credential. Match: {pat_val}"},
                            },
                            {
                                "ruleId": "aws-access-key-id",
                                "level": "error",
                                "message": {"text": f"AWS Access Key ID Match: {aws_val}"},
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = _make_report(str(tmp_path))
    summary = summarize_companion_security_artifacts(report, trivy_path=sarif)
    tr = summary["crate_stage"]["trivy_report"]  # type: ignore[index]
    assert tr["format"] == "sarif"
    assert tr["secret_count"] == 2
    assert tr["misconfiguration_count"] == 0
    dumped = json.dumps(summary)
    assert pat_val not in dumped
    assert aws_val not in dumped


def test_p1_4_otel_ebpf_redaction_and_heap_memgraph(tmp_path: Path) -> None:
    from wythe_plugin_wiretap.heap_memgraph import parse_memgraph_artifact
    from wythe_plugin_wiretap.otel_ebpf import (
        parse_ebpf_flows,
        redact_attributes,
        redact_sql_statement,
    )

    cleaned, r_cnt = redact_attributes(
        {
            "db.connection_string": "postgresql://admin:DSN_SECRET_PASS@db.internal:5432/app?sslmode=require&token=DSN_Q_TOK",
            "url.query": "api_key=QUERY_SECRET&page=1",
            "http.referer": "https://u:REF_PASS@example.invalid/login?code=REF_SECRET",
            "http.location": "https://cb.example.invalid/done?state=LOC_SECRET",
            "os.user": "alice_os",
            "process.owner": "alice_proc",
            "db.user": "alice_db",
            "enduser.id": "usr_12345",
            "user.name": "Alice Sample",
            "exception.message": "DatabaseError: fail on SELECT password FROM users WHERE id = 'SQL_SECRET_VAL'",
            "nested.list": [["Bearer NESTED_SECRET_TOKEN"]],
            "headers": [{"key": "Authorization", "value": "Bearer HEADER_LIST_SECRET"}],
        }
    )
    assert r_cnt >= 12
    dumped = json.dumps(cleaned)
    for leaked in (
        "DSN_SECRET_PASS",
        "DSN_Q_TOK",
        "QUERY_SECRET",
        "REF_PASS",
        "REF_SECRET",
        "LOC_SECRET",
        "alice_os",
        "alice_proc",
        "alice_db",
        "usr_12345",
        "Alice Sample",
        "SQL_SECRET_VAL",
        "NESTED_SECRET_TOKEN",
        "HEADER_LIST_SECRET",
    ):
        assert leaked not in dumped

    sql_mysql, was_sql = redact_sql_statement(
        'SELECT * FROM users WHERE tok = "MYSQL_DQ_SECRET".y',
        db_system="mysql",
    )
    assert was_sql is True
    assert "MYSQL_DQ_SECRET" not in sql_mysql

    ebpf_file = tmp_path / "flows.jsonl"
    ebpf_file.write_text(
        json.dumps(
            {
                "type": "flow",
                "service_name": "api-gw",
                "l7": {
                    "type": "REQUEST",
                    "http": {
                        "method": "GET",
                        "url": "https://example.invalid/api?token=EBPF_URL_SECRET",
                        "headers": [{"key": "X-Api-Key", "value": "EBPF_HDR_SECRET"}],
                    },
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    flows, f_cnt = parse_ebpf_flows(ebpf_file)
    assert f_cnt >= 2
    assert len(flows) == 1
    ebpf_dump = json.dumps([flows[0].attributes, flows[0].redacted_summary])
    assert "EBPF_URL_SECRET" not in ebpf_dump
    assert "EBPF_HDR_SECRET" not in ebpf_dump

    long_buf = "LONGSECRET_" * 30  # > 256 chars
    mg = tmp_path / "heap.txt"
    mg.write_text(f'0x1000 (MyClass) "{long_buf}" -> 0x2000 (Other)\n', encoding="utf-8")
    mg_res = parse_memgraph_artifact(mg)
    assert mg_res["redacted_heap_buffers"] >= 1
    assert long_buf not in json.dumps(mg_res)


def test_p2_3_binary_der_keychain_utf16_xxe_and_ffi_precision(tmp_path: Path) -> None:
    from wythe_plugin_binary.entitlement_drift import (
        SourceEntitlementSpec,
        evaluate_entitlement_drift,
        match_source_entitlement_spec,
        validate_non_symlink_path,
    )
    from wythe_plugin_binary.macho_parser import (
        CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
        CSMAGIC_EMBEDDED_SIGNATURE,
        CSSLOT_DER_ENTITLEMENTS,
        parse_macho_bytes,
    )
    from wythe_plugin_binary.plugin import _symbol_matches_caller_tokens, inspect_binary_artifacts

    # 1. DER-only Mach-O entitlements -> unverified (never clean / no_entitlements)
    der_payload = b"\x30\x00"
    der_blob = struct.pack(">II", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 8 + len(der_payload)) + der_payload
    super_len = 12 + 8 + len(der_blob)
    sig_blob = (
        struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, super_len, 1)
        + struct.pack(">II", CSSLOT_DER_ENTITLEMENTS, 20)
        + der_blob
    )
    # Build minimal single-slice 64-bit Mach-O with LC_CODE_SIGNATURE
    lc_cs = struct.pack("<IIII", 0x1D, 16, 48, len(sig_blob))
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    macho_der = hdr + lc_cs + sig_blob
    cap_der = parse_macho_bytes(macho_der, source_name="DerApp")
    assert cap_der.slice_der_only_entitlements == {"arm64": True}
    drift_der = evaluate_entitlement_drift(
        artifact_name="DerApp",
        signed_entitlements=cap_der.entitlements,
        linux_capabilities=(),
        source_specs=[],
        slice_entitlements=cap_der.slice_entitlements,
        slice_has_entitlements_blob=cap_der.slice_has_entitlements_blob,
        slice_der_only_entitlements=cap_der.slice_der_only_entitlements,
    )
    assert drift_der.drift_status == "unverified"

    # 2. keychain-access-groups is NOT whitelisted
    drift_kc = evaluate_entitlement_drift(
        artifact_name="MainApp",
        signed_entitlements={"keychain-access-groups": ["$(AppIdentifierPrefix)com.example.kc"]},
        linux_capabilities=(),
        source_specs=[SourceEntitlementSpec("MainApp.entitlements", "MainApp", {})],
    )
    assert drift_kc.drift_status == "exceeded"

    # 3. Tight helper matching: MainApp.entitlements must NOT silently match MainAppHelper
    specs = [SourceEntitlementSpec("MainApp.entitlements", "MainApp", {"com.apple.security.app-sandbox": True})]
    assert match_source_entitlement_spec("MainApp.app", specs) is not None
    assert match_source_entitlement_spec("MainAppHelper", specs) is None

    # 4. UTF-16 BOM XXE detection inside rootfs dir
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    xxe_file = rootfs / "Info.plist"
    xxe_file.write_bytes('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><plist/>'.encode("utf-16"))
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="XXE|Mach-O|ELF|inspectable"):
        inspect_binary_artifacts(repo, [rootfs], allow_external=True)

    # 5. Short 4-char FFI substring precision & allow_external=False containment
    assert _symbol_matches_caller_tokens("cleanup_userspace", {"user"}) is False
    assert _symbol_matches_caller_tokens("audit_token_to_pid", {"audit_token_to_pid"}) is True
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"abc")
    with pytest.raises(ValueError, match="escapes repository root"):
        validate_non_symlink_path(outside, repo_root=repo)


def test_p2_3_wiretap_ports_post_scan_and_service_precision(tmp_path: Path) -> None:
    from wythe_plugin_wiretap.otel_ebpf import _service_matches_node
    from wythe_plugin_wiretap.plugin import WIRETAP_PLUGIN, wiretap_inspection_scope
    from wythe_plugin_wiretap.port_occupancy import (
        correlate_port_occupancy,
        extract_declared_ports,
        parse_port_listeners_text,
    )

    # LISTEN-only filtering for lsof and ss
    lsof_txt = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "uvicorn 100 u 6u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)\n"
        "uvicorn 100 u 7u IPv4 0x2 0t0 TCP 127.0.0.1:8080->127.0.0.1:51234 (ESTABLISHED)\n"
    )
    obs_lsof, _, _ = parse_port_listeners_text(lsof_txt)
    assert len(obs_lsof) == 1

    ss_txt = (
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("uvicorn",pid=100,fd=3))\n'
        'tcp ESTAB 0 0 127.0.0.1:8080 127.0.0.1:51234 users:(("uvicorn",pid=100,fd=4))\n'
    )
    obs_ss, _, _ = parse_port_listeners_text(ss_txt)
    assert len(obs_ss) == 1

    # Symlinks and >2 MiB files skipped gracefully in extract_declared_ports; dual-stack & routable IP drift
    repo = tmp_path / "port_repo"
    repo.mkdir()
    (repo / "compose.yaml").write_text(
        'services:\n  api:\n    ports:\n      - "127.0.0.1:8080:8080"\n  worker:\n    ports:\n      - "127.0.0.1:8081:8081"\n',
        encoding="utf-8",
    )
    (repo / "huge.yaml").write_bytes(b"#" * (2 * 1024 * 1024 + 64))
    (repo / "bad_link.yaml").symlink_to(tmp_path / "missing_target.yaml")
    decls = extract_declared_ports(repo)
    assert {d.port for d in decls} == {8080, 8081}

    cap_file = tmp_path / "listeners.txt"
    cap_file.write_text(
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "docker-proxy 11 u 6u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)\n"
        "docker-proxy 11 u 7u IPv6 0x2 0t0 TCP [::]:8080 (LISTEN)\n"
        "docker-proxy 12 u 8u IPv4 0x3 0t0 TCP 198.51.100.42:8081 (LISTEN)\n",
        encoding="utf-8",
    )
    occ = correlate_port_occupancy(repo, port_listeners_paths=[cap_file])
    by_p = {e["port"]: e["classification"] for e in occ["entries"]}
    assert by_p[8080] == "bind_exposure_drift"
    assert by_p[8081] == "bind_exposure_drift"

    # post_scan_hook emits PORT-002 findings into scan report when active, none when inactive
    rep = _make_report(str(repo))
    assert WIRETAP_PLUGIN.post_scan_hook is not None
    inactive_res = WIRETAP_PLUGIN.post_scan_hook(repo, rep)
    assert inactive_res["findings"] == []
    with wiretap_inspection_scope(port_listeners=[cap_file]):
        active_res = WIRETAP_PLUGIN.post_scan_hook(repo, rep)
    assert [f.rule_code for f in active_res["findings"]] == ["PORT-002", "PORT-002"]

    # 2-char service name rejection
    fake_node = AtlasNode(
        id="m:fn:audit",
        label="audit_token_handler",
        tier="manipulate",
        subkind="service",
        source_file="app/db_service.py",
        line=1,
        summary="Audit helper.",
    )
    assert _service_matches_node("db", fake_node) is False


def test_p2_3_compiler_ir_gate_stratum_scc_and_containment(tmp_path: Path) -> None:
    from wythe_plugin_compiler_ir.ir_parsers import CompilerIrBundle, IrCallEdge, IrFunctionNode
    from wythe_plugin_compiler_ir.plugin import upgrade_edges_with_compiler_ir
    from wythe_plugin_compiler_ir.usr_index import validate_safe_path
    from wythe_plugin_cpsat.proto_companion import parse_cp_model_proto
    from wythe_plugin_solver_internals.proto_descriptor import parse_proto_descriptor_artifact
    from wythe_plugin_wiretap.otel_ebpf import parse_otel_traces

    # Dynamic IR call must NOT promote Zoom-1 symbol_links
    n1 = AtlasNode(
        id="m:a",
        label="Caller",
        tier="manipulate",
        subkind="service",
        source_file="a.swift",
        line=1,
        summary="Caller.",
    )
    n2 = AtlasNode(
        id="m:b",
        label="Callee",
        tier="manipulate",
        subkind="service",
        source_file="b.swift",
        line=1,
        summary="Callee.",
    )
    edge = AtlasEdge(
        id="e:a->b",
        source_id="m:a",
        target_id="m:b",
        kind="calls_helper",
        verification="declared",
        evidence_note="call",
    )
    bundle = CompilerIrBundle(
        functions={
            "f1": IrFunctionNode(symbol="f1", label="caller", usr="s:f1", language="swift", ir_format="sil", source_file="a.swift"),
            "f2": IrFunctionNode(symbol="f2", label="callee", usr="s:f2", language="swift", ir_format="sil", source_file="b.swift"),
        },
        calls=[
            IrCallEdge(
                caller_symbol="f1",
                caller_label="caller",
                caller_usr="s:f1",
                callee_symbol="f2",
                callee_label="callee",
                callee_usr="s:f2",
                kind="indirect_call",
                ir_format="sil",
                source_file="a.swift",
                is_dynamic=True,
            )
        ],
    )
    assert upgrade_edges_with_compiler_ir([edge], [n1, n2], bundle) == 0
    assert edge.symbol_links == []

    # Stratum SCC rank propagation preserves intermediate boilerplate node verification rank
    src_n = StratumMicroNode(id="ir:A", label="entry", kind="sil_fn", zoom=2, verification="verified")
    boil_n = StratumMicroNode(
        id="ir:W",
        label="thunk for target",
        kind="thunk",
        zoom=2,
        verification="declared",
    )
    tgt_n = StratumMicroNode(id="ir:B", label="target", kind="sil_fn", zoom=2, verification="verified")
    e1 = StratumMicroEdge(id="e:1", source_id="ir:A", target_id="ir:W", kind="calls_ir", verification="verified")
    e2 = StratumMicroEdge(id="e:2", source_id="ir:W", target_id="ir:B", kind="calls_ir", verification="verified")
    _c_nodes, c_edges, _collapsed, _cnt, _ = compact_stratum_subgraph(
        "m:svc:entry",
        [src_n, boil_n, tgt_n],
        [e1, e2],
    )
    bridged = next(ed for ed in c_edges if ed.id == "s:bridged:ir:A->ir:B:calls_ir")
    assert bridged.verification == "declared"

    # Cross-plugin allow_external=False default enforcement
    repo = tmp_path / "repo"
    repo.mkdir()
    ext = tmp_path / "ext.json"
    ext.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="escapes repository root"):
        validate_safe_path(ext, repo_root=repo)
    with pytest.raises(ValueError, match="escapes repository root"):
        parse_otel_traces(ext, repo_root=repo)
    with pytest.raises(ValueError, match="escapes repository root"):
        parse_cp_model_proto(ext, repo_root=repo)
    with pytest.raises(ValueError, match="escapes repository root"):
        parse_proto_descriptor_artifact(ext, repo_root=repo)


def test_p2_6_crashes_openlineage_tarjan_jsonl_utf8_and_chronicle(tmp_path: Path) -> None:
    from wythe_plugin_cpsat.proto_companion import parse_cp_model_proto
    from wythe_plugin_solver_chronicle.synthesizer import _clean_plain
    from wythe_plugin_solver_internals.proto_descriptor import SolverProtoCatalog
    from wythe_plugin_solver_internals.singleton_graph import (
        SingletonDependencyEdge,
        _find_constructor_cycles,
    )
    from wythe_plugin_solver_internals.stage_matrix import (
        build_constraint_stage_matrix,
        load_cpp_usr_index,
    )

    # 1. Trivy Results: null
    null_trivy = tmp_path / "null-trivy.json"
    null_trivy.write_text('{"SchemaVersion": 2, "Results": null}', encoding="utf-8")
    rep = _make_report(
        "/Users/private_home/workspace/demo-app",
        nodes=[
            AtlasNode(
                id="t:orders",
                label="orders",
                tier="truth",
                subkind="table",
                source_file="schema.sql",
                line=5,
                summary="Orders table.",
                columns=["id:uuid"],
            )
        ],
    )
    summary = summarize_companion_security_artifacts(rep, trivy_path=null_trivy)
    assert summary["crate_stage"]["trivy_report"]["format"] == "trivy-json"  # type: ignore[index]

    # 2. OpenLineage dataset vs job facets + local /Users/... redaction
    ol = build_openlineage_static_bundle(rep)
    ds = ol["datasets"][0]  # type: ignore[index]
    loc_facet = ds["facets"]["sourceCodeLocation"]
    assert "SourceCodeLocationJobFacet" not in loc_facet["_schemaURL"]
    assert "/Users/" not in json.dumps(ol)

    # 3. Iterative Tarjan on 1500-node constructor chain
    deps = tuple(
        SingletonDependencyEdge(
            caller_symbol=f"S{i}::S{i}",
            caller_type=f"S{i}",
            target_type=f"S{(i + 1) % 1500}",
            accessor="GetOrCreate",
            is_constructor_dep=True,
            source_file="s.cc",
            line=i + 1,
            symbol_links=(f"S{i}->S{(i + 1) % 1500}",),
        )
        for i in range(1500)
    )
    cycles = _find_constructor_cycles(deps)
    assert len(cycles) == 1 and len(cycles[0].chain) == 1501

    # 4. Multi-line JSONL + non-UTF-8 C++ source
    ml_jsonl = tmp_path / "multi.jsonl"
    ml_jsonl.write_text(
        json.dumps({"usr": "c:@F@foo", "name": "foo", "kind": "function", "file": "a.cc", "line": 3}, indent=2)
        + "\n"
        + json.dumps({"usr": "c:@F@bar", "name": "bar", "kind": "function", "file": "a.cc", "line": 7}, indent=2),
        encoding="utf-8",
    )
    cpp_idx = load_cpp_usr_index([ml_jsonl])
    assert "c:@F@foo" in cpp_idx.symbols_by_usr
    assert "c:@F@bar" in cpp_idx.symbols_by_usr

    cpp_repo = tmp_path / "cpp_repo"
    cpp_repo.mkdir()
    (cpp_repo / "propagator.cc").write_bytes(b"// latin1 comment: \xff\xfe\nvoid Propagate() {}\n")
    mat = build_constraint_stage_matrix(cpp_repo, SolverProtoCatalog())
    assert "propagator.cc" in mat.stage_files.get("PropagatorInterface", ())

    # 5. \8 / \9 pbtxt escape + chronicle _clean_plain compatibility
    pb_file = tmp_path / "esc.pbtxt"
    pb_file.write_text('name: "val\\8\\9end"\nvariables: { name: "x" domain: [0, 1] }\n', encoding="utf-8")
    pb = parse_cp_model_proto(pb_file, repo_root=tmp_path)
    assert pb.name == "val89end"
    assert "alert" in _clean_plain("Symmetry: <sc<b>ript>alert(1)</script>", 390)
