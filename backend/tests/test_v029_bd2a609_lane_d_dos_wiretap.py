"""Lane D regression suite for post-bd2a609 P0-3, P0-5, P1-6 (3/4/5), and P1-7 fixes."""

from __future__ import annotations

import ast
import json
import struct
import time
from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult
from app.adapters.compose_sources import (
    MAX_TOTAL_COMPOSE_ENV_ENTRIES,
    augment_compose_sources,
    parse_compose_file,
)
from app.adapters.container_launchers import augment_container_launchers, parse_launchd_plist
from app.adapters.dockerfile_sources import (
    MAX_ENV_VALUE_LEN,
    _collect_top_level_callables,
    parse_dockerfile,
    parse_dockerignore,
)
from app.adapters.k8s_sources import (
    MAX_TOTAL_K8S_ENV_ENTRIES,
    augment_k8s_sources,
    parse_k8s_manifests,
)
from app.adapters.launchd_sources import add_launchd_sources, parse_safe_plist_bytes
from app.adapters.registry_sources import add_registry_sources
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.tach_bridge import (
    _compile_cached_nfa,
    _extract_top_level_callables,
    _pattern_matches,
    augment_tach_boundaries,
)
from app.schemas.atlas import AtlasNode
from wythe_plugin_agent_harness.plugin import AgentHarnessPlugin
from wythe_plugin_agent_harness.python_inspector import (
    MAX_SCHEMA_JSON_BYTES,
    estimate_schema_budget,
    inspect_python_module_ast,
)
from wythe_plugin_compiler_ir.usr_index import MAX_TOTAL_USR_RELATIONS, parse_usr_index_text
from wythe_plugin_cpsat.ast_extractor import MAX_OBJECTIVE_TERMS, extract_repo_cpsat_models
from wythe_plugin_wiretap.otel_ebpf import (
    parse_ebpf_flows,
    parse_otel_traces,
    redact_attributes,
    redact_url_target,
)
from wythe_plugin_wiretap.port_occupancy import MAX_TOTAL_PORT_ENTRIES, extract_declared_ports


def _write(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def _build_bplist_with_0x1f_int(fill_byte: int = 0xFF) -> bytes:
    """Construct a valid bplist00 dictionary `{'Program': '/bin/sh', 'Big': <32768B int>}`."""
    header = b"bplist00"
    dict_obj = bytes([0xD2, 1, 2, 3, 4])
    k1 = b"\x57Program"
    k2 = b"\x53Big"
    v1 = b"\x57/bin/sh"
    int_bytes = (bytes([0x00]) * 32767 + bytes([0x01])) if fill_byte == 0 else (bytes([fill_byte]) * 32768)
    v2 = b"\x1f" + int_bytes
    objects = [dict_obj, k1, k2, v1, v2]
    offsets: list[int] = []
    cur = len(header)
    body_parts: list[bytes] = []
    for obj in objects:
        offsets.append(cur)
        body_parts.append(obj)
        cur += len(obj)
    offset_table = b"".join(struct.pack(">I", off) for off in offsets)
    trailer = struct.pack(">6xBBQQQ", 4, 1, len(objects), 0, cur)
    return header + b"".join(body_parts) + offset_table + trailer


def test_p0_3_dockerfile_env_arg_billion_laughs_capped_fast(tmp_path: Path) -> None:
    lines = ["ARG B=seed", *(f"ARG B={'$B' * 10}" for _ in range(10)), "FROM alpine:3.20", "ENV A=x"]
    lines.extend(f"ENV A={'$A' * 10}" for _ in range(10))
    lines.append('CMD ["sh", "-c", "echo ok"]')
    df_path = _write(tmp_path, "Dockerfile", "\n".join(lines) + "\n")

    t0 = time.perf_counter()
    parsed = parse_dockerfile(df_path, tmp_path)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert parsed is not None
    assert elapsed_ms < 25.0
    stage = parsed.stages[0]
    assert len(stage.env["A"]) == MAX_ENV_VALUE_LEN
    assert len(stage.env["B"]) == MAX_ENV_VALUE_LEN


def test_p0_3_yaml_alias_dags_k8s_compose_usr_and_ports(tmp_path: Path) -> None:
    n = 1000
    # 1. Kubernetes cubic alias DAG (~3038 YAML nodes+aliases <= 4096 -> 10^9 env expansion)
    k8s_lines = [
        'x-e1: &e1 {name: "K", value: "1"}',
        "x-env: &e",
        *("  - *e1" for _ in range(n)),
        'x-c1: &c1 {name: "c", image: "alpine", env: *e}',
        "x-conts: &c",
        *("  - *c1" for _ in range(n)),
        'x-p1: &p1 {apiVersion: v1, kind: Pod, metadata: {name: "p"}, spec: {containers: *c}}',
        "apiVersion: v1",
        "kind: List",
        "items:",
        *("  - *p1" for _ in range(n)),
    ]
    k8s_repo = tmp_path / "k8s_dag"
    k8s_file = _write(k8s_repo, "k8s/dag.yaml", "\n".join(k8s_lines) + "\n")
    t0 = time.perf_counter()
    pk = parse_k8s_manifests(k8s_file, k8s_repo, in_k8s_dir=True)
    k8s_ms = (time.perf_counter() - t0) * 1000.0
    assert k8s_ms < 100.0
    assert pk.parse_error is not None and "Truncated" in pk.parse_error
    total_k8s_env = sum(len(c.env) for r in pk.resources for c in r.containers)
    assert 0 < total_k8s_env <= MAX_TOTAL_K8S_ENV_ENTRIES
    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_k8s_sources(k8s_repo, ".", k8s_res)
    assert k8s_res.coverage_complete is False

    # 2. Compose quadratic alias DAG (~3014 YAML nodes+aliases <= 4096 -> 10^6 env expansion)
    comp_lines = [
        'x-e1: &e1 "E=v"',
        "x-env: &ce",
        *("  - *e1" for _ in range(n)),
        'x-svc: &cs {image: "alpine", environment: *ce}',
        "services:",
        *(f"  s{i}: *cs" for i in range(n)),
    ]
    comp_repo = tmp_path / "comp_dag"
    comp_file = _write(comp_repo, "compose.yaml", "\n".join(comp_lines) + "\n")
    t1 = time.perf_counter()
    pc, comp_err = parse_compose_file(comp_file, comp_repo)
    comp_ms = (time.perf_counter() - t1) * 1000.0
    assert comp_ms < 100.0
    assert pc is not None and comp_err is not None and "Truncated" in comp_err
    assert 0 < sum(len(s.environment) for s in pc.services) <= MAX_TOTAL_COMPOSE_ENV_ENTRIES
    comp_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_compose_sources(comp_repo, ".", comp_res)
    assert comp_res.coverage_complete is False

    # 3. USR index cubic alias DAG (~3027 YAML nodes+aliases <= 4096 -> 10^9 relations)
    usr_lines = [
        'x-r1: &r1 {usr: "c:@F@fn", roles: ["calledBy"]}',
        "x-rels: &r",
        *("  - *r1" for _ in range(n)),
        'x-o1: &o1 {usr: "c:@F@cal", roles: ["call"], file: "a.c", relations: *r}',
        "x-occs: &o",
        *("  - *o1" for _ in range(n)),
        "x-u1: &u1 {occurrences: *o}",
        "units:",
        *("  - *u1" for _ in range(n)),
    ]
    usr_yaml = "\n".join(usr_lines) + "\n"
    t2 = time.perf_counter()
    ub = parse_usr_index_text(usr_yaml, format_hint="idx.yaml")
    usr_ms = (time.perf_counter() - t2) * 1000.0
    assert usr_ms < 100.0
    assert ub.truncated is True
    assert 0 < sum(len(o.relations) for o in ub.occurrences) <= MAX_TOTAL_USR_RELATIONS

    # 4. Port occupancy quadratic alias DAG (~3012 YAML nodes+aliases <= 4096 -> 10^6 ports)
    port_lines = [
        'x-p1: &p1 "127.0.0.1:8080:80"',
        "x-ports: &p",
        *("  - *p1" for _ in range(n)),
        "x-svc: &ps {ports: *p}",
        "services:",
        *(f"  svc{i}: *ps" for i in range(n)),
    ]
    port_repo = tmp_path / "port_dag"
    _write(port_repo, "compose.yaml", "\n".join(port_lines) + "\n")
    t3 = time.perf_counter()
    decls = extract_declared_ports(port_repo)
    port_ms = (time.perf_counter() - t3) * 1000.0
    assert port_ms < 100.0
    assert 0 < len(decls) <= MAX_TOTAL_PORT_ENTRIES


def test_p0_3_cpsat_objective_dag_agent_harness_and_p1_7_coverage(tmp_path: Path) -> None:
    # 1. CP-SAT N=28 exponential objective DAG finishes in < 25 ms
    cp_lines = [
        "from ortools.sat.python import cp_model",
        "def solve_dag():",
        "    m = cp_model.CpModel()",
        "    x = m.NewIntVar(0, 1, 'x')",
        "    a0 = [x]",
    ]
    cp_lines.extend(f"    a{i} = [a{i - 1}, a{i - 1}]" for i in range(1, 29))
    cp_lines.extend(["    b0 = []", "    b0 += [x]", "    b0 += [x]"])
    for i in range(1, 29):
        cp_lines.extend([f"    b{i} = []", f"    b{i} += [b{i - 1}]", f"    b{i} += [b{i - 1}]"])
    cp_lines.extend(["    m.Minimize(sum(a28) + sum(b28))", "    return m"])
    cp_repo = tmp_path / "cpsat_dag"
    _write(cp_repo, "dag_solver.py", "\n".join(cp_lines) + "\n")
    t0 = time.perf_counter()
    cp_ext = extract_repo_cpsat_models(cp_repo)
    assert (time.perf_counter() - t0) * 1000.0 < 50.0
    obj_terms = cp_ext.modules["dag_solver.py"].objectives[0].terms
    assert len(obj_terms) <= MAX_OBJECTIVE_TERMS

    # 2. Agent-harness 600-var chain & N=28 diamond (both static and volatile) in < 25 ms
    ah_lines = ["import datetime", "import openai", "v0 = datetime.datetime.now()"]
    ah_lines.extend(f'v{i} = f"{{v{i - 1}}}"' for i in range(1, 601))
    ah_lines.append('d0 = "frozen_prefix"')
    ah_lines.extend(f'd{i} = f"{{d{i - 1}}}{{d{i - 1}}}"' for i in range(1, 29))
    ah_lines.append("dv0 = datetime.datetime.now()")
    ah_lines.extend(f'dv{i} = f"{{dv{i - 1}}}{{dv{i - 1}}}"' for i in range(1, 29))
    ah_lines.extend(
        [
            "def build_prompts():",
            '    m1 = [{"role": "system", "content": f"Sys {v600}"}, {"role": "user", "content": "hi"}]',
            '    m2 = [{"role": "system", "content": f"Sys {d28}"}, {"role": "user", "content": "hi"}]',
            '    m3 = [{"role": "system", "content": f"Sys {dv28}"}, {"role": "user", "content": "hi"}]',
            "    return m1, m2, m3",
        ]
    )
    ah_src = "\n".join(ah_lines) + "\n"
    t1 = time.perf_counter()
    ah_bundle = inspect_python_module_ast("prompts.py", ah_src)
    assert (time.perf_counter() - t1) * 1000.0 < 50.0
    by_line = {p.line: p for p in ah_bundle.prompts}
    prompts_sorted = [by_line[k] for k in sorted(by_line)]
    assert len(prompts_sorted) == 3
    assert prompts_sorted[1].is_volatile is False
    assert prompts_sorted[2].is_volatile is True

    # 3. ListComp ASCII-escaped schema byte cap without multi-MB json.dumps allocation
    ctrl = "\x01" * 100_000
    huge_schema = [{"name": "t", "description": [ctrl for _ in range(250)]} for _ in range(14)]
    t2 = time.perf_counter()
    b_len, approx_toks = estimate_schema_budget(huge_schema)
    assert (time.perf_counter() - t2) * 1000.0 < 25.0
    assert MAX_SCHEMA_JSON_BYTES < b_len <= MAX_SCHEMA_JSON_BYTES * 4
    assert approx_toks > 1000

    # 4. P1-7: Python/TS parse errors before reconciliation mark coverage_complete=False
    bad_repo = tmp_path / "bad_ah"
    _write(bad_repo, "app/broken.py", "def broken(:\n    pass\n")
    ah_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    AgentHarnessPlugin().augment_manipulator(bad_repo, ".", ah_res)
    assert ah_res.coverage_complete is False


def test_p0_3_bplist_0x1f_oversized_int_rejected_cleanly(tmp_path: Path) -> None:
    for fill in (0xFF, 0x00):
        raw_bp = _build_bplist_with_0x1f_int(fill_byte=fill)
        with pytest.raises(ValueError, match="16-byte|128-bit"):
            parse_safe_plist_bytes(raw_bp)
        repo = tmp_path / f"bp_{fill}"
        plist_file = repo / "LaunchAgents" / "com.example.huge.plist"
        plist_file.parent.mkdir(parents=True, exist_ok=True)
        plist_file.write_bytes(raw_bp)
        unit, err = parse_launchd_plist(plist_file, repo)
        assert unit is None and err is not None
        res_ld = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        add_launchd_sources(repo, res_ld)
        assert res_ld.coverage_complete is False
        res_cl = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        augment_container_launchers(repo, ".", res_cl)
        assert res_cl.coverage_complete is False


def test_p0_5_otel_ebpf_six_bypasses_and_linear_sql_cursor(tmp_path: Path) -> None:
    # 1-4. JDBC/compound DSNs, ?b64=/?tok==/; queries/schemeless userinfo, extra-key KV, & SQL gaps
    attrs_in = {
        "db.connection_string": "jdbc:postgresql://admin:SEC_JDBC_1@db.internal:5432/prod?sslmode=require",
        "connection_string": "Server=db.internal;Password=SEC_SEMI_2;Pwd=SEC_PWD_3;Uri=https://u:SEC_URI_4@x.invalid/p?a=1",
        "mssql.connection_string": "jdbc:sqlserver://db.internal:1433;databaseName=prod;user=sa;password=SEC_MSSQL_5?encrypt=true",
        "ora.dsn": "jdbc:oracle:thin:admin/SEC_ORA_6@db.internal:1521:xe",
        "url.full": "https://api.example.invalid/hook?c3VwZXJzZWNyZXQ=",
        "http.url": "https://api.example.invalid/hook?tok==;api_key=SEC_QSEMI_7",
        "http.target": "admin:SEC_USERINFO_8@api.example.invalid:8443/v1/hook?k=SEC_Q_9",
        "url.query": "c3VwZXJzZWNyZXQ=",
        "kv_extra": {"key": "x-api-key", "value": "sk_live_SEC_KV_10", "sensitive": True, "index": 0},
        "kv_short": {"k": "Authorization", "v": "Bearer SEC_KV_11", "meta": {"secret": "SEC_KV_12"}},
        "sql_call": 'db: CALL "auth"."login"(\'SEC_SQL_CALL_13\')',
        "sql_exec": "db: EXEC [dbo].[sp] N'SEC_SQL_EXEC_14'",
        "sql_set": "err: SET app.api_key = 'SEC_SQL_SET_15'",
        "sql_fn": "err: SELECT pgp_sym_encrypt('SEC_SQL_FN_16', 'SEC_SQL_KEY_17')",
        "sql_do": "err: DO $$ BEGIN PERFORM auth('SEC_SQL_DO_18'); END $$",
        "prose": "Please call support at 555-1234",
    }
    cleaned, cnt = redact_attributes(attrs_in)
    assert cnt >= 15
    dumped = json.dumps(cleaned)
    for tok in (
        "SEC_JDBC_1", "SEC_SEMI_2", "SEC_PWD_3", "SEC_URI_4", "SEC_MSSQL_5", "SEC_ORA_6",
        "c3VwZXJzZWNyZXQ", "tok=", "SEC_QSEMI_7", "SEC_USERINFO_8", "SEC_Q_9",
        "SEC_KV_10", "SEC_KV_11", "SEC_KV_12", "SEC_SQL_CALL_13", "SEC_SQL_EXEC_14",
        "SEC_SQL_SET_15", "SEC_SQL_FN_16", "SEC_SQL_KEY_17", "SEC_SQL_DO_18",
    ):
        assert tok not in dumped
    assert cleaned["prose"] == "Please call support at 555-1234"
    assert redact_url_target("https://api.example.invalid/hook?c3VwZXJzZWNyZXQ=")[1].endswith("?[REDACTED]")

    # Linear cursor timing on "SELECT / " * 5000 (with and without trailing FROM)
    t_sql = time.perf_counter()
    redact_attributes({"msg1": "SELECT / " * 5000, "msg2": ("SELECT / " * 5000) + "FROM users"})
    assert (time.perf_counter() - t_sql) * 1000.0 < 40.0

    # 5. OTel HTTP span.name URL redaction (both flat spans and OTLP resourceSpans)
    otel_p = _write(
        tmp_path,
        "http_span.json",
        json.dumps(
            {
                "spans": [
                    {"name": "GET /api/users?api_key=TOP_SECRET_SPAN_1", "service.name": "web"},
                    {"name": "POST https://u:TOP_SECRET_SPAN_2@api.invalid/v1?c3VwZXJzZWNyZXQ=", "service.name": "web"},
                ]
            }
        ),
    )
    otlp_p = _write(
        tmp_path,
        "otlp_span.json",
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "web"}}]},
                        "scopeSpans": [
                            {
                                "spans": [
                                    {"name": "GET /api/users?api_key=TOP_SECRET_OTLP_3", "attributes": []},
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
    )
    otel_trs, otel_c = parse_otel_traces(otel_p, repo_root=tmp_path)
    otlp_trs, otlp_c = parse_otel_traces(otlp_p, repo_root=tmp_path)
    assert len(otel_trs) == 2 and otel_c >= 2
    assert len(otlp_trs) == 1 and otlp_c >= 1
    otel_dump = json.dumps([t.__dict__ for t in [*otel_trs, *otlp_trs]])
    for s_tok in ("TOP_SECRET_SPAN_1", "TOP_SECRET_SPAN_2", "TOP_SECRET_OTLP_3", "c3VwZXJzZWNyZXQ"):
        assert s_tok not in otel_dump

    # 6. eBPF l7.http.headers dict-form and Cilium Hubble list-form redaction
    ebpf_p = _write(
        tmp_path,
        "hubble.jsonl",
        "\n".join(
            [
                json.dumps({"l7": {"http": {"method": "GET", "url": "/a", "headers": {"X-Session-Id": "SESS_DICT_SEC", "Content-Type": "application/json"}}}}),
                json.dumps({"l7": {"http": {"method": "GET", "url": "/b", "headers": [{"key": "X-Session-Id", "value": "SESS_LIST_SEC", "sensitive": True}, {"key": "Content-Type", "value": "application/json"}]}}}),
            ]
        ) + "\n",
    )
    ebpf_trs, ebpf_c = parse_ebpf_flows(ebpf_p, repo_root=tmp_path)
    assert len(ebpf_trs) == 2 and ebpf_c >= 2
    ebpf_dump = json.dumps([t.attributes for t in ebpf_trs])
    assert "SESS_DICT_SEC" not in ebpf_dump and "SESS_LIST_SEC" not in ebpf_dump
    assert "application/json" in ebpf_dump


def test_p1_6_elif_recursion_dockerignore_tach_cache_and_usr_loc_guards(tmp_path: Path) -> None:
    # 1. 1200 elif branches across tach_bridge, registry_sources, & dockerfile_sources
    elif_lines = [
        "import yaml",
        "from pathlib import Path",
        "def load_cfg(x):",
        "    cfg = yaml.safe_load(Path('config/app.yaml').read_text())",
        "    if x == 0:",
        "        return cfg['timeout_seconds']",
    ]
    for i in range(1, 1201):
        elif_lines.extend([f"    elif x == {i}:", "        pass"])
    elif_lines.extend(["    return cfg['timeout_seconds']", "if x0 := 0:", "    def f0(): return 0"])
    for i in range(1, 1201):
        elif_lines.extend([f"elif x == {i}:", f"    def f{i}(): return {i}"])
    elif_src = "\n".join(elif_lines) + "\n"
    tree = ast.parse(elif_src)
    assert "f1200" in _extract_top_level_callables(tree.body)
    assert "f1200" in _collect_top_level_callables(tree.body)

    elif_repo = tmp_path / "elif_repo"
    _write(elif_repo, "config/app.yaml", "policies:\n  timeout_seconds: 10\n")
    _write(elif_repo, "tach.toml", 'source_roots = ["."]\n[[modules]]\npath = "mod"\ndepends_on = []\n')
    _write(elif_repo, "mod.py", elif_src)
    truth = SqlDdlTruthAdapter().extract(elif_repo, ".")
    manip = ManipulatorExtractionResult(
        nodes=[
            AtlasNode(
                id="m:script:mod.py",
                tier="manipulate",
                subkind="service",
                label="mod.py",
                source_file="mod.py",
                summary="mod",
            )
        ],
        edges=[],
        routes=[],
    )
    add_registry_sources(elif_repo, manip, {}, truth=truth, trees={"mod.py": tree})
    augment_tach_boundaries(elif_repo, ".", manip)
    assert manip.coverage_complete is True
    assert any(e.kind == "reads_truth" for e in manip.edges)

    # 2. .dockerignore 1000 rules vs 16-segment path < 25 ms + tach NFA lru_cache
    di_repo = tmp_path / "di_perf"
    _write(di_repo, ".dockerignore", "\n".join(f"**/*nomatch_{i}*/*.tmp" for i in range(1000)) + "\n")
    spec = parse_dockerignore(di_repo, None, di_repo)
    deep_16 = "/".join(f"seg{i}" for i in range(16))
    t0 = time.perf_counter()
    assert spec.is_excluded(deep_16) is False
    assert (time.perf_counter() - t0) * 1000.0 < 25.0

    _compile_cached_nfa.cache_clear()
    for _ in range(50):
        assert _pattern_matches(r"^pkg_[a-z]+\.v[0-9]+$", "pkg_alpha.v2") is True
    assert _compile_cached_nfa.cache_info().hits >= 49

    # 3. compiler-ir usr_index non-dict position/location/symbol guards
    bad_usr = json.dumps([
        {"usr": "c:@F@main", "name": "main", "kind": "function", "location": {"path": "main.c", "position": "bad"}},
        {"usr": "c:@F@sub", "roles": ["call"], "location": "bad", "relations": [{"symbol": "bad", "roles": ["calledBy"]}]},
    ])
    ub = parse_usr_index_text(bad_usr, format_hint="bad.json")
    assert "c:@F@main" in ub.symbols_by_usr and len(ub.occurrences) == 1
