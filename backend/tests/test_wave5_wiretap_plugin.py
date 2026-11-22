"""Wave 5 (#79) tests: `wythe-plugin-wiretap` OTLP/eBPF, `.memgraph`/`vmmap`, & `PORT-001..002`."""

from __future__ import annotations

import json
import os
import sysconfig
import time
import tomllib
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    discover_plugins,
    run_plugin_companion_handlers,
    stratum_artifacts_scope,
)
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import register_target
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    attach_zoom1_stratum_badges,
    build_node_stratum_drilldown,
)
from wythe_examples.truth_in_python_lab import materialize_truth_in_python_fixture
from wythe_plugin_wiretap import (
    MAX_NESTING_DEPTH,
    MAX_WIRETAP_BYTES,
    WIRETAP_PLUGIN,
    correlate_port_occupancy,
    correlate_wiretap_companions,
    ensure_json_depth_bounded,
    extract_declared_ports,
    parse_memgraph_artifact,
    parse_otel_traces,
    parse_safe_plist_xml,
    parse_vmmap_artifact,
    redact_sql_statement,
    redact_url_target,
    wiretap_inspection_scope,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = REPO_ROOT / "plugins" / "wythe-plugin-wiretap"


class _FakeDist:
    def __init__(self, version: str = "0.1.0", name: str = "wythe_plugin_wiretap") -> None:
        self.version = version
        self._path = Path(sysconfig.get_path("purelib")) / f"{name}-{version}.dist-info"

    def locate_file(self, path: str | Path) -> Path:
        return self._path / path


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, obj: object) -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist("0.1.0")
        self._obj = obj

    def load(self) -> object:
        return self._obj


def test_wiretap_pyproject_and_entry_point_registration(monkeypatch) -> None:
    """Verify `pyproject.toml` metadata, `Euda1mon1a` author, 0 deps, and `wythe.plugins` load."""
    pyproject = tomllib.loads((PLUGIN_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    proj = pyproject["project"]
    assert proj["name"] == "wythe-plugin-wiretap"
    assert proj["authors"] == [{"name": "Euda1mon1a"}]
    assert proj["dependencies"] == []
    assert proj["entry-points"]["wythe.plugins"]["wiretap"] == (
        "wythe_plugin_wiretap.plugin:WIRETAP_PLUGIN"
    )

    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda **_kw: [
            _FakeEntryPoint("wiretap", "wythe_plugin_wiretap.plugin:WIRETAP_PLUGIN", WIRETAP_PLUGIN)
        ],
    )
    specs = discover_plugins(include_builtins=False, include_entry_points=True, strict_plugins=True)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.name == "wiretap"
    assert spec.kind == "stratum_inspector"
    assert spec.supported_zooms == (3,)
    assert [r.rule_code for r in spec.rules] == ["PORT-001", "PORT-002"]
    assert "wiretap" in spec.companion_handlers


def test_otel_ebpf_three_way_partition_redaction_and_zoom1_digest_invariance(
    tmp_path: Path, db_session: Session
) -> None:
    """Verify corroborated edges, dark matter, `runtime_only`, redaction, & digest invariance."""
    repo_dir = materialize_truth_in_python_fixture(tmp_path / "target_repo", init_git=True)
    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="wiretap-target",
            name="Wiretap Target",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    baseline_report = run_target_scan(db_session, target, persist_snapshot=False, strict_gate=True)
    baseline_digest = baseline_report.content_digest
    baseline_verdict = baseline_report.gate.verdict
    baseline_verifs = {e.id: e.verification for e in baseline_report.edges}

    probe_sql_val = "probe_sql_literal_987654321"
    secret_sql_val = "tenant_alpha_confidential"
    otel_file = tmp_path / "otel_traces.json"
    otel_file.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "quota-api"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                        "spanId": "00f067aa0ba902b7",
                                        "name": "GET /api/quotas/validate",
                                        "attributes": [
                                            {"key": "http.request.method", "value": {"stringValue": "GET"}},
                                            {
                                                "key": "url.full",
                                                "value": {
                                                    "stringValue": f"http://127.0.0.1:8780/api/quotas/validate?api_key={probe_sql_val}&units=12"
                                                },
                                            },
                                            {
                                                "key": "http.request.header.authorization",
                                                "value": {"stringValue": f"Bearer {probe_sql_val}"},
                                            },
                                            {
                                                "key": "http.request.body",
                                                "value": {"stringValue": "raw_sensitive_payload"},
                                            },
                                        ],
                                    },
                                    {
                                        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                        "spanId": "b7ad6b7169203331",
                                        "parentSpanId": "00f067aa0ba902b7",
                                        "name": "SELECT batch_quota_policies",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {"key": "db.operation", "value": {"stringValue": "SELECT"}},
                                            {"key": "db.sql.table", "value": {"stringValue": "batch_quota_policies"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": f"SELECT id, max_batch_quota FROM batch_quota_policies WHERE name = '{secret_sql_val}' AND id = 42"
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "Dynamic reflective call",
                                        "attributes": [
                                            {"key": "rpc.system", "value": {"stringValue": "grpc"}},
                                            {"key": "rpc.service", "value": {"stringValue": "compute.Metering"}},
                                            {"key": "rpc.method", "value": {"stringValue": "ReportBatchUsage"}},
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    ebpf_file = tmp_path / "ebpf_flows.jsonl"
    ebpf_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "process": "case1_consumed_enforcer",
                        "l7": {
                            "sql": {
                                "sql": "INSERT INTO quota_dispatch_ledger (policy_id, applied_quota) VALUES (1, 32)",
                            }
                        },
                        "headers": {"Cookie": f"sid={probe_sql_val}"},
                    }
                ),
                json.dumps(
                    {
                        "process": "dynamic_worker",
                        "l7": {
                            "http": {
                                "method": "POST",
                                "url": f"/internal/reflective-hook?secret={probe_sql_val}",
                            }
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with stratum_artifacts_scope(otel_traces=str(otel_file), ebpf_flows=str(ebpf_file)):
        scoped_report = run_target_scan(
            db_session,
            target,
            persist_snapshot=False,
            strict_gate=True,
            extra_plugins=[WIRETAP_PLUGIN],
        ) if "extra_plugins" in run_target_scan.__code__.co_varnames else run_target_scan(
            db_session, target, persist_snapshot=False, strict_gate=True
        )
        attach_zoom1_stratum_badges(repo_dir, scoped_report, plugins=[WIRETAP_PLUGIN])

    assert scoped_report.content_digest == baseline_digest
    assert scoped_report.gate.verdict == baseline_verdict
    assert {e.id: e.verification for e in scoped_report.edges} == baseline_verifs
    assert any(
        b.key == "wiretap_runtime_hits"
        for n in scoped_report.nodes
        for b in n.stratum_badges
    )

    comp_map = run_plugin_companion_handlers(
        repo_dir,
        scoped_report,
        plugins=[WIRETAP_PLUGIN],
        handler_key="wiretap",
        otel_traces_path=str(otel_file),
        ebpf_flows_path=str(ebpf_file),
    )
    comp = comp_map["wiretap"]
    assert comp["present"] is True
    assert comp["target_code_executed"] is False
    assert comp["automated_security_audit"] is False
    assert comp["subprocesses_invoked"] == 0
    assert comp["redacted_field_count"] >= 4

    tf = comp["traces_and_flows"]
    assert tf["corroborated_edge_count"] >= 3
    assert tf["static_dark_matter_edge_count"] >= 1
    assert tf["runtime_only_count"] == 2
    assert all(e["dead_code_proof"] is False for e in tf["static_dark_matter"]["edges"])
    assert all(e["epistemic_status"] == "unexercised_in_sample" for e in tf["static_dark_matter"]["edges"])
    assert {r["overlay_kind"] for r in tf["runtime_only"]} == {"runtime_only"}

    serialized = json.dumps(comp)
    assert probe_sql_val not in serialized
    assert secret_sql_val not in serialized
    assert "raw_sensitive_payload" not in serialized

    # Negative control: empty capture
    empty_ebpf = tmp_path / "empty.jsonl"
    empty_ebpf.write_text("", encoding="utf-8")
    empty_comp = correlate_wiretap_companions(
        repo_dir, baseline_report, ebpf_flows_path=str(empty_ebpf)
    )
    assert empty_comp["traces_and_flows"]["transition_count"] == 0
    assert empty_comp["traces_and_flows"]["corroborated_edge_count"] == 0
    assert empty_comp["automated_security_audit"] is False


def test_memgraph_tarjan_scc_and_vmmap_zoom3_attribution(
    tmp_path: Path, db_session: Session
) -> None:
    """Verify `.memgraph` Tarjan retain cycles, weak-edge exclusion, & `vmmap` Zoom-3 drilldown."""
    repo_dir = materialize_truth_in_python_fixture(tmp_path / "heap_repo")
    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="heap-target",
            name="Heap Target",
            repo_path=str(repo_dir),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    report = run_target_scan(db_session, target, persist_snapshot=False, strict_gate=True)

    memgraph_json = tmp_path / "capture.memgraph.json"
    memgraph_json.write_text(
        json.dumps(
            {
                "classes": [
                    {
                        "class_name": "Case1ConsumedEnforcer.BatchSession",
                        "module": "case1_consumed_enforcer",
                        "instance_count": 48,
                        "total_bytes": 12288,
                        "raw_buffer": "SENSITIVE_HEAP_STRING_BUFFER_4411",
                    },
                    {
                        "class_name": "Swift._ContiguousArrayStorage",
                        "module": "case1_consumed_enforcer",
                        "instance_count": 120,
                        "total_bytes": 8192,
                    },
                ],
                "nodes": [
                    {"id": "0x1001", "class_name": "BatchSession", "module": "case1_consumed_enforcer", "size_bytes": 512},
                    {"id": "0x1002", "class_name": "RetryClosureBox", "module": "case1_consumed_enforcer", "size_bytes": 256},
                    {"id": "0x1003", "class_name": "WeakObserver", "module": "case1_consumed_enforcer", "size_bytes": 128},
                ],
                "edges": [
                    {"source": "0x1001", "target": "0x1002", "kind": "strong"},
                    {"source": "0x1002", "target": "0x1001", "kind": "retain"},
                    {"source": "0x1002", "target": "0x1003", "kind": "weak"},
                    {"source": "0x1003", "target": "0x1001", "kind": "weak"},
                ],
            }
        ),
        encoding="utf-8",
    )

    leaks_txt = tmp_path / "leaks_output.txt"
    leaks_txt.write_text(
        '16   4096   256.0   SolverArena  (in case7_solver_and_algorithms)\n'
        '0x2001 (SolverArena) --strong--> 0x2001 (SolverArena) "secret_heap_preview"\n',
        encoding="utf-8",
    )
    leaks_parsed = parse_memgraph_artifact(leaks_txt)
    assert leaks_parsed["retain_cycle_count"] == 1
    assert leaks_parsed["redacted_heap_buffers"] >= 1

    vmmap_txt = tmp_path / "vmmap_summary.txt"
    vmmap_txt.write_text(
        "REGION TYPE                  VIRTUAL   RESIDENT      DIRTY    SWAPPED      WIRED\n"
        "===========                  =======   ========      =====    =======      =====\n"
        "MALLOC_LARGE                   64.0M      32.0M      16.0M       0K         0K  case1_consumed_enforcer\n"
        "IOAccelerator                  32.0M      16.0M       8.0M       0K       4.0M  case1_consumed_enforcer\n"
        "__DATA_DIRTY                    2.0M       1.0M     512K         0K         0K  case1_consumed_enforcer\n"
        "TOTAL                          98.0M      49.0M      24.5M       0K       4.0M\n",
        encoding="utf-8",
    )
    vm_parsed = parse_vmmap_artifact(vmmap_txt)
    assert vm_parsed["malloc_dirty_bytes"] == 16 * 1024 * 1024
    assert vm_parsed["metal_ioaccelerator_dirty_bytes"] == 8 * 1024 * 1024
    assert vm_parsed["data_dirty_bytes"] == 512 * 1024
    assert vm_parsed["total_wired_bytes"] == 4 * 1024 * 1024

    enforcer_node = next(n for n in report.nodes if "case1_consumed_enforcer" in n.id)
    with wiretap_inspection_scope(memgraph=memgraph_json, vmmap=vmmap_txt):
        z3_compacted = build_node_stratum_drilldown(
            repo_dir, report, enforcer_node.id, zoom=3, unfiltered_ir=False, plugins=[WIRETAP_PLUGIN]
        )
        z3_unfiltered = build_node_stratum_drilldown(
            repo_dir, report, enforcer_node.id, zoom=3, unfiltered_ir=True, plugins=[WIRETAP_PLUGIN]
        )

    assert z3_compacted.collapsed_thunk_count >= 1
    assert z3_unfiltered.collapsed_thunk_count == 0
    assert any(n.kind == "retain_cycle_scc" and n.verification == "broken" for n in z3_compacted.nodes)
    assert any(n.kind == "vmmap_region" for n in z3_compacted.nodes)
    assert "SENSITIVE_HEAP_STRING_BUFFER_4411" not in z3_compacted.model_dump_json()


def test_host_port_occupancy_all_sources_and_port001_port002_rules(
    tmp_path: Path, monkeypatch
) -> None:
    """Verify `Z=0` port extraction across 6 formats + `PORT-001`, `PORT-002`, & provenance."""
    repo = tmp_path / "port_repo"
    (repo / "k8s").mkdir(parents=True)
    (repo / "scripts").mkdir(parents=True)
    (repo / "launchd").mkdir(parents=True)
    (repo / "app").mkdir(parents=True)

    (repo / "compose.yaml").write_text(
        "services:\n"
        "  quota_api:\n"
        "    image: quota-api:latest\n"
        "    ports:\n"
        '      - "127.0.0.1:8780:8780"\n'
        "  worker_metrics:\n"
        "    image: metrics:latest\n"
        "    ports:\n"
        '      - "127.0.0.1:9100:9100"\n',
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text("FROM python:3.12-slim\nEXPOSE 9200/tcp\n", encoding="utf-8")
    (repo / "k8s/service.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: scheduler-rpc\n"
        "spec:\n  ports:\n    - port: 9300\n      targetPort: 9300\n",
        encoding="utf-8",
    )
    (repo / "scripts/run_container.sh").write_text(
        "#!/bin/sh\ndocker run --rm -p 0.0.0.0:9400:9400 warehouse-worker:local\n",
        encoding="utf-8",
    )
    (repo / "launchd/io.example.daemon.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        "  <key>Label</key><string>io.example.daemon</string>\n"
        "  <key>Sockets</key><dict><key>Main</key><dict>\n"
        "    <key>SockNodeName</key><string>127.0.0.1</string>\n"
        "    <key>SockServiceName</key><string>9500</string>\n"
        "  </dict></dict>\n"
        "</dict></plist>\n",
        encoding="utf-8",
    )
    (repo / "app/server.py").write_text(
        "import uvicorn\n\ndef main():\n    uvicorn.run('app:api', host='127.0.0.1', port=9600)\n",
        encoding="utf-8",
    )

    decls = extract_declared_ports(repo)
    assert {d.port for d in decls} == {8780, 9100, 9200, 9300, 9400, 9500, 9600}

    lsof_capture = tmp_path / "lsof_listen.txt"
    lsof_capture.write_text(
        "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
        "uvicorn   10100   localadmin  6u  IPv4 0x11      0t0  TCP 127.0.0.1:9600 (LISTEN)\n"
        "nc        20200   localadmin  7u  IPv4 0x12      0t0  TCP 127.0.0.1:9100 (LISTEN)\n"
        "Python    30300   localadmin  8u  IPv4 0x13      0t0  TCP *:9500 (LISTEN)\n"
        "mysteryd  40400   localadmin  9u  IPv4 0x14      0t0  TCP 127.0.0.1:9999 (LISTEN)\n",
        encoding="utf-8",
    )
    ss_capture = tmp_path / "ss_listen.txt"
    ss_capture.write_text(
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        'tcp   LISTEN 0      128    127.0.0.1:9400      0.0.0.0:*         users:(("docker-proxy",pid=5050,fd=4))\n',
        encoding="utf-8",
    )

    occ = correlate_port_occupancy(
        repo,
        port_listeners_paths=[lsof_capture, ss_capture],
        probe_local_ports=False,
    )
    assert occ["provenance"]["subprocesses_invoked"] == 0
    assert occ["provenance"]["capture_mode"] == "recorded_artifact"
    assert "localadmin" not in json.dumps(occ)

    by_port = {e["port"]: e["classification"] for e in occ["entries"]}
    assert by_port[9600] == "corroborated"
    assert by_port[9100] == "squatter_conflict"
    assert by_port[9500] == "bind_exposure_drift"
    assert by_port[9400] == "bind_exposure_drift"
    assert by_port[9999] == "dark_listener"
    assert by_port[8780] == "unlistening_declared"

    rule_codes = [f["rule_code"] for f in occ["findings"]]
    assert "PORT-001" in rule_codes
    assert rule_codes.count("PORT-002") == 2

    # Opt-in `probe_local_ports=True` path (mocking fixed-argv subprocess so test is deterministic)
    monkeypatch.setattr(
        "wythe_plugin_wiretap.port_occupancy.capture_local_port_listeners",
        lambda: ([], "lsof", "2026-11-16T00:00:00+00:00"),
    )
    live_occ = correlate_port_occupancy(repo, probe_local_ports=True)
    assert live_occ["provenance"]["capture_mode"] == "live_local_snapshot"
    assert live_occ["provenance"]["subprocesses_invoked"] == 1


def test_wiretap_symlink_size_depth_xxe_and_redos_guards(tmp_path: Path, monkeypatch) -> None:
    """Enforce pre-`.resolve()` symlink rejection, `<= 32 MiB`, `depth <= 64`, XXE, & ReDoS `< 0.1s`."""
    real_file = tmp_path / "real_traces.json"
    real_file.write_text('{"spans": []}', encoding="utf-8")

    direct_link = tmp_path / "sym_traces.json"
    os.symlink(real_file, direct_link)
    with pytest.raises(ValueError, match="symlink"):
        parse_otel_traces(direct_link)

    real_dir = tmp_path / "real_sub"
    real_dir.mkdir()
    nested = real_dir / "traces.json"
    nested.write_text('{"spans": []}', encoding="utf-8")
    sym_dir = tmp_path / "sym_sub"
    os.symlink(real_dir, sym_dir)
    with pytest.raises(ValueError, match="symlink"):
        parse_otel_traces(sym_dir / "traces.json")

    with pytest.raises(ValueError, match="\\.\\."):
        parse_otel_traces(f"{real_dir}/../real_traces.json")

    # Enforce `<= 32 MiB` ceiling via `os.fstat` check without writing 33 MiB to disk
    orig_fstat = os.fstat

    class _OversizedStat:
        def __init__(self, st_mode: int) -> None:
            self.st_mode = st_mode
            self.st_size = MAX_WIRETAP_BYTES + 1024

    monkeypatch.setattr(
        "os.fstat",
        lambda fd: _OversizedStat(orig_fstat(fd).st_mode),
    )
    with pytest.raises(ValueError, match="exceeds"):
        parse_otel_traces(real_file)
    monkeypatch.undo()

    # Enforce `depth <= 64` without RecursionError
    deep_json = "[" * (MAX_NESTING_DEPTH + 2) + "]" * (MAX_NESTING_DEPTH + 2)
    with pytest.raises(ValueError, match="nesting depth"):
        ensure_json_depth_bounded(deep_json)

    # Reject XXE `<!ENTITY` in `.plist`
    xxe_plist = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<plist><dict><key>Label</key><string>&xxe;</string></dict></plist>"
    )
    with pytest.raises(ValueError, match="XXE"):
        parse_safe_plist_xml(xxe_plist)

    # ReDoS `< 0.1s` budget on adversarial SQL / URL inputs
    adv_sql = "SELECT * FROM items WHERE a = '" + ("x" * 20000) + "' AND b = 12345 VALUES (" + ("1," * 5000) + "1)"
    adv_url = "https://user:secret@example.invalid/api/v1/items?" + "&".join(f"k{i}=v{i}" for i in range(500))
    t0 = time.perf_counter()
    redact_sql_statement(adv_sql)
    redact_url_target(adv_url)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.1
