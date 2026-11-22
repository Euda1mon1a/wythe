"""Milestone M4 regression suite: P1-4, P1-5, P1-7, P1-11, P1-13."""

from __future__ import annotations

import ast
import json
import os
import plistlib
import time
from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult
from app.adapters.compose_sources import augment_compose_sources, parse_compose_file
from app.adapters.container_launchers import (
    augment_container_launchers,
    parse_launchd_plist,
    parse_systemd_unit,
)
from app.adapters.dockerfile_sources import (
    DockerIgnoreSpec,
    _compile_dockerignore_glob,
    augment_dockerfile_sources,
    parse_dockerfile,
)
from app.adapters.k8s_sources import augment_k8s_sources, parse_k8s_manifests
from app.adapters.launchd_sources import add_launchd_sources, parse_safe_plist_bytes
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.registry_sources import (
    _commands,
    _extract_registry_columns,
    _has_registry_keys,
    add_registry_sources,
    extract_registry_truth_nodes,
)
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.tach_bridge import _pattern_matches, augment_tach_boundaries, parse_tach_toml
from wythe_plugin_agent_harness.python_inspector import (
    HarnessConfig,
    _eval_static_ast_value,
    estimate_schema_budget,
    inspect_python_files,
    inspect_python_module_ast,
    load_harness_config,
)
from wythe_plugin_cpsat.ast_extractor import (
    CpSatRepoExtraction,
    _eval_numeric_expr,
    extract_repo_cpsat_models,
)
from wythe_plugin_wiretap.otel_ebpf import (
    _otel_kv_list_to_dict,
    _transition_from_attr_dict,
    parse_ebpf_flows,
    parse_otel_traces,
    read_bounded_json,
    redact_attributes,
    redact_url_target,
    validate_non_symlink_path,
)
from wythe_plugin_wiretap.port_occupancy import extract_declared_ports, parse_port_listeners_text


def _write(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def test_p1_4_registry_statement_io_and_import_qualified_loaders(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "config/routing.yaml",
        "providers:\n  local:\n    enabled: true\npolicies:\n  timeout_seconds: 15\n",
    )
    # Non-I/O references (module-level and function-level) must NOT emit reads_truth
    _write(
        tmp_path,
        "app/non_io.py",
        "import logging\n"
        "DEFAULT_CFG = 'config/routing.yaml'\n"
        "logging.info('config/routing.yaml')\n"
        "def log_only():\n"
        "    path_hint = 'config/routing.yaml'\n"
        "    logging.info('Using %s', path_hint)\n"
        "    return path_hint\n",
    )
    # Unrelated .load() without importing loader.py must NOT emit reads_truth
    _write(
        tmp_path,
        "app/loader.py",
        "from pathlib import Path\n"
        "import yaml\n"
        "def load():\n"
        "    p = 'config/routing.yaml'\n"
        "    return yaml.safe_load(Path(p).read_text())\n",
    )
    _write(
        tmp_path,
        "app/unrelated.py",
        "class Cache:\n"
        "    def load(self):\n"
        "        return {}\n"
        "def run():\n"
        "    c = Cache()\n"
        "    return c.load()\n",
    )
    # Explicit import-qualified caller MUST emit reads_truth
    _write(
        tmp_path,
        "app/caller_alias.py",
        "from app.loader import load as load_routing\n"
        "def handle():\n"
        "    cfg = load_routing()\n"
        "    return cfg['policies']['timeout_seconds']\n",
    )
    _write(
        tmp_path,
        "app/caller_mod.py",
        "import app.loader as ldr\n"
        "def handle():\n"
        "    cfg = ldr.load()\n"
        "    return cfg['policies']['timeout_seconds']\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)
    assert manip.coverage_complete is True

    readers = {
        e.source_id
        for e in manip.edges
        if e.kind == "reads_truth" and e.target_id == "t:registry:config/routing.yaml"
    }
    assert "m:script:app/non_io.py" not in readers
    assert "m:script:app/unrelated.py" not in readers
    assert "m:script:app/loader.py" in readers
    assert "m:script:app/caller_alias.py" in readers
    assert "m:script:app/caller_mod.py" in readers


def test_p1_7_p1_13_yaml_dag_bombs_and_coverage_complete(tmp_path: Path) -> None:
    # 1. Shared-reference DAG in Python directly into registry_sources helpers
    dag: object = {"command": "scripts/run.py"}
    for _ in range(30):
        dag = [dag, dag]
    t0 = time.monotonic()
    cmds = list(_commands(dag))
    has_k = _has_registry_keys(dag)
    cols, _ = _extract_registry_columns(dag)
    assert time.monotonic() - t0 < 0.25
    assert cmds and has_k is False and isinstance(cols, list)

    shallow_dag: object = {"command": "scripts/run.py"}
    for _ in range(3):
        shallow_dag = [shallow_dag, shallow_dag]
    assert _has_registry_keys(shallow_dag) is True

    # 2. 20-level YAML alias DAG completes cleanly; >4096-alias YAML bomb fails closed across config/, k8s/, compose.yaml
    dag_lines = ["a0: &a0 [1, 2, 3]"]
    for idx in range(1, 20):
        dag_lines.append(f"a{idx}: &a{idx} [*a{idx - 1}, *a{idx - 1}]")
    dag_lines.append("commands:\n  run:\n    argv: *a19\n")
    dag_yaml = "\n".join(dag_lines)

    reg_dag_repo = tmp_path / "reg_dag"
    _write(reg_dag_repo, "config/dag.yaml", dag_yaml)
    _write(reg_dag_repo, "scripts/ok.py", "def ok():\n    return 1\n")
    t_dag = time.monotonic()
    truth_d = SqlDdlTruthAdapter().extract(reg_dag_repo, ".")
    manip_d = PythonServicesAdapter().extract(reg_dag_repo, ".", truth_d)
    assert time.monotonic() - t_dag < 0.5
    assert manip_d.coverage_complete is True

    bomb_yaml = "a0: &a0 [1, 2]\nbig: [" + ", ".join(["*a0"] * 4200) + "]\n"

    reg_repo = tmp_path / "reg_bomb"
    _write(reg_repo, "config/bomb.yaml", "commands:\n  run:\n    argv: []\n" + bomb_yaml)
    _write(reg_repo, "scripts/ok.py", "def ok():\n    return 1\n")
    t1 = time.monotonic()
    truth_b = SqlDdlTruthAdapter().extract(reg_repo, ".")
    manip_b = PythonServicesAdapter().extract(reg_repo, ".", truth_b)
    assert time.monotonic() - t1 < 0.5
    assert manip_b.coverage_complete is False
    assert truth_b.coverage_complete is False

    reg_huge = tmp_path / "reg_huge"
    _write(reg_huge, "config/huge.yaml", "commands:\n  a: " + ("x" * 1_100_000) + "\n")
    truth_h = SqlDdlTruthAdapter().extract(reg_huge, ".")
    manip_h = PythonServicesAdapter().extract(reg_huge, ".", truth_h)
    assert manip_h.coverage_complete is False

    k8s_repo = tmp_path / "k8s_bomb"
    _write(k8s_repo, "k8s/bomb.yaml", "apiVersion: apps/v1\nkind: Deployment\n" + bomb_yaml)
    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    t2 = time.monotonic()
    augment_k8s_sources(k8s_repo, ".", k8s_res)
    assert time.monotonic() - t2 < 0.5
    assert k8s_res.coverage_complete is False

    comp_repo = tmp_path / "comp_bomb"
    _write(comp_repo, "compose.yaml", "services:\n  web:\n    image: nginx:1\n" + bomb_yaml)
    comp_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    t3 = time.monotonic()
    augment_compose_sources(comp_repo, ".", comp_res)
    assert time.monotonic() - t3 < 0.5
    assert comp_res.coverage_complete is False


def test_p1_7_dockerignore_dp_and_compose_context_bomb(tmp_path: Path) -> None:
    matcher = _compile_dockerignore_glob(("**/" * 25) + "secret.txt")
    assert matcher is not None
    t0 = time.monotonic()
    assert matcher.matches("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/other.txt") is False
    assert matcher.matches("a/b/c/secret.txt") is True
    assert time.monotonic() - t0 < 0.05

    assert _compile_dockerignore_glob("[!]") is None
    assert _compile_dockerignore_glob("[z-a]") is None

    spec = DockerIgnoreSpec(
        rules=tuple(
            (m, neg)
            for pat, neg in [
                ("leading.txt", False),
                ("dir/", False),
                ("dir/keep.txt", True),
                ("**/*.pyc", False),
                ("a/**/b", False),
                ("*.py[cod]", False),
            ]
            if (m := _compile_dockerignore_glob(pat)) is not None
        )
    )
    assert spec.is_excluded("leading.txt") is True
    assert spec.is_excluded("dir/drop.txt") is True
    assert spec.is_excluded("dir/keep.txt") is False
    assert spec.is_excluded("pkg/sub/mod.pyc") is True
    assert spec.is_excluded("a/b") is True
    assert spec.is_excluded("a/x/y/b") is True
    assert spec.is_excluded("mod.pyd") is True

    bomb_lines = ["a0: &a0 [1, 2]"]
    for idx in range(1, 20):
        bomb_lines.append(f"a{idx}: &a{idx} [*a{idx - 1}, *a{idx - 1}]")
    _write(tmp_path, "compose.yaml", "services:\n  web:\n    build: .\n" + "\n".join(bomb_lines))
    _write(tmp_path, "Dockerfile", "FROM python:3.12-slim\nCMD [\"python\", \"-V\"]\n")
    df_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    t1 = time.monotonic()
    augment_dockerfile_sources(tmp_path, ".", df_res)
    assert time.monotonic() - t1 < 0.5


def test_p1_7_p1_13_tach_redos_and_launchd_plist_hardening(tmp_path: Path) -> None:
    t0 = time.monotonic()
    assert _pattern_matches("(a+)+b", ("a" * 100) + "c") is False
    assert _pattern_matches("*a*a*a*a*a*b", ("a" * 100) + "c") is False
    assert time.monotonic() - t0 < 0.05

    assert _pattern_matches("schemas.*", "schemas.OrderRead") is True
    assert _pattern_matches("get_.*", "get_user") is True
    assert _pattern_matches(r"schemas\..*", "schemas.Item") is True
    assert _pattern_matches("*.py", "src/app/main.py") is True
    assert _pattern_matches("**/tests/**", "backend/tests/test_a.py") is True

    tach_repo = tmp_path / "tach_oversize"
    _write(tach_repo, "tach.toml", "source_roots = ['.']\n# " + ("x" * 600_000))
    tach_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_tach_boundaries(tach_repo, ".", tach_res)
    assert tach_res.coverage_complete is False

    # Deeply nested XML plist & XXE & binary plist depth DAG & valid binary plist
    deep_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        + ("<array>" * 60)
        + "<string>x</string>"
        + ("</array>" * 60)
        + "</dict></plist>"
    ).encode("utf-8")
    try:
        parse_safe_plist_bytes(deep_xml)
        raise AssertionError("Expected deep XML plist to fail")
    except ValueError:
        pass

    xxe_xml = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<plist version=\"1.0\"><dict><key>Label</key><string>&xxe;</string></dict></plist>"
    )
    try:
        parse_safe_plist_bytes(xxe_xml)
        raise AssertionError("Expected XXE XML plist to fail")
    except ValueError:
        pass

    # Valid shallow binary plist still succeeds
    valid_bplist = plistlib.dumps(
        {"Label": "com.example.ok", "ProgramArguments": ["/usr/bin/python3", "scripts/ok.py"]},
        fmt=plistlib.FMT_BINARY,
    )
    parsed_bp = parse_safe_plist_bytes(valid_bplist)
    assert parsed_bp["Label"] == "com.example.ok"

    # Malformed plist in launchagents/ sets coverage_complete=False in both adapters
    la_repo = tmp_path / "la_bad"
    _write(la_repo, "launchagents/broken.plist", "not valid xml or bplist")
    la_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    add_launchd_sources(la_repo, la_res)
    assert la_res.coverage_complete is False

    cl_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_launchers(la_repo, ".", cl_res)
    assert cl_res.coverage_complete is False

    # Binary plist in launchagents/ parses cleanly without crashing plist_locations
    bp_repo = tmp_path / "la_bplist"
    _write(bp_repo, "scripts/worker.py", "def run():\n    return 1\n")
    (bp_repo / "launchagents").mkdir(parents=True, exist_ok=True)
    (bp_repo / "launchagents/com.example.bp.plist").write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.bp",
                "ProgramArguments": ["/usr/bin/python3", "scripts/worker.py"],
            },
            fmt=plistlib.FMT_BINARY,
        )
    )
    bp_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    add_launchd_sources(bp_repo, bp_res)
    assert bp_res.coverage_complete is True
    assert any(n.id == "m:launchd:launchagents/com.example.bp.plist" for n in bp_res.nodes)


def test_p1_7_cpsat_numeric_and_agent_harness_string_bounds(tmp_path: Path) -> None:
    t0 = time.monotonic()
    for expr in ("int(1e200 * 1e200)", "int(1e100)", "1e100 // 1e-300", "1e309", "1e200 ** 2"):
        node = ast.parse(expr, mode="eval").body
        assert _eval_numeric_expr(node, {}) == (None, None)
    assert _eval_numeric_expr(ast.parse("int(0.05 * 10)", mode="eval").body, {}) == (0, 0.5)

    # Doubling chain + stale const eviction
    lines = ["from ortools.sat.python import cp_model", "x = 2**128"]
    for i in range(1, 30):
        lines.append(f"x{i} = x * x" if i == 1 else f"x{i} = x{i - 1} * x{i - 1}")
    lines.extend(["y = 5", "y = 1e309", "z = y + 1"])
    cpsat_repo = tmp_path / "cpsat_dos"
    _write(cpsat_repo, "solver.py", "\n".join(lines) + "\n")
    ext_cp = extract_repo_cpsat_models(cpsat_repo)
    assert time.monotonic() - t0 < 0.25
    assert len(ext_cp.modules) == 1

    # Agent harness: string doubling + deep Path chain + nested JoinedStr
    t1 = time.monotonic()
    s_lines = ["s0 = 'A' * 2048"]
    for i in range(1, 25):
        s_lines.append(f"s{i} = s{i - 1} + s{i - 1}")
    s_lines.append("p = " + " + ".join(["'x'"] * 40))
    ah_src = "\n".join(s_lines) + "\n"
    _write(tmp_path, "agent_dos.py", ah_src)
    bundle = inspect_python_module_ast("agent_dos.py", ah_src)
    assert time.monotonic() - t1 < 0.25
    assert bundle.manifests == []

    big_f = ast.parse("f'" + ("{x}" * 20) + "'", mode="eval").body
    assert _eval_static_ast_value(big_f, {"x": "A" * 512}) is None


def test_p1_11_wiretap_redaction_and_port_occupancy_plist(tmp_path: Path) -> None:
    # 1. Multi-line SQL in exception.message, CALL/EXEC, prefixed span.name, KV values list
    _, r_cnt = redact_attributes(
        {
            "exception.message": "Query failed:\nSELECT *\nFROM users\nWHERE pw = 'TOP_SECRET_PW'",
            "db.call": "CALL sp_auth('TOP_SECRET_PW')",
            "db.exec": "EXEC sp_login 'TOP_SECRET_PW'",
            "prose.note": "Please call support at 555-1234",
            "otel.attributes": [{"key": "Authorization", "values": ["RAW_API_KEY_123"]}],
        }
    )
    assert r_cnt >= 4

    attrs, a_cnt = redact_attributes(
        {
            "exception.message": "Query failed:\nSELECT *\nFROM users\nWHERE pw = 'TOP_SECRET_PW'",
            "prose.note": "Please call support at 555-1234",
            "otel.attributes": [{"key": "Authorization", "values": ["RAW_API_KEY_123"]}],
        }
    )
    assert a_cnt >= 2
    serialized = json.dumps(attrs)
    assert "TOP_SECRET_PW" not in serialized
    assert "RAW_API_KEY_123" not in serialized
    assert attrs["prose.note"] == "Please call support at 555-1234"

    # 2. Prefixed SQL in span.name (both with and without db.statement)
    trace_file = _write(
        tmp_path,
        "trace.json",
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "db.query: SELECT * FROM users WHERE pw = 'TOP_SECRET_PW'",
                                        "attributes": [
                                            {"key": "service.name", "value": {"stringValue": "api"}},
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {"key": "db.statement", "value": {"stringValue": "EXEC sp_login 'TOP_SECRET_PW'"}},
                                        ],
                                    },
                                    {
                                        "name": "db.query: SELECT * FROM users WHERE pw = 'TOP_SECRET_PW'",
                                        "attributes": [
                                            {"key": "service.name", "value": {"stringValue": "api"}},
                                            {"key": "rpc.system", "value": {"stringValue": "grpc"}},
                                        ],
                                    },
                                ]
                            }
                        ]
                    }
                ]
            }
        ),
    )
    spans, _ = parse_otel_traces(trace_file, repo_root=tmp_path)
    assert len(spans) == 2
    for sp in spans:
        assert "TOP_SECRET_PW" not in sp.redacted_summary
        assert "TOP_SECRET_PW" not in json.dumps(sp.attributes)

    # 3. redact_url_target edge cases + ReDoS timing
    _, red_tok, was_tok = redact_url_target("https://api.example.com/x?RAW_SECRET_TOKEN")
    assert was_tok is True and "RAW_SECRET_TOKEN" not in red_tok
    assert redact_url_target("http://[::1")[1:] == ("[REDACTED]", True)
    _, red_bad_p, was_bad_p = redact_url_target("http://host:abc/x")
    assert was_bad_p is True and "host" in red_bad_p
    _, red_oob_p, was_oob_p = redact_url_target("http://host:99999/x")
    assert was_oob_p is True and "host" in red_oob_p
    _, red_v6, was_v6 = redact_url_target("http://[::1]:0/x?a=1#frag")
    assert was_v6 is True and "http://[::1]:0/x?a=[REDACTED]" == red_v6

    t0 = time.monotonic()
    redact_attributes({"exception.message": "SELECT " * 9300})
    assert time.monotonic() - t0 < 0.1

    # 4. port_occupancy extract_declared_ports survives binary & malformed XML plists
    po_repo = tmp_path / "po_repo"
    (po_repo / "launchagents").mkdir(parents=True, exist_ok=True)
    (po_repo / "launchagents/binary.plist").write_bytes(
        plistlib.dumps({"Label": "com.example.bin"}, fmt=plistlib.FMT_BINARY)
    )
    _write(po_repo, "launchagents/broken.plist", "<plist><unclosed")
    (po_repo / "launchagents/valid.plist").write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.ok",
                "ProgramArguments": ["uvicorn", "app:app", "--port", "8123"],
            }
        )
    )
    ports = extract_declared_ports(po_repo, [])
    assert any(p.port == 8123 for p in ports)


def test_r2_registry_class_method_qualification_symlinks_fifo_and_anchor_depth(tmp_path: Path) -> None:
    # 1. Two classes sharing `load` in both orders + top-level `load` + cross-file class/fn imports + `with open` return
    repo_cls = tmp_path / "cls_repo"
    _write(
        repo_cls,
        "config/routing.yaml",
        "providers:\n  local:\n    enabled: true\npolicies:\n  timeout_seconds: 15\n",
    )
    _write(repo_cls, "config/notes.py", "# non-registry python file must not degrade coverage\nX = 1\n")
    _write(
        repo_cls,
        "app/svc_real_first.py",
        "from pathlib import Path\nimport yaml\n"
        "class RealLoader:\n"
        "    def load(self):\n"
        "        with open('config/routing.yaml') as f:\n"
        "            return yaml.safe_load(f)\n"
        "    def run(self):\n"
        "        return self.load()\n"
        "class UnrelatedLoader:\n"
        "    def load(self):\n"
        "        return {}\n"
        "    def run_unrelated(self):\n"
        "        return self.load()\n",
    )
    _write(
        repo_cls,
        "app/svc_unrelated_first.py",
        "from pathlib import Path\nimport yaml\n"
        "class UnrelatedLoader:\n"
        "    def load(self):\n"
        "        return {}\n"
        "    def run_unrelated(self):\n"
        "        return self.load()\n"
        "class RealLoader:\n"
        "    def load(self):\n"
        "        return yaml.safe_load(Path('config/routing.yaml').read_text())\n"
        "    def run(self):\n"
        "        return self.load()\n",
    )
    _write(
        repo_cls,
        "app/mixed_top_and_cls.py",
        "from pathlib import Path\nimport yaml\n"
        "def load():\n"
        "    with open('config/routing.yaml') as f:\n"
        "        return yaml.safe_load(f)\n"
        "class Foo:\n"
        "    def load(self):\n"
        "        return {}\n",
    )
    _write(
        repo_cls,
        "app/caller_bad_cls.py",
        "from app.svc_unrelated_first import UnrelatedLoader\n"
        "def call_bad():\n"
        "    return UnrelatedLoader.load(None)\n",
    )
    _write(
        repo_cls,
        "app/caller_good_cls.py",
        "from app.svc_real_first import RealLoader\n"
        "def call_good():\n"
        "    return RealLoader.load(None)\n",
    )
    _write(
        repo_cls,
        "app/caller_top_fn.py",
        "from app.mixed_top_and_cls import load\n"
        "def call_top():\n"
        "    return load()\n",
    )
    _write(
        repo_cls,
        "app/caller_mod_fn.py",
        "import app.mixed_top_and_cls as m\n"
        "def call_mod():\n"
        "    return m.load()\n",
    )

    truth = SqlDdlTruthAdapter().extract(repo_cls, ".")
    manip = PythonServicesAdapter().extract(repo_cls, ".", truth)
    assert manip.coverage_complete is True
    assert truth.coverage_complete is True

    by_src = {
        e.source_id: e.symbol_links
        for e in manip.edges
        if e.kind == "reads_truth" and e.target_id == "t:registry:config/routing.yaml"
    }
    assert by_src.get("m:script:app/svc_real_first.py") == ["RealLoader.run->*"]
    assert by_src.get("m:script:app/svc_unrelated_first.py") == ["RealLoader.run->*"]
    assert "m:script:app/mixed_top_and_cls.py" in by_src
    assert "m:script:app/caller_good_cls.py" in by_src
    assert "m:script:app/caller_top_fn.py" in by_src
    assert "m:script:app/caller_mod_fn.py" in by_src
    assert "m:script:app/caller_bad_cls.py" not in by_src

    # 2. _has_registry_keys: anchor defined at depth 4 and aliased at depth 1
    shared_sub = {"nested": {"command": "scripts/run.py"}}
    anchor_obj = {
        "deep": {"a": {"b": {"c": shared_sub}}},
        "shallow": shared_sub,
    }
    assert _has_registry_keys(anchor_obj) is True

    # 3. Symlink and FIFO inside config/ set coverage_complete=False on both manip & truth
    outside = tmp_path / "outside_reg.yaml"
    outside.write_text("commands:\n  a:\n    command: x.py\n", encoding="utf-8")
    sym_repo = tmp_path / "reg_sym"
    _write(sym_repo, "scripts/ok.py", "def ok():\n    return 1\n")
    (sym_repo / "config").mkdir(parents=True, exist_ok=True)
    (sym_repo / "config" / "link.yaml").symlink_to(outside)
    t_sym = SqlDdlTruthAdapter().extract(sym_repo, ".")
    m_sym = PythonServicesAdapter().extract(sym_repo, ".", t_sym)
    assert m_sym.coverage_complete is False
    assert t_sym.coverage_complete is False

    fifo_repo = tmp_path / "reg_fifo"
    _write(fifo_repo, "scripts/ok.py", "def ok():\n    return 1\n")
    (fifo_repo / "config").mkdir(parents=True, exist_ok=True)
    os.mkfifo(fifo_repo / "config" / "pipe.yaml")
    t_fifo = SqlDdlTruthAdapter().extract(fifo_repo, ".")
    m_fifo = PythonServicesAdapter().extract(fifo_repo, ".", t_fifo)
    assert m_fifo.coverage_complete is False
    assert t_fifo.coverage_complete is False


def test_r2_cpsat_deep_binop_1500_iterative_no_recursion_error(tmp_path: Path) -> None:
    terms = " + ".join(["y"] * 1500)
    src = (
        "from ortools.sat.python import cp_model\n"
        "def solve_deep():\n"
        "    m = cp_model.CpModel()\n"
        "    y = m.NewBoolVar('y')\n"
        f"    m.Add({terms} >= 1)\n"
        f"    m.Minimize(({terms}) * 2)\n"
        "    s = cp_model.CpSolver()\n"
        f"    s.parameters.num_search_workers = min(4, {terms})\n"
        "    return s.Solve(m)\n"
    )
    _write(tmp_path, "deep_cpsat.py", src)
    t0 = time.monotonic()
    ext = extract_repo_cpsat_models(tmp_path)
    assert time.monotonic() - t0 < 1.0
    assert "deep_cpsat.py" in ext.modules
    mod = ext.modules["deep_cpsat.py"]
    assert mod.is_cpsat_module is True
    assert len(mod.constraints) == 1
    assert len(mod.objectives) == 1


def test_r2_symlink_and_oversized_coverage_complete_false_all_adapters(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("external", encoding="utf-8")

    # 1. launchd_sources + container_launchers plist symlink
    la_repo = tmp_path / "la_sym"
    (la_repo / "LaunchAgents").mkdir(parents=True, exist_ok=True)
    (la_repo / "LaunchAgents" / "link.plist").symlink_to(outside)
    ld_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    add_launchd_sources(la_repo, ld_res)
    assert ld_res.coverage_complete is False

    cl_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_launchers(la_repo, ".", cl_res)
    assert cl_res.coverage_complete is False

    _, p_err = parse_launchd_plist(la_repo / "LaunchAgents" / "link.plist", la_repo)
    assert p_err is not None

    # Oversized .sh in container_launchers
    sh_repo = tmp_path / "sh_big"
    _write(sh_repo, "scripts/huge.sh", "#!/bin/sh\n" + ("echo a\n" * 60_000))
    sh_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_launchers(sh_repo, ".", sh_res)
    assert sh_res.coverage_complete is False

    # 2. k8s_sources symlink
    k8s_repo = tmp_path / "k8s_sym"
    (k8s_repo / "k8s").mkdir(parents=True, exist_ok=True)
    (k8s_repo / "k8s" / "link.yaml").symlink_to(outside)
    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_k8s_sources(k8s_repo, ".", k8s_res)
    assert k8s_res.coverage_complete is False
    parsed_k8s = parse_k8s_manifests(k8s_repo / "k8s" / "link.yaml", k8s_repo, in_k8s_dir=True)
    assert parsed_k8s.parse_error is not None

    # 3. compose_sources symlink
    comp_repo = tmp_path / "comp_sym"
    comp_repo.mkdir(parents=True, exist_ok=True)
    (comp_repo / "compose.yaml").symlink_to(outside)
    comp_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_compose_sources(comp_repo, ".", comp_res)
    assert comp_res.coverage_complete is False
    _, comp_err = parse_compose_file(comp_repo / "compose.yaml", comp_repo)
    assert comp_err is not None

    # 4. dockerfile_sources symlink (Dockerfile & .dockerignore)
    df_repo = tmp_path / "df_sym"
    df_repo.mkdir(parents=True, exist_ok=True)
    (df_repo / "Dockerfile").symlink_to(outside)
    (df_repo / ".dockerignore").symlink_to(outside)
    df_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_dockerfile_sources(df_repo, ".", df_res)
    assert df_res.coverage_complete is False

    # 5. tach_bridge symlink
    tach_repo = tmp_path / "tach_sym"
    tach_repo.mkdir(parents=True, exist_ok=True)
    (tach_repo / "tach.toml").symlink_to(outside)
    tach_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_tach_boundaries(tach_repo, ".", tach_res)
    assert tach_res.coverage_complete is False


def test_r2_wiretap_port_occupancy_huge_int_bool_and_sql_projection_redos(tmp_path: Path) -> None:
    # 1. >4300-digit YAML int & boolean ports in Compose/K8s must not crash or emit port=True
    repo = tmp_path / "po_edge"
    huge_int = "9" * 5000
    _write(repo, "compose.yaml", f"services:\n  api:\n    ports:\n      - published: {huge_int}\n")
    _write(repo, "bool_compose.yaml", "services:\n  api:\n    ports:\n      - published: true\n      - true\n")
    _write(
        repo,
        "bool_k8s.yaml",
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec:\n  ports:\n    - port: true\n",
    )
    assert extract_declared_ports(repo) == []

    # >4300-digit port/pid strings in lsof, ss, and JSON listener captures
    obs1, _, _ = parse_port_listeners_text(f"python 1234 user 6u IPv4 0x1 0t0 TCP 127.0.0.1:{huge_int} (LISTEN)")
    obs2, _, _ = parse_port_listeners_text(f"python {huge_int} user 6u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)")
    obs3, _, _ = parse_port_listeners_text(f"tcp LISTEN 0 128 0.0.0.0:{huge_int} 0.0.0.0:* users:((\"py\",pid={huge_int},fd=3))")
    obs4, _, _ = parse_port_listeners_text(json.dumps({"listeners": [{"port": huge_int, "pid": huge_int}]}))
    obs5, _, _ = parse_port_listeners_text(f'{{"listeners": [{{"port": {huge_int}, "pid": 1}}]}}')
    assert obs1 == [] and obs2 == [] and obs3 == [] and obs4 == [] and obs5 == []

    # 2. Long SELECT projection (>512 chars before FROM) scrubbed in < 0.05s, 64KB SELECT * 9300 in < 0.05s
    long_proj = "failed: SELECT 'SECRET_IN_PROJECTION', " + ", ".join(f"col_{i}" for i in range(80)) + " FROM users"
    t0 = time.monotonic()
    out_proj, cnt_proj = redact_attributes({"exception.message": long_proj})
    assert time.monotonic() - t0 < 0.05
    assert cnt_proj >= 1
    assert "SECRET_IN_PROJECTION" not in str(out_proj["exception.message"])

    t1 = time.monotonic()
    redact_attributes({"exception.message": "SELECT " * 9300})
    assert time.monotonic() - t1 < 0.05

    t2 = time.monotonic()
    redact_attributes({"exception.message": ("SELECT " * 5000) + " FROM users"})
    assert time.monotonic() - t2 < 0.05

    out_neg, cnt_neg = redact_attributes({"prose.note": "Please call support at 555-1234"})
    assert cnt_neg == 0 and out_neg["prose.note"] == "Please call support at 555-1234"


def test_r3_wiretap_otel_ebpf_huge_int_and_unicode_digits(tmp_path: Path) -> None:
    huge = "9" * 5000

    # 1. parse_ebpf_flows on JSON array and JSONL with >4300-digit integer must not raise ValueError
    arr_path = _write(
        tmp_path,
        "ebpf_arr.json",
        f'[{{"service_name": "svc", "http": {{"method": "GET", "url": "/x?TOK=secret1"}}, "bytes": {huge}, "delta": -{huge}}}]',
    )
    arr_flows, arr_red = parse_ebpf_flows(arr_path, repo_root=tmp_path)
    assert len(arr_flows) == 1
    assert arr_flows[0].http_method == "GET"
    assert arr_flows[0].http_route == "/x"
    assert arr_flows[0].attributes.get("bytes") == 0
    assert arr_flows[0].attributes.get("delta") == 0
    assert arr_red >= 1
    assert "secret1" not in json.dumps(arr_flows[0].attributes)

    jsonl_path = _write(
        tmp_path,
        "ebpf_lines.jsonl",
        f'{{"service_name": "svc", "http": {{"method": "POST", "url": "/y?KEY=secret2"}}, "bytes": {huge}}}\n',
    )
    jsonl_flows, jsonl_red = parse_ebpf_flows(jsonl_path, repo_root=tmp_path)
    assert len(jsonl_flows) == 1
    assert jsonl_flows[0].http_method == "POST"
    assert jsonl_flows[0].http_route == "/y"
    assert jsonl_flows[0].attributes.get("bytes") == 0
    assert jsonl_red >= 1
    assert "secret2" not in json.dumps(jsonl_flows[0].attributes)

    # 2. parse_otel_traces + read_bounded_json on >4300-digit intValue & span.kind, preserving 19-digit OTLP timestamp
    ts_nano = 1700000000000000000
    otel_raw = (
        '{"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "api"}}]}, '
        '"scopeSpans": [{"spans": ['
        f'{{"name": "GET /items", "kind": "{huge}", "startTimeUnixNano": {ts_nano}, '
        f'"attributes": [{{"key": "http.request.method", "value": {{"stringValue": "GET"}}}}, '
        f'{{"key": "url.path", "value": {{"stringValue": "/items?tok=secret3"}}}}, '
        f'{{"key": "big", "value": {{"intValue": {huge}}}}}]}}, '
        f'{{"name": "GET /u", "kind": "\\u00b2", "endTimeUnixNano": {ts_nano}, '
        '"attributes": [{"key": "http.request.method", "value": {"stringValue": "GET"}}, '
        '{"key": "url.path", "value": {"stringValue": "/u"}}]}'
        ']}]}]}'
    )
    otel_path = _write(tmp_path, "otel_huge.json", otel_raw)
    _res_p, raw_doc = read_bounded_json(otel_path, repo_root=tmp_path)
    spans_raw = raw_doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert spans_raw[0]["startTimeUnixNano"] == ts_nano
    assert spans_raw[1]["endTimeUnixNano"] == ts_nano
    assert spans_raw[0]["attributes"][2]["value"]["intValue"] == 0

    otel_tr, otel_red = parse_otel_traces(otel_path, repo_root=tmp_path)
    assert len(otel_tr) == 2
    assert otel_tr[0].span_kind == ""
    assert otel_tr[0].attributes.get("big") == 0
    assert otel_tr[1].span_kind == ""
    assert otel_red >= 1
    assert "secret3" not in json.dumps(otel_tr[0].attributes)

    # 3. port_occupancy Unicode superscript digit ('\u00b2') must not raise ValueError
    u_json, _, _ = parse_port_listeners_text('{"listeners": [{"port": "\\u00b2", "pid": "\\u00b2"}]}')
    u_lsof1, _, _ = parse_port_listeners_text("python \u00b2 user 6u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)")
    u_lsof2, _, _ = parse_port_listeners_text("python 1234 user 6u IPv4 0x1 0t0 TCP 127.0.0.1:\u00b2 (LISTEN)")
    u_ss, _, _ = parse_port_listeners_text('tcp LISTEN 0 128 0.0.0.0:\u00b2 0.0.0.0:* users:(("py",pid=\u00b2,fd=3))')
    assert u_json == [] and u_lsof1 == [] and u_lsof2 == [] and u_ss == []

    u_repo = tmp_path / "po_unicode"
    _write(u_repo, "compose.yaml", 'services:\n  api:\n    ports:\n      - "127.0.0.1:\u00b2:8080"\n      - "\u00b2"\n')
    (u_repo / "launchagents").mkdir(parents=True, exist_ok=True)
    (u_repo / "launchagents/u.plist").write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.unicode",
                "ProgramArguments": ["uvicorn", "app:app", "--port", "\u00b2"],
                "Sockets": {"Main": {"SockServiceName": "\u00b2"}},
            }
        )
    )
    assert extract_declared_ports(u_repo) == []


def test_r4_dockerfile_k8s_tach_huge_int_and_unicode_digits(tmp_path: Path) -> None:
    huge_9 = "9" * 5000
    huge_0 = "0" * 5000

    # 1. Dockerfile: Unicode digit in COPY --from, >4300-digit COPY --from, CMD [...], COPY [...]
    df_repo = tmp_path / "df_hostile"
    _write(df_repo, "src/app.py", "def run():\n    return 1\n")
    _write(
        df_repo,
        "Dockerfile",
        (
            "FROM python:3.12 AS builder\n"
            "COPY src/app.py /build/app.py\n"
            "FROM python:3.12\n"
            "COPY --from=0 /build/app.py /app/ok.py\n"
            "COPY --from=\u00b2 /a /b\n"
            f"COPY --from={huge_0} /a /b\n"
            f'COPY [{huge_9}, "/b"]\n'
            f"CMD [{huge_9}]\n"
        ),
    )
    df_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    parsed_dfs = augment_dockerfile_sources(df_repo, ".", df_res)
    assert "Dockerfile" in parsed_dfs
    assert any(
        f.rule_code == "MANIP-004" and "must be an array of strings" in f.detail
        for f in df_res.findings
    )
    assert parsed_dfs["Dockerfile"].stages[1].mappings[0].repo_rel == "src/app.py"

    # 2. K8s: >4300-digit YAML integer scalar fails closed with parse_error & coverage_complete=False
    k8s_repo = tmp_path / "k8s_huge_int"
    cm_path = _write(
        k8s_repo,
        "k8s/cm.yaml",
        f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  x: {huge_9}\n",
    )
    parsed_k8s = parse_k8s_manifests(cm_path, k8s_repo, in_k8s_dir=True)
    assert parsed_k8s.parse_error is not None
    assert parsed_k8s.resources == ()

    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_k8s_sources(k8s_repo, ".", k8s_res)
    assert k8s_res.coverage_complete is False
    assert any("k8s/cm.yaml" in note for note in k8s_res.notes)

    # 3. Tach: Unicode digit quantifiers in exclude & visibility, plus >5-digit quantifier & huge TOML int
    assert _pattern_matches("a{\u00b2}", "a") is False
    assert _pattern_matches("a{1,\u00b2}", "a") is False
    assert _pattern_matches("a{\u00b2,2}", "a") is False
    assert _pattern_matches("a{100000}", "a") is False
    assert _pattern_matches("a{2}", "aa") is True

    tach_repo = tmp_path / "tach_unicode"
    _write(
        tach_repo,
        "tach.toml",
        (
            'source_roots = ["src"]\n'
            'exclude = ["a{\u00b2}"]\n'
            "\n"
            "[[modules]]\n"
            'path = "pkg_a"\n'
            'depends_on = ["pkg_b"]\n'
            'visibility = ["pkg_{\u00b2}"]\n'
            "\n"
            "[[modules]]\n"
            'path = "pkg_b"\n'
            "depends_on = []\n"
            'visibility = ["pkg_{\u00b2}"]\n'
        ),
    )
    _write(tach_repo, "src/pkg_a/__init__.py", "")
    _write(tach_repo, "src/pkg_a/mod.py", "import pkg_b.api\n")
    _write(tach_repo, "src/pkg_b/__init__.py", "")
    _write(tach_repo, "src/pkg_b/api.py", "def ok():\n    return 1\n")

    tach_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_tach_boundaries(tach_repo, ".", tach_res)
    assert tach_res.coverage_complete is True
    assert any(f.rule_code == "MANIP-006" for f in tach_res.findings)

    tach_huge = tmp_path / "tach_huge_int"
    _write(tach_huge, "tach.toml", f"big_num = {huge_9}\n")
    tach_huge_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_tach_boundaries(tach_huge, ".", tach_huge_res)
    assert tach_huge_res.coverage_complete is False


def test_r5_toml_recursion_yaml_hex_int_and_ebpf_sql_values(tmp_path: Path) -> None:
    import pytest

    deep_toml = "x = " + ("[" * 1500) + "1" + ("]" * 1500) + "\n"
    hex_big = "0x" + ("f" * 5000)

    # 1. Deeply nested TOML RecursionError + bounded pyproject.toml read
    tach_deep = tmp_path / "tach_deep"
    tach_toml_path = _write(tach_deep, "tach.toml", deep_toml)
    with pytest.raises(ValueError, match="maximum nesting depth"):
        parse_tach_toml(tach_toml_path, tach_deep)
    tach_deep_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_tach_boundaries(tach_deep, ".", tach_deep_res)
    assert tach_deep_res.coverage_complete is False
    assert any("Tach boundary parse skipped" in note for note in tach_deep_res.notes)

    ah_deep = tmp_path / "ah_deep"
    _write(ah_deep, "pyproject.toml", "[tool.wythe.agent_harness]\n" + deep_toml)
    assert load_harness_config(ah_deep) == HarnessConfig()

    ah_big = tmp_path / "ah_big"
    _write(
        ah_big,
        "pyproject.toml",
        "[tool.wythe.agent_harness]\nmax_slm_tools = 3\n# " + ("a" * 600_000) + "\n",
    )
    assert load_harness_config(ah_big) == HarnessConfig()

    # 2. Oversized 0x hex YAML integers across compose, k8s, registry, and port_occupancy
    comp_repo = tmp_path / "comp_hex"
    _write(
        comp_repo,
        "compose.yaml",
        (
            "services:\n"
            "  app:\n"
            "    image: alpine\n"
            f"    command: [{hex_big}]\n"
            "    environment:\n"
            f"      MAX_WEIGHT: {hex_big}\n"
            f"      SOME_INT: {hex_big}\n"
        ),
    )
    comp_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_compose_sources(comp_repo, ".", comp_res)
    assert comp_res.coverage_complete is False

    k8s_repo = tmp_path / "k8s_hex"
    _write(
        k8s_repo,
        "deploy.yaml",
        (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: web\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: app\n"
            "        image: alpine\n"
            f"        command: [{hex_big}]\n"
            "        env:\n"
            "        - name: MAX_WEIGHT\n"
            f"          value: {hex_big}\n"
        ),
    )
    _write(
        k8s_repo,
        "k8s/cm.yaml",
        (
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            "  name: cfg\n"
            "data:\n"
            f"  MAX_WEIGHT: {hex_big}\n"
        ),
    )
    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_k8s_sources(k8s_repo, ".", k8s_res)
    assert k8s_res.coverage_complete is False

    reg_repo = tmp_path / "reg_hex"
    _write(reg_repo, "config/rules.yaml", f"rules:\n  a:\n    ? {hex_big}\n    : true\n")
    truth_nodes, sym_map = extract_registry_truth_nodes(reg_repo)
    assert truth_nodes == []
    assert sym_map == {}
    reg_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    add_registry_sources(reg_repo, reg_res, {})
    assert reg_res.coverage_complete is False

    po_repo = tmp_path / "po_hex"
    _write(
        po_repo,
        "docker-compose.yml",
        f"services:\n  web:\n    ports: [{hex_big}]\n  ? {hex_big}\n  : {{ports: ['8080:80']}}\n",
    )
    _write(
        po_repo,
        "k8s.yaml",
        (
            "apiVersion: v1\n"
            "kind: Service\n"
            "metadata:\n"
            f"  name: {hex_big}\n"
            "spec:\n"
            "  ports:\n"
            "  - port: 80\n"
        ),
    )
    assert extract_declared_ports(po_repo) == []

    # 3. otel_ebpf sql.values redaction in eBPF SQL flows
    ebpf_file = _write(
        tmp_path,
        "ebpf_sql.jsonl",
        json.dumps(
            {
                "sql": {
                    "query": "WITH x AS (SELECT 1) SELECT * FROM users WHERE pin = 's3cr3t' AND id = 42",
                    "values": ["secret_val_1", "secret_val_2"],
                }
            }
        )
        + "\n",
    )
    flows, r_cnt = parse_ebpf_flows(ebpf_file, repo_root=tmp_path)
    assert len(flows) == 1
    assert r_cnt >= 3
    dumped = json.dumps([flows[0].attributes, flows[0].redacted_summary])
    for leaked in ("secret_val_1", "secret_val_2", "s3cr3t"):
        assert leaked not in dumped
    assert flows[0].attributes.get("values") == ["[REDACTED_BUFFER]", "[REDACTED_BUFFER]"]
    assert flows[0].attributes["sql"]["values"] == ["[REDACTED_BUFFER]", "[REDACTED_BUFFER]"]  # type: ignore[index]


def test_r6_wiretap_sql_values_all_shapes_otel_spans_type_and_path_bounds(tmp_path: Path) -> None:
    # 1. Flat OTLP {"spans": [...]} without "attributes" wrapper
    flat_otel = _write(
        tmp_path,
        "flat_spans.json",
        json.dumps(
            {
                "spans": [
                    {
                        "name": "SELECT users",
                        "db.system": "postgresql",
                        "db.statement": "SELECT * FROM users WHERE pin = $1",
                        "values": ["SEC_FLAT_1"],
                    }
                ]
            }
        ),
    )
    flat_tr, flat_red = parse_otel_traces(flat_otel, repo_root=tmp_path)
    assert len(flat_tr) == 1 and flat_red >= 1
    assert "SEC_FLAT_1" not in json.dumps(flat_tr[0].attributes)
    assert flat_tr[0].attributes.get("values") == ["[REDACTED_BUFFER]"]

    # 2. parse_ebpf_flows with "name", "db.statement", and "values"
    ebpf_named = _write(
        tmp_path,
        "ebpf_named.jsonl",
        json.dumps(
            {
                "name": "sql_flow",
                "db.system": "postgresql",
                "db.statement": "SELECT * FROM users WHERE pin = $1",
                "values": ["SEC_EBPF_2"],
            }
        )
        + "\n",
    )
    ebpf_tr, ebpf_red = parse_ebpf_flows(ebpf_named, repo_root=tmp_path)
    assert len(ebpf_tr) == 1 and ebpf_red >= 1
    assert "SEC_EBPF_2" not in json.dumps(ebpf_tr[0].attributes)
    assert ebpf_tr[0].attributes.get("values") == ["[REDACTED_BUFFER]"]

    # 3. Inline SQL in "name" only
    out_inline, cnt_inline = redact_attributes(
        {"name": "SELECT * FROM users WHERE id = $1", "values": ["SEC_INLINE_3"]}
    )
    assert cnt_inline >= 1
    assert out_inline["values"] == ["[REDACTED_BUFFER]"]

    # 4-6. resourceSpans: KV "name"+"db.statement"+"values", plain-dict "params", SQL span.name + KV "values"
    res_otel = _write(
        tmp_path,
        "res_spans.json",
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "api"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "pg",
                                        "attributes": [
                                            {"key": "name", "value": {"stringValue": "pg_query"}},
                                            {"key": "db.statement", "value": {"stringValue": "SELECT ?"}},
                                            {
                                                "key": "values",
                                                "value": {"arrayValue": {"values": [{"stringValue": "SEC_RES_4"}]}},
                                            },
                                        ],
                                    },
                                    {
                                        "name": "pg_dict",
                                        "attributes": [
                                            {"key": "db.statement", "value": {"stringValue": "SELECT ?"}},
                                            {"key": "params", "value": {"bind": {"values": ["SEC_PLAIN_5"]}}},
                                        ],
                                    },
                                    {
                                        "name": "SELECT * FROM users WHERE id = $1",
                                        "attributes": [
                                            {
                                                "key": "values",
                                                "value": {"arrayValue": {"values": [{"stringValue": "SEC_SPAN_6"}]}},
                                            }
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
    )
    res_tr, res_red = parse_otel_traces(res_otel, repo_root=tmp_path)
    assert len(res_tr) == 3 and res_red >= 3
    res_dump = json.dumps([t.attributes for t in res_tr])
    for leaked in ("SEC_RES_4", "SEC_PLAIN_5", "SEC_SPAN_6"):
        assert leaked not in res_dump

    # 7. Nested sub-dicts: params.values, sql.bind.values, params.bind.values, sql list, named stmt, l7.sql.bind.values
    nested_shapes = [
        {"db.system": "postgresql", "db.statement": "SELECT ?", "params": {"values": ["SEC_N1"]}},
        {"sql": {"query": "SELECT ?", "bind": {"values": ["SEC_N2"]}}},
        {"name": "SELECT", "db.system": "pg", "params": {"bind": {"values": ["SEC_N3"]}}},
        {"sql": [{"values": ["SEC_N4"]}]},
        {"sql": {"name": "get_pin", "values": ["SEC_N5"]}},
        {"l7": {"sql": {"bind": {"values": ["SEC_N6"]}}}},
    ]
    for shape in nested_shapes:
        cleaned, cnt = redact_attributes(shape)
        assert cnt >= 1
        assert "SEC_N" not in json.dumps(cleaned)

    # 8. Sibling KV list in redact_attributes
    kv_sib, kv_sib_cnt = redact_attributes(
        {
            "attributes": [
                {"key": "db.statement", "value": "SELECT 1"},
                {"key": "values", "value": ["SEC_SIB_1"], "values": ["SEC_SIB_2"]},
            ]
        }
    )
    assert kv_sib_cnt >= 2
    assert "SEC_SIB_" not in json.dumps(kv_sib)

    # 9. Top-level KV pair with sql.values
    top_kv, top_kv_cnt = redact_attributes({"key": "sql.values", "values": ["SEC_TOP_KV"]})
    assert top_kv_cnt >= 1
    assert top_kv["values"] == ["[REDACTED_BUFFER]"]

    # 10. Non-SQL KV preservation (top-level, nested, and inside SQL span)
    pres_key, cnt_pk = redact_attributes({"key": "items", "values": ["ok_item"]})
    pres_name, cnt_pn = redact_attributes({"name": "items", "values": ["ok_item"]})
    pres_nest, cnt_pnest = redact_attributes({"items_kv": {"key": "items", "values": ["ok_item"]}})
    pres_sql, cnt_psql = redact_attributes(
        {
            "db.system": "pg",
            "db.statement": "SELECT ?",
            "extra": {"key": "items", "values": ["ok_item"]},
        }
    )
    assert cnt_pk == 0 and pres_key["values"] == ["ok_item"]
    assert cnt_pn == 0 and pres_name["values"] == ["ok_item"]
    assert cnt_pnest == 0 and pres_nest["items_kv"] == {"key": "items", "values": ["ok_item"]}
    assert cnt_psql == 0 and pres_sql["extra"] == {"key": "items", "values": ["ok_item"]}

    # 11. parse_otel_traces non-list spans raises ValueError (never TypeError or char iteration)
    for bad_spans in ({"spans": 123}, {"spans": "bad"}):
        bad_file = _write(tmp_path, "bad_spans.json", json.dumps(bad_spans))
        with pytest.raises(ValueError, match="Unrecognized OTLP trace schema"):
            parse_otel_traces(bad_file, repo_root=tmp_path)

    # 12. validate_non_symlink_path rejects >255-byte segment with ValueError
    with pytest.raises(ValueError, match="255 bytes"):
        validate_non_symlink_path("a" * 300, repo_root=tmp_path)


def test_r6_path_stat_enametoolong_nul_and_python_inspector_hex_int(tmp_path: Path) -> None:
    long300 = "a" * 300
    long253 = "a" * 253
    hex900 = str((1 << 900) - 1)
    oct_big = "0o" + ("7" * 1400)

    # 1. Dockerfile with and without COPY . /app, nested Dockerfile, COPY NUL/long, and long Python import
    df_copy_repo = tmp_path / "df_copy"
    _write(df_copy_repo, "app.py", f"import {long253}\n")
    _write(
        df_copy_repo,
        "Dockerfile",
        (
            "FROM python:3.12\n"
            "COPY . /app\n"
            f"COPY {long300} /app/\n"
            "COPY foo\\x00bar /app/\n"
            f'CMD ["{long300}", "{long253}.js", "python", "-m", "{long300}"]\n'
        ),
    )
    _write(df_copy_repo, "sub/Dockerfile", f"FROM alpine\nCOPY {long300} /app/\n")
    df_res1 = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_dockerfile_sources(df_copy_repo, ".", df_res1)

    df_nocopy_repo = tmp_path / "df_nocopy"
    _write(
        df_nocopy_repo,
        "Dockerfile",
        f'FROM python:3.12\nCMD ["{long300}", "{long253}.js", "foo\\x00bar"]\n',
    )
    df_res2 = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_dockerfile_sources(df_nocopy_repo, ".", df_res2)

    # 2. Compose build.context/build.dockerfile/volumes/command (900-bit int, 0o, 300-char, NUL)
    comp_repo = tmp_path / "comp_long"
    _write(
        comp_repo,
        "compose.yaml",
        (
            "services:\n"
            "  web:\n"
            "    build:\n"
            '      context: "."\n'
            f'      dockerfile: "{long300}"\n'
            "    volumes:\n"
            f'      - "./{long300}:/app"\n'
            '      - "./foo\\0bar:/app2"\n'
            f'    command: [{hex900}, "{oct_big}", "{long300}", "foo\\0bar"]\n'
            "  ctx:\n"
            "    build:\n"
            f'      context: "{long300}"\n'
            "    image: alpine\n"
        ),
    )
    comp_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_compose_sources(comp_repo, ".", comp_res)

    # 3. K8s Deployment + compose bridge with long dockerfile/command
    k8s_repo = tmp_path / "k8s_long"
    _write(
        k8s_repo,
        "compose.yaml",
        (
            "services:\n"
            "  web:\n"
            "    image: web:latest\n"
            "    build:\n"
            '      context: "."\n'
            f'      dockerfile: "{long300}"\n'
        ),
    )
    _write(
        k8s_repo,
        "k8s/deploy.yaml",
        (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: web\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: app\n"
            "        image: web:latest\n"
            f'        command: [{hex900}, "{oct_big}", "{long300}", "{long253}.js", "python", "-m", "{long300}"]\n'
        ),
    )
    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_k8s_sources(k8s_repo, ".", k8s_res)

    # 4. Container launchers: .sh (--env-file, -v, docker build -f), launchd .plist, systemd .service, compose bridge
    cl_repo = tmp_path / "cl_long"
    _write(
        cl_repo,
        "compose.yaml",
        f'services:\n  web:\n    image: myimg\n    build:\n      context: "."\n      dockerfile: "{long300}"\n',
    )
    _write(
        cl_repo,
        "scripts/run.sh",
        (
            "#!/bin/sh\n"
            f"docker run --env-file ./{long300} -v ./{long300}:/app myimg python {long300}.py\n"
            f"docker build -f {long300} .\n"
        ),
    )
    (cl_repo / "LaunchAgents").mkdir(parents=True, exist_ok=True)
    (cl_repo / "LaunchAgents/a.plist").write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.long",
                "ProgramArguments": [f"/usr/bin/{long300}", f"{long300}.py"],
            }
        )
    )
    _write(
        cl_repo,
        "systemd/a.service",
        (
            "[Service]\n"
            f"WorkingDirectory=./{long300}\n"
            f"EnvironmentFile=./{long300}\n"
            f"ExecStart=/usr/bin/{long300}\n"
        ),
    )
    cl_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_container_launchers(cl_repo, ".", cl_res)

    # 5. tach_bridge.parse_tach_toml skips bad source_roots while retaining valid "."
    tach_repo = tmp_path / "tach_long"
    tach_toml = _write(
        tach_repo,
        "tach.toml",
        f'source_roots = ["{long300}", "foo\\u0000bar", "."]\n',
    )
    cfg = parse_tach_toml(tach_toml, tach_repo)
    assert cfg.source_roots == (tach_repo.resolve(),)
    tach_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_tach_boundaries(tach_repo, ".", tach_res)

    # 6. python_inspector >4300-digit 0x hex integer literal in TOOLS and f-strings
    hex_big = "0x" + ("f" * 5000)
    b1 = inspect_python_module_ast(
        "a.py", f'TOOLS = [{{"name": "t1", "description": "d", "x": {hex_big}}}]\n'
    )
    b2 = inspect_python_module_ast(
        "a.py",
        f'X = {hex_big}\nTOOLS = [{{"name": "t1", "description": f"d {{{hex_big}}} {{X}}"}}]\n',
    )
    b3 = inspect_python_module_ast(
        "a.py",
        f'import requests\ndef call():\n    return requests.post(f"/v1/chat/completions/{{{hex_big}}}")\n',
    )
    assert len(b1.manifests) == 1 and len(b2.manifests) == 1 and b3 is not None
    byte_len, tok_len = estimate_schema_budget([{"x": int(hex_big, 16)}])
    assert byte_len > 0 and tok_len >= 1


def _mkdir_deep_chain(base: Path, segments: list[str]) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    cur_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for seg in segments:
            try:
                os.mkdir(seg, 0o755, dir_fd=cur_fd)
            except FileExistsError:
                pass
            nxt_fd = os.open(seg, os.O_RDONLY | os.O_DIRECTORY, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
    finally:
        os.close(cur_fd)
    out = base
    for seg in segments:
        out = out / seg
    return out


def test_r7_wiretap_mixed_case_kv_depth_and_huge_int_guard() -> None:
    # 1. Mixed-case KV dict keys scrubbed properly
    mc_pw, cnt_pw = redact_attributes({"KEY": "password", "VALUE": "hunter2"})
    assert cnt_pw == 1
    assert mc_pw == {"KEY": "password", "VALUE": "[REDACTED]"}

    mc_sql1, cnt_sql1 = redact_attributes(
        {"Key": "values", "Values": ["SECRET_MC"]},
        inherited_sql_context=True,
    )
    assert cnt_sql1 == 1
    assert mc_sql1 == {"Key": "values", "Values": ["[REDACTED_BUFFER]"]}

    mc_sql2, cnt_sql2 = redact_attributes(
        {"key": "values", "Values": ["SECRET_MC2"]},
        inherited_sql_context=True,
    )
    assert cnt_sql2 == 1
    assert mc_sql2 == {"key": "values", "Values": ["[REDACTED_BUFFER]"]}

    # 2. Mixed-case non-SQL KV pairs remain untouched
    ok1, cnt_ok1 = redact_attributes({"Key": "items", "Values": ["ok_item"]})
    ok2, cnt_ok2 = redact_attributes({"Name": "items", "Values": ["ok_item"]})
    assert cnt_ok1 == 0 and ok1 == {"Key": "items", "Values": ["ok_item"]}
    assert cnt_ok2 == 0 and ok2 == {"Name": "items", "Values": ["ok_item"]}

    # 3. _otel_kv_list_to_dict mixed-case KV items
    kv_dict = _otel_kv_list_to_dict(
        [
            {"Key": "db.statement", "Value": {"stringValue": "SELECT * FROM u WHERE p = 'SEC_KV'"}},
            {"Key": "values", "Values": ["SEC_VAL_KV"]},
        ]
    )
    assert "db.statement" in kv_dict and "values" in kv_dict
    red_kv, red_kv_cnt = redact_attributes(kv_dict)
    assert red_kv_cnt >= 2
    assert "SEC_KV" not in json.dumps(red_kv)
    assert "SEC_VAL_KV" not in json.dumps(red_kv)

    # 4. In-memory 1100-level nested dict & >4300-digit int do not raise RecursionError/ValueError
    deep_dict: dict[str, object] = {"password": "secret"}
    for _ in range(1100):
        deep_dict = {"nested": deep_dict}
    red_deep, cnt_deep = redact_attributes(deep_dict)
    assert cnt_deep >= 1
    assert "secret" not in json.dumps(red_deep)
    assert "REDACTED_NESTED" in json.dumps(red_deep)

    huge_int = 10**5000
    tr, _ = _transition_from_attr_dict(
        "otel",
        "svc",
        "op",
        {"db.statement": huge_int, "http.method": "GET", "url.path": "/ok"},
    )
    assert tr is not None and tr.http_method == "GET"


def test_r7_public_parse_entrypoints_and_deep_enametoolong_trees(tmp_path: Path) -> None:
    try:
        path_max = max(1024, min(int(os.pathconf(tmp_path, "PC_PATH_MAX")), 8192))
    except (AttributeError, OSError, ValueError):
        path_max = 4096
    long300 = "a" * 300
    deep_segs = ["d" * 200 for _ in range((path_max // 200) + 3)]
    deep_rel = Path(*deep_segs)

    # 1. Direct calls to 4 public parse_* entrypoints (plus parse_dockerfile) with >255B, >PATH_MAX, and NUL
    for bad_rel in (Path(long300), deep_rel / "item", Path("foo\x00bar")):
        comp_parsed, comp_err = parse_compose_file(tmp_path / bad_rel, tmp_path)
        assert comp_parsed is None and comp_err is not None

        k8s_parsed = parse_k8s_manifests(tmp_path / bad_rel, tmp_path)
        assert k8s_parsed.parse_error is not None and k8s_parsed.resources == ()

        assert parse_systemd_unit(tmp_path / bad_rel, tmp_path) is None

        ld_parsed, ld_err = parse_launchd_plist(tmp_path / bad_rel, tmp_path)
        assert ld_parsed is None and ld_err is not None

        assert parse_dockerfile(tmp_path / bad_rel, tmp_path) is None

    # 2. port_occupancy.extract_declared_ports rejects >255B / NUL repo_root with ValueError, missing returns []
    assert extract_declared_ports(tmp_path / "does_not_exist") == []
    with pytest.raises(ValueError, match="255 bytes"):
        extract_declared_ports(tmp_path / long300)
    with pytest.raises(ValueError, match="NUL"):
        extract_declared_ports(tmp_path / "foo\x00bar")

    # 3. Real >PATH_MAX nested on-disk directory trees do not crash any M4 adapter or plugin
    df_repo = tmp_path / "deep_df"
    _mkdir_deep_chain(df_repo, deep_segs)
    df_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_dockerfile_sources(df_repo, ".", df_res)
    assert df_res.coverage_complete is False

    k8s_repo = tmp_path / "deep_k8s"
    _mkdir_deep_chain(k8s_repo / "k8s", deep_segs)
    k8s_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_k8s_sources(k8s_repo, ".", k8s_res)
    assert k8s_res.coverage_complete is False

    cl_repo = tmp_path / "deep_cl"
    _mkdir_deep_chain(cl_repo, deep_segs)
    cl_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_container_launchers(cl_repo, ".", cl_res)
    assert cl_res.coverage_complete is False

    comp_base = tmp_path / "deep_comp"
    comp_base.mkdir(parents=True, exist_ok=True)
    comp_base_real = comp_base.resolve()
    comp_root_segs: list[str] = []
    cur_len = len(str(comp_base_real))
    while cur_len + 181 < path_max - 180:
        comp_root_segs.append("c" * 180)
        cur_len += 181
    pad_len = max(1, min(200, (path_max - 160) - cur_len - 1))
    comp_root_segs.append("c" * pad_len)
    comp_deep_root = _mkdir_deep_chain(comp_base_real, comp_root_segs)
    sub_len = max(1, min(200, (path_max - 6) - len(str(comp_deep_root)) - 1))
    comp_sub_seg = "s" * sub_len
    comp_sub_dir = _mkdir_deep_chain(comp_deep_root, [comp_sub_seg])
    sub_fd = os.open(comp_deep_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        s2_fd = os.open(comp_sub_seg, os.O_RDONLY | os.O_DIRECTORY, dir_fd=sub_fd)
        try:
            cf_fd = os.open("compose.yaml", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644, dir_fd=s2_fd)
            try:
                os.write(cf_fd, b"services:\n  web:\n    image: nginx:1\n")
            finally:
                os.close(cf_fd)
        finally:
            os.close(s2_fd)
    finally:
        os.close(sub_fd)
    assert len(str(comp_sub_dir)) < path_max
    assert len(str(comp_sub_dir / "compose.yaml")) > path_max
    comp_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_compose_sources(comp_deep_root, ".", comp_res)
    assert comp_res.coverage_complete is False

    tach_repo = tmp_path / "deep_tach"
    _write(tach_repo, "tach.toml", 'source_roots = ["."]\n')
    _mkdir_deep_chain(tach_repo, deep_segs)
    tach_res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_tach_boundaries(tach_repo, ".", tach_res)
    assert tach_res.coverage_complete is False

    cp_repo = tmp_path / "deep_cp"
    _write(cp_repo, "ok.py", "from ortools.sat.python import cp_model\n")
    _mkdir_deep_chain(cp_repo, deep_segs)
    cp_ext = extract_repo_cpsat_models(cp_repo)
    assert "ok.py" in cp_ext.modules

    ah_repo = tmp_path / "deep_ah"
    _write(ah_repo, "ok.py", 'TOOLS = [{"name": "t", "description": "d"}]\n')
    _mkdir_deep_chain(ah_repo, deep_segs)
    ah_bundle = inspect_python_files(ah_repo)
    assert len(ah_bundle.manifests) == 1 and ah_bundle.skipped_files >= 1

    po_repo = tmp_path / "deep_po"
    _write(po_repo, "compose.yaml", 'services:\n  api:\n    ports:\n      - "127.0.0.1:8099:8099"\n')
    _mkdir_deep_chain(po_repo, deep_segs)
    po_decls = extract_declared_ports(po_repo)
    assert any(d.port == 8099 for d in po_decls)


def test_r7_extract_registry_truth_nodes_surfaces_unreadable_coverage(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("commands:\n  a:\n    command: x.py\n", encoding="utf-8")

    # 1. Clean registry -> coverage_complete=True, unreadable_count=0, 2-tuple unpack works
    ok_repo = tmp_path / "reg_ok"
    _write(ok_repo, "config/routing.yaml", "providers:\n  local:\n    enabled: true\n")
    ok_res = extract_registry_truth_nodes(ok_repo)
    ok_nodes, ok_sym = ok_res
    assert len(ok_nodes) == 1
    assert "config/routing.yaml" in ok_sym
    assert ok_res.coverage_complete is True
    assert ok_res.unreadable_count == 0
    assert ok_res.notes == []

    # 2. Symlink and FIFO in config/ -> coverage_complete=False, unreadable_count >= 1, notes populated
    sym_repo = tmp_path / "reg_sym_truth"
    (sym_repo / "config").mkdir(parents=True, exist_ok=True)
    (sym_repo / "config" / "link.yaml").symlink_to(outside)
    notes_out: list[str] = []
    cov_out: list[bool] = []
    sym_res = extract_registry_truth_nodes(sym_repo, notes_out=notes_out, coverage_out=cov_out)
    sym_nodes, sym_map = sym_res
    assert sym_nodes == [] and sym_map == {}
    assert sym_res.coverage_complete is False
    assert sym_res.unreadable_count >= 1
    assert sym_res.notes and notes_out == sym_res.notes
    assert cov_out == [False]

    fifo_repo = tmp_path / "reg_fifo_truth"
    (fifo_repo / "config").mkdir(parents=True, exist_ok=True)
    os.mkfifo(fifo_repo / "config" / "pipe.yaml")
    fifo_res = extract_registry_truth_nodes(fifo_repo)
    assert fifo_res.coverage_complete is False
    assert fifo_res.unreadable_count >= 1
    assert fifo_res.notes


def test_r8_extract_repo_cpsat_models_hostile_repo_roots(tmp_path: Path) -> None:
    real_target = tmp_path / "real_target"
    _write(real_target, "model.py", "from ortools.sat.python import cp_model\n")
    symlink_root = tmp_path / "sym_root"
    symlink_root.symlink_to(real_target)

    try:
        path_max = max(1024, min(int(os.pathconf(tmp_path, "PC_PATH_MAX")), 8192))
    except (AttributeError, OSError, ValueError):
        path_max = 4096
    deep_segs = ["d" * 200 for _ in range((path_max // 200) + 3)]
    deep_root = _mkdir_deep_chain(tmp_path / "deep_root_parent", deep_segs)
    assert len(str(deep_root)) > path_max

    hostile_roots: list[Path | str] = [
        f"{tmp_path}/bad\x00root",
        tmp_path / "bad\x00root",
        symlink_root,
        tmp_path / ("a" * 300),
        deep_root,
    ]
    for bad_root in hostile_roots:
        res = extract_repo_cpsat_models(bad_root)
        assert isinstance(res, CpSatRepoExtraction)
        assert res.repo_root == str(bad_root)
        assert res.modules == {}
        assert res.registered_builders == ()
        assert res.unregistered_builders == ()
        assert res.registration_order == ()
