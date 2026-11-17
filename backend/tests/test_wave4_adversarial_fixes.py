"""Regression tests for Wave 4 adversarial review findings (Pillars 1-5)."""

from __future__ import annotations

import importlib.metadata
import json
import plistlib
import subprocess
import time
from pathlib import Path

import pytest

from app.adapters.plugin_registry import ENTRY_POINT_GROUP
from app.cli import main as cli_main
from wythe_plugin_agent_harness import register_wythe_plugin as register_agent_harness
from wythe_plugin_apple_ipc import APPLE_IPC_PLUGIN, parse_safe_plist_bytes
from wythe_plugin_binary import BINARY_INSPECTION_PLUGIN
from wythe_plugin_compiler_ir import COMPILER_IR_PLUGIN, parse_usr_index
from wythe_plugin_compiler_ir.metal_air import extract_host_metal_dispatches
from wythe_plugin_cpsat import register_wythe_plugin as register_cpsat
from wythe_plugin_solver_chronicle import register_wythe_plugin as register_solver_chronicle
from wythe_plugin_solver_internals import SOLVER_INTERNALS_PLUGIN
from wythe_plugin_solver_internals.proto_descriptor import parse_proto_source_text

REPO_ROOT = Path(__file__).resolve().parents[2]


class _FakeEP:
    def __init__(self, name: str, loaded: object) -> None:
        self.name = name
        self.value = f"pkg:{name}"
        self._loaded = loaded
        self.dist = type("_Dist", (), {"version": "0.1.0"})()

    def load(self) -> object:
        return self._loaded


def _all_seven_entry_points() -> list[_FakeEP]:
    return [
        _FakeEP("agent-harness", register_agent_harness),
        _FakeEP("apple_ipc", APPLE_IPC_PLUGIN),
        _FakeEP("binary", BINARY_INSPECTION_PLUGIN),
        _FakeEP("compiler_ir", COMPILER_IR_PLUGIN),
        _FakeEP("cpsat", register_cpsat),
        _FakeEP("solver-chronicle", register_solver_chronicle),
        _FakeEP("solver_internals", SOLVER_INTERNALS_PLUGIN),
    ]


def _make_mini_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "mini_repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/api/v1/items')\ndef list_items(db=None):\n    return []\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text(
        '{"dependencies": {"next": "15.0.0"}}', encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "api-generated.ts").write_text(
        "export interface paths {}\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { void fetch('/api/v1/items'); return <main><h1>Items</h1></main>; }\n",
        encoding="utf-8",
    )
    git_env = {
        "GIT_AUTHOR_NAME": "Euda1mon1a",
        "GIT_AUTHOR_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Euda1mon1a",
        "GIT_COMMITTER_EMAIL": "214782221+Euda1mon1a@users.noreply.github.com",
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=git_env)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=git_env)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        env=git_env,
    )
    return repo


def test_self_gate_and_digest_invariance_with_all_seven_plugins_enabled(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Pillar 1 & 3: Self-scan of Wythe repo passes strict gate & keeps identical Zoom-1 digest with all 7 plugins."""
    assert isolated_db_url.startswith("sqlite:")
    core_json = tmp_path / "self_core.json"
    all_json = tmp_path / "self_all.json"

    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])
    assert cli_main(["scan", "--strict", str(REPO_ROOT), "--json", str(core_json)]) == 0
    assert cli_main(["gate", "--strict", str(REPO_ROOT)]) == 0
    capsys.readouterr()

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: _all_seven_entry_points() if kw.get("group") == ENTRY_POINT_GROUP else [],
    )
    assert cli_main(["scan", "--strict", str(REPO_ROOT), "--json", str(all_json)]) == 0
    assert cli_main(["gate", "--strict", str(REPO_ROOT)]) == 0
    capsys.readouterr()

    doc_core = json.loads(core_json.read_text(encoding="utf-8"))
    doc_all = json.loads(all_json.read_text(encoding="utf-8"))
    assert doc_all["gate"]["verdict"] == "PASS"
    assert doc_all["summary"]["blocking_findings"] == 0
    assert doc_all["content_digest"] == doc_core["content_digest"]


def test_python_string_fixtures_and_comments_do_not_emit_fake_metal_dispatches(
    tmp_path: Path,
) -> None:
    """Verify `.py` string fixtures/comments are masked while real Python Metal dispatches & test-named artifact dirs work."""
    fixture_py = (
        '"""Docstring mentioning MTL and lib.makeFunction(name: "doc_fake")."""\n'
        '# Comment: enc.setBuffer(a, offset: 0, index: 0) makeFunction(name: "comment_fake")\n'
        'SWIFT_SNIPPET = \'let fn = lib.makeFunction(name: "swift_fake")\\nenc.setBuffer(a, offset: 0, index: 0)\'\n'
        'OBJC_SNIPPET = \'[lib newFunctionWithName:@"objc_fake"];\'\n'
    )
    disps_clean, _ = extract_host_metal_dispatches(
        fixture_py, source_file="app/generator.py", language="python"
    )
    assert disps_clean == []

    real_py = (
        "def run_kernels(mx, op):\n"
        '    k1 = mx.fast.metal_kernel(name="real_static_kernel", source="[[kernel]] void f() {}")\n'
        '    k2 = mx.fast.metal_kernel(name=f"dyn_{op}")\n'
        "    return k1, k2\n"
    )
    disps_real, _ = extract_host_metal_dispatches(
        real_py, source_file="app/mlx_ops.py", language="python"
    )
    assert len(disps_real) == 2
    assert disps_real[0].kernel_name == "real_static_kernel"
    assert disps_real[0].is_dynamic_kernel is False
    assert disps_real[1].is_dynamic_kernel is True

    # Explicit artifact directory inside a path named `tests` must still walk cleanly:
    idx_dir = tmp_path / "tests" / "index_dumps" / "tests"
    idx_dir.mkdir(parents=True)
    (idx_dir / "unit.json").write_text(
        json.dumps(
            {
                "symbols": [
                    {
                        "usr": "c:@F@helper_fn",
                        "name": "helper_fn",
                        "kind": "function",
                        "language": "c",
                        "file": "src/helper.c",
                        "line": 3,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    parsed_idx = parse_usr_index(idx_dir)
    assert "c:@F@helper_fn" in parsed_idx.symbols_by_usr


def test_parse_proto_source_text_linear_time_on_large_tokens() -> None:
    """Pillar 4 & 5: Verify O(N) runtime (< 0.15s) on 80 KB and 200 KB identifiers."""
    for size in (80_000, 200_000):
        proto_src = (
            'syntax = "proto2";\n'
            "message ConstraintProto {\n"
            f"  optional {'x' * size} f = 1;\n"
            "}\n"
        )
        t0 = time.perf_counter()
        parsed = parse_proto_source_text(proto_src)
        elapsed = time.perf_counter() - t0
        assert "ConstraintProto" in parsed
        assert elapsed < 0.15, f"O(N^2) regression: {size}-byte token took {elapsed:.3f}s"


def test_cli_symlink_xxe_and_missing_plugin_flags_fail_closed_exit_2(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Pillar 5: Symlink/XXE artifacts and missing-plugin flags must return exit code 2 across CLI commands."""
    assert isolated_db_url.startswith("sqlite:")
    repo = _make_mini_repo(tmp_path)
    real_file = tmp_path / "real_artifact.txt"
    real_file.write_text("placeholder\n", encoding="utf-8")
    sym_file = tmp_path / "symlink_artifact"
    sym_file.symlink_to(real_file)
    xxe_entitlements = tmp_path / "xxe.entitlements"
    xxe_entitlements.write_text(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE plist SYSTEM "http://127.0.0.1:9999/evil.dtd">\n'
        "<plist version=\"1.0\"><dict><key>a</key><true/></dict></plist>\n",
        encoding="utf-8",
    )

    # 3B: Missing plugins -> fail closed (rc=2) with clear install guidance on stderr
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])
    missing_cases = [
        (["companion", str(repo), "--metallib", str(real_file)], "wythe-plugin-compiler-ir"),
        (["security", "companion", str(repo), "--sil", str(real_file)], "wythe-plugin-compiler-ir"),
        (["scan", str(repo), "--sil", str(real_file)], "wythe-plugin-compiler-ir"),
        (["scan", str(repo), "--llvm-ir", str(real_file)], "wythe-plugin-compiler-ir"),
        (["scan", str(repo), "--index-store", str(real_file)], "wythe-plugin-compiler-ir"),
        (["gate", "--strict", str(repo), "--compile-commands", str(real_file)], "wythe-plugin-solver-internals"),
        (["diff", str(repo), "--base", "HEAD", "--proto-descriptor", str(real_file)], "wythe-plugin-solver-internals"),
        (["context", str(repo), "items", "--zoom", "3", "--binary", str(real_file)], "wythe-plugin-binary"),
    ]
    for argv, expected_pkg in missing_cases:
        rc = cli_main(argv)
        err = capsys.readouterr().err
        assert rc == 2, f"Expected rc=2 for {argv}, got {rc}"
        assert expected_pkg in err

    # 3A: With all plugins enabled, symlink & XXE artifacts -> fail closed (rc=2)
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: _all_seven_entry_points() if kw.get("group") == ENTRY_POINT_GROUP else [],
    )
    bad_artifact_cases = [
        ["gate", "--strict", str(repo), "--binary", str(sym_file)],
        ["gate", "--strict", str(repo), "--binary", str(xxe_entitlements)],
        ["gate", "--strict", str(repo), "--metallib", str(sym_file)],
        ["scan", str(repo), "--proto-descriptor", str(sym_file)],
        ["diff", str(repo), "--base", "HEAD", "--compile-commands", str(sym_file)],
        ["context", str(repo), "items", "--zoom", "3", "--binary", str(sym_file)],
        ["context", str(repo), "items", "--zoom", "2", "--sil", str(sym_file)],
        ["companion", str(repo), "--metallib", str(sym_file)],
        ["security", "companion", str(repo), "--sil", str(sym_file)],
    ]
    for argv in bad_artifact_cases:
        rc = cli_main(argv)
        capsys.readouterr()
        assert rc == 2, f"Expected fail-closed rc=2 for {argv}, got {rc}"


def test_parse_safe_plist_bytes_rejects_external_doctype_and_subsets() -> None:
    """Pillar 2 & 5: Reject external SYSTEM/PUBLIC DTDs, internal subsets, and custom entities."""
    apple_header_plist = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        b'<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>'
    )
    assert parse_safe_plist_bytes(apple_header_plist) == {"com.apple.security.app-sandbox": True}

    bplist_payload = plistlib.dumps({"Label": "com.example.daemon"}, fmt=plistlib.FMT_BINARY)
    assert parse_safe_plist_bytes(bplist_payload) == {"Label": "com.example.daemon"}

    rejected_payloads = [
        b'<?xml version="1.0"?>\n<!DOCTYPE plist SYSTEM "http://127.0.0.1:9999/evil.dtd">\n<plist version="1.0"><dict><key>a</key><true/></dict></plist>',
        b'<?xml version="1.0"?>\n<!DOCTYPE plist PUBLIC "-//Evil//DTD PLIST 1.0//EN" "http://127.0.0.1:9999/evil.dtd">\n<plist version="1.0"><dict><key>a</key><true/></dict></plist>',
        b'<?xml version="1.0"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" [<!ELEMENT x ANY>]>\n<plist version="1.0"><dict/></plist>',
        b'<?xml version="1.0"?>\n<plist version="1.0"><dict><key>a</key><string>&custom_ent;</string></dict></plist>',
    ]
    for payload in rejected_payloads:
        with pytest.raises(ValueError, match="(?i)doctype|entity|xxe"):
            parse_safe_plist_bytes(payload, source_label="adversarial.plist")
