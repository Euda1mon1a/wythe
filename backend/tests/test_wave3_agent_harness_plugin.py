"""Tests for optional `wythe-plugin-agent-harness` companion package (`AGENT-001..003`)."""

from __future__ import annotations

import json
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO_ROOT / "plugins" / "wythe-plugin-agent-harness" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from app.adapters.base import ManipulatorExtractionResult
from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    discover_plugins,
    list_registered_plugins,
    run_manipulator_plugins,
)
from app.schemas.atlas import (
    AtlasSummaryStats,
    GateEvaluation,
    LegacyBridgeSummary,
    TruthAtlasReport,
)
from wythe_plugin_agent_harness import (
    WYTHE_PLUGIN,
    AgentHarnessPlugin,
    register_wythe_plugin,
)


class _FakeDist:
    def __init__(self, version: str = "0.1.0") -> None:
        self.version = version


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, target: object, version: str = "0.1.0") -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist(version)
        self._target = target

    def load(self) -> object:
        return self._target


def _empty_report(repo_root: Path, notes: list[str] | None = None) -> TruthAtlasReport:
    ts = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)
    return TruthAtlasReport(
        target_slug="harness-demo",
        target_name="Harness Demo",
        repo_path=str(repo_root),
        stack_profile="fastapi-sqlalchemy-nextjs",
        source_commit="860c38d",
        observed_at=ts,
        valid_until=ts,
        observation_source="static_ast",
        content_digest="0" * 64,
        scan_notes=list(notes or []),
        summary=AtlasSummaryStats(
            truth_tables=0,
            sql_functions=0,
            ephemeral_stores=0,
            manipulator_routes=0,
            manipulator_services=0,
            display_pages=0,
            display_hooks_and_clients=0,
            verified_edges=0,
            end_to_end_chains=0,
            clean_nodes=0,
            flagged_nodes=0,
            blocking_findings=0,
            warning_findings=0,
        ),
        nodes=[],
        edges=[],
        chains=[],
        findings=[],
        gate=GateEvaluation(
            verdict="PASS",
            mode="strict",
            blocking_violations=0,
            evaluated_at=ts,
        ),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )


def test_agent_harness_entry_point_discovery_and_packaging_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pyproject_path = REPO_ROOT / "plugins" / "wythe-plugin-agent-harness" / "pyproject.toml"
    pkg_meta = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    assert pkg_meta["project"]["name"] == "wythe-plugin-agent-harness"
    assert pkg_meta["project"]["version"] == "0.1.0"
    assert pkg_meta["project"]["authors"] == [{"name": "Euda1mon1a"}]
    assert (
        pkg_meta["project"]["entry-points"]["wythe.plugins"]["agent-harness"]
        == "wythe_plugin_agent_harness:register_wythe_plugin"
    )
    assert pkg_meta["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/wythe_plugin_agent_harness"
    ]

    plugin = register_wythe_plugin()
    assert isinstance(plugin, AgentHarnessPlugin)
    assert plugin is WYTHE_PLUGIN
    assert [r["rule_code"] for r in plugin.plugin_rules] == ["AGENT-001", "AGENT-002", "AGENT-003"]

    fake_ep = _FakeEntryPoint(
        "agent-harness",
        "wythe_plugin_agent_harness:register_wythe_plugin",
        register_wythe_plugin,
        version="0.1.0",
    )
    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: [fake_ep])

    specs = discover_plugins()
    harness_specs = [s for s in specs if s.name == "agent-harness"]
    assert harness_specs, "discover_plugins() must register agent-harness from wythe.plugins"
    assert harness_specs[0].origin == "entry_point"
    assert harness_specs[0].version == "0.1.0"
    assert harness_specs[0].enabled_by_default is True

    meta_list = list_registered_plugins()
    assert any(m["name"] == "agent-harness" and m["origin"] == "entry_point" for m in meta_list)
    json.dumps(meta_list)


def test_agent_001_split_brain_router_vs_frozen_prefix_and_negative_controls(
    tmp_path: Path,
) -> None:
    (tmp_path / "src" / "routes").mkdir(parents=True)

    # Route 1 (Frozen system prefix + dynamic [TURN CONTEXT] in tail user message -> 0 AGENT-001)
    (tmp_path / "src" / "routes" / "frozen_chat_route.py").write_text(
        '''from datetime import datetime, UTC

STATIC_SYSTEM_PROMPT = """You are a deterministic code review assistant.
Follow repository architecture rules strictly."""

def handle_frozen_chat(user_query: str) -> list[dict[str, str]]:
    now_iso = datetime.now(UTC).isoformat()
    messages = [
        {"role": "system", "content": STATIC_SYSTEM_PROMPT},
        {"role": "user", "content": f"{user_query}\\n\\n[TURN CONTEXT]\\nClock: {now_iso}"},
    ]
    return messages
''',
        encoding="utf-8",
    )

    # Route 2 (Sibling route injecting live clock into messages[0] -> flags AGENT-001 naming sibling!)
    (tmp_path / "src" / "routes" / "volatile_stream_route.py").write_text(
        '''import time

BASE_INSTRUCTIONS = "You are a streaming coding assistant."

def handle_stream_chat(prompt: str) -> list[dict[str, str]]:
    messages = [
        {"role": "system", "content": f"[{time.strftime('%H:%M:%S')}] {BASE_INSTRUCTIONS}"},
        {"role": "user", "content": prompt},
    ]
    return messages
''',
        encoding="utf-8",
    )

    # Route 3 (TypeScript MCP sampling volatile systemPrompt vs negative user template)
    (tmp_path / "src" / "routes" / "sampling_gateway.ts").write_text(
        """export function buildUserTurnTemplate(question: string): object {
  const userContent = `[TURN CONTEXT] ${new Date().toISOString()}\\nQuestion: ${question}`;
  return { role: "user", content: userContent };
}

export function buildVolatileSamplingRequest(task: string): object {
  const offlineAuditLabel = `audit-${Date.now()}.json`;
  void offlineAuditLabel;
  return {
    method: "sampling/createMessage",
    params: {
      systemPrompt: `Session ${crypto.randomUUID()} at ${new Date().toISOString()}: static rules`,
      messages: [{ role: "user", content: task }],
    },
  };
}
""",
        encoding="utf-8",
    )

    # Negative control: offline non-chat formatting & dynamic user-only prompt helper
    (tmp_path / "src" / "routes" / "offline_reporter.py").write_text(
        '''from datetime import datetime, UTC

def format_export_banner(summary: str) -> str:
    return f"Export generated at {datetime.now(UTC).isoformat()}: {summary}"

def build_dynamic_user_only_turn(question: str) -> dict[str, str]:
    return {"role": "user", "content": f"[TURN CONTEXT] {datetime.now(UTC).isoformat()}\\n{question}"}
''',
        encoding="utf-8",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(tmp_path, "src", res)

    agent001 = [f for f in res.findings if f.rule_code == "AGENT-001"]
    flagged_files = {f.source_file for f in agent001}
    assert "src/routes/frozen_chat_route.py" not in flagged_files
    assert "src/routes/offline_reporter.py" not in flagged_files
    assert "src/routes/volatile_stream_route.py" in flagged_files
    assert "src/routes/sampling_gateway.ts" in flagged_files

    py_split = next(f for f in agent001 if f.source_file == "src/routes/volatile_stream_route.py")
    assert "src/routes/frozen_chat_route.py:" in py_split.detail
    assert "src/routes/volatile_stream_route.py:" in py_split.detail
    assert "[TURN CONTEXT]" in py_split.detail
    assert py_split.confidence == "confirmed"
    assert py_split.evidence_strength == "ast_exact"


def test_agent_002_bloated_50_tool_shadow_manifest_vs_sliced_4_tool_registry(
    tmp_path: Path,
) -> None:
    # 1. Bloated 50-tool manifest + shadow tools + bypassed registry policy
    bad_repo = tmp_path / "bad_repo"
    (bad_repo / "config").mkdir(parents=True)
    (bad_repo / "src").mkdir(parents=True)
    (bad_repo / "config" / "tools.json").write_text(
        json.dumps(
            {
                "allowlist": ["read_doc", "list_symbols", "run_linter", "get_summary"],
                "tools": [
                    {"name": "read_doc", "enabled": True},
                    {"name": "list_symbols", "enabled": True},
                    {"name": "run_linter", "enabled": True},
                    {"name": "get_summary", "enabled": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    (bad_repo / "src" / "bloated_loader.py").write_text(
        '''import json
from pathlib import Path

TOOL_DEFINITIONS = [
    {
        "name": f"shadow_tool_{idx}",
        "description": "Verbose tool schema flooding small local model context window.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "detail_level": {"type": "integer"}},
            "required": ["target"],
        },
    }
    for idx in range(50)
]

def load_bypassed_tools(repo_dir: Path) -> list[dict[str, object]]:
    raw = json.loads((repo_dir / "config" / "tools.json").read_text(encoding="utf-8"))
    _ = raw.get("tools")
    return TOOL_DEFINITIONS
''',
        encoding="utf-8",
    )

    bad_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    run_manipulator_plugins(
        bad_repo,
        "src",
        bad_res,
        allow_local_plugins=True,
        local_plugin_modules=["wythe_plugin_agent_harness:register_wythe_plugin"],
    )

    bad_002 = [f for f in bad_res.findings if f.rule_code == "AGENT-002"]
    assert len(bad_002) >= 3  # budget exceeded + shadow tools + policy bypass
    assert any("50 tools" in f.title for f in bad_002)
    assert any("uncataloged shadow tool" in f.title for f in bad_002)
    assert any("bypasses `config/tools.json`" in f.title for f in bad_002)

    loader_node = next(n for n in bad_res.nodes if n.source_file == "src/bloated_loader.py")
    assert loader_node.status in ("duplicated_truth", "policy_in_code")
    reg_edge = next(
        e
        for e in bad_res.edges
        if e.kind == "reads_truth" and e.target_id == "t:registry:config/tools.json"
    )
    assert "load_bypassed_tools->*" in reg_edge.symbol_links
    assert reg_edge.policy_field_consumption is not None
    assert reg_edge.policy_field_consumption.state == "bypassed"
    assert "TOOL_DEFINITIONS" in reg_edge.policy_field_consumption.substituted_constants

    # 2. Clean 4-tool (<1,000 token) sliced manifest + policy-consuming YAML/JSON loader
    good_repo = tmp_path / "good_repo"
    (good_repo / "config").mkdir(parents=True)
    (good_repo / "src").mkdir(parents=True)
    (good_repo / "config" / "tools.yaml").write_text(
        """allowlist:
  - read_doc
  - list_symbols
  - run_linter
  - get_summary
tools:
  - name: read_doc
    enabled: true
  - name: list_symbols
    enabled: true
  - name: run_linter
    enabled: true
  - name: get_summary
    enabled: true
""",
        encoding="utf-8",
    )
    (good_repo / "src" / "sliced_mcp.py").write_text(
        '''import yaml
from pathlib import Path

SLM_TOOLS = [
    {"name": "read_doc", "description": "Read doc", "inputSchema": {"type": "object"}},
    {"name": "list_symbols", "description": "List symbols", "inputSchema": {"type": "object"}},
    {"name": "run_linter", "description": "Run linter", "inputSchema": {"type": "object"}},
    {"name": "get_summary", "description": "Summary", "inputSchema": {"type": "object"}},
]

def load_enabled_tools(root: Path, slice_mode: str = "slm") -> list[dict[str, object]]:
    cfg = yaml.safe_load((root / "config" / "tools.yaml").read_text(encoding="utf-8"))
    allowed = set(cfg["allowlist"])
    enabled_names = {t["name"] for t in cfg["tools"] if t.get("enabled") and t["name"] in allowed}
    return [t for t in SLM_TOOLS if t["name"] in enabled_names and slice_mode == "slm"]
''',
        encoding="utf-8",
    )

    good_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(good_repo, "src", good_res)
    assert [f for f in good_res.findings if f.rule_code == "AGENT-002"] == []
    good_edge = next(
        e
        for e in good_res.edges
        if e.kind == "reads_truth" and e.target_id == "t:registry:config/tools.yaml"
    )
    assert "load_enabled_tools->*" in good_edge.symbol_links
    assert good_edge.policy_field_consumption is not None
    assert good_edge.policy_field_consumption.state == "consumed"


def test_agent_003_unguarded_loops_and_raw_http_bypass_vs_verified_canonical_loop(
    tmp_path: Path,
) -> None:
    # Bad repo: canonical adapter exists, but runner uses raw fetch('/v1/chat/completions') + unguarded while True
    bad_repo = tmp_path / "bad_loops"
    (bad_repo / "src").mkdir(parents=True)
    (bad_repo / "src" / "llm_client.py").write_text(
        '''import httpx

class CanonicalLLMClient:
    def complete_turn(self, messages: list[dict], timeout: float = 15.0) -> dict:
        resp = httpx.post("http://127.0.0.1:8080/v1/chat/completions", json={"messages": messages}, timeout=timeout)
        return resp.json()
''',
        encoding="utf-8",
    )
    (bad_repo / "src" / "unguarded_runner.py").write_text(
        '''import httpx

def run_unguarded_agent(messages: list[dict]) -> bool:
    files_modified = False
    while True:
        resp = httpx.post("http://127.0.0.1:8080/v1/chat/completions", json={"messages": messages}).json()
        calls = resp.get("tool_calls", [])
        if not calls:
            if files_modified:
                return True
        for call in calls:
            execute_tool(call["name"], call["args"])
            files_modified = True
''',
        encoding="utf-8",
    )
    (bad_repo / "src" / "unguarded_web_agent.ts").write_text(
        """export async function runBrowserBypassLoop(messages: unknown[]): Promise<boolean> {
  let filesModified = false;
  while (true) {
    const res = await fetch("/v1/chat/completions", { method: "POST", body: JSON.stringify({ messages }) });
    const turn = await res.json();
    if (!turn.toolCalls?.length) {
      if (filesModified) return true;
    }
    for (const tc of turn.toolCalls ?? []) {
      await executeTool(tc.name, tc.args);
      filesModified = true;
    }
  }
}
""",
        encoding="utf-8",
    )

    bad_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(bad_repo, "src", bad_res)
    bad_003 = [f for f in bad_res.findings if f.rule_code == "AGENT-003"]
    assert not any(f.source_file == "src/llm_client.py" for f in bad_003)
    py_loop_f = [f for f in bad_003 if f.source_file == "src/unguarded_runner.py"]
    ts_loop_f = [f for f in bad_003 if f.source_file == "src/unguarded_web_agent.ts"]
    assert len(py_loop_f) == 2  # unguarded loop + raw httpx.post bypass
    assert len(ts_loop_f) == 2  # unguarded loop + raw fetch('/v1/chat/completions') bypass
    assert any("unbounded" in f.detail and "duplicate-call" in f.detail and "files_modified" in f.detail for f in py_loop_f)
    assert any("bypasses canonical adapter `src/llm_client.py`" in f.title for f in ts_loop_f)

    # Verify check_report standalone vs post-augment idempotency
    fresh_rep = _empty_report(bad_repo)
    standalone_out = WYTHE_PLUGIN.check_report(bad_repo, fresh_rep)
    assert standalone_out["already_augmented"] is False
    assert len(standalone_out["findings"]) == 4  # type: ignore[arg-type]

    aug_rep = _empty_report(bad_repo, notes=bad_res.notes)
    idempotent_out = WYTHE_PLUGIN.check_report(bad_repo, aug_rep)
    assert idempotent_out["already_augmented"] is True
    assert idempotent_out["findings"] == []

    # Good repo: bounded, timeout-guarded, duplicate-call brake, receipt-verified loop via canonical adapter
    good_repo = tmp_path / "good_loops"
    (good_repo / "src").mkdir(parents=True)
    (good_repo / "src" / "llm_client.py").write_text(
        '''import httpx

def complete_turn(messages: list[dict], timeout: float = 10.0) -> dict:
    return httpx.post("http://127.0.0.1:8080/v1/chat/completions", json={"messages": messages}, timeout=timeout).json()
''',
        encoding="utf-8",
    )
    (good_repo / "src" / "guarded_runner.py").write_text(
        '''import json
from src.llm_client import complete_turn

MAX_ROUNDS = 8

def verify_workspace_receipt() -> bool:
    return True

def run_guarded_agent(messages: list[dict]) -> bool:
    last_call_sig: tuple[str, str] | None = None
    for _ in range(MAX_ROUNDS):
        turn = complete_turn(messages, timeout=10.0)
        calls = turn.get("tool_calls", [])
        if not calls:
            return verify_workspace_receipt()
        for call in calls:
            sig = (call["name"], json.dumps(call["args"], sort_keys=True))
            if sig == last_call_sig:
                raise RuntimeError("Duplicate tool call circuit breaker tripped")
            last_call_sig = sig
            out = execute_tool(call["name"], call["args"])
            messages.append({"role": "tool", "content": out})
    return verify_workspace_receipt()
''',
        encoding="utf-8",
    )
    good_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(good_repo, "src", good_res)
    assert [f for f in good_res.findings if f.rule_code == "AGENT-003"] == []
    helper_edge = next(e for e in good_res.edges if e.kind == "calls_helper")
    assert "run_guarded_agent->complete_turn" in helper_edge.symbol_links


def test_symlink_escape_oversize_and_malformed_input_resilience(tmp_path: Path) -> None:
    outside_dir = tmp_path / "outside_secret"
    outside_dir.mkdir()
    sentinel = tmp_path / "never_executed.txt"
    outside_py = outside_dir / "escaped.py"
    outside_py.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('pwned')\n"
        "import time\n"
        "messages = [{'role': 'system', 'content': f'{time.time()} instructions'}]\n",
        encoding="utf-8",
    )
    outside_json = outside_dir / "tools.json"
    outside_json.write_text('{"tools": [{"name": "secret_tool", "enabled": true}]}', encoding="utf-8")

    repo = tmp_path / "scanned_repo"
    (repo / "src").mkdir(parents=True)
    (repo / "config").mkdir(parents=True)

    # Symlinks escaping repo_root must be ignored completely
    (repo / "src" / "escape_link.py").symlink_to(outside_py)
    (repo / "config" / "tools.json").symlink_to(outside_json)
    (repo / "src" / "escape_dir").symlink_to(outside_dir)

    # Side-effect code in scanned repo must NEVER be imported or executed
    (repo / "src" / "untrusted_target.py").write_text(
        f"import pathlib\npathlib.Path({str(sentinel)!r}).write_text('executed')\n",
        encoding="utf-8",
    )

    # Oversized >512 KiB file must be skipped cleanly
    (repo / "src" / "huge_generated.py").write_text(
        "# padding\n" + ("x = 'a'\n" * 80_000),
        encoding="utf-8",
    )

    # Malformed Python, TypeScript, JSON, and YAML must never crash the plugin
    (repo / "src" / "broken.py").write_text("def broken_syntax(:\n    while True\n", encoding="utf-8")
    (repo / "src" / "broken.ts").write_text("export function broken( { const x = [ { role: 'system' ", encoding="utf-8")
    (repo / "config" / "broken.json").write_text("{bad json", encoding="utf-8")
    (repo / "config" / "broken.yaml").write_text("tools: [\n  : unclosed", encoding="utf-8")

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(repo, "src", res)

    assert not sentinel.exists()
    assert res.findings == []
    assert any("Skipped" in n and "malformed" in n for n in res.notes)


def test_agent_001_anthropic_system_and_rag_prefix_volatility(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "rag_router.py").write_text(
        '''BASE_SYSTEM = "You are a helpful documentation assistant. Always cite file paths."
EXTRA_RULES = "Return concise markdown answers."

def frozen_composed_prefix(client: object, query: str) -> object:
    return client.messages.create(
        system=f"{BASE_SYSTEM}\\n{EXTRA_RULES}",
        messages=[{"role": "user", "content": query}],
    )

def volatile_rag_prefix(client: object, query: str, rag_context: str) -> object:
    return client.messages.create(
        system=f"Retrieved chunks:\\n{rag_context}\\n\\n{BASE_SYSTEM}",
        messages=[{"role": "user", "content": query}],
    )
''',
        encoding="utf-8",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(tmp_path, "src", res)

    findings = [f for f in res.findings if f.rule_code == "AGENT-001"]
    assert len(findings) == 1
    assert findings[0].line >= 10
    assert "rag_context" in findings[0].detail
    assert "frozen_composed_prefix" in findings[0].detail


def test_agent_002_pyproject_custom_thresholds_and_progressive_discovery(tmp_path: Path) -> None:
    # 1. Progressive discovery router (`search_tools`) with 8 @mcp.tool endpoints passes cleanly
    disc_repo = tmp_path / "discovery_repo"
    (disc_repo / "src").mkdir(parents=True)
    tool_defs = "\n".join(
        f'@mcp.tool()\ndef helper_tool_{i}(query: str) -> str:\n    """Tool {i}."""\n    return query\n'
        for i in range(7)
    )
    (disc_repo / "src" / "progressive_mcp.py").write_text(
        tool_defs
        + '\n@mcp.tool()\ndef search_tools(keyword: str) -> list[str]:\n    """Progressive discovery."""\n    return [keyword]\n',
        encoding="utf-8",
    )
    disc_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(disc_repo, "src", disc_res)
    assert [f for f in disc_res.findings if f.rule_code == "AGENT-002"] == []

    # 2. Custom `[tool.wythe.agent_harness]` threshold override in target `pyproject.toml`
    custom_repo = tmp_path / "custom_repo"
    (custom_repo / "src").mkdir(parents=True)
    (custom_repo / "pyproject.toml").write_text(
        "[tool.wythe.agent_harness]\nmax_slm_tools = 2\nmax_slm_schema_tokens = 120\n",
        encoding="utf-8",
    )
    (custom_repo / "src" / "ts_mcp_server.ts").write_text(
        """server.tool("read_file", async () => ({}));
server.tool("search_code", async () => ({}));
server.tool("run_checks", async () => ({}));
""",
        encoding="utf-8",
    )
    custom_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(custom_repo, "src", custom_res)
    c_002 = [f for f in custom_res.findings if f.rule_code == "AGENT-002"]
    assert len(c_002) == 1
    assert "(max 2)" in c_002[0].detail


def test_agent_003_high_ceiling_without_timeout_and_prose_done_stop(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "high_ceiling.py").write_text(
        '''import ast
import json

HIGH_CEILING = 40

def run_untimed_prose_stop_loop(adapter: object, messages: list[dict]) -> bool:
    seen_calls: set[tuple[str, str]] = set()
    for _ in range(HIGH_CEILING):
        turn = adapter.complete(messages)
        if "DONE" in turn["content"]:
            return True
        for tc in turn.get("tool_calls", []):
            sig = (tc["name"], json.dumps(tc["args"], sort_keys=True))
            if sig in seen_calls:
                return False
            seen_calls.add(sig)
            run_tool(tc["name"], tc["args"])
    return False

def run_timed_ast_verified_loop(adapter: object, messages: list[dict], generated_src: str) -> bool:
    seen_calls: set[tuple[str, str]] = set()
    for _ in range(HIGH_CEILING):
        turn = adapter.complete(messages, timeout=12.0)
        if not turn.get("tool_calls"):
            ast.parse(generated_src)
            return True
        for tc in turn["tool_calls"]:
            sig = (tc["name"], json.dumps(tc["args"], sort_keys=True))
            if sig in seen_calls:
                return False
            seen_calls.add(sig)
            run_tool(tc["name"], tc["args"])
    return False
''',
        encoding="utf-8",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(tmp_path, "src", res)
    f_003 = [f for f in res.findings if f.rule_code == "AGENT-003"]
    assert len(f_003) == 1
    assert f_003[0].title == "Agent tool loop in `run_untimed_prose_stop_loop` lacks execution guardrails"
    assert "40 > 25 rounds" in f_003[0].detail
    assert "DONE" in f_003[0].detail


def test_wythe_self_scan_with_agent_harness_emits_zero_findings_or_graph_drift() -> None:
    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    WYTHE_PLUGIN.augment_manipulator(REPO_ROOT, "backend", res)
    assert res.findings == []
    assert res.nodes == []
    assert res.edges == []



def test_end_to_end_scan_and_entry_point_materialize_agent_001_002_003_into_gate(
    isolated_db_url: str,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    """Verify full core spine + wythe-plugin-agent-harness integration via CLI --plugin and entry_points."""
    import importlib.metadata
    import subprocess

    from sqlalchemy import select

    from app.cli import main as cli_main
    from app.models import RulePolicy
    from app.schemas.atlas import TargetProjectCreate
    from app.services.governance_service import get_target_by_slug, register_target
    from app.services.scanner_service import run_target_scan

    assert isolated_db_url.startswith("sqlite:")

    repo_dir = tmp_path / "integrated_harness_app"
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "config").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True)

    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE sessions (id SERIAL PRIMARY KEY, prompt TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo_dir / "config" / "tools.json").write_text(
        json.dumps(
            {
                "allowlist": ["lookup_session"],
                "tools": [{"name": "lookup_session", "enabled": True}],
            }
        ),
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "frozen_route.py").write_text(
        "STATIC_SYS = 'Deterministic assistant instructions.'\n"
        "def build_frozen(q: str, now_s: str) -> list[dict[str, str]]:\n"
        "    return [\n"
        "        {'role': 'system', 'content': STATIC_SYS},\n"
        "        {'role': 'user', 'content': f'{q}\\n[TURN CONTEXT] {now_s}'},\n"
        "    ]\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "harness_runner.py").write_text(
        "import json\n"
        "import time\n"
        "from pathlib import Path\n"
        "import httpx\n\n"
        "TOOL_DEFINITIONS = [\n"
        "    {'name': f'extra_tool_{i}', 'description': 'Verbose schema', 'inputSchema': {'type': 'object'}}\n"
        "    for i in range(8)\n"
        "]\n\n"
        "def load_tools(root: Path) -> list[dict]:\n"
        "    _ = json.loads((root / 'config' / 'tools.json').read_text(encoding='utf-8'))\n"
        "    return TOOL_DEFINITIONS\n\n"
        "def run_agent(db, prompt: str) -> bool:\n"
        '    db.execute("SELECT id, prompt FROM sessions")\n'
        "    messages = [\n"
        "        {'role': 'system', 'content': f'{time.time()} system instructions'},\n"
        "        {'role': 'user', 'content': prompt},\n"
        "    ]\n"
        "    files_modified = False\n"
        "    while True:\n"
        "        resp = httpx.post('http://127.0.0.1:8080/v1/chat/completions', json={'messages': messages}).json()\n"
        "        calls = resp.get('tool_calls', [])\n"
        "        if not calls:\n"
        "            if files_modified:\n"
        "                return True\n"
        "        for c in calls:\n"
        "            dispatch_tool(c['name'], c['args'])\n"
        "            files_modified = True\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.harness_runner import run_agent\n\n"
        "app = FastAPI()\n\n"
        '@app.post("/api/v1/chat")\n'
        "def post_chat():\n"
        "    return {'ok': run_agent(None, 'hi')}\n",
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function ChatPage() {\n"
        "  async function send() { await fetch('/api/v1/chat', { method: 'POST' }); }\n"
        '  return <button type="button" onClick={send}>Send</button>;\n'
        "}\n",
        encoding="utf-8",
    )
    git_env = {
        "GIT_AUTHOR_NAME": "Test Bot",
        "GIT_AUTHOR_EMAIL": "bot@example.invalid",
        "GIT_COMMITTER_NAME": "Test Bot",
        "GIT_COMMITTER_EMAIL": "bot@example.invalid",
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Init"], cwd=repo_dir, check=True, capture_output=True, env=git_env)

    # 1. CLI `wythe scan --allow-local-plugins --plugin wythe_plugin_agent_harness`
    scan_json = tmp_path / "cli-harness-scan.json"
    rc = cli_main(
        [
            "scan",
            str(repo_dir),
            "--allow-local-plugins",
            "--plugin",
            "wythe_plugin_agent_harness",
            "--json",
            str(scan_json),
        ]
    )
    assert rc == 0
    capsys.readouterr()
    cli_report = json.loads(scan_json.read_text(encoding="utf-8"))
    cli_codes = {f["rule_code"] for f in cli_report["findings"]}
    assert {"AGENT-001", "AGENT-002", "AGENT-003"} <= cli_codes
    cli_gate_by_code = {r["rule_code"]: r for r in cli_report["gate"]["rule_counts"]}
    for code in ("AGENT-001", "AGENT-002", "AGENT-003"):
        assert code in cli_gate_by_code
        assert cli_gate_by_code[code]["observed_count"] >= 1
        assert cli_gate_by_code[code]["tier"] == "manipulate"
        assert cli_gate_by_code[code]["severity"] == "warning"
        assert cli_gate_by_code[code]["blocks_gate"] is False

    # 2. Entry-point discovery (`entry_points(group="wythe.plugins")`) via `run_target_scan`
    fake_ep = _FakeEntryPoint(
        "agent-harness",
        "wythe_plugin_agent_harness:register_wythe_plugin",
        register_wythe_plugin,
        version="0.1.0",
    )
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: [fake_ep] if kw.get("group") == ENTRY_POINT_GROUP else [],
    )
    register_target(
        db_session,
        TargetProjectCreate(
            slug="integrated-harness",
            name="Integrated Harness",
            repo_path=str(repo_dir),
        ),
    )
    target = get_target_by_slug(db_session, "integrated-harness")
    assert target is not None
    ep_report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    ep_codes = {f.rule_code for f in ep_report.findings}
    assert {"AGENT-001", "AGENT-002", "AGENT-003"} <= ep_codes
    ep_gate_by_code = {r.rule_code: r for r in ep_report.gate.rule_counts}
    for code in ("AGENT-001", "AGENT-002", "AGENT-003"):
        assert ep_gate_by_code[code].observed_count >= 1
    assert ep_report.gate.verdict == "PASS"
    assert len(db_session.scalars(select(RulePolicy)).all()) == 19
