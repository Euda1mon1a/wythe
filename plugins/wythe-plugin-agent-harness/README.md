# `wythe-plugin-agent-harness`

Optional companion plugin for [Wythe](https://github.com/Euda1mon1a/wythe) (`wythe.plugins` entry point `agent-harness`) that statically audits **LLM, SLM, and MCP agent-harness architectures** across `Truth <-> Manipulate <-> Display` without executing repository code or opening network connections.

## Motivation

Small and mid-sized local models (`2B–35B` on `ml-explore/mlx@fc344c986c4169d99f76b5d95ae6b4a58a359a63`, `llama.cpp`, Ollama, or WebGPU) suffer severe latency and accuracy regressions when an orchestrator harness invalidates KV-cache prefixes every turn, mounts oversized JSON tool schemas without progressive discovery, or runs open-ended tool loops without duplicate-call circuit breakers.

Keeping `AGENT-001..003` in an opt-in distribution preserves a domain-neutral core `wythe` (`uvx wythe gate .`) while giving AI-application repositories deterministic static checks.

## Rules

| Rule | Tier | Evidence | Checks |
| --- | --- | --- | --- |
| `AGENT-001` | `manipulate` | `ast_exact` | Flags volatile clock/UUID/random/RAG expressions interpolated into `system` / `messages[0]` ahead of static instructions, and detects **split-brain router drift** where one route preserves a frozen `system` prefix (putting `[TURN CONTEXT]` in `messages[-1]`) while a sibling route mutates `messages[0]`. |
| `AGENT-002` | `manipulate` | `structural_match` | Computes deterministic JSON byte size and approximate schema tokens (`max(1, (byte_len + 3) // 4)`) for Python/TypeScript tool manifests against SLM budgets (`max_slm_tools = 5`, `max_slm_schema_tokens = 1000` unless progressive discovery or `--slice` / `slice_mode` is wired), and reconciles hardcoded tool lists against Tier-1 `config/*.json` / `config/*.yaml` registries with function-scoped `AtlasEdge.symbol_links` and `PolicyFieldConsumption` attribution. |
| `AGENT-003` | `manipulate` | `ast_exact` | Audits Python/TypeScript tool-execution loops for explicit round ceilings (and per-step `timeout` when `> 25` rounds), consecutive duplicate-call `(tool_name, canonical_args)` circuit breakers, deterministic verification/receipt gates on stop predicates, and canonical LLM client/adapter usage vs. raw `/v1/chat/completions` HTTP calls. |

## Configuration

Thresholds can be customized in the scanned repository's `pyproject.toml`:

```toml
[tool.wythe.agent_harness]
max_slm_tools = 5
max_slm_schema_tokens = 1000
max_un_timed_loop_rounds = 25
```

## Security & Epistemic Boundary

`wythe-plugin-agent-harness` performs pure static Python `ast`, lexical TypeScript/JavaScript, and `json.loads` / `yaml.safe_load` analysis. Symlinks and paths outside `repo_root.resolve()` are rejected, individual files are capped at `512 KiB`, and target repository code is never imported or executed.
