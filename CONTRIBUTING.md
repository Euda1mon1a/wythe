# Contributing

Please read [SUPPORT.md](SUPPORT.md) first. Wythe is maintained for its author's own use and published **as is**.

- Issues and pull requests are not guaranteed a review, a reply, or a merge, and may be closed without discussion.
- Requests for new stacks, features, or fixes for a specific environment will usually not be acted on. Forking is the supported way to get a change you need.
- Backward compatibility is not promised between versions. Pin an exact version.

If you still want to send a change:

1. Keep it small and focused on one problem.
2. Include a regression test that fails without the change.
3. Run `make lint`, `make types`, `make test`, and `make gate` (strict self-dogfood) before opening the pull request.

## Standing Human–Agent Shared Investigation Standards

All UI, schema, MCP, CLI, and assistant changes must satisfy the four standing engineering standards documented in [AGENTS.md](AGENTS.md) and gated in CI by `backend/tests/test_human_agent_parity_standard.py`:

- **Standard 1: 1:1 Human–Agent Viewport Control & Readback Parity** — Every interactive 3D viewport filter, lens, layout, slice, blast-radius mode, working-set toggle, or selection control in `frontend/src/app/page.tsx` must have a 1:1 counterpart on `ViewportCommand`, `wythe_focus_camera` (`MCP_TOOLS` + `build_ask_openai_tools()`), and `UiFocusStatePayload` / `UiFocusExplainRead`.
- **Standard 2: Salience Isolation Over Smear on Dense Graphs (`>120` nodes)** — Focusing 1 node on a dense graph without explicit filter overrides auto-enables `isolateCone`; focusing `>=2` nodes auto-enables `workingSetActive` + `compactVisible`; `reset_filters=True` restores the full overview.
- **Standard 3: Deterministic Execution Before Action Prose (Zero Confabulated UI Mutations)** — Assistant turns must never claim to have mutated the 3D camera, lens, or filters without executing `wythe_focus_camera` or `wythe_camera_tour`; `on_device_llm_service.py` enforces a bounded corrective tool round and a deterministic `Viewport Notice` post-condition banner.
- **Standard 4: First-Class External Frontier/Terminal Pipe (`wythe reply` & `record_turn`)** — External CLI (`wythe reply`) and MCP (`wythe_investigation(action="record_turn")`) turns record validated citations into the active investigation session and wake the live browser drawer over SSE without clobbering existing camera or filter state.
