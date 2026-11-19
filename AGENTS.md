# Wythe Engineering & Agent Contributor Guide

Wythe is a 3-tier architectural governance engine (`Truth`, `Manipulate`, `Display`) with a shared 3D Stratified Atlas workspace for humans, on-device models, and external coding agents.

Every pull request, feature, and automated change in this repository must uphold the four standing Human–Agent Shared Investigation standards below, enforced in CI by `backend/tests/test_human_agent_parity_standard.py`.

---

## Standing Human–Agent Shared Investigation Standards

### Standard 1: 1:1 Human–Agent Viewport Control & Readback Parity
Every interactive viewport filter, lens, layout, slice, stratum, blast-radius mode, working-set toggle, or selection control available to a human in the 3D workspace (`frontend/src/app/page.tsx`) must have:
1. A strictly typed optional field on `ViewportCommand` (and `TourKeyframe` where applicable) in `backend/app/schemas/atlas.py` (`extra="forbid"`).
2. A matching parameter exposed on `wythe_focus_camera` in `backend/app/services/mcp_service.py` (which also feeds `build_ask_openai_tools()` for OpenAI-compatible tool-calling engines).
3. Live SSE application in `frontend/src/app/page.tsx` (`applyBeatToWorkspace` / `applyCommandOrFirstStep`) and deterministic permalink round-tripping in `viewport_service.py` and `wytheCameraChoreography.ts`.
4. Full 1:1 readback in `UiFocusStatePayload` and `UiFocusExplainRead` (`POST` / `GET /api/v1/ui-focus` and `wythe_what_is_this`) so an agent always reads back the exact controls active on screen.

Adding a GUI viewport filter or scene control without wiring all four surfaces fails `backend/tests/test_human_agent_parity_standard.py`.

### Standard 2: Salience Isolation Over Smear on Dense Graphs (`>120` nodes)
Focusing nodes on a dense repository graph (`>120` nodes) without isolation produces an illegible smear of thousands of overlapping dots. When an agent focuses nodes on a graph with `>120` nodes and does not explicitly pass an isolation or filter override (`isolate_cone`, `neighborhood_hops`, `working_set_only`, `only_flagged`, `tier_filter`, `subkind_filter`, `search_query`, or `reset_filters`):
- **Single-node focus (`len(focus_node_ids) == 1`):** Automatically selects that node and activates `isolateCone = true` so the user immediately sees its clean 3-tier lineage cone.
- **Multi-node focus (`len(focus_node_ids) >= 2`):** Automatically populates the working set from `focus_node_ids` (plus endpoints of `highlight_edge_ids`) and activates `workingSetActive = true` and `compactVisible = true`.
- **Explicit reset (`reset_filters = true`):** Clears active filters, cone isolation, and working-set compaction back to the full overview.

### Standard 3: Deterministic Execution Before Action Prose (Zero Confabulated UI Mutations)
An assistant turn must never claim in prose that it switched a lens, applied a filter, isolated a cone, or moved the 3D camera unless `wythe_focus_camera` or `wythe_camera_tour` actually executed during that turn:
1. **Intent-Triggered Tool Availability:** Prompts asking to filter, isolate, focus, switch lenses/layouts, or steer the 3D view enable MCP tool execution (`_mcp_tool_intent_re` in `on_device_llm_service.py` and `AskWytheDrawer.tsx`).
2. **Corrective Verification Gate:** If a tool-capable turn requests a viewport change—or drafts prose claiming a viewport mutation—without executing `wythe_focus_camera` or `wythe_camera_tour`, `on_device_llm_service.py` runs one bounded `VERIFICATION GATE` round requiring the model to invoke the tool or state honestly that no view change occurred.
3. **Hard Post-Condition Truth Banner:** If completion still finishes without a viewport tool execution while prose claims a view mutation, Wythe deterministically prepends `> **Viewport Notice:** No camera or filter command was executed on this turn; your 3D view remains unchanged.` to `answer_markdown`.

### Standard 4: First-Class External Frontier/Terminal Pipe (`wythe reply` & `record_turn`)
External terminal workflows and MCP coding agents are first-class participants in the live browser investigation drawer:
- **CLI Pipe (`wythe reply`):** `printf "markdown..." | wythe reply` discovers `(active_slug, session_id)` from `/api/v1/ui-focus` when omitted, validates backticked node/finding/file:line citations against the current scan, records an `actor="agent"` turn on `/api/v1/investigations/{session_id}/turns`, and optionally steers the viewport (`--focus`, `--lens`, `--layout`, `--tier`, `--only-flagged`, `--isolate-cone`, `--reset-filters`).
- **MCP Tool (`wythe_investigation(action="record_turn")`):** Persists structured external agent turns and emits a lightweight SSE drawer wakeup (`refresh_session_id`, `open_drawer=True`).
- **Non-Destructive Wakeup:** Pure drawer-refresh SSE events (`isPureDrawerRefreshCommand`) automatically open and refresh `AskWytheDrawer` without clobbering the user's current camera framing, lens, layout, Z-slice, zoom stratum, or filters.

---

## Verification & Pre-PR Checklist

Before committing or opening a pull request, run:

1. **OpenAPI & TypeScript Contracts:** `make types` (`wythe export-openapi`, `npm run generate:types`, `npm run type-check` including all 3D scene unit tests).
2. **Static UI Bundle:** `make build-ui` (`npm run build` synced to `backend/app/ui_dist`).
3. **Python Linting:** `ruff check backend plugins` (zero warnings or errors).
4. **Backend & Parity Test Suite:** `pytest -q -p no:cacheprovider backend/tests` (run as a single serial process; includes `test_human_agent_parity_standard.py`).
5. **Strict Self-Governance Gate:** `wythe gate --strict .` (`PASS` with `blocking=0, warnings=0`).
