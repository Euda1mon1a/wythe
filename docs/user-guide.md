# Wythe User Guide (`v0.2.3`)

**Wythe** (**Why `?` → Therefore `∴`**) audits full-stack repositories around three architectural invariants:

1. **Database holds truth** — Relational schemas (`PostgreSQL`, `MySQL`, `SQLite`) and SQL guards own durable business state and policy; Redis keyspaces and worker queues are modeled explicitly as volatile ephemeral state.
2. **Backend manipulates truth** — Routers, controllers, procedures, background workers, CLIs, and services read/write database truth through explicit transactional boundaries without shadowing domain constants or reading host clocks directly.
3. **Frontend displays truth** — Pages, routes, hooks, and typed SDK clients bind to verified server contracts and accessible markup without inventing client policy shadows or unbacked HTTP calls.

---

## 1. Quick Start & Reading Scan Receipts

Launch the single-port API and 3D/2D WebGL viewer with zero Node.js runtime on the target machine:

```bash
# Scan and serve any local repository (uses --profile auto across 38 stack profiles)
uvx "wythe[treesitter]" serve /path/to/repo --host 127.0.0.1 --port 8780
```

- **Registering / Switching Targets:** Use the header target selector or `+` button (`Register repository path`) to run `Auto-Detect` (`backend/app/adapters/autodetect.py`), which independently detects Tier 1 (Truth), Tier 2 (Manipulate), and Tier 3 (Display) subdirectories so auxiliary subtrees (such as Python ML workers in a TypeScript monorepo) do not override the main stack.
- **Commit & Dirty-Worktree Provenance:** The header receipt displays the inspected commit SHA, observation timestamp/source (`tree-sitter`, `ast`, or `regex`), and `+N uncommitted` whenever files on disk differ from `HEAD`.
- **Gate Verdicts (`PASS`, `FAIL`, `INCOMPLETE`):**
  - `PASS`: Blocking rules have `0` violations above active ratchet ceilings, and all active stack tiers are covered.
  - `FAIL`: At least one enabled blocking rule exceeds `0` (in `--strict` mode) or exceeds its `.wythe/governance.json` ratchet ceiling.
  - `INCOMPLETE`: `coverage_complete=False` (for example `no-truth` or `no-manipulator` placeholder tiers on unsupported persistence or frontend-only scans, or an un-reconstructable diff base). `INCOMPLETE` never masquerades as `PASS` and exits with code `2` in CLI gate/diff runs.

---

## 2. Workspace Tabs (`[1]`–`[4]`)

Switch tabs with the top-right tab bar or keys `1`–`4`:

1. **3D Stratified Atlas `[1]`** — Interactive WebGL topology (with 3D tiers and 2D flat plane modes), filters, layout compaction, working sets, blast overlays, packet trace animation, and the right-hand **Node Inspector**.
2. **3-Tier Lineage `[2]`** — Searchable table of end-to-end `Display → Route/Procedure → Service → Database Table/Guard` request chains (`Trace` animates a glowing packet across all hops in 3D).
3. **Gate & Rules `[3]`** — Policy table backed by `atlas_rule_policies`, **Capture Ratchet Ceiling** button, **Git Diff / Snapshot Comparison**, **SARIF 2.1.0** export, **Export OpenLineage** JSON download, registered `wythe.plugins` status, `.wythe/governance.json` export/sync, and dynamic **Domain Policy Vocabularies**.
4. **Index & Adapters `[4]`** — Keyboard-navigable sortable node index, screen-reader summary, and stack adapter coverage status.

---

## 3. Exploring, Filtering & "Squishing" the 3D/2D Lattice

Use the two control rows above the canvas in **3D Stratified Atlas** to narrow the graph and pack related nodes together without losing architectural context.

### Selecting Nodes & Edges
- **Stratum `[T]`:** Cycle `ALL`, `DISPLAY`, `MANIPULATE`, or `TRUTH`.
- **Subkind:** Filter to one of 11 subkinds (`table`, `sql_function`, `cache_store`, `route`, `service`, `solver`, `cli`, `page`, `hook`, `api_client`, `component`).
- **Edges filter & 4-state verification styles:** Filter edges by semantics (`Writes & Mutations`, `Reads & Queries`, `SQL Guards`, `Hooks / Helpers`) or static verification state:
  - **Solid** (`verified`): Directly backed by AST/CST call, route, or SQL/ORM table evidence.
  - **Dashed** (`declared`): Import/dynamic-import dependency, module edge, or declared operational config.
  - **Dotted** (`unverified`): Heuristic match or unresolved dynamic target requiring manual verification.
  - **Broken Gap** (`broken`): Display HTTP/IPC call with no matching backend route (`DISP-004`).
- **Connected only:** Hides nodes with zero visible connections in the current view (`Connected-only` has no pin exception; missing static links are review evidence, never proof of dead code).
- **Neighborhood: 1 hop / 2 hops & Cone `[C]`:** With a node selected, restrict the canvas to its 1-hop/2-hop neighbors or full transitive upstream+downstream Lineage Cone.
- **Flagged `[G]`:** Show only nodes involved in active boundary findings.
- **3D Blast `[B]`:** Overlay **Git Diff** (touched amber nodes, transitive blast cone sky-blue nodes, new findings crimson) or **Snapshot Delta** against prior scans.

### Spatial Layouts & Compaction ("Squishing Together")
Filters alone preserve overview coordinates so nodes do not jump unexpectedly when you toggle checkboxes. When you want to pull the remaining nodes tightly together:

- **`Compact visible` (`Compacted ✓`):** Repacks *only* the currently visible/filtered/cone/working-set nodes into tight bounding boxes and re-fits the camera. Toggle it off to return to stable global coordinates.
- **`Layout [L]`:** Cycles through 6 deterministic arrangements:
  1. `Domain Districts` (`cluster`): Groups nodes by inferred domain cluster across tiers.
  2. `Uniform Grid` (`grid`): Alphabetical rows per stratum.
  3. `Role Subkinds` (`subkind`): Packs tables, SQL guards, routes, services, pages, hooks, and components into role districts.
  4. `Linked Components` (`connected`): Uses a deterministic BFS/spring heuristic to pull edge-connected nodes tightly together and packs disconnected singletons separately *(illustrative proximity, not runtime call weighting)*.
  5. `Lifecycle Z-Depth` (`lifecycle_z`): Pins canonical `(X, Y)` coordinates (`X` = domain column, `Y` = `Display / Manipulate / Truth` tier) across `Z=0` (`Source Blueprint`), `Z=1` (`Built / Sealed Crate`), and `Z=2` (`Live Runtime`), collapsing empty `Z` planes and rendering intact vs. drift wall-tie beams (`TRUTH-002`, `TRUTH-005`, `MANIP-005`).
  6. `Temporal Z-Diff` (`temporal_z`): Computes union `(X, Y)` coordinates across `Z_base` (including ghosted removed before-image anchors) and `Z_head` so surviving domain columns never shift when nodes are added or deleted.
- **`3D Tiers` ↔ `2D Flat ✓`:** Collapses the three vertical planes (`display` top, `manipulate` mid, `truth` bedrock) onto a single `y = 0` working plane so tightly connected clusters sit side by side.
- **`Group: Off | Domain | Subkind`:** Renders collapsible group pills (`[-] key (count)` / `[+] key (count)`) above the HUD so you can fold noisy districts or subkinds while keeping counts visible.
- **`Pin` / `Pinned ★`:** Selected nodes can be pinned to keep their exact `[x, y, z]` coordinate across layout switches.

### Working-Set Isolation & Saved Views
- **`Isolate visible (N)` / `+ Add visible` / `+ Set` (`In Set ✓`):** Capture the current filtered view (or individual inspected nodes) into an explicit working set without mutating scan data. When a working set is active, the HUD reports how many boundary-crossing edges lead outside the set with a **`+Expand (+K)`** button to pull external neighbors in 1 hop.
- **`Save view` & `Saved views (...):** Persist `{nodeIds, layoutMode, compactVisible, flatten2D, lens, groupBy, pinnedPositions, collapsedGroups}` plus `(targetSlug, sourceCommit, contentDigest)` to browser `localStorage`. Loading a saved view on a newer commit reconciles present vs. removed node IDs explicitly.
- **`Reset overview` / `Exit set`:** Step back to the full overview while optionally retaining working-set membership.

### Visual Modes & Lenses
- **`Mode: Atomic [P]` ↔ `Mode: Simple [P]`:** Switch between faceted polyhedra (`Hex-12`, `Octa-8`, `Solver-20`, `Icosa-20`, `Guard-8`) and geometric primitives (`Boxes`, `Octahedra`, `Cylinders`).
- **`Appearance [D]`:** Cycle `System`, `Dark`, and `Light` polarity plus built-in themes and custom tier color pickers.
- **Lens `[V]` & Scene Diagnostic Lenses:** Color nodes independently of layout by `Boundary Status`, `Write Contention`, `Fan-Out Gravity`, `11-Subkind Taxonomy`, or `Domain Clusters`, and toggle scene lenses including **`Containers`** (`cluster="containers"` highlighting `m:dockerfile:*`, `m:compose:*`, and `m:k8s:*` nodes alongside their connected entrypoints).

---

## 4. Keyboard Shortcuts Reference

Shortcuts apply when focus is outside `<input>`, `<textarea>`, and `<select>` controls:

| Key | Action |
| :--- | :--- |
| `⌘K` or `/` | Open Command Palette & Quick Jump |
| `?` | Open Command Palette in command mode (`>`) |
| `A` or `⌘J` | Open **Ask AI** on-device drawer |
| `W` | Run **What's This?** (capture 3D screenshot + sync MCP viewport brief) |
| `1` / `2` / `3` / `4` | Switch tabs (`3D Stratified Atlas`, `Lineage`, `Gate & Rules`, `Index`) |
| `F` / `Shift+F` | Toggle fullscreen 3D canvas / browser fullscreen |
| `T` | Cycle Stratum filter (`all` → `display` → `manipulate` → `truth`) |
| `G` | Toggle `Flagged only` filter |
| `C` | Toggle transitive `Lineage Cone` (when a node is selected) |
| `L` | Toggle 3D spatial layout |
| `V` | Cycle color lens |
| `P` | Toggle `Atomic` vs `Simple` polygons |
| `D` | Cycle `System` / `Dark` / `Light` appearance |
| `B` | Cycle 3D Blast Overlay (`Off` → `Git Diff` → `Snapshot Delta`) |
| `[` / `k` and `]` / `j` | Select previous / next node in scene (`ArrowLeft` / `ArrowRight` when canvas focused) |
| `M` | Smoothly center orbit pivot on selected node (when canvas focused) |
| `0` | Clear selection and fit/reset camera |
| `R` | Trigger rescan & seal receipt |
| `Escape` | Blur input → close modal/drawer → clear selection → exit fullscreen |

---

## 5. Node Inspector, Scoped Rulings & Store-Purpose Verification

Clicking any node opens the right-hand **Node Inspector** (`frontend/src/components/NodeInspector.tsx`):

- **Source Peek & Editor Deep-Links:** View highlighted source context around `file:line`, copy `path:line`, or jump straight to `vscode://` / `cursor://`.
- **Bounded vs. `--full` Lineage Cone Export & Microscope Strata (`Zoom 1..3`):**
  - `Copy LLM Cone` copies a ~300-token 3-tier slice and displays an explicit completeness banner showing included vs. eligible upstream/downstream nodes, edges, findings, and stratum items whenever a cap omits items (`Full Cone` requests `?full=true`).
  - **Microscope Strata (`Zoom 2: IR / AIR`, `Zoom 3: Binary / Heap`):** Lazily fetches `/api/v1/scans/{slug}/nodes/{node_id}/strata` on click without inflating `Zoom 1` scans, folding stdlib, Swift/ObjC ARC, and compiler witness/thunk boilerplate into expandable `+N runtime/stdlib thunks collapsed` edges unless `Unfiltered IR` (`--unfiltered-ir`) is toggled.
- **3-State Policy Field Consumption (`PolicyFieldConsumption`):**
  - On Python `reads_truth` edges, Tier-1 policy tables, Tier-2
    readers, and `wythe context` cones, `NodeInspector` renders
    `policy:<state>` badges and per-column consumption cards:
    - `consumed` (`field_controls_result`): `consumed_columns` reach
      a live return, guard, solver/helper call, or write sink
      (`fallback_constants` note `policy.cap or FALLBACK_CAP`).
    - `bypassed` (`constant_or_fallback_wins`): an active reader
      queries the policy row while leaving `unconsumed_policy_columns`
      unused or substituting `substituted_constants`, emitting a
      causal `MANIP-001` policy-bypass finding targeting `t:<table>`.
    - `unresolved` (`dynamic_or_opaque_flow`): dynamic `getattr`,
      dynamic subscripts, or opaque whole-row handoffs are surfaced
      honestly without false certainty or false `MANIP-001` findings.
- **Intent-Scoped Diagnostic Briefs (`NodeSourceAndPromptPanel`):** Choose one of three explicit task intents before copying an AI prompt:
  - `Investigate evidence (read-only)` (`investigate`)
  - `Prepare issue / triage report (no edits)` (`prepare_issue`)
  - `Propose or implement scoped refactor` (`scoped_refactor`)
  Wythe automatically cites configured `reference_exemplars` from `.wythe/governance.json` when available, or labels an auto-picked peer node as an unvalidated neighbor heuristic rather than settled authority.
- **Scoped Rulings & Verified Redis Store Purposes (`Record Ownership Ruling`):**
  - Record dispositions (`confirmed_owner_intent`, `accepted_clean`, `intentional_copy`, `deferred_cutover`) into database truth (`atlas_audit_rulings`).
  - Expand **`+ Declare Store Purpose & Evidence Scope`** (auto-expanded for `intentional_copy`) to declare `intended_use` (`derived_cache`, `read_replica`, `materialized_view`, `historical_snapshot`, `persistent_config`, `ephemeral_state`, `queue_buffer`, `authoritative_store`), `authoritative_source`, `copy_reason`, `refresh_policy`, `recovery_expectation`, `keyspace_scope`, and comma-separated `evidence_scope` targets (`RULE@file:line`, `file:line`, or `keyspace:prefix*`).
  - **Independent verification:** Declarations never rubber-stamp findings. Derived copies still require verified TTL/invalidation or an `authoritative_source`; `persistent_config` requires a `recovery_expectation`; and `authoritative_store` claims on Redis keys actively conflicting with SQL table writers escalate to `duplicated_truth`.

---

## 6. CLI, CI Gates, Diffs & Live Probes

```bash
# 1. Full 3-tier static scan (JSON + SARIF 2.1.0)
wythe scan /path/to/repo --json report.json --sarif report.sarif.json

# 2. CI gate (exit 0 PASS, 1 FAIL, 2 INCOMPLETE or error)
wythe gate /path/to/repo --sync-config --sarif gate.sarif.json
wythe gate /path/to/repo --strict

# 3. PR diff gate + directional 3-tier blast radius
wythe diff /path/to/repo --base origin/main --sarif diff.sarif.json

# 4. Portable Git governance bundle (.wythe/governance.json)
wythe export-config /path/to/repo
wythe sync-config /path/to/repo

# 5. Read-only live DB catalog + Redis keyspace metadata probes (zero row/value reads)
wythe scan /path/to/repo \
  --dsn "postgresql://readonly@127.0.0.1:5432/appdb" \
  --redis-dsn "redis://127.0.0.1:6379/0"

# 6. Opt-in unauthenticated GET confirmation of unbacked calls against a running backend
wythe scan /path/to/repo --probe-url http://127.0.0.1:8000

# 7. Experimental static + synthetic regression check for record ownership
wythe security ownership /path/to/repo \
  --handler backend/app/api/records.py:update_record \
  --record record --principal user.id --json ownership-evidence.json
```

**Diff & deletion semantics:** `wythe diff` traverses the `--base` commit and current tree separately in an isolated temporary directory without executing target code. Removed nodes retain their base-commit callers and dependencies, renames include both paths, and an unavailable/un-reconstructable base exits `2` (`INCOMPLETE`). Passing on changed lines never certifies safe code deletion.

---

## 7. On-Device AI, Vision & MCP Bridges + Epistemic Guardrails

- **Live Browser Bridges:**
  - **`What's This? [W]`:** Captures a `1024px` WebP `<canvas>` frame plus exact screen-color counts (`clean`, `policy_in_code`/`gray_zone`, `duplicated_truth`) and syncs `/api/v1/ui-focus` so remote CLI/MCP clients see what you see without copy-pasting.
  - **`Ask AI [A]` / `⌘J`:** Auto-cascades across local Apple Intelligence (`FoundationModels`), Chrome built-in `LanguageModel` (Gemini Nano), or local OpenAI-compatible `/v1` servers (MLX, Ollama, LM Studio) with zero cloud API keys.
  - **WebMCP:** Exposes `window.wythe` / `navigator.modelContext` (`whatIsThis`, `getLineageCone`, `selectNode`, `ask`).
- **Terminal & Agent Bridges:**
  - `wythe llms /path/to/repo --max-tokens 2200` emits a compact `llms.txt` architecture pointer map.
  - `wythe context /path/to/repo <query> [--zoom 1|2|3] [--unfiltered-ir] [--full]` extracts a focused 3-tier slice (with optional `StratumPlugin` microscope drill-downs at `--zoom 2|3`) around any table, route, queue, file, or node ID.
  - `wythe focus [--remote http://<tailnet-host>:8780]` pulls the active browser viewport brief over LAN/Tailnet.
  - **Agent -> Human Camera Choreography (`wythe_focus_camera`,
    `wythe_camera_tour`):** Steers connected 3D WebGL tabs over
    `/api/v1/viewport/events` SSE (and hydrates cold
    `#target=...&focus=...&chronicle=<id>&phase=<idx>` permalinks)
    across `iso_overview`, `tier_elevation`, `wythe_cross_section`,
    and `corridor_trace` presets plus `TourKeyframe[]` /
    `ChronicleTimeline` scrubbers; `Live Follow` halts automatically
    on `halted_reason` or human `OrbitControls`/keyboard input
    (`Paused — Resume Follow`), and `Index` (`AccessibleIndexView`)
    mirrors captions and `Z`/stratum attribution via
    `aria-live="polite"`.
  - `wythe plugins [--json]` (plus `GET /api/v1/adapters/plugins` and
    MCP `wythe_plugins`) lists built-in (`tach-boundaries`,
    `container-sources`) and optional `wythe.plugins` companions
    (`wythe-plugin-agent-harness`, `wythe-plugin-cpsat`,
    `wythe-plugin-solver-chronicle`, `wythe-plugin-apple-ipc`,
    `wythe-plugin-compiler-ir`, `wythe-plugin-solver-internals`,
    `wythe-plugin-binary`, `wythe-plugin-wiretap`) with explicit
    `interaction_capabilities` and `evidence_source_kinds` without
    executing target repo code (`--allow-local-plugins` is CLI-only).
  - **Optional Solver, IR, Binary & Wiretap Companion CLI Flags:**
    When companion packages are installed (or passed via
    `--allow-local-plugins --plugin ...`), `wythe context`,
    `wythe scan`, `wythe companion`, and `wythe security companion`
    accept read-only `--index-store`, `--sil`, `--llvm-ir`,
    `--metallib`, `--proto-descriptor`, `--compile-commands`,
    repeatable `--binary`, and passive wiretap `--otel-traces`,
    `--ebpf-flows`, `--memgraph`, `--vmmap`, `--port-listeners`, and
    opt-in `--probe-local-ports` flags (`--cp-model-proto` /
    `--cp-solver-response` for CP-SAT, and `wythe watch-solver` for
    6-phase chronicles)—failing closed with install guidance when a
    required companion plugin is absent, never invoking `ldd`,
    build tools, or target binaries (`automated_security_audit:
    false`).
  - **Shared Human-Agent Investigation & Six-Link Understanding
    Quickstart:**
    1. *Human quickstart (Browser / Accessible Mode):* Run
       `wythe serve /path/to/repo`, select a node or finding in 3D or
       `AccessibleIndexView`, copy the per-tab `session_id` (or share
       `#target=<slug>&session=<id>`), submit clarifications via
       **Challenge / Add Correction** (`promoted_to_ruling: false`),
       diff source changes via **Compare Revisions**, and inspect the
       **Six-Link Understanding Chain** (`Intent -> Effective Policy ->
       Execution -> Committed Result -> Human-Visible Result ->
       Preservation Checks`).
    2. *External-agent quickstart (Stdio / HTTP MCP / CLI):* Point an
       agent at the same `session_id` via `wythe focus --session-id
       <id>`, MCP `wythe_what_is_this(session_id="<id>")`,
       `wythe_focus_camera(session_id="<id>", correlation_id="...")`
       (verified via `POST /api/v1/viewport/receipts`
       `applied_by_browser` vs `paused_by_human`),
       `wythe_investigation(action="explain_understanding", ...)`, or
       `wythe understand schedule-policy-to-export --json`.
  - `wythe export-openlineage /path/to/repo [--profile auto] [--out openlineage.json]` (plus `GET /api/v1/scans/{slug}/openlineage`, MCP `wythe_openlineage`, and the Governance **Export OpenLineage** button) exports Tier-1 datasets and Tier-2 jobs as OpenLineage static JSON.
  - `wythe security companion /path/to/repo [--trivy-report FILE] [--syft-sbom FILE] [--json FILE]` (or `wythe scan ... --companion-out FILE`) correlates static blueprint findings with read-only `Syft` SBOM and `Trivy` CVE/SARIF artifacts.
  - **MCP:** Connect coding agents directly to `http://127.0.0.1:8780/api/v1/mcp` (Streamable HTTP) or `wythe mcp` (stdio).
- **Architecture & Security References:**
  - [Containers, Security Workflows & Plugin Architecture](architecture/containers-security-and-plugins.md) — `Dockerfile`/`.dockerignore`/`.docker/`, Compose, and Kubernetes manifest lineage (`$(VAR_NAME)` vs. `$VAR`), `Syft`+`Trivy` Blue/Red/Purple CI handoffs, `wythe.plugins`, and `tach.toml` (`MANIP-006`) + OpenLineage bridges.
  - [Ecosystem Reference & Positioning](architecture/ecosystem-and-positioning.md) — Comparison across layer linters, schema engines, SAST/runtime tracers, container scanners, and enterprise catalogs.
  - [Multi-Language & Multi-Database Extensibility](architecture/multi-language-extensibility.md) and [Experimental Record-Ownership Workflow](architecture/record-ownership.md).

> **Epistemic Guardrail:** Static reachability (`DISP-004` vs. `DISP-007`), zero discovered callers (`MANIP-003`, `TRUTH-001`), declared dependency edges (`dashed`), and 3D proximity (`Linked Components`) are investigation leads—never proof of runtime dead code, safe deletion, or production health. Always verify dynamic imports, external webhooks/workers, and test/build suites before removing code.

> **Security & Data-Handling Boundary:** `wythe serve` is an unauthenticated local workstation server (`127.0.0.1` default), and JSON receipts, `wythe context`/`llms`/`mcp`, and `What's This?` briefs contain local paths and source/AST excerpts—see [SECURITY.md](../SECURITY.md) for bind-host limits, read-only catalog `--dsn` credentials, and `wythe security` non-certification bounds.
