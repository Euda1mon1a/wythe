<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/icon/icon-light.svg">
    <img src="docs/icon/icon-dark.svg" width="96" height="96" alt="Wythe icon — three architectural wythe bars mortised by a Why (?) triskelion and Therefore (∴) core">
  </picture>
</p>

# Wythe

**Why (`?`) → Therefore (`∴`)** — Generalizable 3-tier architecture verifier, cross-boundary lineage solver, interactive 3D WebGL latticework visualizer, and fail-closed CI gate built around three masonry wythe invariants:

1. **Database holds truth** — Relational schemas (`PostgreSQL`, `MySQL`, `SQLite` via `SQLAlchemy 2.0`/`SQLModel` + `Alembic`, `Prisma`, `Drizzle ORM`, `Kysely` migrations, `@immich/sql-tools` decorators, `Django ORM`, Rust `sqlx`/`Diesel`/`SeaORM`, or raw SQL DDL/`sqlc` + optional read-only catalog probes) own domain policy, thresholds, temporal validity, and write-lane guards, while `Redis` keyspaces and worker queues are modeled explicitly as ephemeral stores/lanes with independently verified purpose declarations rather than durable shadow truth.
2. **Backend manipulates truth** — Services, background workers, solvers, routers, and static container/orchestration declarations (`Python/FastAPI`, `TypeScript/Node/Express/Hono/Fastify/NestJS/Next.js/SvelteKit/tRPC`, `Python/Django/DRF/Ninja`, `Go net/http/chi/gin/echo`, `Rust axum/actix-web/rocket/Tauri`, plus `Dockerfile`/`.dockerignore`/`.docker/`, `compose.yaml`/`docker-compose.*.yml`, Kubernetes manifests, and `tach.toml` domain walls) execute mechanisms over database rows behind explicit transactional service/SQL doors across single or multi-root workspaces without embedding shadow policy literals or host-clock drift.
3. **Frontend displays truth** — UI surfaces (`Next.js`, `React/Vite/TanStack Router/Remix`, `Vue 3/Nuxt`, `Svelte 5/SvelteKit`, `Rust WASM Leptos/Dioxus/Yew` + Tauri `invoke()`) bind to typed OpenAPI SDK (`Hey API`, `oazapfts`), `tRPC`, and REST contracts, centralized clock utilities, and WCAG-accessible markup without inventing client-side policy maps or unbacked HTTP/IPC calls.

Wythe supports **38 stack profiles** via `--profile auto` (**1 production-dogfooded Tier-1 profile** + **36 `experimental` profiles**, including partial-coverage `INCOMPLETE` profiles + **1 `planned` slot**), pairs Python's native `ast` with an optional **Tree-sitter CST grammar engine** (`wythe[treesitter]` for TypeScript/TSX, JavaScript, Rust, and Go), traces background worker & scheduled beat queues (`Celery` / `Beat`, `BullMQ` / NestJS `@Processor`/`@InjectQueue`, `Asynq`), augments any profile via **`wythe.plugins`** (`container-sources` + `tach-boundaries` `MANIP-006`) and **OpenLineage** static export, enforces **WCAG accessibility semantics** (`DISP-005`), renders both **Simple Solids** and **120 fps Breathing Atomic Wythe Polyhedra** (with adaptive `System | Dark | Light` polarity and custom user palettes), and **self-dogfoods** its own 3-tier codebase (`wythe gate --strict wythe` passes with zero blocking and zero warning findings).

> [!IMPORTANT]
> **Status, Maturity & Zero-Maintenance Notice (`"AS IS"`)**
> - **No Maintenance Promises:** Wythe is released free under the MIT License strictly **"AS IS"** as an open-source give-back from internal engineering work. The author makes **zero promises of ongoing maintenance, bug fixes, feature requests, support, SLAs, or issue/PR turnaround**. Pin exact tags or commit SHAs in CI (e.g., `Euda1mon1a/wythe@v0.2.2` or `wythe==0.2.2`) and fork freely. See [`SUPPORT.md`](SUPPORT.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or pull request.
> - **Tier-1 vs. Experimental Adapters:** Only **`fastapi-sqlalchemy-nextjs`** (`postgres-sqlalchemy` + `python-fastapi` + `typescript-nextjs`) is marked **`implemented`** (production-hardened & self-dogfooded). The other **36 experimental profiles** (`nextjs-prisma`, `node-kysely-react`, `node-sql-tools-sveltekit`, `django-nextjs`, `postgres-drizzle-nextjs`, `postgres-go-react`, `rust-fullstack-wasm`, partial-coverage profiles, etc.) are marked **`experimental`**—prefer `wythe diff` or `.wythe/governance.json` ratchets before enabling `--strict`.

---

## Instant Usage (`uvx` / `uv`)

Run Wythe directly from [PyPI (`wythe`)](https://pypi.org/project/wythe/) without polluting project dependencies (add `[treesitter]` to enable prebuilt Tree-sitter CST wheels for TS/TSX, JS, Rust, and Go):

```bash
# Instant CLI gate & lineage scan directly from PyPI
uvx "wythe[treesitter]" scan /path/to/repo
uvx "wythe[treesitter]" diff /path/to/repo --base origin/main
uvx "wythe[treesitter]" gate --strict /path/to/repo

# Launch single-port API + interactive 3D WebGL UI on http://127.0.0.1:8780 (no Node.js runtime needed)
uvx "wythe[treesitter]" serve /path/to/repo

# Or install persistently as an isolated CLI tool
uv tool install "wythe[treesitter]"
wythe serve .
```

### Exploring the full graph (see the [User Guide](docs/user-guide.md))

The 3D/2D view represents every scanned node matching the current filters with no node or connection sampling limit. Distant nodes appear as dots; zooming in reveals detailed shapes in both Atomic and Simple modes. The HUD count panel separates the visible graph, nodes hidden by filters or collapsed groups, and detailed meshes inside the camera view.

- **Layout `[L]`** selects **Domain Districts** (`cluster`), **Uniform Grid** (`grid`), **Role Subkinds** (`subkind`), or **Linked Components** (`connected`, which pulls edge-connected nodes closer and packs singletons separately).
- **`Compact visible`** repacks only the currently visible/filtered/working-set nodes to remove empty space and re-fits the camera; ordinary filters keep global coordinates stable until you opt in.
- **`3D Tiers` ↔ `2D Flat`** flattens the three strata onto a single `y = 0` plane; **`Pin` (`Pinned ★`)** locks individual node coordinates across layout changes.
- **Working sets & collapsible groups:** Use **`Isolate visible`**, **`+ Add visible`**, and **`Group: Domain | Subkind`** to build focused views with boundary-crossing `+Expand (+K)` links, and persist layouts as **`Saved views`** (reconciled across commit/digest changes).
- **4-state edge styling, diagnostic lenses & filters:** **Connected only** hides isolated nodes in the active view; **Neighborhood: 1 hop / 2 hops** and symbol-scoped **Cone `[C]`** (`AtlasEdge.symbol_links`) follow connections in either direction; diagnostic lenses include **`Containers`** (`cluster="containers"` highlighting `m:dockerfile:*`, `m:compose:*`, and `m:k8s:*` nodes and their linked entrypoints); edge styles distinguish **Solid** (`verified`), **Dashed** (`declared`), **Dotted** (`unverified`), and **Gap** (`broken`).
- **Fit view & Governance exports:** **Fit view** frames the active selection or visible set while zooming toward the pointer; **Gate & Rules** surfaces registered `wythe.plugins` status alongside **`Export OpenLineage`** JSON downloads.

Selected and traced nodes remain pinned outside ordinary filters (with the extra count shown explicitly; `Connected-only` has no pin exception). Hidden or disconnected nodes remain in the scan and index; missing static connections are never proof of dead code or safe deletion. Rendering the entire scan does not extend the scanner's coverage.

### GitHub Actions Integration

Pin an explicit release tag (do not track unpinned branches if you want zero-surprise builds):

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: Euda1mon1a/wythe@v0.2.2
  with:
    mode: diff
    base-ref: origin/main
    sarif-file: wythe.sarif.json
```

---

## Persisted Rule Catalog (`atlas_rule_policies`)

Rule severity, enablement, gate-blocking behavior, and effective-date windows live in database truth (`atlas_rule_policies`) and round-trip cleanly to Git via `.wythe/governance.json`:

| Code | Tier | Default | Description |
| :--- | :--- | :--- | :--- |
| `TRUTH-001` | `truth` | Warning | Persisted input table has zero verified backend readers |
| `TRUTH-002` | `truth` | Blocking | ORM model, `schema.sql`/migrations, or live DB catalog table drift |
| `TRUTH-003` | `truth` | Blocking | Table or Redis store mutated directly inside HTTP route without service/DB door |
| `TRUTH-004` | `truth` | Warning | Unbounded Redis `SET`/`HSET` write without TTL risks volatile shadow truth |
| `TRUTH-005` | `truth` | Warning | A model's table exists in the live DB (`--dsn`) but no `schema.sql`/migration creates it |
| `MANIP-001` | `manipulate` | Blocking | Mutable domain policy/threshold constant hardcoded in code or container/service config, or active policy-table read bypassing policy columns (`atlas_policy_vocabularies`) |
| `MANIP-002` | `manipulate` | Blocking | Direct host `date.today()` or naive `datetime.now()` / `datetime.utcnow()` call |
| `MANIP-003` | `manipulate` | Warning | Service/solver module has zero verified inbound route, CLI, container, or worker callers |
| `MANIP-004` | `manipulate` | Warning | Service, launchd, Dockerfile, Compose, or Kubernetes launch declaration has an invalid command or unexpanded `$VAR`/`~` path (allowing K8s `$(VAR_NAME)`) |
| `MANIP-005` | `manipulate` | Warning | Deployment or Dockerfile `COPY`/`ADD` references an absent/`.dockerignore`-excluded source or omits a transitive runtime import |
| `MANIP-006` | `manipulate` | Blocking | Cross-domain Python import violates `tach.toml` horizontal module or public `[[interfaces]]` boundary |
| `DISP-001` | `display` | Blocking | Display tier defines domain policy threshold shadows in frontend code |
| `DISP-002` | `display` | Blocking | Raw `new Date()` or UTC `.toISOString().slice(0, 10)` date slicing |
| `DISP-003` | `display` | Warning | Frontend API client omits `api-generated` OpenAPI/schema types |
| `DISP-004` | `display` | Blocking | Frontend HTTP/IPC call targets a path absent from backend router graph, in code a page can reach |
| `DISP-005` | `display` | Warning | Display markup violates core WCAG semantics (missing `alt`, unlabeled form input, nameless icon button, non-keyboard `<div onClick>`) |
| `DISP-006` | `display` | Warning | Call path is built at runtime (`/${kind}/items`) and could match real routes: reported for review, not called broken |
| `DISP-007` | `display` | Warning | Call to a missing route with no discovered entry path; retained for removal or reconnection review |
| `DISP-008` | `display` | Warning | Display API call cannot be verified because backend route coverage is incomplete |

**How a frontend call with no matching route is classified.** A call served by the frontend's own Next.js `route.ts` / `pages/api` handler is not a backend call and is not reported. A path built at runtime that could match real routes is `DISP-006`. On the `typescript-nextjs` and `typescript-react` display adapters, Wythe follows imports per exported symbol from entry pages/layouts/roots (honoring `tsconfig` path aliases, barrels, re-exports, and dynamic imports); a call in a symbol nothing reaches is `DISP-007`. Everything else is `DISP-004`, and its detail names the page/entry trail that reaches it. When the analysis cannot tell, it treats the call as reachable, so a real defect is never demoted to a warning by a parsing gap. Other display profiles keep `DISP-004` for every unmatched call.

**Separate databases and migration DDL.** SQLAlchemy models on a second declarative base (their own metadata, often another database or schema) are not checked for drift against the primary schema and are listed in the scan notes. Alembic `upgrade()` DDL is read from literals, module-level constants (including f-strings), and helper functions it calls, in `down_revision` order, so a table a later revision drops is no longer counted as created.

---

**Reachability and removal decisions.** With the Tree-sitter extra, a lazy import such as `import('./widgets').then(m => m.Chart)` reaches the selected export while retaining barrel dependencies and import-time initializers. Unknown export selectors conservatively retain all exports; runtime-selected module paths are explicitly unresolved. Scan notes record these distinctions, and additional import dependencies appear as `declared` edges in the existing blast-radius graph. `DISP-007` keeps inactive broken calls visible. A small blast radius or a missing caller is evidence for review, not proof that deletion is safe: check external entry points, registration side effects and the relevant build/tests before removing code or reconnecting its useful behavior. Without a usable CST, import execution stays conservative.

**Python services and operational declarations (experimental).** The `python-services` profile maps Python imports, literal importlib targets and package initializers outside an `app/` layout, shell script references, launchd commands, and JSON command fields under `config/` or `configs/`. It also recognizes literal deployment constructors whose first fields are `repo_path` and `live_path`, including source-to-installed-path renames. These are **declared** edges, not proof of admission, installation or execution. Module summaries distinguish source references, deployment-only references, and no discovered references; none certifies safe deletion. Missing deployment source files and invalid launchd commands are review warnings. Coverage notes name exclusions, parse failures and unresolved dynamic imports. This profile does not analyze UI/custom HTTP routes, evaluate job eligibility, execute installers, or query running services. Use `wythe scan /path/to/services --profile python-services` and inspect the coverage notes before interpreting a passing gate.

**Policy field-to-result consumption (`PolicyFieldConsumption`).**
On Python `reads_truth` edges, Tier-1 policy tables, Tier-2 readers,
`wythe context` cones, and `NodeInspector`, Wythe classifies policy
columns (`policy_columns`, matched via `atlas_policy_vocabularies`
and cap/limit/quota/threshold stems) into three epistemic states:
`consumed` (`field_controls_result`, where `>=1` policy column
reaches a live return, branch guard, solver/helper call, or write
sink; `policy.cap or FALLBACK_CAP` records `fallback_constants`
without false alarm), `bypassed` (`constant_or_fallback_wins`, where
an active reader touches non-policy fields, dead branches, or
overwritten locals while leaving `unconsumed_policy_columns` unused
or substituting `substituted_constants`, emitting a causal
`MANIP-001` policy-bypass finding targeting `t:<table>`), and
`unresolved` (`dynamic_or_opaque_flow`, for `getattr(row, dyn_name)`,
dynamic subscripts, or opaque whole-row handoffs).

**Containers, Kubernetes, `tach.toml` & `wythe.plugins` (`cluster="containers"`).** Across every stack profile, built-in `wythe.plugins` augmenters statically inspect `Dockerfile`/`Containerfile` (including `.docker/` subdirectories) and `.dockerignore`, `compose.yaml`/`docker-compose.*.yml`, Kubernetes manifests (`Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `Pod`, `ConfigMap` in root or `k8s/`, `kubernetes/`, `manifests/`, `deploy/`, `deployments/`, `.k8s/`, safely skipping Helm/Mustache `{{` templates with a coverage note), and `tach.toml` modular-monolith walls (`MANIP-006`). Container and K8s edges populate `AtlasEdge.symbol_links` (`*->sym` on callable entrypoints like `dramatiq app.tasks:process_queue`, falling back to whole-module `[]` on framework variable/router hubs like `uvicorn app.main:app` or `celery -A app.worker.celery_app`) so Lineage Cones stay surgical without severing mounted routers or tasks; K8s `$(VAR_NAME)` parenthesized interpolation is honored while bare `$VAR`/`~` in exec arrays triggers `MANIP-004`, and literal policy tokens in Compose `environment:` or K8s `env:`/`ConfigMap.data` trigger `MANIP-001`. Scanning never imports or executes `.py` files from a target repository unless `--allow-local-plugins` is explicitly passed on the CLI.

**Deletion and rename diffs.** `wythe diff` resolves the requested base to an exact commit and scans its committed files in a temporary directory, without checking out or executing target code. It traverses the base and current graphs separately, retaining removed nodes, their old callers and import-time dependencies. Renames include both paths. New violation counts still use current-side changed lines. `PASS` means the diff gate found no blocking findings on those lines; it does not certify safe deletion. Invalid bases exit with code 2. If the base cannot be reconstructed (including unresolved symlinks or submodules), JSON and SARIF explicitly report incomplete evidence and the CLI exits 2.

## CLI Commands

```bash
# Scan any supported full-stack repository (--profile auto)
wythe scan /path/to/repo --json report.json --sarif report.sarif.json

# Optional metadata-only live DB & Redis keyspace probes (zero row or value reads;
# PostgreSQL table names come from pg_catalog, so a least-privilege role still sees every table)
wythe scan /path/to/repo \
  --dsn "postgresql://readonly@127.0.0.1:5432/appdb" \
  --redis-dsn "redis://127.0.0.1:6379/0"

# Opt-in: confirm unbacked calls against a RUNNING backend (one unauthenticated GET each,
# never a write; loopback/private hosts only unless --probe-allow-remote).
# 404 confirms a missing path; 401/403/422 means the route exists and the finding moves to DISP-006.
wythe scan /path/to/repo --probe-url http://127.0.0.1:8000

# PR diff gate & directional 3-tier blast-radius slice
wythe diff /path/to/repo --base origin/main --sarif diff.sarif.json

# Git-portable governance bundle (.wythe/governance.json) for CI runners
wythe export-config /path/to/repo
wythe gate --sync-config /path/to/repo

# Inspect trusted built-in / entry-point plugins & export OpenLineage static JSON
wythe plugins --json
wythe export-openlineage /path/to/repo --profile auto --out openlineage.json

# Correlate blueprint findings with read-only post-build Syft SBOM & Trivy JSON/SARIF artifacts
wythe security companion /path/to/repo \
  --syft-sbom sbom.cdx.json \
  --trivy-report trivy.sarif \
  --json companion-handoff.json

# Single-port API + 3D WebGL UI (auto-registers target directory on startup)
wythe serve /path/to/repo --host 127.0.0.1 --port 8780
```

### Record ownership (experimental)

Inspect one ownership hypothesis without importing or executing the target:

```bash
wythe security ownership /path/to/repo \
  --handler backend/app/api/records.py:update_record \
  --record record --principal user.id --json ownership-evidence.json

# Separately execute the shipped synthetic vulnerable/repaired examples only:
wythe security ownership-demo --json ownership-demo.json
```

The source report shows route/dependency declarations, recognized record lookups
and writes, owner comparisons, line evidence and unknowns. It always leaves
runtime enforcement **unknown**. The demonstration checks two identities, HTTP
responses and database contents in fresh in-memory applications: the same
regression fails before the example repair and passes afterward. Neither command
tests a live target. See the [scope, limitations and exit codes](docs/architecture/record-ownership.md)
and [SECURITY.md](SECURITY.md) for non-certification bounds, isolated
`wythe_examples` packaging, and local-bind rules.

---

## First-Class LLM & Human ↔ Vision/MCP Bridge (On-Device AI, Streamable HTTP MCP, OpenAPI & WebMCP)

Full JSON scans on large repositories span megabytes; Wythe exposes five zero-copy-paste Human ↔ LLM surfaces spanning bare-minimum on-device models through remote Tailnet agents:

1. **Zero-Setup On-Device AI (`Ask AI [A]` / `⌘J`, `/api/v1/ask`)** — Zero-cloud, zero-API-key cascade with real-time Three.js camera-frustum & screen-color telemetry, `1024px` WebP vision frames, and rolling multi-turn sessions across:
   - **Apple Intelligence (`apple`)**: macOS 26+/27 native `FoundationModels` helper (`arm64-apple-macos26.0`, serialized with `modelmanagerd` backoff).
   - **Chrome Built-In (`chrome`)**: Client-side browser `LanguageModel` (Gemini Nano via Prompt API, including 1-click download and multimodal WebGL `<canvas>` vision when enabled).
   - **Local OpenAI `/v1` (`local`)**: Auto-probes browser-host & server loopback `/v1/models` & `/v1/chat/completions` (`:8080`/`:8084`/`:8083` MLX, `:11434` Ollama, `:1234` LM Studio) without triggering weight reloads.
2. **Streamable HTTP MCP (`POST /api/v1/mcp` & `GET /api/v1/mcp`) + Stdio MCP (`wythe mcp`)** — Connect local or remote Tailnet coding agents (`http://<host>:8780/api/v1/mcp`) with zero local install.
3. **OpenAPI 3.1 (`/openapi.json`, `/api/v1/adapters/plugins`, `/api/v1/scans/{slug}/openlineage`) + Remote CLI (`wythe focus --remote <url>`)** — Universal HTTP tool/Actions compatibility, read-only plugin and OpenLineage JSON endpoints, plus cross-host CLI X-Ray inspection.
4. **In-Tab WebMCP (`navigator.modelContext` & `window.wythe`)** — Exposes `whatIsThis()`, `getLineageCone(query)`, `selectNode(nodeId)`, and `ask(question)` directly to browser agents and extensions.
5. **Token-Budgeted `llms.txt` & Lineage Cone Slicer** — Deterministic ~2,000-token repo maps and ~300-token 3-tier cones.

```bash
# 1. Token-budgeted llms.txt pointer map (~2,000 tokens regardless of repo size)
wythe llms /path/to/repo --max-tokens 2200 --out llms-wythe.txt

# 2. Surgical ~300-token 3-tier Lineage Cone around any table, file, route, or queue (add --full for complete slice)
wythe context /path/to/repo audit_exports
wythe context /path/to/repo /api/v1/scans --full --json

# 3. Zero-copy-paste Human <-> LLM Bridge (local state or remote private/Tailnet server)
wythe focus
wythe focus --remote http://100.64.0.10:8780

# 4. Zero-dependency read-only stdio MCP server (or connect directly to http://127.0.0.1:8780/api/v1/mcp)
wythe mcp
```

MCP client configuration (Stdio or Streamable HTTP — exposes `wythe_what_is_this`, `wythe_list_targets`, `wythe_overview`, `wythe_lineage_cone`, `wythe_blast_radius`, `wythe_findings`, `wythe_plugins`, `wythe_openlineage`):

```json
{
  "mcpServers": {
    "wythe-http": {
      "url": "http://127.0.0.1:8780/api/v1/mcp"
    },
    "wythe-stdio": {
      "command": "uvx",
      "args": ["wythe[treesitter]", "mcp"]
    }
  }
}
```

---

## Adapter Maturity Matrix

Only the dogfooded Python/SQLAlchemy/Next.js trio is classified **`Implemented`**; secondary polyglot adapters are classified **`Experimental`** (`atlas_stack_profiles.implementation_status = 'experimental'`):

| Stratum | Adapter Key | Maturity | Stack Coverage |
| :--- | :--- | :--- | :--- |
| **Tier 1 (Truth)** | `postgres-sqlalchemy` | **Implemented** | SQLAlchemy 1.x/2.0, `SQLModel`, nested `Alembic`, `schema.sql` + PG/MySQL/SQLite live catalog |
| **Tier 1 (Truth)** | `prisma-schema` | Experimental | Prisma `schema.prisma` (`@@map`) + `prisma/migrations/*.sql` + live catalog probe |
| **Tier 1 (Truth)** | `drizzle-orm` | Experimental | Drizzle `pgTable`/`mysqlTable`/`sqliteTable` + Drizzle SQL migrations + live catalog probe |
| **Tier 1 (Truth)** | `kysely-migrations` | Experimental | Kysely `SchemaBuilder` up-migration replay (`createTable`/`alterTable`/`renameTable`/`CamelCasePlugin`) + SQL functions + live catalog probe |
| **Tier 1 (Truth)** | `sql-tools` | Experimental | `@immich/sql-tools` `@Table`/columns/FKs/indexes/checks/triggers & `registerFunction()` + live catalog probe |
| **Tier 1 (Truth)** | `django-orm` | Experimental | Django `models.Model` (`Meta.db_table`) + `migrations/*.py` + live catalog probe |
| **Tier 1 (Truth)** | `sql-ddl` | Experimental | Multi-dialect SQL DDL + `golang-migrate`/`goose`/`Flyway` + `sqlc` + live catalog probe |
| **Tier 1 (Truth)** | `rust-sql` | Experimental | Rust `sqlx` (`migrations/*.sql`, `query_file!`), `Diesel` (`table!`), `SeaORM` entities + live catalog probe |
| **Tier 1 (Truth)** | `no-truth` | Experimental | Explicit placeholder reporting `INCOMPLETE` coverage for unsupported persistence layers |
| **Tier 1 (Ephemeral)** | `redis-ephemeral` | **Implemented** | Cross-language Redis keyspaces, verified `StorePurposeDeclaration`s, & `Celery`/`Beat`, `BullMQ`, `Asynq` queues |
| **Tier 2 (Manipulate)** | `python-fastapi` | **Implemented** | FastAPI routers, Python services/workers/CLI, SQLAlchemy/`SQLModel`/SQL AST |
| **Tier 2 (Manipulate)** | `python-services` | Experimental | Python scripts/imports, shell and launchd references, JSON command declarations, literal deployment mappings |
| **Tier 2 (Manipulate)** | `typescript-node` | Experimental | Multi-root TypeScript workspaces, Next.js `route.ts`, SvelteKit `+page.server.ts`/`+server.ts`, Express, Hono, Fastify, NestJS (`RouteKey` controllers, inherited DI, BullMQ `@Processor`/`@InjectQueue`), `tRPC` routers/procedures, Kysely & Prisma queries |
| **Tier 2 (Manipulate)** | `python-django` | Experimental | Django `urls.py` & `urls/` packages (`path`, `re_path`, `include`), DRF `ViewSet`/routers, CBVs (`APIView`/`ViewSet`), Django Ninja + `Model.objects` |
| **Tier 2 (Manipulate)** | `go-http` | Experimental | Go 1.22+ `net/http`, `chi`, `gin`, `echo` (nested router groups) + `sqlc`/GORM/SQL |
| **Tier 2 (Manipulate)** | `rust-http` | Experimental | Rust Cargo workspaces, `axum`, `actix-web`, `rocket`, Tauri `#[tauri::command]` + `sqlx`/Diesel/SeaORM |
| **Tier 2 (Manipulate)** | `no-manipulator` | Experimental | Explicit placeholder reporting `INCOMPLETE` coverage for frontend-only or unsupported backends |
| **Tier 3 (Display)** | `no-display` | Experimental | Explicitly unobserved UI for the service-only profile |
| **Tier 3 (Display)** | `typescript-nextjs` | **Implemented** | Next.js App & Pages Router + `Hey API` / `oazapfts` / `tRPC` clients + Tauri `invoke()` + cross-component WCAG `DISP-005` |
| **Tier 3 (Display)** | `typescript-react` | Experimental | React SPA, Vite, React Router, TanStack Router, Remix + `Hey API` / `oazapfts` / `tRPC` clients + WCAG `DISP-005` |
| **Tier 3 (Display)** | `vue-sfc` | Experimental | Vue 3 & Nuxt 3 `.vue` SFCs + composables (`$fetch`, `useFetch`) + WCAG `DISP-005` |
| **Tier 3 (Display)** | `sveltekit` | Experimental | Svelte 5 & SvelteKit `+page.svelte`, `+page.ts`, `#lib`/`$lib`, `oazapfts` SDK barrels + WCAG `DISP-005` |
| **Tier 3 (Display)** | `rust-wasm` | Experimental | Rust WASM `Leptos`, `Dioxus`, `Yew` (`gloo-net` / `reqwest` / Tauri WASM) + WCAG `DISP-005` |

---

## Empirical Corpus Benchmarks (Dogfood + Wild Open-Source Repos)

The [Open WebUI source audit](docs/audits/open-webui.md) records the 0.1.7 repairs, measured coverage and remaining gaps. Its FastAPI/Svelte profile remains experimental.

Every stack family has been scanned against synthetic regression suites and pinned open-source repositories (`wythe[treesitter]==0.2.2`):

| Repository | Profile (`--profile auto`) | Maturity | Tier 1 (Truth) | Tier 2 (Manipulate) | Tier 3 (Display) | Verified Edges / E2E Chains | Notes & Observed Boundaries |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`Euda1mon1a/wythe`** (`v0.2.2`) | `fastapi-sqlalchemy-nextjs` | **Implemented** | 7 tables, 1 SQL fn | 9 routes, 71 services | 1 page, 27 hooks/clients | **346 / 31** | Self-dogfooded (`PASS --strict`, 0 blocking, 0 warnings) |
| **`fastapi/full-stack-fastapi-template`** (`aabb90126964`) | `fastapi-react-spa` | Experimental | 2 tables | 6 routes, 7 services | 10 pages, 58 hooks/clients | **229 / 39** | SQLModel + nested Alembic + Hey API OpenAPI SDK (`0` `DISP-004`/`007`) |
| **`makeplane/plane`** (`9cefae892c4c`) | `django-nextjs` | Experimental | 112 tables, 34 Redis | 109 routes, 238 services | 58 pages, 1,590 UI nodes | **5,095 / 300** | Imported Django URL packages & CBVs; Next.js `pages`+`app` (`300` report cap) |
| **`docmost/docmost`** (`3a3e812f25e8`) | `node-kysely-react` | Experimental | 49 tables, 16 fn, 14 Redis/BullMQ | 70 routes, 486 services | 26 pages, 817 UI nodes | **3,854 / 300** | Kysely `CamelCasePlugin` replay + NestJS BullMQ `@Processor`/`@InjectQueue` |
| **`calcom/cal.com`** (`ef7954d16ab5`) | `nextjs-prisma` | Experimental | 100 Prisma tables, 2 Redis | 341 routes/tRPC, 1,055 services | 80 pages, 701 UI nodes | **3,580 / 293** | Multi-root TypeScript workspace (`apps/*`, `packages/*`) + tRPC lineage |
| **`immich-app/immich`** (`e5d6eb7be678`) | `node-sql-tools-sveltekit` | Experimental | 71 tables, 28 SQL fn | 55 routes, 348 services | 123 pages, 454 UI nodes | **3,777 / 300** | `@immich/sql-tools` + `RouteKey` + inherited DI + `oazapfts` SDK (`0` `DISP-004`/`007`) |
| **`umami-software/umami`** (`d3c62a805bed`) | `nextjs-prisma` | Experimental | 41 Prisma tables | 156 routes, 189 query/service modules | 64 pages, 758 UI nodes | **3,162 / 294** | `(group)` route dirs & `prisma.client.*` wrappers |
| **`usememos/memos`** (`9ee06fdc4722`) | `postgres-go-react` | Experimental | 13 SQL tables | 5 Go routes, 2 services | 17 pages, 307 UI nodes | **1,224 / 0** | Intra-tier Go + React resolve; Connect-RPC (`proto/`) is non-REST |
| **`lldap/lldap`** (`99c510a7a603`) | `rust-fullstack-wasm` | Experimental | 12 SeaORM tables | 64 Rust modules | 2 Yew WASM pages, 47 components | **412 / 0** | Intra-tier SeaORM + Yew WASM resolve; GraphQL (`schema.graphql`) is non-REST |

---

## FAQ & Known Limitations

**1. Which stacks are production-ready vs. experimental?**
`fastapi-sqlalchemy-nextjs` (`PostgreSQL`/`SQLite` + `SQLAlchemy 2.0`/`Alembic` + `Python/FastAPI` + `Next.js/TypeScript`) is Tier-1 dogfooded (`implemented`). All **36** other enabled stack profiles are **`experimental`**. On experimental profiles, start with `wythe scan`, `wythe llms`, `wythe context`, or `wythe diff --base origin/main` (or capture a `.wythe/governance.json` ratchet ceiling) rather than turning on `wythe gate --strict` blind.

**2. What happens if my app uses GraphQL, gRPC / Connect-RPC, or Next.js Server Actions?**
Wythe resolves **HTTP REST** (`RouteDescriptor` ↔ `FrontendHttpCall` including **Hey API** & **`oazapfts`** OpenAPI SDKs), **tRPC** (`/trpc/<procedure>` routers ↔ React/Next.js `trpc.*` hooks), and **Tauri IPC** (`#[tauri::command]` ↔ `invoke()`). On **GraphQL** (`lldap`), **Connect-RPC / gRPC** (`memos`), or **React Server Actions (`"use server"`)**, Wythe still extracts intra-tier DB tables, backend call graphs, and frontend component graphs, but cross-tier HTTP E2E chains read `0` and rules like `TRUTH-001`, `MANIP-003`, or `DISP-004` should be ratcheted or disabled in `.wythe/governance.json`.

**3. Why ship a static analyzer, SARIF CI gate, interactive 3D/2D WebGL UI, and local AI/MCP bridges in one wheel?**
So `uvx "wythe[treesitter]" serve /path/to/repo` works in one command on any machine with zero Node.js toolchain, zero cloud API keys, and zero split-version drift between the CLI gate, MCP server, and visual X-Ray UI. Core `wythe` stays lightweight; prebuilt Tree-sitter C grammars are isolated in the optional `[treesitter]` extra.

**4. Is Wythe actively maintained, or can I request features / SLAs?**
**No.** Wythe is shared openly as a free community give-back from internal R&D, provided strictly **"AS IS"** under MIT with **zero commitment to maintain, patch, review PRs, triage issues, or preserve backward compatibility**. Pin exact versions in CI and fork freely.

### User Guide, Architecture & Ecosystem Docs
- [`docs/user-guide.md`](docs/user-guide.md) — Interactive 3D/2D WebGL usage, working-set compaction (`Compact visible`, `Linked Components`, `2D Flat`, Saved Views), `Containers` lens, keyboard shortcuts, scoped rulings/store purposes, CLI flags, and epistemic guardrails.
- [`docs/architecture/containers-security-and-plugins.md`](docs/architecture/containers-security-and-plugins.md) — `Dockerfile`/`.dockerignore`/`.docker/`, Compose, and Kubernetes manifest lineage (`$(VAR_NAME)` vs. `$VAR`), two-stage `Syft` + `Trivy` Blue/Red/Purple CI handoffs, `wythe.plugins`, `tach.toml` (`MANIP-006`), and OpenLineage export.
- [`docs/architecture/ecosystem-and-positioning.md`](docs/architecture/ecosystem-and-positioning.md) — Ecosystem comparison (`tach`, `import-linter`, `dependency-cruiser`, `Ariga Atlas`, `SQLGlot`/`SQLLineage`, `OpenLineage`, `Syft`, `Trivy`, `Semgrep`) and pairing `tach` + Wythe in CI.
- [`docs/architecture/multi-language-extensibility.md`](docs/architecture/multi-language-extensibility.md) — Language-neutral intermediate contract, `AtlasEdge.symbol_links`, adapter maturity matrix, pinned corpus benchmarks, and non-REST transport boundaries.

---

## Local Development

```bash
make types      # Export OpenAPI 3.1 -> generate TypeScript schema types -> run tsc --noEmit
make build-ui   # Build static Next.js export into backend/app/ui_dist
make lint       # Run ruff check
make test       # Run serial pytest suite
make gate       # Run strict self-dogfood 3-tier + WCAG gate
make package    # Build standalone wheel & sdist containing bundled 3D WebGL UI
```

## License & Disclaimer

MIT — see [`LICENSE`](LICENSE). Provided strictly **"AS IS"**, without warranty of any kind and with **no promise of ongoing maintenance or support**.
