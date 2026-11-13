<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/icon/icon-light.svg">
    <img src="docs/icon/icon-dark.svg" width="96" height="96" alt="Wythe icon — three architectural wythe bars mortised by a Why (?) triskelion and Therefore (∴) core">
  </picture>
</p>

# Wythe

**Why (`?`) → Therefore (`∴`)** — Generalizable 3-tier architecture verifier, cross-boundary lineage solver, interactive 3D WebGL latticework visualizer, and fail-closed CI gate built around three masonry wythe invariants:

1. **Database holds truth** — Relational schemas (`PostgreSQL`, `MySQL`, `SQLite` via `SQLAlchemy 2.0` + `Alembic`, `Prisma`, `Drizzle ORM`, `Django ORM`, Rust `sqlx`/`Diesel`/`SeaORM`, or raw SQL DDL/`sqlc` + optional read-only catalog probes) own domain policy, thresholds, temporal validity, and write-lane guards, while `Redis` keyspaces and worker queues are modeled explicitly as ephemeral stores/lanes rather than durable shadow truth.
2. **Backend manipulates truth** — Services, background workers, solvers, and routers (`Python/FastAPI`, `TypeScript/Node/Express/Hono/Fastify/NestJS/Next.js/SvelteKit`, `Python/Django/DRF/Ninja`, `Go net/http/chi/gin/echo`, `Rust axum/actix-web/rocket/Tauri`) execute mechanisms over database rows behind explicit transactional service/SQL doors without embedding shadow policy literals or host-clock drift.
3. **Frontend displays truth** — UI surfaces (`Next.js`, `React/Vite/TanStack Router/Remix`, `Vue 3/Nuxt`, `Svelte 5/SvelteKit`, `Rust WASM Leptos/Dioxus/Yew` + Tauri `invoke()`) bind to typed contracts, centralized clock utilities, and WCAG-accessible markup without inventing client-side policy maps or unbacked HTTP/IPC calls.

Wythe supports **19 stack profiles** via `--profile auto` (**1 production-dogfooded Tier-1 profile** + **17 `experimental` profiles** + **1 `planned` slot**), pairs Python's native `ast` with an optional **Tree-sitter CST grammar engine** (`wythe[treesitter]` for TypeScript/TSX, JavaScript, Rust, and Go), traces background worker & scheduled beat queues (`Celery` / `Beat`, `BullMQ`, `Asynq`), enforces **WCAG accessibility semantics** (`DISP-005`), renders both **Simple Solids** and **120 fps Breathing Atomic Wythe Polyhedra** (with adaptive `System | Dark | Light` polarity and custom user palettes), and **self-dogfoods** its own 3-tier codebase (`wythe gate --strict wythe` passes with zero blocking and zero warning findings).

> [!IMPORTANT]
> **Status, Maturity & Zero-Maintenance Notice (`"AS IS"`)**
> - **No Maintenance Promises:** Wythe is released free under the MIT License strictly **"AS IS"** as an open-source give-back from internal engineering work. The author makes **zero promises of ongoing maintenance, bug fixes, feature requests, support, SLAs, or issue/PR turnaround**. Pin exact tags or commit SHAs in CI (e.g., `Euda1mon1a/wythe@v0.1.3` or `wythe==0.1.3`) and fork freely. See [`SUPPORT.md`](SUPPORT.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or pull request.
> - **Tier-1 vs. Experimental Adapters:** Only **`fastapi-sqlalchemy-nextjs`** (`postgres-sqlalchemy` + `python-fastapi` + `typescript-nextjs`) is marked **`implemented`** (production-hardened & self-dogfooded). The other **17 experimental profiles** (`nextjs-prisma`, `postgres-drizzle-nextjs`, `postgres-go-react`, `rust-fullstack-wasm`, `django-react`, etc.) are marked **`experimental`**—prefer `wythe diff` or `.wythe/governance.json` ratchets before enabling `--strict`.

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

### GitHub Actions Integration

Pin an explicit release tag (do not track unpinned branches if you want zero-surprise builds):

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: Euda1mon1a/wythe@v0.1.3
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
| `MANIP-001` | `manipulate` | Blocking | Mutable domain policy/threshold constant hardcoded in code (`atlas_policy_vocabularies`) |
| `MANIP-002` | `manipulate` | Blocking | Direct host `date.today()` or naive `datetime.now()` / `datetime.utcnow()` call |
| `MANIP-003` | `manipulate` | Warning | Service/solver module has zero verified inbound route, CLI, or worker callers |
| `DISP-001` | `display` | Blocking | Display tier defines domain policy threshold shadows in frontend code |
| `DISP-002` | `display` | Blocking | Raw `new Date()` or UTC `.toISOString().slice(0, 10)` date slicing |
| `DISP-003` | `display` | Warning | Frontend API client omits `api-generated` OpenAPI/schema types |
| `DISP-004` | `display` | Blocking | Frontend HTTP/IPC call targets a path absent from backend router graph, in code a page can reach |
| `DISP-005` | `display` | Warning | Display markup violates core WCAG semantics (missing `alt`, unlabeled form input, nameless icon button, non-keyboard `<div onClick>`) |
| `DISP-006` | `display` | Warning | Call path is built at runtime (`/${kind}/items`) and could match real routes: reported for review, not called broken |
| `DISP-007` | `display` | Warning | Call to a missing route with no discovered entry path; retained for removal or reconnection review |

**How a frontend call with no matching route is classified.** A call served by the frontend's own Next.js `route.ts` / `pages/api` handler is not a backend call and is not reported. A path built at runtime that could match real routes is `DISP-006`. On the `typescript-nextjs` and `typescript-react` display adapters, Wythe follows imports per exported symbol from entry pages/layouts/roots (honoring `tsconfig` path aliases, barrels, re-exports, and dynamic imports); a call in a symbol nothing reaches is `DISP-007`. Everything else is `DISP-004`, and its detail names the page/entry trail that reaches it. When the analysis cannot tell, it treats the call as reachable, so a real defect is never demoted to a warning by a parsing gap. Other display profiles keep `DISP-004` for every unmatched call.

**Separate databases and migration DDL.** SQLAlchemy models on a second declarative base (their own metadata, often another database or schema) are not checked for drift against the primary schema and are listed in the scan notes. Alembic `upgrade()` DDL is read from literals, module-level constants (including f-strings), and helper functions it calls, in `down_revision` order, so a table a later revision drops is no longer counted as created.

---

**Reachability and removal decisions.** With the Tree-sitter extra, a lazy import such as `import('./widgets').then(m => m.Chart)` reaches the selected export while retaining barrel dependencies and import-time initializers. Unknown export selectors conservatively retain all exports; runtime-selected module paths are explicitly unresolved. Scan notes record these distinctions, and additional import dependencies appear as `declared` edges in the existing blast-radius graph. `DISP-007` keeps inactive broken calls visible. A small blast radius or a missing caller is evidence for review, not proof that deletion is safe: check external entry points, registration side effects and the relevant build/tests before removing code or reconnecting its useful behavior. Without a usable CST, import execution stays conservative.

**Python services and operational declarations (experimental).** The `python-services` profile maps Python imports, literal importlib targets and package initializers outside an `app/` layout, shell script references, launchd commands, and JSON command fields under `config/` or `configs/`. It also recognizes literal deployment constructors whose first fields are `repo_path` and `live_path`, including source-to-installed-path renames. These are **declared** edges, not proof of admission, installation or execution. Module summaries distinguish source references, deployment-only references, and no discovered references; none certifies safe deletion. Missing deployment source files and invalid launchd commands are review warnings. Coverage notes name exclusions, parse failures and unresolved dynamic imports. This profile does not analyze UI/custom HTTP routes, evaluate job eligibility, execute installers, or query running services. Use `wythe scan /path/to/services --profile python-services` and inspect the coverage notes before interpreting a passing gate.

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

# Single-port API + 3D WebGL UI (auto-registers target directory on startup)
wythe serve /path/to/repo --host 127.0.0.1 --port 8780
```

---

## First-Class LLM & Human ↔ Vision/MCP Bridge (On-Device AI, Streamable HTTP MCP, OpenAPI & WebMCP)

Full JSON scans on large repositories span megabytes; Wythe exposes five zero-copy-paste Human ↔ LLM surfaces spanning bare-minimum on-device models through remote Tailnet agents:

1. **Zero-Setup On-Device AI (`Ask AI [A]` / `⌘J`, `/api/v1/ask`)** — Zero-cloud, zero-API-key cascade with real-time Three.js camera-frustum & screen-color telemetry, `1024px` WebP vision frames, and rolling multi-turn sessions across:
   - **Apple Intelligence (`apple`)**: macOS 26+/27 native `FoundationModels` helper (`arm64-apple-macos26.0`, serialized with `modelmanagerd` backoff).
   - **Chrome Built-In (`chrome`)**: Client-side browser `LanguageModel` (Gemini Nano via Prompt API, including 1-click download and multimodal WebGL `<canvas>` vision when enabled).
   - **Local OpenAI `/v1` (`local`)**: Auto-probes browser-host & server loopback `/v1/models` & `/v1/chat/completions` (`:8080`/`:8084`/`:8083` MLX, `:11434` Ollama, `:1234` LM Studio) without triggering weight reloads.
2. **Streamable HTTP MCP (`POST /api/v1/mcp` & `GET /api/v1/mcp`) + Stdio MCP (`wythe mcp`)** — Connect local or remote Tailnet coding agents (`http://<host>:8780/api/v1/mcp`) with zero local install.
3. **OpenAPI 3.1 (`/openapi.json`) + Remote CLI (`wythe focus --remote <url>`)** — Universal HTTP tool/Actions compatibility plus cross-host CLI X-Ray inspection.
4. **In-Tab WebMCP (`navigator.modelContext` & `window.wythe`)** — Exposes `whatIsThis()`, `getLineageCone(query)`, `selectNode(nodeId)`, and `ask(question)` directly to browser agents and extensions.
5. **Token-Budgeted `llms.txt` & Lineage Cone Slicer** — Deterministic ~2,000-token repo maps and ~300-token 3-tier cones.

```bash
# 1. Token-budgeted llms.txt pointer map (~2,000 tokens regardless of repo size)
wythe llms /path/to/repo --max-tokens 2200 --out llms-wythe.txt

# 2. Surgical ~300-token 3-tier Lineage Cone around any table, file, route, or queue
wythe context /path/to/repo audit_exports
wythe context /path/to/repo /api/v1/scans --json

# 3. Zero-copy-paste Human <-> LLM Bridge (local state or remote private/Tailnet server)
wythe focus
wythe focus --remote http://100.64.0.10:8780

# 4. Zero-dependency read-only stdio MCP server (or connect directly to http://127.0.0.1:8780/api/v1/mcp)
wythe mcp
```

MCP client configuration (Stdio or Streamable HTTP — exposes `wythe_what_is_this`, `wythe_list_targets`, `wythe_overview`, `wythe_lineage_cone`, `wythe_blast_radius`, `wythe_findings`):

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
| **Tier 1 (Truth)** | `postgres-sqlalchemy` | **Implemented** | SQLAlchemy 2.0 + Alembic + `schema.sql` + PG/MySQL/SQLite live catalog |
| **Tier 1 (Truth)** | `prisma-schema` | Experimental | Prisma `schema.prisma` (`@@map`) + `prisma/migrations/*.sql` |
| **Tier 1 (Truth)** | `drizzle-orm` | Experimental | Drizzle `pgTable`/`mysqlTable`/`sqliteTable` + Drizzle SQL migrations |
| **Tier 1 (Truth)** | `django-orm` | Experimental | Django `models.Model` (`Meta.db_table`) + `migrations/*.py` |
| **Tier 1 (Truth)** | `sql-ddl` | Experimental | Multi-dialect SQL DDL + `golang-migrate`/`goose`/`Flyway` + `sqlc` |
| **Tier 1 (Truth)** | `rust-sql` | Experimental | Rust `sqlx` (`migrations/*.sql`, `query_file!`), `Diesel` (`table!`), `SeaORM` entities |
| **Tier 1 (Ephemeral)** | `redis-ephemeral` | **Implemented** | Cross-language Redis keyspaces + `Celery`/`Beat`, `BullMQ`, & `Asynq` named queues |
| **Tier 2 (Manipulate)** | `python-fastapi` | **Implemented** | FastAPI routers, Python services/workers/CLI, SQLAlchemy/SQL AST |
| **Tier 2 (Manipulate)** | `python-services` | Experimental | Python scripts/imports, shell and launchd references, JSON command declarations, literal deployment mappings |
| **Tier 2 (Manipulate)** | `typescript-node` | Experimental | Next.js `route.ts`, SvelteKit `+page.server.ts`/`+server.ts`, Express, Hono, Fastify, NestJS |
| **Tier 2 (Manipulate)** | `python-django` | Experimental | Django `urls.py` (`path`/`re_path`), DRF `ViewSet`/routers, Django Ninja + `Model.objects` |
| **Tier 2 (Manipulate)** | `go-http` | Experimental | Go 1.22+ `net/http`, `chi`, `gin`, `echo` (nested router groups) + `sqlc`/GORM/SQL |
| **Tier 2 (Manipulate)** | `rust-http` | Experimental | Rust Cargo workspaces, `axum`, `actix-web`, `rocket`, Tauri `#[tauri::command]` + `sqlx`/Diesel/SeaORM |
| **Tier 3 (Display)** | `no-display` | Experimental | Explicitly unobserved UI for the service-only profile |
| **Tier 3 (Display)** | `typescript-nextjs` | **Implemented** | Next.js App & Pages Router + custom fetch/RTK Query + Tauri `invoke()` + WCAG `DISP-005` |
| **Tier 3 (Display)** | `typescript-react` | Experimental | React SPA, Vite, React Router, TanStack Router, Remix + barrel exports + WCAG `DISP-005` |
| **Tier 3 (Display)** | `vue-sfc` | Experimental | Vue 3 & Nuxt 3 `.vue` SFCs + composables (`$fetch`, `useFetch`) + WCAG `DISP-005` |
| **Tier 3 (Display)** | `sveltekit` | Experimental | Svelte 5 & SvelteKit `+page.svelte`, `+page.ts`, `$lib` + WCAG `DISP-005` |
| **Tier 3 (Display)** | `rust-wasm` | Experimental | Rust WASM `Leptos`, `Dioxus`, `Yew` (`gloo-net` / `reqwest` / Tauri WASM) + WCAG `DISP-005` |

---

## Empirical Corpus Benchmarks (Dogfood + Wild Open-Source Repos)

Every stack family has been scanned against synthetic test fixtures and multi-thousand-line real-world repositories (`wythe[treesitter]`):

| Repository | Profile (`--profile auto`) | Maturity | Tier 1 (Truth) | Tier 2 (Manipulate) | Tier 3 (Display) | Verified Edges / E2E Chains | Notes & Observed Boundaries |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`Euda1mon1a/wythe`** | `fastapi-sqlalchemy-nextjs` | **Implemented** | 7 tables, 1 SQL fn | 53 routes & services | 23 pages/hooks/clients | **260 edges / 29 E2E** | Self-dogfooded (`PASS --strict`, 0 blocking, 0 warnings) |
| **Production scheduling stack** | `fastapi-sqlalchemy-nextjs` | **Implemented** | 294 tables, 30 SQL guards, 15 Redis | 1,362 routes, services & solvers | 630 pages, hooks & clients | **10,056 edges / 300 E2E** | Continuous multi-thousand-file production target |
| **`umami-software/umami`** (`d3c62a805bed`) | `nextjs-prisma` | Experimental | 41 Prisma tables | 156 routes, 189 query/service modules | 64 pages, 758 hooks/components | **3,162 edges / 294 E2E** | Resolves `(main)` route groups & `prisma.client.*`; 4 dynamic URL `DISP-004`s |
| **`sadmann7/shadcn-table`** (`f4438fda7864`) | `postgres-drizzle-nextjs` | Experimental | 1 Drizzle table | 3 routes, 5 query/db modules | 8 pages, 88 hooks/components | **140 edges / 1 E2E** | `0` `DISP-004`; Next.js Server Actions bypass HTTP routes |
| **`vintasoftware/django-react-boilerplate`** (`340e19b11249`) | `django-react` | Experimental | 1 Django table, 1 Redis | 3 route modules, 14 services | 5 React UI modules | **13 edges / 0 E2E** | `PASS --strict` (`0` blocking); uses generated OpenAPI client |
| **`usememos/memos`** (`9ee06fdc4722`) | `postgres-go-react` | Experimental | 13 SQL tables | 5 Go route modules, 2 services | 17 pages, 307 UI modules | **1,224 edges / 0 E2E** | Intra-tier Go + React graphs resolve; Connect-RPC (`proto/`) is non-REST |
| **`lldap/lldap`** (`99c510a7a603`) | `rust-fullstack-wasm` | Experimental | 12 SeaORM tables | 64 Rust backend modules | 2 Yew WASM pages, 47 components | **412 edges / 0 E2E** | Intra-tier SeaORM + Yew WASM graphs resolve; GraphQL (`schema.graphql`) is non-REST |

---

## FAQ & Known Limitations

**1. Which stacks are production-ready vs. experimental?**
`fastapi-sqlalchemy-nextjs` (`PostgreSQL`/`SQLite` + `SQLAlchemy 2.0`/`Alembic` + `Python/FastAPI` + `Next.js/TypeScript`) is Tier-1 dogfooded (`implemented`). All 17 other enabled stack profiles are **`experimental`**. On experimental profiles, start with `wythe scan`, `wythe llms`, `wythe context`, or `wythe diff --base origin/main` (or capture a `.wythe/governance.json` ratchet ceiling) rather than turning on `wythe gate --strict` blind.

**2. What happens if my app uses GraphQL, gRPC / Connect-RPC, tRPC, or Next.js Server Actions instead of HTTP REST?**
Wythe's cross-tier linker currently matches HTTP REST paths (`RouteDescriptor` ↔ `FrontendHttpCall`) plus Tauri `#[tauri::command]` ↔ `invoke()`. On GraphQL (`lldap`), Connect-RPC/gRPC (`memos`), tRPC, or React Server Actions (`"use server"`), Wythe still extracts intra-tier DB tables, backend call graphs, and frontend component graphs, but cross-tier HTTP E2E chains will read `0` and rules like `TRUTH-001`, `MANIP-003`, or `DISP-004` may fire until ratcheted or disabled in `.wythe/governance.json`.

**3. Why ship a static analyzer, SARIF CI gate, 120 fps 3D WebGL UI, and local AI/MCP bridges in one wheel?**
So `uvx "wythe[treesitter]" serve /path/to/repo` works in one command on any machine with zero Node.js toolchain, zero cloud API keys, and zero split-version drift between the CLI gate, MCP server, and visual X-Ray UI. Core `wythe` stays lightweight; prebuilt Tree-sitter C grammars are isolated in the optional `[treesitter]` extra.

**4. Is Wythe actively maintained, or can I request features / SLAs?**
**No.** Wythe is shared openly as a free community give-back from internal R&D, provided strictly **"AS IS"** under MIT with **zero commitment to maintain, patch, review PRs, triage issues, or preserve backward compatibility**. Pin exact versions in CI and fork freely.

### Architecture & Ecosystem Docs
- [`docs/architecture/ecosystem-and-positioning.md`](docs/architecture/ecosystem-and-positioning.md) — Ecosystem comparison (`tach`, `import-linter`, `dependency-cruiser`, `sqllineage`, `OpenLineage`, `CodeCharta`, `Semgrep`) and pairing `tach` + Wythe in CI.
- [`docs/architecture/multi-language-extensibility.md`](docs/architecture/multi-language-extensibility.md) — Language-neutral intermediate contract, adapter maturity matrix, wild OSS corpus benchmarks, and non-REST boundaries.

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
