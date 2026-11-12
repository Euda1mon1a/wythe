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

Wythe supports **18 full-stack profiles** out of the box via `--profile auto`, pairs Python's native `ast` with an optional **Tree-sitter CST grammar engine** (`wythe[treesitter]` for TypeScript/TSX, JavaScript, Rust, and Go), traces background worker & scheduled beat queues (`Celery` / `Beat`, `BullMQ`, `Asynq`), enforces **WCAG accessibility semantics** (`DISP-005`), renders both **Simple Solids** and **120 fps Breathing Atomic Wythe Polyhedra** (with adaptive `System | Dark | Light` polarity and custom user palettes), and **self-dogfoods** its own 3-tier codebase (`wythe gate --strict wythe` passes with zero blocking and zero warning findings).

---

## Instant Usage (`uvx` / `uv`)

Run Wythe directly against any repository without polluting project dependencies (add `[treesitter]` to enable prebuilt Tree-sitter CST wheels for TS/TSX, JS, Rust, and Go):

```bash
# Instant CLI gate & lineage scan from PyPI (once published) or directly from GitHub
uvx "wythe[treesitter]" gate --strict /path/to/repo
uvx --from "git+https://github.com/Euda1mon1a/wythe[treesitter]" wythe scan /path/to/repo
uvx --from "git+https://github.com/Euda1mon1a/wythe[treesitter]" wythe gate --strict /path/to/repo

# Launch single-port API + interactive 3D WebGL UI on http://127.0.0.1:8780 (no Node.js runtime needed)
uvx --from "git+https://github.com/Euda1mon1a/wythe[treesitter]" wythe serve /path/to/repo

# Or install persistently as an isolated CLI tool
uv tool install "git+https://github.com/Euda1mon1a/wythe[treesitter]"
wythe serve .
```

### GitHub Actions Integration

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: Euda1mon1a/wythe@main
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
| `MANIP-001` | `manipulate` | Blocking | Mutable domain policy/threshold constant hardcoded in code (`atlas_policy_vocabularies`) |
| `MANIP-002` | `manipulate` | Blocking | Direct host `date.today()` or naive `datetime.utcnow()` call |
| `MANIP-003` | `manipulate` | Warning | Service/solver module has zero verified inbound route, CLI, or worker callers |
| `DISP-001` | `display` | Blocking | Display tier defines domain policy threshold shadows in frontend code |
| `DISP-002` | `display` | Blocking | Raw `new Date()` or UTC `.toISOString().slice(0, 10)` date slicing |
| `DISP-003` | `display` | Warning | Frontend API client omits `api-generated` OpenAPI/schema types |
| `DISP-004` | `display` | Blocking | Frontend HTTP/IPC call targets a path absent from backend router graph |
| `DISP-005` | `display` | Warning | Display markup violates core WCAG semantics (missing `alt`, unlabeled form input, nameless icon button, non-keyboard `<div onClick>`) |

---

## CLI Commands

```bash
# Scan any supported full-stack repository (--profile auto)
wythe scan /path/to/repo --json report.json --sarif report.sarif.json

# Optional metadata-only live DB & Redis keyspace probes (zero row or value reads)
wythe scan /path/to/repo \
  --dsn "postgresql://readonly@127.0.0.1:5432/appdb" \
  --redis-dsn "redis://127.0.0.1:6379/0"

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
      "args": ["--from", "git+https://github.com/Euda1mon1a/wythe[treesitter]", "wythe", "mcp"]
    }
  }
}
```

---

## Supported Multi-Language & Multi-DB Adapters

| Stratum | Adapter Key | Stack Coverage |
| :--- | :--- | :--- |
| **Tier 1 (Truth)** | `postgres-sqlalchemy` | SQLAlchemy 2.0 + Alembic + `schema.sql` + PG/MySQL/SQLite live catalog |
| **Tier 1 (Truth)** | `prisma-schema` | Prisma `schema.prisma` (`@@map`) + `prisma/migrations/*.sql` |
| **Tier 1 (Truth)** | `drizzle-orm` | Drizzle `pgTable`/`mysqlTable`/`sqliteTable` + Drizzle SQL migrations |
| **Tier 1 (Truth)** | `django-orm` | Django `models.Model` (`Meta.db_table`) + `migrations/*.py` |
| **Tier 1 (Truth)** | `sql-ddl` | Multi-dialect SQL DDL + `golang-migrate`/`goose`/`Flyway` + `sqlc` |
| **Tier 1 (Truth)** | `rust-sql` | Rust `sqlx` (`migrations/*.sql`, `query_file!`), `Diesel` (`table!`), `SeaORM` entities |
| **Tier 1 (Ephemeral)** | `redis-ephemeral` | Cross-language Redis keyspaces + `Celery`/`Beat`, `BullMQ`, & `Asynq` named queues |
| **Tier 2 (Manipulate)** | `python-fastapi` | FastAPI routers, Python services/workers/CLI, SQLAlchemy/SQL AST |
| **Tier 2 (Manipulate)** | `typescript-node` | Next.js `route.ts`, SvelteKit `+page.server.ts`/`+server.ts`, Express, Hono, Fastify, NestJS |
| **Tier 2 (Manipulate)** | `python-django` | Django `urls.py` (`path`/`re_path`), DRF `ViewSet`/routers, Django Ninja + `Model.objects` |
| **Tier 2 (Manipulate)** | `go-http` | Go 1.22+ `net/http`, `chi`, `gin`, `echo` (nested router groups) + `sqlc`/GORM/SQL |
| **Tier 2 (Manipulate)** | `rust-http` | Rust Cargo workspaces, `axum`, `actix-web`, `rocket`, Tauri `#[tauri::command]` + `sqlx`/Diesel/SeaORM |
| **Tier 3 (Display)** | `typescript-nextjs` | Next.js App & Pages Router + custom fetch/RTK Query + Tauri `invoke()` + WCAG `DISP-005` |
| **Tier 3 (Display)** | `typescript-react` | React SPA, Vite, React Router, TanStack Router, Remix + barrel exports + WCAG `DISP-005` |
| **Tier 3 (Display)** | `vue-sfc` | Vue 3 & Nuxt 3 `.vue` SFCs + composables (`$fetch`, `useFetch`) + WCAG `DISP-005` |
| **Tier 3 (Display)** | `sveltekit` | Svelte 5 & SvelteKit `+page.svelte`, `+page.ts`, `$lib` + WCAG `DISP-005` |
| **Tier 3 (Display)** | `rust-wasm` | Rust WASM `Leptos`, `Dioxus`, `Yew` (`gloo-net` / `reqwest` / Tauri WASM) + WCAG `DISP-005` |

### Architecture & Ecosystem Docs
- [`docs/architecture/ecosystem-and-positioning.md`](docs/architecture/ecosystem-and-positioning.md) — Ecosystem comparison (`tach`, `import-linter`, `dependency-cruiser`, `sqllineage`, `OpenLineage`, `CodeCharta`, `Semgrep`) and pairing `tach` + Wythe in CI.
- [`docs/architecture/multi-language-extensibility.md`](docs/architecture/multi-language-extensibility.md) — Language-neutral intermediate contract, adapter matrix, read-only DB/Redis probes, and `--profile auto` detection.

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

## License

MIT — see [`LICENSE`](LICENSE).
