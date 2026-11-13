# Multi-Language & Multi-Database Extensibility Architecture

Wythe separates **language-specific syntax extraction** from **language-agnostic cross-tier lineage, policy governance, and 3D/2D visualization**. This document records the adapter contract and the industry-popularity matrix guiding tier expansion.

---

## 1. Language-Neutral Intermediate Contract

The core lineage solver (`_solve_cross_tier_lineage`), database policy filter (`evaluate_findings_and_gate`), ratchet engine, CLI gate, and WebGL/2D UI never inspect language ASTs directly. Every scan executes one **Stack Profile** (`atlas_stack_profiles`) binding three protocol slots:

1. **`TruthTierAdapter` (`tier="truth"`)** -> `TruthExtractionResult`
   - Emits normalized `AtlasNode` objects (`subkind="table"` or `"sql_function"`), `table_symbol_map` (mapping ORM class names, query symbols, and physical table names to `t:table:<name>`), `function_symbol_map`, `TRUTH-002` schema/catalog drift findings, and `observation_source`.
2. **`ManipulatorTierAdapter` (`tier="manipulate"`)** -> `ManipulatorExtractionResult`
   - Emits route/service/solver/CLI `AtlasNode` objects, intra-tier `calls_helper` edges, `reads_truth` / `writes_truth` / `guards_truth` edges into `TruthExtractionResult`, normalized `RouteDescriptor` regexes (`http_method`, `full_path`, `path_regex`), and `TRUTH-001`, `TRUTH-003`, `MANIP-001..003` candidate findings.
3. **`DisplayTierAdapter` (`tier="display"`)** -> `DisplayExtractionResult`
   - Emits page/hook/api_client/component `AtlasNode` objects, intra-tier `uses_hook` / `uses_client` edges, normalized `FrontendHttpCall` records (`http_method`, `normalized_path`), and `DISP-001..003` candidate findings (while the cross-tier solver emits `DISP-004` when a frontend call has no matching `RouteDescriptor`).

Because `StackProfile` rows compose any `(truth_adapter, manipulator_adapter, display_adapter)` tuple in database truth, `M` truth adapters × `N` manipulator adapters × `P` display adapters support `M × N × P` full-stack combinations without custom glue code.

---

## 2. Popularity-Ranked Tier Matrix & Maturity Classification

Only the dogfooded `fastapi-sqlalchemy-nextjs` trio (`postgres-sqlalchemy`, `python-fastapi`, `typescript-nextjs`) is marked **`Implemented`** in `atlas_stack_profiles` and `/api/v1/adapters/slots`. All 13 secondary polyglot adapters (and their 16 composed stack profiles) are marked **`Experimental`** so operators know to start with `wythe diff` or ratchets before strict gating.

### Tier 1 — Database & Schema/ORM Truth

| Adapter Key | Target Databases | Schema & ORM Sources | Status |
| :--- | :--- | :--- | :--- |
| `postgres-sqlalchemy` | PostgreSQL, MySQL, SQLite | SQLAlchemy 1.x/2.0 models, `schema.sql`, Alembic `op.create_table` + live read-only catalog probe | **Implemented** |
| `prisma-schema` | PostgreSQL, MySQL, SQLite, SQL Server, CockroachDB | `schema.prisma` (`model`, `@@map`, `@@schema`), `prisma/migrations/**/*.sql`, live catalog probe | Experimental |
| `drizzle-orm` | PostgreSQL, MySQL, SQLite | Drizzle `pgTable` / `mysqlTable` / `sqliteTable` TS schemas, `drizzle/**/*.sql`, live catalog probe | Experimental |
| `django-orm` | PostgreSQL, MySQL, SQLite | Django `models.Model` AST (`Meta.db_table` or `<app>_<model>`), `migrations/*.py` (`CreateModel`, `RunSQL`), live catalog probe | Experimental |
| `sql-ddl` | PostgreSQL, MySQL, SQLite | Raw `schema.sql` / `migrations/**/*.sql` (`golang-migrate`, `goose`, `Flyway`, `sqlx`) + `sqlc` `-- name:` query-to-table bindings + live catalog probe | Experimental |
| `rust-sql` | PostgreSQL, MySQL, SQLite | Rust `sqlx` (`migrations/*.sql` + `query_file!` SQL bindings), `Diesel` (`diesel::table!` in `schema.rs` + `up.sql`), `SeaORM` (`#[sea_orm(table_name)]` entities) + live catalog probe | Experimental |

### Tier 2 — Backend Manipulation

| Adapter Key | Languages & Frameworks | Route & Truth-Door Extraction | Status |
| :--- | :--- | :--- | :--- |
| `python-fastapi` | Python · FastAPI, SQLAlchemy, Celery/CLI | `APIRouter` mount + decorator synthesis, Python AST ORM/SQL read vs. write, helper call graph | **Implemented** |
| `typescript-node` | TypeScript / JS · Next.js Route Handlers (`route.ts`), Express, Hono, Fastify, NestJS | File-convention & router/decorator URL synthesis; Prisma (`prisma.*` & `prisma.client.*`), Drizzle, and raw SQL read vs. write; TS service/query graph | Experimental |
| `python-django` | Python · Django, Django REST Framework (`ViewSet`/routers), Django Ninja | `urls.py` (`path`, `re_path`, `include`, DRF `router.register`), `Model.objects` read vs. write AST, service/view split | Experimental |
| `go-http` | Go · `net/http` (Go 1.22+ ServeMux), `chi`, `gin`, `echo`, `fiber` + `sqlc` / `pgx` / `GORM` | Router group + verb handler synthesis, `sqlc` query symbol binding, GORM & SQL `Query` vs. `Exec`, package call graph | Experimental |
| `rust-http` | Rust · `axum`, `actix-web`, `rocket`, `Tauri v2` (`#[tauri::command]`) + `sqlx` / `Diesel` / `SeaORM` | `Router::route`/`nest`, `#[get]`/`#[post]`, and `#[tauri::command]` IPC synthesis; `sqlx::query!`/`query_file!`, Diesel, & SeaORM read vs. write; crate call graph | Experimental |
| `swift-vapor` | Swift · Vapor | Typed route handlers, Fluent ORM doors, & SwiftUI contract bindings | Planned |

### Tier 3 — Frontend Display

| Adapter Key | Languages & Frameworks | Surface & Contract Extraction | Status |
| :--- | :--- | :--- | :--- |
| `typescript-nextjs` | TypeScript / TSX · Next.js App Router & Pages Router + Tauri `invoke()` | `app/**/page.tsx` & `pages/**/*.tsx`, hooks, API clients, per-symbol reachability (`DISP-004`/`DISP-007`), OpenAPI/schema type check, WCAG `DISP-005` | **Implemented** |
| `typescript-react` | TypeScript / TSX · React SPA, Vite, React Router, TanStack Router, Remix + Tauri `invoke()` | `src/pages/**`, `src/routes/**`, `src/views/**`, `App.tsx`, hooks, per-symbol reachability (`DISP-004`/`DISP-007`), `fetch`/`axios`/Tauri `invoke`, WCAG `DISP-005` | Experimental |
| `vue-sfc` | Vue 3 / TypeScript · Vue Router & Nuxt 3 (`.vue` SFCs + composables + Tauri `invoke()`) | Line-accurate `<script setup>` / `<script>` & `<template>` extraction, `pages/**/*.vue`, `$fetch`/`useFetch`, WCAG `DISP-005` | Experimental |
| `sveltekit` | Svelte 5 / TypeScript · SvelteKit (`.svelte` + `$lib` + `+page.server.ts` + Tauri `invoke()`) | `src/routes/**/+page.svelte` & `+page.ts`, `$lib` alias resolution, line-accurate `<script>` & markup `DISP-005` | Experimental |
| `rust-wasm` | Rust (WASM) · `Leptos`, `Dioxus`, `Yew` + `gloo-net` / `reqwest` / Tauri WASM `invoke()` | `<Route path=.../>`, `#[route]`, `#[at]`, `Request::get/post/...`, WASM `DISP-001..005` checks | Experimental |

---

## 3. Read-Only Multi-Database & Ephemeral Redis Verification (`--dsn`, `--redis-dsn`)

All six Tier-1 Truth adapters share `probe_live_catalog_tables(dsn)` (`backend/app/adapters/db_catalog_probe.py`), performing **metadata-only** catalog reflection with zero table-row or PII reads:
- **PostgreSQL (`postgresql://` / `postgres://`)**: One autocommit read-only statement over `pg_catalog.pg_class` (ordinary and partitioned tables, partitions excluded). `information_schema.tables` is not used: it lists only tables the connecting role holds a privilege on.
- **MySQL / MariaDB (`mysql://`)**: Read-only metadata query against `information_schema.tables WHERE table_schema = DATABASE()`.
- **SQLite (`sqlite:///path/to/file.db`)**: Read-only URI connection (`mode=ro`) querying `sqlite_master WHERE type = 'table'`.

### Why Redis Is Inspected Ephemeral State (`cache_store`), Not Wythe's Own DB
Storing Wythe's own rules, ratchets, or audit rulings in Redis would violate the core architectural invariant (**Database holds durable truth**). Instead, `augment_redis_ephemeral_lineage` (`backend/app/adapters/redis_ephemeral.py`) inspects **target repositories' Redis usage** across Python (`redis-py`, `aioredis`, `django.core.cache`, `Celery`), TypeScript/Node (`ioredis`, `node-redis`, `@upstash/redis`, `BullMQ`), Go (`go-redis`, `asynq`), and Rust (`redis-rs`, `deadpool-redis`, `fred`):
- **3D & Lineage Representation**: Emits `t:redis:<namespace>` nodes (`tier="truth"`, `subkind="cache_store"`, `role="ephemeral"`), rendered as horizontal torus rings beside solid relational SQL cylinders on the Tier-1 plane.
- **`TRUTH-004` (`ephemeral_shadow_truth`)**: Flags unbounded Redis `SET` / `HSET` writes without an explicit TTL (`ex`/`px`/`setex`/`expire`), catching volatile shadow truth that can diverge from or evaporate independently of PostgreSQL/MySQL/SQLite.
- **Worker Queue Entry Doors**: Connects `Celery` (`@shared_task`, `@app.task`), `BullMQ` (`new Worker(...)`), and `Asynq` consumers/producers through `t:redis:queue_*` stores and clears false `MANIP-003` inert-module warnings on active background workers.
- **Zero-Value-Read `--redis-dsn` Probe**: Optional `redis://` / `rediss://` stdlib RESP check issuing ONLY `INFO keyspace` and `SCAN 0 COUNT 200` prefix discovery — never executing `GET`/`HGET`/`LRANGE` value reads.

---

## 4. Automatic Stack Detection, Custom Vocabularies & Portable CI Governance

1. **`--profile auto` (`autodetect.py`)**: Inspects deterministic repository markers (`Cargo.toml`, `prisma/schema.prisma`, `drizzle.config.*`, `manage.py`, `go.mod`, `sqlc.yaml`, `nuxt.config.*`, `svelte.config.*`, `next.config.*`, `vite.config.*`, `pyproject.toml`) to select an enabled `StackProfile` plus `backend_subdir` and `frontend_subdir`.
2. **DB-Backed Domain Policy Vocabularies (`atlas_policy_vocabularies`)**: `MANIP-001` and `DISP-001` query active domain packs (`scheduling`, `fintech`, `commerce`, `saas`, `custom`) dynamically from database truth across all 16 adapters — adding a token like `ROYALTY_BPS` flags hardcoded literals across Python, TypeScript, Go, and Rust with zero code changes.
3. **PR Diff Slicer, SARIF 2.1.0 & Git-Portable Config (`diff_and_sarif_service.py`, `portable_config_service.py`)**:
   - `wythe diff <target> --base origin/main --sarif results.sarif` gates **only newly introduced violations on changed hunks** while computing directional upstream/downstream 3-tier blast radius.
   - Base and current graphs are traversed separately. Deleted and renamed paths retain their before-image nodes and dependencies; invalid bases are rejected, and an unavailable base graph produces `INCOMPLETE` (CLI exit 2), never a passing removal certificate.
   - `wythe export-config` / `sync-config` (`gate --sync-config`) round-trip `.wythe/governance.json` so ephemeral CI runners hydrate DB rule policies, vocabularies, ratchets, and rulings from Git.

---

## 5. Wild Open-Source Corpus Benchmarks & Known Transport Boundaries

Every adapter family is evaluated on synthetic regression suites (`backend/tests/test_multilang_*.py`, `test_rust_stacks.py`) and benchmarked against real open-source full-stack repositories:

| Repository (`git rev-parse --short HEAD`) | Detected Profile | Tier-1 Truth | Tier-2 Manipulate | Tier-3 Display | Verified Edges / E2E Chains | Observed Parser & Transport Boundaries |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`Euda1mon1a/wythe`** | `fastapi-sqlalchemy-nextjs` (**Implemented**) | 7 tables, 1 SQL fn | 53 modules | 23 modules | **260 / 29** | `PASS --strict` (0 blocking, 0 warnings) |
| **Production scheduling system** | `fastapi-sqlalchemy-nextjs` (**Implemented**) | 294 tables, 30 SQL guards, 15 Redis | 1,362 modules | 630 modules | **10,056 / 300** | Multi-thousand-file production target |
| **`umami-software/umami`** (`d3c62a805bed`) | `nextjs-prisma` (Experimental) | 41 Prisma tables | 156 routes, 189 query/service modules | 64 pages, 758 hooks/components | **3,162 / 294** | Resolves Next.js `(group)` route dirs, `[[...slug]]` catch-alls, `/api`-stripped `useApi` calls, and `prisma.client.<model>.*` wrappers |
| **`sadmann7/shadcn-table`** (`f4438fda7864`) | `postgres-drizzle-nextjs` (Experimental) | 1 Drizzle table | 3 routes, 5 query/db modules | 8 pages, 88 hooks/components | **140 / 1** | `0` `DISP-004`; Next.js `"use server"` Server Actions bypass HTTP REST routes |
| **`vintasoftware/django-react-boilerplate`** (`340e19b11249`) | `django-react` (Experimental) | 1 Django table, 1 Redis | 3 route modules, 14 services | 5 React modules | **13 / 0** | `PASS --strict` (`0` blocking); generated OpenAPI SDK abstracts raw fetch URLs |
| **`usememos/memos`** (`9ee06fdc4722`) | `postgres-go-react` (Experimental) | 13 SQL tables | 5 Go route modules, 2 services | 17 pages, 307 UI modules | **1,224 / 0** | Intra-tier Go + React graphs resolve; Connect-RPC / gRPC (`proto/`) is non-REST |
| **`lldap/lldap`** (`99c510a7a603`) | `rust-fullstack-wasm` (Experimental) | 12 SeaORM tables | 64 Rust backend modules | 2 Yew WASM pages, 47 components | **412 / 0** | Multi-crate SeaORM + root `app/` Yew WASM resolve; GraphQL (`schema.graphql`) is non-REST |

### Known Non-REST Transport Limitations
`_solve_cross_tier_lineage` currently bridges HTTP REST paths (`RouteDescriptor.path_regex` ↔ `FrontendHttpCall.normalized_path`) and Tauri IPC (`#[tauri::command]` ↔ `invoke()`). Repositories using **GraphQL**, **gRPC / Connect-RPC**, **tRPC**, or **React Server Actions (`"use server"`)** still receive Tier-1 schema drift checks (`TRUTH-002`, `TRUTH-004`), Tier-2/3 clock & policy-literal checks (`MANIP-001/002`, `DISP-001/002`), and Tier-3 WCAG accessibility checks (`DISP-005`), but cross-tier REST chains will report `0` and rules assuming HTTP route entrypoints (`TRUTH-001`, `MANIP-003`, `DISP-004`) should be ratcheted or disabled in `.wythe/governance.json`.
