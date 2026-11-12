# Ecosystem Reference & Positioning (`tach` + Wythe)

This document maps existing open-source static analysis, dependency boundary, and data-lineage tools across PyPI (`uv`), npm, and GitHub, explains why none of them cover vertical 3-tier truth ownership alone, and defines how **Wythe** pairs with horizontal modular-monolith linters such as **`tach`**.

---

## 1. Open-Source Landscape Comparison

| Tool | Ecosystem / Install | Primary Capability | Boundary Where It Stops |
| :--- | :--- | :--- | :--- |
| **`tach`** (`gauge-sh/tach`) | Python (`uv tool install tach`, Rust core) | Enforces intra-Python modular-monolith import walls and public module interfaces (`tach.toml`, `tach check`, `tach map`). | **Single-language (`import` statements only).** Does not parse SQL DDL, separate ORM `SELECT` vs. `INSERT`, or cross HTTP routes into TypeScript. |
| **`import-linter`** (`seddonym/import-linter`) | Python (`uv add --dev import-linter`) | Declarative Python layer contracts (`layers`, `forbidden`, `independence`). | Inspects Python module imports only; blind to hardcoded policy constants, host-clock calls, ORM-to-DDL drift, or frontend callers. |
| **`pytest-archon`** | Python (`uv add --dev pytest-archon`) | Fluent `ArchUnit`-style architecture assertions inside `pytest`. | Asserts Python package import rules; no SQL catalog awareness or cross-tier HTTP route matching. |
| **`dependency-cruiser`** | JS / TS (`npx dependency-cruiser`) | Validates JS/TS module graphs, circular dependencies, and folder import rules; exports SVG/DOT/Mermaid. | **Stops at client `fetch()` / `api.get()`.** Cannot verify whether an API path exists on the backend or which database table backs it. |
| **`@nx/enforce-module-boundaries`** | Monorepo JS / TS (npm) | Workspace tag constraints across frontend/backend monorepo packages. | Enforces workspace package import tags; does not trace REST/RPC URL contracts or database table read/write lineage. |
| **`sqllineage`** / **`sqlglot`** | Python (`uv tool install sqllineage`) | Parses SQL dialects to extract warehouse `Table A -> Table B` and column-level ETL lineage. | Built for warehouse/dbt SQL pipelines; does not parse ORM model classes, HTTP routers, or UI components. |
| **`OpenLineage`** / **`Marquez`** / **`DataHub`** | Polyglot data platform (GitHub) | Runtime & metadata lineage across Spark, Airflow, dbt, and warehouses. | Data-engineering pipeline focus rather than full-stack transactional application architecture. |
| **`AppMap`** (`getappmap`) | Polyglot runtime agent (GitHub / IDE) | Records live HTTP requests, function calls, and SQL queries during test execution. | **Runtime-only.** Unhit routes, inert service modules (`MANIP-003`), and unread input tables (`TRUTH-001`) remain invisible unless exercised by a trace. |
| **`CodeCharta`** (`MaibornWolff/codecharta`) | Polyglot metrics visualizer (GitHub / npm) | 3D WebGL "code city" treemaps of LOC, cyclomatic complexity, and git churn. | Visualizes file-size and churn hotspots rather than 3-tier architectural strata or cross-language call chains. |
| **`Semgrep`** / **`Joern`** / **`CodeQL`** | Polyglot AST / CPG (`uv tool install semgrep`) | Custom pattern rules and security taint tracking across languages. | General SAST engines; no built-in router prefix synthesis, ORM-to-migration catalog diffing, or database-backed architectural ratchets. |

---

## 2. Why Wythe Exists: Epistemic Role vs. Import Topology

Traditional architecture linters (`tach`, `import-linter`, `dependency-cruiser`) verify **import topology**: *"Is module A allowed to import module B?"*

A full-stack codebase can pass 100% of its import rules while still suffering severe **truth-boundary decay**:
1. **Shadow policy in backend code (`MANIP-001`)** — `services/scheduling.py` legally imports `models/schedule.py`, yet hardcodes `MAX_WEEKLY_HOURS = 80` in Python instead of reading policy rows from the database.
2. **Orphaned database truth (`TRUTH-001`)** — A migration creates a policy table and seed rows, giving operators confidence that the database governs behavior, while zero backend services actually read that table.
3. **ORM-to-schema drift (`TRUTH-002`)** — An ORM model class declares a table or column absent from `schema.sql`, migrations, or the live database catalog.
4. **Unguarded route writes (`TRUTH-003`)** — An HTTP controller mutates ORM entities directly instead of routing writes through an explicit transactional service or SQL write-lane function.
5. **Clock authority split (`MANIP-002`, `DISP-002`)** — Backend code calls naive host `date.today()` / `time.Now()` or UI components slice UTC `.toISOString().slice(0, 10)`, shifting calendar dates across time zones.
6. **Broken HTTP seams (`DISP-003`, `DISP-004`)** — Frontend code calls an endpoint path that was renamed or deleted on the backend, or bypasses generated OpenAPI types.

Wythe audits **epistemic role across tiers**:
- **Tier 1 (Truth)**: Persisted tables, migrations, triggers, and SQL write-lane functions hold durable state and domain policy.
- **Tier 2 (Manipulate)**: Backend routes, services, and solvers read and mutate truth through guarded doors using a single clock authority.
- **Tier 3 (Display)**: Frontend pages, hooks/composables, and typed API clients render server-supplied truth without inventing shadow rules.

---

## 3. Running `tach` + Wythe Together (Horizontal + Vertical Guardrails)

`tach` and Wythe are **orthogonal complements**:

```text
                 HORIZONTAL MODULE WALLS (tach / dependency-cruiser)
                 ┌───────────────────────┬───────────────────────┐
  DISPLAY TIER   │  ui/billing/*         │  ui/scheduling/*      │  ─┐
                 ├───────────────────────┼───────────────────────┤   │ VERTICAL
  MANIPULATE     │  app/billing/*  ✗───► │  app/scheduling/*     │   │ TRUTH &
  TIER           │  (blocked by tach)    │                       │   │ LINEAGE
                 ├───────────────────────┼───────────────────────┤   │ (Wythe)
  TRUTH TIER     │  billing_ledgers      │  rotation_policies    │  ─┘
                 └───────────────────────┴───────────────────────┘
```

- Use **`tach`** (`tach.toml`) inside large Python backends (and **`dependency-cruiser`** inside large JS/TS frontends) to enforce **horizontal domain boundaries** between peer feature packages (`billing` cannot import internal helpers from `scheduling`).
- Use **Wythe** (`wythe gate`) across the repository to enforce **vertical 3-tier truth ownership**, cross-language `UI -> HTTP -> Backend -> DB` lineage, ORM/DDL/catalog parity, and database-governed downward-only ratchets:

```bash
# Recommended CI gate pairing horizontal module walls with vertical 3-tier truth verification
tach check && wythe gate --strict <target-slug>
```
