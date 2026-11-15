# Ecosystem Reference & Positioning (`tach`, Lineage, Containers & Wythe)

This document maps open-source and enterprise tools across layer linters, schema/data lineage, SAST/runtime tracing, container scanners, and privacy/architecture suites. It explains objectively where single-domain tools go deeper, where **Wythe** statically crosses full-stack seams (`UI <-> HTTP` and `Backend <-> SQL`), and how Wythe natively ingests `tach.toml` boundaries and exports **OpenLineage** static facets.

For container source analysis (`Dockerfile`, `.dockerignore`, `compose.yaml`), Blue/Red/Purple workflows with `Syft` + `Trivy`, and the `wythe.plugins` extension architecture, see [Containers, Security Workflows & Plugin Architecture](containers-security-and-plugins.md).

---

## 1. Landscape Comparison Across Five Tool Families

### A. Open-Source Layer & Module-Boundary Linters

| Tool | Ecosystem / Install | Where It Excels | Boundary Where It Stops |
| :--- | :--- | :--- | :--- |
| **`tach`** (`gauge-sh/tach`) | Python (`uv tool install tach`, Rust core) | Fast intra-Python modular-monolith walls, ordered `layers`, `utility` modules, and `[[interfaces]]` symbol visibility (`tach.toml`, `tach check`, `tach sync`). | **Python `import` topology only.** Does not separate SQL `SELECT` vs. `INSERT`, diff ORM models against migrations, or match FastAPI/Django routes to TypeScript callers. *(Now bridged natively by Wythe as `MANIP-006`.)* |
| **`import-linter`** (`seddonym/import-linter`) | Python (`uv add --dev import-linter`) | Grimp-based Python import contracts (`layers`, `forbidden`, `independence`) + custom contracts via `importlinter.contracts` entry points. | Inspects Python module imports only; blind to hardcoded policy constants (`MANIP-001`), host-clock calls (`MANIP-002`), SQL DDL drift, and UI callers. |
| **`pytest-archon`** | Python (`uv add --dev pytest-archon`) | Fluent `ArchUnit`-style `archrule` assertions embedded directly inside `pytest` suites. | Evaluates Python package/module imports in test code; no database catalog parity, HTTP route synthesis, or cross-language lineage. |
| **`dependency-cruiser`** | JS / TS (`npx dependency-cruiser`) | Rich `.dependency-cruiser.js` graph rules (cycles, orphans, folder walls) and DOT/SVG/Mermaid export across JS/TS workspaces. | **Stops at `fetch()` / SDK / `invoke()`.** Cannot verify whether a target backend route exists (`DISP-004`) or which SQL table backs it. |
| **`@nx/enforce-module-boundaries`** | Monorepo JS / TS (npm / Nx) | Project-tag and scope rules (`scope:*`, `type:*`) governing package imports across large monorepos. | Governs workspace package imports; does not resolve REST/tRPC/IPC contracts or trace handler-to-table database mutations. |
| **`archlint`** / **`arch-lint`** | Python, Rust (`syn`), Go / TS | Lightweight AI-coding guardrails (e.g. Python layer checks from repo rules, Rust `arch-lint` crate rules, structural/MCP checks). | Enforces intra-language structural/layer rules; does not synthesize cross-language HTTP routes, ORM-to-DDL parity, or 3-tier E2E chains. |
| **`archgate`** | Cross-language CLI / guardrails | Enforces repository-level architectural decisions and structural conventions above per-file style linters for human and AI workflows. | Checks structural conventions rather than full-stack ORM/migration/live-catalog schema parity or cross-tier HTTP/RPC request lineage. |

### B. Schema Management & Data Lineage

| Tool | Ecosystem / Install | Where It Excels | Boundary Where It Stops |
| :--- | :--- | :--- | :--- |
| **`Ariga Atlas`** (`ariga/atlas`) | Database CLI (Go / HCL / SQL) | Declarative schema-as-code diffing, dev-database migration planning, destructive-change linting, and OpenTelemetry migration metrics. | Deep Tier-1 DDL lifecycle tool; does not trace which backend services read/write each table or which UI pages call those services. |
| **`SQLGlot`** / **`SQLLineage`** | Python (`uv add sqlglot`, `sqllineage`) | Multi-dialect SQL AST parsing/transpilation (`SQLGlot`) and warehouse `Table A -> Table B` + column-level ETL lineage (`SQLLineage`). | Built for SQL scripts, dbt, and analytical warehouses; does not parse imperative ORM code, HTTP routers, or frontend components. |
| **`OpenLineage`** (Static Lineage Facets) | Linux Foundation spec (JSON) | Vendor-neutral `JobEvent` / `DatasetEvent` metadata (`SourceCodeLocationJobFacet`, `SQLJobFacet`, `LineageDatasetFacet`) without an active `RunEvent`. | Metadata specification & transport rather than a full-stack code extractor. *(Wythe exports this format natively via `wythe export-openlineage`.)* |
| **`DataHub`** (Acryl Data) | Polyglot metadata platform | Enterprise catalog aggregating warehouse schemas, dbt/Airflow/Spark pipelines, ownership, and OpenLineage graphs. | Heavy platform service focused on data-engineering assets; relies on upstream producers (such as Wythe's OpenLineage export) for app-code lineage. |

### C. SAST, Code Property Graphs & Runtime Observability

| Tool | Ecosystem / Install | Where It Excels | Boundary Where It Stops |
| :--- | :--- | :--- | :--- |
| **`Semgrep`** / **`CodeQL`** / **`Joern`** | Polyglot AST / relational DB / CPG | Deep intra- and inter-procedural taint tracking, vulnerability pattern matching, and sanitizer verification across source code. | Security/bug-pattern engines; they do not synthesize router prefix trees, diff ORM models against live `pg_catalog`, or maintain DB-backed architecture ratchets. |
| **`AppMap`** (`getappmap`) | Runtime recorder (Python/JS/Java/Ruby) | Captures live HTTP requests, runtime call trees, and executed SQL statements during test or dev runs. | **Runtime-only.** Unexercised routes, inert modules (`MANIP-003`), and unread policy tables (`TRUTH-001`) stay invisible until hit by a test. |
| **`OpenTelemetry`** (`OTel`) | Polyglot runtime telemetry | Production distributed traces, spans, metrics, and logs across live services, queues, and databases. | Observes live traffic post-deploy; cannot statically gate unhit code paths, `.dockerignore` packaging omissions, or schema-vs-migration drift pre-build. |

### D. Container & Artifact Packaging Scanners

| Tool | Ecosystem / Install | Where It Excels | Boundary Where It Stops |
| :--- | :--- | :--- | :--- |
| **`Hadolint`** | Dockerfile linter (Haskell + ShellCheck) | Single-file Dockerfile best practices (`DL3008` package pinning, `DL3025` exec-form preference, inline shell linting, SARIF output). | Inspects the `Dockerfile` in isolation; cannot walk Python/TS import graphs or `.dockerignore` to notice an omitted transitive helper (`MANIP-005`). |
| **`Syft`** (`anchore/syft`) | Container / FS CLI | Authoritative post-build SBOM extraction (**CycloneDX**, **SPDX**) across OS layers (`apk`, `dpkg`, `rpm`) and language lockfiles/wheels. | Inventories installed packages inside the sealed crate; has no visibility into stripped `.git` history, UI source, or cross-tier app architecture. |
| **`Trivy`** (`aquasecurity/trivy`) | Container / IaC / CVE CLI | Matches SBOM/image packages against CVE advisories, scans IaC/Dockerfiles for misconfigurations and secrets, and emits JSON/SARIF. | Identifies vulnerable packages and IaC misconfigs, not whether an app route bypasses a service write door (`TRUTH-003`) or shadows DB policy (`MANIP-001`). |

### E. Enterprise Architecture & Privacy Suites

| Tool | Ecosystem / Delivery | Where It Excels | Boundary Where It Stops |
| :--- | :--- | :--- | :--- |
| **`CAST Imaging`** | Commercial enterprise platform (Neo4j + MCP) | Reverse-engineers large legacy + modern portfolios (mainframe, Java EE, .NET, SQL) into transaction graphs with an MCP server for impact analysis. | Heavyweight commercial server deployment rather than a zero-cloud MIT CLI/WebGL binary with `.wythe/governance.json` git ratchets. |
| **`Privado.ai`** | Privacy code scanner | Builds static personal-data-flow graphs tracing PII fields from collection sources to DB, log, and third-party API sinks for GDPR/CCPA mapping. | Specialized for PII/privacy compliance flows rather than general 3-tier schema parity, clock/policy invariants, or interactive 3D working-set compaction. |

---

## 2. Where Specialized Tools Go Deeper vs. Where Wythe Crosses Seams

Wythe does **not** replace specialized single-layer tools inside their home discipline:
- Use **`Semgrep` / `CodeQL` / `Joern`** for exploit-oriented taint tracking, injection analysis, and auth/crypto rule packs.
- Use **`Ariga Atlas`** to plan and lint SQL DDL migrations, and **`SQLGlot` / `SQLLineage`** for complex warehouse CTE column projections.
- Use **`tach`** (`tach check` / `tach sync`) and **`dependency-cruiser`** for fine-grained intra-language cycle banning and workspace tag matrices.
- Use **`Hadolint`**, **`Syft`**, and **`Trivy`** to lint `RUN` shell recipes, generate CycloneDX/SPDX SBOMs, and scan built OCI images for CVEs.
- Use **`OpenTelemetry`** and **`AppMap`** to observe dynamic dispatch, external webhooks, and live production behavior that static ASTs cannot prove.

Wythe fills the **cross-tier architectural seam** between those tools—verifying **epistemic role** (*who owns truth, who mutates it, and who displays it*) statically across languages before `docker build`:

```text
+--------------------------------------------------------------------+
| TIER 3: DISPLAY (Next.js / React / Vue / Svelte / WASM)            |
| Single-tier: dependency-cruiser, @nx/enforce-module-boundaries     |
| Wythe checks: DISP-001..008 (policy, clock, WCAG, reachability)    |
+---------------------------------+----------------------------------+
                                  |
       UI <-> HTTP / tRPC / IPC   |  (Single-tier import linters stop
       Resolved statically by     |   at fetch() / SDK / invoke() and
       Wythe cross-tier solver    |   cannot verify backend routes)
                                  v
+---------------------------------+----------------------------------+
| TIER 2: MANIPULATE (FastAPI / Django / Node / Go / Rust + Docker)  |
| Horizontal walls: tach (tach.toml -> MANIP-006), import-linter,    |
|                   pytest-archon, archlint, archgate                |
| Packaging/SAST:   Hadolint, Semgrep/CodeQL/Joern; AppMap/OTel(run) |
| Wythe checks:     MANIP-001..006 + Dockerfile/compose source graph |
+---------------------------------+----------------------------------+
                                  |
       Backend <-> SQL / Redis    |  (Import linters do not separate
       ORM/SQL reads vs. guarded  |   SELECT vs. INSERT or diff ORM
       writes + catalog parity    |   models against live pg_catalog)
                                  v
+---------------------------------+----------------------------------+
| TIER 1: TRUTH (PostgreSQL / MySQL / SQLite + Ephemeral Redis)      |
| Schema/ETL tools: Ariga Atlas, SQLGlot/SQLLineage, DataHub         |
| Wythe checks:     TRUTH-001..005 + wythe export-openlineage JSON   |
+--------------------------------------------------------------------+
```

A repository can pass 100% of its intra-language import checks while suffering severe **truth-boundary decay** that Wythe catches statically:
1. **Shadow policy in code or `compose.yaml` (`MANIP-001`, `DISP-001`)** — Legal imports or container `environment:` blocks hardcode mutable domain thresholds (`MAX_WEEKLY_HOURS = 80`, `QUOTA_LIMIT=500`) instead of reading persisted database policy rows.
2. **Orphaned or unmigrated database truth (`TRUTH-001`, `TRUTH-002`, `TRUTH-005`)** — Migrations seed a policy table that zero backend services read (`TRUTH-001`), ORM classes drift from SQL DDL (`TRUTH-002`), or live tables lack source migrations (`TRUTH-005`).
3. **Unguarded writes & volatile Redis shadow truth (`TRUTH-003`, `TRUTH-004`)** — HTTP routes mutate ORM entities directly without a service/SQL write door, or Redis `SET`/`HSET` calls omit a TTL.
4. **Split clock authority & broken HTTP contracts (`MANIP-002`, `DISP-002`, `DISP-004`)** — Naive host clocks or UTC `.toISOString().slice(0, 10)` shift calendar dates, or UI clients call renamed/deleted backend routes.
5. **Container source-to-image drift (`MANIP-004`, `MANIP-005`)** — A `Dockerfile` omits a transitive Python helper from `COPY`, excludes a copied path via `.dockerignore`, or passes unexpanded `$VAR` in JSON exec-form `CMD`/`ENTRYPOINT`.

---

## 3. Native `tach.toml` Bridge + OpenLineage Static Export

Wythe bridges horizontal domain modularity and enterprise data catalogs directly from one static scan:

```text
             HORIZONTAL DOMAIN WALLS (tach.toml / MANIP-006)
             +---------------------+---------------------+
  DISPLAY    | ui/billing/*        | ui/scheduling/*     | --+
             +---------------------+---------------------+   | 3-TIER
  MANIPULATE | app/billing/* X---> | app/scheduling/*    |   | TRUTH
  TIER       | (blocked MANIP-006) |                     |   | LINEAGE
             +---------------------+---------------------+   | (Wythe)
  TRUTH      | billing_ledgers     | rotation_policies   | --+
             +---------------------+---------------------+
```

- **Zero-binary `tach.toml` ingestion (`tach-boundaries` plugin -> `MANIP-006`)**: When `tach.toml` is present at the repository root or backend subdirectory, Wythe parses `source_roots`, `layers`, `[[modules]]` (`depends_on`, `utility = true`, `strict`/`visibility`), and `[[interfaces]]` (`expose`, `from`) using Python 3.12 `tomllib`. It labels Tier-2 nodes with their `tach` domain in the 3D/2D atlas and flags forbidden cross-domain Python imports as **`MANIP-006`** (`horizontal_module_boundary`, blocking). Run `tach check` alongside `wythe gate --strict` when you also want `tach sync` workflow management.
- **OpenLineage static lineage export (`wythe export-openlineage`)**: Wythe serializes Tier-1 SQL tables and Redis stores as OpenLineage `datasets` (with column schema and source-location facets) and Tier-2 routes, services, background workers, and E2E chains as static `jobs` (`inputs` = read tables, `outputs` = written tables, plus static code-location facets), bridging transactional application code into **DataHub**, **Marquez**, and warehouse lineage graphs without running the target app:

```bash
# Enforce horizontal + vertical gates and emit OpenLineage static JSON
tach check && wythe gate --strict .
wythe export-openlineage . --profile auto --out openlineage.json
```
