# Security Policy

## 1. Maintenance & Vulnerability Posture

Wythe is published **as is** under the [MIT License](LICENSE) for its author's
own use; it is not a supported product (see [SUPPORT.md](SUPPORT.md)).

- **No warranty, SLA, or patch timeline:** There is no maintenance commitment,
  no security SLA, and no promised fix, patch, release, compatibility, or
  response timeline.
- **Pin and fork:** Downstream users who depend on Wythe should pin an exact
  version (`wythe==0.2.0`, or `Euda1mon1a/wythe@v0.2.0` in GitHub Actions) and
  fork the repository whenever immediate fixes or changes are needed.
- **Vulnerability reporting:** Per [SUPPORT.md](SUPPORT.md), there is no formal
  security response process. If GitHub Private Vulnerability Reporting or
  Security Advisories are enabled on the repository, reports are reviewed
  strictly best-effort with zero obligation to respond, triage, patch, or
  publish an advisory. Public issues and pull requests carry the same
  zero-obligation posture.

## 2. Defensive / Blue-Team Component (`wythe security`)

Wythe's experimental `wythe security` commands provide bounded evidence
collection and self-contained regression examples—never an automated security
audit or certification. See
[docs/architecture/record-ownership.md](docs/architecture/record-ownership.md)
for the complete specification and exit codes.

### Static ownership evidence (`wythe security ownership`)

- **Opt-in, source-only static AST collector:** Inspects one caller-specified
  Python handler for one hypothesis:
  `One user cannot modify another user's record.`
- **Always inconclusive by contract:** Every report emits
  `invariant_result: "unknown"`, `target_code_executed: false`, and
  `target_database_contacted: false`. It does not trace imports, helpers,
  middleware, authentication, aliases, dynamic writes, or database row-level
  policies.
- **Bounded filesystem reads:** Reads a single regular `.py` file of at most
  1 MiB (`1,048,576` bytes) under the chosen repository root using
  descriptor-relative opens (`O_DIRECTORY`, `O_NOFOLLOW`, `O_NONBLOCK`),
  rejecting symlinks, path traversal, and non-regular files and failing closed
  when required OS primitives are unavailable. It never imports target code,
  initializes Wythe's database, spawns subprocesses, or contacts endpoints or
  databases.
- **Non-certification semantics:** Exit code `0` means static evidence was
  collected (exit `2` signals an invalid selector, refused read, parse error,
  or an existing `--json` path, which is never overwritten). Exit `0` is never
  a passing security audit, taint proof, or exploitability verdict, and
  `wythe gate` `PASS` (or `RATCHET_PASS`) checks 3-tier lineage and WCAG
  accessibility (`DISP-005`) only—never certifying authentication,
  authorization, or input validation.

### Synthetic ownership regression suite (`wythe security ownership-demo`)

- **Intentional vulnerable/repaired fixture pair:**
  `wythe security ownership-demo` and `backend/wythe_examples/ownership_lab.py`
  ship a synthetic vulnerable cross-owner FastAPI router
  (`ownership_vulnerable.py`) paired with its repaired twin
  (`ownership_repaired.py`) for in-process ASGI (`TestClient`) + fresh per-case
  `:memory:` SQLite regression verification (`network_requests_sent: false`,
  `target_code_executed: false`).
- **Isolated and non-routable:** The demo takes no target path, URL, or
  credentials. Its default `get_session` dependency raises `RuntimeError`
  outside the in-memory harness, its fixed Bearer tokens (`demo-user-1`,
  `demo-user-2`) are public test fixtures rather than authentication guidance,
  and `wythe_examples` is never mounted by `wythe serve` (`backend/app/main.py`
  mounts only `/api/v1`, `/healthz`, and `ui_dist`).
- **SAST scanner guidance:** `wythe_examples` is packaged separately from `app`
  so SAST scanners and Wythe's self-dogfooding gate do not flag the
  intentionally vulnerable fixture as a flaw in Wythe's production server.

## 3. Safe Deployment & Data-Handling Boundaries

### Unauthenticated local workstation server (`wythe serve`)

- **Loopback default:** `wythe serve` runs an unauthenticated HTTP API and
  WebGL UI defaulting to `127.0.0.1` port `8780` (`WYTHE_HOST` / `WYTHE_PORT`)
  with loopback CORS defaults (`http://127.0.0.1:3780,http://localhost:3780`).
- **Local path & source access by design:** Endpoints including
  `/api/v1/targets`, `/api/v1/scans`, and `/api/v1/scans/{slug}/source`
  register local repository paths, execute scans, and read bounded local
  source excerpts (blocking `.git`, `secrets`/`.secrets`, `node_modules`,
  `.env*`, and key/DB extensions).
- **Bind boundary:** Bind `wythe serve` only to `127.0.0.1` or an
  ACL-restricted single-owner Tailnet. Never bind `0.0.0.0` on untrusted LANs or
  expose the server to the public internet.

### Read-only live probes (`--dsn`, `--redis-dsn`, `--probe-url`)

- **Read-only catalog credentials:** When passing `--dsn` to `wythe scan`,
  `wythe gate`, or `wythe diff` (distinct from `WYTHE_DATABASE_URL`, which
  holds Wythe's own metadata database), use strictly least-privilege, read-only
  catalog credentials. Wythe reads table metadata only via `pg_catalog` in a
  `READ ONLY` PostgreSQL session, `information_schema` in `READ ONLY` mode on
  MySQL/MariaDB, or read-only SQLite (`?mode=ro`), with zero row or PII reads.
- **Metadata-only Redis & GET probes:** `--redis-dsn` executes metadata-only
  `INFO keyspace` and `SCAN` key-prefix checks without reading values.
  `--probe-url` is opt-in, sends unauthenticated `GET` requests only (dropping
  cookies), and blocks non-loopback/non-private hosts unless
  `--probe-allow-remote` is supplied.

### Output and LLM confidentiality

- **Confidential source artifacts:** JSON receipts, `/api/v1/scans/{slug}/source`
  responses, `wythe context`, `wythe llms`, `wythe mcp`, and `What's This?`
  viewport briefs/snapshots contain local repository paths, `file:line`
  pointers, schema/route inventories, findings, and AST or verbatim source
  excerpts.
- **Share and LLM boundary:** Treat these outputs as confidential source
  artifacts and review or redact them before external sharing or submission to
  hosted/cloud LLMs (`Ask AI` defaults to local on-device Apple Intelligence,
  Chrome Prompt API, or loopback/private `/v1` model endpoints).
