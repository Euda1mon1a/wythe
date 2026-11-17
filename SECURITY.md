# Security Policy

## 1. Maintenance & Vulnerability Posture

Wythe is published **as is** under the [MIT License](LICENSE) for its author's
own use; it is not a supported product (see [SUPPORT.md](SUPPORT.md)).

- **No warranty, SLA, or patch timeline:** There is no maintenance commitment,
  no security SLA, and no promised fix, patch, release, compatibility, or
  response timeline.
- **Pin and fork:** Downstream users who depend on Wythe should pin an exact
  version (`wythe==0.2.4`, or `Euda1mon1a/wythe@v0.2.4` in GitHub Actions) and
  fork the repository whenever immediate fixes or changes are needed.
- **Vulnerability reporting:** Per [SUPPORT.md](SUPPORT.md), there is no formal
  security response process. If GitHub Private Vulnerability Reporting or
  Security Advisories are enabled on the repository, reports are reviewed
  strictly best-effort with zero obligation to respond, triage, patch, or
  publish an advisory. Public issues and pull requests carry the same
  zero-obligation posture.

## 2. Defensive / Blue-Team Component (`wythe security`)

Wythe's experimental `wythe security` commands provide bounded evidence
collection, read-only companion artifact correlation, and self-contained
regression examples—never an automated security audit or certification. See
[docs/architecture/record-ownership.md](docs/architecture/record-ownership.md)
and
[docs/architecture/containers-security-and-plugins.md](docs/architecture/containers-security-and-plugins.md)
for complete specifications and exit codes.

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

### Companion artifact correlation (`wythe security companion`)

- **Read-only post-build artifact join:** `wythe security companion` (and
  `wythe scan --trivy-report ... --syft-sbom ... --companion-out ...`) joins
  Wythe's static blueprint findings with optional caller-supplied Trivy
  JSON/SARIF reports and Syft CycloneDX/SPDX/JSON SBOMs, redacting Trivy secret
  `Match` values.
- **Non-certification and zero external execution:** Every companion summary
  records `target_code_executed: false` and `automated_security_audit: false`.
  Wythe never invokes `docker`, `trivy`, or `syft`, never queries vulnerability
  feeds, and never certifies CVE reachability, exploitability, or production
  security posture.

## 3. Safe Deployment & Data-Handling Boundaries

### Untrusted-repository plugin boundary (`wythe.plugins`)

- **No automatic target-repository code execution:** Scanning an unfamiliar or
  untrusted repository never imports or executes `.py` files from the target
  checkout by default (`allow_local_plugins: false`).
- **Trusted discovery lanes only:** Default discovery loads only built-in
  first-party plugins (`tach-boundaries`, `container-sources`) and packages
  installed into Wythe's own Python environment via
  `importlib.metadata.entry_points(group="wythe.plugins")`.
- **CLI-only explicit opt-in:** Loading an arbitrary local module requires
  passing `--allow-local-plugins` alongside `--plugin MODULE` on the CLI; it is
  never enabled over HTTP (`/api/v1/adapters/plugins`) or MCP
  (`wythe_plugins`).
- **Zoom-1 invariance & fault-isolated `StratumPlugin` expansion:**
  `Zoom 1` remains the invariant default across `wythe scan`,
  `wythe gate`, HTTP, MCP, and initial WebGL load. Optional
  `StratumPlugin` (`stratum_inspector`) extensions are read-only,
  execute zero target-repo code, never alter `content_digest` or
  flatten `Zoom 2`/`Zoom 3` micro-nodes into `TruthAtlasReport.nodes`,
  and roll back in-place report mutations if a plugin raises.
- **Optional companion plugins (`agent-harness`, `cpsat`,
  `solver-chronicle`):** Core `wythe` ships zero domain-specific
  rules or solver dependencies (`MCP_TOOLS` = 10, `MCP_SLM_TOOLS` = 4
  `< 2,000` bytes, seeded `RulePolicy` = 19). When optional
  `wythe.plugins` packages are installed or opted in via CLI:
  - **Passive non-execution & containment:** `wythe-plugin-agent-harness`
    (`AGENT-001..003`), `wythe-plugin-cpsat` (`Zoom 2` lattice and
    `wythe companion --cp-model-proto` / `--cp-solver-response`), and
    `wythe-plugin-solver-chronicle` (`wythe watch-solver` and MCP
    `wythe_solver_chronicle`) read only repository-contained,
    non-symlink regular files (`<= 8..16 MiB`) and pure-Python AST or
    wire-format artifacts without importing target code, invoking
    `ortools` or external solvers, or calling LLM endpoints.
  - **Non-certification & NP-hard epistemic boundary:** Companion
    findings and 6-phase solver chronicles (`MODEL_INVALID`,
    `INFEASIBLE`, scaling/presolve/stall forensics) are structural
    leads only. They never certify prompt-injection safety, agent loop
    termination, mathematical feasibility, global optimality of
    NP-hard optimization models, or runtime solver correctness.
  - **Systems, compiler IR, solver-internals & static binary plugins
    (`apple-ipc`, `compiler-ir`, `solver-internals`, `binary`):**
    - **Zero target-binary, `ldd`, or build-system execution:**
      `wythe-plugin-binary` (`--binary`, `Zoom 3`, `BIN-ENT-001`),
      `wythe-plugin-compiler-ir` (`--index-store`, `--sil`,
      `--llvm-ir`, `--metallib`, `Zoom 2`, `METAL-001..003`),
      `wythe-plugin-solver-internals` (`--proto-descriptor`,
      `--compile-commands`, `SAT-INT-001..004`), and
      `wythe-plugin-apple-ipc` (`swift-systems-ipc`, `IPC-001`) are
      100% passive pure-Python readers. They never execute target
      binaries, never invoke `ldd` (which may run dynamic linkers on
      untrusted ELFs), and never run CMake, Bazel, `swiftc`, `xcrun`,
      or `protoc`, rejecting symlinks on every path component and
      XML `<!DOCTYPE`/`<!ENTITY` XXE payloads.
    - **Epistemic & non-certification invariants:** Compiled
      `.metallib` inspection covers LLVM-based `AIR` bitcode and
      reflection only—never OS driver-lowered `AGX` GPU hardware ISA,
      occupancy, or register allocation. Strings extracted from
      `__cstring` / `.rodata` remain `binary_string_witness` with
      `verification="unverified"` and are never promoted to `verified`
      call edges. `ConstraintProto` stage-coverage matrices report
      structural C++ phase asymmetries and never claim formal
      propagator mathematical soundness. All companion receipts keep
      `target_code_executed: false` and
      `automated_security_audit: false`.

  - **`wythe-plugin-wiretap` (`--otel-traces`, `--ebpf-flows`,
    `--memgraph`, `--vmmap`, `--port-listeners`, opt-in
    `--probe-local-ports`):** Passively correlates captured spans,
    socket flows, heap summaries, and port listeners without
    attaching debuggers or executing target code. SQL bind literals,
    URL query values, auth/cookie headers, raw heap buffers, and OS
    usernames are redacted by default. Zero spans in a capture window
    are reported as `unexercised_in_sample` (`static_dark_matter`),
    never dead-code proof. `--probe-local-ports` is strictly opt-in
    and takes a read-only local listener snapshot (`PORT-001`
    squatter conflict, `PORT-002` wildcard vs loopback bind drift).
  - **Six-Link Understanding Contract (`/api/v1/understanding`,
    `wythe understand`):** Read-only evaluation across intent,
    effective policy/context, execution, committed result,
    human-visible delivery, and preservation contracts. Bundle reads
    reject symlinks, `..` traversal, `.git`/`secrets`/`.env*`, and
    files `> 8 MiB` (`depth <= 64`). Indeterminate
    `committed_unacknowledged` states explicitly prohibit blind write
    retries before settlement; `target_code_executed: false` and
    `automated_security_audit: false` always hold.

### Hardware-isolated read-only scanning of untrusted repositories

- **Defense-in-depth host isolation:** Although Wythe is a static analyzer that
  keeps `allow_local_plugins: false` by default and never executes target
  repository code, operators auditing unfamiliar or untrusted third-party
  checkouts can enclose the scanner itself inside an ephemeral micro-VM or
  rootless read-only container with host networking disabled and the target
  repository mounted strictly read-only.
- **Building the local scanner image (`Containerfile`):** Build `wythe:local`
  once from the repository root (`container build -t wythe:local -f Containerfile .`,
  `podman build -t wythe:local -f Containerfile .`, or
  `docker build -t wythe:local -f Containerfile .`).
- **macOS (`apple/container` lightweight micro-VMs):** Run Wythe inside a
  dedicated per-invocation Linux micro-VM backed by Apple
  `Virtualization.framework` with `--network none` (`NetworkClient.noNetworkName`
  detaching VM network interfaces), mounting the target checkout read-only
  (`readonly`) and keeping `--allow-local-plugins` omitted:
  ```bash
  container run --rm --network none \
    -e WYTHE_STATE_DIR=/tmp/wythe-state \
    --mount type=bind,source=/path/to/untrusted-repo,target=/workspace/target,readonly \
    wythe:local \
    wythe scan /workspace/target --profile auto
  ```
- **Linux / OCI rootless equivalents (`podman` / `docker`):** On shared-kernel
  container runtimes, combine `--read-only`, `--network=none`, dropped
  capabilities, `no-new-privileges`, a bounded `/tmp` tmpfs for Wythe's scratch
  SQLite state (`WYTHE_STATE_DIR`), and a `:ro` bind
  mount:
  ```bash
  podman run --rm --read-only --network=none \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    -e WYTHE_STATE_DIR=/tmp/wythe-state \
    -v /path/to/untrusted-repo:/workspace/target:ro \
    wythe:local \
    wythe scan /workspace/target --profile auto

  docker run --rm --read-only --network=none \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    -e WYTHE_STATE_DIR=/tmp/wythe-state \
    -v /path/to/untrusted-repo:/workspace/target:ro \
    wythe:local \
    wythe scan /workspace/target --profile auto
  ```
- **Non-certification invariant:** Enclosing Wythe inside an `apple/container`
  micro-VM or `--read-only --network=none` rootless container hardens *scanner
  host isolation* only. Scan and `wythe gate` results remain static 3-tier
  lineage and WCAG (`DISP-005`) evidence (`target_code_executed: false`,
  `automated_security_audit: false`) and never certify that the inspected
  repository is safe to build, execute, or deploy on the host.

### Unauthenticated local workstation server (`wythe serve`)

- **Loopback default:** `wythe serve` runs an unauthenticated HTTP API and
  WebGL UI defaulting to `127.0.0.1` port `8780` (`WYTHE_HOST` / `WYTHE_PORT`)
  with loopback CORS defaults (`http://127.0.0.1:3780,http://localhost:3780`).
- **Local path & source access by design:** Endpoints including
  `/api/v1/targets`, `/api/v1/scans`, `/api/v1/scans/{slug}/source`,
  `/api/v1/scans/{slug}/openlineage`, and `/api/v1/adapters/plugins` register
  local repository paths, execute scans, export static lineage metadata, and
  read bounded local source excerpts (blocking `.git`, `secrets`/`.secrets`,
  `node_modules`, `.env*`, and key/DB extensions).
- **Bind boundary:** Bind `wythe serve` only to `127.0.0.1` or an
  ACL-restricted single-owner Tailnet. Never bind `0.0.0.0` on untrusted LANs or
  expose the server to the public internet.
- **Loopback SSE viewport choreography & plain-text sanitization:**
  `/api/v1/viewport/command`, `/api/v1/viewport/state`, and
  `/api/v1/viewport/events` (`wythe_focus_camera`, `wythe_camera_tour`)
  use a bounded 64-event in-memory ring buffer scoped by `target_slug`
  and optional `session_id` without mutating repositories or scan
  digests. Raw numeric camera coordinates, `<script>`/`<iframe>` tags,
  inline `on*=` handlers, and `javascript:`/`data:text/html` URIs are
  rejected, HTML angle-bracket markup is stripped to plain text, and
  any human pointer, wheel, touch, or keyboard input immediately flips
  the HUD from `Following` to `Paused` (`prefers-reduced-motion` cuts
  instantly without animated camera sweeps).

- **Shared investigation sessions & bidirectional receipts:**
  `/api/v1/investigations`, `/api/v1/ui-focus`,
  `/api/v1/viewport/command`, and `/api/v1/viewport/receipts` store
  bounded session state (`max_sessions=64`, `max_turns=100`,
  `max_events=200`) and per-session snapshots in `WYTHE_STATE_DIR`
  (`viewport_bus.sqlite3`, WAL mode). Independent browser tabs keep
  isolated `session_id`s unless explicitly joined via `#session=<id>`,
  multi-session ambiguity is surfaced instead of cross-tab guessing,
  commands report `applied_by_browser` only upon an explicit browser
  receipt (never subscriber count), and conversation corrections stay
  `promoted_to_ruling: false` so chat notes never silently disable
  governance rules.

### Read-only live probes (`--dsn`, `--redis-dsn`, `--probe-url`)

- **Read-only catalog credentials:** When passing `--dsn` to `wythe scan`,
  `wythe gate`, `wythe diff`, or `wythe export-openlineage` (distinct from
  `WYTHE_DATABASE_URL`, which holds Wythe's own metadata database), use strictly
  least-privilege, read-only catalog credentials. Wythe reads table metadata
  only via `pg_catalog` in a `READ ONLY` PostgreSQL session,
  `information_schema` in `READ ONLY` mode on MySQL/MariaDB, or read-only SQLite
  (`?mode=ro`), with zero row or PII reads.
- **Metadata-only Redis & GET probes:** `--redis-dsn` executes metadata-only
  `INFO keyspace` and `SCAN` key-prefix checks without reading values.
  `--probe-url` is opt-in, sends unauthenticated `GET` requests only (dropping
  cookies), and blocks non-loopback/non-private hosts unless
  `--probe-allow-remote` is supplied.

### Output and LLM confidentiality

- **Confidential source artifacts:** JSON receipts, `/api/v1/scans/{slug}/source`
  and `/api/v1/scans/{slug}/openlineage` responses, `wythe export-openlineage`,
  `wythe security companion`, `wythe context`, `wythe llms`, `wythe mcp`
  (`wythe_plugins`, `wythe_openlineage`), and `What's This?` viewport
  briefs/snapshots contain local repository paths, `file:line` pointers,
  schema/route inventories, findings, and AST or verbatim source excerpts.
- **Share and LLM boundary:** Treat these outputs as confidential source
  artifacts and review or redact them before external sharing or submission to
  hosted/cloud LLMs (`Ask AI` defaults to local on-device Apple Intelligence,
  Chrome Prompt API, or loopback/private `/v1` model endpoints).
