# Containers, Security Workflows & Plugin Architecture (`v0.2.7`)

This document explains why Wythe inspects container and Kubernetes **source blueprints** (`Dockerfile`/`.docker/`, `.dockerignore`, `compose.yaml`/`docker-compose.*.yml`, and Kubernetes manifests) rather than sealed OCI image tarballs, how **Stage 1 (`tach` + Wythe)** hands off to **Stage 2 (`Syft` + `Trivy`)** in CI across Blue, Red, and Purple workflows, and how Wythe's extension system (`wythe.plugins`, `tach.toml` bridge, and OpenLineage export across CLI, HTTP, MCP, and WebGL UI) operates without executing untrusted repository code.

For a broader tool comparison across linters, schema engines, SAST, and catalogs, see [Ecosystem Reference & Positioning](ecosystem-and-positioning.md). For vulnerability reporting, server binding limits, and non-certification rules, read [SECURITY.md](../../SECURITY.md) and [record-ownership.md](record-ownership.md).

---

## 1. Containers & Images: Blueprint vs. Sealed Shipping Crate

### Why Sealed OCI Images Strip Architectural Truth (By Design)

A common operator question is: *"Can I point Wythe directly at `docker save app:latest` or an OCI registry digest instead of the git repository?"*

**No—and the reason an OCI image lacks 3-tier architectural evidence is an intentional security feature of modern container builds.**

In a hardened multi-stage build (`FROM node:22 AS ui-build`, `FROM python:3.12 AS builder`, `FROM gcr.io/distroless/python3-debian12`), `docker build` acts like packing a sealed shipping crate:
- **Plain-English view**: The repository is the **architectural blueprint** showing how UI screens, API doors, background workers, and SQL tables fit together. The built OCI image is a **sealed runtime crate** stripped down to the minimum bytes required to run one process safely.
- **Technical view**: Building a production image intentionally discards `.git` commit history (needed by `wythe diff`), compiles Tier-3 TypeScript/JSX components into minified static bundles, strips SQL migration history or Prisma/Drizzle schema DSLs run by separate release jobs, omits `tach.toml` and `.wythe/governance.json`, and isolates a single container rootfs away from sibling workloads in `compose.yaml` and Kubernetes manifests.
- **Security benefit**: Keeping `.git`, raw source trees, compilers, test fixtures, and shells out of the runtime image shrinks the container's attack surface, prevents source/history leakage on container compromise, and eliminates unnecessary OS package CVEs. Wythe never asks teams to ship source trees or `.git` inside production images.

```text
+----------------------------------+---------------------------------+
| SOURCE BLUEPRINT (Pre-Build)     | SEALED OCI IMAGE (Post-Build)   |
| Inspected statically by Wythe    | Scanned by Syft + Trivy         |
+----------------------------------+---------------------------------+
| [Present] Tier-3 TS/UI sources   | [Stripped] Minified static dist |
| [Present] Tier-2 AST + tach.toml | [Partial]  Runtime files only   |
| [Present] Tier-1 DDL/migrations  | [Stripped] Live DB is external  |
| [Present] .git history & ratchets| [Stripped] No .git metadata     |
| [Present] Dockerfile + ignore    | [Baked]    Flattened FS layers  |
| [Present] Compose & K8s manifests| [Absent]   Single-image scope   |
| [Absent]  Resolved OS/apt layers | [Present]  Exact OS/pkg digests |
+----------------------------------+---------------------------------+
```

### How Wythe Analyzes `Dockerfile`, `.dockerignore`, Compose, Kubernetes & Host CLI Launchers

Instead of unpacking built layer tarballs, Wythe's built-in `container-sources` plugin (`dockerfile_sources.py`, `container_launchers.py`, `compose_sources.py`, and `k8s_sources.py`) statically inspects container, orchestration, and host-unit blueprints across **any** active stack profile whenever container or service unit files exist—without invoking `container`, `docker`, `podman`, `kubectl`, `launchctl`, or `systemctl`, and without following symlinks outside the repository root:

1. **Multi-Stage `Dockerfile` & `.dockerignore` Lineage (`m:dockerfile:<rel>`)**
   - Discovers `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, and `Containerfile` (including inside `.docker/` hidden directories such as `.docker/backend.Dockerfile`), parsing multi-stage `FROM <image> [AS <stage>]`, `WORKDIR`, literal `ARG`/`ENV` bindings, `COPY`/`ADD` (`--chown`, `--chmod`, `--link`, `--from=<stage|index>`, JSON-array and whitespace forms), and `ENTRYPOINT`/`CMD`.
   - Evaluates `.dockerignore` rules in the build-context root (including `*`, `**`, directory prefixes, and `!` negations) to determine which repository files actually enter the build context.
   - Maps final-stage container commands (`uvicorn app.main:app`, `gunicorn`, `python -m pkg.mod`, `python path/to/script.py`, `celery -A ...`, `node ...`, `.sh` scripts) back to repository source files across `WORKDIR` and `COPY --from=builder` chains, emitting `declared` `calls_helper` edges on `AtlasNode(cluster="containers")` with the explicit epistemic note: *"Container build declaration; image build and runtime execution are not observed."*
2. **Three High-Signal Container Packaging & Launch Checks**
   - **Missing or `.dockerignore`-excluded `COPY` source (`MANIP-005`, warning)**: Flags `COPY`/`ADD` declarations whose literal repository source path is absent on disk or excluded by `.dockerignore`.
   - **Unpacked transitive runtime import (`MANIP-005`, warning)**: Starting from the repository module(s) invoked by final-stage `ENTRYPOINT`/`CMD`, Wythe walks `declared` and `verified` intra-repo `calls_helper` edges. If `backend/app/main.py` imports `shared/policy_loader.py` (directly or transitively), and final-stage `COPY` omits `shared/`—or `.dockerignore` filters it out—`docker build` exits `0` while the container fails at startup or first request with `ModuleNotFoundError`. Single-file Dockerfile linters (`Hadolint`) cannot see across the Python/TS import graph to catch this seam.
   - **Exec-form `$VAR` / `~` expansion bug (`MANIP-004`, warning)**: Hadolint rule `DL3025` recommends JSON exec-array syntax (`CMD ["uvicorn", "app.main:app"]`) so PID 1 receives `SIGTERM` cleanly. A common bug occurs when teams mechanically convert `CMD uvicorn app.main:app --port $PORT` into `CMD ["uvicorn", "app.main:app", "--port", "$PORT"]`: exec form bypasses `/bin/sh`, passing the literal string `"$PORT"` or unexpanded `"~/run.sh"` directly to `execve`. Wythe flags unexpanded `$VAR`/`~` tokens (and empty commands) in JSON exec arrays while passing explicit shell wrappers (`["sh", "-c", ...]`, including `tini --`, `dumb-init`, `env`, or split `ENTRYPOINT ["sh", "-c"]` + `CMD`) and copied `.sh` entrypoint scripts.
3. **Multi-Service `compose.yaml` Roots & Shadow Policy Env Vars (`m:compose:<rel>:<svc>`)**
   - Parses `compose.yaml`, `compose.yml`, `docker-compose.yaml`, `docker-compose.yml`, and environment-scoped `docker-compose.*.yml`/`yaml` + `compose.*.yml`/`yaml` variants (in root, 1-level subdirs, and `.docker/` such as `.docker/docker-compose.prod.yml`) via `yaml.safe_load`, extracting `services.<name>` (`build` string or `{context, dockerfile, target}`, `image`, `command`, `entrypoint`, `depends_on`, `environment`).
   - Connects multi-service roots (`web`, `api`, `worker`, `scheduler`) to both their `Dockerfile` node and resolved repository entrypoint scripts (such as `celery` or `BullMQ` workers, preventing false `MANIP-003` inert-module warnings on containerized workers), and records backing infrastructure services (`postgres`, `mysql`, `mariadb`, `redis`, `valkey`) plus external images in scan coverage notes.
   - Audits literal `environment:` assignments against active `PolicyVocabulary` tokens (`MANIP-001`, blocking), catching mutable domain thresholds (`DUTY_HOUR_LIMIT: 80`, `QUOTA_LIMIT=500`) hardcoded in orchestration YAML instead of persisted database policy tables.
4. **Kubernetes Workloads & `ConfigMap` Static Lineage (`m:k8s:<rel>:<kind>:<name>`)**
   - Parses multi-document Kubernetes manifests via `yaml.safe_load_all` (`Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `Pod`, `ConfigMap`, and `kind: List` items) across repo root, `k8s/`, `kubernetes/`, `manifests/`, `deploy/`, `deployments/`, and `.k8s/` (containment-checked, no external symlinks). Files containing Helm/Mustache `{{` templates are skipped safely without failing YAML parsing and recorded in scan coverage notes.
   - Connects workload `image`, `command`, and `args` declarations to matching repository `Dockerfile`s and entrypoint modules via `declared` `calls_helper` edges (`cluster="containers"`), clearing false `MANIP-003` inert-module warnings on Kubernetes `CronJob`s and queue consumers.
   - **`$(VAR_NAME)` vs. bare `$VAR` (`MANIP-004`)**: Kubernetes natively interpolates parenthesized `$(VAR_NAME)` references in container `command` and `args` arrays without a shell, whereas bare POSIX `$VAR`, `${VAR}`, or `~` tokens remain unexpanded literals unless wrapped in `sh -c` / `bash -c`. Wythe honors `$(VAR_NAME)` cleanly and flags bare `$VAR`/`${VAR}`/`~` under `MANIP-004`.
   - Audits literal `PolicyVocabulary` tokens in container `env:` `value:` literals and `ConfigMap.data` via **`MANIP-001`** (ignoring `valueFrom` `secretKeyRef`/`configMapKeyRef` references).
5. **Imperative Host CLI Launchers & Service Units (`m:systemd:<rel>`, `m:launchd:<rel>`, `m:script:<rel>`)**
   - Statically parses `container run` (`apple/container` `ContainerRun.swift` grammar), `docker run`, and `podman run` across `launchd` `.plist` `Program`/`ProgramArguments` (reusing existing `m:launchd:<rel>` nodes or emitting them on non-`python-services` profiles), `systemd` `.service` units (`ExecStart=`, `ExecStartPre=`, `Environment=`, `EnvironmentFile=`, `WorkingDirectory=`), and repository POSIX `.sh` wrappers—ignoring non-run subcommands (`build`, `pull`, `inspect`, `ps`, `login`).
   - Recovers `-e`/`--env` literals vs. bare pass-through keys, containment-checked in-repo `--env-file` and `EnvironmentFile=` targets (rejecting symlinks and `..` traversal outside `repo_root`), `--mount` (`type=bind,source=...,target=...,readonly`) and `-v`/`--volume` (`:ro` vs. writable) specs, `-w`/`--workdir`, `--entrypoint`, `--rm`, image tags, and trailing commands—linking host units both to matching `m:dockerfile:*` nodes and to repository Python/shell entrypoints (including direct non-container `systemd` `ExecStart=` scripts).
   - Audits hardcoded `-e KEY=VALUE`, `systemd` `Environment=KEY=VALUE`, and committed static env-file policy thresholds under **`MANIP-001`** (skipping `${VAR}` pass-throughs, bare keys, booleans, and `.example`/`.sample`/`.template` files), flags unexpanded `$VAR`/`~` tokens in non-shell `launchd` and `systemd` exec declarations under **`MANIP-004`**, and records external/digest-pinned images without an in-repo `Dockerfile` plus dynamic `$IMAGE_TAG` references as explicit `unresolved` scan coverage notes rather than broken edges.
6. **Surgical `AtlasEdge.symbol_links` Cones & WebGL `Containers` Lens**
   - Whenever concrete callable `module:symbol` entrypoints (`uvicorn app.main:create_app --factory` -> `*->create_app`, `dramatiq app.worker:process_queue` -> `*->process_queue`) are parsed across `Dockerfile`, Compose, Kubernetes manifests, or host CLI launchers (subject to Wythe's AST callable/router-hub guard so router-mounting `app = FastAPI()` modules preserve full downstream route cones), Wythe populates `AtlasEdge.symbol_links` so function-scoped Lineage Cones stay narrow rather than fanning out across unrelated functions in the file.
   - In the 3D/2D WebGL explorer, the **`Containers`** diagnostic lens isolates `cluster="containers"` (`m:dockerfile:*`, `m:compose:*`, `m:k8s:*`) alongside their connected backend entrypoints.

---

## 2. CI Two-Stage Handoff & Blue / Red / Purple Workflows

### Two-Stage Blueprint-to-Crate CI Pipeline

Pair **Stage 1** static source gates (`tach` + Wythe) before `docker build` with **Stage 2** artifact scanners (`Syft` + `Trivy`) on the built image, then optionally join their machine-readable outputs into a single companion handoff receipt:

```text
+--------------------------------------------------------------------+
| STAGE 1: SOURCE BLUEPRINT GATE (Pre-Build, Static Only)            |
| Repo Tree ---> tach check + wythe gate --strict .                  |
|   * Verifies UI <-> HTTP <-> Backend <-> SQL & tach (MANIP-006)    |
|   * Audits Dockerfile/.docker/, Compose & K8s manifests            |
+---------------------------------+----------------------------------+
                                  |
                                  |  docker build (seals runtime FS,
                                  |  strips .git, UI AST, dev tools)
                                  v
+---------------------------------+----------------------------------+
| STAGE 2: SEALED CRATE AUDIT (Post-Build Artifact)                  |
| OCI Image ---> Syft (CycloneDX/SPDX SBOM) + Trivy (CVE/IaC/SARIF)  |
|   * Inventories OS/pkg layers and known vulnerability advisories   |
+---------------------------------+----------------------------------+
                                  |
                                  |  wythe security companion .
                                  |    --syft-sbom sbom.cdx.json
                                  |    --trivy-report trivy.sarif
                                  v
+---------------------------------+----------------------------------+
| COMBINED HANDOFF RECEIPT (Blue / Red / Purple Triage, Non-Cert)    |
| Blueprint truth/boundary findings + Crate SBOM & CVE counts        |
+--------------------------------------------------------------------+
```

```bash
# Stage 1: Horizontal + 3-tier blueprint gate (before spending CI time on docker build)
tach check && wythe gate --strict .

# Build the sealed runtime image
docker build -t app:candidate .

# Stage 2: Extract CycloneDX SBOM (Syft) and CVE/misconfig SARIF (Trivy)
syft app:candidate -o cyclonedx-json=sbom.cdx.json
trivy image --format sarif --output trivy.sarif app:candidate

# Correlate Stage-1 architectural posture with Stage-2 SBOM/CVE artifacts (read-only)
wythe security companion . \
  --syft-sbom sbom.cdx.json \
  --trivy-report trivy.sarif \
  --json companion-handoff.json

# Or emit the companion handoff summary directly during a standard scan:
wythe scan . \
  --trivy-report trivy.sarif \
  --syft-sbom sbom.cdx.json \
  --companion-out companion-handoff.json
```

### Concrete Blue / Red / Purple Team Workflows

Wythe is **not** an exploit generator, active scanner, or automated security auditor. Instead, `summarize_companion_security_artifacts` (`companion_export_service.py`) produces a structured **Blue / Red / Purple Handoff Summary** so human engineers and authorized assessment teams share one deterministic source-to-artifact map:

| Posture | Primary Question | How Blueprint (Wythe) + Crate (`Syft` / `Trivy`) Pair |
| :--- | :--- | :--- |
| **Blue Team** *(Defensive Architecture & Hardening)* | *"Are mutations behind guarded write doors, is policy stored in DB truth, and does our container image match what the code imports?"* | Enforce `TRUTH-003` guarded service/SQL write doors; eliminate client-only (`DISP-001`) and Compose/K8s (`MANIP-001`) shadow policy; flag unread policy tables (`TRUTH-001`) that give operators false confidence; block `MANIP-004`/`MANIP-005` container packaging drift before deploy; track `Syft` CycloneDX/SPDX package inventories and `Trivy` CVE/misconfig counts per release. |
| **Red Team** *(Authorized Read-Only Scoping)* | *"Which HTTP/tRPC routes mutate persistent tables directly, where does UI code enforce shadow rules, and which services carry vulnerable dependencies?"* | Use 3-tier E2E chains and `TRUTH-003` findings to prioritize manual review of routes that mutate tables directly without a service guard; inspect `DISP-001` client policy shadows to verify whether server handlers enforce the same rule; collect bounded AST evidence via `wythe security ownership` (`invariant_result: "unknown"`); cross-reference `Trivy` CVEs/secrets against active Compose/Kubernetes service entrypoints. |
| **Purple Team** *(Collaborative Hypothesis -> Regression)* | *"How do we turn a suspected authorization or boundary gap into a permanent, deterministic CI regression?"* | Take a structural hypothesis from `wythe security ownership` or `TRUTH-003`, write an isolated two-identity + DB-state-readback ASGI test modeled on `wythe security ownership-demo` ([record-ownership.md](record-ownership.md)), lock horizontal domain walls in `tach.toml` (`MANIP-006`), and lower `.wythe/governance.json` ratchet ceilings so the repaired class cannot regress. |

### Strict Non-Certification & Epistemic Boundaries (`SECURITY.md`)

Every security-related surface in Wythe preserves strict epistemic honesty:
- **Never a security certification**: `wythe gate` `PASS` (or `RATCHET_PASS`), `wythe scan --companion-out`, and `wythe security companion` verify static 3-tier architectural lineage, WCAG markup (`DISP-005`), and caller-supplied artifact counts only. They **never** certify authentication, authorization, input validation, cryptographic soundness, or absence of vulnerabilities.
- **Inconclusive static ownership contract**: `wythe security ownership` reads at most one caller-selected regular `.py` file (`<= 1 MiB`) using descriptor-relative no-symlink opens and **always** emits `invariant_result: "unknown"`, `target_code_executed: false`, and `target_database_contacted: false`.
- **Read-only companion correlation**: `--trivy-report` (Trivy JSON or SARIF 2.1.0) and `--syft-sbom` (CycloneDX or SPDX JSON) are parsed **read-only** from local files generated by your pipeline. Wythe does not execute `docker`, `trivy`, or `syft`, fetch CVE feeds, or claim whether a package CVE is reachable or exploitable at runtime.
- **Confidential source artifacts**: Scan JSON, companion handoff receipts, `wythe context`, `wythe llms`, and OpenLineage exports contain repository paths, `file:line` pointers, and schema/route inventories—review or redact them before external sharing per [SECURITY.md](../../SECURITY.md).

### Hardware-Isolated Read-Only Micro-VM & Rootless Container Scanning

Although Wythe never imports or executes target-repository Python code by default (`allow_local_plugins: false`), teams auditing unfamiliar or untrusted third-party repositories can enclose the scanner itself inside an ephemeral hardware micro-VM (`apple/container` on macOS Apple Silicon) or a rootless `--read-only --network=none` OCI container (`podman` / `docker` on Linux):

```text
+----------------------------------+----------------------------------+
| ISOLATION LANE                   | BOUNDARY & MOUNT CONTRACT        |
+----------------------------------+----------------------------------+
| apple/container (macOS arm64)    | Dedicated Linux micro-VM kernel  |
|   container run --rm             | --mount type=bind,source=<repo>, |
|     --network none ...           |   target=/workspace/target,      |
|                                  |   readonly                       |
+----------------------------------+----------------------------------+
| Rootless podman / docker (Linux) | Userns + seccomp + cap-drop=ALL  |
|   podman run --rm --read-only    | -v <repo>:/workspace/target:ro   |
|     --network=none ...           | --tmpfs /tmp:rw,noexec,nosuid    |
+----------------------------------+----------------------------------+
```

```bash
# Build the minimal rootless scanner image from the repository Containerfile
docker build -t wythe:local -f Containerfile .   # or `podman build` / `container build`

# macOS Apple Silicon: dedicated Virtualization.framework micro-VM (apple/container)
container run --rm --network none \
  -e WYTHE_STATE_DIR=/tmp/wythe-state \
  --mount type=bind,source=/path/to/untrusted-repo,target=/workspace/target,readonly \
  wythe:local \
  wythe scan /workspace/target --profile auto

# Linux rootless Podman: read-only rootfs, no network, dropped capabilities, :ro target
podman run --rm --read-only --network=none \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -e WYTHE_STATE_DIR=/tmp/wythe-state \
  -v /path/to/untrusted-repo:/workspace/target:ro \
  wythe:local \
  wythe scan /workspace/target --profile auto

# Docker Engine equivalent (prefer rootless mode)
docker run --rm --read-only --network=none \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -e WYTHE_STATE_DIR=/tmp/wythe-state \
  -v /path/to/untrusted-repo:/workspace/target:ro \
  wythe:local \
  wythe scan /workspace/target --profile auto
```

Keep `--allow-local-plugins` omitted so Wythe loads only built-in and image-installed plugins. Per [SECURITY.md](../../SECURITY.md), micro-VM and container isolation protect the *scanning host* only—a clean `wythe scan` or `wythe gate` result (`target_code_executed: false`, `automated_security_audit: false`) never certifies that the untrusted repository is safe to build, execute, or deploy.

---

## 3. Plugin & Extension Architecture (`wythe.plugins`)

### Security Boundary: Never Auto-Executing Untrusted Repo Code

When an engineer or CI job runs `wythe scan /path/to/untrusted-checkout`, scanning must remain a **pure read-only inspection**. Automatically importing `.py` hooks, `.wythe/plugins/*.py`, or `conftest.py` from inside a scanned target repository would turn static analysis into arbitrary code execution.

`backend/app/adapters/plugin_registry.py` enforces three explicit discovery lanes:
1. **Built-in first-party plugins (`origin="builtin"`)**: `tach-boundaries` and `container-sources` ship inside Wythe, run deterministically across stack profiles, and act as zero-noise no-ops when `tach.toml`, `Dockerfile`, Compose, or Kubernetes manifests are absent.
2. **Installed Python package entry points (`origin="entry_point"`)**: Third-party or organization plugins installed into **Wythe's own Python environment** are discovered via `importlib.metadata.entry_points(group="wythe.plugins")` (mirroring `importlinter.contracts` in `import-linter`).
3. **Explicit local module paths (`origin="local_opt_in"`)**: Arbitrary Python module paths are refused unless the operator explicitly passes `--allow-local-plugins` alongside `--plugin MODULE` on the CLI (`allow_local_plugins=True`). HTTP (`GET /api/v1/adapters/plugins`, where `local_plugins_allowed` is permanently `false`) and MCP (`wythe_plugins`) never enable local repository plugin code.

### Plugin Protocols, Fault Isolation & CLI / HTTP / MCP Inspection

Plugins register a typed `WythePluginSpec` (`name`, `kind`, `origin`,
`version`, `description`, `enabled_by_default`, `rules`, `mcp_tools`,
`cli_subcommands`, `companion_handlers`) and may implement multiple
protocols simultaneously on one plugin object:
- **`ManipulatorAugmenterPlugin` (`run_manipulator_plugins`)**:
  Augments `ManipulatorExtractionResult` (`nodes`, `edges`,
  `findings`, `notes`) after core tier extraction, indexing existing
  nodes by repo-relative `node.source_file` across stack profiles.
- **`PostScanCheckPlugin` (`run_post_scan_plugins`)**: Inspects an
  isolated copy of `TruthAtlasReport` for cross-tier checks without
  mutating `Zoom 1` `content_digest`.
- **`StratumPlugin` (`attach_zoom1_stratum_badges` /
  `build_node_stratum_drilldown`)**: Attaches lightweight `Zoom 1`
  `stratum_badges` and expands lazy `Zoom 2`/`Zoom 3` micro-nodes on
  demand without inflating `TruthAtlasReport.nodes`, reading explicit
  read-only CLI artifact paths via `stratum_artifacts_scope`.
- **`stack_adapter` (`PluginStackProfileSpec` /
  `register_plugin_tier_adapters`)**: Registers optional 3-tier
  language/systems adapters and stack profiles (such as
  `swift-systems-ipc`) without altering core's seeded DB
  `StackProfile` catalog when uninstalled.
- **Dynamic rules, MCP tools, CLI subcommands & companions**:
  Plugins may declare `PluginRuleSpec` rows (honoring DB `RulePolicy`
  overrides without altering core's 19 seeded rules), `full`-slice
  `PluginMcpToolSpec` tools (never overriding core tools and never
  expanding the 4-tool `< 2,000 B` `slm` slice), `cli_subcommands`
  (`wythe watch-solver`), and `companion_handlers` (`wythe companion
  --cp-model-proto ... --cp-solver-response ...`).
- **Fault isolation**: Plugins execute in deterministic name order. If
  an installed plugin raises an exception, Wythe isolates the failure
  (rolling back partial list mutations) and appends a diagnostic scan
  note instead of crashing core `wythe scan` / `wythe gate` (unless
  strict plugin mode is requested).

### Optional First-Party Companion Packages (`plugins/wythe-plugin-*`)

Core `wythe` remains 100% domain-agnostic; domain-specific inspectors
ship as separate optional `wythe.plugins` packages:
- **`wythe-plugin-agent-harness`** (`AGENT-001..003`): Audits prompt
  KV-cache prefix stability (`AGENT-001`), SLM/MCP tool-schema byte
  budgets and Tier-1 registry parity (`AGENT-002`), and bounded
  agent-loop termination (`AGENT-003`).
- **`wythe-plugin-cpsat`**: Pure-Python OR-Tools CP-SAT AST extractor,
  `Zoom 2` bipartite `Variable <-> Constraint` lattice, and read-only
  `CpModelProto` / `CpSolverResponse` JSON, `.pbtxt`, and binary wire
  companion correlator (requiring zero `ortools` runtime).
- **`wythe-plugin-solver-chronicle`**: Synthesizes the 6-phase causal
  3-tier solver chronicle (`[1.Load]` -> `[6.Render]`), classifies
  `MODEL_INVALID`, `INFEASIBLE`, and scaling/presolve/stall forensics
  back to `Z=0` `file:line` builders and `[1.Load]` Truth tables, and
  serves passive `wythe watch-solver` + MCP `wythe_solver_chronicle`
  with `#chronicle=<id>&phase=<idx>` `Live Follow` permalinks.
- **`wythe-plugin-apple-ipc`** (`IPC-001`, `MANIP-006`): Registers
  `swift-systems-ipc` (`cli` -> `ipc_handler`/`ffi_shim`/`service` ->
  `entity_store`/`entitlement_spec`) across `Package.swift`,
  `ArgumentParser`, XPC, `vsock`/gRPC, C FFI, OCI stores, and
  `.entitlements`; uninstalled `Package.swift` repos report truthful
  `no-truth`/`no-manipulator`/`no-display` partial coverage.
- **`wythe-plugin-compiler-ir`** (`METAL-001..003`): Read-only
  `Zoom 2` `IndexStoreDB`/`clangd` USR, Swift `.sil`, and LLVM `.ll`
  resolver plus CPU <-> Metal `AIR` compute seam verifier (`--sil`,
  `--llvm-ir`, `--index-store`, `--metallib`), distinguishing
  `.metallib` `AIR` bitcode from driver-lowered `AGX` GPU ISA.
- **`wythe-plugin-solver-internals`** (`SAT-INT-001..004`): Read-only
  `Zoom 2` C++/Protobuf solver-engine inspector (`--proto-descriptor`,
  `--compile-commands`) tracing the 7-stage `ConstraintProto` matrix,
  `SatParameters` knob lineage, `Model::GetOrCreate<T>()` singleton
  cycles, and Python/SWIG/pybind11/nanobind wrapper parity (reporting
  structural stage asymmetries, never formal propagator soundness).
- **`wythe-plugin-binary`** (`BIN-ENT-001`): 100% passive `Zoom 3`
  Mach-O 64/Universal and Linux ELF64 inspector (`--binary`, zero
  `ldd`/target execution) extracting dynamic libraries, Swift/ObjC
  reflection, `unverified` `binary_string_witness` literals (never
  promoted to `verified` call edges), and non-certifying signed
  entitlement drift (`automated_security_audit: false`).
- **`wythe-plugin-wiretap`** (`PORT-001`, `PORT-002`): Passive `Zoom 3`
  OTLP/eBPF trace correlator (`corroborated`, `static_dark_matter`
  `unexercised_in_sample`, `runtime_only`), `.memgraph`/`vmmap` heap
  and Tarjan retain-cycle inspector, and host port occupancy verifier
  (`--otel-traces`, `--ebpf-flows`, `--memgraph`, `--vmmap`,
  `--port-listeners`, opt-in `--probe-local-ports`) with SQL/URL/auth/
  heap redaction. Every plugin descriptor also advertises explicit
  `interaction_capabilities` and `evidence_source_kinds`
  (`source_static`, `compiled_artifact`, `runtime_capture`) via
  `wythe plugins --json` and `GET /api/v1/adapters/plugins`.
- **Passive non-execution & non-certification**: None of the eight
  plugins imports target code, invokes `ldd`/CMake/Bazel/`swiftc`/
  `xcrun`, executes a target binary or solver, or certifies security,
  propagator soundness, or NP-hard global optimality.

Register an environment plugin in your companion package's `pyproject.toml`:

```toml
[project.entry-points."wythe.plugins"]
acme-boundaries = "acme_wythe_plugin:PLUGIN_SPEC"
```

Inspect active built-in and entry-point plugins across CLI, HTTP, MCP, or the Governance UI:

```bash
wythe plugins
wythe plugins --json
curl -s http://127.0.0.1:8780/api/v1/adapters/plugins
# MCP tool: wythe_plugins
```

---

## 4. Built-in `tach.toml` Bridge & OpenLineage Static Export

### Zero-Binary `tach.toml` Horizontal Walls (`tach-boundaries` -> `MANIP-006`)

The built-in `tach-boundaries` plugin (`backend/app/adapters/tach_bridge.py`) reads `tach.toml` (at `<repo_root>/tach.toml` or `<backend_subdir>/tach.toml`) via Python 3.12's standard-library `tomllib`—requiring zero external `tach` binary at scan time:
- **Supported `tach.toml` schema**: `source_roots`, ordered `layers`, `[[modules]]` (`path`, `depends_on` string or `{path = ...}` entries, `layer`, `utility = true`, `strict` / `visibility`), and `[[interfaces]]` (`expose`, `from`).
- **Dual edge + AST verification & `symbol_links`**: Annotates Tier-2 Python `AtlasNode` summaries with their owning `tach` module, populates `AtlasEdge.symbol_links` (`["*->sym"]`) when concrete `from X import sym` imports are parsed, verifies intra-repo `calls_helper` edges and Python AST imports under `source_roots` against `depends_on`, `<root>`, `utility = true`, and `[[interfaces]]` public symbol exposure, and emits **`MANIP-006`** (`horizontal_module_boundary`, `severity="blocking"`, `confidence="confirmed"`, `evidence_strength="structural_match"`) on forbidden cross-domain imports.

### OpenLineage Static Lineage Facet Exporter (`wythe export-openlineage`, HTTP, MCP & UI)

`wythe export-openlineage` (`build_openlineage_static_bundle` in `companion_export_service.py`), `GET /api/v1/scans/{target_slug}/openlineage`, MCP `wythe_openlineage`, and the Governance tab's **Export OpenLineage** button adapt the Linux Foundation **OpenLineage** design-time model so enterprise catalogs (**DataHub**, **Marquez**) can ingest application-tier lineage without waiting for live runtime `RunEvent` traffic:
- **`datasets`**: Emitted for Tier-1 SQL tables (`t:<table_name>`) and Redis ephemeral stores (`t:redis:*`), attaching schema column facets and static repository `sourceCodeLocation` facets.
- **`jobs`**: Emitted for Tier-2 routes, services, background workers, container/Compose/K8s entrypoints (respecting Compose `CMD` overrides and excluding `depends_on` startup edges from SQL write inheritance), and reconstructed E2E chains, binding `inputs` to read tables/stores (`reads_truth`), `outputs` to mutated tables/stores (`writes_truth`), and static code-location facets (`file:line` and commit provenance):

```bash
wythe export-openlineage /path/to/repo --profile auto --out openlineage.json
curl -s http://127.0.0.1:8780/api/v1/scans/wythe/openlineage -o openlineage.json
# MCP tool: wythe_openlineage (target="/path/to/repo")
```
