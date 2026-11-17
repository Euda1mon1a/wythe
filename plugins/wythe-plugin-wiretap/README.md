# `wythe-plugin-wiretap`

Optional read-only **Zoom-3 runtime wiretap, live-heap, and host port occupancy companion plugin** for [Wythe](https://github.com/Euda1mon1a/wythe).

## Capabilities

1. **OTLP Traces & eBPF L7 Flows (`otel_ebpf.py`)**
   - Passively correlates exported OpenTelemetry OTLP JSON spans (`--otel-traces`) and eBPF HTTP/SQL/gRPC JSONL flow captures (`--ebpf-flows`) against static `AtlasNode` and `AtlasEdge` topology.
   - Partitions runtime correlation into:
     - **`corroborated_edges`**: Statically extracted edges observed in the capture sample with witness counts.
     - **`static_dark_matter`**: Statically extracted nodes/edges with zero hits in the sample (`epistemic_status="unexercised_in_sample"`, `dead_code_proof=False` — *never proof of dead or unreachable code*).
     - **`runtime_only` (`dynamic_blind_spots`)**: Observed runtime transitions absent from static extraction, kept strictly in the companion/Zoom-3 overlay without mutating Zoom-1 `declared`/`verified` states or `content_digest`.
   - Redacts SQL bind values, URL query parameters, auth/cookie headers, and raw payload buffers by default.

2. **macOS `.memgraph` & `vmmap` Heap Correlator (`heap_memgraph.py`)**
   - Passively reads recorded `leaks --outputGraph` / `.memgraph` JSON or text summaries and `vmmap` region tables (`MALLOC_*`, `IOAccelerator`/Metal, `__DATA_DIRTY`).
   - Runs iterative Tarjan strongly connected components (SCC) cycle detection to attribute live instance counts, retain cycles, and dirty/wired bytes to declaring modules at `Zoom 3`.

3. **Host Port & Listener Occupancy (`port_occupancy.py`)**
   - Extracts `Z=0` static port and bind declarations (`compose.yaml`, `Dockerfile`, Kubernetes manifests, `container`/`docker run -p`, `launchd` `.plist`, and Python `uvicorn`/`HTTPServer`).
   - Correlates declarations against recorded `lsof -nP -iTCP -sTCP:LISTEN` / `ss -tulnp` / JSON captures (`port_listeners_path`) or an explicit opt-in local snapshot (`probe_local_ports=True`).
   - Classifies `corroborated`, `squatter_conflict` (`PORT-001`), `bind_exposure_drift` `0.0.0.0` vs `127.0.0.1` (`PORT-002`), `dark_listener`, and `unlistening_declared` with structured runtime provenance.

## Security & Epistemic Guardrails

- Rejects symlinked path components before `.resolve()`, enforces a `<= 32 MiB` file size ceiling and `depth <= 64` structured nesting limit, and never executes target repository code (`target_code_executed: false`, `automated_security_audit: false`).
