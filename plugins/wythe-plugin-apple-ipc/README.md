# `wythe-plugin-apple-ipc`

Optional pure-Python **Swift & Systems IPC** companion plugin for [Wythe](https://github.com/Euda1mon1a/wythe).

Activates the `swift-systems-ipc` architectural stack profile (`swift-stores-truth`, `swift-ipc-manipulator`, `swift-cli-display`) without requiring Xcode, `swiftc`, or native grammar wheels on Linux CI hosts.

## Capabilities

- **`Package.swift` Manifest & Dependency Boundary Enforcement (`MANIP-006`)**:
  - Parses `executableTarget`, `target`, `systemLibrary` / C targets, `testTarget` (excluding `Tests/*` from runtime graphs), custom `path:`, and `dependencies:`.
  - Emits `MANIP-006` when a non-test Swift target imports an in-repo sibling target omitted from its declared `Package.swift` `dependencies:`.
- **Native 3-Wythe Systems Lineage** (benchmarked against `apple/container@16e8d488ee1d9ede35ab9cf21b9973ffdc9361b3` and `apple/containerization@706cb512ccfc50fe27b575084c17a2964526be8e`):
  - **Surface (`display`, `subkind="cli"`)**: `ArgumentParser` `ParsableCommand` / `AsyncParsableCommand` hierarchies (`CommandConfiguration(commandName:, subcommands:)`) and CLI `run()` -> IPC client/route edges (`queries_endpoint` / `mutates_endpoint`).
  - **Logic (`manipulate`, `subkind="ipc_handler" | "ffi_shim" | "service"`)**: XPC route enums, clients, and server handlers, `vsock` / gRPC `.proto` and `.grpc.swift` services, and C FFI shims (`@_silgen_name` and C header/source targets).
  - **Truth (`truth`, `subkind="entity_store" | "entitlement_spec"`)**: Persistent OCI/entity/content/snapshot/image stores, `launchd` Mach service plist definitions, and `.entitlements` XML capability plists.
- **XPC Route Seam Verification (`IPC-001`)**:
  - Reconciles static in-repo XPC route keys sent by clients against server handler registrations, emitting `IPC-001` (`blocking`) and a `broken` edge when an in-repo route key lacks a server handler.
  - Classifies external OS Mach services (`com.apple.*` outside repository scope) and dynamic runtime XPC strings as `unverified` (`unresolved` note) without false `IPC-001` findings, and ignores unused XPC enum constants and `Tests/*` targets.
