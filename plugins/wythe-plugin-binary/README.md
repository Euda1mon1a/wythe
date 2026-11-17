# `wythe-plugin-binary`

Optional **Zoom-3 static binary and capability inspection plugin** (`wythe.plugins` entry point `binary`) for compiled macOS Mach-O binaries, `.app` / `.xpc` bundles, Linux ELF64 container binaries, and recorded passive inspection fixtures.

## Capabilities

- **100% Passive Non-Execution (`SECURITY.md`):** Parses raw 64-bit / Universal Mach-O and ELF64 headers, sections, and code-signing blobs purely in Python without executing target binaries or invoking `ldd` or external subprocesses.
- **Dynamic Linkage & Symbol Graphs (`--zoom 3`):** Extracts `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_RPATH` (`@rpath`, `@executable_path`, `@loader_path`), and `LC_SYMTAB` on Mach-O, plus `DT_NEEDED`, `DT_RUNPATH`, `DT_RPATH`, and `.dynsym` / `.symtab` on Linux ELF64.
- **Swift, Objective-C & Native Demangling:** Recovers Mach-O `__TEXT,__swift5_types`, `__swift5_proto`, `__swift5_fieldmd`, `__DATA_CONST,__objc_classlist`, and `__objc_selrefs` metadata and demangles Swift (`_$s` / `$s`), Itanium C++ (`_ZN`), and Rust v0 (`_RNv`) symbols while folding ARC / stdlib helpers (`_swift_retain`, `_objc_release`) unless `--unfiltered-ir` is set.
- **Epistemic String Witnesses:** Tags HTTP route templates, XPC Mach service identifiers, SQL DDL/table snippets, and gRPC `/pkg.Service/Method` strings from `__TEXT,__cstring` and `.rodata` explicitly as `kind="binary_string_witness"` with `verification="unverified"`—never promoting uncorroborated literals to `verified` call edges.
- **Signed Entitlement & Capability Drift (`BIN-ENT-001`):** Compares embedded Mach-O `CSMAGIC_EMBEDDED_ENTITLEMENTS` (`0xfade7171`) XML plists and Linux ELF capability notes against source `.entitlements` declarations (such as `signing/container-runtime-linux.entitlements` and `signing/container-network-vmnet.entitlements` in `apple/container`), emitting non-certifying companion summaries (`target_code_executed: false`, `automated_security_audit: false`).
- **Recorded Passive Fixtures:** Supports deterministic cross-platform analysis from recorded `otool -L`, `dyld_info`, `nm`, `codesign -d --entitlements - --xml`, and `readelf -d -W` captures.
