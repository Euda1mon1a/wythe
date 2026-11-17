# wythe-plugin-compiler-ir

Optional **Zoom-2 Compiler IR & Metal `AIR` Compute Seam** plugin (`wythe.plugins`) for Wythe.

## Capabilities

1. **Zoom-2 Compiler IR & USR Resolution (`usr_index.py`, `ir_parsers.py`)**
   - Ingests read-only `IndexStoreDB` / `clangd` JSON, JSONL, TSV, and YAML symbol/occurrence dumps (`--index-store`), Swift Intermediate Language `.sil` modules (`--sil`), and LLVM IR `.ll` text modules (`--llvm-ir`) across Swift, C/C++, Objective-C, and Rust/Python native extensions.
   - Emits Zoom-2 `StratumMicroNode` and `StratumMicroEdge` subgraphs with Unified Symbol Resolution (`USR`) cross-references (including Swift protocol-witness thunks, vtable thunks, and ARC runtime helpers so Wythe's default `--zoom 2` compacts boilerplate and `--unfiltered-ir` preserves full compiler fidelity).
   - Upgrades matching Zoom-1 `AtlasEdge.symbol_links` with compiler-resolved `caller->callee` and USR links while keeping Zoom-1 `content_digest` invariant.

2. **CPU <-> Metal GPU Compute Seam Verifier (`metal_air.py`)**
   - Extracts host Metal compute dispatches across Swift, Objective-C++, C++, and Python (`makeFunction(name:)`, `newFunction`, `get_kernel`, `MTLComputePipelineState`, `setComputePipelineState`, `setBuffer` / `setBytes` index bindings, `dispatchThreads` / `dispatchThreadgroups`).
   - Parses `.metal` shader sources (`[[kernel]]` / `kernel void`, `[[host_name(...)]]`, `[[buffer(N)]]` bindings, and shared C++/MSL `struct` layouts) plus `--metallib` `AIR` disassembly/reflection outputs (`xcrun metal-objdump` text and raw `MTLB` binary headers).
   - Contributes blocking seam rules:
     - `METAL-001`: Static host compute kernel name absent from target `.metal` sources and `.metallib` `AIR` exports.
     - `METAL-002`: Host `setBuffer` / `setBytes` indices omit a declared kernel `[[buffer(N)]]` binding or collide on duplicate indices.
     - `METAL-003`: Statically shared host vs `.metal` `struct` layout mismatch on size, stride, alignment, or field offsets (e.g., 16-byte MSL `float3` / `simd_float3` alignment padding vs 12-byte C++ `float[3]`).
   - Classifies runtime-concatenated or JIT-specialized kernel names (such as `ml-explore/mlx` dynamic specialization) as `unverified` (`unresolved`) rather than `METAL-001`.

## Epistemic & Execution Boundary

- **Passive & Zero-Build**: Never invokes `swiftc`, `clang`, `xcrun`, or repository build scripts.
- **`AIR` vs `AGX` Hardware ISA**: Compiled `.metallib` archives contain LLVM-based **Apple Intermediate Representation (`AIR`)** bitcode and reflection metadata; final per-GPU machine ISA (`AGX` instructions, register allocation, occupancy) is lowered at runtime by the OS Metal driver and remains outside static verification claims.
