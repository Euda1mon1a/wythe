# `wythe-plugin-solver-internals`

Optional C++/Protobuf solver-engine architecture microscope plugin (`zoom=2`) for [Wythe](https://github.com/Euda1mon1a/wythe), validated against upstream `google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5` (`ortools/sat/`) with **zero** `protobuf`, `ortools`, or compiler runtime dependencies.

## Why Separate from `wythe-plugin-cpsat`

- `wythe-plugin-cpsat` inspects application-level Python `CpModel` builders and serialized model/response companions.
- `wythe-plugin-solver-internals` inspects **native C++/Protobuf solver engines** themselves: `.proto` and binary `protoc` `FileDescriptorSet` schemas, 7-stage C++ pipeline dispatchers, `SatParameters` C++ consumer lineage, `Model::GetOrCreate<T>()` singleton service-locator graphs, and Python/SWIG/pybind11/nanobind wrapper parity.

## Capabilities & Rules

1. **Pure-Python `.proto` & Wire-Format `FileDescriptorSet` Parser (`proto_descriptor.py`):**
   - Reads `.proto` sources (`cp_model.proto`, `sat_parameters.proto`) and pre-compiled `google.protobuf.FileDescriptorSet` `.pb` / JSON artifacts (`--proto-descriptor`) without importing `google.protobuf`.
2. **`ConstraintProto` 7-Stage Pipeline Coverage Matrix (`stage_matrix.py` — `SAT-INT-001`):**
   - Traces every `ConstraintProto` `oneof constraint` case and `enforcement_literal` across `Expand` (`cp_model_expand.cc`), `Presolve` (`cp_model_presolve.cc`), `Symmetries` (`cp_model_symmetries.cc`), `Loader` (`cp_model_loader.cc`), `Cuts` (`cuts.h`), `LNS` (`cp_model_lns.cc`), and `PropagatorInterface` / `SatPropagator` (`integer.h`, `sat_solver.h`) plus optional `--index-store` C++ USRs.
   - Emits `SAT-INT-001` (`warning`) on asymmetric stage omissions (e.g., constraints or `enforcement_literal` modes loaded into search propagators in `Loader` while omitted from `Presolve`, `Symmetries`, `Cuts`, or `LNS`).
3. **`SatParameters` Knob Lineage vs. Hardcoded C++ Heuristic Constants (`param_lineage.py` — `SAT-INT-002` / `MANIP-001`):**
   - Traces `SatParameters` knobs (`cp_model_presolve`, `linearization_level`, `symmetry_level`, `num_workers`, `num_search_workers`, `max_time_in_seconds`, etc.) into C++ consumers (`parameters.foo()` / `params_.foo()`), attaches `PolicyFieldConsumption` (`consumed` vs. `bypassed`), and flags hardcoded C++ work-limit or clause/domain thresholds bypassing `SatParameters`.
4. **`Model::GetOrCreate<T>()` Service-Locator Singleton Graph (`singleton_graph.py` — `SAT-INT-003`):**
   - Extracts `Model::GetOrCreate<T>()`, `model->GetOrCreate<T>()`, and `model->Get<T>()` dependencies across `Trail`, `IntegerTrail`, `SatSolver`, `TimeLimit`, `ImpliedBounds`, and cut generators into Zoom-2 `StratumMicroNode` / `StratumMicroEdge` subgraphs, flagging cyclic constructor injection (`SAT-INT-003`).
5. **Host-Language Wrapper Parity (`wrapper_parity.py` — `SAT-INT-004`):**
   - Cross-checks `cp_model.py` and SWIG/pybind11/nanobind binding shims against `ConstraintProto` cases and `SatParameters` fields, flagging unexposed `.proto` constraint cases and deprecated parameter aliases (`SAT-INT-004`).

## Passive Non-Execution & Epistemic Boundary

- **100% Passive Read-Only Inspection:** Never invokes CMake, Bazel, `protoc`, `clang`, or target C++/Python code. All `.pb`, `.proto`, `--index-store`, and `--compile-commands` inputs are read as bounded, symlink-checked files (`<= 32 MiB`).
- **Epistemic Boundary:** Stage-coverage matrix findings (`SAT-INT-001`) report structural handling asymmetries across C++ solver pipeline phases and never claim formal verification or mathematical unsoundness of solver propagators.
