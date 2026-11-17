# `wythe-plugin-cpsat`

Optional pure-Python `wythe.plugins` extension for repositories using OR-Tools CP-SAT
(`ortools.sat.python.cp_model.CpModel` / `CpSolver`), such as warehouse order-picking waves,
job-shop machine interval planning, and vehicle-routing capacity optimization.

## Design & Epistemic Boundary

- **Zero C++ / `ortools` / `protobuf` runtime dependencies**: Runs anywhere on Python 3.12+ using
  standard-library `ast` inspection and a pure-Python reader for `CpModelProto` (`Z=1`) and
  `CpSolverResponse` (`Z=2`) in JSON, `.pbtxt` text-format, and binary protobuf wire format
  (aligned with `google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5`
  `ortools/sat/cp_model.proto`).
- **Strictly non-executing & non-certifying (`SECURITY.md`)**: Target repository Python modules
  are never imported or executed. Static lineage and read-only companion correlation do **not**
  predict NP-hard combinatorial runtime, decide satisfiability, or certify global optimality
  (`automated_security_audit: false`).
- **Baseline `Zoom 1` digest invariance**: Compact `Zoom 1` summary badges (`cp_vars`,
  `cp_constraints`, `cp_objective_terms`, `cp_assumptions`) attach via `StratumPlugin` without
  inflating baseline node counts or mutating static `Z=0` `content_digest` values.

## Capabilities

1. **Variable <-> Constraint Bipartite Coupling Lattice (`Zoom 1` Badges + `Zoom 2` `StratumPlugin`)**:
   - Inspects `NewBoolVar`, `NewIntVar`, `NewIntervalVar`, `NewOptionalIntervalVar`, `NewConstant`,
     linear/global constraints (`Add`, `AddLinearConstraint`, `AddExactlyOne`, `AddAtMostOne`,
     `AddAllDifferent`, `AddNoOverlap`, `AddCumulative`, `AddCircuit`, `AddReservoirConstraint`,
     `AddAllowedAssignments`, `AddImplication`), half-reified `OnlyEnforceIf` literals, and
     channeling constraints (`AddMaxEquality`, `AddMinEquality`, `AddMultiplicationEquality`,
     `AddAbsEquality`, `AddDivisionEquality`, `AddModuloEquality`, `AddElement`).
   - Expands `Zoom 2` micro-strata (`cp_var`, `cp_constraint`, `cp_objective`) with
     `constrains_var`, `enforced_by_literal`, and `channels_var` edges so `wythe context --zoom 2`
     exposes 1-hop variable-sharing conflict neighborhoods (`job_intervals`,
     `machine_assignments`, `vehicle_routes`).
2. **Solver Factory Registration & Post-Solve Validator Symmetry**:
   - Flags exported constraint builders (`add_*_constraints`, `*Constraint`) omitted from active
     solver assembly pipelines (`MANIP-003`) while recording exact registration order.
   - Detects asymmetric `Truth`-tier table reads between `CpModel` assembly modules and post-solve
     validator modules (`TRUTH-001`).
3. **Objective Weight Tower, Float-to-Zero Truncation & Empty-Table Silent Shedding**:
   - Extracts `Minimize` / `Maximize` linear penalty hierarchies, flagging hardcoded integer
     weights and `int(scale * weight) == 0` float-to-zero truncations (`MANIP-001`).
   - Flags dynamic `Truth` table iteration loops lacking an explicit empty-table guard
     (`TRUTH-001`).
4. **Multi-Solver Status Masking, Bound-Gap Omission, Parameter Clamping & Assumption Coverage**:
   - Detects multi-stage `CpSolver()` pipelines where a secondary `OPTIMAL` masks a primary
     `FEASIBLE` timeout, `FEASIBLE` branches omitting `(ObjectiveValue(), BestObjectiveBound())`,
     unguarded `os.cpu_count()` worker assignments or missing `max_time_in_seconds` (`MANIP-001`),
     and hard `model.Add(...)` blocks with zero assumption literals (`MANIP-003`).
5. **Read-Only `CpModelProto` (`Z=1`) & `CpSolverResponse` (`Z=2`) Companion Correlation**:
   - Correlates serialized variable/constraint prefixes, expansion bloat ratios, bound gaps, and
     `sufficient_assumptions_for_infeasibility` cores back to `Z=0` source builders via `WallTie`
     beams while keeping `Z=0` `content_digest` invariant.
