# `wythe-plugin-solver-chronicle`

Optional companion plugin (`importlib.metadata.entry_points(group="wythe.plugins")`) adding a **phase-ordered 6-phase 3-tier solver chronicle**, passive live/offline log watcher (`wythe watch-solver` / `wythe-watch-solver`), and structured `MODEL_INVALID` / `INFEASIBLE` / search-pathology forensics over Wythe's domain-agnostic `ChronicleFrame[]` timeline primitive.

## Capabilities

1. **Unified Incremental `Live Watch <-> Replay` Parser (`log_parser.py`)**:
   - Single incremental line/event parser handling both live tailing (`--log <path>` or `--stdin`) and post-hoc replay (`CpSolverResponse.solve_log`, `CpModelProto` JSON/`.pbtxt`, and `CpSolverSolutionCallback` JSONL telemetry streams).
   - Recognizes upstream OR-Tools CP-SAT `log_search_progress=true` progress, presolve, symmetry, `ValidateCpModel`, portfolio worker, and `CpSolverResponse summary:` lines (`google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5`).
2. **Six-Phase Causal 3-Tier Chronicle (`synthesizer.py`)**:
   - `[1.Load]` (`truth`): `reads_truth` preloads, `PolicyFieldConsumption` (`consumed` vs `bypassed` vs `unresolved`), and `TRUTH-001` empty-seed-table silent no-op risks.
   - `[2.Build]` (`manipulate`): `Variables -> Sequential Constraints -> Objective Tower` in AST registration order, flagging unwired exported constraint builders (`MANIP-003`) and `int(scale * weight) == 0` float-to-zero truncations (`MANIP-001`).
   - `[3.Presolve]` (`manipulate`): `Expand -> Presolve -> Symmetry` variable/constraint compression vs expansion bloat and presolve `INFEASIBLE` conflict neighborhoods.
   - `[4.Search]` (`manipulate`): Sequential multi-solver (`Solver 1 -> Solver 2`) and portfolio search (`CDCL`, `LP` cuts, `LNS`), tracking `best_bound` convergence toward `objective`.
   - `[5.Persist]` (`truth`): Post-solve validator `Truth`-read symmetry vs `[2.Build]` and `writes_truth` persistence (flagging auxiliary `OPTIMAL` masking primary `FEASIBLE` or omitted `(ObjectiveValue, BestObjectiveBound)` gap persistence).
   - `[6.Render]` (`display`): `Truth -> Manipulate -> Display` projection through HTTP routes into UI components (flagging optimistic `"Solved"` / `"Optimal"` badges omitting `FEASIBLE` bound-gap caveats).
3. **Structured 5-Class Log Forensics (`forensics.py`)**:
   - `model_invalid` (`[2.Build]` halt): `ValidateCpModel` (`lb > ub`, negative interval size, coefficient overflow) resolved to `Z=0` `file:line` + `[1.Load]` `Truth` table/column.
   - `presolve_infeasible` (`[3.Presolve]` halt): `Problem closed by presolve` + `INFEASIBLE` resolved to `Z=0` constraint bricks + 1-hop variable-sharing neighborhood.
   - `root_lp_infeasible` (`[4.Search]` root halt): Root LP / probing infeasibility (`conflicts: 0`, `branches: 0` after presolve) highlighting capacity-vs-demand `[1.Load]` `Truth` tables.
   - `assumption_core_or_missing_assumptions` (`[4.Search]` halt): `sufficient_assumptions_for_infeasibility` core attribution or un-assumed hard constraint highlight + opt-in soft-slack pass guidance.
   - `search_pathology` (`[3.Presolve]` / `[4.Search]` warning): Extreme coefficient ranges (`[1e+00, 1e+12]`), `>5x` presolve expansion blowups, and prolonged zero-incumbent / zero-LNS-acceptance stalls.

## Epistemic & Security Boundary

Strictly passive/read-only: `wythe-plugin-solver-chronicle` never imports or executes target repository code or solvers, enforces non-symlink regular-file and `is_relative_to` containment on companion inputs, and keeps `Z=0` `wythe gate` `content_digest` values invariant.
