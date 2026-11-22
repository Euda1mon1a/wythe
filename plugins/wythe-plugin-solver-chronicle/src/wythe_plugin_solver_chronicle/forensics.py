"""Static Z=0 AST solver/UI extractor and 5-class CP-SAT log forensics engine.

Maps `CpModelProto` variable/constraint indices and `log_search_progress=true`
diagnostics back to `Z=0` AST builder bricks (`file:line`), 1-hop shared-variable
neighborhoods, and upstream `[1.Load]` `Truth` tables without executing target code.
"""

from __future__ import annotations

import ast
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from app.schemas.atlas import AtlasNode, TruthAtlasReport
from wythe_plugin_solver_chronicle.log_parser import (
    CpModelProtoSummary,
    CpSolverResponseSummary,
    ParsedSolverSession,
)

MAX_SOURCE_BYTES: Final[int] = 512 * 1024

ForensicClassKind = Literal[
    "model_invalid",
    "presolve_infeasible",
    "root_lp_infeasible",
    "assumption_core_or_missing_assumptions",
    "search_pathology",
]

_VAR_METHODS = frozenset(
    {
        "NewBoolVar",
        "NewIntVar",
        "NewIntervalVar",
        "NewOptionalIntervalVar",
        "NewFixedSizeIntervalVar",
        "NewOptionalFixedSizeIntervalVar",
        "NewConstant",
    }
)
_CONSTRAINT_METHODS = frozenset(
    {
        "Add",
        "AddLinearConstraint",
        "AddExactlyOne",
        "AddAtMostOne",
        "AddBoolOr",
        "AddBoolAnd",
        "AddImplication",
        "AddAllDifferent",
        "AddNoOverlap",
        "AddNoOverlap2D",
        "AddCumulative",
        "AddReservoirConstraint",
        "AddCircuit",
        "AddMultipleCircuit",
        "AddAllowedAssignments",
        "AddForbiddenAssignments",
        "AddMaxEquality",
        "AddMinEquality",
        "AddMultiplicationEquality",
        "AddDivisionEquality",
        "AddModuloEquality",
        "AddAbsEquality",
        "AddElement",
    }
)


@dataclass(frozen=True)
class AstVarBuilderSite:
    name_hint: str
    local_var: str
    method: str
    source_file: str
    line: int
    func_name: str
    node_id: str | None
    truth_table_ids: tuple[str, ...] = ()
    truth_columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class AstConstraintBuilderSite:
    name_hint: str
    method: str
    source_file: str
    line: int
    func_name: str
    node_id: str | None
    registration_order: int
    var_families: tuple[str, ...] = ()
    has_assumption_literal: bool = False
    assumption_hints: tuple[str, ...] = ()
    truth_table_ids: tuple[str, ...] = ()
    has_explicit_name: bool = False


@dataclass(frozen=True)
class RepoSolverAstProfile:
    solver_node_ids: tuple[str, ...] = ()
    validator_node_ids: tuple[str, ...] = ()
    var_builders: tuple[AstVarBuilderSite, ...] = ()
    constraint_builders: tuple[AstConstraintBuilderSite, ...] = ()
    unwired_builders: tuple[AstConstraintBuilderSite, ...] = ()
    objective_terms: tuple[str, ...] = ()
    objective_truncations: tuple[str, ...] = ()
    empty_table_risks: tuple[str, ...] = ()
    has_assumptions_configured: bool = False
    multi_solver_calls: int = 0
    masks_primary_feasible: bool = False
    masking_site: str | None = None
    omits_bound_gap_persistence: bool = False
    gap_omission_site: str | None = None
    asymmetric_truth_tables: tuple[str, ...] = ()
    optimistic_ui_nodes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ForensicPathology:
    kind: Literal["extreme_coefficient_scaling", "presolve_expansion_blowup", "search_or_lns_stall"]
    phase_index: int
    phase_key: str
    summary: str


@dataclass(frozen=True)
class Z0BuilderResolution:
    symbol: str
    node_id: str | None
    source_file: str
    line: int
    func_name: str
    truth_table_ids: tuple[str, ...] = ()
    truth_columns: tuple[str, ...] = ()

    def pointer(self) -> str:
        return f"{self.source_file}:{self.line}"


@dataclass(frozen=True)
class ForensicReport:
    forensic_class: ForensicClassKind | None = None
    submode: str | None = None
    halted: bool = False
    halt_phase_index: int | None = None
    halt_phase_key: str | None = None
    halted_reason: str | None = None
    summary: str = ""
    z0_builders: tuple[Z0BuilderResolution, ...] = ()
    upstream_truth_tables: tuple[str, ...] = ()
    upstream_truth_columns: tuple[str, ...] = ()
    neighborhood_node_ids: tuple[str, ...] = ()
    neighborhood_builders: tuple[str, ...] = ()
    focus_node_ids: tuple[str, ...] = ()
    highlight_edge_ids: tuple[str, ...] = ()
    recommended_action: str = ""
    pathologies: tuple[ForensicPathology, ...] = ()
    unverified_candidates_note: str | None = None

    @property
    def z0_truth_nodes(self) -> tuple[str, ...]:
        return self.upstream_truth_tables


def _read_contained_repo_file(real_root: Path, rel_path: str) -> str | None:
    clean = rel_path.strip().lstrip("/")
    if not clean or ".." in Path(clean).parts:
        return None
    walk = real_root
    for part in Path(clean).parts:
        if part in ("", "."):
            continue
        walk = walk / part
        if walk.is_symlink():
            return None
    try:
        resolved = walk.resolve()
        if not resolved.is_relative_to(real_root):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(resolved, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SOURCE_BYTES:
                return None
            with os.fdopen(fd, "rb") as fh:
                fd = -1
                raw = fh.read(MAX_SOURCE_BYTES + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        if len(raw) > MAX_SOURCE_BYTES:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def _extract_str_prefix(expr: ast.AST | None) -> str:
    if expr is None:
        return ""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, ast.JoinedStr):
        parts: list[str] = []
        for val in expr.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            else:
                break
        return "".join(parts)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return _extract_str_prefix(expr.left)
    return ""


def _eval_numeric_const(expr: ast.AST, const_map: dict[str, float]) -> float | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (int, float)) and not isinstance(expr.value, bool):
        return float(expr.value)
    if isinstance(expr, ast.Name) and expr.id in const_map:
        return const_map[expr.id]
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
        sub = _eval_numeric_const(expr.operand, const_map)
        return -sub if sub is not None else None
    if isinstance(expr, ast.BinOp):
        lv = _eval_numeric_const(expr.left, const_map)
        rv = _eval_numeric_const(expr.right, const_map)
        if lv is None or rv is None:
            return None
        if isinstance(expr.op, ast.Mult):
            return lv * rv
        if isinstance(expr.op, ast.Div) and rv != 0:
            return lv / rv
        if isinstance(expr.op, ast.Add):
            return lv + rv
        if isinstance(expr.op, ast.Sub):
            return lv - rv
    return None


def _clean_col_name(raw_col: str) -> str:
    head = raw_col.strip().split(":", 1)[0].strip()
    return head.split(None, 1)[0].strip().strip('"').strip("`")


def _call_method_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def _unwrap_chained_constraint_call(
    expr: ast.AST,
) -> tuple[ast.Call | None, bool, list[str], str]:
    """Unwrap `model.Add(...).OnlyEnforceIf(lit).WithName('cst')` chains."""
    has_assump = False
    assump_hints: list[str] = []
    with_name = ""
    cur: ast.AST = expr
    while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
        attr = cur.func.attr
        if attr == "OnlyEnforceIf":
            has_assump = True
            for arg in cur.args:
                assump_hints.extend(_collect_expr_names(arg))
            cur = cur.func.value
            continue
        if attr == "WithName" and cur.args:
            with_name = _extract_str_prefix(cur.args[0])
            cur = cur.func.value
            continue
        if attr in _CONSTRAINT_METHODS:
            return cur, has_assump, assump_hints, with_name
        break
    return None, has_assump, assump_hints, with_name


def _collect_expr_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.append(sub.id)
        elif isinstance(sub, ast.Attribute):
            names.append(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.isidentifier():
            names.append(sub.value)
    return list(dict.fromkeys(names))


def inspect_repo_solver_ast(repo_root: Path, report: TruthAtlasReport) -> RepoSolverAstProfile:
    """Statically inspect target repo ASTs for Z=0 CP-SAT builders, symmetry, and UI caveats."""
    real_root = repo_root.resolve()
    truth_cols_by_id: dict[str, tuple[str, ...]] = {}
    nodes_by_file: dict[str, list[AtlasNode]] = {}
    for node in report.nodes:
        if node.tier == "truth":
            truth_cols_by_id[node.id] = tuple(
                c for c in (_clean_col_name(rc) for rc in node.columns) if c
            )
        nodes_by_file.setdefault(node.source_file, []).append(node)

    truth_by_src: dict[str, list[str]] = {}
    writes_by_src: dict[str, set[str]] = {}
    calls_out: dict[str, list[str]] = {}
    calls_in: dict[str, list[str]] = {}
    for edge in report.edges:
        if edge.kind in ("reads_truth", "guards_truth", "writes_truth") and edge.target_id in truth_cols_by_id:
            truth_by_src.setdefault(edge.source_id, []).append(edge.target_id)
        if edge.kind == "writes_truth":
            writes_by_src.setdefault(edge.source_id, set()).add(edge.target_id)
        elif edge.kind == "calls_helper":
            calls_out.setdefault(edge.source_id, []).append(edge.target_id)
            calls_in.setdefault(edge.target_id, []).append(edge.source_id)

    def _upstream_truth_for_node(nid: str | None) -> tuple[str, ...]:
        if not nid:
            return ()
        linked_truth: list[str] = list(truth_by_src.get(nid, ()))
        # Transitive helper callees (`nid -> callee -> ...`)
        seen_down: set[str] = {nid}
        down_work: list[str] = list(calls_out.get(nid, ()))
        while down_work:
            cur = down_work.pop()
            if cur in seen_down:
                continue
            seen_down.add(cur)
            linked_truth.extend(truth_by_src.get(cur, ()))
            down_work.extend(calls_out.get(cur, ()))
        # Transitive preload callers (`caller -> ... -> nid`, never bouncing to sibling callees)
        seen_up: set[str] = {nid}
        up_work: list[str] = list(calls_in.get(nid, ()))
        while up_work:
            cur = up_work.pop()
            if cur in seen_up:
                continue
            seen_up.add(cur)
            linked_truth.extend(truth_by_src.get(cur, ()))
            up_work.extend(calls_in.get(cur, ()))
        return tuple(dict.fromkeys(linked_truth))

    manip_files = sorted(
        {
            n.source_file
            for n in report.nodes
            if n.tier == "manipulate" and n.source_file.endswith(".py")
        }
    )
    parsed_trees: list[tuple[str, str | None, ast.Module, str]] = []
    all_called_names: set[str] = set()
    ordered_call_rank: dict[str, int] = {}
    call_counter = 0

    for rel_file in manip_files:
        src = _read_contained_repo_file(real_root, rel_file)
        if src is None:
            continue
        try:
            tree = ast.parse(src, filename=rel_file)
        except SyntaxError:
            continue
        fnodes = nodes_by_file.get(rel_file, [])
        primary_nid = next(
            (n.id for n in fnodes if n.subkind == "solver"),
            fnodes[0].id if fnodes else None,
        )
        parsed_trees.append((rel_file, primary_nid, tree, src))
        call_sites_in_file: list[tuple[int, int, str]] = []
        for sub in ast.walk(tree):
            if isinstance(sub, ast.Call):
                mname = _call_method_name(sub)
                if mname:
                    call_sites_in_file.append(
                        (getattr(sub, "lineno", 0), getattr(sub, "col_offset", 0), mname)
                    )
            elif isinstance(sub, (ast.List, ast.Tuple)):
                for elt in sub.elts:
                    if isinstance(elt, ast.Name):
                        call_sites_in_file.append(
                            (getattr(elt, "lineno", 0), getattr(elt, "col_offset", 0), elt.id)
                        )
        call_sites_in_file.sort(key=lambda item: (item[0], item[1]))
        for _, _, sym_called in call_sites_in_file:
            all_called_names.add(sym_called)
            if sym_called not in ordered_call_rank:
                call_counter += 1
                ordered_call_rank[sym_called] = call_counter

    solver_nids: list[str] = []
    validator_nids: list[str] = []
    var_sites: list[AstVarBuilderSite] = []
    cst_sites: list[AstConstraintBuilderSite] = []
    unwired_sites: list[AstConstraintBuilderSite] = []
    obj_terms: list[str] = []
    obj_truncs: list[str] = []
    empty_risks: list[str] = [
        f"{f.source_file}:{f.line} ({f.title})"
        for f in report.findings
        if f.rule_code == "TRUTH-001"
    ]
    has_assumptions = False
    total_solve_calls = 0
    masks_feasible = False
    masking_site: str | None = None
    omits_gap = False
    gap_site: str | None = None

    for rel_file, nid, tree, src in parsed_trees:
        const_map: dict[str, float] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                val = _eval_numeric_const(stmt.value, const_map)
                if val is not None:
                    const_map[stmt.targets[0].id] = val

        is_validator_mod = "validat" in rel_file.lower()
        file_has_cp = "CpModel" in src or "CpSolver" in src or any(m in src for m in ("NewBoolVar", "NewIntVar", "NewIntervalVar"))
        if file_has_cp and nid and nid not in solver_nids:
            solver_nids.append(nid)
        if is_validator_mod and nid and nid not in validator_nids:
            validator_nids.append(nid)

        node_truth_ids = _upstream_truth_for_node(nid)
        known_var_locals: set[str] = set()

        for item in tree.body:
            if (
                isinstance(item, ast.ClassDef)
                and item.name.endswith("Constraint")
                and not item.name.startswith("_")
                and item.name not in all_called_names
            ):
                unwired_sites.append(
                    AstConstraintBuilderSite(
                        name_hint=item.name,
                        method="class",
                        source_file=rel_file,
                        line=item.lineno,
                        func_name=item.name,
                        node_id=nid,
                        registration_order=9999,
                        truth_table_ids=node_truth_ids,
                    )
                )
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fname = item.name
            if "validat" in fname.lower() and nid and nid not in validator_nids:
                validator_nids.append(nid)

            is_exported_cst_fn = (
                not fname.startswith("_")
                and (fname.startswith("add_") and "constraint" in fname.lower() or fname.startswith("build_") and "constraint" in fname.lower())
            )
            if is_exported_cst_fn and fname not in all_called_names:
                unwired_sites.append(
                    AstConstraintBuilderSite(
                        name_hint=fname,
                        method="function",
                        source_file=rel_file,
                        line=item.lineno,
                        func_name=fname,
                        node_id=nid,
                        registration_order=9999,
                        truth_table_ids=node_truth_ids,
                    )
                )

            fn_names = set(_collect_expr_names(item))
            matched_tbls: list[str] = []
            matched_cols: list[str] = []
            for tid in node_truth_ids:
                cols = truth_cols_by_id.get(tid, ())
                hit_cols = [c for c in cols if c in fn_names and c.lower() != "id"]
                if hit_cols:
                    matched_tbls.append(tid)
                    matched_cols.extend(f"{tid}.{c}" for c in hit_cols)
            eff_tbls = tuple(matched_tbls) if matched_tbls else node_truth_ids

            fn_solve_lines: list[int] = []
            fn_status_assigns: list[int] = []
            has_empty_guard = False
            has_for_loop = False

            for stmt in ast.walk(item):
                if isinstance(stmt, ast.If):
                    test_src = ast.unparse(stmt.test) if hasattr(ast, "unparse") else ""
                    if "not " in test_src or "len(" in test_src:
                        has_empty_guard = True
                elif isinstance(stmt, ast.For):
                    has_for_loop = True

                if isinstance(stmt, ast.Assign):
                    lhs_names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                    if isinstance(stmt.value, ast.Call):
                        cm = _call_method_name(stmt.value)
                        if cm in _VAR_METHODS:
                            if nid and nid not in solver_nids:
                                solver_nids.append(nid)
                            str_arg = (
                                _extract_str_prefix(stmt.value.args[-1])
                                if stmt.value.args
                                else ""
                            )
                            local_v = lhs_names[0] if lhs_names else (str_arg or cm)
                            known_var_locals.add(local_v)
                            var_sites.append(
                                AstVarBuilderSite(
                                    name_hint=str_arg or local_v,
                                    local_var=local_v,
                                    method=cm,
                                    source_file=rel_file,
                                    line=stmt.lineno,
                                    func_name=fname,
                                    node_id=nid,
                                    truth_table_ids=eff_tbls,
                                    truth_columns=tuple(dict.fromkeys(matched_cols)),
                                )
                            )
                        elif cm == "Solve":
                            fn_solve_lines.append(stmt.lineno)
                            if any("status" in ln.lower() for ln in lhs_names):
                                fn_status_assigns.append(stmt.lineno)
                    elif any("status" in ln.lower() for ln in lhs_names) and fn_solve_lines:
                        val_txt = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                        if "OPTIMAL" in val_txt:
                            fn_status_assigns.append(stmt.lineno)

                if isinstance(stmt, ast.Call):
                    cm = _call_method_name(stmt)
                    if cm in _VAR_METHODS and not any(v.line == stmt.lineno and v.source_file == rel_file for v in var_sites):
                        str_arg = _extract_str_prefix(stmt.args[-1]) if stmt.args else cm
                        known_var_locals.add(str_arg or cm)
                        var_sites.append(
                            AstVarBuilderSite(
                                name_hint=str_arg or cm,
                                local_var=str_arg or cm,
                                method=cm,
                                source_file=rel_file,
                                line=stmt.lineno,
                                func_name=fname,
                                node_id=nid,
                                truth_table_ids=eff_tbls,
                                truth_columns=tuple(dict.fromkeys(matched_cols)),
                            )
                        )
                    elif cm in ("AddAssumptions", "AddAssumption"):
                        has_assumptions = True
                    elif cm in ("Minimize", "Maximize"):
                        expr_s = ast.unparse(stmt.args[0]) if stmt.args and hasattr(ast, "unparse") else cm
                        obj_terms.append(f"{cm}({expr_s[:80]}) @ {rel_file}:{stmt.lineno}")
                    elif cm == "int" and len(stmt.args) == 1:
                        ev = _eval_numeric_const(stmt.args[0], const_map)
                        if ev is not None and 0.0 < abs(ev) < 1.0:
                            raw_e = ast.unparse(stmt) if hasattr(ast, "unparse") else "int(...)"
                            obj_truncs.append(f"{raw_e} -> 0 @ {rel_file}:{stmt.lineno}")
                    elif cm == "Solve" and stmt.lineno not in fn_solve_lines:
                        fn_solve_lines.append(stmt.lineno)

                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    base_c, has_enf, enf_hints, wname = _unwrap_chained_constraint_call(stmt.value)
                    if base_c is not None:
                        if has_enf:
                            has_assumptions = True
                        cm = _call_method_name(base_c)
                        ref_names = _collect_expr_names(base_c)
                        vfams = tuple(
                            n for n in ref_names
                            if n in known_var_locals or any(n == vs.local_var or n == vs.name_hint for vs in var_sites)
                        ) or tuple(n for n in ref_names if n not in ("model", "self", "cp_model", cm))[:4]
                        reg_ord = ordered_call_rank.get(fname, 5000) * 1000 + base_c.lineno
                        cst_sites.append(
                            AstConstraintBuilderSite(
                                name_hint=wname or fname,
                                method=cm,
                                source_file=rel_file,
                                line=base_c.lineno,
                                func_name=fname,
                                node_id=nid,
                                registration_order=reg_ord,
                                var_families=vfams,
                                has_assumption_literal=has_enf,
                                assumption_hints=tuple(enf_hints),
                                truth_table_ids=eff_tbls,
                                has_explicit_name=bool(wname),
                            )
                        )

            total_solve_calls += len(fn_solve_lines)
            if len(fn_solve_lines) >= 2 and len(fn_status_assigns) >= 2 and not masks_feasible:
                masks_feasible = True
                masking_site = f"{rel_file}:{fn_status_assigns[-1]}"
            if (fn_solve_lines or (nid and nid in writes_by_src)) and "ObjectiveValue" in fn_names and "BestObjectiveBound" not in fn_names and not omits_gap:
                omits_gap = True
                gap_site = f"{rel_file}:{item.lineno}"
            if has_for_loop and not has_empty_guard and node_truth_ids and file_has_cp:
                risk = f"Unguarded table-row loop in {fname} @ {rel_file}:{item.lineno}"
                if risk not in empty_risks:
                    empty_risks.append(risk)

    cst_sites.sort(key=lambda s: (s.registration_order, s.source_file, s.line))
    solver_truth = {t for sn in solver_nids for t in _upstream_truth_for_node(sn)}
    validator_truth = {t for vn in validator_nids for t in _upstream_truth_for_node(vn)}
    asym_tables: tuple[str, ...] = ()
    if solver_truth and validator_nids and solver_truth != validator_truth:
        asym_tables = tuple(sorted(solver_truth ^ validator_truth))

    optimistic_ui = _inspect_display_optimistic_badges(real_root, report)
    return RepoSolverAstProfile(
        solver_node_ids=tuple(solver_nids),
        validator_node_ids=tuple(validator_nids),
        var_builders=tuple(var_sites),
        constraint_builders=tuple(cst_sites),
        unwired_builders=tuple(unwired_sites),
        objective_terms=tuple(obj_terms),
        objective_truncations=tuple(obj_truncs),
        empty_table_risks=tuple(empty_risks),
        has_assumptions_configured=has_assumptions,
        multi_solver_calls=total_solve_calls,
        masks_primary_feasible=masks_feasible,
        masking_site=masking_site,
        omits_bound_gap_persistence=omits_gap,
        gap_omission_site=gap_site,
        asymmetric_truth_tables=asym_tables,
        optimistic_ui_nodes=optimistic_ui,
    )


_OPTIMISTIC_STATUS_RE = re.compile(
    r"""(?:["'`]|>\s*)(Solved|Optimal|Schedule Ready|Plan Optimal)(?:["'`]|\s*<)""",
    re.IGNORECASE,
)
_GAP_CAVEAT_RE = re.compile(
    r"best_bound|bestObjectiveBound|bound_gap|boundGap|optimality_gap|optimalityGap"
    r"|soft_violation|softViolation|gap_pct|is_feasible|FEASIBLE",
    re.IGNORECASE,
)


def _inspect_display_optimistic_badges(
    real_root: Path,
    report: TruthAtlasReport,
) -> tuple[tuple[str, str], ...]:
    flagged: list[tuple[str, str]] = []
    seen_files: set[str] = set()
    for node in report.nodes:
        if node.tier != "display":
            continue
        if node.source_file in seen_files:
            continue
        seen_files.add(node.source_file)
        text = _read_contained_repo_file(real_root, node.source_file)
        if text is None:
            continue
        m = _OPTIMISTIC_STATUS_RE.search(text)
        if m and not _GAP_CAVEAT_RE.search(text):
            badge = m.group(1)
            flagged.append(
                (
                    node.id,
                    f"{node.source_file} renders '{badge}' without FEASIBLE bound-gap or soft-violation caveats",
                )
            )
    return tuple(flagged)


_NUMERIC_INDEX_SUFFIX_RE = re.compile(r"^[_\-.][0-9]+(?:[_\-.][0-9]+)*$")
_INTERVAL_VAR_METHODS = frozenset(
    {
        "NewIntervalVar",
        "NewOptionalIntervalVar",
        "NewFixedSizeIntervalVar",
        "NewOptionalFixedSizeIntervalVar",
    }
)


def _symbol_match_score(query_raw: str, anchor_raw: str) -> tuple[int, int] | None:
    """Score `query_raw` against `anchor_raw`: Tier 2 exact, Tier 1 boundary-indexed prefix, never reverse."""
    q = query_raw.strip().lstrip("~!").lower()
    a = anchor_raw.strip().lstrip("~!").lower()
    if not q or not a:
        return None
    q_base = q.split("[", 1)[0].split(":", 1)[0]
    a_base = a.split("[", 1)[0].split(":", 1)[0]
    if q == a or (q_base and q_base == a_base):
        return (2, len(a_base or a))
    a_clean = a_base.rstrip("_-.")
    if not a_clean:
        return None
    if a_base.endswith(("_", "-", ".")) and q_base.startswith(a_base):
        return (1, len(a_clean))
    if (
        q_base.startswith(a_clean)
        and len(q_base) > len(a_clean)
        and _NUMERIC_INDEX_SUFFIX_RE.fullmatch(q_base[len(a_clean) :]) is not None
    ):
        return (1, len(a_clean))
    return None


def _match_var_site(
    sym_or_idx: str | int | None,
    ast_profile: RepoSolverAstProfile,
    proto: CpModelProtoSummary | None,
) -> tuple[str, AstVarBuilderSite | None]:
    if sym_or_idx is None:
        return "unknown_var", None

    explicit_sym = ""
    display_sym = ""
    if isinstance(sym_or_idx, int):
        if proto is not None and 0 <= sym_or_idx < len(proto.variable_names):
            pv_name = proto.variable_names[sym_or_idx].strip()
            default_tag = f"var_{sym_or_idx}"
            if pv_name and (
                pv_name != default_tag
                or any(
                    vs.name_hint == pv_name or vs.local_var == pv_name
                    for vs in ast_profile.var_builders
                )
            ):
                explicit_sym = pv_name
                display_sym = pv_name
            else:
                display_sym = f"var #{sym_or_idx}"
        else:
            display_sym = f"var #{sym_or_idx}"
    elif isinstance(sym_or_idx, str):
        explicit_sym = sym_or_idx.strip()
        display_sym = explicit_sym or "unknown_var"

    if explicit_sym:
        best_key: tuple[int, int, int] | None = None
        best_site: AstVarBuilderSite | None = None
        for order_idx, vs in enumerate(ast_profile.var_builders):
            s_hint = _symbol_match_score(explicit_sym, vs.name_hint)
            s_loc = _symbol_match_score(explicit_sym, vs.local_var)
            top = (
                s_hint
                if (s_hint is not None and (s_loc is None or s_hint >= s_loc))
                else s_loc
            )
            if top is not None:
                cand_key = (top[0], top[1], -order_idx)
                if best_key is None or cand_key > best_key:
                    best_key = cand_key
                    best_site = vs
        if best_site is not None:
            return display_sym or best_site.name_hint, best_site

    return display_sym or "unknown_var", None


def _match_constraint_sites(
    symbols: list[str],
    ast_profile: RepoSolverAstProfile,
    *,
    allow_var_fallback: bool = True,
) -> list[AstConstraintBuilderSite]:
    clean_syms = [s.strip() for s in symbols if s and s.strip()]
    if not clean_syms:
        return []
    scored_direct: list[tuple[int, int, int, AstConstraintBuilderSite]] = []
    scored_var: list[tuple[int, int, int, AstConstraintBuilderSite]] = []

    for cs in ast_profile.constraint_builders:
        direct_anchors: list[str] = list(cs.assumption_hints)
        if cs.has_explicit_name:
            direct_anchors.insert(0, cs.name_hint)
        elif cs.func_name and (
            "constraint" in cs.func_name.lower()
            or cs.func_name.lower().startswith(("add_", "enforce_"))
        ):
            direct_anchors.insert(0, cs.func_name)

        best_d: tuple[int, int] | None = None
        for sym in clean_syms:
            for anc in direct_anchors:
                sc = _symbol_match_score(sym, anc)
                if sc is not None and (best_d is None or sc > best_d):
                    best_d = sc
        if best_d is not None:
            scored_direct.append((best_d[0], best_d[1], -cs.registration_order, cs))
            continue

        if allow_var_fallback:
            best_v: tuple[int, int] | None = None
            for sym in clean_syms:
                for vf in cs.var_families:
                    sc_v = _symbol_match_score(sym, vf)
                    if sc_v is not None and (best_v is None or sc_v > best_v):
                        best_v = sc_v
            if best_v is not None:
                scored_var.append((best_v[0], best_v[1], -cs.registration_order, cs))

    if scored_direct:
        scored_direct.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
        return [item[3] for item in scored_direct]
    if allow_var_fallback and scored_var:
        scored_var.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
        return [item[3] for item in scored_var]
    return []


def _one_hop_variable_neighborhood(
    seed_sites: list[AstConstraintBuilderSite],
    ast_profile: RepoSolverAstProfile,
    proto: CpModelProtoSummary | None,
    implicated_var_indices: set[int],
) -> tuple[list[str], list[str]]:
    shared_fams = {vf for s in seed_sites for vf in s.var_families if vf}
    neighbor_builders: list[str] = []
    neighbor_nodes: list[str] = []
    for cs in ast_profile.constraint_builders:
        if cs in seed_sites:
            continue
        if shared_fams & set(cs.var_families):
            ptr = f"{cs.func_name}@{cs.source_file}:{cs.line}"
            if ptr not in neighbor_builders:
                neighbor_builders.append(ptr)
            if cs.node_id and cs.node_id not in neighbor_nodes:
                neighbor_nodes.append(cs.node_id)

    if proto is not None and implicated_var_indices:
        for c_idx, c_vars in enumerate(proto.constraint_vars):
            resolved_c_vars = {proto.resolve_literal_var_index(v) for v in c_vars}
            if implicated_var_indices & resolved_c_vars:
                cname = (
                    proto.constraint_names[c_idx]
                    if c_idx < len(proto.constraint_names)
                    else ""
                )
                if cname and cname != f"constraint_{c_idx}":
                    for extra_cs in _match_constraint_sites(
                        [cname], ast_profile, allow_var_fallback=False
                    ):
                        ptr = f"{extra_cs.func_name}@{extra_cs.source_file}:{extra_cs.line}"
                        if extra_cs not in seed_sites and ptr not in neighbor_builders:
                            neighbor_builders.append(ptr)
                        if extra_cs.node_id and extra_cs.node_id not in neighbor_nodes:
                            neighbor_nodes.append(extra_cs.node_id)
    return neighbor_nodes, neighbor_builders


def _detect_search_pathologies(
    session: ParsedSolverSession | None,
    proto: CpModelProtoSummary | None,
) -> list[ForensicPathology]:
    if session is None:
        return []
    out: list[ForensicPathology] = []

    for label, lo_c, hi_c in session.coefficient_ranges:
        abs_lo = max(abs(lo_c), 1e-12)
        abs_hi = abs(hi_c)
        if abs_hi >= 1e10 or (abs_lo > 0 and (abs_hi / abs_lo) >= 1e9):
            out.append(
                ForensicPathology(
                    kind="extreme_coefficient_scaling",
                    phase_index=2,
                    phase_key="3.Presolve",
                    summary=(
                        f"Extreme coefficient scaling in {label}: "
                        f"[{lo_c:.0e}, {hi_c:.0e}] risks LP numerical instability."
                    ),
                )
            )
            break

    base_vars = (
        len(proto.variable_names)
        if proto is not None and proto.variable_names
        else session.initial_variables
    )
    post_vars = session.expanded_variables or session.presolved_variables
    base_csts = (
        len(proto.constraint_names)
        if proto is not None and proto.constraint_names
        else session.initial_constraints
    )
    post_csts = session.expanded_constraints or session.presolved_constraints

    var_ratio = (post_vars / base_vars) if (base_vars and post_vars and base_vars > 0) else 0.0
    cst_ratio = (post_csts / base_csts) if (base_csts and post_csts and base_csts > 0) else 0.0
    max_ratio = max(var_ratio, cst_ratio)
    if max_ratio > 5.0:
        detail = (
            f"vars {base_vars}->{post_vars} ({var_ratio:.1f}x)"
            if var_ratio >= cst_ratio
            else f"constraints {base_csts}->{post_csts} ({cst_ratio:.1f}x)"
        )
        out.append(
            ForensicPathology(
                kind="presolve_expansion_blowup",
                phase_index=2,
                phase_key="3.Presolve",
                summary=f"Presolve/expansion blowup >5x ({detail}).",
            )
        )

    stall_reasons: list[str] = []
    wt = session.max_observed_walltime
    if session.explicit_stall_reported:
        stall_reasons.append("explicit telemetry stall event")
    if session.search_started and not session.incumbents and wt >= 10.0 and session.final_status not in ("OPTIMAL", "INFEASIBLE", "MODEL_INVALID"):
        stall_reasons.append(f"zero incumbents after {wt:.1f}s search")
    if (
        session.last_incumbent_walltime is not None
        and (wt - session.last_incumbent_walltime) >= 15.0
        and session.final_status != "OPTIMAL"
    ):
        stall_reasons.append(f"no incumbent improvement for {wt - session.last_incumbent_walltime:.1f}s")
    if session.lns_zero_acceptance_workers:
        w_str = ", ".join(session.lns_zero_acceptance_workers[:3])
        stall_reasons.append(f"zero LNS move acceptance ({w_str})")

    if stall_reasons:
        out.append(
            ForensicPathology(
                kind="search_or_lns_stall",
                phase_index=3,
                phase_key="4.Search",
                summary=f"Search stall detected: {'; '.join(stall_reasons)}.",
            )
        )
    return out


def classify_solver_forensics(
    report: TruthAtlasReport,
    ast_profile: RepoSolverAstProfile,
    session: ParsedSolverSession | None = None,
    proto: CpModelProtoSummary | None = None,
    response: CpSolverResponseSummary | None = None,
) -> ForensicReport:
    """Classify runtime/companion solver diagnostics into the 5 structured forensic classes."""
    pathologies = tuple(_detect_search_pathologies(session, proto))
    truth_nodes = [n for n in report.nodes if n.tier == "truth"]
    read_edges_by_tbl: dict[str, list[str]] = {}
    for edge in report.edges:
        if edge.kind in ("reads_truth", "guards_truth", "writes_truth"):
            read_edges_by_tbl.setdefault(edge.target_id, []).append(edge.id)

    eff_status = (
        (response.status if response and response.status else None)
        or (session.final_status if session else None)
    )
    assump_lits = list(session.sufficient_assumptions) if session else []
    if response is not None:
        for lit in response.sufficient_assumptions_for_infeasibility:
            if lit not in assump_lits:
                assump_lits.append(lit)

    # Class 1: MODEL_INVALID -> [2.Build] halt (phase_index=1)
    has_val_err = bool(session and session.validation_errors)
    proto_inv_var: int | None = None
    if proto is not None and eff_status == "MODEL_INVALID":
        for v_i, dom in enumerate(proto.variable_domains):
            if dom is not None and dom[0] > dom[1]:
                proto_inv_var = v_i
                break

    if eff_status == "MODEL_INVALID" or has_val_err:
        diag = session.validation_errors[0] if (session and session.validation_errors) else None
        submode = diag.kind if diag is not None else "inverted_bounds"
        z0_list: list[Z0BuilderResolution] = []
        up_tbls: list[str] = []
        up_cols: list[str] = []
        cand_note: str | None = None

        if diag is not None and diag.constraint_index is not None:
            c_idx = diag.constraint_index
            cand_c_syms: list[str] = []
            if diag.symbol_name:
                cand_c_syms.append(diag.symbol_name)
            if proto is not None and 0 <= c_idx < len(proto.constraint_names):
                pc_name = proto.constraint_names[c_idx].strip()
                default_c_tag = f"constraint_{c_idx}"
                if pc_name and (
                    pc_name != default_c_tag
                    or any(cs.name_hint == pc_name for cs in ast_profile.constraint_builders)
                ):
                    cand_c_syms.append(pc_name)
            resolved_sym = cand_c_syms[0] if cand_c_syms else f"constraint #{c_idx}"
            matched_csts = (
                _match_constraint_sites(cand_c_syms, ast_profile, allow_var_fallback=False)
                if cand_c_syms
                else []
            )
            for cs in matched_csts[:1]:
                z0_list.append(
                    Z0BuilderResolution(
                        symbol=resolved_sym,
                        node_id=cs.node_id,
                        source_file=cs.source_file,
                        line=cs.line,
                        func_name=cs.func_name,
                        truth_table_ids=cs.truth_table_ids,
                    )
                )
                up_tbls.extend(cs.truth_table_ids)
            if not z0_list and cand_c_syms:
                # Interval constraints in CpModelProto originate from New*IntervalVar(...) builders
                is_interval_cst = submode == "invalid_interval" or bool(
                    proto is not None
                    and 0 <= c_idx < len(proto.constraint_kinds)
                    and proto.constraint_kinds[c_idx] == "interval"
                )
                if is_interval_cst:
                    for sym_cand in cand_c_syms:
                        _, iv_site = _match_var_site(sym_cand, ast_profile, proto)
                        if iv_site is not None and iv_site.method in _INTERVAL_VAR_METHODS:
                            z0_list.append(
                                Z0BuilderResolution(
                                    symbol=resolved_sym,
                                    node_id=iv_site.node_id,
                                    source_file=iv_site.source_file,
                                    line=iv_site.line,
                                    func_name=iv_site.func_name,
                                    truth_table_ids=iv_site.truth_table_ids,
                                    truth_columns=iv_site.truth_columns,
                                )
                            )
                            up_tbls.extend(iv_site.truth_table_ids)
                            up_cols.extend(iv_site.truth_columns)
                            break
            if not z0_list and ast_profile.constraint_builders:
                cands = ", ".join(
                    f"{c.name_hint}@{c.source_file}:{c.line}"
                    for c in ast_profile.constraint_builders[:3]
                )
                cand_note = f"Unverified repo constraint builders (not attributed): {cands}"
        else:
            key_lookup: str | int | None = None
            if diag is not None and diag.symbol_name:
                key_lookup = diag.symbol_name
            elif diag is not None and diag.var_index is not None:
                key_lookup = diag.var_index
            elif proto_inv_var is not None:
                key_lookup = proto_inv_var

            if key_lookup is not None:
                resolved_sym, v_site = _match_var_site(key_lookup, ast_profile, proto)
            else:
                resolved_sym, v_site = "model", None

            if v_site is not None:
                z0_list.append(
                    Z0BuilderResolution(
                        symbol=resolved_sym,
                        node_id=v_site.node_id,
                        source_file=v_site.source_file,
                        line=v_site.line,
                        func_name=v_site.func_name,
                        truth_table_ids=v_site.truth_table_ids,
                        truth_columns=v_site.truth_columns,
                    )
                )
                up_tbls.extend(v_site.truth_table_ids)
                up_cols.extend(v_site.truth_columns)
            elif ast_profile.var_builders:
                cands = ", ".join(
                    f"{v.name_hint}@{v.source_file}:{v.line}"
                    for v in ast_profile.var_builders[:3]
                )
                cand_note = f"Unverified repo variable builders (not attributed): {cands}"

        up_tbls = list(dict.fromkeys(up_tbls))
        up_cols = list(dict.fromkeys(up_cols))
        focus_ids = list(
            dict.fromkeys(
                [*(z.node_id for z in z0_list if z.node_id), *ast_profile.solver_node_ids[:2], *up_tbls]
            )
        )
        hl_edges = [eid for tid in up_tbls for eid in read_edges_by_tbl.get(tid, ())]
        if z0_list:
            ptr_note = f" @ {z0_list[0].pointer()}"
            tbl_note = f" (Truth: {', '.join(up_tbls)})" if up_tbls else ""
            reason = f"MODEL_INVALID ({submode}) on '{resolved_sym}'{ptr_note}{tbl_note}"
        else:
            reason = f"MODEL_INVALID ({submode}) on '{resolved_sym}' (unresolved source builder)"
        return ForensicReport(
            forensic_class="model_invalid",
            submode=submode,
            halted=True,
            halt_phase_index=1,
            halt_phase_key="2.Build",
            halted_reason=reason[:240],
            summary=reason,
            z0_builders=tuple(z0_list),
            upstream_truth_tables=tuple(up_tbls),
            upstream_truth_columns=tuple(up_cols),
            focus_node_ids=tuple(focus_ids[:50]),
            highlight_edge_ids=tuple(dict.fromkeys(hl_edges))[:80],
            recommended_action="Validate upstream Truth domain bounds (lb <= ub, size >= 0, bounded coefficients) before CpModel assembly.",
            pathologies=pathologies,
            unverified_candidates_note=cand_note,
        )

    # Class 2: Presolve INFEASIBLE -> [3.Presolve] halt (phase_index=2)
    closed_presolve = bool(session and session.closed_by_presolve)
    if closed_presolve and (eff_status in ("INFEASIBLE", None)):
        syms = list(session.implicated_symbols) if session else []
        imp_var_idxs: set[int] = set()
        if proto is not None:
            for s in list(syms):
                for vi, vn in enumerate(proto.variable_names):
                    if vn != f"var_{vi}" and _symbol_match_score(s, vn) is not None:
                        imp_var_idxs.add(vi)
                for ci, cn in enumerate(proto.constraint_names):
                    if cn != f"constraint_{ci}" and _symbol_match_score(s, cn) is not None:
                        imp_var_idxs.update(
                            proto.resolve_literal_var_index(v) for v in proto.constraint_vars[ci]
                        )

        seed_csts = _match_constraint_sites(syms, ast_profile) if syms else []
        neigh_nodes, neigh_builders = _one_hop_variable_neighborhood(
            seed_csts, ast_profile, proto, imp_var_idxs
        )
        z0_csts = [
            Z0BuilderResolution(
                symbol=cs.name_hint,
                node_id=cs.node_id,
                source_file=cs.source_file,
                line=cs.line,
                func_name=cs.func_name,
                truth_table_ids=cs.truth_table_ids,
            )
            for cs in seed_csts
        ]
        up_tbls = list(dict.fromkeys(t for cs in seed_csts for t in cs.truth_table_ids))
        focus_ids = list(
            dict.fromkeys(
                [
                    *(cs.node_id for cs in seed_csts if cs.node_id),
                    *neigh_nodes,
                    *ast_profile.solver_node_ids[:2],
                    *up_tbls,
                ]
            )
        )
        hl_edges = [eid for tid in up_tbls for eid in read_edges_by_tbl.get(tid, ())]
        sym_label = ", ".join(syms[:2]) if syms else (seed_csts[0].name_hint if seed_csts else "presolve_rule")
        unres_suffix = "" if z0_csts else " (unresolved source builder)"
        reason = (
            f"Presolve INFEASIBLE: Problem closed by presolve on '{sym_label}' "
            f"(+{len(neigh_builders)} 1-hop coupled builder(s)){unres_suffix}"
        )
        return ForensicReport(
            forensic_class="presolve_infeasible",
            submode="presolve_contradiction",
            halted=True,
            halt_phase_index=2,
            halt_phase_key="3.Presolve",
            halted_reason=reason[:240],
            summary=reason,
            z0_builders=tuple(z0_csts),
            upstream_truth_tables=tuple(up_tbls),
            neighborhood_node_ids=tuple(neigh_nodes),
            neighborhood_builders=tuple(neigh_builders),
            focus_node_ids=tuple(focus_ids[:50]),
            highlight_edge_ids=tuple(dict.fromkeys(hl_edges))[:80],
            recommended_action="Inspect implicated Z=0 constraint bricks and 1-hop shared-variable neighbors for mutually exclusive fixed bounds.",
            pathologies=pathologies,
        )

    # Class 3: Root-LP / Probing INFEASIBLE -> [4.Search] root halt (phase_index=3)
    resp_has_telemetry = response is not None and (
        any(
            v is not None
            for v in (
                response.num_conflicts,
                response.num_branches,
                response.num_booleans,
                response.wall_time,
                response.user_time,
                response.deterministic_time,
            )
        )
        or bool(response.solution_info)
    )
    resp_zero_branch_conflict = bool(
        resp_has_telemetry
        and response is not None
        and response.num_conflicts in (0, None)
        and response.num_branches in (0, None)
        and (
            session is None
            or (
                session.final_conflicts in (0, None)
                and session.final_branches in (0, None)
            )
        )
    )
    is_root_lp = bool(session and session.root_lp_infeasible) or bool(
        eff_status == "INFEASIBLE"
        and not closed_presolve
        and not assump_lits
        and (
            resp_zero_branch_conflict
            or (
                session is not None
                and session.final_conflicts == 0
                and session.final_branches in (0, None)
            )
        )
    )
    if is_root_lp and eff_status == "INFEASIBLE":
        linked_truth_set = set(
            dict.fromkeys(
                [
                    *(t for cs in ast_profile.constraint_builders for t in cs.truth_table_ids),
                    *(t for vs in ast_profile.var_builders for t in vs.truth_table_ids),
                ]
            )
        )
        linked_truth_nodes = [n for n in truth_nodes if n.id in linked_truth_set]
        cap_tbls = [
            n.id
            for n in linked_truth_nodes
            if any(
                tok in " ".join([n.id, *n.columns]).lower()
                for tok in ("cap", "limit", "quota", "supply", "demand", "order", "dock", "machine", "vehicle", "job")
            )
        ] or [n.id for n in linked_truth_nodes]
        cap_tbls = list(dict.fromkeys(cap_tbls))
        z0_csts = [
            Z0BuilderResolution(
                symbol=cs.name_hint,
                node_id=cs.node_id,
                source_file=cs.source_file,
                line=cs.line,
                func_name=cs.func_name,
                truth_table_ids=cs.truth_table_ids,
            )
            for cs in ast_profile.constraint_builders[:3]
        ]
        focus_ids = list(dict.fromkeys([*cap_tbls, *ast_profile.solver_node_ids[:2]]))
        hl_edges = [eid for tid in cap_tbls for eid in read_edges_by_tbl.get(tid, ())]
        tbl_desc = ", ".join(cap_tbls[:3]) if cap_tbls else "unresolved upstream Truth tables"
        reason = (
            f"Root-LP / probing INFEASIBLE before branching (conflicts=0, branches=0); "
            f"aggregate capacity vs demand mismatch in {tbl_desc}"
        )
        return ForensicReport(
            forensic_class="root_lp_infeasible",
            submode="root_lp_relaxation",
            halted=True,
            halt_phase_index=3,
            halt_phase_key="4.Search",
            halted_reason=reason[:240],
            summary=reason,
            z0_builders=tuple(z0_csts),
            upstream_truth_tables=tuple(cap_tbls),
            focus_node_ids=tuple(focus_ids[:50]),
            highlight_edge_ids=tuple(dict.fromkeys(hl_edges))[:80],
            recommended_action="Compare aggregate supply/capacity rows against total demand in [1.Load] Truth tables feeding the linear relaxation.",
            pathologies=pathologies,
        )

    # Class 4: Search / Assumption-Core INFEASIBLE or Missing-Assumption Guidance -> [4.Search] halt
    if eff_status == "INFEASIBLE":
        if assump_lits:
            resolvable_syms: list[str] = []
            display_syms: list[str] = []
            for lit in assump_lits:
                if proto is not None:
                    v_idx = proto.resolve_literal_var_index(lit)
                    if 0 <= v_idx < len(proto.variable_names):
                        vn = proto.variable_names[v_idx]
                        display_syms.append(vn)
                        if vn != f"var_{v_idx}":
                            resolvable_syms.append(vn)
                    for c_i, enf_tuple in enumerate(proto.constraint_enforcement_literals):
                        if (
                            lit in enf_tuple
                            or v_idx in (proto.resolve_literal_var_index(e) for e in enf_tuple)
                        ) and c_i < len(proto.constraint_names):
                            cn = proto.constraint_names[c_i]
                            display_syms.append(cn)
                            if cn != f"constraint_{c_i}":
                                resolvable_syms.append(cn)
                else:
                    display_syms.append(f"literal {lit}")
            matched_csts = (
                _match_constraint_sites(resolvable_syms, ast_profile) if resolvable_syms else []
            )
            z0_core = [
                Z0BuilderResolution(
                    symbol=cs.name_hint,
                    node_id=cs.node_id,
                    source_file=cs.source_file,
                    line=cs.line,
                    func_name=cs.func_name,
                    truth_table_ids=cs.truth_table_ids,
                )
                for cs in matched_csts
            ]
            up_tbls = list(dict.fromkeys(t for cs in matched_csts for t in cs.truth_table_ids))
            focus_ids = list(
                dict.fromkeys([*(z.node_id for z in z0_core if z.node_id), *ast_profile.solver_node_ids[:2], *up_tbls])
            )
            hl_edges = [eid for tid in up_tbls for eid in read_edges_by_tbl.get(tid, ())]
            unres_tag = "" if z0_core else " (unresolved source builder)"
            reason = (
                f"Assumption-core INFEASIBLE: {len(assump_lits)} assumption literal(s) "
                f"({', '.join(display_syms[:3])}) localized to {len(z0_core)} Z=0 builder(s){unres_tag}"
            )
            return ForensicReport(
                forensic_class="assumption_core_or_missing_assumptions",
                submode="assumption_core",
                halted=True,
                halt_phase_index=3,
                halt_phase_key="4.Search",
                halted_reason=reason[:240],
                summary=reason,
                z0_builders=tuple(z0_core),
                upstream_truth_tables=tuple(up_tbls),
                focus_node_ids=tuple(focus_ids[:50]),
                highlight_edge_ids=tuple(dict.fromkeys(hl_edges))[:80],
                recommended_action="Relax or audit the Z=0 constraint builders bound to sufficient_assumptions_for_infeasibility.",
                pathologies=pathologies,
            )

        hard_csts = [cs for cs in ast_profile.constraint_builders if not cs.has_assumption_literal] or list(ast_profile.constraint_builders)
        z0_hard = [
            Z0BuilderResolution(
                symbol=cs.name_hint,
                node_id=cs.node_id,
                source_file=cs.source_file,
                line=cs.line,
                func_name=cs.func_name,
                truth_table_ids=cs.truth_table_ids,
            )
            for cs in hard_csts[:6]
        ]
        up_tbls = list(dict.fromkeys(t for cs in hard_csts for t in cs.truth_table_ids))
        focus_ids = list(dict.fromkeys([*(z.node_id for z in z0_hard if z.node_id), *ast_profile.solver_node_ids[:2], *up_tbls]))
        hl_edges = [eid for tid in up_tbls for eid in read_edges_by_tbl.get(tid, ())]
        has_any_assump = ast_profile.has_assumptions_configured or bool(proto and proto.assumptions)
        submode = "empty_assumption_core" if has_any_assump else "missing_assumptions"
        reason = (
            f"Search INFEASIBLE with zero assumptions configured across {len(hard_csts)} hard constraint brick(s); "
            "run opt-in soft-slack diagnostic pass to localize frustrated constraints"
        )
        return ForensicReport(
            forensic_class="assumption_core_or_missing_assumptions",
            submode=submode,
            halted=True,
            halt_phase_index=3,
            halt_phase_key="4.Search",
            halted_reason=reason[:240],
            summary=reason,
            z0_builders=tuple(z0_hard),
            upstream_truth_tables=tuple(up_tbls),
            focus_node_ids=tuple(focus_ids[:50]),
            highlight_edge_ids=tuple(dict.fromkeys(hl_edges))[:80],
            recommended_action="Attach OnlyEnforceIf / AddAssumptions literals to hard model.Add(...) blocks or run an opt-in soft-slack diagnostic pass.",
            pathologies=pathologies,
        )

    # Class 5: Live Search Pathologies -> warning annotation on [3.Presolve] / [4.Search]
    if pathologies:
        focus_ids = list(dict.fromkeys([*ast_profile.solver_node_ids[:3], *(n.id for n in truth_nodes[:2])]))
        joined = " | ".join(p.summary for p in pathologies)
        return ForensicReport(
            forensic_class="search_pathology",
            submode=pathologies[0].kind,
            halted=False,
            halt_phase_index=None,
            halt_phase_key=None,
            halted_reason=None,
            summary=joined[:320],
            focus_node_ids=tuple(focus_ids[:50]),
            recommended_action="Rescale extreme objective/matrix coefficients, compact Z=1 constraint expansion, or tune LNS neighborhood workers.",
            pathologies=pathologies,
        )

    return ForensicReport()
