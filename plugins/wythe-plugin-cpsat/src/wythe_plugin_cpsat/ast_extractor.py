"""Pure-Python AST lineage extractor for OR-Tools CP-SAT models, builders, and solvers."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_max_py_file_bytes = 512 * 1024
_skip_dir_names = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "tests",
        "test",
        "alembic",
        "migrations",
    }
)
_builtin_skip_idents = frozenset(
    {
        "abs",
        "all",
        "any",
        "bool",
        "cp_model",
        "dict",
        "enumerate",
        "float",
        "int",
        "len",
        "list",
        "max",
        "min",
        "model",
        "range",
        "round",
        "self",
        "set",
        "solver",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
        "True",
        "False",
        "None",
    }
)

_var_method_families: dict[str, str] = {
    "NewBoolVar": "bool_var",
    "new_bool_var": "bool_var",
    "NewIntVar": "int_var",
    "NewIntVarFromDomain": "int_var",
    "new_int_var": "int_var",
    "new_int_var_from_domain": "int_var",
    "NewIntervalVar": "interval_var",
    "NewFixedSizeIntervalVar": "interval_var",
    "new_interval_var": "interval_var",
    "new_fixed_size_interval_var": "interval_var",
    "NewOptionalIntervalVar": "optional_interval_var",
    "NewOptionalFixedSizeIntervalVar": "optional_interval_var",
    "new_optional_interval_var": "optional_interval_var",
    "new_optional_fixed_size_interval_var": "optional_interval_var",
    "NewConstant": "constant",
    "new_constant": "constant",
}

_constraint_method_types: dict[str, str] = {
    "Add": "linear_or_bool",
    "AddLinearConstraint": "linear_domain",
    "add_linear_constraint": "linear_domain",
    "AddExactlyOne": "exactly_one",
    "add_exactly_one": "exactly_one",
    "AddAtMostOne": "at_most_one",
    "add_at_most_one": "at_most_one",
    "AddAllDifferent": "all_different",
    "add_all_different": "all_different",
    "AddNoOverlap": "no_overlap",
    "AddNoOverlap2D": "no_overlap_2d",
    "add_no_overlap": "no_overlap",
    "add_no_overlap_2d": "no_overlap_2d",
    "AddCumulative": "cumulative",
    "add_cumulative": "cumulative",
    "AddCircuit": "circuit",
    "AddMultipleCircuit": "circuit",
    "add_circuit": "circuit",
    "add_multiple_circuit": "circuit",
    "AddReservoirConstraint": "reservoir",
    "AddReservoirConstraintWithActive": "reservoir",
    "add_reservoir_constraint": "reservoir",
    "add_reservoir_constraint_with_active": "reservoir",
    "AddAllowedAssignments": "allowed_assignments",
    "AddForbiddenAssignments": "forbidden_assignments",
    "add_allowed_assignments": "allowed_assignments",
    "add_forbidden_assignments": "forbidden_assignments",
    "AddImplication": "implication",
    "add_implication": "implication",
    "AddBoolOr": "bool_or",
    "AddBoolAnd": "bool_and",
    "AddBoolXor": "bool_xor",
    "add_bool_or": "bool_or",
    "add_bool_and": "bool_and",
    "add_bool_xor": "bool_xor",
}

_channel_method_types: dict[str, str] = {
    "AddMaxEquality": "max_equality",
    "add_max_equality": "max_equality",
    "AddMinEquality": "min_equality",
    "add_min_equality": "min_equality",
    "AddMultiplicationEquality": "multiplication_equality",
    "add_multiplication_equality": "multiplication_equality",
    "AddAbsEquality": "abs_equality",
    "add_abs_equality": "abs_equality",
    "AddDivisionEquality": "division_equality",
    "add_division_equality": "division_equality",
    "AddModuloEquality": "modulo_equality",
    "add_modulo_equality": "modulo_equality",
    "AddElement": "element",
    "add_element": "element",
}

_objective_methods: dict[str, Literal["minimize", "maximize"]] = {
    "Minimize": "minimize",
    "minimize": "minimize",
    "Maximize": "maximize",
    "maximize": "maximize",
}

_assumption_methods = frozenset(
    {"AddAssumptions", "AddAssumption", "add_assumptions", "add_assumption"}
)
_enforce_methods = frozenset({"OnlyEnforceIf", "only_enforce_if"})
_name_methods = frozenset({"WithName", "with_name"})
_solve_methods = frozenset({"Solve", "solve", "SolveWithSolutionCallback", "solve_with_solution_callback"})
_builder_fn_re = re.compile(
    r"^(?:add|build|apply|attach|register)_[a-z0-9_]*constraint[a-z0-9_]*$"
)
_validator_name_re = re.compile(
    r"(?:^validate_[a-z0-9_]*(?:solution|plan|route|assignment|alloc|job|order|output|result)[a-z0-9_]*$"
    r"|^[A-Z][A-Za-z0-9]*(?:Solution|Plan|Route|Assignment|Allocation|Output)?Validator$"
    r"|(?:^|/)(?:solution_|post_solve_|plan_|route_)?validator(?:s)?\.py$)"
)


@dataclass(frozen=True)
class CpSatVariableDecl:
    symbol: str
    family: str
    method: str
    name_prefix: str
    component_vars: tuple[str, ...]
    source_file: str
    line: int
    function_name: str


@dataclass(frozen=True)
class CpSatConstraintDecl:
    method: str
    constraint_type: str
    is_channeling: bool
    referenced_vars: tuple[str, ...]
    channel_target_vars: tuple[str, ...]
    enforced_by_vars: tuple[str, ...]
    name_prefix: str
    source_file: str
    line: int
    function_name: str


@dataclass(frozen=True)
class CpSatObjectiveTerm:
    expr_text: str
    static_weight: int | float | None
    truncated_from_float: float | None
    dynamic_source: str | None
    referenced_vars: tuple[str, ...]
    source_file: str
    line: int


@dataclass(frozen=True)
class CpSatObjectiveDecl:
    sense: Literal["minimize", "maximize"]
    terms: tuple[CpSatObjectiveTerm, ...]
    referenced_vars: tuple[str, ...]
    source_file: str
    line: int
    function_name: str


@dataclass(frozen=True)
class CpSatTruncationHazard:
    expr_text: str
    evaluated_float: float
    truncated_int: int
    source_file: str
    line: int
    function_name: str


@dataclass(frozen=True)
class CpSatBuilderDecl:
    symbol: str
    kind: Literal["function", "class"]
    source_file: str
    line: int
    param_names: tuple[str, ...]
    is_registered: bool = False


@dataclass(frozen=True)
class CpSatUnguardedLoop:
    iterable_expr: str
    table_hint: str | None
    source_file: str
    line: int
    function_name: str


@dataclass(frozen=True)
class CpSatSolverRunDecl:
    function_name: str
    source_file: str
    line: int
    solve_call_lines: tuple[int, ...]
    status_masked: bool
    status_mask_line: int | None
    status_mask_detail: str
    missing_bound_gap: bool
    missing_bound_gap_line: int | None
    unguarded_cpu_workers: bool
    unguarded_cpu_workers_line: int | None
    missing_max_time: bool
    registration_order: tuple[str, ...]
    call_arg_var_map: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class CpSatModuleModel:
    source_file: str
    is_cpsat_module: bool
    is_validator_module: bool
    variables: tuple[CpSatVariableDecl, ...]
    constraints: tuple[CpSatConstraintDecl, ...]
    objectives: tuple[CpSatObjectiveDecl, ...]
    assumption_vars: tuple[str, ...]
    assumption_lines: tuple[int, ...]
    truncations: tuple[CpSatTruncationHazard, ...]
    builders: tuple[CpSatBuilderDecl, ...]
    unguarded_loops: tuple[CpSatUnguardedLoop, ...]
    solver_runs: tuple[CpSatSolverRunDecl, ...]
    called_symbols: frozenset[str]


@dataclass(frozen=True)
class CpSatRepoExtraction:
    repo_root: str
    modules: dict[str, CpSatModuleModel]
    registered_builders: tuple[str, ...]
    unregistered_builders: tuple[CpSatBuilderDecl, ...]
    registration_order: tuple[str, ...]


def _extract_string_prefix(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    ):
        head, _, _ = node.func.value.value.partition("{")
        return head
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Mod)
        and isinstance(node.left, ast.Constant)
        and isinstance(node.left.value, str)
    ):
        head, _, _ = node.left.value.partition("%")
        return head
    return ""


def _eval_numeric_expr(
    node: ast.AST,
    const_env: dict[str, int | float],
    depth: int = 0,
) -> tuple[int | float | None, float | None]:
    """Return `(value, truncated_from_float)` for pure constant arithmetic expressions."""
    if depth > 12:
        return None, None
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(
        node.value, bool
    ):
        return node.value, None
    if isinstance(node, ast.Name) and node.id in const_env:
        return const_env[node.id], None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        sub_val, sub_trunc = _eval_numeric_expr(node.operand, const_env, depth + 1)
        if sub_val is None:
            return None, None
        return (sub_val if isinstance(node.op, ast.UAdd) else -sub_val), sub_trunc
    if isinstance(node, ast.BinOp):
        lv, lt = _eval_numeric_expr(node.left, const_env, depth + 1)
        rv, rt = _eval_numeric_expr(node.right, const_env, depth + 1)
        if lv is None or rv is None:
            return None, None
        trunc = lt if lt is not None else rt
        if isinstance(node.op, ast.Add):
            return lv + rv, trunc
        if isinstance(node.op, ast.Sub):
            return lv - rv, trunc
        if isinstance(node.op, ast.Mult):
            return lv * rv, trunc
        if isinstance(node.op, ast.Div):
            return (lv / rv, trunc) if rv != 0 else (None, None)
        if isinstance(node.op, ast.FloorDiv):
            if rv == 0:
                return None, None
            fval = lv / rv
            res = lv // rv
            if isinstance(fval, float) and fval != 0.0 and int(res) == 0 and abs(fval) < 1.0:
                return int(res), float(fval)
            return res, trunc
        if isinstance(node.op, ast.Pow) and abs(rv) <= 16:
            return lv**rv, trunc
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("int", "round")
        and len(node.args) == 1
        and not node.keywords
    ):
        inner_val, inner_trunc = _eval_numeric_expr(node.args[0], const_env, depth + 1)
        if inner_val is None:
            return None, None
        cast_val = int(inner_val) if node.func.id == "int" else round(inner_val)
        if isinstance(inner_val, float) and inner_val != 0.0 and cast_val == 0:
            return 0, inner_val
        return cast_val, inner_trunc
    return None, None


def _collect_comp_targets(node: ast.AST) -> set[str]:
    bound: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.comprehension):
            for t in ast.walk(sub.target):
                if isinstance(t, ast.Name):
                    bound.add(t.id)
    return bound


def _collect_ident_roots(node: ast.AST | None, extra_skip: set[str] | None = None) -> list[str]:
    if node is None:
        return []
    skip = _builtin_skip_idents | _collect_comp_targets(node) | (extra_skip or set())
    found: list[str] = []

    def _visit(cur: ast.AST) -> None:
        if isinstance(cur, ast.Call):
            if isinstance(cur.func, ast.Attribute) and not (
                isinstance(cur.func.value, ast.Name) and cur.func.value.id in skip
            ):
                _visit(cur.func.value)
            for arg in cur.args:
                _visit(arg)
            for kw in cur.keywords:
                _visit(kw.value)
            return
        if isinstance(cur, ast.Subscript):
            _visit(cur.value)
            return
        if isinstance(cur, ast.Attribute):
            if isinstance(cur.value, ast.Name) and cur.value.id in ("self", "cls", "ctx", "state"):
                if cur.attr not in skip and not cur.attr.isupper():
                    found.append(cur.attr)
                return
            _visit(cur.value)
            return
        if isinstance(cur, ast.Name):
            if cur.id not in skip and not cur.id.isupper():
                found.append(cur.id)
            return
        for child in ast.iter_child_nodes(cur):
            _visit(child)

    _visit(node)
    return list(dict.fromkeys(found))


def _lhs_symbol(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Subscript):
        return _lhs_symbol(target.value)
    if isinstance(target, ast.Attribute):
        if isinstance(target.value, ast.Name) and target.value.id in ("self", "cls", "ctx", "state"):
            return target.attr
        return target.attr
    return None


def _var_name_arg_and_components(method: str, call: ast.Call) -> tuple[ast.AST | None, list[ast.AST]]:
    kw_name = next((kw.value for kw in call.keywords if kw.arg == "name"), None)
    low = method.lower()
    if "optional" in low and "fixed" in low:
        return (kw_name or (call.args[3] if len(call.args) > 3 else None)), list(call.args[:3])
    if "optional" in low:
        return (kw_name or (call.args[4] if len(call.args) > 4 else None)), list(call.args[:4])
    if "fixed" in low and "interval" in low:
        return (kw_name or (call.args[2] if len(call.args) > 2 else None)), list(call.args[:2])
    if "interval" in low:
        return (kw_name or (call.args[3] if len(call.args) > 3 else None)), list(call.args[:3])
    if "bool" in low:
        return (kw_name or (call.args[0] if call.args else None)), []
    if "domain" in low:
        return (kw_name or (call.args[1] if len(call.args) > 1 else None)), []
    if "int" in low:
        return (kw_name or (call.args[2] if len(call.args) > 2 else None)), []
    return kw_name, []


def _unwrap_cpsat_chain(
    call: ast.Call,
) -> tuple[ast.Call, list[ast.AST], str, set[int]]:
    """Unwrap `.OnlyEnforceIf(...)` and `.WithName(...)` chains to the inner `Add*` call."""
    enforced_args: list[ast.AST] = []
    name_prefix = ""
    wrapped_ids: set[int] = set()
    cur = call
    while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
        attr = cur.func.attr
        if attr in _enforce_methods and isinstance(cur.func.value, ast.Call):
            wrapped_ids.add(id(cur))
            enforced_args.extend(cur.args)
            cur = cur.func.value
            continue
        if attr in _name_methods and isinstance(cur.func.value, ast.Call):
            wrapped_ids.add(id(cur))
            if cur.args and not name_prefix:
                name_prefix = _extract_string_prefix(cur.args[0])
            cur = cur.func.value
            continue
        break
    wrapped_ids.add(id(cur))
    return cur, enforced_args, name_prefix, wrapped_ids


def _flatten_objective_exprs(
    expr: ast.AST,
    accumulators: dict[str, list[ast.AST]],
    seen_acc: set[str] | None = None,
) -> list[ast.AST]:
    visited = seen_acc or set()
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Sub)):
        left_items = _flatten_objective_exprs(expr.left, accumulators, visited)
        right_items = _flatten_objective_exprs(expr.right, accumulators, visited)
        if isinstance(expr.op, ast.Sub):
            right_items = [
                ast.UnaryOp(op=ast.USub(), operand=r) for r in right_items
            ]
        return [*left_items, *right_items]
    if isinstance(expr, ast.Name) and expr.id in accumulators and expr.id not in visited:
        nxt = visited | {expr.id}
        out: list[ast.AST] = []
        for item in accumulators[expr.id]:
            out.extend(_flatten_objective_exprs(item, accumulators, nxt))
        return out or [expr]
    if isinstance(expr, ast.Call):
        is_sum = (isinstance(expr.func, ast.Name) and expr.func.id == "sum") or (
            isinstance(expr.func, ast.Attribute) and expr.func.attr in ("Sum", "sum")
        )
        if is_sum and expr.args:
            arg0 = expr.args[0]
            if isinstance(arg0, (ast.List, ast.Tuple, ast.Set)):
                out = []
                for elt in arg0.elts:
                    out.extend(_flatten_objective_exprs(elt, accumulators, visited))
                return out
            if isinstance(arg0, (ast.GeneratorExp, ast.ListComp)):
                return [arg0]
            if isinstance(arg0, ast.Name) and arg0.id in accumulators and arg0.id not in visited:
                return _flatten_objective_exprs(arg0, accumulators, visited)
    return [expr]


def _analyze_objective_term(
    term_node: ast.AST,
    source_file: str,
    fallback_line: int,
    const_env: dict[str, int | float],
    extra_skip: set[str],
) -> CpSatObjectiveTerm:
    line = getattr(term_node, "lineno", None) or fallback_line
    core = term_node.elt if isinstance(term_node, (ast.GeneratorExp, ast.ListComp)) else term_node
    comp_skip = _collect_comp_targets(term_node) | extra_skip
    static_w: int | float | None = None
    trunc_f: float | None = None
    dyn_src: str | None = None

    if isinstance(core, ast.BinOp) and isinstance(core.op, ast.Mult):
        lv, lt = _eval_numeric_expr(core.left, const_env)
        rv, rt = _eval_numeric_expr(core.right, const_env)
        if lv is not None and rv is None:
            static_w, trunc_f = lv, lt
        elif rv is not None and lv is None:
            static_w, trunc_f = rv, rt
        else:
            for side in (core.left, core.right):
                if isinstance(side, (ast.Attribute, ast.Subscript)):
                    txt = ast.unparse(side)
                    if any(tok in txt.lower() for tok in ("weight", "penalty", "cost", "coeff", "priority", "points", "fee")):
                        dyn_src = txt
                        break
    elif (
        isinstance(core, ast.Call)
        and isinstance(core.func, ast.Attribute)
        and core.func.attr in ("WeightedSum", "weighted_sum")
        and len(core.args) >= 2
        and isinstance(core.args[1], (ast.List, ast.Tuple))
    ):
        for w_elt in core.args[1].elts:
            wv, wt = _eval_numeric_expr(w_elt, const_env)
            if wt is not None:
                static_w, trunc_f = wv, wt
                break
            if wv is not None and static_w is None:
                static_w = wv

    refs = tuple(_collect_ident_roots(term_node, comp_skip))
    return CpSatObjectiveTerm(
        expr_text=ast.unparse(term_node)[:180],
        static_weight=static_w,
        truncated_from_float=trunc_f,
        dynamic_source=dyn_src,
        referenced_vars=refs,
        source_file=source_file,
        line=line,
    )


def _contains_cpu_count_without_cap(expr: ast.AST) -> bool:
    has_raw = False

    def _walk(node: ast.AST, capped: bool) -> None:
        nonlocal has_raw
        if isinstance(node, ast.Call):
            fn_name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            )
            if fn_name in ("min", "clamp"):
                for arg in node.args:
                    _walk(arg, True)
                return
            if fn_name == "cpu_count" and not capped:
                has_raw = True
                return
        for child in ast.iter_child_nodes(node):
            _walk(child, capped)

    _walk(expr, False)
    return has_raw


def _test_mentions_feasible(test_node: ast.AST) -> bool:
    for sub in ast.walk(test_node):
        if isinstance(sub, ast.Name) and sub.id == "FEASIBLE":
            return True
        if isinstance(sub, ast.Attribute) and sub.attr == "FEASIBLE":
            return True
        if isinstance(sub, ast.Constant) and sub.value == "FEASIBLE":
            return True
    return False


def _is_db_query_expr(expr: ast.AST) -> tuple[bool, str | None]:
    txt = ast.unparse(expr)
    low = txt.lower()
    if any(tok in low for tok in (".scalars(", ".execute(", ".fetchall(", ".query(", "select(")):
        m_sql = re.search(r"\bfrom\s+([a-zA-Z_][a-zA-Z0-9_]*)", txt, re.IGNORECASE)
        if m_sql:
            return True, m_sql.group(1)
        m_sel = re.search(r"\bselect\(\s*([A-Za-z_][A-Za-z0-9_]*)", txt)
        if m_sel:
            return True, m_sel.group(1)
        return True, None
    return False, None


def _extract_guarded_iterables(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    guarded: set[str] = set()
    for sub in ast.walk(func_node):
        if isinstance(sub, ast.Assert):
            guarded.update(_collect_ident_roots(sub.test))
        elif isinstance(sub, ast.If):
            test = sub.test
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                guarded.update(_collect_ident_roots(test.operand))
            elif isinstance(test, ast.Compare):
                t_str = ast.unparse(test)
                if "len(" in t_str or "[]" in t_str or "None" in t_str:
                    guarded.update(_collect_ident_roots(test))
            elif isinstance(test, ast.BoolOp):
                for val in test.values:
                    if isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not):
                        guarded.update(_collect_ident_roots(val.operand))
            elif sub.orelse:
                guarded.update(_collect_ident_roots(test))
    return guarded


def _analyze_function(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    qual_name: str,
    module_consts: dict[str, int | float],
    has_cpsat_import: bool,
) -> tuple[
    list[CpSatVariableDecl],
    list[CpSatConstraintDecl],
    list[CpSatObjectiveDecl],
    list[str],
    list[int],
    list[CpSatTruncationHazard],
    list[CpSatUnguardedLoop],
    CpSatSolverRunDecl | None,
    set[str],
]:
    vars_out: list[CpSatVariableDecl] = []
    cts_out: list[CpSatConstraintDecl] = []
    objs_out: list[CpSatObjectiveDecl] = []
    assump_vars: list[str] = []
    assump_lines: list[int] = []
    truncs_out: list[CpSatTruncationHazard] = []
    loops_out: list[CpSatUnguardedLoop] = []
    called_syms: set[str] = set()

    param_names = [a.arg for a in fn_node.args.args if a.arg not in ("self", "cls")]
    model_Receivers: set[str] = {"model", "cp_model", "m"}
    for a in fn_node.args.args:
        if a.annotation and "CpModel" in ast.unparse(a.annotation):
            model_Receivers.add(a.arg)

    local_consts = dict(module_consts)
    accumulators: dict[str, list[ast.AST]] = {}
    ct_var_index: dict[str, int] = {}
    queried_vars: dict[str, str | None] = {}
    for p in param_names:
        if any(p.endswith(suf) for suf in ("_rows", "policy_rows", "penalty_rows", "weight_rows", "rule_rows")):
            queried_vars[p] = p

    guarded_vars = _extract_guarded_iterables(fn_node)
    seen_calls: set[int] = set()
    seen_trunc_calls: set[int] = set()
    seen_vars: set[tuple[str, str, int]] = set()
    reg_order: list[str] = []
    arg_var_map: list[tuple[str, int, str]] = []
    solve_events: list[tuple[int, str | None, str | None]] = []
    solver_vars: set[str] = set()
    has_max_time = False
    unguarded_workers = False
    unguarded_workers_line: int | None = None

    def _record_var_call(lhs: str, call: ast.Call, method: str) -> None:
        fam = _var_method_families[method]
        name_arg, comp_nodes = _var_name_arg_and_components(method, call)
        prefix = _extract_string_prefix(name_arg)
        comp_syms: list[str] = []
        for cn in comp_nodes:
            comp_syms.extend(_collect_ident_roots(cn))
        vkey = (lhs, fam, call.lineno)
        if vkey not in seen_vars:
            seen_vars.add(vkey)
            vars_out.append(
                CpSatVariableDecl(
                    symbol=lhs,
                    family=fam,
                    method=method,
                    name_prefix=prefix or lhs,
                    component_vars=tuple(dict.fromkeys(comp_syms)),
                    source_file=rel_path,
                    line=call.lineno,
                    function_name=qual_name,
                )
            )

    for stmt in _dfs_nodes(fn_node):
        assign_t0: ast.AST | None = None
        val_expr: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            assign_t0 = stmt.targets[0]
            val_expr = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            assign_t0 = stmt.target
            val_expr = stmt.value

        if assign_t0 is not None and val_expr is not None:
            lhs = _lhs_symbol(assign_t0)
            if lhs:
                nv, _ = _eval_numeric_expr(val_expr, local_consts)
                if nv is not None:
                    local_consts[lhs] = nv
                is_q, tbl_h = _is_db_query_expr(val_expr)
                if is_q:
                    queried_vars[lhs] = tbl_h
                if isinstance(val_expr, (ast.List, ast.Tuple)):
                    accumulators[lhs] = list(val_expr.elts)
                if isinstance(val_expr, ast.Call):
                    fn_txt = ast.unparse(val_expr.func)
                    if fn_txt.endswith("CpModel"):
                        model_Receivers.add(lhs)
                    elif fn_txt.endswith("CpSolver"):
                        solver_vars.add(lhs)
                for sub_c in ast.walk(val_expr):
                    if (
                        isinstance(sub_c, ast.Call)
                        and isinstance(sub_c.func, ast.Attribute)
                        and sub_c.func.attr in _var_method_families
                    ):
                        _record_var_call(lhs, sub_c, sub_c.func.attr)
                        seen_calls.add(id(sub_c))
                if (
                    isinstance(val_expr, ast.Call)
                    and isinstance(val_expr.func, ast.Attribute)
                    and val_expr.func.attr in _solve_methods
                ):
                    s_recv = _lhs_symbol(val_expr.func.value)
                    solve_events.append((val_expr.lineno, lhs, s_recv))
                    seen_calls.add(id(val_expr))
            if (
                isinstance(assign_t0, ast.Attribute)
                and isinstance(assign_t0.value, ast.Attribute)
                and assign_t0.value.attr == "parameters"
            ):
                if assign_t0.attr == "max_time_in_seconds":
                    has_max_time = True
                elif assign_t0.attr in ("num_search_workers", "num_workers") and _contains_cpu_count_without_cap(val_expr):
                    unguarded_workers = True
                    unguarded_workers_line = stmt.lineno
        elif isinstance(stmt, ast.AugAssign):
            lhs = _lhs_symbol(stmt.target)
            if lhs and isinstance(stmt.op, ast.Add):
                accumulators.setdefault(lhs, []).append(stmt.value)

    return _finish_function_pass(
        fn_node=fn_node,
        rel_path=rel_path,
        qual_name=qual_name,
        has_cpsat_import=has_cpsat_import,
        model_receivers=model_Receivers,
        solver_vars=solver_vars,
        local_consts=local_consts,
        accumulators=accumulators,
        ct_var_index=ct_var_index,
        queried_vars=queried_vars,
        guarded_vars=guarded_vars,
        seen_calls=seen_calls,
        seen_trunc_calls=seen_trunc_calls,
        vars_out=vars_out,
        cts_out=cts_out,
        objs_out=objs_out,
        assump_vars=assump_vars,
        assump_lines=assump_lines,
        truncs_out=truncs_out,
        loops_out=loops_out,
        reg_order=reg_order,
        arg_var_map=arg_var_map,
        solve_events=solve_events,
        has_max_time=has_max_time,
        unguarded_workers=unguarded_workers,
        unguarded_workers_line=unguarded_workers_line,
        called_syms=called_syms,
    )


def _dfs_nodes(root: ast.AST) -> list[ast.AST]:
    ordered: list[ast.AST] = []

    def _visit(n: ast.AST) -> None:
        ordered.append(n)
        for ch in ast.iter_child_nodes(n):
            _visit(ch)

    _visit(root)
    return ordered


def _finish_function_pass(
    *,
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    qual_name: str,
    has_cpsat_import: bool,
    model_receivers: set[str],
    solver_vars: set[str],
    local_consts: dict[str, int | float],
    accumulators: dict[str, list[ast.AST]],
    ct_var_index: dict[str, int],
    queried_vars: dict[str, str | None],
    guarded_vars: set[str],
    seen_calls: set[int],
    seen_trunc_calls: set[int],
    vars_out: list[CpSatVariableDecl],
    cts_out: list[CpSatConstraintDecl],
    objs_out: list[CpSatObjectiveDecl],
    assump_vars: list[str],
    assump_lines: list[int],
    truncs_out: list[CpSatTruncationHazard],
    loops_out: list[CpSatUnguardedLoop],
    reg_order: list[str],
    arg_var_map: list[tuple[str, int, str]],
    solve_events: list[tuple[int, str | None, str | None]],
    has_max_time: bool,
    unguarded_workers: bool,
    unguarded_workers_line: int | None,
    called_syms: set[str],
) -> tuple[
    list[CpSatVariableDecl],
    list[CpSatConstraintDecl],
    list[CpSatObjectiveDecl],
    list[str],
    list[int],
    list[CpSatTruncationHazard],
    list[CpSatUnguardedLoop],
    CpSatSolverRunDecl | None,
    set[str],
]:
    dfs_all = _dfs_nodes(fn_node)
    assign_lhs_by_val_id: dict[int, str] = {}
    for n in dfs_all:
        if isinstance(n, ast.Assign) and len(n.targets) == 1:
            lhs_s = _lhs_symbol(n.targets[0])
            if lhs_s:
                assign_lhs_by_val_id[id(n.value)] = lhs_s
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            lhs_s = _lhs_symbol(n.target)
            if lhs_s:
                assign_lhs_by_val_id[id(n.value)] = lhs_s

    for n in dfs_all:
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                callee = n.func.id
                called_syms.add(callee)
            elif isinstance(n.func, ast.Attribute):
                callee = n.func.attr
                called_syms.add(callee)
                if callee == "append" and n.args:
                    recv_name = _lhs_symbol(n.func.value)
                    if recv_name:
                        accumulators.setdefault(recv_name, []).append(n.args[0])
                        arg0 = n.args[0]
                        if (
                            isinstance(arg0, ast.Call)
                            and isinstance(arg0.func, ast.Attribute)
                            and arg0.func.attr in _var_method_families
                            and id(arg0) not in seen_calls
                        ):
                            seen_calls.add(id(arg0))
                            name_arg, comp_nodes = _var_name_arg_and_components(arg0.func.attr, arg0)
                            comp_s = [s for cn in comp_nodes for s in _collect_ident_roots(cn)]
                            vars_out.append(
                                CpSatVariableDecl(
                                    symbol=recv_name,
                                    family=_var_method_families[arg0.func.attr],
                                    method=arg0.func.attr,
                                    name_prefix=_extract_string_prefix(name_arg) or recv_name,
                                    component_vars=tuple(dict.fromkeys(comp_s)),
                                    source_file=rel_path,
                                    line=arg0.lineno,
                                    function_name=qual_name,
                                )
                            )
                elif callee == "extend" and n.args and isinstance(n.args[0], (ast.List, ast.Tuple)):
                    recv_name = _lhs_symbol(n.func.value)
                    if recv_name:
                        accumulators.setdefault(recv_name, []).extend(n.args[0].elts)
            else:
                callee = ""

            if (
                callee
                and (_builder_fn_re.match(callee) or callee.endswith("Constraint"))
                and callee not in reg_order
            ):
                reg_order.append(callee)
            if callee and not callee.startswith("_") and callee not in _builtin_skip_idents:
                for idx_a, arg_a in enumerate(n.args):
                    roots = _collect_ident_roots(arg_a)
                    if len(roots) == 1:
                        arg_var_map.append((callee, idx_a, roots[0]))

            # Check float-to-zero integer truncation `int(scale * weight) == 0`
            if (
                isinstance(n.func, ast.Name)
                and n.func.id in ("int", "round")
                and len(n.args) == 1
                and id(n) not in seen_trunc_calls
            ):
                ev_val, trunc_src = _eval_numeric_expr(n, local_consts)
                if ev_val == 0 and trunc_src is not None:
                    seen_trunc_calls.add(id(n))
                    truncs_out.append(
                        CpSatTruncationHazard(
                            expr_text=ast.unparse(n)[:160],
                            evaluated_float=float(trunc_src),
                            truncated_int=0,
                            source_file=rel_path,
                            line=n.lineno,
                            function_name=qual_name,
                        )
                    )

            if id(n) in seen_calls or not isinstance(n.func, ast.Attribute):
                continue

            inner_call, enf_args, w_prefix, chain_ids = _unwrap_cpsat_chain(n)
            if not isinstance(inner_call.func, ast.Attribute):
                continue
            m_attr = inner_call.func.attr
            recv_sym = _lhs_symbol(inner_call.func.value)

            if m_attr in _solve_methods:
                seen_calls.update(chain_ids)
                solve_events.append((inner_call.lineno, None, recv_sym))
                continue

            if m_attr in _assumption_methods:
                seen_calls.update(chain_ids)
                for a_arg in inner_call.args:
                    for v_sym in _collect_ident_roots(a_arg):
                        if v_sym not in assump_vars:
                            assump_vars.append(v_sym)
                assump_lines.append(inner_call.lineno)
                continue

            if m_attr in _enforce_methods and recv_sym in ct_var_index:
                seen_calls.update(chain_ids)
                c_idx = ct_var_index[recv_sym]
                old_ct = cts_out[c_idx]
                extra_enf = [s for ea in inner_call.args for s in _collect_ident_roots(ea)]
                for es in extra_enf:
                    if es not in assump_vars:
                        assump_vars.append(es)
                assump_lines.append(inner_call.lineno)
                merged_enf = tuple(dict.fromkeys([*old_ct.enforced_by_vars, *extra_enf]))
                cts_out[c_idx] = CpSatConstraintDecl(
                    method=old_ct.method,
                    constraint_type=old_ct.constraint_type,
                    is_channeling=old_ct.is_channeling,
                    referenced_vars=old_ct.referenced_vars,
                    channel_target_vars=old_ct.channel_target_vars,
                    enforced_by_vars=merged_enf,
                    name_prefix=old_ct.name_prefix,
                    source_file=old_ct.source_file,
                    line=old_ct.line,
                    function_name=old_ct.function_name,
                )
                continue

            is_lower_add = m_attr == "add"
            if is_lower_add and not (has_cpsat_import and recv_sym in model_receivers):
                continue

            if m_attr in _constraint_method_types or m_attr in _channel_method_types or is_lower_add:
                seen_calls.update(chain_ids)
                is_chan = m_attr in _channel_method_types
                ctype = (
                    _channel_method_types[m_attr]
                    if is_chan
                    else _constraint_method_types.get(m_attr, "linear_or_bool")
                )
                all_refs = [s for ca in inner_call.args for s in _collect_ident_roots(ca)]
                enf_syms = [s for ea in enf_args for s in _collect_ident_roots(ea)]
                if ctype == "implication" and inner_call.args:
                    enf_syms.extend(_collect_ident_roots(inner_call.args[0]))
                for es in enf_syms:
                    if es not in assump_vars:
                        assump_vars.append(es)
                if enf_syms:
                    assump_lines.append(inner_call.lineno)
                chan_tgts: list[str] = []
                if is_chan and inner_call.args:
                    tgt_arg = (
                        inner_call.args[2]
                        if ctype == "element" and len(inner_call.args) >= 3
                        else inner_call.args[0]
                    )
                    chan_tgts = _collect_ident_roots(tgt_arg)
                assigned_ct = assign_lhs_by_val_id.get(id(n))
                if assigned_ct:
                    ct_var_index[assigned_ct] = len(cts_out)
                cts_out.append(
                    CpSatConstraintDecl(
                        method=m_attr,
                        constraint_type=ctype,
                        is_channeling=is_chan,
                        referenced_vars=tuple(dict.fromkeys(all_refs)),
                        channel_target_vars=tuple(dict.fromkeys(chan_tgts)),
                        enforced_by_vars=tuple(dict.fromkeys(enf_syms)),
                        name_prefix=w_prefix,
                        source_file=rel_path,
                        line=inner_call.lineno,
                        function_name=qual_name,
                    )
                )
                continue

            if m_attr in _objective_methods and inner_call.args:
                if m_attr.islower() and not (has_cpsat_import and recv_sym in model_receivers):
                    continue
                seen_calls.update(chain_ids)
                sense = _objective_methods[m_attr]
                flat_terms = _flatten_objective_exprs(inner_call.args[0], accumulators)
                parsed_terms = [
                    _analyze_objective_term(t_ast, rel_path, inner_call.lineno, local_consts, model_receivers)
                    for t_ast in flat_terms
                ]
                obj_refs = tuple(
                    dict.fromkeys(v for pt in parsed_terms for v in pt.referenced_vars)
                )
                objs_out.append(
                    CpSatObjectiveDecl(
                        sense=sense,
                        terms=tuple(parsed_terms),
                        referenced_vars=obj_refs,
                        source_file=rel_path,
                        line=inner_call.lineno,
                        function_name=qual_name,
                    )
                )

    _collect_loops_and_solver_runs(
        fn_node=fn_node,
        dfs_all=dfs_all,
        rel_path=rel_path,
        qual_name=qual_name,
        queried_vars=queried_vars,
        guarded_vars=guarded_vars,
        loops_out=loops_out,
        solve_events=solve_events,
        solver_vars=solver_vars,
        objs_out=objs_out,
        has_max_time=has_max_time,
        unguarded_workers=unguarded_workers,
        unguarded_workers_line=unguarded_workers_line,
        reg_order=reg_order,
        arg_var_map=arg_var_map,
        called_syms=called_syms,
        run_holder=(solver_runs_box := []),
    )
    return (
        vars_out,
        cts_out,
        objs_out,
        assump_vars,
        assump_lines,
        truncs_out,
        loops_out,
        solver_runs_box[0] if solver_runs_box else None,
        called_syms,
    )


def _collect_loops_and_solver_runs(
    *,
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    dfs_all: list[ast.AST],
    rel_path: str,
    qual_name: str,
    queried_vars: dict[str, str | None],
    guarded_vars: set[str],
    loops_out: list[CpSatUnguardedLoop],
    solve_events: list[tuple[int, str | None, str | None]],
    solver_vars: set[str],
    objs_out: list[CpSatObjectiveDecl],
    has_max_time: bool,
    unguarded_workers: bool,
    unguarded_workers_line: int | None,
    reg_order: list[str],
    arg_var_map: list[tuple[str, int, str]],
    called_syms: set[str],
    run_holder: list[CpSatSolverRunDecl],
) -> None:
    for n in dfs_all:
        if not isinstance(n, ast.For):
            continue
        touches_model = any(
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and (
                sub.func.attr in _constraint_method_types
                or sub.func.attr in _channel_method_types
                or sub.func.attr in _objective_methods
                or sub.func.attr in ("append", "extend")
            )
            for sub in ast.walk(n)
        )
        if not touches_model:
            continue
        direct_q, tbl_hint = _is_db_query_expr(n.iter)
        if direct_q:
            loops_out.append(
                CpSatUnguardedLoop(
                    iterable_expr=ast.unparse(n.iter)[:120],
                    table_hint=tbl_hint,
                    source_file=rel_path,
                    line=n.lineno,
                    function_name=qual_name,
                )
            )
        elif isinstance(n.iter, ast.Name) and n.iter.id in queried_vars and n.iter.id not in guarded_vars:
            loops_out.append(
                CpSatUnguardedLoop(
                    iterable_expr=n.iter.id,
                    table_hint=queried_vars[n.iter.id],
                    source_file=rel_path,
                    line=n.lineno,
                    function_name=qual_name,
                )
            )

    dedup_solves: list[tuple[int, str | None, str | None]] = []
    seen_slines: set[int] = set()
    for s_line, st_var, sv_var in sorted(solve_events, key=lambda item: item[0]):
        if s_line not in seen_slines:
            seen_slines.add(s_line)
            dedup_solves.append((s_line, st_var, sv_var))

    if not dedup_solves and not solver_vars and not reg_order:
        return

    status_masked = False
    status_mask_line: int | None = None
    status_mask_detail = ""
    if len(dedup_solves) >= 2:
        st_vars = [st for _, st, _ in dedup_solves if st is not None]
        if len(st_vars) >= 2 and len(set(st_vars)) < len(st_vars):
            status_masked = True
            status_mask_line = dedup_solves[-1][0]
            status_mask_detail = (
                f"Status variable `{st_vars[-1]}` is overwritten across {len(dedup_solves)} "
                "CpSolver.Solve() stages; an auxiliary OPTIMAL can mask a primary FEASIBLE timeout."
            )
        elif len(st_vars) >= 2:
            first_st, last_st = st_vars[0], st_vars[-1]
            uses_add_hint = "AddHint" in called_syms or "add_hint" in called_syms
            ret_refs: set[str] = set()
            for sub in dfs_all:
                if isinstance(sub, ast.Return) and sub.value is not None:
                    ret_refs.update(_collect_ident_roots(sub.value))
                elif (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr in ("add", "execute", "merge")
                ):
                    for a in sub.args:
                        ret_refs.update(_collect_ident_roots(a))
            if last_st in ret_refs and first_st not in ret_refs and not uses_add_hint:
                status_masked = True
                status_mask_line = dedup_solves[-1][0]
                status_mask_detail = (
                    f"Final persisted/returned status references `{last_st}` while ignoring prior "
                    f"stage `{first_st}`, allowing stage-2 OPTIMAL to mask stage-1 FEASIBLE."
                )

    has_obj_val = "ObjectiveValue" in called_syms or "objective_value" in called_syms
    has_best_bnd = "BestObjectiveBound" in called_syms or "best_objective_bound" in called_syms
    feasible_if_line: int | None = None
    for sub in dfs_all:
        if isinstance(sub, ast.If) and _test_mentions_feasible(sub.test):
            feasible_if_line = sub.lineno
            break

    missing_gap = bool(
        dedup_solves
        and feasible_if_line is not None
        and (objs_out or has_obj_val)
        and not (has_obj_val and has_best_bnd)
    )
    missing_gap_line: int | None = feasible_if_line

    run_holder.append(
        CpSatSolverRunDecl(
            function_name=qual_name,
            source_file=rel_path,
            line=fn_node.lineno,
            solve_call_lines=tuple(ln for ln, _, _ in dedup_solves),
            status_masked=status_masked,
            status_mask_line=status_mask_line,
            status_mask_detail=status_mask_detail,
            missing_bound_gap=missing_gap,
            missing_bound_gap_line=missing_gap_line,
            unguarded_cpu_workers=unguarded_workers,
            unguarded_cpu_workers_line=unguarded_workers_line,
            missing_max_time=bool(dedup_solves) and not has_max_time,
            registration_order=tuple(reg_order),
            call_arg_var_map=tuple(arg_var_map),
        )
    )


def _has_cpsat_imports(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import):
            if any("ortools" in a.name or "cp_model" in a.name for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if "ortools" in mod or "cp_model" in mod:
                return True
            if any(a.name in ("CpModel", "CpSolver", "cp_model") for a in node.names):
                return True
    return False


def _analyze_module_ast(tree: ast.Module, rel_path: str) -> tuple[CpSatModuleModel, set[str]]:
    has_imp = _has_cpsat_imports(tree)
    mod_consts: dict[str, int | float] = {}
    external_refs: set[str] = set()
    is_init = rel_path.endswith("__init__.py")

    for stmt in tree.body:
        m_target: ast.AST | None = None
        m_val: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            m_target = stmt.targets[0]
            m_val = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            m_target = stmt.target
            m_val = stmt.value
        if isinstance(m_target, ast.Name) and m_val is not None:
            lhs_name = m_target.id
            nv, _ = _eval_numeric_expr(m_val, mod_consts)
            if nv is not None:
                mod_consts[lhs_name] = nv
            if not is_init and lhs_name != "__all__" and isinstance(m_val, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                for sub in ast.walk(m_val):
                    if isinstance(sub, ast.Name):
                        external_refs.add(sub.id)

    all_vars: list[CpSatVariableDecl] = []
    all_cts: list[CpSatConstraintDecl] = []
    all_objs: list[CpSatObjectiveDecl] = []
    all_assump: list[str] = []
    all_assump_lines: list[int] = []
    all_truncs: list[CpSatTruncationHazard] = []
    all_builders: list[CpSatBuilderDecl] = []
    all_loops: list[CpSatUnguardedLoop] = []
    all_runs: list[CpSatSolverRunDecl] = []
    called_all: set[str] = set()
    is_validator = bool(_validator_name_re.search(rel_path))

    scopes: list[tuple[str, str | None, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _validator_name_re.match(node.name):
                is_validator = True
            scopes.append((node.name, None, node))
        elif isinstance(node, ast.ClassDef):
            if _validator_name_re.match(node.name):
                is_validator = True
            if (
                not node.name.startswith("_")
                and node.name not in ("BaseConstraint", "AbstractConstraint", "ConstraintProtocol")
                and node.name.endswith(("Constraint", "ConstraintBuilder"))
            ):
                all_builders.append(
                    CpSatBuilderDecl(
                        symbol=node.name,
                        kind="class",
                        source_file=rel_path,
                        line=node.lineno,
                        param_names=(),
                    )
                )
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append((f"{node.name}.{item.name}", node.name, item))

    fn_feasible_meta: list[tuple[int, int | None, bool]] = []
    for qual, cls_owner, fn_node in scopes:
        v_l, c_l, o_l, a_v, a_ln, tr_l, lp_l, run_d, c_syms = _analyze_function(
            fn_node, rel_path, qual, mod_consts, has_imp
        )
        all_vars.extend(v_l)
        all_cts.extend(c_l)
        all_objs.extend(o_l)
        for av in a_v:
            if av not in all_assump:
                all_assump.append(av)
        all_assump_lines.extend(a_ln)
        all_truncs.extend(tr_l)
        all_loops.extend(lp_l)
        called_all.update(c_syms)
        if not is_init:
            external_refs.update(c_syms)
        if run_d is not None:
            feas_ln = next(
                (s.lineno for s in ast.walk(fn_node) if isinstance(s, ast.If) and _test_mentions_feasible(s.test)),
                None,
            )
            both_bnds = (
                ("ObjectiveValue" in c_syms or "objective_value" in c_syms)
                and ("BestObjectiveBound" in c_syms or "best_objective_bound" in c_syms)
            )
            fn_feasible_meta.append((len(all_runs), feas_ln, both_bnds))
            all_runs.append(run_d)

        if cls_owner is None and not fn_node.name.startswith("_"):
            is_b_name = bool(_builder_fn_re.match(fn_node.name))
            is_ct_only = bool(c_l) and (run_d is None or not run_d.solve_call_lines) and "constraint" in rel_path.lower()
            if is_b_name or is_ct_only:
                p_names = tuple(a.arg for a in fn_node.args.args if a.arg not in ("self", "cls"))
                all_builders.append(
                    CpSatBuilderDecl(
                        symbol=fn_node.name,
                        kind="function",
                        source_file=rel_path,
                        line=fn_node.lineno,
                        param_names=p_names,
                    )
                )

    is_cpsat = bool(
        has_imp or all_vars or all_cts or all_objs or all_assump or any(r.solve_call_lines for r in all_runs)
    )
    if not is_cpsat:
        all_truncs = []
        all_loops = []
        all_runs = []

    for r_idx, feas_ln, both_bnds in fn_feasible_meta:
        if r_idx < len(all_runs) and feas_ln is not None and all_objs and not both_bnds:
            cur_r = all_runs[r_idx]
            if not cur_r.missing_bound_gap and cur_r.solve_call_lines:
                all_runs[r_idx] = CpSatSolverRunDecl(
                    function_name=cur_r.function_name,
                    source_file=cur_r.source_file,
                    line=cur_r.line,
                    solve_call_lines=cur_r.solve_call_lines,
                    status_masked=cur_r.status_masked,
                    status_mask_line=cur_r.status_mask_line,
                    status_mask_detail=cur_r.status_mask_detail,
                    missing_bound_gap=True,
                    missing_bound_gap_line=feas_ln,
                    unguarded_cpu_workers=cur_r.unguarded_cpu_workers,
                    unguarded_cpu_workers_line=cur_r.unguarded_cpu_workers_line,
                    missing_max_time=cur_r.missing_max_time,
                    registration_order=cur_r.registration_order,
                    call_arg_var_map=cur_r.call_arg_var_map,
                )

    return (
        CpSatModuleModel(
            source_file=rel_path,
            is_cpsat_module=is_cpsat,
            is_validator_module=is_validator,
            variables=tuple(all_vars),
            constraints=tuple(all_cts),
            objectives=tuple(all_objs),
            assumption_vars=tuple(all_assump),
            assumption_lines=tuple(sorted(set(all_assump_lines))),
            truncations=tuple(all_truncs),
            builders=tuple(all_builders),
            unguarded_loops=tuple(all_loops),
            solver_runs=tuple(all_runs),
            called_symbols=frozenset(called_all),
        ),
        external_refs,
    )


def extract_repo_cpsat_models(
    repo_root: Path | str,
    backend_subdir: str | None = None,
) -> CpSatRepoExtraction:
    """Statically inspect Python modules in `repo_root` for OR-Tools CP-SAT lineage."""
    root_path = Path(repo_root)
    real_root = root_path.resolve()
    scan_base = real_root
    if backend_subdir and backend_subdir not in ("", "."):
        cand_sub = root_path / backend_subdir
        if not cand_sub.is_symlink():
            resolved_sub = cand_sub.resolve()
            if resolved_sub.is_relative_to(real_root) and resolved_sub.is_dir():
                scan_base = resolved_sub

    py_files: list[tuple[str, Path]] = []
    if scan_base.is_dir():
        for dirpath, dirnames, filenames in os.walk(scan_base, followlinks=False):
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in _skip_dir_names and not (Path(dirpath) / d).is_symlink()
            )
            for fname in sorted(filenames):
                if not fname.endswith(".py"):
                    continue
                fpath = Path(dirpath) / fname
                if fpath.is_symlink():
                    continue
                resolved_f = fpath.resolve()
                if not resolved_f.is_relative_to(real_root):
                    continue
                try:
                    if resolved_f.stat().st_size > _max_py_file_bytes:
                        continue
                except OSError:
                    continue
                rel_posix = resolved_f.relative_to(real_root).as_posix()
                py_files.append((rel_posix, resolved_f))

    raw_models: dict[str, CpSatModuleModel] = {}
    refs_by_file: dict[str, set[str]] = {}
    for rel_posix, resolved_f in sorted(py_files, key=lambda item: item[0]):
        try:
            src = resolved_f.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src, filename=rel_posix)
        except (OSError, SyntaxError):
            continue
        mod_model, ext_refs = _analyze_module_ast(tree, rel_posix)
        raw_models[rel_posix] = mod_model
        refs_by_file[rel_posix] = ext_refs

    repo_has_obj = any(m.objectives for m in raw_models.values() if m.is_cpsat_module)
    all_active_refs: set[str] = set()
    global_reg_order: list[str] = []
    for rel_f, mod_m in raw_models.items():
        all_active_refs.update(refs_by_file.get(rel_f, set()))
        for r in mod_m.solver_runs:
            for b_sym in r.registration_order:
                if b_sym not in global_reg_order:
                    global_reg_order.append(b_sym)

    final_models: dict[str, CpSatModuleModel] = {}
    registered_syms: list[str] = []
    unregistered_decls: list[CpSatBuilderDecl] = []

    for rel_f, mod_m in raw_models.items():
        updated_builders: list[CpSatBuilderDecl] = []
        for b in mod_m.builders:
            is_reg = b.symbol in all_active_refs
            b_upd = CpSatBuilderDecl(
                symbol=b.symbol,
                kind=b.kind,
                source_file=b.source_file,
                line=b.line,
                param_names=b.param_names,
                is_registered=is_reg,
            )
            updated_builders.append(b_upd)
            if is_reg:
                if b.symbol not in registered_syms:
                    registered_syms.append(b.symbol)
            elif mod_m.is_cpsat_module:
                unregistered_decls.append(b_upd)

        updated_runs = list(mod_m.solver_runs)
        if repo_has_obj and not mod_m.objectives and updated_runs:
            has_both = (
                ("ObjectiveValue" in mod_m.called_symbols or "objective_value" in mod_m.called_symbols)
                and ("BestObjectiveBound" in mod_m.called_symbols or "best_objective_bound" in mod_m.called_symbols)
            )
            if not has_both:
                for idx_r, r_item in enumerate(updated_runs):
                    if (
                        r_item.solve_call_lines
                        and not r_item.missing_bound_gap
                        and r_item.missing_bound_gap_line is not None
                    ):
                        updated_runs[idx_r] = CpSatSolverRunDecl(
                            function_name=r_item.function_name,
                            source_file=r_item.source_file,
                            line=r_item.line,
                            solve_call_lines=r_item.solve_call_lines,
                            status_masked=r_item.status_masked,
                            status_mask_line=r_item.status_mask_line,
                            status_mask_detail=r_item.status_mask_detail,
                            missing_bound_gap=True,
                            missing_bound_gap_line=r_item.missing_bound_gap_line,
                            unguarded_cpu_workers=r_item.unguarded_cpu_workers,
                            unguarded_cpu_workers_line=r_item.unguarded_cpu_workers_line,
                            missing_max_time=r_item.missing_max_time,
                            registration_order=r_item.registration_order,
                            call_arg_var_map=r_item.call_arg_var_map,
                        )

        final_models[rel_f] = CpSatModuleModel(
            source_file=mod_m.source_file,
            is_cpsat_module=mod_m.is_cpsat_module,
            is_validator_module=mod_m.is_validator_module,
            variables=mod_m.variables,
            constraints=mod_m.constraints,
            objectives=mod_m.objectives,
            assumption_vars=mod_m.assumption_vars,
            assumption_lines=mod_m.assumption_lines,
            truncations=mod_m.truncations,
            builders=tuple(updated_builders),
            unguarded_loops=mod_m.unguarded_loops,
            solver_runs=tuple(updated_runs),
            called_symbols=mod_m.called_symbols,
        )

    return CpSatRepoExtraction(
        repo_root=str(real_root),
        modules=final_models,
        registered_builders=tuple(registered_syms),
        unregistered_builders=tuple(unregistered_decls),
        registration_order=tuple(global_reg_order),
    )
