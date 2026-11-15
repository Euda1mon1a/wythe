"""Per-reader AST policy field-to-result consumption lineage for Python manipulators.

Distinguishes three honest static epistemic states on `reads_truth` links to tables
carrying domain policy columns:
- `consumed` (`field_controls_result`): >=1 policy column flows along live expressions
  into an effective return, branch guard, domain helper/solver argument, or write sink.
- `bypassed` (`constant_or_fallback_wins`): reader touches the policy table/row (e.g.
  only `.id`, dead `if False:` branch, or overwritten local variable) while leaving
  policy column(s) unconsumed or substituting a hardcoded policy constant.
- `unresolved` (`dynamic_or_opaque_flow`): dynamic attribute/subscript access
  (`getattr(row, dyn_name)`) or whole-row handoff to an opaque external callable
  prevents static field-selection proof without justifying a false violation.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import (
    PolicyConsumptionMechanism,
    PolicyConsumptionState,
    PolicyFieldConsumption,
)

_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")

_IDENTITY_OR_AUDIT_EXACT = frozenset(
    {
        "ID",
        "UUID",
        "GUID",
        "PK",
        "ROWID",
        "OID",
        "SLUG",
        "NAME",
        "LABEL",
        "TITLE",
        "DESCRIPTION",
        "SUMMARY",
        "NOTE",
        "NOTES",
        "RATIONALE",
        "COMMENT",
        "BODY",
        "TEXT",
        "PATH",
        "REPO_PATH",
        "REL_PATH",
        "URL",
        "EMAIL",
        "ACTOR",
        "USERNAME",
        "CATEGORY",
        "TIER",
        "DOMAIN_PACK",
        "DISPOSITION",
        "VERSION",
        "SCHEMA_VERSION",
        "COMMIT",
        "SOURCE_COMMIT",
        "AUDITED_COMMIT",
        "RECORDED_COMMIT",
        "CONTENT_DIGEST",
        "PAYLOAD_JSON",
        "CHECKSUM",
        "HASH",
    }
)
_IDENTITY_OR_AUDIT_SUFFIXES = (
    "_ID",
    "_UUID",
    "_GUID",
    "_PK",
    "_FK",
    "_AT",
    "_BY",
    "_PATH",
    "_RELPATH",
    "_SLUG",
    "_URL",
    "_COMMIT",
    "_DIGEST",
    "_JSON",
)
_POLICY_COLUMN_STEMS = frozenset(
    {
        "CAP",
        "CAPS",
        "LIMIT",
        "LIMITS",
        "QUOTA",
        "QUOTAS",
        "CEILING",
        "CEILINGS",
        "FLOOR",
        "FLOORS",
        "THRESHOLD",
        "THRESHOLDS",
        "PENALTY",
        "PENALTIES",
        "WEIGHT",
        "WEIGHTS",
        "RATIO",
        "RATIOS",
        "CAPACITY",
        "CAPACITIES",
        "MAX",
        "MAXIMUM",
        "MIN",
        "MINIMUM",
        "ALLOWANCE",
        "ALLOWANCES",
        "BUDGET",
        "BUDGETS",
        "BPS",
        "MARKUP",
        "DISCOUNT",
        "SLIPPAGE",
        "CADENCE",
        "CUTOFF",
        "COOLDOWN",
        "TIMEOUT",
        "TTL",
        "SUPERVISION",
        "WORKLOAD",
        "BLOCKS",
    }
)
_POLICY_TABLE_STEMS = frozenset(
    {
        "POLICY",
        "POLICIES",
        "RULE",
        "RULES",
        "QUOTA",
        "QUOTAS",
        "LIMIT",
        "LIMITS",
        "THRESHOLD",
        "THRESHOLDS",
        "BASELINE",
        "BASELINES",
    }
)
_POLICY_TABLE_VALUE_COLS = frozenset(
    {
        "VALUE",
        "VALUES",
        "AMOUNT",
        "ENABLED",
        "IS_ENABLED",
        "SEVERITY",
        "ALLOWED",
        "TOKEN",
        "DEFAULT_VALUE",
    }
)
_ORM_CHAIN_ATTRS = frozenset(
    {
        "scalars",
        "scalar",
        "scalar_one",
        "scalar_one_or_none",
        "first",
        "last",
        "one",
        "one_or_none",
        "all",
        "unique",
        "where",
        "filter",
        "filter_by",
        "order_by",
        "limit",
        "offset",
        "options",
        "join",
        "outerjoin",
        "select_from",
        "execution_options",
        "with_for_update",
        "objects",
        "using",
        "only",
        "defer",
        "select_related",
        "prefetch_related",
        "mappings",
    }
)
_TRANSPARENT_WRAPPERS = frozenset(
    {"list", "tuple", "set", "frozenset", "iter", "reversed", "sorted", "next"}
)
_WHOLE_ROW_SERIALIZERS = frozenset({"model_validate", "from_orm", "asdict"})
_TELEMETRY_RECEIVERS = frozenset({"logger", "log", "logging"})
_TELEMETRY_FUNCS = frozenset({"print"})


def _normalize_ident_upper(raw: str) -> str:
    spaced = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", raw.strip().strip('"').strip("`"))
    return re.sub(r"[^A-Za-z0-9]+", "_", spaced).strip("_").upper()


def classify_table_policy_columns(
    table_name: str,
    columns: Sequence[str],
    active_tokens: Sequence[str] | None = None,
) -> list[str]:
    """Return ordered columns of `table_name` carrying mutable domain policy semantics."""
    tokens = tuple(active_tokens) if active_tokens is not None else get_active_policy_tokens()
    tbl_norm = _normalize_ident_upper(table_name.rpartition(".")[2] or table_name)
    tbl_parts = set(tbl_norm.split("_")) if tbl_norm else set()
    is_policy_tbl = bool(tbl_parts & _POLICY_TABLE_STEMS) or name_has_policy_token(tbl_norm, tokens)

    matched: list[str] = []
    for col in columns:
        norm = _normalize_ident_upper(col)
        if not norm or norm in _IDENTITY_OR_AUDIT_EXACT:
            continue
        has_explicit_tok = name_has_policy_token(norm, tokens)
        if not has_explicit_tok and norm.endswith(_IDENTITY_OR_AUDIT_SUFFIXES):
            continue
        parts = set(norm.split("_"))
        if (
            has_explicit_tok
            or bool(parts & _POLICY_COLUMN_STEMS)
            or (is_policy_tbl and norm in _POLICY_TABLE_VALUE_COLS)
        ):
            matched.append(col)
    return matched


def is_policy_constant_symbol(name: str, active_tokens: Sequence[str] | None = None) -> bool:
    """True when `name` is an uppercase constant identifier carrying policy/limit semantics."""
    stripped = name.lstrip("_")
    if not stripped or not stripped.isupper() or stripped in {"TRUE", "FALSE", "NONE", "SQL"}:
        return False
    tokens = tuple(active_tokens) if active_tokens is not None else get_active_policy_tokens()
    if name_has_policy_token(stripped, tokens):
        return True
    parts = set(stripped.split("_"))
    return bool(parts & (_POLICY_COLUMN_STEMS | {"DEFAULT", "FALLBACK", "OVERRIDE"}))


def _dotted_expr(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _const_bool(node: ast.AST, const_truth: dict[str, bool] | None = None) -> bool | None:
    """Return compile-time truthiness when `node` is a constant expression, else `None`."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (bool, int, float, str, bytes)) or node.value is None:
            return bool(node.value)
        return None
    if isinstance(node, ast.Name) and const_truth and node.id in const_truth:
        return const_truth[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _const_bool(node.operand, const_truth)
        return (not inner) if inner is not None else None
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return len(node.elts) > 0 if not any(isinstance(e, ast.Starred) for e in node.elts) else True
    if isinstance(node, ast.Dict):
        return len(node.keys) > 0 if None not in node.keys else None
    return None


@dataclass(frozen=True)
class _Val:
    row: bool = False
    row_map: bool = False
    cols: frozenset[str] = frozenset()
    tuple_cols: tuple[str, ...] = ()
    dict_items: tuple[tuple[str, _Val], ...] = ()
    consts: frozenset[str] = frozenset()
    fallbacks: frozenset[str] = frozenset()
    dynamic: bool = False

    def merge(self, other: _Val) -> _Val:
        return _Val(
            row=self.row or other.row,
            row_map=self.row_map or other.row_map,
            cols=self.cols | other.cols,
            consts=self.consts | other.consts,
            fallbacks=self.fallbacks | other.fallbacks,
            dynamic=self.dynamic or other.dynamic,
        )


@dataclass(frozen=True)
class _HelperSummary:
    param_names: tuple[str, ...]
    param_consumed_attrs: dict[int, frozenset[str]]
    param_returned_whole: frozenset[int]
    param_dynamic: frozenset[int]
    returned_cols: frozenset[str] = frozenset()
    guard_cols: frozenset[str] = frozenset()
    returned_consts: frozenset[str] = frozenset()
    returns_tid_row: bool = False
    returns_tid_row_map: bool = False
    has_direct_query: bool = False


@dataclass(frozen=True)
class ScopePolicyReadAnalysis:
    scope_name: str
    lineno: int
    state: PolicyConsumptionState
    mechanism: PolicyConsumptionMechanism
    is_write_lookup: bool
    policy_columns: tuple[str, ...]
    consumed_columns: tuple[str, ...]
    unconsumed_policy_columns: tuple[str, ...]
    substituted_constants: tuple[str, ...]
    fallback_constants: tuple[str, ...]
    opaque_callees: tuple[str, ...] = ()
    had_dead_policy_access: bool = False
    note: str = ""


_SQL_SELECT_RE = re.compile(
    r"\bSELECT\s+(?:DISTINCT\s+)?(?P<proj>.+?)\s+FROM\s+(?:ONLY\s+)?"
    r'(?:"?[A-Za-z_][A-Za-z0-9_]*"?\.)?"?(?P<tbl>[A-Za-z_][A-Za-z0-9_]*)"?\b',
    re.IGNORECASE | re.DOTALL,
)


def _sql_projection_for_table(sql_text: str, sql_table_names: set[str]) -> _Val | None:
    """Extract projected columns for `SELECT <proj> FROM <tbl>` when `<tbl>` matches target."""
    for match in _SQL_SELECT_RE.finditer(sql_text):
        tbl = match.group("tbl").lower()
        if tbl not in sql_table_names:
            continue
        proj = match.group("proj").strip()
        if proj == "*" or proj.endswith(".*"):
            return _Val(row=True)
        cols: list[str] = []
        for raw_part in proj.split(","):
            seg = raw_part.strip()
            seg = re.split(r"\s+AS\s+|\s+", seg, maxsplit=1, flags=re.IGNORECASE)[0]
            col = seg.rpartition(".")[2] or seg
            col = col.strip('"').strip("`")
            if col == "*":
                return _Val(row=True)
            if col.isidentifier():
                cols.append(col)
        if cols:
            return _Val(cols=frozenset(cols), tuple_cols=tuple(cols))
        return _Val(dynamic=True)
    return None


def _null_guard_polarity(test: ast.AST, env: dict[str, _Val]) -> str | None:
    """Return `'null_true'` when `test` holds on None/empty row, `'null_false'` when present."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        op = test.ops[0]
        comp = test.comparators[0]
        if isinstance(comp, ast.Constant) and comp.value is None:
            if isinstance(op, (ast.Is, ast.Eq)):
                return "null_true"
            if isinstance(op, (ast.IsNot, ast.NotEq)):
                return "null_false"
    if isinstance(test, ast.Name) and test.id in env and env[test.id].row and not env[test.id].cols:
        return "null_false"
    if (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Name)
        and test.operand.id in env
        and env[test.operand.id].row
        and not env[test.operand.id].cols
    ):
        return "null_true"
    if isinstance(test, ast.BoolOp):
        subs = [_null_guard_polarity(v, env) for v in test.values]
        if isinstance(test.op, ast.And) and all(s == "null_false" for s in subs):
            return "null_false"
        if isinstance(test.op, ast.Or) and all(s == "null_true" for s in subs):
            return "null_true"
    return None


@dataclass
class _ScopeAccum:
    sink_cols: set[str] = field(default_factory=set)
    return_cols: set[str] = field(default_factory=set)
    touched_cols: set[str] = field(default_factory=set)
    dead_cols: set[str] = field(default_factory=set)
    return_consts: set[str] = field(default_factory=set)
    fallback_consts: set[str] = field(default_factory=set)
    opaque_callees: set[str] = field(default_factory=set)
    sink_dynamic: bool = False
    any_dynamic: bool = False
    mutates_row: bool = False
    primary_return_line: int = 0
    first_query_line: int = 0


_SESSION_MUTATION_METHODS = frozenset(
    {"add", "add_all", "delete", "merge", "refresh", "expunge", "flush", "commit"}
)
_NON_CONSUMING_ROW_BUILTINS = frozenset(
    {"len", "bool", "isinstance", "id", "type", "repr", "str", "enumerate", "zip"}
)


class _FlowRunner:
    """AST abstract interpreter tracking policy-column flow, overwrites, and dead branches."""

    def __init__(
        self,
        *,
        all_table_cols: frozenset[str],
        policy_cols: frozenset[str],
        model_symbols: frozenset[str],
        sql_table_names: set[str],
        policy_consts: frozenset[str],
        const_truth: dict[str, bool],
        aliases: dict[str, str],
        helpers: dict[str, _HelperSummary],
        excluded: set[int],
    ) -> None:
        self.all_table_cols = all_table_cols
        self.policy_cols = policy_cols
        self.model_symbols = model_symbols
        self.sql_table_names = sql_table_names
        self.policy_consts = policy_consts
        self.const_truth = const_truth
        self.aliases = aliases
        self.helpers = helpers
        self.excluded = excluded
        self.acc = _ScopeAccum()

    def _note_query(self, node: ast.AST) -> None:
        lineno = getattr(node, "lineno", 0)
        if lineno and (self.acc.first_query_line == 0 or lineno < self.acc.first_query_line):
            self.acc.first_query_line = lineno

    def _resolve_dotted(self, dotted: str) -> str:
        head, sep, tail = dotted.partition(".")
        resolved = self.aliases.get(head, head)
        return f"{resolved}.{tail}" if sep else resolved

    def _is_model_expr(self, node: ast.AST) -> bool:
        dotted = _dotted_expr(node)
        if not dotted:
            return False
        return dotted in self.model_symbols or self._resolve_dotted(dotted) in self.model_symbols

    def eval_expr(self, node: ast.AST | None, env: dict[str, _Val], *, dead: bool = False) -> _Val:
        if node is None or id(node) in self.excluded:
            return _Val()
        if isinstance(node, ast.NamedExpr):
            val = self.eval_expr(node.value, env, dead=dead)
            if not dead and isinstance(node.target, ast.Name):
                env[node.target.id] = val
            return val
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if self._is_model_expr(node):
                if not dead:
                    self._note_query(node)
                return _Val(row=True)
            if node.id in self.policy_consts:
                return _Val(consts=frozenset({node.id})) if not dead else _Val()
            return _Val()
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and self.sql_table_names:
                proj = _sql_projection_for_table(node.value, self.sql_table_names)
                if proj is not None:
                    if not dead:
                        self._note_query(node)
                        self.acc.touched_cols.update(proj.cols)
                    else:
                        self.acc.dead_cols.update(proj.cols)
                    return proj if not dead else _Val()
            return _Val()
        if isinstance(node, ast.Attribute):
            if self._is_model_expr(node):
                if not dead:
                    self._note_query(node)
                return _Val(row=True)
            if self._is_model_expr(node.value):
                if not dead:
                    self._note_query(node)
                if node.attr == "objects":
                    return _Val(row=True)
                if not node.attr.startswith("__"):
                    if dead:
                        self.acc.dead_cols.add(node.attr)
                        return _Val()
                    self.acc.touched_cols.add(node.attr)
                    return _Val(cols=frozenset({node.attr}), tuple_cols=(node.attr,))
            base = self.eval_expr(node.value, env, dead=dead)
            if base.row and not base.row_map:
                if node.attr in _ORM_CHAIN_ATTRS:
                    return base
                if not node.attr.startswith("_"):
                    if dead:
                        self.acc.dead_cols.add(node.attr)
                        return _Val()
                    self.acc.touched_cols.add(node.attr)
                    return _Val(cols=frozenset({node.attr}))
            return _Val(
                cols=base.cols,
                consts=base.consts,
                fallbacks=base.fallbacks,
                dynamic=base.dynamic,
            )
        if isinstance(node, ast.Subscript):
            base = self.eval_expr(node.value, env, dead=dead)
            slc = node.slice
            if base.dict_items and isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                for d_k, d_v in reversed(base.dict_items):
                    if d_k == slc.value:
                        return d_v
            if base.tuple_cols and isinstance(slc, ast.Constant) and isinstance(slc.value, int):
                idx = slc.value
                if 0 <= idx < len(base.tuple_cols):
                    col = base.tuple_cols[idx]
                    if dead:
                        self.acc.dead_cols.add(col)
                        return _Val()
                    self.acc.touched_cols.add(col)
                    return _Val(cols=frozenset({col}))
            if base.row_map:
                sl_val = self.eval_expr(slc, env, dead=dead)
                if not dead:
                    self.acc.sink_cols.update(sl_val.cols)
                return _Val(row=True, cols=base.cols, fallbacks=base.fallbacks)
            if base.row:
                if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                    col = slc.value
                    if dead:
                        self.acc.dead_cols.add(col)
                        return _Val()
                    self.acc.touched_cols.add(col)
                    return _Val(cols=frozenset({col}))
                if isinstance(slc, ast.Slice) or (
                    isinstance(slc, ast.Constant) and isinstance(slc.value, int)
                ):
                    return base
                if not dead:
                    self.acc.any_dynamic = True
                return _Val(dynamic=not dead)
            return base.merge(self.eval_expr(slc, env, dead=dead))
        if isinstance(node, ast.BoolOp):
            return self._eval_boolop(node, env, dead=dead)
        if isinstance(node, ast.IfExp):
            return self._eval_ifexp(node, env, dead=dead)
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, env, dead=dead)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._eval_comprehension(node, env, dead=dead)
        if isinstance(node, ast.Call):
            return self._eval_call(node, env, dead=dead)
        out = _Val()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out = out.merge(self.eval_expr(child, env, dead=dead))
        return out

    def _eval_boolop(self, node: ast.BoolOp, env: dict[str, _Val], *, dead: bool) -> _Val:
        if isinstance(node.op, ast.Or):
            seen_live = False
            primary = _Val()
            cur = _Val()
            for idx, expr_item in enumerate(node.values):
                cb = _const_bool(expr_item, self.const_truth)
                if cb is False:
                    self.eval_expr(expr_item, env, dead=True)
                    continue
                val = self.eval_expr(expr_item, env, dead=dead)
                if not seen_live:
                    seen_live = True
                    primary = val
                    cur = val
                elif (primary.cols & self.policy_cols) or primary.row:
                    cur = _Val(
                        row=cur.row or val.row,
                        cols=cur.cols | val.cols,
                        consts=cur.consts,
                        fallbacks=cur.fallbacks | val.consts | val.fallbacks,
                        dynamic=cur.dynamic or val.dynamic,
                    )
                else:
                    cur = cur.merge(val)
                if cb is True:
                    for rest in node.values[idx + 1 :]:
                        self.eval_expr(rest, env, dead=True)
                    break
            return cur

        cur = _Val()
        for idx, expr_item in enumerate(node.values):
            cb = _const_bool(expr_item, self.const_truth)
            if cb is False:
                for rest in node.values[idx:]:
                    self.eval_expr(rest, env, dead=True)
                return _Val()
            cur = cur.merge(self.eval_expr(expr_item, env, dead=dead))
        return cur

    def _eval_ifexp(self, node: ast.IfExp, env: dict[str, _Val], *, dead: bool) -> _Val:
        cb = _const_bool(node.test, self.const_truth)
        if cb is True:
            self.eval_expr(node.orelse, env, dead=True)
            return self.eval_expr(node.body, env, dead=dead)
        if cb is False:
            self.eval_expr(node.body, env, dead=True)
            return self.eval_expr(node.orelse, env, dead=dead)
        pol = _null_guard_polarity(node.test, env)
        if pol is None:
            t_val = self.eval_expr(node.test, env, dead=dead)
            if not dead:
                self.acc.sink_cols.update(t_val.cols)
        b_val = self.eval_expr(node.body, env, dead=dead)
        o_val = self.eval_expr(node.orelse, env, dead=dead)
        if pol == "null_false" and ((b_val.cols & self.policy_cols) or b_val.row):
            return _Val(
                row=b_val.row or o_val.row,
                cols=b_val.cols | o_val.cols,
                consts=b_val.consts,
                fallbacks=b_val.fallbacks | o_val.consts | o_val.fallbacks,
                dynamic=b_val.dynamic or o_val.dynamic,
            )
        if pol == "null_true" and ((o_val.cols & self.policy_cols) or o_val.row):
            return _Val(
                row=b_val.row or o_val.row,
                cols=b_val.cols | o_val.cols,
                consts=o_val.consts,
                fallbacks=o_val.fallbacks | b_val.consts | b_val.fallbacks,
                dynamic=b_val.dynamic or o_val.dynamic,
            )
        return b_val.merge(o_val)

    def _eval_dict(self, node: ast.Dict, env: dict[str, _Val], *, dead: bool) -> _Val:
        items_map: dict[str, _Val] = {}
        anon: list[_Val] = []
        for k_node, v_node in zip(node.keys, node.values):
            v_val = self.eval_expr(v_node, env, dead=dead)
            if k_node is None:
                is_dyn = v_val.dynamic or v_val.row
                if is_dyn and not dead:
                    self.acc.any_dynamic = True
                anon.append(
                    _Val(
                        cols=v_val.cols,
                        consts=v_val.consts,
                        fallbacks=v_val.fallbacks,
                        dynamic=is_dyn and not dead,
                    )
                )
            elif isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                if (
                    not dead
                    and k_node.value in self.policy_cols
                    and isinstance(v_node, ast.Constant)
                    and isinstance(v_node.value, (int, float, bool))
                ):
                    v_val = v_val.merge(
                        _Val(consts=frozenset({f"{k_node.value}={v_node.value!r}"}))
                    )
                items_map[k_node.value] = v_val
            else:
                k_val = self.eval_expr(k_node, env, dead=dead)
                anon.append(k_val.merge(v_val))
        merged = _Val()
        for item_val in (*items_map.values(), *anon):
            merged = merged.merge(item_val)
        return _Val(
            row=merged.row,
            cols=merged.cols,
            dict_items=tuple(items_map.items()),
            consts=merged.consts,
            fallbacks=merged.fallbacks,
            dynamic=merged.dynamic,
        )

    def _bind_target(self, target: ast.AST, val: _Val, env: dict[str, _Val]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = val
        elif isinstance(target, (ast.Tuple, ast.List)):
            for idx, elt in enumerate(target.elts):
                if val.tuple_cols and idx < len(val.tuple_cols):
                    col = val.tuple_cols[idx]
                    self.acc.touched_cols.add(col)
                    self._bind_target(elt, _Val(cols=frozenset({col})), env)
                else:
                    self._bind_target(elt, val, env)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            d_name = target.value.id
            sl_val = self.eval_expr(target.slice, env)
            self.acc.sink_cols.update(sl_val.cols)
            prev = env.get(d_name)
            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                if prev is not None and not prev.row_map:
                    d_map = dict(prev.dict_items)
                    s_key = target.slice.value
                    if (
                        s_key in self.policy_cols
                        and not val.cols
                        and not val.row
                        and not val.consts
                        and not val.dynamic
                    ):
                        val = val.merge(_Val(consts=frozenset({f"{s_key}=<override>"})))
                    d_map[s_key] = val
                    merged = _Val()
                    for dv in d_map.values():
                        merged = merged.merge(dv)
                    env[d_name] = _Val(
                        row=merged.row,
                        cols=merged.cols,
                        dict_items=tuple(d_map.items()),
                        consts=merged.consts,
                        fallbacks=merged.fallbacks,
                        dynamic=prev.dynamic or merged.dynamic,
                    )
            else:
                base_prev = prev if prev is not None else _Val()
                env[d_name] = _Val(
                    row=base_prev.row or val.row,
                    row_map=base_prev.row_map or val.row,
                    cols=base_prev.cols | val.cols,
                    consts=base_prev.consts | val.consts,
                    fallbacks=base_prev.fallbacks | val.fallbacks,
                    dynamic=base_prev.dynamic or val.dynamic,
                )

    def _eval_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        env: dict[str, _Val],
        *,
        dead: bool,
    ) -> _Val:
        comp_env = dict(env)
        for gen in node.generators:
            it_val = self.eval_expr(gen.iter, comp_env, dead=dead)
            if not dead:
                self._bind_target(gen.target, it_val, comp_env)
            for if_clause in gen.ifs:
                g_val = self.eval_expr(if_clause, comp_env, dead=dead)
                if not dead:
                    self.acc.sink_cols.update(g_val.cols)
        if isinstance(node, ast.DictComp):
            k_val = self.eval_expr(node.key, comp_env, dead=dead)
            v_val = self.eval_expr(node.value, comp_env, dead=dead)
            if not dead:
                self.acc.sink_cols.update(k_val.cols)
            merged = k_val.merge(v_val)
            return _Val(
                row=merged.row,
                row_map=merged.row_map or v_val.row,
                cols=merged.cols,
                consts=merged.consts,
                fallbacks=merged.fallbacks,
                dynamic=merged.dynamic,
            )
        return self.eval_expr(node.elt, comp_env, dead=dead)

    def _eval_call(self, node: ast.Call, env: dict[str, _Val], *, dead: bool) -> _Val:
        func = node.func
        dotted = _dotted_expr(func) or ""
        short = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else ""
        )
        recv_name = (
            func.value.id
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            else ""
        )
        if short in _TELEMETRY_FUNCS or recv_name in _TELEMETRY_RECEIVERS:
            for a in (*node.args, *(kw.value for kw in node.keywords)):
                self.eval_expr(a, env, dead=True)
            return _Val()

        if isinstance(func, ast.Name) and short == "getattr" and node.args:
            base = self.eval_expr(node.args[0], env, dead=dead)
            fb_val = (
                self.eval_expr(node.args[2], env, dead=dead) if len(node.args) >= 3 else _Val()
            )
            if base.row and len(node.args) >= 2:
                attr_arg = node.args[1]
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    col = attr_arg.value
                    if dead:
                        self.acc.dead_cols.add(col)
                        return _Val()
                    self.acc.touched_cols.add(col)
                    return _Val(cols=frozenset({col}), fallbacks=fb_val.consts | fb_val.fallbacks)
                if not dead:
                    self.acc.any_dynamic = True
                return _Val(dynamic=not dead)
            return base.merge(fb_val)

        if short in {"select", "query"}:
            arg_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
            if any(av.row and not av.cols for av in arg_vals):
                return _Val(row=True)
            cols_union = frozenset().union(*(av.cols for av in arg_vals))
            t_cols = tuple(c for av in arg_vals for c in av.tuple_cols)
            if cols_union:
                return _Val(cols=cols_union, tuple_cols=t_cols)

        recv_seed = _Val()
        if isinstance(func, ast.Attribute):
            recv_val = self.eval_expr(func.value, env, dead=dead)
            if short in {"where", "filter", "filter_by", "having"}:
                for pred in (*node.args, *(kw.value for kw in node.keywords)):
                    pv = self.eval_expr(pred, env, dead=dead)
                    if not dead:
                        self.acc.sink_cols.update(pv.cols)
                return recv_val
            if short in (_ORM_CHAIN_ATTRS | {"execute", "exec", "get", "values", "values_list"}):
                arg_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
                if recv_val.row and short in {"values", "values_list"}:
                    lit_cols = [
                        a.value
                        for a in node.args
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)
                    ]
                    if lit_cols:
                        if not dead:
                            self.acc.touched_cols.update(lit_cols)
                        return _Val(cols=frozenset(lit_cols), tuple_cols=tuple(lit_cols))
                is_orm_objects = (
                    isinstance(func.value, ast.Attribute) and func.value.attr == "objects"
                )
                if recv_val.row_map and short == "get":
                    fb = (
                        arg_vals[1].consts | arg_vals[1].fallbacks
                        if len(arg_vals) >= 2
                        else frozenset()
                    )
                    if arg_vals and not dead:
                        self.acc.sink_cols.update(arg_vals[0].cols)
                    return _Val(row=True, cols=recv_val.cols, fallbacks=fb)
                if recv_val.row and short == "get" and node.args and not is_orm_objects:
                    fb = (
                        arg_vals[1].consts | arg_vals[1].fallbacks
                        if len(arg_vals) >= 2
                        else frozenset()
                    )
                    key_arg = node.args[0]
                    if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, str):
                        col = key_arg.value
                        if dead:
                            self.acc.dead_cols.add(col)
                            return _Val()
                        self.acc.touched_cols.add(col)
                        return _Val(cols=frozenset({col}), fallbacks=fb)
                    if not dead:
                        self.acc.any_dynamic = True
                    return _Val(dynamic=not dead, fallbacks=fb)
                if not (recv_val.row or recv_val.cols):
                    for av in arg_vals:
                        if av.row or av.cols or av.dynamic:
                            return av
                return recv_val
            if (
                short in {"append", "extend", "update", "setdefault"}
                and isinstance(func.value, ast.Name)
                and func.value.id in env
                and (not recv_val.row or recv_val.row_map)
            ):
                arg_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
                kw_vals = [self.eval_expr(kw.value, env, dead=dead) for kw in node.keywords]
                comb = _Val()
                for av in (*arg_vals, *kw_vals):
                    comb = comb.merge(av)
                if not dead:
                    prev_c = env[func.value.id]
                    env[func.value.id] = _Val(
                        row=prev_c.row or comb.row,
                        row_map=prev_c.row_map
                        or (comb.row and short in {"update", "setdefault"}),
                        cols=prev_c.cols | comb.cols,
                        consts=prev_c.consts | comb.consts,
                        fallbacks=prev_c.fallbacks | comb.fallbacks,
                        dynamic=prev_c.dynamic or comb.dynamic,
                    )
                return arg_vals[1] if short == "setdefault" and len(arg_vals) >= 2 else _Val()
            if short in _WHOLE_ROW_SERIALIZERS and node.args:
                a0 = self.eval_expr(node.args[0], env, dead=dead)
                if a0.row and not dead:
                    self.acc.touched_cols.update(self.all_table_cols)
                    return _Val(cols=self.all_table_cols)
            if short in _SESSION_MUTATION_METHODS:
                for a in (*node.args, *(kw.value for kw in node.keywords)):
                    av = self.eval_expr(a, env, dead=dead)
                    if not dead:
                        self.acc.sink_cols.update(av.cols)
                return _Val()
            recv_seed = _Val(
                cols=recv_val.cols,
                consts=recv_val.consts,
                fallbacks=recv_val.fallbacks,
                dynamic=recv_val.dynamic,
            )

        if isinstance(func, ast.Name) and short in _TRANSPARENT_WRAPPERS and node.args:
            return self.eval_expr(node.args[0], env, dead=dead)

        helper = self.helpers.get(short) or self.helpers.get(self.aliases.get(short, ""))
        if helper is not None:
            pos_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
            by_idx: dict[int, _Val] = dict(enumerate(pos_vals))
            for kw in node.keywords:
                kv = self.eval_expr(kw.value, env, dead=dead)
                if kw.arg and kw.arg in helper.param_names:
                    by_idx[helper.param_names.index(kw.arg)] = kv
                elif not dead:
                    self.acc.sink_cols.update(kv.cols)
            out_cols: set[str] = set(helper.returned_cols)
            if not dead and helper.guard_cols:
                self.acc.sink_cols.update(helper.guard_cols)
            ret_row = helper.returns_tid_row
            ret_row_map = helper.returns_tid_row_map
            ret_dyn = False
            for idx, aval in by_idx.items():
                if aval.row:
                    h_cols = helper.param_consumed_attrs.get(idx, frozenset())
                    if not dead:
                        self.acc.touched_cols.update(h_cols)
                        self.acc.sink_cols.update(h_cols)
                    out_cols.update(h_cols)
                    if idx in helper.param_returned_whole:
                        ret_row = True
                    if idx in helper.param_dynamic:
                        ret_dyn = True
                        if not dead:
                            self.acc.any_dynamic = True
                elif aval.cols and not dead:
                    self.acc.sink_cols.update(aval.cols)
                    out_cols.update(aval.cols)
            return _Val(
                row=ret_row,
                row_map=ret_row_map,
                cols=frozenset(out_cols),
                consts=helper.returned_consts if not dead else frozenset(),
                dynamic=ret_dyn and not dead,
            )

        out = recv_seed
        res_dyn = False
        for a in node.args:
            av = self.eval_expr(a, env, dead=dead)
            if not dead:
                self.acc.sink_cols.update(av.cols)
                if av.row and short not in _NON_CONSUMING_ROW_BUILTINS:
                    self.acc.opaque_callees.add(dotted or short or "<call>")
                    res_dyn = True
            out = out.merge(av)
        for kw in node.keywords:
            kv = self.eval_expr(kw.value, env, dead=dead)
            if not dead:
                self.acc.sink_cols.update(kv.cols)
                if kw.arg is None and (kv.row or kv.dynamic):
                    self.acc.any_dynamic = True
                    res_dyn = True
                elif kv.row and short not in _NON_CONSUMING_ROW_BUILTINS:
                    self.acc.opaque_callees.add(dotted or short or "<call>")
                    res_dyn = True
            out = out.merge(kv)
        return _Val(
            cols=out.cols,
            consts=out.consts,
            fallbacks=out.fallbacks,
            dynamic=(out.dynamic or res_dyn) and not dead,
        )

    def run_stmts(
        self,
        stmts: Sequence[ast.stmt],
        env: dict[str, _Val],
        *,
        dead: bool = False,
        null_fallback: bool = False,
                    returned_whole_flag: list[str] | None = None,
    ) -> bool:
        """Execute `stmts`, returning True when control flow unconditionally terminates."""
        terminated = False
        for stmt in stmts:
            if id(stmt) in self.excluded:
                continue
            cur_dead = dead or terminated
            if isinstance(stmt, ast.Return):
                rv = self.eval_expr(stmt.value, env, dead=cur_dead)
                if not cur_dead:
                    if rv.row and returned_whole_flag is not None:
                        returned_whole_flag.append("map" if rv.row_map else "row")
                    if null_fallback:
                        self.acc.fallback_consts.update(rv.consts | rv.fallbacks)
                        self.acc.sink_cols.update(rv.cols)
                        self.acc.return_cols.update(rv.cols)
                        if rv.row:
                            self.acc.sink_cols.update(self.all_table_cols)
                    else:
                        self.acc.primary_return_line = stmt.lineno
                        if rv.row:
                            self.acc.sink_cols.update(self.all_table_cols)
                        self.acc.sink_cols.update(rv.cols)
                        self.acc.return_cols.update(rv.cols)
                        self.acc.return_consts.update(rv.consts)
                        self.acc.fallback_consts.update(rv.fallbacks)
                        if rv.dynamic:
                            self.acc.sink_dynamic = True
                    terminated = True
                continue
            if isinstance(stmt, (ast.Raise, ast.Break, ast.Continue)):
                if isinstance(stmt, ast.Raise):
                    ev = self.eval_expr(stmt.exc, env, dead=cur_dead)
                    if not cur_dead:
                        self.acc.sink_cols.update(ev.cols)
                if not cur_dead:
                    terminated = True
                continue
            if isinstance(stmt, ast.Assert):
                tv = self.eval_expr(stmt.test, env, dead=cur_dead)
                if not cur_dead:
                    self.acc.sink_cols.update(tv.cols)
                continue
            if isinstance(stmt, ast.Expr):
                val_node = stmt.value
                if isinstance(val_node, (ast.Yield, ast.YieldFrom)):
                    yv = self.eval_expr(val_node.value, env, dead=cur_dead)
                    if not cur_dead:
                        if yv.row:
                            self.acc.sink_cols.update(self.all_table_cols)
                        self.acc.sink_cols.update(yv.cols)
                        if null_fallback:
                            self.acc.fallback_consts.update(yv.consts | yv.fallbacks)
                        else:
                            self.acc.return_consts.update(yv.consts)
                            self.acc.fallback_consts.update(yv.fallbacks)
                        if yv.dynamic:
                            self.acc.sink_dynamic = True
                else:
                    self.eval_expr(val_node, env, dead=cur_dead)
                continue
            if isinstance(stmt, ast.Assign):
                val = self.eval_expr(stmt.value, env, dead=cur_dead)
                if not cur_dead:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Attribute):
                            t_recv = self.eval_expr(tgt.value, env, dead=cur_dead)
                            if t_recv.row:
                                self.acc.mutates_row = True
                            self.acc.sink_cols.update(val.cols)
                        else:
                            self._bind_target(tgt, val, env)
                continue
            if isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    val = self.eval_expr(stmt.value, env, dead=cur_dead)
                    if not cur_dead:
                        if isinstance(stmt.target, ast.Attribute):
                            t_recv = self.eval_expr(stmt.target.value, env, dead=cur_dead)
                            if t_recv.row:
                                self.acc.mutates_row = True
                            self.acc.sink_cols.update(val.cols)
                        else:
                            self._bind_target(stmt.target, val, env)
                continue
            if isinstance(stmt, ast.AugAssign):
                val = self.eval_expr(stmt.value, env, dead=cur_dead)
                if not cur_dead:
                    if isinstance(stmt.target, ast.Name):
                        prev = env.get(stmt.target.id, _Val())
                        env[stmt.target.id] = prev.merge(val)
                    else:
                        self.acc.sink_cols.update(val.cols)
                continue
            if isinstance(stmt, ast.If):
                cb = _const_bool(stmt.test, self.const_truth)
                if cb is True:
                    term_t = self.run_stmts(
                        stmt.body, env, dead=cur_dead, null_fallback=null_fallback,
                        returned_whole_flag=returned_whole_flag,
                    )
                    self.run_stmts(stmt.orelse, dict(env), dead=True)
                    if not cur_dead and term_t:
                        terminated = True
                    continue
                if cb is False:
                    self.run_stmts(stmt.body, dict(env), dead=True)
                    term_f = self.run_stmts(
                        stmt.orelse, env, dead=cur_dead, null_fallback=null_fallback,
                        returned_whole_flag=returned_whole_flag,
                    )
                    if not cur_dead and term_f:
                        terminated = True
                    continue
                pol = _null_guard_polarity(stmt.test, env)
                if pol is None:
                    tv = self.eval_expr(stmt.test, env, dead=cur_dead)
                    if not cur_dead:
                        self.acc.sink_cols.update(tv.cols)
                env_b = dict(env)
                env_o = dict(env)
                term_b = self.run_stmts(
                    stmt.body,
                    env_b,
                    dead=cur_dead,
                    null_fallback=null_fallback or (pol == "null_true"),
                    returned_whole_flag=returned_whole_flag,
                )
                term_o = self.run_stmts(
                    stmt.orelse,
                    env_o,
                    dead=cur_dead,
                    null_fallback=null_fallback or (pol == "null_false"),
                    returned_whole_flag=returned_whole_flag,
                )
                if cur_dead:
                    continue
                if term_b and term_o:
                    terminated = True
                elif term_b:
                    env.clear()
                    env.update(env_o)
                    if pol == "null_false":
                        null_fallback = True
                elif term_o:
                    env.clear()
                    env.update(env_b)
                    if pol == "null_true":
                        null_fallback = True
                else:
                    all_k = set(env_b) | set(env_o)
                    for k in all_k:
                        vb = env_b.get(k, _Val())
                        vo = env_o.get(k, _Val())
                        if pol == "null_false" and ((vb.cols & self.policy_cols) or vb.row):
                            env[k] = _Val(
                                row=vb.row or vo.row,
                                cols=vb.cols | vo.cols,
                                consts=vb.consts,
                                fallbacks=vb.fallbacks | vo.consts | vo.fallbacks,
                                dynamic=vb.dynamic or vo.dynamic,
                            )
                        elif pol == "null_true" and ((vo.cols & self.policy_cols) or vo.row):
                            env[k] = _Val(
                                row=vb.row or vo.row,
                                cols=vb.cols | vo.cols,
                                consts=vo.consts,
                                fallbacks=vo.fallbacks | vb.consts | vb.fallbacks,
                                dynamic=vb.dynamic or vo.dynamic,
                            )
                        else:
                            env[k] = vb.merge(vo)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                itv = self.eval_expr(stmt.iter, env, dead=cur_dead)
                loop_env = dict(env)
                if not cur_dead:
                    self._bind_target(stmt.target, itv, loop_env)
                self.run_stmts(stmt.body, loop_env, dead=cur_dead, null_fallback=null_fallback)
                self.run_stmts(stmt.orelse, loop_env, dead=cur_dead, null_fallback=null_fallback)
                if not cur_dead:
                    for k, lv in loop_env.items():
                        env[k] = env[k].merge(lv) if k in env else lv
                continue
            if isinstance(stmt, ast.While):
                cb = _const_bool(stmt.test, self.const_truth)
                if cb is False:
                    self.run_stmts(stmt.body, dict(env), dead=True)
                    self.run_stmts(stmt.orelse, env, dead=cur_dead, null_fallback=null_fallback)
                    continue
                tv = self.eval_expr(stmt.test, env, dead=cur_dead)
                if not cur_dead:
                    self.acc.sink_cols.update(tv.cols)
                loop_env = dict(env)
                self.run_stmts(stmt.body, loop_env, dead=cur_dead, null_fallback=null_fallback)
                if not cur_dead:
                    for k, lv in loop_env.items():
                        env[k] = env[k].merge(lv) if k in env else lv
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    iv = self.eval_expr(item.context_expr, env, dead=cur_dead)
                    if not cur_dead and item.optional_vars is not None:
                        self._bind_target(item.optional_vars, iv, env)
                if self.run_stmts(stmt.body, env, dead=cur_dead, null_fallback=null_fallback):
                    terminated = True
                continue
            if isinstance(stmt, (ast.Try, ast.TryStar)):
                self.run_stmts(stmt.body, env, dead=cur_dead, null_fallback=null_fallback)
                for h in stmt.handlers:
                    h_env = dict(env)
                    self.run_stmts(h.body, h_env, dead=cur_dead, null_fallback=null_fallback)
                    if not cur_dead:
                        for k, hv in h_env.items():
                            env[k] = env[k].merge(hv) if k in env else hv
                self.run_stmts(stmt.orelse, env, dead=cur_dead, null_fallback=null_fallback)
                self.run_stmts(stmt.finalbody, env, dead=cur_dead, null_fallback=null_fallback)
        return terminated


def _excluded_type_checking_ids(tree: ast.AST) -> set[int]:
    excluded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            dotted = _dotted_expr(node.test)
            if dotted in {"TYPE_CHECKING", "typing.TYPE_CHECKING"}:
                for sub in node.body:
                    excluded.update(id(c) for c in ast.walk(sub))
    return excluded


def _collect_module_context(
    tree: ast.Module,
    excluded: set[int],
    active_tokens: Sequence[str],
    declared_policy_consts: Sequence[str],
) -> tuple[
    dict[str, tuple[int, list[ast.stmt], tuple[str, ...]]],
    list[ast.stmt],
    dict[str, str],
    frozenset[str],
    dict[str, bool],
]:
    scopes: dict[str, tuple[int, list[ast.stmt], tuple[str, ...]]] = {}
    top_stmts: list[ast.stmt] = []
    aliases: dict[str, str] = {}
    policy_consts: set[str] = set(declared_policy_consts)
    const_truth: dict[str, bool] = {}

    for node in ast.walk(tree):
        if id(node) in excluded:
            continue
        if isinstance(node, ast.ImportFrom):
            for al in node.names:
                lname = al.asname or al.name
                aliases[lname] = al.name
                if is_policy_constant_symbol(lname, active_tokens) or is_policy_constant_symbol(
                    al.name, active_tokens
                ):
                    policy_consts.add(lname)
        elif isinstance(node, ast.Import):
            for al in node.names:
                if al.asname:
                    aliases[al.asname] = al.name

    for stmt in tree.body:
        if id(stmt) in excluded:
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pnames = tuple(a.arg for a in (*stmt.args.posonlyargs, *stmt.args.args))
            scopes[stmt.name] = (stmt.lineno, stmt.body, pnames)
        elif isinstance(stmt, ast.ClassDef):
            scopes[stmt.name] = (stmt.lineno, stmt.body, ())
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    raw_p = [a.arg for a in (*member.args.posonlyargs, *member.args.args)]
                    if raw_p and raw_p[0] in {"self", "cls"}:
                        raw_p = raw_p[1:]
                    scopes[member.name] = (member.lineno, member.body, tuple(raw_p))
        else:
            top_stmts.append(stmt)
            t_name: str | None = None
            t_val: ast.AST | None = None
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                t_name, t_val = stmt.targets[0].id, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                t_name, t_val = stmt.target.id, stmt.value
            if t_name and t_val is not None:
                if is_policy_constant_symbol(t_name, active_tokens):
                    policy_consts.add(t_name)
                cb = _const_bool(t_val)
                if cb is not None and t_name.isupper():
                    const_truth[t_name] = cb

    return scopes, top_stmts, aliases, frozenset(policy_consts), const_truth


def _build_helper_summaries(
    scopes: dict[str, tuple[int, list[ast.stmt], tuple[str, ...]]],
    *,
    all_table_cols: frozenset[str],
    policy_cols: frozenset[str],
    model_symbols: frozenset[str],
    sql_table_names: set[str],
    policy_consts: frozenset[str],
    const_truth: dict[str, bool],
    aliases: dict[str, str],
    excluded: set[int],
) -> dict[str, _HelperSummary]:
    summaries: dict[str, _HelperSummary] = {}
    for fn_name, (_lineno, body, pnames) in scopes.items():
        consumed_by_param: dict[int, frozenset[str]] = {}
        returned_whole: set[int] = set()
        dyn_params: set[int] = set()
        for idx, pname in enumerate(pnames):
            runner = _FlowRunner(
                all_table_cols=all_table_cols,
                policy_cols=policy_cols,
                model_symbols=frozenset(),
                sql_table_names=set(),
                policy_consts=policy_consts,
                const_truth=const_truth,
                aliases=aliases,
                helpers={},
                excluded=excluded,
            )
            whole_flag: list[str] = []
            runner.run_stmts(body, {pname: _Val(row=True)}, returned_whole_flag=whole_flag)
            if whole_flag:
                returned_whole.add(idx)
                consumed_by_param[idx] = frozenset(runner.acc.touched_cols)
            elif runner.acc.sink_cols:
                consumed_by_param[idx] = frozenset(runner.acc.sink_cols)
            if runner.acc.any_dynamic or runner.acc.opaque_callees:
                dyn_params.add(idx)

        base_runner = _FlowRunner(
            all_table_cols=all_table_cols,
            policy_cols=policy_cols,
            model_symbols=model_symbols,
            sql_table_names=sql_table_names,
            policy_consts=policy_consts,
            const_truth=const_truth,
            aliases=aliases,
            helpers={},
            excluded=excluded,
        )
        ret_tid_whole: list[str] = []
        base_runner.run_stmts(body, {}, returned_whole_flag=ret_tid_whole)
        ret_cols = frozenset(base_runner.acc.return_cols)
        summaries[fn_name] = _HelperSummary(
            param_names=pnames,
            param_consumed_attrs=consumed_by_param,
            param_returned_whole=frozenset(returned_whole),
            param_dynamic=frozenset(dyn_params),
            returned_cols=ret_cols,
            guard_cols=frozenset(base_runner.acc.sink_cols - ret_cols),
            returned_consts=frozenset(base_runner.acc.return_consts),
            returns_tid_row=bool(ret_tid_whole),
            returns_tid_row_map=("map" in ret_tid_whole),
            has_direct_query=(base_runner.acc.first_query_line > 0),
        )
    return summaries


def analyze_module_policy_table_read(
    source: str,
    *,
    table_label: str,
    table_columns: Sequence[str],
    policy_columns: Sequence[str],
    active_scopes: Sequence[str],
    write_scopes: set[str],
    func_calls: dict[str, frozenset[str]],
    model_symbols: set[str],
    sql_table_names: set[str],
    declared_policy_consts: Sequence[str] = (),
    active_tokens: Sequence[str] | None = None,
) -> list[ScopePolicyReadAnalysis]:
    """Analyze per-scope policy column consumption for one `(module, policy_table)` pair."""
    if not policy_columns:
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    tokens = tuple(active_tokens) if active_tokens is not None else get_active_policy_tokens()
    excluded = _excluded_type_checking_ids(tree)
    scopes, top_stmts, aliases, policy_consts, const_truth = _collect_module_context(
        tree, excluded, tokens, declared_policy_consts
    )
    all_cols_set = frozenset(table_columns) | frozenset(policy_columns)
    policy_col_set = frozenset(policy_columns)
    norm_sql_names = {s.rpartition(".")[2].lower() or s.lower() for s in sql_table_names}
    norm_sql_names.add(table_label.rpartition(".")[2].lower() or table_label.lower())

    helpers = _build_helper_summaries(
        scopes,
        all_table_cols=all_cols_set,
        policy_cols=policy_col_set,
        model_symbols=frozenset(model_symbols),
        sql_table_names=norm_sql_names,
        policy_consts=policy_consts,
        const_truth=const_truth,
        aliases=aliases,
        excluded=excluded,
    )

    active_set = set(active_scopes) or {"*"}
    internal_loaders_with_caller = {
        sc
        for sc in active_set
        if sc in helpers
        and helpers[sc].returns_tid_row
        and any(sc in func_calls.get(other, ()) for other in (active_set - {sc}))
    }
    target_scopes = sorted(active_set - internal_loaders_with_caller) or sorted(active_set)

    results: list[ScopePolicyReadAnalysis] = []
    for sc in target_scopes:
        if sc == "*":
            sc_line = 1
            body = top_stmts
        elif sc in scopes:
            sc_line, body, _ = scopes[sc]
        else:
            continue

        runner = _FlowRunner(
            all_table_cols=all_cols_set,
            policy_cols=policy_col_set,
            model_symbols=frozenset(model_symbols),
            sql_table_names=norm_sql_names,
            policy_consts=policy_consts,
            const_truth=const_truth,
            aliases=aliases,
            helpers=helpers,
            excluded=excluded,
        )
        runner.run_stmts(body, {})
        acc = runner.acc
        known_cols = set(table_columns) | set(policy_columns)
        consumed_cols = sorted(acc.sink_cols & known_cols) if known_cols else sorted(acc.sink_cols)
        consumed_pol = acc.sink_cols & policy_col_set
        unconsumed_pol = sorted(policy_col_set - consumed_pol)
        raw_return_consts = sorted(acc.return_consts)
        subst_consts = raw_return_consts if unconsumed_pol else []
        fb_consts = sorted(acc.fallback_consts - set(subst_consts))
        dead_pol = bool(acc.dead_cols & policy_col_set)
        ev_line = acc.primary_return_line or acc.first_query_line or sc_line
        called_direct_helpers = [
            cal
            for cal in func_calls.get(sc, ())
            if cal != sc and cal in target_scopes and cal in helpers and helpers[cal].has_direct_query
        ]
        if (
            acc.first_query_line == 0
            and called_direct_helpers
            and all(
                not helpers[cal].returns_tid_row
                and not (helpers[cal].returned_cols & policy_col_set)
                and not (helpers[cal].guard_cols & policy_col_set)
                for cal in called_direct_helpers
            )
        ):
            continue
        is_w_lookup = (
            ((sc in write_scopes) or acc.mutates_row)
            and not consumed_pol
            and not raw_return_consts
        )

        state: PolicyConsumptionState
        mech: PolicyConsumptionMechanism
        if is_w_lookup:
            state = "consumed"
            mech = "field_controls_result"
            note = f"`{sc}()` reads `{table_label}` keys/rows for an audited write/upsert path."
        elif subst_consts and unconsumed_pol:
            state = "bypassed"
            mech = "constant_or_fallback_wins"
            note = (
                f"`{sc}()` leaves policy column(s) {', '.join(f'`{c}`' for c in unconsumed_pol)} "
                f"unconsumed and substitutes {', '.join(f'`{k}`' for k in subst_consts)}."
            )
        elif consumed_pol:
            state = "consumed"
            mech = "field_controls_result"
            fb_tag = (
                f" (with null/falsy fallback {', '.join(f'`{k}`' for k in fb_consts)})"
                if fb_consts
                else ""
            )
            note = (
                f"`{sc}()` flows policy column(s) "
                f"{', '.join(f'`{c}`' for c in sorted(consumed_pol))} into result/guard{fb_tag}."
            )
        elif acc.sink_dynamic or acc.any_dynamic or acc.opaque_callees:
            state = "unresolved"
            mech = "dynamic_or_opaque_flow"
            via = (
                f"opaque handoff to {', '.join(f'`{c}()`' for c in sorted(acc.opaque_callees))}"
                if acc.opaque_callees
                else "dynamic attribute/mapping lookup"
            )
            note = f"`{sc}()` accesses `{table_label}` via {via}; field selection is unresolved statically."
        else:
            state = "bypassed"
            mech = "constant_or_fallback_wins"
            dead_tag = " (policy column referenced only in dead code)" if dead_pol else ""
            note = (
                f"`{sc}()` queries `{table_label}` without flowing policy column(s) "
                f"{', '.join(f'`{c}`' for c in unconsumed_pol)} into any live result or guard{dead_tag}."
            )

        results.append(
            ScopePolicyReadAnalysis(
                scope_name=sc,
                lineno=ev_line,
                state=state,
                mechanism=mech,
                is_write_lookup=is_w_lookup,
                policy_columns=tuple(policy_columns),
                consumed_columns=tuple(consumed_cols),
                unconsumed_policy_columns=tuple(unconsumed_pol),
                substituted_constants=tuple(subst_consts),
                fallback_constants=tuple(fb_consts),
                opaque_callees=tuple(sorted(acc.opaque_callees)),
                had_dead_policy_access=dead_pol,
                note=note,
            )
        )
    return results


def summarize_edge_policy_consumption(
    table_label: str,
    policy_columns: Sequence[str],
    scope_analyses: Sequence[ScopePolicyReadAnalysis],
) -> tuple[PolicyFieldConsumption, str] | None:
    """Aggregate scope-level analyses onto a `reads_truth` edge `(consumption, evidence_note)`."""
    if not policy_columns or not scope_analyses:
        return None
    states = {sa.state for sa in scope_analyses}
    state: PolicyConsumptionState
    mech: PolicyConsumptionMechanism
    if "bypassed" in states:
        state = "bypassed"
        mech = "constant_or_fallback_wins"
    elif "consumed" in states:
        state = "consumed"
        mech = "field_controls_result"
    else:
        state = "unresolved"
        mech = "dynamic_or_opaque_flow"

    consumed_cols = sorted({c for sa in scope_analyses for c in sa.consumed_columns})
    consumed_pol = {c for c in consumed_cols if c in set(policy_columns)}
    if state == "bypassed":
        bypassing = [sa for sa in scope_analyses if sa.state == "bypassed"]
        unconsumed_pol = sorted({c for sa in bypassing for c in sa.unconsumed_policy_columns})
    else:
        unconsumed_pol = sorted(set(policy_columns) - consumed_pol)
    subst_consts = sorted(
        {k for sa in scope_analyses if sa.state == "bypassed" for k in sa.substituted_constants}
    )
    fb_consts = sorted({k for sa in scope_analyses for k in sa.fallback_constants})
    scopes = [sa.scope_name for sa in scope_analyses]
    note = " ".join(sa.note for sa in scope_analyses)

    pfc = PolicyFieldConsumption(
        state=state,
        mechanism=mech,
        reader_scopes=scopes,
        policy_columns=list(policy_columns),
        consumed_columns=consumed_cols,
        unconsumed_policy_columns=unconsumed_pol,
        substituted_constants=subst_consts,
        fallback_constants=fb_consts,
        note=note,
    )
    ev_note = f"AST verified read of `{table_label}` (policy_field_consumption={state}: {note})"
    return pfc, ev_note


def merge_policy_consumptions(
    items: Sequence[PolicyFieldConsumption],
) -> PolicyFieldConsumption | None:
    """Aggregate multiple edge `PolicyFieldConsumption` records onto a table or service node."""
    if not items:
        return None
    if len(items) == 1:
        return items[0]
    states = {it.state for it in items}
    state: PolicyConsumptionState
    mech: PolicyConsumptionMechanism
    if "bypassed" in states:
        state = "bypassed"
        mech = "constant_or_fallback_wins"
    elif "consumed" in states:
        state = "consumed"
        mech = "field_controls_result"
    else:
        state = "unresolved"
        mech = "dynamic_or_opaque_flow"
    pol_cols = list(dict.fromkeys(c for it in items for c in it.policy_columns))
    cons_cols = sorted({c for it in items for c in it.consumed_columns})
    uncons = (
        sorted({c for it in items if it.state == "bypassed" for c in it.unconsumed_policy_columns})
        if state == "bypassed"
        else sorted(set(pol_cols) - set(cons_cols))
    )
    return PolicyFieldConsumption(
        state=state,
        mechanism=mech,
        reader_scopes=list(dict.fromkeys(s for it in items for s in it.reader_scopes)),
        policy_columns=pol_cols,
        consumed_columns=cons_cols,
        unconsumed_policy_columns=uncons,
        substituted_constants=sorted(
            {k for it in items if it.state == "bypassed" for k in it.substituted_constants}
        ),
        fallback_constants=sorted({k for it in items for k in it.fallback_constants}),
        note=" ".join(it.note for it in items if it.note)[:480],
    )
