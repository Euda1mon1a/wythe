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
        "fetchone",
        "fetchall",
        "fetchmany",
        "partitions",
        "unique",
        "where",
        "filter",
        "filter_by",
        "order_by",
        "limit",
        "offset",
        "options",
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
    {"list", "tuple", "set", "frozenset", "iter", "reversed", "sorted", "next", "text", "aliased"}
)
_WHOLE_ROW_SERIALIZERS = frozenset({"model_validate", "from_orm", "asdict"})
_TELEMETRY_RECEIVERS = frozenset({"logger", "log", "logging"})
_TELEMETRY_FUNCS = frozenset({"print"})
_STRUCTURAL_TABLE_COLS = frozenset(
    {
        "id",
        "uuid",
        "guid",
        "pk",
        "rowid",
        "oid",
        "created_at",
        "updated_at",
        "deleted_at",
        "created_by",
        "updated_by",
        "version",
    }
)
_GENERIC_POLICY_MODIFIER_STEMS = frozenset(
    {
        "MAX",
        "MAXIMUM",
        "MIN",
        "MINIMUM",
        "LIMIT",
        "LIMITS",
        "CAP",
        "CAPS",
        "DEFAULT",
        "DEFAULTS",
        "FALLBACK",
        "OVERRIDE",
        "THRESHOLD",
        "THRESHOLDS",
        "VALUE",
        "VALUES",
        "ALLOWED",
        "ENABLED",
        "IS",
        "PER",
        "BY",
        "FOR",
        "IN",
        "OF",
        "TO",
        "HARD",
        "SOFT",
        "GLOBAL",
        "LOCAL",
        "BASE",
        "EXTRA",
    }
)


def _is_structural_col(col: str) -> bool:
    low = col.strip().lower()
    return low in _STRUCTURAL_TABLE_COLS or low.endswith(("_id", "_uuid", "_guid", "_pk", "_fk"))


def _singular_stem(part: str) -> str:
    if len(part) > 4 and part.endswith("IES"):
        return part[:-3] + "Y"
    if len(part) > 3 and part.endswith("ES") and part[:-2].endswith(("SH", "CH", "X", "Z", "S")):
        return part[:-2]
    if len(part) > 3 and part.endswith("S") and not part.endswith("SS"):
        return part[:-1]
    return part


def _meaningful_domain_stems(raw_name: str) -> frozenset[str]:
    norm = _normalize_ident_upper(raw_name)
    if not norm:
        return frozenset()
    return frozenset(
        _singular_stem(p)
        for p in norm.split("_")
        if p and p not in _GENERIC_POLICY_MODIFIER_STEMS and not p.isdigit()
    )


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


_ALGORITHMIC_OR_PROTOCOL_PREFIXES = (
    "SECONDS_PER_",
    "MINUTES_PER_",
    "HOURS_PER_",
    "DAYS_PER_",
    "MS_PER_",
    "US_PER_",
    "NS_PER_",
    "BYTES_PER_",
    "BITS_PER_",
    "KIB_",
    "MIB_",
    "GIB_",
    "TIB_",
    "HTTP_",
    "HTTPS_",
    "GRPC_",
    "TCP_",
    "UDP_",
    "TLS_",
    "SSL_",
    "IPV4_",
    "IPV6_",
    "UTF8_",
    "ASCII_",
    "SHA256_",
    "BASE64_",
)
_ALGORITHMIC_OR_PROTOCOL_EXACT = frozenset(
    {"EPSILON", "RADIX", "PI", "TAU", "INF", "NAN", "MIB_BYTES", "KIB_BYTES", "GIB_BYTES"}
)
_UNIT_BYTE_STEMS = frozenset({"KIB", "MIB", "GIB", "TIB", "KB", "MB", "GB", "TB"})


def is_algorithmic_or_protocol_constant(name: str) -> bool:
    """True when `name` denotes a unit conversion, wire protocol, or math/algorithmic constant."""
    stripped = name.lstrip("_").upper()
    if not stripped:
        return False
    if stripped in _ALGORITHMIC_OR_PROTOCOL_EXACT or stripped.startswith(
        _ALGORITHMIC_OR_PROTOCOL_PREFIXES
    ):
        return True
    parts = stripped.split("_")
    if "PER" in parts and (
        set(parts)
        & {"SECOND", "SECONDS", "MINUTE", "MINUTES", "HOUR", "HOURS", "DAY", "DAYS", "BYTE", "BYTES", "BIT", "BITS", "MS", "NS"}
    ):
        return True
    return parts[-1] == "BYTES" and bool(set(parts[:-1]) & _UNIT_BYTE_STEMS)


def is_policy_constant_symbol(name: str, active_tokens: Sequence[str] | None = None) -> bool:
    """True when `name` is an uppercase constant identifier carrying policy/limit semantics."""
    stripped = name.lstrip("_")
    if (
        not stripped
        or not stripped.isupper()
        or stripped in {"TRUE", "FALSE", "NONE", "SQL"}
        or is_algorithmic_or_protocol_constant(stripped)
    ):
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
    col_ns: bool = False
    existence_only: bool = False
    from_query: bool = False
    cols: frozenset[str] = frozenset()
    tuple_cols: tuple[str, ...] = ()
    tuple_items: tuple[_Val, ...] = ()
    dict_items: tuple[tuple[str, _Val], ...] = ()
    consts: frozenset[str] = frozenset()
    num_lits: frozenset[str] = frozenset()
    fallbacks: frozenset[str] = frozenset()
    zero_clobbers: frozenset[tuple[str, str]] = frozenset()
    overwrite_line: int = 0
    overwritten_cols: frozenset[str] = frozenset()
    dynamic: bool = False

    def merge(self, other: _Val, *, keep_num_lits: bool = True) -> _Val:
        return _Val(
            row=self.row or other.row,
            row_map=self.row_map or other.row_map,
            col_ns=self.col_ns or other.col_ns,
            existence_only=self.existence_only or other.existence_only,
            from_query=self.from_query or other.from_query,
            cols=self.cols | other.cols,
            consts=self.consts | other.consts,
            num_lits=(self.num_lits | other.num_lits) if keep_num_lits else frozenset(),
            fallbacks=self.fallbacks | other.fallbacks,
            zero_clobbers=self.zero_clobbers | other.zero_clobbers,
            overwrite_line=other.overwrite_line or self.overwrite_line,
            overwritten_cols=self.overwritten_cols | other.overwritten_cols,
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


_SQL_ALIAS_SKIP_WORDS = frozenset(
    {
        "where",
        "join",
        "left",
        "right",
        "inner",
        "outer",
        "full",
        "cross",
        "natural",
        "on",
        "using",
        "limit",
        "offset",
        "order",
        "group",
        "having",
        "union",
        "intersect",
        "except",
        "for",
        "window",
        "fetch",
        "as",
    }
)
_SQL_FROM_OR_JOIN_RE = re.compile(
    r"\b(?:FROM|JOIN)\s+(?:ONLY\s+)?"
    r'(?:["`\[]?[A-Za-z_][A-Za-z0-9_]*["`\]]?\.)?["`\[]?(?P<tbl>[A-Za-z_][A-Za-z0-9_]*)["`\]]?'
    r'(?:\s+AS\s+["`\[]?(?P<alias1>[A-Za-z_][A-Za-z0-9_]*)["`\]]?|\s+["`\[]?(?P<alias2>[A-Za-z_][A-Za-z0-9_]*)["`\]]?)?',
    re.IGNORECASE,
)
_SQL_SELECT_CLAUSE_RE = re.compile(
    r"\bSELECT\s+(?:DISTINCT\s+(?:ON\s*\([^)]*\)\s+)?)?(?P<proj>.+?)\s+FROM\b",
    re.IGNORECASE | re.DOTALL,
)
_SQL_QUAL_COL_RE = re.compile(
    r'["`\[]?(?P<qual>[A-Za-z_][A-Za-z0-9_]*)["`\]]?\s*\.\s*["`\[]?(?P<col>[A-Za-z_][A-Za-z0-9_]*|\*)["`\]]?'
)
_DOLLAR_QUOTE_TAG_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
_SUBQUERY_HEAD_RE = re.compile(r"^\s*(?:SELECT|WITH)\b", re.IGNORECASE)
_SUBQUERY_PLACEHOLDER = "__wythe_subquery__"


def _strip_sql_literals_and_comments(sql_text: str) -> str:
    """Strip SQL string literals (`'...'`, `$tag$...$tag$`) and comments (`--`, `/* */`),
    preserving quoted identifiers (`"col"`, `` `col` ``, `[col]`)."""
    out: list[str] = []
    i = 0
    n = len(sql_text)
    while i < n:
        ch = sql_text[i]
        nxt = sql_text[i + 1] if i + 1 < n else ""
        if ch == "-" and nxt == "-":
            i += 2
            while i < n and sql_text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if sql_text[i] == "/" and i + 1 < n and sql_text[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif sql_text[i] == "*" and i + 1 < n and sql_text[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if sql_text[i] == "\n" else " ")
                    i += 1
            continue
        if ch in ('"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = sql_text[i]
                out.append(c)
                i += 1
                if c == quote:
                    if i < n and sql_text[i] == quote:
                        out.append(sql_text[i])
                        i += 1
                    else:
                        break
            continue
        if ch == "[":
            out.append(ch)
            i += 1
            while i < n:
                c = sql_text[i]
                out.append(c)
                i += 1
                if c in ("]", "\n"):
                    break
            continue
        if (
            ch in "EeNnXxBb"
            and nxt == "'"
            and (i == 0 or not (sql_text[i - 1].isalnum() or sql_text[i - 1] == "_"))
        ):
            i += 1
            ch = "'"
        if ch == "'":
            newlines = 0
            i += 1
            while i < n:
                c = sql_text[i]
                if c == "\n":
                    newlines += 1
                if c == "\\":
                    if i + 1 < n and sql_text[i + 1] == "\n":
                        newlines += 1
                    i += 2
                    continue
                if c == "'":
                    if i + 1 < n and sql_text[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append("''" + ("\n" * newlines))
            continue
        if ch == "$":
            dm = _DOLLAR_QUOTE_TAG_RE.match(sql_text, i)
            if dm is not None:
                tag = dm.group(0)
                end_idx = sql_text.find(tag, dm.end())
                span_end = n if end_idx < 0 else end_idx + len(tag)
                newlines = sql_text.count("\n", i, span_end)
                out.append("''" + ("\n" * newlines))
                i = span_end
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _decompose_sql_query_blocks(cleaned_sql: str) -> list[str]:
    """Split nested `(SELECT ...)` subqueries into isolated query blocks."""
    sub_blocks: list[str] = []
    outer_chars: list[str] = []
    i = 0
    n = len(cleaned_sql)
    quote: str | None = None
    while i < n:
        ch = cleaned_sql[i]
        if quote:
            outer_chars.append(ch)
            if (quote == "[" and ch == "]") or (quote != "[" and ch == quote):
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`", "["):
            quote = ch
            outer_chars.append(ch)
            i += 1
            continue
        if ch == "(":
            depth = 1
            j = i + 1
            inner_q: str | None = None
            while j < n and depth > 0:
                cj = cleaned_sql[j]
                if inner_q:
                    if (inner_q == "[" and cj == "]") or (inner_q != "[" and cj == inner_q):
                        inner_q = None
                elif cj in ("'", '"', "`", "["):
                    inner_q = cj
                elif cj == "(":
                    depth += 1
                elif cj == ")":
                    depth -= 1
                j += 1
            if depth == 0:
                inner_txt = cleaned_sql[i + 1 : j - 1]
                if _SUBQUERY_HEAD_RE.match(inner_txt):
                    sub_blocks.extend(_decompose_sql_query_blocks(inner_txt))
                    outer_chars.append(f"({_SUBQUERY_PLACEHOLDER})")
                    i = j
                    continue
        outer_chars.append(ch)
        i += 1
    outer_sql = "".join(outer_chars)
    branches = re.split(
        r"\b(?:UNION(?:\s+ALL|\s+DISTINCT)?|INTERSECT|EXCEPT)\b",
        outer_sql,
        flags=re.IGNORECASE,
    )
    return [b for b in branches if b.strip()] + sub_blocks


def _split_top_level_sql_commas(proj: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    quote: str | None = None
    for ch in proj:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")" and depth > 0:
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _sql_projection_for_table(
    sql_text: str,
    sql_table_names: set[str],
    all_table_cols: frozenset[str] = frozenset(),
) -> _Val | None:
    """Extract projected columns for `SELECT <proj> FROM/JOIN <tbl>` when `<tbl>` matches target."""
    cleaned_sql = _strip_sql_literals_and_comments(sql_text)
    known_lower = {c.lower(): c for c in all_table_cols}
    matched_vals: list[_Val] = []

    for block in _decompose_sql_query_blocks(cleaned_sql):
        from_hits = list(_SQL_FROM_OR_JOIN_RE.finditer(block))
        subq_from_count = len(
            re.findall(
                rf"\b(?:FROM|JOIN)\s*\(\s*{_SUBQUERY_PLACEHOLDER}\s*\)",
                block,
                flags=re.IGNORECASE,
            )
        )
        if not from_hits:
            continue
        target_quals: set[str] = set()
        total_tables = subq_from_count
        for fh in from_hits:
            tbl = fh.group("tbl").lower()
            total_tables += 1
            if tbl not in sql_table_names:
                continue
            target_quals.add(tbl)
            raw_al = fh.group("alias1") or fh.group("alias2")
            if raw_al and raw_al.lower() not in _SQL_ALIAS_SKIP_WORDS:
                target_quals.add(raw_al.lower())
        if not target_quals:
            continue

        for match in _SQL_SELECT_CLAUSE_RE.finditer(block):
            proj = match.group("proj").strip()
            if proj == "*":
                return _Val(row=True, from_query=True)
            cols: list[str] = []
            slots: list[str] = []
            saw_agg_or_const = False
            for raw_part in _split_top_level_sql_commas(proj):
                seg = raw_part.strip()
                seg = re.split(r"\s+AS\s+", seg, maxsplit=1, flags=re.IGNORECASE)[0].strip()
                if ")" not in seg and not seg.startswith("'"):
                    seg = seg.split()[0] if seg else ""
                if seg == "*" or any(seg.lower() == f"{q}.*" for q in target_quals):
                    return _Val(row=True, from_query=True)
                upper_seg = seg.upper()
                if (
                    upper_seg.startswith(("COUNT(", "EXISTS("))
                    or seg.isdigit()
                    or upper_seg in {"TRUE", "FALSE", "NULL"}
                    or (seg.startswith("'") and seg.endswith("'"))
                ):
                    saw_agg_or_const = True
                    slots.append("")
                    continue
                if "(" in seg:
                    expr_cols: list[str] = []
                    for qm in _SQL_QUAL_COL_RE.finditer(seg):
                        q_low = qm.group("qual").lower()
                        c_raw = qm.group("col")
                        if q_low in target_quals:
                            if c_raw == "*":
                                return _Val(row=True, from_query=True)
                            if c_raw.isidentifier():
                                expr_cols.append(known_lower.get(c_raw.lower(), c_raw))
                    if not expr_cols and total_tables == 1 and known_lower:
                        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", seg):
                            if tok != _SUBQUERY_PLACEHOLDER and tok.lower() in known_lower:
                                expr_cols.append(known_lower[tok.lower()])
                    if expr_cols:
                        cols.extend(expr_cols)
                        slots.append(expr_cols[0])
                    else:
                        saw_agg_or_const = True
                        slots.append("")
                    continue
                qual_part, dot, col_part = seg.rpartition(".")
                qual_clean = qual_part.strip('"`[]').lower()
                col = col_part.strip('"`[]')
                if dot:
                    if qual_clean not in target_quals:
                        slots.append("")
                        continue
                    if col == "*":
                        return _Val(row=True, from_query=True)
                if col.isidentifier() and col != _SUBQUERY_PLACEHOLDER and (
                    dot or total_tables == 1 or col.lower() in known_lower
                ):
                    canon = known_lower.get(col.lower(), col)
                    cols.append(canon)
                    slots.append(canon)
                else:
                    if not re.search(r"[A-Za-z_]", seg):
                        saw_agg_or_const = True
                    slots.append("")
            if cols:
                matched_vals.append(_Val(cols=frozenset(cols), tuple_cols=tuple(slots), from_query=True))
            elif saw_agg_or_const or total_tables > 1:
                matched_vals.append(_Val(existence_only=True, from_query=True))
            else:
                matched_vals.append(_Val(dynamic=True, from_query=True))

    if not matched_vals:
        return None
    cur = matched_vals[0]
    for nxt in matched_vals[1:]:
        cur = cur.merge(nxt)
    return cur


def _null_guard_polarity(
    test: ast.AST,
    env: dict[str, _Val],
    policy_cols: frozenset[str] = frozenset(),
) -> str | None:
    """Return `'null_true'` when `test` holds on None/invalid value, `'null_false'` when present."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        op = test.ops[0]
        comp = test.comparators[0]
        if isinstance(comp, ast.Constant) and comp.value is None:
            if isinstance(op, (ast.Is, ast.Eq)):
                return "null_true"
            if isinstance(op, (ast.IsNot, ast.NotEq)):
                return "null_false"
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Name)
        and test.func.id == "isinstance"
        and len(test.args) >= 2
        and isinstance(test.args[0], ast.Name)
        and test.args[0].id in env
        and (env[test.args[0].id].row or env[test.args[0].id].cols)
    ):
        return "null_false"
    if isinstance(test, ast.Name) and test.id in env:
        ev = env[test.id]
        if (ev.row and not ev.cols) or (ev.cols and not (ev.cols & policy_cols)):
            return "null_false"
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _null_guard_polarity(test.operand, env, policy_cols)
        if inner == "null_false":
            return "null_true"
        if inner == "null_true":
            return "null_false"
    if isinstance(test, ast.BoolOp):
        subs = [_null_guard_polarity(v, env, policy_cols) for v in test.values]
        if isinstance(test.op, ast.And) and any(s == "null_false" for s in subs) and "null_true" not in subs:
            return "null_false"
        if isinstance(test.op, ast.Or) and any(s == "null_true" for s in subs) and "null_false" not in subs:
            return "null_true"
    return None


@dataclass
class _ScopeAccum:
    sink_cols: set[str] = field(default_factory=set)
    return_cols: set[str] = field(default_factory=set)
    touched_cols: set[str] = field(default_factory=set)
    dead_cols: set[str] = field(default_factory=set)
    return_consts: set[str] = field(default_factory=set)
    sink_consts: set[str] = field(default_factory=set)
    enforced_num_consts: set[str] = field(default_factory=set)
    explicit_pol_overrides: set[str] = field(default_factory=set)
    overwritten_consts: set[str] = field(default_factory=set)
    overwritten_pol_cols: set[str] = field(default_factory=set)
    overwritten_vars: list[tuple[str, tuple[str, ...], tuple[str, ...], int]] = field(
        default_factory=list
    )
    fallback_consts: set[str] = field(default_factory=set)
    zero_clobbers: set[tuple[str, str]] = field(default_factory=set)
    opaque_callees: set[str] = field(default_factory=set)
    sink_dynamic: bool = False
    any_dynamic: bool = False
    mutates_row: bool = False
    saw_existence_query: bool = False
    primary_return_line: int = 0
    first_query_line: int = 0
    first_helper_call_line: int = 0
    causal_overwrite_line: int = 0
    causal_enforcement_line: int = 0


_SESSION_MUTATION_METHODS = frozenset(
    {"add", "add_all", "delete", "merge", "refresh", "expunge", "flush", "commit"}
)
_NON_CONSUMING_ROW_BUILTINS = frozenset(
    {"len", "bool", "isinstance", "id", "type", "repr", "str", "enumerate", "zip"}
)
_TRIVIAL_NUM_LITS = frozenset({"0", "1", "-1", "0.0", "1.0", "-1.0"})
_NON_POLICY_COUNTER_SUFFIXES = (
    "_COUNT",
    "_COUNTS",
    "_TOTAL",
    "_INDEX",
    "_IDX",
    "_OFFSET",
    "_PAGE",
    "_SIZE",
)


class _FlowRunner:
    """AST abstract interpreter tracking policy-column flow, overwrites, and dead branches."""

    def __init__(
        self,
        *,
        all_table_cols: frozenset[str],
        policy_cols: frozenset[str],
        is_pure_policy_schema: bool = False,
        model_symbols: frozenset[str],
        sql_table_names: set[str],
        policy_consts: frozenset[str],
        const_truth: dict[str, bool],
        aliases: dict[str, str],
        helpers: dict[str, _HelperSummary],
        local_data_classes: frozenset[str] = frozenset(),
        excluded: set[int],
    ) -> None:
        self.all_table_cols = all_table_cols
        self.policy_cols = policy_cols
        self.is_pure_policy_schema = is_pure_policy_schema
        self.policy_domain_stems = frozenset().union(
            *(_meaningful_domain_stems(c) for c in policy_cols)
        )
        self.model_symbols = model_symbols
        self.sql_table_names = sql_table_names
        self.policy_consts = policy_consts
        self.const_truth = const_truth
        self.aliases = aliases
        self.helpers = helpers
        self.local_data_classes = local_data_classes
        self.excluded = excluded
        self.acc = _ScopeAccum()

    def _note_query(self, node: ast.AST) -> None:
        lineno = getattr(node, "lineno", 0)
        if lineno and (self.acc.first_query_line == 0 or lineno < self.acc.first_query_line):
            self.acc.first_query_line = lineno

    def _note_enforcement(self, lineno: int) -> None:
        if lineno and self.acc.causal_enforcement_line == 0:
            self.acc.causal_enforcement_line = lineno

    def _consume_sink_val(self, val: _Val, *, lineno: int = 0) -> None:
        self.acc.sink_cols.update(val.cols)
        self.acc.fallback_consts.update(val.fallbacks)
        self.acc.zero_clobbers.update(val.zero_clobbers)
        self.acc.sink_consts.update(val.consts)
        if val.overwrite_line:
            self.acc.causal_overwrite_line = val.overwrite_line
        elif (val.consts or val.num_lits) and lineno:
            self._note_enforcement(lineno)
        if val.dynamic:
            self.acc.sink_dynamic = True

    def _is_policy_like_key(self, raw_name: str) -> bool:
        norm = _normalize_ident_upper(raw_name)
        if (
            not norm
            or norm in _IDENTITY_OR_AUDIT_EXACT
            or norm.endswith(_IDENTITY_OR_AUDIT_SUFFIXES)
            or is_algorithmic_or_protocol_constant(norm)
        ):
            return False
        if raw_name in self.policy_cols:
            return True
        if norm.endswith(_NON_POLICY_COUNTER_SUFFIXES):
            return False
        return bool(set(norm.split("_")) & _POLICY_COLUMN_STEMS)

    def _usable_override_tokens(self, key_name: str, tok_set: frozenset[str]) -> frozenset[str]:
        if self.is_pure_policy_schema or key_name in self.policy_cols:
            return tok_set
        if _normalize_ident_upper(key_name).endswith(_NON_POLICY_COUNTER_SUFFIXES):
            return frozenset()
        return frozenset(tok_set - _TRIVIAL_NUM_LITS)

    def _record_explicit_pol_override(self, key_name: str, tok_set: frozenset[str]) -> None:
        filtered = self._usable_override_tokens(key_name, tok_set)
        if not filtered:
            return
        if key_name in self.policy_cols or bool(
            _meaningful_domain_stems(key_name) & self.policy_domain_stems
        ):
            self.acc.explicit_pol_overrides.update(filtered)

    def _truthy_pol_cols(self, test: ast.AST, env: dict[str, _Val]) -> tuple[str | None, frozenset[str]]:
        if _null_guard_polarity(test, env, self.policy_cols) is not None:
            return None, frozenset()
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            sub_pol, sub_cols = self._truthy_pol_cols(test.operand, env)
            if sub_pol == "truthy_present":
                return "falsy_missing", sub_cols
            return None, frozenset()
        if isinstance(test, ast.Name) and test.id in env:
            ev = env[test.id]
            pol_c = ev.cols & self.policy_cols
            if pol_c and not ev.row:
                return "truthy_present", pol_c
        if (
            isinstance(test, ast.Attribute)
            and isinstance(test.value, ast.Name)
            and test.value.id in env
            and env[test.value.id].row
            and test.attr in self.policy_cols
        ):
            return "truthy_present", frozenset({test.attr})
        if (
            isinstance(test, ast.Subscript)
            and isinstance(test.value, ast.Name)
            and test.value.id in env
            and env[test.value.id].row
            and isinstance(test.slice, ast.Constant)
            and isinstance(test.slice.value, str)
            and test.slice.value in self.policy_cols
        ):
            return "truthy_present", frozenset({test.slice.value})
        return None, frozenset()

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
                self._bind_target(node.target, val, env, lineno=getattr(node, "lineno", 0))
            return val
        if isinstance(node, ast.Name):
            if node.id in env:
                ev = env[node.id]
                if not dead and ev.from_query:
                    self._note_query(node)
                    self.acc.touched_cols.update(ev.cols)
                    if ev.existence_only:
                        self.acc.saw_existence_query = True
                return ev
            if self._is_model_expr(node):
                if not dead:
                    self._note_query(node)
                return _Val(row=True, from_query=True)
            if node.id in self.policy_consts:
                return _Val(consts=frozenset({node.id})) if not dead else _Val()
            return _Val()
        if isinstance(node, ast.JoinedStr):
            parts_txt: list[str] = []
            merged_js = _Val()
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    parts_txt.append(part.value)
                elif isinstance(part, ast.FormattedValue):
                    parts_txt.append("__expr__")
                    merged_js = merged_js.merge(self.eval_expr(part.value, env, dead=dead))
            if self.sql_table_names and parts_txt:
                proj = _sql_projection_for_table(
                    "".join(parts_txt), self.sql_table_names, self.all_table_cols
                )
                if proj is not None:
                    if not dead:
                        self._note_query(node)
                        self.acc.touched_cols.update(proj.cols)
                        if proj.existence_only:
                            self.acc.saw_existence_query = True
                    else:
                        self.acc.dead_cols.update(proj.cols)
                    return proj.merge(merged_js, keep_num_lits=False) if not dead else _Val()
            return merged_js
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and self.sql_table_names:
                proj = _sql_projection_for_table(
                    node.value, self.sql_table_names, self.all_table_cols
                )
                if proj is not None:
                    if not dead:
                        self._note_query(node)
                        self.acc.touched_cols.update(proj.cols)
                        if proj.existence_only:
                            self.acc.saw_existence_query = True
                    else:
                        self.acc.dead_cols.update(proj.cols)
                    return proj if not dead else _Val()
            if (
                not dead
                and isinstance(node.value, (int, float))
                and not isinstance(node.value, bool)
            ):
                return _Val(num_lits=frozenset({repr(node.value)}))
            return _Val()
        if (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.USub)
            and isinstance(node.operand, ast.Constant)
            and isinstance(node.operand.value, (int, float))
            and not isinstance(node.operand.value, bool)
        ):
            return _Val(num_lits=frozenset({repr(-node.operand.value)})) if not dead else _Val()
        if isinstance(node, ast.BinOp):
            lv = self.eval_expr(node.left, env, dead=dead)
            rv = self.eval_expr(node.right, env, dead=dead)
            return lv.merge(rv, keep_num_lits=False)
        if isinstance(node, ast.Compare):
            lv = self.eval_expr(node.left, env, dead=dead)
            merged = lv
            comp_vals = [self.eval_expr(c, env, dead=dead) for c in node.comparators]
            for cv in comp_vals:
                merged = merged.merge(cv, keep_num_lits=False)
            if not dead and any(
                isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in node.ops
            ):
                bound_lits: set[str] = set()
                for side in (lv, *comp_vals):
                    for lit in side.num_lits:
                        if lit not in {"0", "1", "-1"}:
                            bound_lits.add(lit)
                if bound_lits and not merged.cols:
                    merged = _Val(
                        row=merged.row,
                        row_map=merged.row_map,
                        cols=merged.cols,
                        consts=merged.consts,
                        num_lits=frozenset(bound_lits),
                        fallbacks=merged.fallbacks,
                        zero_clobbers=merged.zero_clobbers,
                        overwrite_line=merged.overwrite_line,
                        overwritten_cols=merged.overwritten_cols,
                        dynamic=merged.dynamic,
                    )
            return merged
        if isinstance(node, ast.Attribute):
            if self._is_model_expr(node):
                if not dead:
                    self._note_query(node)
                return _Val(row=True, from_query=True)
            if self._is_model_expr(node.value):
                if not dead:
                    self._note_query(node)
                if node.attr == "objects":
                    return _Val(row=True, from_query=True)
                if node.attr in {"__table__", "__mapper__"}:
                    return _Val(col_ns=True, from_query=True)
                if not node.attr.startswith("__"):
                    if dead:
                        self.acc.dead_cols.add(node.attr)
                        return _Val()
                    self.acc.touched_cols.add(node.attr)
                    return _Val(
                        cols=frozenset({node.attr}),
                        tuple_cols=(node.attr,),
                        from_query=True,
                    )
            base = self.eval_expr(node.value, env, dead=dead)
            if base.col_ns and node.attr in {"c", "columns"}:
                return _Val(row=True, from_query=True)
            if base.row and not base.row_map:
                if node.attr in _ORM_CHAIN_ATTRS:
                    return base
                if node.attr in {"__table__", "__mapper__"}:
                    return _Val(col_ns=True, from_query=True)
                if not node.attr.startswith("_"):
                    if dead:
                        self.acc.dead_cols.add(node.attr)
                        return _Val()
                    self.acc.touched_cols.add(node.attr)
                    return _Val(cols=frozenset({node.attr}), from_query=base.from_query)
            if not base.row and base.tuple_cols and node.attr in base.cols:
                if dead:
                    self.acc.dead_cols.add(node.attr)
                    return _Val()
                self.acc.touched_cols.add(node.attr)
                return _Val(cols=frozenset({node.attr}), from_query=base.from_query)
            return _Val(
                cols=base.cols,
                consts=base.consts,
                fallbacks=base.fallbacks,
                zero_clobbers=base.zero_clobbers,
                overwrite_line=base.overwrite_line,
                overwritten_cols=base.overwritten_cols,
                existence_only=base.existence_only,
                from_query=base.from_query,
                dynamic=base.dynamic,
            )
        if isinstance(node, ast.Subscript):
            base = self.eval_expr(node.value, env, dead=dead)
            slc = node.slice
            if isinstance(slc, ast.Slice):
                for s_part in (slc.lower, slc.upper, slc.step):
                    self.eval_expr(s_part, env, dead=dead)
                return base
            if base.dict_items and isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                for d_k, d_v in reversed(base.dict_items):
                    if d_k == slc.value:
                        return d_v
            if base.tuple_items and isinstance(slc, ast.Constant) and isinstance(slc.value, int):
                idx = slc.value
                if 0 <= idx < len(base.tuple_items):
                    return base.tuple_items[idx]
            if base.tuple_cols and isinstance(slc, ast.Constant) and isinstance(slc.value, int):
                idx = slc.value
                if 0 <= idx < len(base.tuple_cols):
                    col = base.tuple_cols[idx]
                    if not col:
                        return _Val()
                    if dead:
                        self.acc.dead_cols.add(col)
                        return _Val()
                    self.acc.touched_cols.add(col)
                    return _Val(cols=frozenset({col}), from_query=base.from_query)
            if (
                not base.row
                and base.tuple_cols
                and isinstance(slc, ast.Constant)
                and isinstance(slc.value, str)
                and slc.value in base.cols
            ):
                if dead:
                    self.acc.dead_cols.add(slc.value)
                    return _Val()
                self.acc.touched_cols.add(slc.value)
                return _Val(cols=frozenset({slc.value}), from_query=base.from_query)
            if base.row_map:
                sl_val = self.eval_expr(slc, env, dead=dead)
                if not dead:
                    self._consume_sink_val(sl_val, lineno=getattr(node, "lineno", 0))
                return _Val(row=True, cols=base.cols, fallbacks=base.fallbacks)
            if base.row:
                if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                    col = slc.value
                    if dead:
                        self.acc.dead_cols.add(col)
                        return _Val()
                    self.acc.touched_cols.add(col)
                    return _Val(cols=frozenset({col}), from_query=base.from_query)
                if isinstance(slc, ast.Constant) and isinstance(slc.value, int):
                    return base
                if not dead:
                    self.acc.any_dynamic = True
                return _Val(dynamic=not dead)
            return base.merge(self.eval_expr(slc, env, dead=dead), keep_num_lits=False)
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
                elif bool(primary.cols) or primary.row:
                    is_pol_primary = bool(primary.cols & self.policy_cols) or primary.row
                    fb_items = val.consts | val.fallbacks | (val.num_lits if is_pol_primary else frozenset())
                    clobbers = set(cur.zero_clobbers) | set(val.zero_clobbers)
                    if not primary.row:
                        for pcol in primary.cols & self.policy_cols:
                            for fk in val.consts | val.num_lits:
                                clobbers.add((pcol, fk))
                    cur = _Val(
                        row=cur.row or val.row,
                        cols=cur.cols | val.cols,
                        consts=cur.consts,
                        fallbacks=cur.fallbacks | fb_items,
                        zero_clobbers=frozenset(clobbers),
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
        pol = _null_guard_polarity(node.test, env, self.policy_cols)
        truthy_pol, truthy_cols = self._truthy_pol_cols(node.test, env)
        if pol is None and truthy_pol is None:
            t_val = self.eval_expr(node.test, env, dead=dead)
            if not dead:
                self._consume_sink_val(t_val, lineno=getattr(node.test, "lineno", 0))
        b_val = self.eval_expr(node.body, env, dead=dead)
        o_val = self.eval_expr(node.orelse, env, dead=dead)
        if pol == "null_false" and (bool(b_val.cols) or b_val.row):
            is_pol_b = bool(b_val.cols & self.policy_cols) or b_val.row
            fb_b = o_val.consts | o_val.fallbacks | (o_val.num_lits if is_pol_b else frozenset())
            return _Val(
                row=b_val.row or o_val.row,
                cols=b_val.cols | o_val.cols,
                consts=b_val.consts,
                fallbacks=b_val.fallbacks | fb_b,
                zero_clobbers=b_val.zero_clobbers | o_val.zero_clobbers,
                dynamic=b_val.dynamic or o_val.dynamic,
            )
        if pol == "null_true" and (bool(o_val.cols) or o_val.row):
            is_pol_o = bool(o_val.cols & self.policy_cols) or o_val.row
            fb_o = b_val.consts | b_val.fallbacks | (b_val.num_lits if is_pol_o else frozenset())
            return _Val(
                row=b_val.row or o_val.row,
                cols=b_val.cols | o_val.cols,
                consts=o_val.consts,
                fallbacks=o_val.fallbacks | fb_o,
                zero_clobbers=b_val.zero_clobbers | o_val.zero_clobbers,
                dynamic=b_val.dynamic or o_val.dynamic,
            )
        if truthy_pol == "truthy_present" and (b_val.cols & self.policy_cols):
            fb_k = o_val.consts | o_val.num_lits
            clob = {(c, k) for c in truthy_cols for k in fb_k}
            return _Val(
                row=b_val.row or o_val.row,
                cols=b_val.cols | o_val.cols,
                consts=b_val.consts,
                fallbacks=b_val.fallbacks | fb_k | o_val.fallbacks,
                zero_clobbers=b_val.zero_clobbers | o_val.zero_clobbers | frozenset(clob),
                dynamic=b_val.dynamic or o_val.dynamic,
            )
        if truthy_pol == "falsy_missing" and (o_val.cols & self.policy_cols):
            fb_k = b_val.consts | b_val.num_lits
            clob = {(c, k) for c in truthy_cols for k in fb_k}
            return _Val(
                row=b_val.row or o_val.row,
                cols=b_val.cols | o_val.cols,
                consts=o_val.consts,
                fallbacks=o_val.fallbacks | fb_k | b_val.fallbacks,
                zero_clobbers=b_val.zero_clobbers | o_val.zero_clobbers | frozenset(clob),
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
                        zero_clobbers=v_val.zero_clobbers,
                        dynamic=is_dyn and not dead,
                    )
                )
            elif isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                k_str = k_node.value
                if not dead and self._is_policy_like_key(k_str):
                    eff_lits = self._usable_override_tokens(k_str, v_val.num_lits)
                    key_matches_table = (
                        self.is_pure_policy_schema
                        or k_str in self.policy_cols
                        or bool(_meaningful_domain_stems(k_str) & self.policy_domain_stems)
                    )
                    if eff_lits and key_matches_table and not v_val.cols and not v_val.consts:
                        self._note_enforcement(getattr(v_node, "lineno", 0))
                        self._record_explicit_pol_override(k_str, eff_lits)
                        v_val = _Val(
                            row=v_val.row,
                            cols=v_val.cols,
                            consts=eff_lits,
                            fallbacks=v_val.fallbacks,
                            zero_clobbers=v_val.zero_clobbers,
                            overwrite_line=v_val.overwrite_line,
                            overwritten_cols=v_val.overwritten_cols,
                            dynamic=v_val.dynamic,
                        )
                    elif (
                        k_str in self.policy_cols
                        and v_val.consts
                        and not (v_val.cols & self.policy_cols)
                        and not v_val.row
                    ):
                        self._record_explicit_pol_override(k_str, v_val.consts)
                    elif (
                        k_str in self.policy_cols
                        and isinstance(v_node, ast.Constant)
                        and isinstance(v_node.value, bool)
                    ):
                        override_tok = f"{k_str}={v_node.value!r}"
                        self.acc.explicit_pol_overrides.add(override_tok)
                        v_val = v_val.merge(_Val(consts=frozenset({override_tok})))
                    else:
                        v_val = _Val(
                            row=v_val.row,
                            row_map=v_val.row_map,
                            cols=v_val.cols,
                            dict_items=v_val.dict_items,
                            consts=v_val.consts,
                            fallbacks=v_val.fallbacks,
                            zero_clobbers=v_val.zero_clobbers,
                            overwrite_line=v_val.overwrite_line,
                            overwritten_cols=v_val.overwritten_cols,
                            dynamic=v_val.dynamic,
                        )
                else:
                    v_val = _Val(
                        row=v_val.row,
                        row_map=v_val.row_map,
                        cols=v_val.cols,
                        dict_items=v_val.dict_items,
                        consts=v_val.consts,
                        fallbacks=v_val.fallbacks,
                        zero_clobbers=v_val.zero_clobbers,
                        overwrite_line=v_val.overwrite_line,
                        overwritten_cols=v_val.overwritten_cols,
                        dynamic=v_val.dynamic,
                    )
                items_map[k_str] = v_val
            else:
                k_val = self.eval_expr(k_node, env, dead=dead)
                anon.append(k_val.merge(v_val, keep_num_lits=False))
        merged = _Val()
        for item_val in (*items_map.values(), *anon):
            merged = merged.merge(item_val)
        return _Val(
            row=merged.row,
            cols=merged.cols,
            dict_items=tuple(items_map.items()),
            consts=merged.consts,
            num_lits=merged.num_lits,
            fallbacks=merged.fallbacks,
            zero_clobbers=merged.zero_clobbers,
            overwrite_line=merged.overwrite_line,
            overwritten_cols=merged.overwritten_cols,
            dynamic=merged.dynamic,
        )

    def _bind_target(
        self,
        target: ast.AST,
        val: _Val,
        env: dict[str, _Val],
        *,
        lineno: int = 0,
    ) -> None:
        if isinstance(target, ast.Name):
            prev = env.get(target.id)
            repl = val.consts | val.num_lits
            prev_pol = (
                (prev.cols & self.policy_cols)
                if prev is not None and not prev.row
                else (
                    self.policy_cols
                    if prev is not None and prev.row and bool(val.consts)
                    else frozenset()
                )
            )
            killed_pol = (
                (prev_pol - (val.cols & self.policy_cols))
                if not val.row and (repl or not (prev and prev.row))
                else frozenset()
            )
            if killed_pol and (repl or (prev is not None and not prev.row)):
                if lineno:
                    self.acc.causal_overwrite_line = lineno
                self.acc.overwritten_pol_cols.update(killed_pol)
                self.acc.overwritten_consts.update(repl)
                self.acc.overwritten_vars.append(
                    (target.id, tuple(sorted(killed_pol)), tuple(sorted(repl)), lineno)
                )
                val = _Val(
                    row=val.row,
                    row_map=val.row_map,
                    cols=val.cols,
                    tuple_cols=val.tuple_cols,
                    tuple_items=val.tuple_items,
                    dict_items=val.dict_items,
                    consts=repl,
                    fallbacks=val.fallbacks,
                    zero_clobbers=val.zero_clobbers,
                    overwrite_line=lineno or val.overwrite_line,
                    overwritten_cols=(prev.overwritten_cols if prev else frozenset()) | killed_pol,
                    dynamic=val.dynamic,
                )
            elif (
                val.num_lits
                and not val.cols
                and not val.consts
                and self._is_policy_like_key(target.id)
                and bool(self._usable_override_tokens(target.id, val.num_lits))
            ):
                eff_t_lits = self._usable_override_tokens(target.id, val.num_lits)
                if lineno:
                    self._note_enforcement(lineno)
                val = _Val(
                    cols=val.cols,
                    consts=eff_t_lits,
                    num_lits=eff_t_lits,
                    fallbacks=val.fallbacks,
                    zero_clobbers=val.zero_clobbers,
                    overwrite_line=val.overwrite_line,
                    overwritten_cols=val.overwritten_cols,
                    dynamic=val.dynamic,
                )
            env[target.id] = val
        elif isinstance(target, (ast.Tuple, ast.List)):
            for idx, elt in enumerate(target.elts):
                if val.tuple_items and idx < len(val.tuple_items):
                    self._bind_target(elt, val.tuple_items[idx], env, lineno=lineno)
                elif val.tuple_cols and idx < len(val.tuple_cols):
                    col = val.tuple_cols[idx]
                    if col:
                        self.acc.touched_cols.add(col)
                        self._bind_target(elt, _Val(cols=frozenset({col})), env, lineno=lineno)
                    else:
                        self._bind_target(elt, _Val(), env, lineno=lineno)
                else:
                    self._bind_target(elt, val, env, lineno=lineno)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            d_name = target.value.id
            sl_val = self.eval_expr(target.slice, env)
            self._consume_sink_val(sl_val, lineno=lineno)
            prev = env.get(d_name)
            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                if prev is not None and not prev.row_map:
                    d_map = dict(prev.dict_items)
                    s_key = target.slice.value
                    prev_entry = d_map.get(s_key)
                    prev_k_pol = (prev_entry.cols & self.policy_cols) if prev_entry else frozenset()
                    if (
                        (s_key in self.policy_cols or prev_k_pol)
                        and not (val.cols & self.policy_cols)
                        and not val.row
                    ):
                        repl_k = val.consts | val.num_lits
                        if prev_k_pol:
                            if lineno:
                                self.acc.causal_overwrite_line = lineno
                            self.acc.overwritten_pol_cols.update(prev_k_pol)
                            self.acc.overwritten_consts.update(repl_k)
                        if repl_k:
                            val = val.merge(_Val(consts=repl_k))
                        elif not val.dynamic:
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
                        zero_clobbers=merged.zero_clobbers,
                        overwrite_line=merged.overwrite_line,
                        overwritten_cols=merged.overwritten_cols,
                        dynamic=prev.dynamic or merged.dynamic,
                    )
            else:
                base_prev = prev if prev is not None else _Val()
                env[d_name] = base_prev.merge(val)

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
                self._bind_target(gen.target, it_val, comp_env, lineno=getattr(gen.target, "lineno", 0))
            for if_clause in gen.ifs:
                g_val = self.eval_expr(if_clause, comp_env, dead=dead)
                if not dead:
                    self._consume_sink_val(g_val, lineno=getattr(if_clause, "lineno", 0))
        if isinstance(node, ast.DictComp):
            k_val = self.eval_expr(node.key, comp_env, dead=dead)
            v_val = self.eval_expr(node.value, comp_env, dead=dead)
            if not dead:
                self._consume_sink_val(k_val, lineno=getattr(node.key, "lineno", 0))
            merged = k_val.merge(v_val)
            return _Val(
                row=merged.row,
                row_map=merged.row_map or v_val.row,
                cols=merged.cols,
                consts=merged.consts,
                fallbacks=merged.fallbacks,
                zero_clobbers=merged.zero_clobbers,
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
                    return _Val(
                        cols=frozenset({col}),
                        fallbacks=fb_val.consts | fb_val.num_lits | fb_val.fallbacks,
                    )
                if not dead:
                    self.acc.any_dynamic = True
                return _Val(dynamic=not dead)
            return base.merge(fb_val)

        if short in {"count", "exists"} and (
            isinstance(func, ast.Name)
            or recv_name == "func"
            or dotted.endswith((".func.count", ".func.exists"))
        ):
            for a in node.args:
                self.eval_expr(a, env, dead=dead)
            if not dead:
                self.acc.saw_existence_query = True
            return _Val(existence_only=not dead, from_query=not dead)

        if short == "coalesce" and node.args:
            arg_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
            primary = arg_vals[0]
            if bool(primary.cols) or primary.row:
                fb = frozenset().union(
                    *(av.consts | av.num_lits | av.fallbacks for av in arg_vals[1:])
                )
                return _Val(
                    row=primary.row,
                    cols=frozenset().union(*(av.cols for av in arg_vals)),
                    tuple_cols=primary.tuple_cols,
                    fallbacks=primary.fallbacks | fb,
                    from_query=primary.from_query,
                )

        if short == "inspect" and node.args:
            a0 = self.eval_expr(node.args[0], env, dead=dead)
            if a0.row:
                return _Val(col_ns=True, from_query=True)

        if short in {"select", "query"}:
            arg_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
            t_items = tuple(arg_vals) if len(arg_vals) > 1 else ()
            t_cols = tuple(
                av.tuple_cols[0] if len(av.tuple_cols) == 1 else "" for av in arg_vals
            )
            if any(av.row and not av.cols for av in arg_vals):
                return _Val(row=True, tuple_items=t_items, from_query=True)
            cols_union = frozenset().union(*(av.cols for av in arg_vals))
            if cols_union:
                return _Val(
                    cols=cols_union,
                    tuple_cols=t_cols,
                    tuple_items=t_items,
                    from_query=True,
                )
            if any(av.existence_only for av in arg_vals):
                return _Val(existence_only=True, from_query=True)

        recv_seed = _Val()
        if isinstance(func, ast.Attribute):
            if short in {"text", "aliased"} and node.args:
                return self.eval_expr(node.args[0], env, dead=dead)
            recv_val = self.eval_expr(func.value, env, dead=dead)
            if short in {"count", "exists"} and (recv_val.row or recv_val.cols or recv_val.from_query):
                for a in (*node.args, *(kw.value for kw in node.keywords)):
                    self.eval_expr(a, env, dead=dead)
                if not dead:
                    self.acc.saw_existence_query = True
                return _Val(existence_only=not dead, from_query=not dead)
            if short in {"join", "outerjoin"}:
                if node.args:
                    self.eval_expr(node.args[0], env, dead=dead)
                for pred in (*node.args[1:], *(kw.value for kw in node.keywords)):
                    pv = self.eval_expr(pred, env, dead=dead)
                    if not dead:
                        self.acc.sink_cols.update(pv.cols)
                return recv_val
            if short == "select_from":
                arg_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
                if recv_val.row or recv_val.cols or recv_val.existence_only or recv_val.dynamic:
                    return recv_val
                if any(av.row or av.from_query for av in arg_vals):
                    if not dead:
                        self.acc.saw_existence_query = True
                    return _Val(existence_only=not dead, from_query=not dead)
                return recv_val
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
                        arg_vals[1].consts | arg_vals[1].num_lits | arg_vals[1].fallbacks
                        if len(arg_vals) >= 2
                        else frozenset()
                    )
                    if arg_vals and not dead:
                        self._consume_sink_val(arg_vals[0], lineno=getattr(node, "lineno", 0))
                    return _Val(row=True, cols=recv_val.cols, fallbacks=fb)
                if recv_val.row and short == "get" and node.args and not is_orm_objects:
                    fb = (
                        arg_vals[1].consts | arg_vals[1].num_lits | arg_vals[1].fallbacks
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
                if not (recv_val.row or recv_val.cols or recv_val.existence_only):
                    for av in arg_vals:
                        if av.row or av.cols or av.dynamic or av.existence_only:
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
                        zero_clobbers=prev_c.zero_clobbers | comb.zero_clobbers,
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
                        self._consume_sink_val(av, lineno=getattr(node, "lineno", 0))
                return _Val()
            recv_seed = _Val(
                cols=recv_val.cols,
                consts=recv_val.consts,
                fallbacks=recv_val.fallbacks,
                zero_clobbers=recv_val.zero_clobbers,
                overwrite_line=recv_val.overwrite_line,
                overwritten_cols=recv_val.overwritten_cols,
                dynamic=recv_val.dynamic,
            )

        if isinstance(func, ast.Name) and short in _TRANSPARENT_WRAPPERS and node.args:
            return self.eval_expr(node.args[0], env, dead=dead)

        if isinstance(func, ast.Name) and short in self.local_data_classes:
            dc_out = _Val()
            call_ln = getattr(node, "lineno", 0)
            for a in node.args:
                av = self.eval_expr(a, env, dead=dead)
                if not dead and not av.row:
                    self._consume_sink_val(av, lineno=call_ln)
                dc_out = dc_out.merge(av, keep_num_lits=False)
            for kw in node.keywords:
                kv = self.eval_expr(kw.value, env, dead=dead)
                if not dead and not kv.row:
                    self._consume_sink_val(kv, lineno=call_ln)
                    if kw.arg and self._is_policy_like_key(kw.arg) and kv.num_lits and not kv.cols:
                        eff_dc_lits = self._usable_override_tokens(kw.arg, kv.num_lits)
                        if eff_dc_lits:
                            self.acc.enforced_num_consts.update(eff_dc_lits)
                            self._record_explicit_pol_override(kw.arg, eff_dc_lits)
                            self._note_enforcement(getattr(kw.value, "lineno", call_ln))
                dc_out = dc_out.merge(kv, keep_num_lits=False)
            return dc_out

        helper = self.helpers.get(short) or self.helpers.get(self.aliases.get(short, ""))
        if helper is not None:
            if (
                not dead
                and self.acc.first_helper_call_line == 0
                and (
                    helper.returns_tid_row
                    or bool(helper.returned_cols & self.policy_cols)
                    or bool(helper.guard_cols & self.policy_cols)
                )
            ):
                self.acc.first_helper_call_line = getattr(node, "lineno", 0)
            pos_vals = [self.eval_expr(a, env, dead=dead) for a in node.args]
            by_idx: dict[int, _Val] = dict(enumerate(pos_vals))
            for kw in node.keywords:
                kv = self.eval_expr(kw.value, env, dead=dead)
                if kw.arg and kw.arg in helper.param_names:
                    by_idx[helper.param_names.index(kw.arg)] = kv
                elif not dead:
                    self._consume_sink_val(kv, lineno=getattr(node, "lineno", 0))
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
                elif not dead:
                    self._consume_sink_val(aval, lineno=getattr(node, "lineno", 0))
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
        call_line = getattr(node, "lineno", 0)
        for a in node.args:
            av = self.eval_expr(a, env, dead=dead)
            if not dead:
                self._consume_sink_val(av, lineno=call_line)
                if isinstance(a, ast.Compare) and av.num_lits and not av.cols:
                    self.acc.enforced_num_consts.update(av.num_lits)
                    self._note_enforcement(getattr(a, "lineno", call_line))
                if av.row and short not in _NON_CONSUMING_ROW_BUILTINS:
                    self.acc.opaque_callees.add(dotted or short or "<call>")
                    res_dyn = True
            out = out.merge(av, keep_num_lits=False)
        for kw in node.keywords:
            kv = self.eval_expr(kw.value, env, dead=dead)
            if not dead:
                self._consume_sink_val(kv, lineno=call_line)
                if kw.arg and self._is_policy_like_key(kw.arg) and kv.num_lits and not kv.cols:
                    eff_kw_lits = self._usable_override_tokens(kw.arg, kv.num_lits)
                    if eff_kw_lits:
                        self.acc.enforced_num_consts.update(eff_kw_lits)
                        self._record_explicit_pol_override(kw.arg, eff_kw_lits)
                        self._note_enforcement(getattr(kw.value, "lineno", call_line))
                elif (
                    kw.arg
                    and kv.consts
                    and not (kv.cols & self.policy_cols)
                    and not kv.row
                ):
                    self._record_explicit_pol_override(kw.arg, kv.consts)
                if kw.arg is None and (kv.row or kv.dynamic):
                    self.acc.any_dynamic = True
                    res_dyn = True
                elif kv.row and short not in _NON_CONSUMING_ROW_BUILTINS:
                    self.acc.opaque_callees.add(dotted or short or "<call>")
                    res_dyn = True
            out = out.merge(kv, keep_num_lits=False)
        return _Val(
            cols=out.cols,
            consts=out.consts,
            fallbacks=out.fallbacks,
            zero_clobbers=out.zero_clobbers,
            overwrite_line=out.overwrite_line,
            overwritten_cols=out.overwritten_cols,
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
                        self.acc.fallback_consts.update(rv.consts | rv.num_lits | rv.fallbacks)
                        self.acc.zero_clobbers.update(rv.zero_clobbers)
                        self.acc.sink_cols.update(rv.cols)
                        self.acc.return_cols.update(rv.cols)
                        if rv.row:
                            self.acc.sink_cols.update(self.all_table_cols)
                    else:
                        self.acc.primary_return_line = stmt.lineno
                        if rv.row:
                            self.acc.sink_cols.update(self.all_table_cols)
                        self._consume_sink_val(rv, lineno=stmt.lineno)
                        self.acc.return_cols.update(rv.cols)
                        self.acc.return_consts.update(rv.consts)
                        if rv.num_lits and not rv.cols and not rv.consts:
                            self.acc.enforced_num_consts.update(rv.num_lits)
                            self._note_enforcement(stmt.lineno)
                    terminated = True
                continue
            if isinstance(stmt, (ast.Raise, ast.Break, ast.Continue)):
                if isinstance(stmt, ast.Raise):
                    ev = self.eval_expr(stmt.exc, env, dead=cur_dead)
                    if not cur_dead:
                        self._consume_sink_val(ev, lineno=stmt.lineno)
                if not cur_dead:
                    terminated = True
                continue
            if isinstance(stmt, ast.Assert):
                tv = self.eval_expr(stmt.test, env, dead=cur_dead)
                if not cur_dead:
                    self._consume_sink_val(tv, lineno=stmt.lineno)
                    if isinstance(stmt.test, ast.Compare) and tv.num_lits and not tv.cols:
                        self.acc.enforced_num_consts.update(tv.num_lits)
                        self._note_enforcement(stmt.lineno)
                continue
            if isinstance(stmt, ast.Expr):
                val_node = stmt.value
                if isinstance(val_node, (ast.Yield, ast.YieldFrom)):
                    yv = self.eval_expr(val_node.value, env, dead=cur_dead)
                    if not cur_dead:
                        if yv.row:
                            self.acc.sink_cols.update(self.all_table_cols)
                        if null_fallback:
                            self.acc.sink_cols.update(yv.cols)
                            self.acc.fallback_consts.update(yv.consts | yv.num_lits | yv.fallbacks)
                            self.acc.zero_clobbers.update(yv.zero_clobbers)
                        else:
                            self._consume_sink_val(yv, lineno=stmt.lineno)
                            self.acc.return_consts.update(yv.consts)
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
                            self._consume_sink_val(val, lineno=stmt.lineno)
                        else:
                            self._bind_target(tgt, val, env, lineno=stmt.lineno)
                continue
            if isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    val = self.eval_expr(stmt.value, env, dead=cur_dead)
                    if not cur_dead:
                        if isinstance(stmt.target, ast.Attribute):
                            t_recv = self.eval_expr(stmt.target.value, env, dead=cur_dead)
                            if t_recv.row:
                                self.acc.mutates_row = True
                            self._consume_sink_val(val, lineno=stmt.lineno)
                        else:
                            self._bind_target(stmt.target, val, env, lineno=stmt.lineno)
                continue
            if isinstance(stmt, ast.AugAssign):
                val = self.eval_expr(stmt.value, env, dead=cur_dead)
                if not cur_dead:
                    if isinstance(stmt.target, ast.Name):
                        prev = env.get(stmt.target.id, _Val())
                        env[stmt.target.id] = prev.merge(val, keep_num_lits=False)
                    else:
                        self._consume_sink_val(val, lineno=stmt.lineno)
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
                pol = _null_guard_polarity(stmt.test, env, self.policy_cols)
                truthy_pol, truthy_cols = self._truthy_pol_cols(stmt.test, env)
                tv = _Val()
                if pol is None:
                    tv = self.eval_expr(stmt.test, env, dead=cur_dead)
                    if not cur_dead:
                        self._consume_sink_val(tv, lineno=stmt.lineno)
                        if isinstance(stmt.test, ast.Compare) and tv.num_lits and not tv.cols:
                            self.acc.enforced_num_consts.update(tv.num_lits)
                            self._note_enforcement(stmt.lineno)
                env_b = dict(env)
                env_o = dict(env)
                ret_cols_before = set(self.acc.return_cols)
                term_b = self.run_stmts(
                    stmt.body,
                    env_b,
                    dead=cur_dead,
                    null_fallback=null_fallback or (pol == "null_true") or (truthy_pol == "falsy_missing"),
                    returned_whole_flag=returned_whole_flag,
                )
                body_added_ret_cols = bool(self.acc.return_cols - ret_cols_before)
                term_o = self.run_stmts(
                    stmt.orelse,
                    env_o,
                    dead=cur_dead,
                    null_fallback=null_fallback or (pol == "null_false") or (truthy_pol == "truthy_present"),
                    returned_whole_flag=returned_whole_flag,
                )
                if cur_dead:
                    continue
                if term_b and term_o:
                    terminated = True
                elif term_b:
                    env.clear()
                    env.update(env_o)
                    if pol == "null_false" or (bool(tv.cols) and body_added_ret_cols):
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
                        if (pol == "null_false" or truthy_pol == "truthy_present") and (
                            bool(vb.cols) or vb.row
                        ):
                            is_pol_vb = bool(vb.cols & self.policy_cols) or vb.row
                            fb_add = vo.consts | vo.fallbacks | (
                                vo.num_lits if is_pol_vb else frozenset()
                            )
                            clob = set(vb.zero_clobbers) | set(vo.zero_clobbers)
                            if truthy_pol == "truthy_present":
                                for c in truthy_cols:
                                    for fk in vo.consts | vo.num_lits:
                                        clob.add((c, fk))
                            env[k] = _Val(
                                row=vb.row or vo.row,
                                cols=vb.cols | vo.cols,
                                consts=vb.consts,
                                fallbacks=vb.fallbacks | fb_add,
                                zero_clobbers=frozenset(clob),
                                dynamic=vb.dynamic or vo.dynamic,
                            )
                        elif (pol == "null_true" or truthy_pol == "falsy_missing") and (
                            bool(vo.cols) or vo.row
                        ):
                            is_pol_vo = bool(vo.cols & self.policy_cols) or vo.row
                            fb_add = vb.consts | vb.fallbacks | (
                                vb.num_lits if is_pol_vo else frozenset()
                            )
                            clob = set(vb.zero_clobbers) | set(vo.zero_clobbers)
                            if truthy_pol == "falsy_missing":
                                for c in truthy_cols:
                                    for fk in vb.consts | vb.num_lits:
                                        clob.add((c, fk))
                            env[k] = _Val(
                                row=vb.row or vo.row,
                                cols=vb.cols | vo.cols,
                                consts=vo.consts,
                                fallbacks=vo.fallbacks | fb_add,
                                zero_clobbers=frozenset(clob),
                                dynamic=vb.dynamic or vo.dynamic,
                            )
                        else:
                            env[k] = vb.merge(vo)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                itv = self.eval_expr(stmt.iter, env, dead=cur_dead)
                loop_env = dict(env)
                if not cur_dead:
                    self._bind_target(stmt.target, itv, loop_env, lineno=stmt.lineno)
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
                    self._consume_sink_val(tv, lineno=stmt.lineno)
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
                        self._bind_target(item.optional_vars, iv, env, lineno=stmt.lineno)
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
    dict[str, tuple[int, list[ast.stmt]]],
    frozenset[str],
    list[ast.stmt],
    dict[str, str],
    frozenset[str],
    dict[str, bool],
]:
    scopes: dict[str, tuple[int, list[ast.stmt], tuple[str, ...]]] = {}
    class_scopes: dict[str, tuple[int, list[ast.stmt]]] = {}
    local_data_classes: set[str] = set()
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
            pnames = tuple(
                a.arg
                for a in (*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs)
            )
            scopes[stmt.name] = (stmt.lineno, stmt.body, pnames)
        elif isinstance(stmt, ast.ClassDef):
            cls_stmts: list[ast.stmt] = []
            has_custom_init = False
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if member.name == "__init__":
                        has_custom_init = True
                    raw_p = [
                        a.arg
                        for a in (
                            *member.args.posonlyargs,
                            *member.args.args,
                            *member.args.kwonlyargs,
                        )
                    ]
                    if raw_p and raw_p[0] in {"self", "cls"}:
                        raw_p = raw_p[1:]
                    scopes[member.name] = (member.lineno, member.body, tuple(raw_p))
                else:
                    cls_stmts.append(member)
            class_scopes[stmt.name] = (stmt.lineno, cls_stmts)
            if not has_custom_init:
                local_data_classes.add(stmt.name)
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

    return (
        scopes,
        class_scopes,
        frozenset(local_data_classes),
        top_stmts,
        aliases,
        frozenset(policy_consts),
        const_truth,
    )


def _build_helper_summaries(
    scopes: dict[str, tuple[int, list[ast.stmt], tuple[str, ...]]],
    *,
    all_table_cols: frozenset[str],
    policy_cols: frozenset[str],
    is_pure_policy_schema: bool,
    model_symbols: frozenset[str],
    sql_table_names: set[str],
    policy_consts: frozenset[str],
    const_truth: dict[str, bool],
    aliases: dict[str, str],
    local_data_classes: frozenset[str],
    module_env: dict[str, _Val],
    excluded: set[int],
) -> dict[str, _HelperSummary]:
    summaries: dict[str, _HelperSummary] = {}
    for _pass_idx in range(2):
        next_summaries: dict[str, _HelperSummary] = {}
        for fn_name, (_lineno, body, pnames) in scopes.items():
            consumed_by_param: dict[int, frozenset[str]] = {}
            returned_whole: set[int] = set()
            dyn_params: set[int] = set()
            for idx, pname in enumerate(pnames):
                runner = _FlowRunner(
                    all_table_cols=all_table_cols,
                    policy_cols=policy_cols,
                    is_pure_policy_schema=is_pure_policy_schema,
                    model_symbols=frozenset(),
                    sql_table_names=set(),
                    policy_consts=policy_consts,
                    const_truth=const_truth,
                    aliases=aliases,
                    helpers=summaries,
                    local_data_classes=local_data_classes,
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
                is_pure_policy_schema=is_pure_policy_schema,
                model_symbols=model_symbols,
                sql_table_names=sql_table_names,
                policy_consts=policy_consts,
                const_truth=const_truth,
                aliases=aliases,
                helpers=summaries,
                local_data_classes=local_data_classes,
                excluded=excluded,
            )
            ret_tid_whole: list[str] = []
            base_runner.run_stmts(body, dict(module_env), returned_whole_flag=ret_tid_whole)
            ret_cols = frozenset(base_runner.acc.return_cols)
            next_summaries[fn_name] = _HelperSummary(
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
        summaries = next_summaries
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
    (
        scopes,
        class_scopes,
        local_data_classes,
        top_stmts,
        aliases,
        policy_consts,
        const_truth,
    ) = _collect_module_context(tree, excluded, tokens, declared_policy_consts)
    all_cols_set = frozenset(table_columns) | frozenset(policy_columns)
    policy_col_set = frozenset(policy_columns)
    norm_sql_names = {s.rpartition(".")[2].lower() or s.lower() for s in sql_table_names}
    norm_sql_names.add(table_label.rpartition(".")[2].lower() or table_label.lower())

    tbl_norm = _normalize_ident_upper(table_label.rpartition(".")[2] or table_label)
    tbl_parts = set(tbl_norm.split("_")) if tbl_norm else set()
    non_structural_table_cols = {c for c in all_cols_set if not _is_structural_col(c)}
    is_pure_policy_schema = bool(
        non_structural_table_cols and non_structural_table_cols <= policy_col_set
    )
    is_policy_named_table = bool(tbl_parts & _POLICY_TABLE_STEMS)
    pol_domain_stems = frozenset().union(*(_meaningful_domain_stems(c) for c in policy_columns))

    top_seed_runner = _FlowRunner(
        all_table_cols=all_cols_set,
        policy_cols=policy_col_set,
        is_pure_policy_schema=is_pure_policy_schema,
        model_symbols=frozenset(model_symbols),
        sql_table_names=norm_sql_names,
        policy_consts=policy_consts,
        const_truth=const_truth,
        aliases=aliases,
        helpers={},
        local_data_classes=local_data_classes,
        excluded=excluded,
    )
    raw_top_env: dict[str, _Val] = {}
    top_seed_runner.run_stmts(top_stmts, raw_top_env)
    module_env: dict[str, _Val] = {
        k: v
        for k, v in raw_top_env.items()
        if v.row or v.cols or v.existence_only or v.from_query
    }

    helpers = _build_helper_summaries(
        scopes,
        all_table_cols=all_cols_set,
        policy_cols=policy_col_set,
        is_pure_policy_schema=is_pure_policy_schema,
        model_symbols=frozenset(model_symbols),
        sql_table_names=norm_sql_names,
        policy_consts=policy_consts,
        const_truth=const_truth,
        aliases=aliases,
        local_data_classes=local_data_classes,
        module_env=module_env,
        excluded=excluded,
    )

    trans_calls: dict[str, set[str]] = {k: set(v) for k, v in func_calls.items()}
    scope_names_set = set(scopes)
    for fn_name, (_ln, fn_body, _pnames) in scopes.items():
        s_set = trans_calls.setdefault(fn_name, set())
        for st in fn_body:
            for nd in ast.walk(st):
                if isinstance(nd, ast.Call) and id(nd) not in excluded:
                    cal_s = (
                        nd.func.id
                        if isinstance(nd.func, ast.Name)
                        else nd.func.attr
                        if isinstance(nd.func, ast.Attribute)
                        else ""
                    )
                    if cal_s in scope_names_set and cal_s != fn_name:
                        s_set.add(cal_s)
    for _ in range(6):
        changed_tc = False
        for sc_k, c_set in list(trans_calls.items()):
            for cal_k in list(c_set & scope_names_set):
                extra = trans_calls.get(cal_k, set()) - c_set - {sc_k}
                if extra:
                    c_set.update(extra)
                    changed_tc = True
        if not changed_tc:
            break

    active_set = set(active_scopes) or {"*"}
    if "*" in active_set and module_env and not top_seed_runner.acc.sink_cols:
        mod_q_vars = set(module_env)
        consuming_fn_scopes = {
            fn_name
            for fn_name, (_ln, fn_body, _pnames) in scopes.items()
            if any(
                isinstance(nd, ast.Name) and isinstance(nd.ctx, ast.Load) and nd.id in mod_q_vars
                for st in fn_body
                for nd in ast.walk(st)
                if id(nd) not in excluded
            )
        }
        if consuming_fn_scopes:
            active_set = (active_set - {"*"}) | consuming_fn_scopes

    internal_loaders_with_caller = {
        sc
        for sc in active_set
        if sc in helpers
        and helpers[sc].returns_tid_row
        and any(sc in trans_calls.get(other, ()) for other in (active_set - {sc}))
    }
    target_scopes = sorted(active_set - internal_loaders_with_caller) or sorted(active_set)

    results: list[ScopePolicyReadAnalysis] = []
    for sc in target_scopes:
        if sc == "*":
            sc_line = 1
            body = top_stmts
            init_env: dict[str, _Val] = {}
        elif sc in scopes:
            sc_line, body, _ = scopes[sc]
            init_env = dict(module_env)
        elif sc in class_scopes:
            sc_line, body = class_scopes[sc]
            init_env = dict(module_env)
        else:
            continue

        runner = _FlowRunner(
            all_table_cols=all_cols_set,
            policy_cols=policy_col_set,
            is_pure_policy_schema=is_pure_policy_schema,
            model_symbols=frozenset(model_symbols),
            sql_table_names=norm_sql_names,
            policy_consts=policy_consts,
            const_truth=const_truth,
            aliases=aliases,
            helpers=helpers,
            local_data_classes=local_data_classes,
            excluded=excluded,
        )
        runner.run_stmts(body, init_env)
        acc = runner.acc
        called_direct_helpers = [
            cal
            for cal in trans_calls.get(sc, ())
            if cal != sc and cal in helpers and helpers[cal].has_direct_query
        ]
        if (
            acc.first_query_line == 0
            and not called_direct_helpers
            and not acc.touched_cols
            and not acc.sink_cols
            and not acc.dead_cols
            and not acc.saw_existence_query
            and not acc.opaque_callees
            and not acc.any_dynamic
        ):
            continue
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

        known_cols = set(table_columns) | set(policy_columns)
        consumed_cols = sorted(acc.sink_cols & known_cols) if known_cols else sorted(acc.sink_cols)
        consumed_non_structural_cols = {c for c in consumed_cols if not _is_structural_col(c)}
        consumed_pol = acc.sink_cols & policy_col_set
        unconsumed_pol = sorted(policy_col_set - consumed_pol)
        overwritten_unconsumed = acc.overwritten_pol_cols & set(unconsumed_pol)
        dead_pol = bool(acc.dead_cols & policy_col_set)
        touched_or_overwrote_pol = (
            bool((acc.touched_cols | acc.overwritten_pol_cols | acc.dead_cols) & policy_col_set)
            or bool(acc.explicit_pol_overrides)
        )

        if is_pure_policy_schema or touched_or_overwrote_pol:
            cand_subst = (
                set(acc.overwritten_consts)
                | set(acc.return_consts)
                | set(acc.sink_consts)
                | set(acc.explicit_pol_overrides)
                | (set(acc.enforced_num_consts) if not consumed_pol else set())
            )
        elif is_policy_named_table:
            named_pool = (
                set(acc.overwritten_consts)
                | set(acc.return_consts)
                | set(acc.sink_consts)
            )
            filtered_named = {
                k
                for k in named_pool
                if (
                    not consumed_non_structural_cols
                    or not any(ch.isalpha() for ch in k)
                    or bool(_meaningful_domain_stems(k) & pol_domain_stems)
                )
            }
            enforced_pool = (
                (set(acc.enforced_num_consts) - _TRIVIAL_NUM_LITS)
                if not consumed_pol
                else set()
            )
            cand_subst = filtered_named | enforced_pool
        else:
            cand_subst = {
                k
                for k in (
                    set(acc.overwritten_consts)
                    | set(acc.return_consts)
                    | set(acc.sink_consts)
                )
                if any(ch.isalpha() for ch in k)
                and bool(_meaningful_domain_stems(k) & pol_domain_stems)
            }
        raw_return_consts = sorted(cand_subst)
        if unconsumed_pol and (not consumed_pol or overwritten_unconsumed):
            subst_consts = (
                sorted(acc.overwritten_consts)
                if overwritten_unconsumed and acc.overwritten_consts
                else raw_return_consts
            )
        else:
            subst_consts = []
        fb_consts = sorted(acc.fallback_consts - set(subst_consts))
        ev_line = (
            (acc.causal_overwrite_line if overwritten_unconsumed else 0)
            or (acc.causal_enforcement_line if subst_consts and not consumed_pol else 0)
            or acc.primary_return_line
            or acc.first_query_line
            or acc.first_helper_call_line
            or sc_line
        )
        is_w_lookup = (
            ((sc in write_scopes) or acc.mutates_row)
            and not consumed_pol
            and not raw_return_consts
        )

        state: PolicyConsumptionState
        mech: PolicyConsumptionMechanism
        if is_w_lookup:
            if not is_pure_policy_schema and not touched_or_overwrote_pol and (
                consumed_non_structural_cols or not is_policy_named_table
            ):
                continue
            state = "consumed"
            mech = "field_controls_result"
            note = f"`{sc}()` reads `{table_label}` keys/rows for an audited write/upsert path."
        elif subst_consts and unconsumed_pol:
            state = "bypassed"
            mech = "constant_or_fallback_wins"
            ov_trail = ""
            if acc.overwritten_vars and overwritten_unconsumed:
                v_name, _k_cols, _r_consts, ov_ln = acc.overwritten_vars[-1]
                ov_trail = f" (local `{v_name}` overwritten at line {ov_ln})"
            elif ev_line:
                ov_trail = f" (at line {ev_line})"
            note = (
                f"`{sc}()` leaves policy column(s) {', '.join(f'`{c}`' for c in unconsumed_pol)} "
                f"unconsumed and substitutes {', '.join(f'`{k}`' for k in subst_consts)}{ov_trail}."
            )
        elif consumed_pol:
            state = "consumed"
            mech = "field_controls_result"
            fb_tag = (
                f" (with null/falsy fallback {', '.join(f'`{k}`' for k in fb_consts)})"
                if fb_consts
                else ""
            )
            clobber_tag = ""
            live_clobbers = sorted(
                (col, fk) for col, fk in acc.zero_clobbers if col in consumed_pol
            )
            if live_clobbers:
                pairs_txt = ", ".join(f"`{col}` -> `{fk}`" for col, fk in live_clobbers)
                clobber_tag = (
                    f" Warning: zero-clobbering truthiness fallback ({pairs_txt}) "
                    "overwrites valid `0` policy values; use `is not None`."
                )
            note = (
                f"`{sc}()` flows policy column(s) "
                f"{', '.join(f'`{c}`' for c in sorted(consumed_pol))} into result/guard{fb_tag}.{clobber_tag}"
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
            if not touched_or_overwrote_pol and not dead_pol:
                if consumed_non_structural_cols:
                    continue
                if not is_pure_policy_schema and not is_policy_named_table:
                    continue
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
