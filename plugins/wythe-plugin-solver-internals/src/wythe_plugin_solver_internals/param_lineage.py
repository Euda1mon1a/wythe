"""`SatParameters` knob-to-C++ consumer lineage and `SAT-INT-002` heuristic detector.

Traces declared `sat_parameters.proto` fields (`cp_model_presolve`, `linearization_level`,
`symmetry_level`, `num_workers`, `num_search_workers`, `max_time_in_seconds`, etc.) into
C++ consumers (`parameters.foo()` / `params_.foo()`), constructs `PolicyFieldConsumption`
(`consumed` vs. `bypassed`), and flags hardcoded C++ work-limit and clause/domain constants.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.adapters.base import RawCandidateFinding
from app.schemas.atlas import AtlasEdge, PolicyFieldConsumption
from wythe_plugin_solver_internals.proto_descriptor import (
    MAX_LINE_SCAN_CHARS,
    MAX_SOLVER_FILE_BYTES,
    ProtoFieldDef,
    SolverProtoCatalog,
    iter_safe_repo_files,
    read_safe_artifact_text,
    strip_c_comments_and_strings,
)

CORE_SAT_PARAMETER_KNOBS: tuple[str, ...] = (
    "cp_model_presolve",
    "linearization_level",
    "symmetry_level",
    "num_workers",
    "num_search_workers",
    "max_time_in_seconds",
)

_CPP_SUFFIXES: frozenset[str] = frozenset({".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"})

# Receiver names commonly holding `SatParameters` in `ortools/sat/` and C++ solvers.
_PARAM_RECEIVER_CALL_RE = re.compile(
    r"\b((?:[A-Za-z_][A-Za-z0-9_]*)?(?:parameters|params|param)_?)\s*(?:\.|->)\s*"
    r"([a-z][a-z0-9_]*)\s*\(\s*\)"
)

# Named C++ heuristic threshold / work-limit constants in solver phases.
_CONST_DECL_RE = re.compile(
    r"\b(?:constexpr|const)\s+(?:int(?:32_t|64_t)?|uint(?:32_t|64_t)?|size_t|double|float)\s+"
    r"(k[A-Z][A-Za-z0-9_]*)\s*=\s*([+-]?(?:\d[\d']*(?:\.\d+)?(?:[eE][+-]?\d+)?))\s*;"
)
_DEFINE_CONST_RE = re.compile(
    r"^\s*#\s*define\s+([A-Z][A-Z0-9_]{3,})\s+([+-]?(?:\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))\b"
)
_HEURISTIC_BOUND_TOKENS: tuple[str, ...] = (
    "max",
    "limit",
    "threshold",
    "budget",
    "cutoff",
    "cap",
)
_HEURISTIC_SOLVER_TOKENS: tuple[str, ...] = (
    "work",
    "operation",
    "presolve",
    "probing",
    "probe",
    "clause",
    "domain",
    "cut",
    "symmetr",
    "lns",
    "expand",
    "expansion",
    "search",
    "conflict",
    "node",
    "round",
    "dtime",
    "deterministic",
    "triplet",
    "var",
)
_BENIGN_CONST_EXCLUSIONS: tuple[str, ...] = (
    "bits",
    "bytes",
    "int64max",
    "int32max",
    "uint64max",
    "infinity",
    "nan",
    "epsilon",
    "version",
)

# Direct magic numeric threshold guard on solver work / clause / domain counters.
_INLINE_MAGIC_GUARD_RE = re.compile(
    r"\bif\s*\(\s*([A-Za-z_][A-Za-z0-9_.->()]{1,80})\s*(>=|>|<=|<)\s*"
    r"(\d[\d']*(?:\.\d+)?(?:[eE][+-]?\d+)?)\s*\)"
)
_INLINE_COUNTER_TOKENS: tuple[str, ...] = (
    "work",
    "operations",
    "num_operations",
    "domain",
    "clause",
    "dtime",
    "num_cuts",
    "cut_rounds",
    "probing",
)
_CPP_FN_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_:<>,&\*\s]{0,120}\s+)?([A-Za-z_][A-Za-z0-9_:]*)\s*\("
)


@dataclass(frozen=True)
class ParamConsumerSite:
    knob: str
    receiver: str
    source_file: str
    line: int
    scope_name: str


@dataclass(frozen=True)
class HardcodedHeuristicThreshold:
    symbol_or_expr: str
    literal_value: str
    numeric_value: float
    kind: str  # "named_constant" | "inline_threshold"
    source_file: str
    line: int
    scope_name: str


@dataclass(frozen=True)
class ParamKnobLineage:
    name: str
    field_number: int
    type_name: str
    default_value: str | None
    deprecated: bool
    consumed: bool
    consumers: tuple[ParamConsumerSite, ...] = ()


@dataclass(frozen=True)
class ParamLineageReport:
    knobs: tuple[ParamKnobLineage, ...]
    hardcoded_thresholds: tuple[HardcodedHeuristicThreshold, ...]
    consumption_by_file: dict[str, PolicyFieldConsumption] = field(default_factory=dict)
    overall_consumption: PolicyFieldConsumption | None = None
    atlas_edges: tuple[AtlasEdge, ...] = ()
    findings: tuple[RawCandidateFinding, ...] = ()


def _is_solver_cpp_file(rel_path: str, cleaned: str) -> bool:
    low_p = rel_path.lower()
    if "/sat/" in f"/{low_p}" or low_p.startswith("sat/"):
        return True
    markers = (
        "SatParameters",
        "ConstraintProto",
        "operations_research::sat",
        "PropagatorInterface",
        "SatPropagator",
        "cp_model_",
    )
    return any(m in cleaned for m in markers)


def _enclosing_cpp_scope(lines: list[str], line_no: int, rel_path: str) -> str:
    for back in range(line_no - 1, max(-1, line_no - 50), -1):
        cand = lines[back][:MAX_LINE_SCAN_CHARS]
        s = cand.lstrip()
        if s.startswith(("if ", "if(", "for ", "for(", "while ", "switch ", "case ", "return ")):
            continue
        m_fn = _CPP_FN_RE.match(cand)
        if m_fn:
            sym = m_fn.group(1)
            if sym not in {"if", "for", "while", "switch", "return", "sizeof", "DCHECK", "CHECK"}:
                return sym
    return PurePosixPath(rel_path).stem


def _parse_cpp_number(raw_num: str) -> float | None:
    try:
        return float(raw_num.replace("'", ""))
    except ValueError:
        return None


def _is_heuristic_constant_name(name: str) -> bool:
    low = name.lower()
    if any(excl in low for excl in _BENIGN_CONST_EXCLUSIONS):
        return False
    return any(b in low for b in _HEURISTIC_BOUND_TOKENS) and any(
        t in low for t in _HEURISTIC_SOLVER_TOKENS
    )


def trace_sat_parameter_lineage(
    repo_root: Path,
    catalog: SolverProtoCatalog,
    *,
    node_id_by_file: dict[str, str] | None = None,
    include_manip_001: bool = False,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> ParamLineageReport:
    """Trace `SatParameters` C++ consumers vs. hardcoded work/clause/domain thresholds."""
    nid_map = node_id_by_file or {}
    declared_params: dict[str, ProtoFieldDef] = dict(catalog.sat_parameters)
    if not declared_params:
        # If only C++ solver files exist without sat_parameters.proto, seed core SatParameters knobs
        # only when solver C++ code explicitly references SatParameters.
        has_cpp_sat_params = False
        for _, abs_p in iter_safe_repo_files(repo_root, suffixes=_CPP_SUFFIXES):
            _, raw_t = read_safe_artifact_text(
                abs_p, repo_root=repo_root, max_bytes=max_bytes, errors="replace"
            )
            if "SatParameters" in raw_t:
                has_cpp_sat_params = True
                break
        if not has_cpp_sat_params:
            return ParamLineageReport(knobs=(), hardcoded_thresholds=())
        for idx, kname in enumerate(CORE_SAT_PARAMETER_KNOBS, start=1):
            declared_params[kname] = ProtoFieldDef(name=kname, number=idx, type_name="scalar")

    known_knobs = set(declared_params)
    consumers_by_knob: dict[str, list[ParamConsumerSite]] = {k: [] for k in declared_params}
    file_consumers: dict[str, list[ParamConsumerSite]] = {}
    file_thresholds: dict[str, list[HardcodedHeuristicThreshold]] = {}
    all_thresholds: list[HardcodedHeuristicThreshold] = []

    for rel_posix, abs_p in iter_safe_repo_files(repo_root, suffixes=_CPP_SUFFIXES):
        _, raw_txt = read_safe_artifact_text(
            abs_p, repo_root=repo_root, max_bytes=max_bytes, errors="replace"
        )
        cleaned = strip_c_comments_and_strings(raw_txt, blank_strings=True)
        if not _is_solver_cpp_file(rel_posix, cleaned):
            continue
        lines = cleaned.splitlines()

        for idx, raw_ln in enumerate(lines):
            ln_no = idx + 1
            ln_txt = raw_ln[:MAX_LINE_SCAN_CHARS]

            for m_call in _PARAM_RECEIVER_CALL_RE.finditer(ln_txt):
                recv, method_name = m_call.group(1), m_call.group(2)
                knob = method_name.removeprefix("has_")
                if knob in known_knobs:
                    scope = _enclosing_cpp_scope(lines, ln_no, rel_posix)
                    site = ParamConsumerSite(
                        knob=knob,
                        receiver=recv,
                        source_file=rel_posix,
                        line=ln_no,
                        scope_name=scope,
                    )
                    consumers_by_knob[knob].append(site)
                    file_consumers.setdefault(rel_posix, []).append(site)

            m_cdecl = _CONST_DECL_RE.search(ln_txt) or _DEFINE_CONST_RE.search(ln_txt)
            if m_cdecl:
                cname, clit = m_cdecl.group(1), m_cdecl.group(2)
                num_v = _parse_cpp_number(clit)
                if num_v is not None and abs(num_v) > 1.0 and _is_heuristic_constant_name(cname):
                    scope = _enclosing_cpp_scope(lines, ln_no, rel_posix)
                    rec = HardcodedHeuristicThreshold(
                        symbol_or_expr=cname,
                        literal_value=clit,
                        numeric_value=num_v,
                        kind="named_constant",
                        source_file=rel_posix,
                        line=ln_no,
                        scope_name=scope,
                    )
                    all_thresholds.append(rec)
                    file_thresholds.setdefault(rel_posix, []).append(rec)
                    continue

            if "parameters" not in ln_txt and "params" not in ln_txt:
                m_guard = _INLINE_MAGIC_GUARD_RE.search(ln_txt)
                if m_guard:
                    lhs, _op, glit = m_guard.groups()
                    lhs_low = lhs.lower()
                    num_v = _parse_cpp_number(glit)
                    if (
                        num_v is not None
                        and num_v >= 16.0
                        and any(tok in lhs_low for tok in _INLINE_COUNTER_TOKENS)
                    ):
                        scope = _enclosing_cpp_scope(lines, ln_no, rel_posix)
                        rec = HardcodedHeuristicThreshold(
                            symbol_or_expr=lhs.strip(),
                            literal_value=glit,
                            numeric_value=num_v,
                            kind="inline_threshold",
                            source_file=rel_posix,
                            line=ln_no,
                            scope_name=scope,
                        )
                        all_thresholds.append(rec)
                        file_thresholds.setdefault(rel_posix, []).append(rec)

    policy_cols = sorted(declared_params)
    consumption_by_file: dict[str, PolicyFieldConsumption] = {}
    atlas_edges: list[AtlasEdge] = []
    touched_files = sorted(set(file_consumers) | set(file_thresholds))

    for sf in touched_files:
        c_sites = file_consumers.get(sf, [])
        t_sites = file_thresholds.get(sf, [])
        consumed_cols = sorted({s.knob for s in c_sites})
        unconsumed_cols = sorted(set(policy_cols) - set(consumed_cols))
        scopes = sorted({s.scope_name for s in c_sites} | {t.scope_name for t in t_sites})
        subst = [f"{t.symbol_or_expr}={t.literal_value}" for t in t_sites]
        is_bypassed = bool(t_sites)
        pfc = PolicyFieldConsumption(
            state="bypassed" if is_bypassed else "consumed",
            mechanism="constant_or_fallback_wins" if is_bypassed else "field_controls_result",
            reader_scopes=scopes,
            policy_columns=policy_cols,
            consumed_columns=consumed_cols,
            unconsumed_policy_columns=unconsumed_cols,
            substituted_constants=subst,
            note=(
                f"`{sf}` bypasses `SatParameters` with hardcoded C++ heuristic threshold(s) "
                f"{', '.join(subst[:4])}."
                if is_bypassed
                else f"`{sf}` consumes `SatParameters` knob(s) {', '.join(consumed_cols[:6])}."
            ),
        )
        consumption_by_file[sf] = pfc
        src_nid = nid_map.get(sf, f"m:solver_tu:{sf}")
        links = [f"{s.scope_name}->SatParameters::{s.knob}" for s in c_sites[:8]]
        atlas_edges.append(
            AtlasEdge(
                id=f"e:{src_nid}->t:proto:sat_parameters:reads_truth",
                source_id=src_nid,
                target_id="t:proto:sat_parameters",
                kind="reads_truth",
                verification="verified",
                evidence_path=sf,
                evidence_note=pfc.note,
                symbol_links=links,
                policy_field_consumption=pfc,
            )
        )

    all_consumed = sorted({k for k, v in consumers_by_knob.items() if v})
    all_unconsumed = sorted(set(policy_cols) - set(all_consumed))
    all_subst = [f"{t.symbol_or_expr}={t.literal_value}" for t in all_thresholds]
    overall_pfc = PolicyFieldConsumption(
        state="bypassed" if all_thresholds else ("consumed" if all_consumed else "unresolved"),
        mechanism=(
            "constant_or_fallback_wins"
            if all_thresholds
            else ("field_controls_result" if all_consumed else "dynamic_or_opaque_flow")
        ),
        reader_scopes=sorted({s.scope_name for v in consumers_by_knob.values() for s in v}),
        policy_columns=policy_cols,
        consumed_columns=all_consumed,
        unconsumed_policy_columns=all_unconsumed,
        substituted_constants=all_subst,
        note=(
            f"Consumed {len(all_consumed)}/{len(policy_cols)} `SatParameters` knobs; "
            f"detected {len(all_thresholds)} hardcoded C++ heuristic threshold(s)."
        ),
    )

    knobs_out = tuple(
        ParamKnobLineage(
            name=fld.name,
            field_number=fld.number,
            type_name=fld.type_name,
            default_value=fld.default_value,
            deprecated=fld.deprecated,
            consumed=bool(consumers_by_knob.get(fld.name)),
            consumers=tuple(consumers_by_knob.get(fld.name, ())),
        )
        for _, fld in sorted(declared_params.items(), key=lambda kv: (kv[1].number, kv[0]))
    )

    findings: list[RawCandidateFinding] = []
    for thr in all_thresholds:
        nid = nid_map.get(thr.source_file)
        file_knobs = sorted({s.knob for s in file_consumers.get(thr.source_file, ())})
        knob_ctx = (
            f" alongside `SatParameters` reader(s) [{', '.join(file_knobs[:4])}]"
            if file_knobs
            else " without consulting `SatParameters`"
        )
        title = (
            f"Hardcoded C++ solver heuristic threshold `{thr.symbol_or_expr} = {thr.literal_value}` "
            f"bypasses `SatParameters`"
        )
        detail = (
            f"`{thr.source_file}:{thr.line}` (`{thr.scope_name}`) enforces hardcoded C++ "
            f"{thr.kind.replace('_', ' ')} `{thr.symbol_or_expr}` (`{thr.literal_value}`){knob_ctx} "
            "(shadow-threshold class `MANIP-001`), preventing callers from tuning or bounding this "
            "work/clause/domain cutoff via `sat_parameters.proto`."
        )
        remediation = (
            f"Promote `{thr.symbol_or_expr}` to an explicit `SatParameters` field in "
            "`sat_parameters.proto` and read `parameters.<field>()` instead of embedding a "
            "hardcoded C++ threshold."
        )
        findings.append(
            RawCandidateFinding(
                rule_code="SAT-INT-002",
                node_id=nid,
                source_file=thr.source_file,
                line=thr.line,
                title=title,
                detail=detail,
                remediation=remediation,
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )
        if include_manip_001:
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-001",
                    node_id=nid,
                    source_file=thr.source_file,
                    line=thr.line,
                    title=title,
                    detail=detail,
                    remediation=remediation,
                    confidence="confirmed",
                    evidence_strength="ast_exact",
                )
            )

    return ParamLineageReport(
        knobs=knobs_out,
        hardcoded_thresholds=tuple(all_thresholds),
        consumption_by_file=consumption_by_file,
        overall_consumption=overall_pfc,
        atlas_edges=tuple(atlas_edges),
        findings=tuple(findings),
    )
