"""Unified incremental Live Watch <-> Replay CP-SAT log & companion parser.

Benchmarked against upstream OR-Tools CP-SAT (`log_search_progress=true` and
`cp_model.proto` / `cp_model_checker.cc` in
`google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5`).
Strictly passive, pure-Python, and non-executing.
"""

from __future__ import annotations

import json
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

MAX_SOLVER_COMPANION_BYTES: Final[int] = 16 * 1024 * 1024

ValidationErrorKind = Literal[
    "inverted_bounds",
    "invalid_interval",
    "coefficient_overflow",
    "invalid_model",
]


_OS_ROOT_SYMLINK_PREFIXES: Final[frozenset[tuple[str, str]]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)


def _check_non_os_symlinks_in_abs_parts(parts: tuple[str, ...], raw_str: str) -> None:
    for k in range(2, len(parts) + 1):
        if k == 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
            continue
        if Path(*parts[:k]).is_symlink():
            raise ValueError(f"Symlink component rejected in companion path '{raw_str}'.")


def resolve_safe_companion_path(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_COMPANION_BYTES,
) -> Path:
    """Validate a companion log/proto/JSONL file as a contained, non-symlink regular file."""
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Companion input path must be a non-empty string without NUL bytes.")

    cand = Path(raw_str).expanduser()
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_str}'.")

    real_root = repo_root.resolve() if repo_root is not None else None
    if not cand.is_absolute():
        base = real_root if real_root is not None else Path.cwd().resolve()
        walk = base
        for part in cand.parts:
            if part in ("", "."):
                continue
            walk = walk / part
            if walk.is_symlink():
                raise ValueError(f"Symlink component rejected in companion path '{raw_str}'.")
        target = walk
        if real_root is not None and not allow_external and not target.resolve().is_relative_to(real_root):
            raise ValueError(
                f"Companion path '{raw_str}' escapes target repository root '{real_root}'."
            )
    elif real_root is not None and not allow_external:
        matched_k: int | None = None
        for k in range(1, len(cand.parts) + 1):
            pref = Path(*cand.parts[:k])
            if k >= 2 and not (k == 2 and cand.parts[:2] in _OS_ROOT_SYMLINK_PREFIXES) and pref.is_symlink():
                raise ValueError(f"Symlink component rejected in companion path '{raw_str}'.")
            if pref.exists() and pref.resolve() == real_root:
                matched_k = k
                break
        if matched_k is None:
            raise ValueError(
                f"Companion path '{raw_str}' escapes target repository root '{real_root}'."
            )
        walk = real_root
        for part in cand.parts[matched_k:]:
            if part in ("", "."):
                continue
            walk = walk / part
            if walk.is_symlink():
                raise ValueError(f"Symlink component rejected in companion path '{raw_str}'.")
        target = walk
        if not target.resolve().is_relative_to(real_root):
            raise ValueError(
                f"Companion path '{raw_str}' escapes target repository root '{real_root}'."
            )
    else:
        _check_non_os_symlinks_in_abs_parts(cand.parts, raw_str)
        target = cand

    try:
        st = target.lstat()
    except OSError as exc:
        raise ValueError(f"Companion path '{raw_str}' is not accessible: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Companion path '{raw_str}' must be a non-symlink regular file.")
    if st.st_size > max_bytes:
        raise ValueError(
            f"Companion path '{raw_str}' ({st.st_size} bytes) exceeds {max_bytes}-byte limit."
        )
    return target


def read_safe_companion_bytes(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_COMPANION_BYTES,
) -> tuple[Path, bytes]:
    """Read raw companion bytes after enforcing symlink, containment, and size bounds."""
    safe_path = resolve_safe_companion_path(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        max_bytes=max_bytes,
    )
    data = safe_path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"Companion path '{raw_path}' exceeds {max_bytes}-byte limit.")
    return safe_path, data


def read_safe_companion_text(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_COMPANION_BYTES,
) -> str:
    """Read UTF-8 companion text after enforcing symlink, containment, and size bounds."""
    _, data = read_safe_companion_bytes(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        max_bytes=max_bytes,
    )
    return data.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class ValidationDiagnostic:
    raw_line: str
    kind: ValidationErrorKind
    var_index: int | None = None
    constraint_index: int | None = None
    symbol_name: str | None = None
    domain_bounds: tuple[int, int] | None = None


@dataclass(frozen=True)
class IncumbentStep:
    step_index: int
    wall_time: float
    objective: float
    best_bound: float | None = None
    worker: str = "portfolio"
    source: Literal["solve_log", "telemetry_jsonl"] = "solve_log"
    lns_accepted: int | None = None
    lns_trials: int | None = None


@dataclass(frozen=True)
class SolverRunSummary:
    run_index: int
    model_name: str = ""
    status: str | None = None
    objective: float | None = None
    best_bound: float | None = None
    booleans: int | None = None
    conflicts: int | None = None
    branches: int | None = None
    walltime: float | None = None
    closed_by_presolve: bool = False
    root_lp_infeasible: bool = False


@dataclass(frozen=True)
class CpModelProtoSummary:
    name: str = ""
    variable_names: tuple[str, ...] = ()
    variable_domains: tuple[tuple[int, int] | None, ...] = ()
    constraint_names: tuple[str, ...] = ()
    constraint_kinds: tuple[str, ...] = ()
    constraint_vars: tuple[tuple[int, ...], ...] = ()
    constraint_enforcement_literals: tuple[tuple[int, ...], ...] = ()
    objective_vars: tuple[int, ...] = ()
    assumptions: tuple[int, ...] = ()

    def resolve_literal_var_index(self, literal: int) -> int:
        return literal if literal >= 0 else (-literal - 1)


@dataclass(frozen=True)
class CpSolverResponseSummary:
    status: str | None = None
    objective_value: float | None = None
    best_objective_bound: float | None = None
    sufficient_assumptions_for_infeasibility: tuple[int, ...] = ()
    num_booleans: int | None = None
    num_conflicts: int | None = None
    num_branches: int | None = None
    wall_time: float | None = None
    solve_log: str = ""
    user_time: float | None = None
    deterministic_time: float | None = None
    solution_info: str = ""


@dataclass(frozen=True)
class ParsedSolverSession:
    line_count: int = 0
    telemetry_event_count: int = 0
    solver_runs: tuple[SolverRunSummary, ...] = ()
    model_name: str = ""
    initial_variables: int | None = None
    initial_booleans: int | None = None
    initial_constraints: int | None = None
    initial_constraint_families: dict[str, int] = field(default_factory=dict)
    expanded_variables: int | None = None
    expanded_constraints: int | None = None
    presolved_variables: int | None = None
    presolved_constraints: int | None = None
    presolve_started: bool = False
    presolve_rules_applied: tuple[str, ...] = ()
    symmetry_summary: str | None = None
    closed_by_presolve: bool = False
    presolve_contradictions: tuple[str, ...] = ()
    implicated_symbols: tuple[str, ...] = ()
    search_started: bool = False
    workers_configured: int | None = None
    portfolio_subsolvers: tuple[str, ...] = ()
    root_lp_infeasible: bool = False
    incumbents: tuple[IncumbentStep, ...] = ()
    best_bound_history: tuple[tuple[float, float], ...] = ()
    validation_errors: tuple[ValidationDiagnostic, ...] = ()
    coefficient_ranges: tuple[tuple[str, float, float], ...] = ()
    lns_zero_acceptance_workers: tuple[str, ...] = ()
    max_observed_walltime: float = 0.0
    last_incumbent_walltime: float | None = None
    explicit_stall_reported: bool = False
    final_status: str | None = None
    final_objective: float | None = None
    final_best_bound: float | None = None
    final_booleans: int | None = None
    final_conflicts: int | None = None
    final_branches: int | None = None
    final_walltime: float | None = None
    sufficient_assumptions: tuple[int, ...] = ()


_INT_CLEAN_RE = re.compile(r"[,\s_]")
_MODEL_HEADER_RE = re.compile(
    r"^(Initial|Expanded|Presolved)\s+(?:optimization|satisfaction)\s+model\s+'([^']*)'",
    re.IGNORECASE,
)
_VARIABLES_RE = re.compile(
    r"^#Variables:\s*([\d,]+)(?:.*?#bools:\s*([\d,]+))?",
    re.IGNORECASE,
)
_KCONSTRAINT_RE = re.compile(r"^#(k[A-Za-z0-9_]+):\s*([\d,]+)")
_MODEL_PROGRESS_RE = re.compile(
    r"^#Model\s+([\d.]+)s\s+var:([\d,]+)/([\d,]+)\s+constraints:([\d,]+)/([\d,]+)",
    re.IGNORECASE,
)
_PRESOLVED_HAS_RE = re.compile(
    r"Presolved model has\s+([\d,]+)\s+variables\s+and\s+([\d,]+)\s+constraints",
    re.IGNORECASE,
)
_EXPANDED_HAS_RE = re.compile(
    r"Expanded model has\s+([\d,]+)\s+variables(?:\s+and\s+([\d,]+)\s+constraints)?",
    re.IGNORECASE,
)
_PRESOLVE_RULE_RE = re.compile(r"rule\s+'([^']+)'\s+was applied", re.IGNORECASE)
_COEFF_RANGE_RE = re.compile(
    r"(Objective(?:\s+coefficients?(?:\s+range)?)?|Linear constraint matrix|(?:[A-Za-z0-9_]+\s+){0,4}coefficients?(?:\s+range)?)"
    r"[^\[\n]{0,120}\[\s*([+-]?\d+(?:\.\d+)?(?:e[+-]?\d+)?)\s*,\s*([+-]?\d+(?:\.\d+)?(?:e[+-]?\d+)?)\s*\]",
    re.IGNORECASE,
)
_INCUMBENT_RE = re.compile(
    r"^#(\d+)\s+([\d.]+)s\s+best:([+-]?(?:\d+(?:\.\d+)?(?:e[+-]?\d+)?|inf))\s+"
    r"next:\[\s*([^,\]]*)\s*,\s*([^\]]*)\]\s*(.*)$",
    re.IGNORECASE,
)
_BOUND_RE = re.compile(
    r"^#Bound\s+([\d.]+)s\s+best:([+-]?(?:\d+(?:\.\d+)?(?:e[+-]?\d+)?|inf))\s+"
    r"next:\[\s*([+-]?\d+(?:\.\d+)?(?:e[+-]?\d+)?)\s*,[^\]]*\]\s*(.*)$",
    re.IGNORECASE,
)
_DONE_RE = re.compile(r"^#Done\s+([\d.]+)s\s*(.*)$", re.IGNORECASE)
_WORKERS_RE = re.compile(
    r"(?:Setting number of workers to|with)\s+(\d+)\s*workers?",
    re.IGNORECASE,
)
_SUBSOLVERS_RE = re.compile(r"subsolvers:\s*\[([^\]]+)\]", re.IGNORECASE)
_SUMMARY_KV_RE = re.compile(
    r"^(status|objective|best_bound|booleans|conflicts|branches|walltime):\s*(.+)$",
    re.IGNORECASE,
)
_ASSUMPTIONS_LINE_RE = re.compile(
    r"sufficient_assumptions_for_infeasibility\s*:\s*\[([^\]]*)\]",
    re.IGNORECASE,
)
_LNS_STATS_RE = re.compile(
    r"^\s*'?(?P<worker>[a-z0-9_]{1,80})'?\s*:[^\n]{0,160}?"
    r"(?:(?P<acc>\d+)\s*/\s*(?P<tot>\d+)|improves:\s*(?P<imp>\d+)/(?P<calls>\d+)|0\.00%\s+accepted)",
    re.IGNORECASE,
)
_VAR_IDX_RE = re.compile(r"\bvar(?:iable)?\s*#?(\d+)\b", re.IGNORECASE)
_CST_IDX_RE = re.compile(r"\b(?:constraint|interval)\s*#?(\d+)\b", re.IGNORECASE)
_QUOTED_SYM_RE = re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_\[\]:.-]{1,96})['\"]")
_DOMAIN_PAIR_RE = re.compile(r"\[\s*([+-]?\d+)\s*,\s*([+-]?\d+)\s*\]")


def _parse_int(raw: str) -> int:
    return int(_INT_CLEAN_RE.sub("", raw))


def _parse_opt_float(raw: str) -> float | None:
    cleaned = raw.strip().rstrip("s")
    if not cleaned or cleaned.upper() in ("NA", "N/A", "NONE", "INF", "+INF", "-INF"):
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


class IncrementalSolverLogParser:
    """Single incremental parser driving both live `watch-solver` tailing and offline replay."""

    def __init__(self) -> None:
        self._line_count = 0
        self._telemetry_count = 0
        self._completed_runs: list[SolverRunSummary] = []
        self._run_index = 0
        self._in_run = False
        self._model_section: Literal["initial", "expanded", "presolved"] = "initial"
        self._in_summary = False
        self._in_validation_block = False

        self._model_name = ""
        self._initial_vars: int | None = None
        self._initial_bools: int | None = None
        self._initial_csts = 0
        self._initial_families: dict[str, int] = {}
        self._expanded_vars: int | None = None
        self._expanded_csts: int | None = None
        self._presolved_vars: int | None = None
        self._presolved_csts: int | None = None

        self._presolve_started = False
        self._presolve_rules: list[str] = []
        self._symmetry_summary: str | None = None
        self._closed_by_presolve = False
        self._presolve_contradictions: list[str] = []
        self._implicated_symbols: list[str] = []

        self._search_started = False
        self._workers: int | None = None
        self._subsolvers: list[str] = []
        self._root_lp_infeasible = False
        self._done_worker: str = ""

        self._incumbents: list[IncumbentStep] = []
        self._bound_history: list[tuple[float, float]] = []
        self._latest_bound: float | None = None
        self._validation_errors: list[ValidationDiagnostic] = []
        self._coeff_ranges: list[tuple[str, float, float]] = []
        self._lns_zero_workers: list[str] = []
        self._max_walltime = 0.0
        self._last_incumbent_walltime: float | None = None
        self._explicit_stall = False

        self._run_closed_by_presolve = False
        self._run_root_lp_infeasible = False
        self._run_status: str | None = None
        self._run_obj: float | None = None
        self._run_bound: float | None = None
        self._run_bools: int | None = None
        self._run_conflicts: int | None = None
        self._run_branches: int | None = None
        self._run_walltime: float | None = None
        self._assumptions: list[int] = []

    def _flush_current_run(self) -> None:
        if not self._in_run and self._run_status is None and not self._model_name:
            return
        idx = max(1, self._run_index)
        summary = SolverRunSummary(
            run_index=idx,
            model_name=self._model_name,
            status=self._run_status,
            objective=self._run_obj,
            best_bound=self._run_bound,
            booleans=self._run_bools,
            conflicts=self._run_conflicts,
            branches=self._run_branches,
            walltime=self._run_walltime,
            closed_by_presolve=self._run_closed_by_presolve,
            root_lp_infeasible=self._run_root_lp_infeasible,
        )
        if self._completed_runs and self._completed_runs[-1].run_index == idx:
            self._completed_runs[-1] = summary
        else:
            self._completed_runs.append(summary)

    def feed_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.feed_line(line)

    def feed_line(self, raw_line: str) -> None:
        stripped = raw_line.strip()
        if not stripped:
            return
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                obj = json.loads(stripped[:65536])
            except (ValueError, RecursionError):
                obj = None
            if isinstance(obj, dict) and ("event" in obj or "step" in obj or "objective" in obj):
                self._ingest_telemetry_obj(obj)
                return

        self._line_count += 1
        lower = stripped.lower()

        if lower.startswith("starting cp-sat solver"):
            if self._in_run or self._run_status is not None:
                self._flush_current_run()
            self._run_index += 1
            self._in_run = True
            self._in_summary = False
            self._in_validation_block = False
            self._model_section = "initial"
            self._run_status = None
            self._run_obj = None
            self._run_bound = None
            self._run_bools = None
            self._run_conflicts = None
            self._run_branches = None
            self._run_walltime = None
            self._run_closed_by_presolve = False
            self._run_root_lp_infeasible = False
            return

        if lower.startswith("cpsolverresponse summary"):
            self._in_summary = True
            self._in_validation_block = False
            return

        if self._in_summary:
            kv = _SUMMARY_KV_RE.match(stripped)
            if kv:
                key, val = kv.group(1).lower(), kv.group(2).strip()
                if key == "status":
                    self._run_status = val.split()[0].upper()
                elif key == "objective":
                    self._run_obj = _parse_opt_float(val)
                elif key == "best_bound":
                    self._run_bound = _parse_opt_float(val)
                elif key == "booleans":
                    self._run_bools = _parse_int(val.split()[0])
                elif key == "conflicts":
                    self._run_conflicts = _parse_int(val.split()[0])
                elif key == "branches":
                    self._run_branches = _parse_int(val.split()[0])
                elif key == "walltime":
                    wt = _parse_opt_float(val.split()[0])
                    if wt is not None:
                        self._run_walltime = wt
                        self._max_walltime = max(self._max_walltime, wt)
                self._flush_current_run()
                return

        assump_m = _ASSUMPTIONS_LINE_RE.search(stripped)
        if assump_m:
            for tok in assump_m.group(1).split(","):
                tok_s = tok.strip()
                if tok_s and (tok_s.lstrip("+-").isdigit()):
                    lit = int(tok_s)
                    if lit not in self._assumptions:
                        self._assumptions.append(lit)
            return

        self._parse_stage_line(stripped[:2048], lower[:2048])

    def _parse_stage_line(self, stripped: str, lower: str) -> None:
        mh = _MODEL_HEADER_RE.match(stripped)
        if mh:
            stage, mname = mh.group(1).lower(), mh.group(2)
            if mname and not self._model_name:
                self._model_name = mname
            if stage.startswith("init"):
                self._model_section = "initial"
            elif stage.startswith("expand"):
                self._model_section = "expanded"
            else:
                self._model_section = "presolved"
            return

        vm = _VARIABLES_RE.match(stripped)
        if vm:
            vcount = _parse_int(vm.group(1))
            bcount = _parse_int(vm.group(2)) if vm.group(2) else None
            if self._model_section == "initial":
                self._initial_vars = vcount
                if bcount is not None:
                    self._initial_bools = bcount
            elif self._model_section == "expanded":
                self._expanded_vars = vcount
            else:
                self._presolved_vars = vcount
            return

        km = _KCONSTRAINT_RE.match(stripped)
        if km:
            fam, ccount = km.group(1), _parse_int(km.group(2))
            if self._model_section == "initial":
                self._initial_families[fam] = ccount
                self._initial_csts = sum(self._initial_families.values())
            elif self._model_section == "expanded":
                self._expanded_csts = (self._expanded_csts or 0) + ccount
            else:
                self._presolved_csts = (self._presolved_csts or 0) + ccount
            return

        mp = _MODEL_PROGRESS_RE.match(stripped)
        if mp:
            wt = float(mp.group(1))
            self._max_walltime = max(self._max_walltime, wt)
            self._presolve_started = True
            self._presolved_vars = _parse_int(mp.group(2))
            if self._initial_vars is None:
                self._initial_vars = _parse_int(mp.group(3))
            self._presolved_csts = _parse_int(mp.group(4))
            if self._initial_csts == 0:
                self._initial_csts = _parse_int(mp.group(5))
            return

        eh = _EXPANDED_HAS_RE.search(stripped)
        if eh:
            self._presolve_started = True
            self._expanded_vars = _parse_int(eh.group(1))
            if eh.group(2):
                self._expanded_csts = _parse_int(eh.group(2))
            return

        ph = _PRESOLVED_HAS_RE.search(stripped)
        if ph:
            self._presolve_started = True
            self._presolved_vars = _parse_int(ph.group(1))
            self._presolved_csts = _parse_int(ph.group(2))
            return

        if "starting presolve" in lower or lower.startswith("presolve summary"):
            self._presolve_started = True
            return

        pr = _PRESOLVE_RULE_RE.search(stripped)
        if pr:
            self._presolve_started = True
            rule_name = pr.group(1)
            if rule_name not in self._presolve_rules:
                self._presolve_rules.append(rule_name)
            if "empty domain" in rule_name.lower() or "infeasible" in rule_name.lower():
                self._presolve_contradictions.append(stripped)
            return

        if "symmetry" in lower and ("generator" in lower or "orbit" in lower or "symmetry" in lower):
            self._symmetry_summary = stripped
            return

        if (
            "model is invalid" in lower
            or "validatecpmodel" in lower
            or lower.startswith("invalid model")
            or (self._in_validation_block and ("var" in lower or "constraint" in lower or "overflow" in lower or "interval" in lower or "domain" in lower))
            or ("invalid domain" in lower or "inverted domain" in lower or "negative size" in lower or "integer overflow" in lower)
        ):
            self._in_validation_block = True
            if self._run_status is None:
                self._run_status = "MODEL_INVALID"
            self._record_validation_diagnostic(stripped, lower)
            return

        if "problem closed by presolve" in lower or "unsat after presolve" in lower:
            self._presolve_started = True
            self._closed_by_presolve = True
            self._run_closed_by_presolve = True
            for qsym in _QUOTED_SYM_RE.findall(stripped):
                if qsym not in self._implicated_symbols:
                    self._implicated_symbols.append(qsym)
            return

        if self._presolve_started and not self._search_started and (
            "infeasible" in lower or "contradiction" in lower or "empty domain" in lower
        ):
            self._presolve_contradictions.append(stripped)
            for qsym in _QUOTED_SYM_RE.findall(stripped):
                if qsym not in self._implicated_symbols:
                    self._implicated_symbols.append(qsym)
            return

        if "[" in stripped and "]" in stripped:
            cr = _COEFF_RANGE_RE.search(stripped)
            if cr:
                lo_c, hi_c = float(cr.group(2)), float(cr.group(3))
                self._coeff_ranges.append((cr.group(1).strip(), lo_c, hi_c))
                return

        wm = _WORKERS_RE.search(stripped)
        if wm:
            self._workers = int(wm.group(1))
        if "starting search" in lower:
            self._search_started = True
            return

        sm = _SUBSOLVERS_RE.search(stripped)
        if sm:
            for item in sm.group(1).split(","):
                name = item.strip().strip("'\"")
                if name and name not in self._subsolvers:
                    self._subsolvers.append(name)
            return

        if "root lp" in lower and "infeasible" in lower:
            self._search_started = True
            self._root_lp_infeasible = True
            self._run_root_lp_infeasible = True
            return

        inc = _INCUMBENT_RE.match(stripped)
        if inc:
            self._search_started = True
            step_no = int(inc.group(1))
            wt = float(inc.group(2))
            obj = _parse_opt_float(inc.group(3))
            nxt_lo = _parse_opt_float(inc.group(4))
            worker_raw = inc.group(6).strip() or "portfolio"
            worker = worker_raw.split()[0]
            self._max_walltime = max(self._max_walltime, wt)
            if nxt_lo is not None:
                self._latest_bound = nxt_lo
                self._bound_history.append((wt, nxt_lo))
            if obj is not None:
                self._last_incumbent_walltime = wt
                self._incumbents.append(
                    IncumbentStep(
                        step_index=step_no,
                        wall_time=wt,
                        objective=obj,
                        best_bound=self._latest_bound,
                        worker=worker,
                        source="solve_log",
                    )
                )
            return

        bnd = _BOUND_RE.match(stripped)
        if bnd:
            self._search_started = True
            wt = float(bnd.group(1))
            lo = float(bnd.group(3))
            self._max_walltime = max(self._max_walltime, wt)
            self._latest_bound = lo
            self._bound_history.append((wt, lo))
            return

        dn = _DONE_RE.match(stripped)
        if dn:
            wt = float(dn.group(1))
            self._max_walltime = max(self._max_walltime, wt)
            self._done_worker = dn.group(2).strip().lower()
            if (
                not self._closed_by_presolve
                and any(tok in self._done_worker for tok in ("default_lp", "root_lp", "probing", "initial_domain"))
                and not self._incumbents
            ):
                self._done_worker = self._done_worker or "default_lp"
            return

        if "lns" in lower and ":" in stripped:
            lns_m = _LNS_STATS_RE.match(stripped)
            if lns_m and "lns" in lns_m.group("worker").lower():
                wname = lns_m.group("worker")
                acc = lns_m.group("acc") or lns_m.group("imp")
                tot = lns_m.group("tot") or lns_m.group("calls")
                is_zero = (acc is not None and tot is not None and int(acc) == 0 and int(tot) >= 5) or (
                    "0.00% accepted" in lower
                )
                if is_zero and wname not in self._lns_zero_workers:
                    self._lns_zero_workers.append(wname)

    def _record_validation_diagnostic(self, stripped: str, lower: str) -> None:
        v_match = _VAR_IDX_RE.search(stripped)
        c_match = _CST_IDX_RE.search(stripped)
        q_syms = _QUOTED_SYM_RE.findall(stripped)
        dom_m = _DOMAIN_PAIR_RE.search(stripped)
        bounds: tuple[int, int] | None = None
        if dom_m:
            bounds = (int(dom_m.group(1)), int(dom_m.group(2)))

        kind: ValidationErrorKind = "invalid_model"
        if "overflow" in lower:
            kind = "coefficient_overflow"
        elif "interval" in lower or "size" in lower:
            kind = "invalid_interval"
        elif (bounds is not None and bounds[0] > bounds[1]) or "inverted" in lower or "invalid domain" in lower or "lb > ub" in lower:
            kind = "inverted_bounds"

        sym = q_syms[0] if q_syms else None
        if sym and sym not in self._implicated_symbols:
            self._implicated_symbols.append(sym)
        if kind == "invalid_model" and v_match is None and c_match is None and sym is None and self._validation_errors:
            return
        diag = ValidationDiagnostic(
            raw_line=stripped[:240],
            kind=kind,
            var_index=int(v_match.group(1)) if v_match else None,
            constraint_index=int(c_match.group(1)) if c_match else None,
            symbol_name=sym,
            domain_bounds=bounds,
        )
        if (
            len(self._validation_errors) == 1
            and self._validation_errors[0].kind == "invalid_model"
            and self._validation_errors[0].var_index is None
            and self._validation_errors[0].constraint_index is None
            and self._validation_errors[0].symbol_name is None
            and (diag.kind != "invalid_model" or diag.var_index is not None or diag.constraint_index is not None or diag.symbol_name is not None)
        ):
            self._validation_errors[0] = diag
        else:
            self._validation_errors.append(diag)

    def feed_telemetry_jsonl_line(self, raw_line: str) -> None:
        stripped = raw_line.strip()
        if not stripped:
            return
        payload = json.loads(stripped)
        if not isinstance(payload, dict):
            raise TypeError("Telemetry JSONL line must decode to a JSON object.")
        self._ingest_telemetry_obj(payload)

    def _ingest_telemetry_obj(self, obj: dict[str, Any]) -> None:
        self._telemetry_count += 1
        ev_type = str(obj.get("event") or "incumbent").lower()
        wt_raw = obj.get("wall_time") if "wall_time" in obj else obj.get("walltime")
        wt = float(wt_raw) if isinstance(wt_raw, (int, float)) and not isinstance(wt_raw, bool) else self._max_walltime
        self._max_walltime = max(self._max_walltime, wt)

        bnd_raw = obj.get("best_bound") if "best_bound" in obj else obj.get("best_objective_bound")
        bnd = float(bnd_raw) if isinstance(bnd_raw, (int, float)) and not isinstance(bnd_raw, bool) else self._latest_bound
        if bnd is not None:
            self._latest_bound = bnd
            self._bound_history.append((wt, bnd))

        worker = str(obj.get("worker") or "callback").strip() or "callback"
        lns_acc = obj.get("lns_accepted")
        lns_tot = obj.get("lns_trials")
        if (
            isinstance(lns_acc, int)
            and lns_acc == 0
            and isinstance(lns_tot, int)
            and lns_tot >= 5
            and "lns" in worker.lower()
            and worker not in self._lns_zero_workers
        ):
            self._lns_zero_workers.append(worker)

        if ev_type == "stall":
            self._explicit_stall = True
            return

        obj_raw = obj.get("objective") if "objective" in obj else obj.get("objective_value")
        if isinstance(obj_raw, (int, float)) and not isinstance(obj_raw, bool):
            self._search_started = True
            self._last_incumbent_walltime = wt
            step_idx = int(obj["step"]) if isinstance(obj.get("step"), int) and not isinstance(obj.get("step"), bool) else len(self._incumbents) + 1
            self._incumbents.append(
                IncumbentStep(
                    step_index=step_idx,
                    wall_time=wt,
                    objective=float(obj_raw),
                    best_bound=bnd,
                    worker=worker,
                    source="telemetry_jsonl",
                    lns_accepted=int(lns_acc) if isinstance(lns_acc, int) else None,
                    lns_trials=int(lns_tot) if isinstance(lns_tot, int) else None,
                )
            )

    def apply_response_summary(self, resp: CpSolverResponseSummary) -> None:
        if resp.solve_log:
            self.feed_lines(resp.solve_log.splitlines())
        if resp.status:
            self._run_status = resp.status.strip().upper()
        if resp.objective_value is not None:
            self._run_obj = resp.objective_value
        if resp.best_objective_bound is not None:
            self._run_bound = resp.best_objective_bound
        if resp.num_booleans is not None:
            self._run_bools = resp.num_booleans
        if resp.num_conflicts is not None:
            self._run_conflicts = resp.num_conflicts
        if resp.num_branches is not None:
            self._run_branches = resp.num_branches
        if resp.wall_time is not None:
            self._run_walltime = resp.wall_time
            self._max_walltime = max(self._max_walltime, resp.wall_time)
        for lit in resp.sufficient_assumptions_for_infeasibility:
            if lit not in self._assumptions:
                self._assumptions.append(lit)
        self._flush_current_run()

    def is_terminal(self) -> bool:
        return bool(
            self._run_status in ("OPTIMAL", "FEASIBLE", "INFEASIBLE", "MODEL_INVALID")
            or self._validation_errors
        )

    def snapshot(self) -> ParsedSolverSession:
        self._flush_current_run()
        final_status = self._run_status
        if final_status is None and self._validation_errors:
            final_status = "MODEL_INVALID"
        root_lp_inf = self._root_lp_infeasible or bool(
            final_status == "INFEASIBLE"
            and not self._closed_by_presolve
            and (self._run_conflicts == 0)
            and (self._run_branches in (0, None))
        )
        return ParsedSolverSession(
            line_count=self._line_count,
            telemetry_event_count=self._telemetry_count,
            solver_runs=tuple(self._completed_runs),
            model_name=self._model_name,
            initial_variables=self._initial_vars,
            initial_booleans=self._initial_bools,
            initial_constraints=self._initial_csts if self._initial_csts > 0 else None,
            initial_constraint_families=dict(self._initial_families),
            expanded_variables=self._expanded_vars,
            expanded_constraints=self._expanded_csts,
            presolved_variables=self._presolved_vars,
            presolved_constraints=self._presolved_csts,
            presolve_started=self._presolve_started,
            presolve_rules_applied=tuple(self._presolve_rules),
            symmetry_summary=self._symmetry_summary,
            closed_by_presolve=self._closed_by_presolve,
            presolve_contradictions=tuple(self._presolve_contradictions),
            implicated_symbols=tuple(self._implicated_symbols),
            search_started=self._search_started,
            workers_configured=self._workers,
            portfolio_subsolvers=tuple(self._subsolvers),
            root_lp_infeasible=root_lp_inf,
            incumbents=tuple(self._incumbents),
            best_bound_history=tuple(self._bound_history),
            validation_errors=tuple(self._validation_errors),
            coefficient_ranges=tuple(self._coeff_ranges),
            lns_zero_acceptance_workers=tuple(self._lns_zero_workers),
            max_observed_walltime=self._max_walltime,
            last_incumbent_walltime=self._last_incumbent_walltime,
            explicit_stall_reported=self._explicit_stall,
            final_status=final_status,
            final_objective=self._run_obj,
            final_best_bound=self._run_bound if self._run_bound is not None else self._latest_bound,
            final_booleans=self._run_bools,
            final_conflicts=self._run_conflicts,
            final_branches=self._run_branches,
            final_walltime=self._run_walltime if self._run_walltime is not None else (self._max_walltime or None),
            sufficient_assumptions=tuple(self._assumptions),
        )


def parse_solve_log_text(text: str) -> ParsedSolverSession:
    """Parse a complete CP-SAT solve_log string using the unified incremental parser."""
    parser = IncrementalSolverLogParser()
    parser.feed_lines(text.splitlines())
    return parser.snapshot()


_PBTXT_STR_RE = re.compile(r'^\s*([a-zA-Z0-9_]+)\s*:\s*"((?:\\.|[^"\\])*)"\s*$')
_PBTXT_STR_CONT_RE = re.compile(r'^\s*"((?:\\.|[^"\\])*)"\s*$')
_PBTXT_SCALAR_RE = re.compile(r"^\s*([a-zA-Z0-9_]+)\s*:\s*([A-Za-z0-9_.+-]+)\s*$")
_PBTXT_BLOCK_OPEN_RE = re.compile(r"^\s*([a-zA-Z0-9_]+)\s*\{\s*$")
_SIMPLE_PBTXT_ESCAPES: Final[dict[str, str]] = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "?": "?",
}


def _unescape_pbtxt_string(raw: str) -> str:
    """Safely decode `.pbtxt` string escapes without `unicode_escape` crashes or UTF-8 mojibake."""
    out: list[str] = []
    byte_buf = bytearray()
    i = 0
    n = len(raw)

    def _flush_bytes() -> None:
        if byte_buf:
            out.append(byte_buf.decode("utf-8", errors="replace"))
            byte_buf.clear()

    while i < n:
        ch = raw[i]
        if ch != "\\":
            _flush_bytes()
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            _flush_bytes()
            out.append("\\")
            break
        nxt = raw[i + 1]
        if nxt in _SIMPLE_PBTXT_ESCAPES:
            _flush_bytes()
            out.append(_SIMPLE_PBTXT_ESCAPES[nxt])
            i += 2
            continue
        if nxt == "x" and i + 3 < n and all(c in "0123456789abcdefABCDEF" for c in raw[i + 2 : i + 4]):
            byte_buf.append(int(raw[i + 2 : i + 4], 16))
            i += 4
            continue
        if nxt in "01234567":
            j = i + 1
            while j < min(i + 4, n) and raw[j] in "01234567":
                j += 1
            byte_buf.append(int(raw[i + 1 : j], 8) & 0xFF)
            i = j
            continue
        _flush_bytes()
        out.append("\\" + nxt)
        i += 2
    _flush_bytes()
    return "".join(out)


def _strip_pbtxt_comment(line: str) -> str:
    in_quote = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_quote:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
        elif ch == "#":
            return line[:i]
        i += 1
    return line
_PBTXT_CST_KINDS = frozenset(
    {
        "bool_or",
        "bool_and",
        "bool_xor",
        "at_most_one",
        "exactly_one",
        "int_div",
        "int_mod",
        "int_max",
        "int_min",
        "lin_max",
        "int_prod",
        "linear",
        "all_diff",
        "element",
        "circuit",
        "routes",
        "table",
        "automaton",
        "inverse",
        "reservoir",
        "interval",
        "no_overlap",
        "no_overlap_2d",
        "cumulative",
        "dummy_constraint",
    }
)

_CST_JSON_KEY_TO_KIND: dict[str, str] = {
    **{k: k for k in _PBTXT_CST_KINDS},
    "boolOr": "bool_or",
    "boolAnd": "bool_and",
    "boolXor": "bool_xor",
    "atMostOne": "at_most_one",
    "exactlyOne": "exactly_one",
    "intDiv": "int_div",
    "intMod": "int_mod",
    "intMax": "int_max",
    "intMin": "int_min",
    "linMax": "lin_max",
    "intProd": "int_prod",
    "allDiff": "all_diff",
    "noOverlap": "no_overlap",
    "noOverlap2d": "no_overlap_2d",
    "noOverlap2D": "no_overlap_2d",
    "dummyConstraint": "dummy_constraint",
}

_DIRECT_VAR_OR_LIT_KEYS = (
    "vars",
    "literals",
    "f_direct",
    "fDirect",
    "f_inverse",
    "fInverse",
    "active_literals",
    "activeLiterals",
    "index",
)

_HYBRID_VAR_OR_EXPR_KEYS = (
    "target",
    "start",
    "size",
    "end",
)

_LINEAR_EXPR_ONLY_KEYS = (
    "exprs",
    "demands",
    "capacity",
    "linear_index",
    "linearIndex",
    "linear_target",
    "linearTarget",
    "time_exprs",
    "timeExprs",
    "level_changes",
    "levelChanges",
)


def _parse_protojson_int(raw: Any) -> int | None:
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float) and raw.is_integer():
        return int(raw)
    if isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            return None
        try:
            return int(cleaned, 10)
        except ValueError:
            return None
    return None


def _parse_protojson_int_list(raw: Any) -> list[int]:
    if not isinstance(raw, list):
        return []
    out: list[int] = []
    for item in raw:
        parsed = _parse_protojson_int(item)
        if parsed is not None:
            out.append(parsed)
    return out


def _extract_submsg_var_refs(sub: dict[str, Any]) -> list[int]:
    v_refs: list[int] = []
    for vk in _DIRECT_VAR_OR_LIT_KEYS:
        if vk not in sub:
            continue
        vv = sub[vk]
        single = _parse_protojson_int(vv)
        if single is not None:
            v_refs.append(single)
        elif isinstance(vv, list):
            v_refs.extend(_parse_protojson_int_list(vv))
    for hk in _HYBRID_VAR_OR_EXPR_KEYS:
        if hk not in sub:
            continue
        hv = sub[hk]
        single = _parse_protojson_int(hv)
        if single is not None:
            v_refs.append(single)
        elif isinstance(hv, dict) and "vars" in hv:
            v_refs.extend(_parse_protojson_int_list(hv.get("vars")))
    for ek in _LINEAR_EXPR_ONLY_KEYS:
        if ek not in sub:
            continue
        ev = sub[ek]
        if isinstance(ev, dict) and "vars" in ev:
            v_refs.extend(_parse_protojson_int_list(ev.get("vars")))
        elif isinstance(ev, list):
            for elem in ev:
                if isinstance(elem, dict) and "vars" in elem:
                    v_refs.extend(_parse_protojson_int_list(elem.get("vars")))
    return v_refs


def _first_present(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _opt_protojson_int(mapping: dict[str, Any], *keys: str) -> int | None:
    raw = _first_present(mapping, *keys)
    return _parse_protojson_int(raw)


def _opt_protojson_float(mapping: dict[str, Any], *keys: str) -> float | None:
    raw = _first_present(mapping, *keys)
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        return _parse_opt_float(raw)
    return None


def _check_json_depth(root: Any, max_depth: int = 64) -> None:
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        cur, d = stack.pop()
        if d > max_depth:
            raise ValueError(f"Corrupt or excessively nested JSON companion artifact (> {max_depth} levels).")
        if isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))


def parse_cp_model_proto_text(raw_text: str) -> CpModelProtoSummary:
    """Parse a `CpModelProto` JSON or `.pbtxt` text-format representation."""
    stripped = raw_text.strip()
    if not stripped:
        return CpModelProtoSummary()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except RecursionError as exc:
            raise ValueError("Corrupt or excessively nested CpModelProto JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("CpModelProto JSON root must be an object.")
        _check_json_depth(data)
        var_names: list[str] = []
        var_domains: list[tuple[int, int] | None] = []
        raw_vars = data.get("variables")
        for idx, v in enumerate(raw_vars if isinstance(raw_vars, list) else ()):
            if not isinstance(v, dict):
                continue
            var_names.append(str(v.get("name") or f"var_{idx}"))
            dom = v.get("domain")
            if isinstance(dom, list) and len(dom) >= 2:
                dom_ints = [_parse_protojson_int(x) for x in dom]
                if all(x is not None for x in dom_ints):
                    var_domains.append((int(dom_ints[0]), int(dom_ints[-1])))  # type: ignore[arg-type]
                else:
                    var_domains.append(None)
            else:
                var_domains.append(None)

        cst_names: list[str] = []
        cst_kinds: list[str] = []
        cst_vars: list[tuple[int, ...]] = []
        cst_enf: list[tuple[int, ...]] = []
        raw_csts = data.get("constraints")
        for idx, c in enumerate(raw_csts if isinstance(raw_csts, list) else ()):
            if not isinstance(c, dict):
                continue
            cst_names.append(str(c.get("name") or f"constraint_{idx}"))
            enf_raw = _first_present(c, "enforcement_literal", "enforcementLiteral")
            cst_enf.append(tuple(_parse_protojson_int_list(enf_raw)))
            ckind = "unknown"
            v_refs: list[int] = []
            for key_name, mapped_kind in _CST_JSON_KEY_TO_KIND.items():
                if key_name in c and isinstance(c[key_name], dict):
                    ckind = mapped_kind
                    v_refs = _extract_submsg_var_refs(c[key_name])
                    break
            cst_kinds.append(ckind)
            cst_vars.append(tuple(dict.fromkeys(v_refs)))

        obj = data.get("objective") if isinstance(data.get("objective"), dict) else {}
        fp_obj_raw = _first_present(data, "floating_point_objective", "floatingPointObjective")
        fp_obj = fp_obj_raw if isinstance(fp_obj_raw, dict) else {}
        obj_vars_list = _parse_protojson_int_list(obj.get("vars"))
        if not obj_vars_list and fp_obj:
            obj_vars_list = _parse_protojson_int_list(fp_obj.get("vars"))
        assumps = tuple(_parse_protojson_int_list(data.get("assumptions")))
        return CpModelProtoSummary(
            name=str(data.get("name") or ""),
            variable_names=tuple(var_names),
            variable_domains=tuple(var_domains),
            constraint_names=tuple(cst_names),
            constraint_kinds=tuple(cst_kinds),
            constraint_vars=tuple(cst_vars),
            constraint_enforcement_literals=tuple(cst_enf),
            objective_vars=tuple(obj_vars_list),
            assumptions=assumps,
        )

    return _parse_cp_model_pbtxt(stripped)


_PBTXT_TOKEN_RE = re.compile(
    r'[a-zA-Z0-9_]+\s*:\s*"(?:\\.|[^"\\])*"'
    r"|[a-zA-Z0-9_]+\s*:\s*\[[^\]]*\]"
    r"|[a-zA-Z0-9_]+\s*:\s*[A-Za-z0-9_.+-]+"
    r"|[a-zA-Z0-9_]+\s*:?\s*\{"
    r"|\}"
)
_PBTXT_LIST_RE = re.compile(r"^\s*([a-zA-Z0-9_]+)\s*:\s*\[([^\]]*)\]\s*$")
_PBTXT_LIN_EXPR_BLOCKS = frozenset(
    {
        "exprs",
        "target",
        "linear_index",
        "linear_target",
        "start",
        "end",
        "size",
        "demands",
        "capacity",
        "time_exprs",
        "level_changes",
    }
)


def _expand_pbtxt_statements(text: str) -> list[str]:
    stmts: list[str] = []
    for raw_ln in text.splitlines():
        uncommented = _strip_pbtxt_comment(raw_ln).strip()
        if not uncommented:
            continue
        for m in _PBTXT_TOKEN_RE.finditer(uncommented):
            tok = m.group(0).strip()
            if tok.endswith("{") and tok != "{":
                bname = tok[:-1].rstrip(": \t")
                stmts.append(f"{bname} {{")
            else:
                stmts.append(tok)
    return stmts


def _parse_cp_model_pbtxt(text: str) -> CpModelProtoSummary:
    model_name = ""
    var_names: list[str] = []
    var_domains: list[tuple[int, int] | None] = []
    cst_names: list[str] = []
    cst_kinds: list[str] = []
    cst_vars: list[tuple[int, ...]] = []
    cst_enf: list[tuple[int, ...]] = []
    obj_vars: list[int] = []
    fp_obj_vars: list[int] = []
    assumps: list[int] = []

    stack: list[str] = []
    cur_var_name = ""
    cur_var_dom: list[int] = []
    cur_cst_name = ""
    cur_cst_kind = "unknown"
    cur_cst_vars: list[int] = []
    cur_cst_enf: list[int] = []

    def _record_pbtxt_int(k: str, ival: int) -> None:
        if not stack and k == "assumptions":
            assumps.append(ival)
        elif stack == ["variables"] and k == "domain":
            cur_var_dom.append(ival)
        elif stack == ["objective"] and k == "vars":
            obj_vars.append(ival)
        elif stack == ["floating_point_objective"] and k == "vars":
            fp_obj_vars.append(ival)
        elif stack and stack[0] == "constraints":
            if len(stack) == 1 and k == "enforcement_literal":
                cur_cst_enf.append(ival)
            elif len(stack) == 2 and stack[1] in _PBTXT_CST_KINDS:
                if k in (
                    "vars",
                    "literals",
                    "f_direct",
                    "f_inverse",
                    "active_literals",
                    "index",
                    "target",
                    "start",
                    "size",
                    "end",
                ):
                    cur_cst_vars.append(ival)
            elif (
                len(stack) == 3
                and stack[1] in _PBTXT_CST_KINDS
                and stack[2] in _PBTXT_LIN_EXPR_BLOCKS
                and k == "vars"
            ):
                cur_cst_vars.append(ival)

    for ln in _expand_pbtxt_statements(text):
        bo = _PBTXT_BLOCK_OPEN_RE.match(ln)
        if bo:
            bname = bo.group(1)
            stack.append(bname)
            if len(stack) == 1 and bname == "variables":
                cur_var_name = ""
                cur_var_dom = []
            elif len(stack) == 1 and bname == "constraints":
                cur_cst_name = ""
                cur_cst_kind = "unknown"
                cur_cst_vars = []
                cur_cst_enf = []
            elif len(stack) == 2 and stack[0] == "constraints" and bname in _PBTXT_CST_KINDS:
                cur_cst_kind = bname
            continue
        if ln == "}":
            if stack:
                popped = stack.pop()
                if not stack and popped == "variables":
                    var_names.append(cur_var_name or f"var_{len(var_names)}")
                    var_domains.append((cur_var_dom[0], cur_var_dom[-1]) if len(cur_var_dom) >= 2 else None)
                elif not stack and popped == "constraints":
                    cst_names.append(cur_cst_name or f"constraint_{len(cst_names)}")
                    cst_kinds.append(cur_cst_kind)
                    cst_vars.append(tuple(dict.fromkeys(cur_cst_vars)))
                    cst_enf.append(tuple(cur_cst_enf))
            continue

        sm = _PBTXT_STR_RE.match(ln)
        if sm:
            k, sval = sm.group(1), _unescape_pbtxt_string(sm.group(2))
            if not stack and k == "name":
                model_name = sval
            elif stack == ["variables"] and k == "name":
                cur_var_name = sval
            elif stack == ["constraints"] and k == "name":
                cur_cst_name = sval
            continue

        lm = _PBTXT_LIST_RE.match(ln)
        if lm:
            lk = lm.group(1)
            for item_tok in lm.group(2).split(","):
                it = item_tok.strip()
                if it and it.lstrip("+-").isdigit():
                    _record_pbtxt_int(lk, int(it))
            continue

        scm = _PBTXT_SCALAR_RE.match(ln)
        if scm:
            k, rval = scm.group(1), scm.group(2)
            if rval.lstrip("+-").isdigit():
                _record_pbtxt_int(k, int(rval))

    return CpModelProtoSummary(
        name=model_name,
        variable_names=tuple(var_names),
        variable_domains=tuple(var_domains),
        constraint_names=tuple(cst_names),
        constraint_kinds=tuple(cst_kinds),
        constraint_vars=tuple(cst_vars),
        constraint_enforcement_literals=tuple(cst_enf),
        objective_vars=tuple(obj_vars or fp_obj_vars),
        assumptions=tuple(assumps),
    )


def parse_cp_solver_response_text(raw_text: str) -> CpSolverResponseSummary:
    """Parse a `CpSolverResponse` JSON or `.pbtxt` text-format representation."""
    stripped = raw_text.strip()
    if not stripped:
        return CpSolverResponseSummary()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except RecursionError as exc:
            raise ValueError("Corrupt or excessively nested CpSolverResponse JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("CpSolverResponse JSON root must be an object.")
        _check_json_depth(data)
        raw_status = data.get("status")
        status_map = {0: "UNKNOWN", 1: "MODEL_INVALID", 2: "FEASIBLE", 3: "INFEASIBLE", 4: "OPTIMAL"}
        if isinstance(raw_status, int) and not isinstance(raw_status, bool):
            status_str: str | None = status_map.get(raw_status, "UNKNOWN")
        elif isinstance(raw_status, str) and raw_status.strip().isdigit():
            status_str = status_map.get(int(raw_status.strip()), "UNKNOWN")
        else:
            status_str = str(raw_status).strip().upper() if raw_status else None
        assumps_raw = _first_present(
            data,
            "sufficient_assumptions_for_infeasibility",
            "sufficientAssumptionsForInfeasibility",
        )
        return CpSolverResponseSummary(
            status=status_str,
            objective_value=_opt_protojson_float(data, "objective_value", "objectiveValue"),
            best_objective_bound=_opt_protojson_float(
                data, "best_objective_bound", "bestObjectiveBound"
            ),
            sufficient_assumptions_for_infeasibility=tuple(_parse_protojson_int_list(assumps_raw)),
            num_booleans=_opt_protojson_int(data, "num_booleans", "numBooleans"),
            num_conflicts=_opt_protojson_int(data, "num_conflicts", "numConflicts"),
            num_branches=_opt_protojson_int(data, "num_branches", "numBranches"),
            wall_time=_opt_protojson_float(data, "wall_time", "wallTime"),
            solve_log=str(_first_present(data, "solve_log", "solveLog") or ""),
            user_time=_opt_protojson_float(data, "user_time", "userTime"),
            deterministic_time=_opt_protojson_float(
                data, "deterministic_time", "deterministicTime"
            ),
            solution_info=str(_first_present(data, "solution_info", "solutionInfo") or ""),
        )

    status_s: str | None = None
    obj_v: float | None = None
    bnd_v: float | None = None
    bools_v: int | None = None
    conf_v: int | None = None
    br_v: int | None = None
    wt_v: float | None = None
    ut_v: float | None = None
    dt_v: float | None = None
    sinfo = ""
    slog = ""
    last_str_key: str | None = None
    assumps_l: list[int] = []
    for raw_ln in stripped.splitlines():
        uncommented = _strip_pbtxt_comment(raw_ln)
        sm = _PBTXT_STR_RE.match(uncommented)
        if sm:
            last_str_key = sm.group(1)
            un_s = _unescape_pbtxt_string(sm.group(2))
            if last_str_key == "solve_log":
                slog += un_s
            elif last_str_key == "solution_info":
                sinfo += un_s
            continue
        cm = _PBTXT_STR_CONT_RE.match(uncommented)
        if cm and last_str_key in ("solve_log", "solution_info"):
            un_c = _unescape_pbtxt_string(cm.group(1))
            if last_str_key == "solve_log":
                slog += un_c
            else:
                sinfo += un_c
            continue
        last_str_key = None
        lm = _PBTXT_LIST_RE.match(uncommented)
        if lm and lm.group(1) == "sufficient_assumptions_for_infeasibility":
            for item_tok in lm.group(2).split(","):
                it = item_tok.strip()
                if it and it.lstrip("+-").isdigit():
                    assumps_l.append(int(it))
            continue
        scm = _PBTXT_SCALAR_RE.match(uncommented)
        if not scm:
            continue
        k, v = scm.group(1), scm.group(2)
        if k == "status":
            status_map = {0: "UNKNOWN", 1: "MODEL_INVALID", 2: "FEASIBLE", 3: "INFEASIBLE", 4: "OPTIMAL"}
            status_s = status_map.get(int(v), "UNKNOWN") if v.isdigit() else v.upper()
        elif k == "objective_value":
            obj_v = _parse_opt_float(v)
        elif k == "best_objective_bound":
            bnd_v = _parse_opt_float(v)
        elif k == "num_booleans" and v.lstrip("+-").isdigit():
            bools_v = int(v)
        elif k == "num_conflicts" and v.lstrip("+-").isdigit():
            conf_v = int(v)
        elif k == "num_branches" and v.lstrip("+-").isdigit():
            br_v = int(v)
        elif k == "wall_time":
            wt_v = _parse_opt_float(v)
        elif k == "user_time":
            ut_v = _parse_opt_float(v)
        elif k == "deterministic_time":
            dt_v = _parse_opt_float(v)
        elif k == "sufficient_assumptions_for_infeasibility" and v.lstrip("+-").isdigit():
            assumps_l.append(int(v))
    return CpSolverResponseSummary(
        status=status_s,
        objective_value=obj_v,
        best_objective_bound=bnd_v,
        sufficient_assumptions_for_infeasibility=tuple(assumps_l),
        num_booleans=bools_v,
        num_conflicts=conf_v,
        num_branches=br_v,
        wall_time=wt_v,
        solve_log=slog,
        user_time=ut_v,
        deterministic_time=dt_v,
        solution_info=sinfo,
    )


def parse_cp_model_proto_file(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_COMPANION_BYTES,
) -> CpModelProtoSummary:
    """Parse a `CpModelProto` JSON, `.pbtxt`, or binary `.pb` file safely."""
    from wythe_plugin_solver_chronicle._binary_proto import (
        is_binary_proto_payload,
        parse_binary_cp_model_proto,
    )

    safe_path, raw = read_safe_companion_bytes(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        max_bytes=max_bytes,
    )
    if is_binary_proto_payload(raw, safe_path):
        return parse_binary_cp_model_proto(raw)
    return parse_cp_model_proto_text(raw.decode("utf-8-sig", errors="replace"))


def parse_cp_solver_response_file(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_COMPANION_BYTES,
) -> CpSolverResponseSummary:
    """Parse a `CpSolverResponse` JSON, `.pbtxt`, or binary `.pb` file safely."""
    from wythe_plugin_solver_chronicle._binary_proto import (
        is_binary_proto_payload,
        parse_binary_cp_solver_response,
    )

    safe_path, raw = read_safe_companion_bytes(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        max_bytes=max_bytes,
    )
    if is_binary_proto_payload(raw, safe_path):
        return parse_binary_cp_solver_response(raw)
    return parse_cp_solver_response_text(raw.decode("utf-8-sig", errors="replace"))
