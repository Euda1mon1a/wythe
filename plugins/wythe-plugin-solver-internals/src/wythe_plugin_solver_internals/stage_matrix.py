"""7-stage `ConstraintProto` C++ pipeline coverage matrix and `SAT-INT-001` detector.

Traces every `ConstraintProto` `oneof constraint` case and `enforcement_literal` across
`Expand`, `Presolve`, `Symmetries`, `Loader`, `Cuts`, `LNS`, and `PropagatorInterface` /
`SatPropagator` C++ translation units plus optional `--index-store` USR artifacts.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.adapters.base import RawCandidateFinding
from wythe_plugin_solver_internals.proto_descriptor import (
    MAX_LINE_SCAN_CHARS,
    MAX_NESTING_DEPTH,
    MAX_SOLVER_FILE_BYTES,
    ConstraintCaseSpec,
    SolverProtoCatalog,
    check_json_depth,
    iter_safe_repo_files,
    load_safe_json,
    read_safe_artifact_text,
    strip_c_comments_and_strings,
)

PIPELINE_STAGES: tuple[str, ...] = (
    "Expand",
    "Presolve",
    "Symmetries",
    "Loader",
    "Cuts",
    "LNS",
    "PropagatorInterface",
)

EPISTEMIC_STAGE_NOTE = (
    "Epistemic boundary: ConstraintProto stage-coverage matrix findings report structural "
    "C++ phase-handling asymmetries across Expand, Presolve, Symmetries, Loader, Cuts, LNS, "
    "and PropagatorInterface/SatPropagator and never claim formal verification or mathematical "
    "unsoundness of solver propagators."
)

_CPP_SUFFIXES: frozenset[str] = frozenset({".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"})
_INTERNAL_NON_SEARCH_CASES: frozenset[str] = frozenset({"dummy_constraint", "interval"})

_CASE_STEM_ALIASES: dict[str, tuple[str, ...]] = {
    "linear": ("Linear", "IntegerSum", "Knapsack", "Gomory", "ImpliedBounds"),
    "no_overlap": ("NoOverlap", "Disjunctive"),
    "no_overlap_2d": ("NoOverlap2D", "NoOverlap2d", "Diffn", "NonOverlappingRectangles"),
    "cumulative": ("Cumulative", "TimeTabling", "Timetabling"),
    "reservoir": ("Reservoir",),
    "routes": ("Routes", "Routing", "MultipleCircuit", "Circuit"),
    "circuit": ("Circuit", "Subcircuit", "Hamiltonian"),
    "all_diff": ("AllDiff", "AllDifferent"),
    "at_most_one": ("AtMostOne", "Amo", "BinaryImplication"),
    "exactly_one": ("ExactlyOne", "LiteralWatchers", "BinaryImplication"),
    "bool_or": ("BoolOr", "Clause", "LiteralWatchers", "SatPropagator"),
    "bool_and": ("BoolAnd", "BinaryImplication"),
    "bool_xor": ("BoolXor", "XorPropagator"),
    "lin_max": ("LinMax", "MaxEquality"),
    "int_prod": ("IntProd", "ProductPropagator"),
    "int_div": ("IntDiv", "DivisionPropagator"),
    "int_mod": ("IntMod", "FixedModulo"),
    "element": ("Element",),
    "table": ("Table",),
    "automaton": ("Automaton",),
    "inverse": ("Inverse",),
}


@dataclass(frozen=True)
class UsrSymbolEntry:
    usr: str
    name: str
    kind: str
    file: str
    line: int
    callees: tuple[str, ...] = ()


@dataclass(frozen=True)
class CppUsrIndex:
    symbols_by_usr: dict[str, UsrSymbolEntry] = field(default_factory=dict)
    symbols_by_file: dict[str, tuple[UsrSymbolEntry, ...]] = field(default_factory=dict)
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class StageCoverageCell:
    stage: str
    covered: bool
    handles_enforcement_literal: bool = False
    skips_enforced: bool = False
    locations: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    symbol_links: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConstraintStageRow:
    case_name: str
    field_number: int
    message_type: str
    proto_location: str
    cells: dict[str, StageCoverageCell]
    covered_stages: tuple[str, ...]
    omitted_active_stages: tuple[str, ...]
    asymmetric: bool


@dataclass(frozen=True)
class StageMatrixReport:
    rows: tuple[ConstraintStageRow, ...]
    active_stages: tuple[str, ...]
    stage_files: dict[str, tuple[str, ...]]
    compile_command_files: tuple[str, ...]
    usr_symbol_count: int
    findings: tuple[RawCandidateFinding, ...]
    epistemic_note: str = EPISTEMIC_STAGE_NOTE


def load_cpp_usr_index(
    index_paths: Sequence[Path | str],
    *,
    repo_root: Path | None = None,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> CppUsrIndex:
    """Parse read-only JSON/JSONL/TSV C++ USR symbol dumps (`--index-store`)."""
    by_usr: dict[str, UsrSymbolEntry] = {}
    per_file: dict[str, list[UsrSymbolEntry]] = {}
    sources: list[str] = []

    def _add_rec(raw_obj: dict[str, object]) -> None:
        usr = str(raw_obj.get("usr") or raw_obj.get("id") or "").strip()
        name = str(raw_obj.get("name") or raw_obj.get("symbol") or "").strip()
        if not usr and not name:
            return
        kind = str(raw_obj.get("kind") or "function").strip()
        loc = raw_obj.get("location")
        if isinstance(loc, dict):
            f_str = str(loc.get("file") or loc.get("path") or raw_obj.get("file") or "").strip()
            ln_raw = loc.get("line", raw_obj.get("line", 1))
        else:
            f_str = str(raw_obj.get("file") or raw_obj.get("path") or "").strip()
            ln_raw = raw_obj.get("line", 1)
        ln = int(ln_raw) if isinstance(ln_raw, int) and not isinstance(ln_raw, bool) else 1
        raw_callees = raw_obj.get("callees") or raw_obj.get("references") or ()
        callees = (
            tuple(str(c) for c in raw_callees if isinstance(c, str) and c)
            if isinstance(raw_callees, list)
            else ()
        )
        key = usr or f"sym:{f_str}:{ln}:{name}"
        entry = UsrSymbolEntry(usr=key, name=name or key, kind=kind, file=f_str, line=max(1, ln), callees=callees)
        by_usr[key] = entry
        if f_str:
            per_file.setdefault(f_str, []).append(entry)

    def _expand_index_sources(raw_item: Path | str) -> list[tuple[Path, str]]:
        raw_s = str(raw_item).strip()
        cand_p = Path(raw_s).expanduser() if raw_s else Path(raw_s)
        if (
            raw_s
            and "\x00" not in raw_s
            and ".." not in cand_p.parts
            and not cand_p.is_symlink()
        ):
            if cand_p.is_absolute():
                has_sym = any(
                    not (k == 2 and cand_p.parts[:2] in {("/", "var"), ("/", "tmp"), ("/", "etc")})
                    and Path(*cand_p.parts[:k]).is_symlink()
                    for k in range(2, len(cand_p.parts) + 1)
                )
                probe = cand_p
            else:
                base = (repo_root or Path.cwd()).resolve()
                walk = base
                has_sym = False
                for part in cand_p.parts:
                    if part in ("", "."):
                        continue
                    walk = walk / part
                    if walk.is_symlink():
                        has_sym = True
                        break
                probe = walk
            if not has_sym and not probe.is_symlink() and probe.is_dir():
                dir_files = iter_safe_repo_files(
                    probe,
                    suffixes=frozenset({".json", ".jsonl", ".tsv"}),
                    max_files=512,
                )
                return [
                    read_safe_artifact_text(
                        abs_f, repo_root=None, allow_external=True, max_bytes=max_bytes
                    )
                    for _, abs_f in dir_files
                ]
        return [
            read_safe_artifact_text(
                raw_item, repo_root=repo_root, allow_external=True, max_bytes=max_bytes
            )
        ]

    for raw_p in index_paths:
        for resolved, text in _expand_index_sources(raw_p):
            sources.append(str(resolved))
            stripped = text.lstrip()
            is_jsonl = resolved.suffix.lower() in (".jsonl", ".ndjson")
            if not is_jsonl and stripped.startswith(("{", "[")):
                try:
                    loaded = json.loads(text)
                except (json.JSONDecodeError, RecursionError) as exc:
                    raise ValueError(f"Malformed USR index JSON '{raw_p}': {exc}") from exc
                check_json_depth(loaded, max_depth=MAX_NESTING_DEPTH)
                if isinstance(loaded, list):
                    for item in loaded:
                        if isinstance(item, dict):
                            _add_rec(item)
                elif isinstance(loaded, dict):
                    for sec in ("symbols", "occurrences", "entries"):
                        arr = loaded.get(sec)
                        if isinstance(arr, list):
                            for item in arr:
                                if isinstance(item, dict):
                                    _add_rec(item)
            else:
                decoder = json.JSONDecoder()
                idx = 0
                txt_len = len(text)
                parsed_entries = 0
                while idx < txt_len and parsed_entries < 50000:
                    while idx < txt_len and text[idx].isspace():
                        idx += 1
                    if idx >= txt_len:
                        break
                    if text[idx] == "#":
                        nl = text.find("\n", idx)
                        idx = txt_len if nl == -1 else nl + 1
                        continue
                    if text[idx] == "{":
                        try:
                            obj, end_idx = decoder.raw_decode(text, idx)
                        except (json.JSONDecodeError, RecursionError):
                            nl = text.find("\n", idx)
                            idx = txt_len if nl == -1 else nl + 1
                            continue
                        idx = end_idx
                        parsed_entries += 1
                        if isinstance(obj, dict):
                            check_json_depth(obj, max_depth=MAX_NESTING_DEPTH)
                            _add_rec(obj)
                    else:
                        nl = text.find("\n", idx)
                        line = (text[idx:] if nl == -1 else text[idx:nl]).strip()
                        idx = txt_len if nl == -1 else nl + 1
                        parsed_entries += 1
                        if "\t" in line:
                            cols = line.split("\t")
                            if len(cols) >= 4:
                                ln_no = int(cols[4]) if len(cols) >= 5 and cols[4].isdigit() else 1
                                _add_rec(
                                    {
                                        "usr": cols[0],
                                        "name": cols[1],
                                        "kind": cols[2],
                                        "file": cols[3],
                                        "line": ln_no,
                                    }
                                )

    return CppUsrIndex(
        symbols_by_usr=by_usr,
        symbols_by_file={
            k: tuple(sorted(v, key=lambda e: (e.line, e.name, e.usr)))
            for k, v in per_file.items()
        },
        sources=tuple(sources),
    )


def parse_compile_commands_files(
    cc_paths: Sequence[Path | str],
    *,
    repo_root: Path | None = None,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> tuple[str, ...]:
    """Read `compile_commands.json` passively (never executing compiler commands)."""
    tu_files: list[str] = []
    real_root = repo_root.resolve() if repo_root is not None and not repo_root.is_symlink() else None
    for raw_p in cc_paths:
        _, loaded = load_safe_json(raw_p, repo_root=repo_root, max_bytes=max_bytes)
        if not isinstance(loaded, list):
            raise ValueError(f"compile_commands.json '{raw_p}' root must be a JSON array.")  # noqa: TRY004
        for entry in loaded[:10000]:
            if not isinstance(entry, dict):
                continue
            f_val = str(entry.get("file") or "").strip()
            if not f_val:
                continue
            d_val = str(entry.get("directory") or "").strip()
            cand = Path(f_val)
            if not cand.is_absolute() and d_val:
                cand = Path(d_val) / cand
            if real_root is not None:
                try:
                    if not cand.is_symlink() and cand.exists():
                        res = cand.resolve()
                        if res.is_relative_to(real_root):
                            tu_files.append(res.relative_to(real_root).as_posix())
                            continue
                except OSError:
                    pass
            tu_files.append(f_val.replace("\\", "/"))
    return tuple(dict.fromkeys(tu_files))


_PROPAGATOR_BASES_RE = re.compile(
    r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\b[^;{]{0,200}:\s*[^{;]{0,200}"
    r"\b(?:PropagatorInterface|SatPropagator|LazyReasonInterface)\b"
)
_CPP_FN_DECL_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_:<>,&\*\s]{0,120}\s+)?([A-Za-z_][A-Za-z0-9_:]*)\s*\("
)
_CASE_SWITCH_RE = re.compile(r"\bcase\s+(?:[A-Za-z0-9_:]+::)?(k[A-Za-z0-9_]+)\s*:")
_ENF_BAILOUT_RE = re.compile(
    r"\bif\s*\(\s*(?:HasEnforcementLiteral\s*\([^()]{0,120}\)"
    r"|!\s*[A-Za-z0-9_.->]+\s*enforcement_literal\s*\(\s*\)\s*\.\s*empty\s*\(\s*\)"
    r"|[A-Za-z0-9_.->]+\s*enforcement_literal_size\s*\(\s*\)\s*>\s*0)\s*\)\s*"
    r"(?:return|continue|break)\b"
)
_ENF_TOKEN_RE = re.compile(r"\b(?:enforcement_literal|HasEnforcementLiteral|EnforcementLiteral)\b")


def classify_cpp_solver_stages(rel_path: str, cleaned_text: str) -> tuple[str, ...]:
    """Map a solver C++ file to one or more of the 7 canonical pipeline stages."""
    name_low = PurePosixPath(rel_path).name.lower()
    stages: list[str] = []
    if "expand" in name_low:
        stages.append("Expand")
    if "presolve" in name_low:
        stages.append("Presolve")
    if "symmetr" in name_low:
        stages.append("Symmetries")
    if "loader" in name_low:
        stages.append("Loader")
    if "cut" in name_low:
        stages.append("Cuts")
    if "lns" in name_low or "neighborhood" in name_low:
        stages.append("LNS")
    if (
        name_low in {"integer.h", "integer.cc", "sat_solver.h", "sat_solver.cc"}
        or "propagator" in name_low
        or name_low.startswith(
            ("disjunctive.", "cumulative.", "diffn.", "table.", "circuit.", "all_different.", "reservoir.")
        )
        or _PROPAGATOR_BASES_RE.search(cleaned_text)
    ):
        stages.append("PropagatorInterface")
    return tuple(dict.fromkeys(stages))


def _case_stems(case_spec: ConstraintCaseSpec) -> tuple[str, ...]:
    base_stems = [en.removeprefix("k") for en in case_spec.cpp_enum_names if en.startswith("k")]
    aliases = list(_CASE_STEM_ALIASES.get(case_spec.name, ()))
    return tuple(dict.fromkeys([*base_stems, *aliases]))


def _nearest_usr_or_fn(
    rel_path: str,
    line_no: int,
    lines: list[str],
    usr_index: CppUsrIndex,
) -> tuple[str, str]:
    file_usrs = usr_index.symbols_by_file.get(rel_path, ())
    if not file_usrs:
        leaf = PurePosixPath(rel_path).name
        for k_path, entries in usr_index.symbols_by_file.items():
            if PurePosixPath(k_path).name == leaf:
                file_usrs = entries
                break
    preceding = [u for u in file_usrs if u.line <= line_no]
    if preceding:
        best = preceding[-1]
        return best.name, best.usr

    for back in range(line_no - 1, max(-1, line_no - 45), -1):
        cand_ln = lines[back][:MAX_LINE_SCAN_CHARS]
        if cand_ln.lstrip().startswith(("if ", "if(", "for ", "for(", "while ", "switch ", "case ", "return ")):
            continue
        m_fn = _CPP_FN_DECL_RE.match(cand_ln)
        if m_fn:
            fn_sym = m_fn.group(1)
            if fn_sym not in {"if", "for", "while", "switch", "return", "sizeof", "DCHECK", "CHECK"}:
                return fn_sym, f"{rel_path}:{line_no}#{fn_sym}"
    return PurePosixPath(rel_path).stem, f"{rel_path}:{line_no}"


def _scan_stage_for_case(
    stage: str,
    case_spec: ConstraintCaseSpec,
    stage_sources: Sequence[tuple[str, str, list[str]]],
    usr_index: CppUsrIndex,
) -> StageCoverageCell:
    enums_set = set(case_spec.cpp_enum_names)
    stems = _case_stems(case_spec)
    cname = case_spec.name
    acc_pat = re.compile(
        rf"(?:\.|->)\s*(?:has_{re.escape(cname)}|mutable_{re.escape(cname)}|{re.escape(cname)})\s*\("
    )
    stage_prefix_map: dict[str, tuple[str, ...]] = {
        "Expand": ("Expand",),
        "Presolve": ("Presolve", "TryTo"),
        "Symmetries": ("Symmetr", "Detect", "Add"),
        "Loader": ("Load",),
        "Cuts": ("Cut", "Create"),
        "LNS": ("Lns", "Relax", "Neighborhood"),
        "PropagatorInterface": ("Propagator", "TimeTabling", "Watch", "Implication", "IntegerSum", "SatSolver"),
    }
    prefixes = stage_prefix_map.get(stage, ())

    locations: list[str] = []
    symbols: list[str] = []
    symbol_links: list[str] = []
    handles_enf = False
    skips_enf = False

    for rel_path, cleaned_text, lines in stage_sources:
        matched_lines: list[int] = []
        for idx, raw_ln in enumerate(lines):
            ln_txt = raw_ln[:MAX_LINE_SCAN_CHARS]
            hit = False
            for en in enums_set:
                if f"::{en}" in ln_txt:
                    hit = True
                    break
            if not hit:
                m_sw = _CASE_SWITCH_RE.search(ln_txt)
                if m_sw and m_sw.group(1) in enums_set:
                    hit = True
            if not hit and stage != "PropagatorInterface" and acc_pat.search(ln_txt):
                hit = True
            if not hit:
                if stage == "PropagatorInterface":
                    m_prop = _PROPAGATOR_BASES_RE.search(ln_txt)
                    if m_prop:
                        cls_name = m_prop.group(1)
                        if any(st.lower() in cls_name.lower() for st in stems):
                            hit = True
                    elif any(
                        st in ln_txt and ("Propagator" in ln_txt or "TimeTabling" in ln_txt or "LiteralWatchers" in ln_txt)
                        for st in stems
                    ):
                        hit = True
                elif stage == "Cuts":
                    if any(st.lower() in ln_txt.lower() and "cut" in ln_txt.lower() for st in stems):
                        hit = True
                else:
                    for pref in prefixes:
                        if any(f"{pref}{st}" in ln_txt for st in stems):
                            hit = True
                            break
            if hit:
                matched_lines.append(idx + 1)

        for ln_no in matched_lines[:6]:
            loc = f"{rel_path}:{ln_no}"
            if loc not in locations:
                locations.append(loc)
            sym_name, sym_link = _nearest_usr_or_fn(rel_path, ln_no, lines, usr_index)
            if sym_name not in symbols:
                symbols.append(sym_name)
            full_link = sym_link if ":" in sym_link else f"{loc}#{sym_name}"
            if full_link not in symbol_links:
                symbol_links.append(full_link)

            win_end = min(len(lines), ln_no + 45)
            window_lines: list[str] = [lines[ln_no - 1][:MAX_LINE_SCAN_CHARS]]
            for w_idx in range(ln_no, win_end):
                w_ln = lines[w_idx][:MAX_LINE_SCAN_CHARS]
                m_next = _CASE_SWITCH_RE.search(w_ln)
                if m_next and m_next.group(1) not in enums_set:
                    break
                window_lines.append(w_ln)
            window_text = "\n".join(window_lines)
            if _ENF_BAILOUT_RE.search(window_text):
                skips_enf = True
            elif _ENF_TOKEN_RE.search(window_text):
                handles_enf = True

        _ = cleaned_text

    return StageCoverageCell(
        stage=stage,
        covered=bool(locations),
        handles_enforcement_literal=handles_enf,
        skips_enforced=skips_enf and not handles_enf,
        locations=tuple(sorted(locations)),
        symbols=tuple(symbols),
        symbol_links=tuple(symbol_links),
    )


def build_constraint_stage_matrix(
    repo_root: Path,
    catalog: SolverProtoCatalog,
    *,
    usr_index: CppUsrIndex | None = None,
    compile_command_files: Sequence[str] = (),
    node_id_by_file: dict[str, str] | None = None,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> StageMatrixReport:
    """Construct the 7-stage `ConstraintProto` matrix and emit `SAT-INT-001` warnings."""
    idx = usr_index or CppUsrIndex()
    nid_map = node_id_by_file or {}
    stage_sources: dict[str, list[tuple[str, str, list[str]]]] = {s: [] for s in PIPELINE_STAGES}

    for rel_posix, abs_p in iter_safe_repo_files(repo_root, suffixes=_CPP_SUFFIXES):
        _, raw_txt = read_safe_artifact_text(
            abs_p, repo_root=repo_root, max_bytes=max_bytes, errors="replace"
        )
        cleaned = strip_c_comments_and_strings(raw_txt, blank_strings=True)
        stages = classify_cpp_solver_stages(rel_posix, cleaned)
        if not stages:
            continue
        lines = cleaned.splitlines()
        for st in stages:
            stage_sources[st].append((rel_posix, cleaned, lines))

    active_stages = tuple(st for st in PIPELINE_STAGES if stage_sources[st])
    stage_files = {
        st: tuple(sorted(src[0] for src in stage_sources[st]))
        for st in PIPELINE_STAGES
    }
    if not catalog.constraint_cases or not active_stages:
        return StageMatrixReport(
            rows=(),
            active_stages=active_stages,
            stage_files=stage_files,
            compile_command_files=tuple(compile_command_files),
            usr_symbol_count=len(idx.symbols_by_usr),
            findings=(),
        )

    opt_stages = tuple(
        s for s in ("Presolve", "Symmetries", "Cuts", "LNS", "PropagatorInterface")
        if s in active_stages
    )
    has_loader = "Loader" in active_stages
    loader_anchor_file = stage_files["Loader"][0] if stage_files["Loader"] else active_stages[0]

    rows: list[ConstraintStageRow] = []
    findings: list[RawCandidateFinding] = []

    for cspec in catalog.constraint_cases:
        cells = {
            st: _scan_stage_for_case(st, cspec, stage_sources[st], idx)
            for st in PIPELINE_STAGES
        }
        covered = tuple(st for st in PIPELINE_STAGES if cells[st].covered)
        omitted: list[str] = []
        asymmetric = False

        if cspec.name not in _INTERNAL_NON_SEARCH_CASES and has_loader:
            loaded = cells["Loader"].covered
            expanded = cells["Expand"].covered
            if loaded:
                omitted = [st for st in opt_stages if not cells[st].covered]
                if omitted:
                    asymmetric = True
            elif not expanded:
                omitted = ["Expand", "Loader"]
                asymmetric = True

        enf_gap_stages: list[str] = []
        if (
            catalog.has_enforcement_literal
            and cspec.name not in _INTERNAL_NON_SEARCH_CASES
            and cells["Loader"].covered
            and cells["Loader"].handles_enforcement_literal
        ):
            for ost in ("Presolve", "Symmetries", "Cuts"):
                if cells[ost].covered and cells[ost].skips_enforced:
                    enf_gap_stages.append(ost)
            if enf_gap_stages:
                asymmetric = True

        proto_loc = f"{cspec.source_file}:{cspec.line}" if cspec.source_file else f"ConstraintProto#{cspec.number}"
        rows.append(
            ConstraintStageRow(
                case_name=cspec.name,
                field_number=cspec.number,
                message_type=cspec.message_type,
                proto_location=proto_loc,
                cells=cells,
                covered_stages=covered,
                omitted_active_stages=tuple(omitted),
                asymmetric=asymmetric,
            )
        )

        if asymmetric:
            loader_locs = cells["Loader"].locations
            src_file = (
                loader_locs[0].split(":", 1)[0]
                if loader_locs
                else (cspec.source_file if cspec.source_file and not Path(cspec.source_file).is_absolute() else loader_anchor_file)
            )
            src_line = (
                int(loader_locs[0].split(":", 1)[1])
                if loader_locs and ":" in loader_locs[0]
                else max(1, cspec.line)
            )
            links_preview = ", ".join(
                lnk
                for st in covered
                for lnk in cells[st].symbol_links[:2]
            ) or proto_loc
            gap_parts: list[str] = []
            if omitted:
                gap_parts.append(f"omitted from stage(s) [{', '.join(omitted)}]")
            if enf_gap_stages:
                gap_parts.append(
                    f"`enforcement_literal` skipped/unhandled in [{', '.join(enf_gap_stages)}]"
                )
            gap_desc = "; ".join(gap_parts)
            findings.append(
                RawCandidateFinding(
                    rule_code="SAT-INT-001",
                    node_id=nid_map.get(src_file),
                    source_file=src_file,
                    line=src_line,
                    title=(
                        f"Asymmetric C++ pipeline stage coverage for `ConstraintProto.{cspec.name}`: "
                        f"{gap_desc}"
                    ),
                    detail=(
                        f"`ConstraintProto.{cspec.name}` ({cspec.message_type}, proto `{proto_loc}`) is "
                        f"covered in [{', '.join(covered) or 'none'}] ({links_preview}) yet {gap_desc}. "
                        f"{EPISTEMIC_STAGE_NOTE}"
                    ),
                    remediation=(
                        f"Verify whether `ConstraintProto.{cspec.name}` (and its `enforcement_literal` mode) "
                        f"intentionally bypasses [{', '.join(omitted or enf_gap_stages)}] or add corresponding "
                        "presolve/symmetry/cut/LNS handlers."
                    ),
                    confidence="confirmed",
                    evidence_strength="structural_match",
                )
            )

    return StageMatrixReport(
        rows=tuple(rows),
        active_stages=active_stages,
        stage_files=stage_files,
        compile_command_files=tuple(compile_command_files),
        usr_symbol_count=len(idx.symbols_by_usr),
        findings=tuple(findings),
    )
