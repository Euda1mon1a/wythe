"""Host-language wrapper parity (`cp_model.py` & SWIG/pybind11/nanobind) and `SAT-INT-004`.

Cross-checks Python SDK wrappers (`ortools/sat/python/cp_model.py`) and C++ binding shims
against `ConstraintProto` `oneof` cases and `SatParameters` fields, emitting `SAT-INT-004`
warnings on unexposed `.proto` constraint capabilities or deprecated parameter aliases.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from app.adapters.base import RawCandidateFinding
from wythe_plugin_solver_internals.proto_descriptor import (
    MAX_LINE_SCAN_CHARS,
    MAX_SOLVER_FILE_BYTES,
    SolverProtoCatalog,
    iter_safe_repo_files,
    read_safe_artifact_text,
    strip_c_comments_and_strings,
)

_PY_SUFFIXES: frozenset[str] = frozenset({".py"})
_BINDING_SUFFIXES: frozenset[str] = frozenset({".i", ".swig", ".cc", ".cpp", ".cxx", ".h", ".hpp"})
_SKIP_CONSTRAINT_CASES: frozenset[str] = frozenset({"dummy_constraint"})

_CP_MODEL_METHOD_TO_CASE: dict[str, str] = {
    "add": "linear",
    "add_linear_constraint": "linear",
    "add_linear_expression_in_domain": "linear",
    "add_no_overlap": "no_overlap",
    "add_no_overlap_2d": "no_overlap_2d",
    "add_cumulative": "cumulative",
    "add_reservoir_constraint": "reservoir",
    "add_reservoir_constraint_with_active": "reservoir",
    "add_multiple_circuit": "routes",
    "add_circuit": "circuit",
    "add_all_different": "all_diff",
    "add_at_most_one": "at_most_one",
    "add_exactly_one": "exactly_one",
    "add_max_equality": "lin_max",
    "add_min_equality": "lin_max",
    "add_multiplication_equality": "int_prod",
    "add_division_equality": "int_div",
    "add_modulo_equality": "int_mod",
    "add_bool_or": "bool_or",
    "add_implication": "bool_or",
    "add_bool_and": "bool_and",
    "add_bool_xor": "bool_xor",
    "add_element": "element",
    "add_allowed_assignments": "table",
    "add_forbidden_assignments": "table",
    "add_automaton": "automaton",
    "add_inverse": "inverse",
    "new_interval_var": "interval",
    "new_optional_interval_var": "interval",
    "new_fixed_size_interval_var": "interval",
}

_BINDING_DEF_RE = re.compile(
    r"""(?:\.\s*def(?:_property|_prop_rw|_readwrite|_readonly|_static)?\s*\(\s*|%rename\s*\(\s*)"""
    r""""((?:\\.|[^"\\]){1,120})" """.strip()
)
_BINDING_PARAM_REF_RE = re.compile(r"\bSatParameters\s*::\s*([a-z_][a-z0-9_]*)\b")


@dataclass(frozen=True)
class WrapperDeprecatedAlias:
    alias_name: str
    canonical_or_proto_field: str
    reason: str
    source_file: str
    line: int


@dataclass(frozen=True)
class WrapperParityReport:
    wrapper_files: tuple[str, ...]
    binding_shim_files: tuple[str, ...]
    exposed_constraints: dict[str, tuple[str, ...]]
    unexposed_constraints: tuple[str, ...]
    exposed_parameters: tuple[str, ...]
    deprecated_aliases: tuple[WrapperDeprecatedAlias, ...]
    findings: tuple[RawCandidateFinding, ...]


def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    s2 = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s1)
    return s2.lower()


def _method_maps_to_case(method_name: str, known_cases: set[str]) -> str | None:
    snake = _camel_to_snake(method_name)
    if snake in _CP_MODEL_METHOD_TO_CASE:
        cand = _CP_MODEL_METHOD_TO_CASE[snake]
        if cand in known_cases:
            return cand
    if snake.startswith("add_"):
        rem = snake.removeprefix("add_").removesuffix("_constraint")
        if rem in known_cases:
            return rem
    return None


def _has_deprecation_marker(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn_node.decorator_list:
        dec_name = ""
        if isinstance(dec, ast.Name):
            dec_name = dec.id
        elif isinstance(dec, ast.Attribute):
            dec_name = dec.attr
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                dec_name = dec.func.id
            elif isinstance(dec.func, ast.Attribute):
                dec_name = dec.func.attr
        if "deprecat" in dec_name.lower():
            return True
    for child in ast.walk(fn_node):
        if isinstance(child, ast.Name) and "DeprecationWarning" in child.id:
            return True
    doc = ast.get_docstring(fn_node) or ""
    return "deprecated" in doc.lower()


def _inspect_python_wrapper_ast(
    rel_path: str,
    source_text: str,
    known_cases: set[str],
    deprecated_proto_params: set[str],
    known_proto_params: set[str],
) -> tuple[bool, dict[str, list[str]], set[str], list[WrapperDeprecatedAlias]]:
    try:
        tree = ast.parse(source_text, filename=rel_path)
    except (SyntaxError, RecursionError, ValueError):
        return False, {}, set(), []

    top_classes = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    is_sdk_wrapper = bool({"CpModel", "CpSolver"} & set(top_classes)) or rel_path.endswith(
        ("sat/python/cp_model.py", "sat/python/cp_model_helper.py")
    )
    if not is_sdk_wrapper:
        return False, {}, set(), []

    exposed_cases: dict[str, list[str]] = {}
    exposed_params: set[str] = set()
    depr_aliases: list[WrapperDeprecatedAlias] = []
    seen_depr: set[tuple[str, int]] = set()

    for cls_name in ("CpModel", "CpSolver"):
        cls_node = top_classes.get(cls_name)
        if cls_node is None:
            continue
        for item in cls_node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            mapped = _method_maps_to_case(item.name, known_cases)
            if mapped is not None:
                exposed_cases.setdefault(mapped, []).append(f"{rel_path}:{item.lineno}#{cls_name}.{item.name}")

            param_attrs_in_fn: list[tuple[str, int]] = []
            for sub in ast.walk(item):
                if isinstance(sub, ast.Attribute):
                    if sub.attr in known_cases:
                        exposed_cases.setdefault(sub.attr, []).append(
                            f"{rel_path}:{sub.lineno}#{cls_name}.{item.name}"
                        )
                    if (
                        isinstance(sub.value, ast.Attribute)
                        and sub.value.attr == "parameters"
                    ) or (isinstance(sub.value, ast.Name) and sub.value.id in {"parameters", "params"}):
                        param_attrs_in_fn.append((sub.attr, sub.lineno))

            is_fn_depr = _has_deprecation_marker(item)
            if is_fn_depr and param_attrs_in_fn:
                target_p = param_attrs_in_fn[0][0]
                key = (item.name, item.lineno)
                if key not in seen_depr:
                    seen_depr.add(key)
                    depr_aliases.append(
                        WrapperDeprecatedAlias(
                            alias_name=item.name,
                            canonical_or_proto_field=target_p,
                            reason=f"Deprecated Python wrapper `{cls_name}.{item.name}` aliases `SatParameters.{target_p}`",
                            source_file=rel_path,
                            line=item.lineno,
                        )
                    )

            for pattr, pline in param_attrs_in_fn:
                exposed_params.add(pattr)
                if pattr in deprecated_proto_params and (pattr, pline) not in seen_depr:
                    seen_depr.add((pattr, pline))
                    depr_aliases.append(
                        WrapperDeprecatedAlias(
                            alias_name=pattr,
                            canonical_or_proto_field=pattr,
                            reason=f"Wrapper references `[deprecated = true]` proto field `SatParameters.{pattr}`",
                            source_file=rel_path,
                            line=pline,
                        )
                    )
                elif (
                    known_proto_params
                    and len(known_proto_params) >= 4
                    and pattr not in known_proto_params
                    and not pattr.startswith(("CopyFrom", "MergeFrom", "Serialize", "Parse", "Clear", "HasField", "ListFields"))
                    and (pattr, pline) not in seen_depr
                ):
                    seen_depr.add((pattr, pline))
                    depr_aliases.append(
                        WrapperDeprecatedAlias(
                            alias_name=pattr,
                            canonical_or_proto_field="SatParameters",
                            reason=f"Wrapper accesses undeclared or retired parameter alias `parameters.{pattr}`",
                            source_file=rel_path,
                            line=pline,
                        )
                    )

    # Also catch module-level helper references to proto constraint fields or deprecated parameters
    for sub in ast.walk(tree):
        if isinstance(sub, ast.Attribute):
            if sub.attr in known_cases:
                exposed_cases.setdefault(sub.attr, []).append(f"{rel_path}:{sub.lineno}")
            if sub.attr in deprecated_proto_params:
                exposed_params.add(sub.attr)
                if (sub.attr, sub.lineno) not in seen_depr:
                    seen_depr.add((sub.attr, sub.lineno))
                    depr_aliases.append(
                        WrapperDeprecatedAlias(
                            alias_name=sub.attr,
                            canonical_or_proto_field=sub.attr,
                            reason=f"Wrapper references `[deprecated = true]` proto field `SatParameters.{sub.attr}`",
                            source_file=rel_path,
                            line=sub.lineno,
                        )
                    )

    return True, exposed_cases, exposed_params, depr_aliases


def check_host_wrapper_parity(
    repo_root: Path,
    catalog: SolverProtoCatalog,
    *,
    node_id_by_file: dict[str, str] | None = None,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> WrapperParityReport:
    """Verify Python `cp_model.py` and SWIG/pybind11/nanobind parity against `.proto` schemas."""
    nid_map = node_id_by_file or {}
    known_cases = {
        c.name for c in catalog.constraint_cases if c.name not in _SKIP_CONSTRAINT_CASES
    }
    known_params = set(catalog.sat_parameters)
    deprecated_params = {
        k for k, f in catalog.sat_parameters.items() if f.deprecated
    }

    wrapper_files: list[str] = []
    shim_files: list[str] = []
    exposed_cases: dict[str, list[str]] = {}
    exposed_params: set[str] = set()
    deprecated_aliases: list[WrapperDeprecatedAlias] = []

    for rel_posix, abs_p in iter_safe_repo_files(repo_root, suffixes=_PY_SUFFIXES):
        if not (rel_posix.endswith(("cp_model.py", "cp_model_helper.py")) or "sat" in rel_posix.lower()):
            continue
        _, src = read_safe_artifact_text(
            abs_p, repo_root=repo_root, max_bytes=max_bytes, errors="replace"
        )
        if "CpModel" not in src and "CpSolver" not in src:
            continue
        is_wrap, f_cases, f_params, f_depr = _inspect_python_wrapper_ast(
            rel_posix, src, known_cases, deprecated_params, known_params
        )
        if not is_wrap:
            continue
        wrapper_files.append(rel_posix)
        for ck, locs in f_cases.items():
            exposed_cases.setdefault(ck, []).extend(locs)
        exposed_params.update(f_params)
        deprecated_aliases.extend(f_depr)

    for rel_posix, abs_p in iter_safe_repo_files(repo_root, suffixes=_BINDING_SUFFIXES):
        is_swig = rel_posix.endswith((".i", ".swig"))
        if not is_swig and not any(tok in rel_posix.lower() for tok in ("python", "pybind", "nanobind", "wrap", "swig", "helper")):
            continue
        _, raw_txt = read_safe_artifact_text(
            abs_p, repo_root=repo_root, max_bytes=max_bytes, errors="replace"
        )
        if not is_swig and not any(
            m in raw_txt for m in ("PYBIND11_MODULE", "NB_MODULE", "pybind11", "nanobind", "SWIG")
        ):
            continue
        shim_files.append(rel_posix)
        cleaned = strip_c_comments_and_strings(raw_txt, blank_strings=False)
        for idx, raw_ln in enumerate(cleaned.splitlines()):
            ln_no = idx + 1
            ln_txt = raw_ln[:MAX_LINE_SCAN_CHARS]
            for m_def in _BINDING_DEF_RE.finditer(ln_txt):
                bound_name = m_def.group(1)
                mapped_c = _method_maps_to_case(bound_name, known_cases)
                if mapped_c:
                    exposed_cases.setdefault(mapped_c, []).append(f"{rel_posix}:{ln_no}#{bound_name}")
                elif bound_name in known_cases:
                    exposed_cases.setdefault(bound_name, []).append(f"{rel_posix}:{ln_no}#{bound_name}")
                if bound_name in known_params:
                    exposed_params.add(bound_name)
                if bound_name in deprecated_params:
                    deprecated_aliases.append(
                        WrapperDeprecatedAlias(
                            alias_name=bound_name,
                            canonical_or_proto_field=bound_name,
                            reason=f"C++ binding shim exposes `[deprecated = true]` field `SatParameters.{bound_name}`",
                            source_file=rel_posix,
                            line=ln_no,
                        )
                    )
                m_cpp_ref = _BINDING_PARAM_REF_RE.search(ln_txt)
                if m_cpp_ref:
                    cpp_field = m_cpp_ref.group(1)
                    if bound_name != cpp_field and cpp_field in known_params and bound_name not in known_params:
                        deprecated_aliases.append(
                            WrapperDeprecatedAlias(
                                alias_name=bound_name,
                                canonical_or_proto_field=cpp_field,
                                reason=(
                                    f"C++ binding shim exposes legacy parameter alias `{bound_name}` "
                                    f"mapped to `SatParameters::{cpp_field}`"
                                ),
                                source_file=rel_posix,
                                line=ln_no,
                            )
                        )

    all_host_files = [*wrapper_files, *shim_files]
    if not all_host_files or not (known_cases or known_params):
        return WrapperParityReport(
            wrapper_files=tuple(wrapper_files),
            binding_shim_files=tuple(shim_files),
            exposed_constraints={},
            unexposed_constraints=(),
            exposed_parameters=(),
            deprecated_aliases=(),
            findings=(),
        )

    unexposed = tuple(
        sorted(c for c in known_cases if c not in exposed_cases)
        if wrapper_files
        else ()
    )
    anchor_wrapper = wrapper_files[0] if wrapper_files else all_host_files[0]
    findings: list[RawCandidateFinding] = []

    for c_name in unexposed:
        cspec = next((c for c in catalog.constraint_cases if c.name == c_name), None)
        proto_ref = f"{cspec.source_file}:{cspec.line}" if cspec and cspec.source_file else "cp_model.proto"
        findings.append(
            RawCandidateFinding(
                rule_code="SAT-INT-004",
                node_id=nid_map.get(anchor_wrapper),
                source_file=anchor_wrapper,
                line=1,
                title=f"Host wrapper `{anchor_wrapper}` omits `ConstraintProto.{c_name}` builder surface",
                detail=(
                    f"`ConstraintProto` declares `oneof constraint` case `{c_name}` (`{proto_ref}`), "
                    f"but host-language SDK wrapper(s) [{', '.join(all_host_files)}] expose neither "
                    f"`ct.{c_name}` construction nor a corresponding `CpModel.Add*` helper."
                ),
                remediation=(
                    f"Expose a typed builder method for `ConstraintProto.{c_name}` in `{anchor_wrapper}` "
                    "or document why the proto capability is internal-only."
                ),
                confidence="confirmed",
                evidence_strength="structural_match",
            )
        )

    for depr in deprecated_aliases:
        findings.append(
            RawCandidateFinding(
                rule_code="SAT-INT-004",
                node_id=nid_map.get(depr.source_file),
                source_file=depr.source_file,
                line=depr.line,
                title=f"Deprecated or drifted `SatParameters` wrapper alias `{depr.alias_name}` in `{depr.source_file}`",
                detail=(
                    f"`{depr.source_file}:{depr.line}`: {depr.reason} "
                    f"(target `{depr.canonical_or_proto_field}`)."
                ),
                remediation=(
                    f"Migrate wrapper callers and bindings from `{depr.alias_name}` to the canonical "
                    f"non-deprecated `SatParameters` field in `sat_parameters.proto`."
                ),
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )

    return WrapperParityReport(
        wrapper_files=tuple(wrapper_files),
        binding_shim_files=tuple(shim_files),
        exposed_constraints={k: tuple(dict.fromkeys(v)) for k, v in sorted(exposed_cases.items())},
        unexposed_constraints=unexposed,
        exposed_parameters=tuple(sorted(exposed_params)),
        deprecated_aliases=tuple(deprecated_aliases),
        findings=tuple(findings),
    )
