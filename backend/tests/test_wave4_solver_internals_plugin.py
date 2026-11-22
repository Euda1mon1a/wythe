"""Wave 4 (#85) tests: `wythe-plugin-solver-internals` C++/Protobuf solver microscope."""

from __future__ import annotations

import importlib.metadata
import json
import random
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO_ROOT / "plugins" / "wythe-plugin-solver-internals" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from app.adapters import plugin_registry
from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    discover_plugins,
    run_plugin_companion_handlers,
)
from app.db.session import get_session_factory
from app.schemas.atlas import TargetProjectCreate, validate_semantic_atlas_id
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    attach_zoom1_stratum_badges,
    build_node_stratum_drilldown,
)
from wythe_plugin_solver_internals import (
    EPISTEMIC_STAGE_NOTE,
    PIPELINE_STAGES,
    SOLVER_INTERNALS_PLUGIN,
    UPSTREAM_ORTOOLS_REF,
    analyze_solver_internals,
    build_singleton_zoom2_subgraph,
    correlate_solver_internals_companion,
    extract_singleton_dependency_graph,
    parse_file_descriptor_set_bytes,
    parse_proto_descriptor_artifact,
    parse_proto_source_text,
    register_wythe_plugin,
)


class _FakeDist:
    def __init__(self, version: str = "0.1.0") -> None:
        import sysconfig

        self.version = version
        self._path = Path(sysconfig.get_path("purelib")) / f"wythe_plugin_solver_internals-{version}.dist-info"

    def locate_file(self, path: str) -> Path:
        return self._path.parent / path


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, obj: object, version: str = "0.1.0") -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist(version)
        self._obj = obj

    def load(self) -> object:
        return self._obj


def _enc_varint(val: int) -> bytes:
    if val < 0:
        val = (1 << 64) + val
    out = bytearray()
    while True:
        bits = val & 0x7F
        val >>= 7
        if val:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _enc_len(field_num: int, payload: bytes) -> bytes:
    return _enc_varint((field_num << 3) | 2) + _enc_varint(len(payload)) + payload


def _enc_str(field_num: int, text: str) -> bytes:
    return _enc_len(field_num, text.encode("utf-8"))


def _enc_int(field_num: int, val: int) -> bytes:
    return _enc_varint((field_num << 3) | 0) + _enc_varint(val)


def _encode_field_descriptor(
    name: str,
    number: int,
    *,
    label: int = 1,
    field_type: int = 11,
    type_name: str = "",
    default_value: str | None = None,
    oneof_index: int | None = None,
    deprecated: bool = False,
) -> bytes:
    parts = [
        _enc_str(1, name),
        _enc_int(3, number),
        _enc_int(4, label),
        _enc_int(5, field_type),
    ]
    if type_name:
        parts.append(_enc_str(6, type_name))
    if default_value is not None:
        parts.append(_enc_str(7, default_value))
    if deprecated:
        parts.append(_enc_len(8, _enc_int(3, 1)))
    if oneof_index is not None:
        parts.append(_enc_int(9, oneof_index))
    return b"".join(parts)


def _build_ortools_descriptor_pb() -> bytes:
    """Synthesize a genuine wire-format `google.protobuf.FileDescriptorSet` `.pb` payload."""
    ct_cases = [
        ("linear", 12, ".operations_research.sat.LinearConstraintProto"),
        ("no_overlap", 21, ".operations_research.sat.NoOverlapConstraintProto"),
        ("no_overlap_2d", 22, ".operations_research.sat.NoOverlap2DConstraintProto"),
        ("cumulative", 23, ".operations_research.sat.CumulativeConstraintProto"),
        ("reservoir", 24, ".operations_research.sat.ReservoirConstraintProto"),
        ("routes", 16, ".operations_research.sat.RoutesConstraintProto"),
        ("circuit", 15, ".operations_research.sat.CircuitConstraintProto"),
        ("all_diff", 13, ".operations_research.sat.AllDifferentConstraintProto"),
        ("at_most_one", 5, ".operations_research.sat.BoolArgumentProto"),
        ("exactly_one", 29, ".operations_research.sat.BoolArgumentProto"),
        ("lin_max", 27, ".operations_research.sat.LinearArgumentProto"),
        ("int_prod", 9, ".operations_research.sat.LinearArgumentProto"),
        ("table", 17, ".operations_research.sat.TableConstraintProto"),
        ("automaton", 18, ".operations_research.sat.AutomatonConstraintProto"),
    ]
    ct_fields = [
        _enc_len(2, _encode_field_descriptor("name", 1, field_type=9)),
        _enc_len(2, _encode_field_descriptor("enforcement_literal", 2, label=3, field_type=5)),
    ]
    for cname, cnum, ctype in ct_cases:
        ct_fields.append(
            _enc_len(
                2,
                _encode_field_descriptor(
                    cname,
                    cnum,
                    field_type=11,
                    type_name=ctype,
                    oneof_index=0,
                ),
            )
        )
    ct_msg = b"".join(
        [
            _enc_str(1, "ConstraintProto"),
            *ct_fields,
            _enc_len(8, _enc_str(1, "constraint")),
        ]
    )
    cp_file = b"".join(
        [
            _enc_str(1, "ortools/sat/cp_model.proto"),
            _enc_str(2, "operations_research.sat"),
            _enc_len(4, ct_msg),
            _enc_str(12, "proto3"),
        ]
    )

    sat_param_defs = [
        ("cp_model_presolve", 86, 8, "true", False),
        ("linearization_level", 90, 5, "1", False),
        ("symmetry_level", 183, 5, "2", False),
        ("num_workers", 206, 5, "0", False),
        ("num_search_workers", 100, 5, "0", True),
        ("max_time_in_seconds", 36, 1, "inf", False),
    ]
    sat_msg = b"".join(
        [
            _enc_str(1, "SatParameters"),
            *[
                _enc_len(
                    2,
                    _encode_field_descriptor(
                        pname,
                        pnum,
                        field_type=ptype,
                        default_value=pdef,
                        deprecated=pdep,
                    ),
                )
                for pname, pnum, ptype, pdef, pdep in sat_param_defs
            ],
        ]
    )
    sat_file = b"".join(
        [
            _enc_str(1, "ortools/sat/sat_parameters.proto"),
            _enc_str(2, "operations_research.sat"),
            _enc_len(4, sat_msg),
            _enc_str(12, "proto2"),
        ]
    )
    return _enc_len(1, cp_file) + _enc_len(1, sat_file)


def _init_git_repo(repo_dir: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Euda1mon1a"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "config", "user.email", "214782221+Euda1mon1a@users.noreply.github.com"],
        cwd=repo_dir,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init distilled ortools sat fixture"], cwd=repo_dir, check=True)
    return repo_dir


def _build_distilled_ortools_sat_repo(
    repo_dir: Path,
    *,
    include_defects: bool = True,
) -> tuple[Path, Path, Path, Path]:
    """Create distilled `google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5` fixture."""
    sat_dir = repo_dir / "ortools" / "sat"
    py_sat_dir = sat_dir / "python"
    artifacts_dir = repo_dir / "artifacts"
    (repo_dir / "backend" / "app" / "api").mkdir(parents=True)
    (repo_dir / "backend" / "app" / "solvers").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app" / "solver").mkdir(parents=True)
    py_sat_dir.mkdir(parents=True)
    artifacts_dir.mkdir(parents=True)

    (sat_dir / "cp_model.proto").write_text(
        'syntax = "proto3";\n'
        "package operations_research.sat;\n\n"
        "message ConstraintProto {\n"
        "  string name = 1;\n"
        "  repeated int32 enforcement_literal = 2;\n"
        "  oneof constraint {\n"
        "    BoolArgumentProto at_most_one = 5;\n"
        "    LinearArgumentProto int_prod = 9;\n"
        "    LinearConstraintProto linear = 12;\n"
        "    AllDifferentConstraintProto all_diff = 13;\n"
        "    CircuitConstraintProto circuit = 15;\n"
        "    RoutesConstraintProto routes = 16;\n"
        "    TableConstraintProto table = 17;\n"
        "    AutomatonConstraintProto automaton = 18;\n"
        "    NoOverlapConstraintProto no_overlap = 21;\n"
        "    NoOverlap2DConstraintProto no_overlap_2d = 22;\n"
        "    CumulativeConstraintProto cumulative = 23;\n"
        "    ReservoirConstraintProto reservoir = 24;\n"
        "    LinearArgumentProto lin_max = 27;\n"
        "    BoolArgumentProto exactly_one = 29;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    (sat_dir / "sat_parameters.proto").write_text(
        'syntax = "proto2";\n'
        "package operations_research.sat;\n\n"
        "message SatParameters {\n"
        "  optional double max_time_in_seconds = 36 [default = inf];\n"
        "  optional bool cp_model_presolve = 86 [default = true];\n"
        "  optional int32 linearization_level = 90 [default = 1];\n"
        "  optional int32 num_search_workers = 100 [default = 0, deprecated = true];\n"
        "  optional int32 symmetry_level = 183 [default = 2];\n"
        "  optional int32 num_workers = 206 [default = 0];\n"
        "}\n",
        encoding="utf-8",
    )

    (sat_dir / "model.h").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "class Model {\n"
        " public:\n"
        "  template <typename T>\n"
        "  T* GetOrCreate() { return nullptr; }\n"
        "  template <typename T>\n"
        "  const T* Get() const { return nullptr; }\n"
        "};\n"
        "class TimeLimit {\n"
        " public:\n"
        "  explicit TimeLimit(Model* model) {}\n"
        "};\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    (sat_dir / "sat_solver.h").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "class Trail {\n"
        " public:\n"
        "  explicit Trail(Model* model) {}\n"
        "};\n"
        "class SatPropagator {\n"
        " public:\n"
        "  virtual ~SatPropagator() = default;\n"
        "};\n"
        "class BinaryImplicationGraph : public SatPropagator {\n"
        " public:\n"
        "  explicit BinaryImplicationGraph(Model* model)\n"
        "      : trail_(model->GetOrCreate<Trail>()) {}\n"
        " private:\n"
        "  Trail* trail_;\n"
        "};\n"
        "class SatSolver {\n"
        " public:\n"
        "  explicit SatSolver(Model* model)\n"
        "      : trail_(model->GetOrCreate<Trail>()),\n"
        "        time_limit_(model->GetOrCreate<TimeLimit>()) {}\n"
        " private:\n"
        "  Trail* trail_;\n"
        "  TimeLimit* time_limit_;\n"
        "};\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    cyc_block = (
        "class ProductDetector;\n"
        "class ImpliedBounds {\n"
        " public:\n"
        "  explicit ImpliedBounds(Model* model);\n"
        "};\n"
        "class ProductDetector {\n"
        " public:\n"
        "  explicit ProductDetector(Model* model)\n"
        "      : implied_(model->GetOrCreate<ImpliedBounds>()) {}\n"
        " private:\n"
        "  ImpliedBounds* implied_;\n"
        "};\n"
        "inline ImpliedBounds::ImpliedBounds(Model* model) {\n"
        "  auto* sat = model->GetOrCreate<SatSolver>();\n"
        "  auto* integer_trail = model->GetOrCreate<IntegerTrail>();\n"
        "  auto* prod = model->GetOrCreate<ProductDetector>();\n"
        "  (void)sat; (void)integer_trail; (void)prod;\n"
        "}\n"
        if include_defects
        else (
            "class ImpliedBounds {\n"
            " public:\n"
            "  explicit ImpliedBounds(Model* model) {\n"
            "    auto* sat = model->GetOrCreate<SatSolver>();\n"
            "    auto* integer_trail = model->GetOrCreate<IntegerTrail>();\n"
            "    (void)sat; (void)integer_trail;\n"
            "  }\n"
            "};\n"
        )
    )

    (sat_dir / "integer.h").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "class PropagatorInterface {\n"
        " public:\n"
        "  virtual bool Propagate() = 0;\n"
        "};\n"
        "class IntegerTrail {\n"
        " public:\n"
        "  explicit IntegerTrail(Model* model)\n"
        "      : trail_(model->GetOrCreate<Trail>()),\n"
        "        time_limit_(model->GetOrCreate<TimeLimit>()) {}\n"
        " private:\n"
        "  Trail* trail_;\n"
        "  TimeLimit* time_limit_;\n"
        "};\n"
        "class LinearPropagator : public PropagatorInterface {};\n"
        "class DisjunctivePropagator : public PropagatorInterface {};\n"
        "class NonOverlappingRectanglesDisjunctivePropagator : public PropagatorInterface {};\n"
        "class TimeTablingPerTask : public PropagatorInterface {};\n"
        "class CircuitPropagator : public PropagatorInterface {};\n"
        "class AllDifferentBoundsPropagator : public PropagatorInterface {};\n"
        "class LinMaxPropagator : public PropagatorInterface {};\n"
        "class IntProdPropagator : public PropagatorInterface {};\n"
        "class TablePropagator : public PropagatorInterface {};\n"
        + cyc_block
        + "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    (sat_dir / "cp_model_expand.cc").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "void ExpandCpModel(CpModelProto* proto, const SatParameters& parameters) {\n"
        "  if (parameters.linearization_level() <= 0) return;\n"
        "  for (const auto& ct : proto->constraints()) {\n"
        "    switch (ct.constraint_case()) {\n"
        "      case ConstraintProto::kReservoir:\n"
        "        ExpandReservoir(ct);\n"
        "        break;\n"
        "      case ConstraintProto::kAutomaton:\n"
        "        ExpandAutomaton(ct);\n"
        "        break;\n"
        "      default:\n"
        "        break;\n"
        "    }\n"
        "  }\n"
        "}\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )
    return _populate_remaining_ortools_files(
        repo_dir,
        sat_dir=sat_dir,
        py_sat_dir=py_sat_dir,
        artifacts_dir=artifacts_dir,
        include_defects=include_defects,
    )



def _populate_remaining_ortools_files(
    repo_dir: Path,
    *,
    sat_dir: Path,
    py_sat_dir: Path,
    artifacts_dir: Path,
    include_defects: bool,
) -> tuple[Path, Path, Path, Path]:
    presolve_consts = (
        "constexpr int64_t kMaxPresolveOperations = 100000;\n"
        "constexpr int kMaxClauseSizeForProbing = 32;\n"
        if include_defects
        else ""
    )
    presolve_table_body = (
        "      case ConstraintProto::kTable:\n"
        "        if (HasEnforcementLiteral(ct)) return false;\n"
        "        return PresolveTable(ct);\n"
        if include_defects
        else (
            "      case ConstraintProto::kTable:\n"
            "        return PresolveTable(ct, ct.enforcement_literal());\n"
            "      case ConstraintProto::kIntProd:\n"
            "        return PresolveIntProd(ct, ct.enforcement_literal());\n"
        )
    )
    (sat_dir / "cp_model_presolve.cc").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        + presolve_consts
        + "bool PresolveCpModel(CpModelProto* proto, const SatParameters& parameters) {\n"
        "  if (!parameters.cp_model_presolve()) return false;\n"
        "  for (const auto& ct : proto->constraints()) {\n"
        "    switch (ct.constraint_case()) {\n"
        "      case ConstraintProto::kLinear: return PresolveLinear(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kNoOverlap: return PresolveNoOverlap(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kNoOverlap2D: return PresolveNoOverlap2D(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kCumulative: return PresolveCumulative(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kRoutes: return PresolveRoutes(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kCircuit: return PresolveCircuit(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kAllDiff: return PresolveAllDiff(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kAtMostOne: return PresolveAtMostOne(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kExactlyOne: return PresolveExactlyOne(ct, ct.enforcement_literal());\n"
        "      case ConstraintProto::kLinMax: return PresolveLinMax(ct, ct.enforcement_literal());\n"
        + presolve_table_body
        + "      default: break;\n"
        "    }\n"
        "  }\n"
        "  return true;\n"
        "}\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    sym_extra = (
        ""
        if include_defects
        else (
            "      case ConstraintProto::kNoOverlap2D: DetectNoOverlap2DSymmetry(ct); break;\n"
            "      case ConstraintProto::kTable: DetectTableSymmetry(ct); break;\n"
            "      case ConstraintProto::kIntProd: DetectIntProdSymmetry(ct); break;\n"
        )
    )
    (sat_dir / "cp_model_symmetries.cc").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "void FindCpModelSymmetries(const CpModelProto& proto, const SatParameters& params_) {\n"
        "  if (params_.symmetry_level() <= 0) return;\n"
        "  for (const auto& ct : proto.constraints()) {\n"
        "    switch (ct.constraint_case()) {\n"
        "      case ConstraintProto::kLinear: DetectLinearSymmetry(ct); break;\n"
        "      case ConstraintProto::kNoOverlap: DetectNoOverlapSymmetry(ct); break;\n"
        "      case ConstraintProto::kCumulative: DetectCumulativeSymmetry(ct); break;\n"
        "      case ConstraintProto::kRoutes: DetectRoutesSymmetry(ct); break;\n"
        "      case ConstraintProto::kCircuit: DetectCircuitSymmetry(ct); break;\n"
        "      case ConstraintProto::kAllDiff: DetectAllDiffSymmetry(ct); break;\n"
        "      case ConstraintProto::kAtMostOne: DetectAtMostOneSymmetry(ct); break;\n"
        "      case ConstraintProto::kExactlyOne: DetectExactlyOneSymmetry(ct); break;\n"
        "      case ConstraintProto::kLinMax: DetectLinMaxSymmetry(ct); break;\n"
        + sym_extra
        + "      default: break;\n"
        "    }\n"
        "  }\n"
        "}\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    (sat_dir / "cp_model_loader.cc").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "void LoadCpModel(const CpModelProto& proto, const SatParameters& parameters, Model* model) {\n"
        "  const double max_t = parameters.max_time_in_seconds();\n"
        "  const int workers = parameters.num_workers();\n"
        "  (void)max_t; (void)workers;\n"
        "  auto* integer_trail = model->GetOrCreate<IntegerTrail>();\n"
        "  auto* implied = model->GetOrCreate<ImpliedBounds>();\n"
        "  const auto* limit = model->Get<TimeLimit>();\n"
        "  (void)integer_trail; (void)implied; (void)limit;\n"
        "  for (const auto& ct : proto.constraints()) {\n"
        "    switch (ct.constraint_case()) {\n"
        "      case ConstraintProto::kLinear: LoadLinearConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kNoOverlap: LoadNoOverlapConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kNoOverlap2D: LoadNoOverlap2dConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kCumulative: LoadCumulativeConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kRoutes: LoadRoutesConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kCircuit: LoadCircuitConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kAllDiff: LoadAllDiffConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kAtMostOne: LoadAtMostOneConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kExactlyOne: LoadExactlyOneConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kLinMax: LoadLinMaxConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kIntProd: LoadIntProdConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      case ConstraintProto::kTable: LoadTableConstraint(ct, ct.enforcement_literal(), model); break;\n"
        "      default: break;\n"
        "    }\n"
        "  }\n"
        "}\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    cuts_extra = (
        ""
        if include_defects
        else (
            "CutGenerator CreateNoOverlap2dEnergyCutGenerator(Model* model);\n"
            "CutGenerator CreateTableCutGenerator(Model* model);\n"
            "CutGenerator CreateIntProdCutGenerator(Model* model);\n"
        )
    )
    (sat_dir / "cuts.h").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "struct CutGenerator {};\n"
        "inline CutGenerator CreateLinearConstraintCutGenerator(Model* model) {\n"
        "  auto* implied = model->GetOrCreate<ImpliedBounds>();\n"
        "  (void)implied;\n"
        "  return CutGenerator{};\n"
        "}\n"
        "CutGenerator CreateNoOverlapCutGenerator(Model* model);\n"
        "CutGenerator CreateCumulativeTimeTableCutGenerator(Model* model);\n"
        "CutGenerator CreateRoutesCutGenerator(Model* model);\n"
        "CutGenerator CreateCircuitCutGenerator(Model* model);\n"
        "CutGenerator CreateAllDiffCutGenerator(Model* model);\n"
        "CutGenerator CreateAtMostOneCutGenerator(Model* model);\n"
        "CutGenerator CreateExactlyOneCutGenerator(Model* model);\n"
        "CutGenerator CreateLinMaxCutGenerator(Model* model);\n"
        + cuts_extra
        + "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )

    lns_extra = (
        ""
        if include_defects
        else (
            "      case ConstraintProto::kNoOverlap2D: RelaxNoOverlap2D(ct); break;\n"
            "      case ConstraintProto::kTable: RelaxTable(ct); break;\n"
            "      case ConstraintProto::kIntProd: RelaxIntProd(ct); break;\n"
        )
    )
    (sat_dir / "cp_model_lns.cc").write_text(
        "namespace operations_research {\n"
        "namespace sat {\n"
        "void RelaxNeighborhood(const CpModelProto& proto) {\n"
        "  for (const auto& ct : proto.constraints()) {\n"
        "    switch (ct.constraint_case()) {\n"
        "      case ConstraintProto::kLinear: RelaxLinear(ct); break;\n"
        "      case ConstraintProto::kNoOverlap: RelaxNoOverlap(ct); break;\n"
        "      case ConstraintProto::kCumulative: RelaxCumulative(ct); break;\n"
        "      case ConstraintProto::kRoutes: RelaxRoutes(ct); break;\n"
        "      case ConstraintProto::kCircuit: RelaxCircuit(ct); break;\n"
        "      case ConstraintProto::kAllDiff: RelaxAllDiff(ct); break;\n"
        "      case ConstraintProto::kAtMostOne: RelaxAtMostOne(ct); break;\n"
        "      case ConstraintProto::kExactlyOne: RelaxExactlyOne(ct); break;\n"
        "      case ConstraintProto::kLinMax: RelaxLinMax(ct); break;\n"
        + lns_extra
        + "      default: break;\n"
        "    }\n"
        "  }\n"
        "}\n"
        "}  // namespace sat\n"
        "}  // namespace operations_research\n",
        encoding="utf-8",
    )
    return _populate_wrapper_and_artifacts(
        repo_dir,
        py_sat_dir=py_sat_dir,
        artifacts_dir=artifacts_dir,
        include_defects=include_defects,
    )


def _populate_wrapper_and_artifacts(
    repo_dir: Path,
    *,
    py_sat_dir: Path,
    artifacts_dir: Path,
    include_defects: bool,
) -> tuple[Path, Path, Path, Path]:
    py_extra_ct = (
        ""
        if include_defects
        else "    def add_multiplication_equality(self, tgt, vars_): return self._proto.int_prod\n"
    )
    py_depr_param = (
        "    def set_legacy_workers(self, n: int) -> None:\n"
        "        self.parameters.num_search_workers = n\n"
        if include_defects
        else "    def set_workers(self, n: int) -> None:\n        self.parameters.num_workers = n\n"
    )
    (py_sat_dir / "cp_model.py").write_text(
        "class CpModel:\n"
        "    def __init__(self, proto=None):\n"
        "        self._proto = proto\n"
        "    def add(self, expr): return self._proto.linear\n"
        "    def add_no_overlap(self, ivs): return self._proto.no_overlap\n"
        "    def add_no_overlap_2d(self, x, y): return self._proto.no_overlap_2d\n"
        "    def add_cumulative(self, ivs, d, c): return self._proto.cumulative\n"
        "    def add_reservoir_constraint(self, t, l, mn, mx): return self._proto.reservoir\n"
        "    def add_multiple_circuit(self, arcs): return self._proto.routes\n"
        "    def add_circuit(self, arcs): return self._proto.circuit\n"
        "    def add_all_different(self, exprs): return self._proto.all_diff\n"
        "    def add_at_most_one(self, lits): return self._proto.at_most_one\n"
        "    def add_exactly_one(self, lits): return self._proto.exactly_one\n"
        "    def add_max_equality(self, tgt, exprs): return self._proto.lin_max\n"
        "    def add_allowed_assignments(self, vars_, tuples_): return self._proto.table\n"
        "    def add_automaton(self, vars_, s, f, tr): return self._proto.automaton\n"
        + py_extra_ct
        + "\nclass CpSolver:\n"
        "    def __init__(self, params=None):\n"
        "        self.parameters = params\n"
        "    def configure(self, limit_s: float) -> None:\n"
        "        self.parameters.max_time_in_seconds = limit_s\n"
        "        self.parameters.cp_model_presolve = True\n"
        + py_depr_param,
        encoding="utf-8",
    )

    shim_depr = (
        '  m.def_property("num_search_workers", &SatParameters::num_search_workers);\n'
        if include_defects
        else '  m.def_property("num_workers", &SatParameters::num_workers);\n'
    )
    (py_sat_dir / "cp_model_helper.cc").write_text(
        "#include <pybind11/pybind11.h>\n"
        "PYBIND11_MODULE(cp_model_helper, m) {\n"
        '  m.def("solve", &SolveCpModel);\n'
        + shim_depr
        + "}\n",
        encoding="utf-8",
    )

    pb_path = artifacts_dir / "ortools_sat.pb"
    pb_path.write_bytes(_build_ortools_descriptor_pb())

    usr_path = artifacts_dir / "usr_index.json"
    usr_path.write_text(
        json.dumps(
            {
                "symbols": [
                    {
                        "usr": "c:@N@operations_research@N@sat@F@LoadCpModel#",
                        "name": "LoadCpModel",
                        "kind": "function",
                        "file": "ortools/sat/cp_model_loader.cc",
                        "line": 3,
                    },
                    {
                        "usr": "c:@N@operations_research@N@sat@S@IntegerTrail",
                        "name": "operations_research::sat::IntegerTrail",
                        "kind": "class",
                        "file": "ortools/sat/integer.h",
                        "line": 7,
                        "callees": [
                            "std::vector<int>::push_back",
                            "vtable thunk for PropagatorInterface::Propagate()",
                        ],
                    },
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    cc_path = artifacts_dir / "compile_commands.json"
    cc_path.write_text(
        json.dumps(
            [
                {"directory": str(repo_dir), "file": "ortools/sat/cp_model_expand.cc", "command": "clang++ -c"},
                {"directory": str(repo_dir), "file": "ortools/sat/cp_model_presolve.cc", "command": "clang++ -c"},
                {"directory": str(repo_dir), "file": "ortools/sat/cp_model_loader.cc", "command": "clang++ -c"},
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    # Minimal clean 3-tier wrapper so `run_target_scan` builds a deterministic Zoom-1 report
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE solver_runs (\n"
        "    id INTEGER PRIMARY KEY,\n"
        "    status TEXT NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "solvers" / "engine_runner.py").write_text(
        "def execute_solver_job(db):\n"
        "    rows = db.execute('SELECT id, status FROM solver_runs').fetchall()\n"
        "    return {'count': len(rows)}\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "api" / "solver_api.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.solvers.engine_runner import execute_solver_job\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/solver/runs')\n"
        "def list_runs(db=None):\n"
        "    return execute_solver_job(db)\n",
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "solver" / "page.tsx").write_text(
        "export default async function SolverPage() {\n"
        "  const res = await fetch('/api/v1/solver/runs');\n"
        "  return <main>{String(res.ok)}</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    _init_git_repo(repo_dir)
    return repo_dir, pb_path, usr_path, cc_path


def test_plugin_manifest_spec_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    pyproject = REPO_ROOT / "plugins" / "wythe-plugin-solver-internals" / "pyproject.toml"
    manifest = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    proj = manifest["project"]
    assert proj["name"] == "wythe-plugin-solver-internals"
    assert proj["authors"] == [{"name": "Euda1mon1a"}]
    assert proj["dependencies"] == []
    assert (
        proj["entry-points"]["wythe.plugins"]["solver_internals"]
        == "wythe_plugin_solver_internals.plugin:SOLVER_INTERNALS_PLUGIN"
    )

    spec = register_wythe_plugin()
    assert spec is SOLVER_INTERNALS_PLUGIN
    assert spec.kind == "stratum_inspector"
    assert spec.supported_zooms == (2,)
    assert spec.stratum_badge_hook is not None
    assert spec.stratum_expand_hook is not None
    assert spec.post_scan_hook is not None
    assert "solver_internals" in spec.companion_handlers
    assert [r.rule_code for r in spec.rules] == [
        "SAT-INT-001",
        "SAT-INT-002",
        "SAT-INT-003",
        "SAT-INT-004",
    ]
    assert all(r.severity == "warning" and not r.blocks_gate for r in spec.rules)

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (
            [_FakeEntryPoint("solver_internals", "wythe_plugin_solver_internals.plugin:SOLVER_INTERNALS_PLUGIN", SOLVER_INTERNALS_PLUGIN)]
            if kw.get("group") == ENTRY_POINT_GROUP
            else []
        ),
    )
    discovered = discover_plugins(include_builtins=False, include_entry_points=True, strict_plugins=True)
    assert len(discovered) == 1
    assert discovered[0].name == "solver-internals"
    assert discovered[0].supported_zooms == (2,)


def test_proto_descriptor_pb_json_and_source_parity(tmp_path: Path) -> None:
    pb_bytes = _build_ortools_descriptor_pb()
    pb_msgs = parse_file_descriptor_set_bytes(pb_bytes)
    assert "ConstraintProto" in pb_msgs
    assert "SatParameters" in pb_msgs

    ct_msg = pb_msgs["ConstraintProto"]
    assert "constraint" in ct_msg.oneofs
    assert len(ct_msg.oneofs["constraint"]) == 14
    assert any(f.name == "enforcement_literal" and f.label == "repeated" for f in ct_msg.fields)

    sat_msg = pb_msgs["SatParameters"]
    by_name = {f.name: f for f in sat_msg.fields}
    assert by_name["cp_model_presolve"].default_value == "true"
    assert by_name["num_search_workers"].deprecated is True
    assert by_name["num_workers"].deprecated is False

    # Also verify JSON FileDescriptorSet artifact parity without `.proto` sources
    json_desc = tmp_path / "ortools_desc.json"
    json_desc.write_text(
        json.dumps(
            {
                "file": [
                    {
                        "name": "ortools/sat/cp_model.proto",
                        "package": "operations_research.sat",
                        "messageType": [
                            {
                                "name": "ConstraintProto",
                                "oneofDecl": [{"name": "constraint"}],
                                "field": [
                                    {"name": "enforcement_literal", "number": 2, "label": "LABEL_REPEATED", "type": "TYPE_INT32"},
                                    {"name": "linear", "number": 12, "typeName": ".operations_research.sat.LinearConstraintProto", "oneofIndex": 0},
                                    {"name": "no_overlap_2d", "number": 22, "typeName": ".operations_research.sat.NoOverlap2DConstraintProto", "oneofIndex": 0},
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    json_msgs = parse_proto_descriptor_artifact(json_desc)
    assert json_msgs["ConstraintProto"].oneofs["constraint"] == ("linear", "no_overlap_2d")


def test_ortools_7_stage_matrix_param_lineage_singleton_cycles_and_wrapper_parity(
    tmp_path: Path,
) -> None:
    repo_dir, pb_path, usr_path, cc_path = _build_distilled_ortools_sat_repo(
        tmp_path / "ortools_flawed", include_defects=True
    )
    analysis = analyze_solver_internals(
        repo_dir,
        proto_descriptor=pb_path,
        index_store=usr_path,
        compile_commands=cc_path,
    )
    assert analysis.solver_engine_detected is True
    assert analysis.stage_matrix.active_stages == PIPELINE_STAGES
    assert len(analysis.compile_command_files) == 3
    assert EPISTEMIC_STAGE_NOTE in analysis.notes

    row_by_case = {r.case_name: r for r in analysis.stage_matrix.rows}
    assert row_by_case["linear"].asymmetric is False
    assert set(row_by_case["linear"].covered_stages) >= {
        "Presolve", "Symmetries", "Loader", "Cuts", "LNS", "PropagatorInterface"
    }
    assert any(
        "c:@N@operations_research@N@sat@F@LoadCpModel#" in lnk
        for lnk in row_by_case["linear"].cells["Loader"].symbol_links
    )
    # Pure Expand-lowered cases are NOT falsely flagged as asymmetric
    assert row_by_case["reservoir"].asymmetric is False
    assert row_by_case["automaton"].asymmetric is False
    # Asymmetric omissions and enforcement_literal bailouts ARE flagged
    assert row_by_case["no_overlap_2d"].asymmetric is True
    assert {"Symmetries", "Cuts", "LNS"} <= set(row_by_case["no_overlap_2d"].omitted_active_stages)
    assert row_by_case["table"].asymmetric is True
    assert row_by_case["table"].cells["Presolve"].skips_enforced is True

    # SatParameters PolicyFieldConsumption (`consumed` vs `bypassed`)
    pfc_map = analysis.param_lineage.consumption_by_file
    assert pfc_map["ortools/sat/cp_model_loader.cc"].state == "consumed"
    assert pfc_map["ortools/sat/cp_model_expand.cc"].state == "consumed"
    assert pfc_map["ortools/sat/cp_model_symmetries.cc"].state == "consumed"
    assert pfc_map["ortools/sat/cp_model_presolve.cc"].state == "bypassed"
    assert "kMaxPresolveOperations=100000" in pfc_map["ortools/sat/cp_model_presolve.cc"].substituted_constants

    # Singleton graph & cycle detection (qualified C++ namespace vertex identity)
    assert {
        "operations_research::sat::Trail",
        "operations_research::sat::IntegerTrail",
        "operations_research::sat::SatSolver",
        "operations_research::sat::TimeLimit",
        "operations_research::sat::ImpliedBounds",
        "operations_research::sat::ProductDetector",
    } <= set(analysis.singleton_graph.singletons)
    assert any(
        c.chain
        == (
            "operations_research::sat::ImpliedBounds",
            "operations_research::sat::ProductDetector",
            "operations_research::sat::ImpliedBounds",
        )
        for c in analysis.singleton_graph.cycles
    )

    # Wrapper parity
    assert analysis.wrapper_parity.unexposed_constraints == ("int_prod",)
    depr_names = {d.alias_name for d in analysis.wrapper_parity.deprecated_aliases}
    assert "num_search_workers" in depr_names

    # All 4 plugin rule codes fire cleanly with epistemic boundary preserved
    codes = {f.rule_code for f in analysis.findings}
    assert codes == {"SAT-INT-001", "SAT-INT-002", "SAT-INT-003", "SAT-INT-004"}
    assert all(
        EPISTEMIC_STAGE_NOTE in f.detail
        for f in analysis.findings
        if f.rule_code == "SAT-INT-001"
    )

    # Verify binary `.pb` descriptor works standalone when `.proto` files are absent
    (repo_dir / "ortools" / "sat" / "cp_model.proto").unlink()
    (repo_dir / "ortools" / "sat" / "sat_parameters.proto").unlink()
    pb_only = analyze_solver_internals(repo_dir, proto_descriptor=pb_path)
    assert len(pb_only.proto_catalog.constraint_cases) == 14
    assert {f.rule_code for f in pb_only.findings} == {
        "SAT-INT-001", "SAT-INT-002", "SAT-INT-003", "SAT-INT-004"
    }


def test_zoom1_digest_invariance_zoom2_drilldown_companion_and_non_solver_silence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_db_url: str,
) -> None:
    clean_dir, pb_path, usr_path, cc_path = _build_distilled_ortools_sat_repo(
        tmp_path / "ortools_clean", include_defects=False
    )
    factory = get_session_factory(isolated_db_url)

    # 1. Baseline Zoom-1 scan WITHOUT plugin
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [])
    with factory() as session:
        register_target(
            session,
            TargetProjectCreate(
                slug="clean-ortools",
                name="Clean OR-Tools Engine",
                repo_path=str(clean_dir),
                stack_profile_slug="fastapi-sqlalchemy-nextjs",
            ),
        )
        target = get_target_by_slug(session, "clean-ortools")
        assert target is not None
        base_report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    assert base_report.findings == []
    base_digest = base_report.content_digest
    base_node_count = len(base_report.nodes)

    # 2. Scan WITH `wythe-plugin-solver-internals` + active stratum artifacts
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (
            [_FakeEntryPoint("solver_internals", "wythe_plugin_solver_internals.plugin:SOLVER_INTERNALS_PLUGIN", SOLVER_INTERNALS_PLUGIN)]
            if kw.get("group") == ENTRY_POINT_GROUP
            else []
        ),
    )
    monkeypatch.setattr(
        plugin_registry,
        "get_active_stratum_artifacts",
        lambda: {
            "proto_descriptor": (str(pb_path),),
            "index_store": (str(usr_path),),
            "compile_commands": (str(cc_path),),
        },
        raising=False,
    )
    with factory() as session:
        target = get_target_by_slug(session, "clean-ortools")
        assert target is not None
        plug_report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)

    assert plug_report.findings == []
    assert plug_report.content_digest == base_digest
    assert len(plug_report.nodes) == base_node_count

    attach_zoom1_stratum_badges(clean_dir, plug_report)
    assert plug_report.content_digest == base_digest

    manip_node = next(n for n in plug_report.nodes if n.subkind == "solver")
    badge_counts = {b.key: b.count for b in manip_node.stratum_badges}
    assert badge_counts["proto_constraints"] == 14
    assert badge_counts["pipeline_stages"] == 7
    assert badge_counts["model_singletons"] >= 5

    # 3. Zoom-2 drilldown: compacts std::vector / vtable thunk by default, preserves with unfiltered_ir=True
    drill_compact = build_node_stratum_drilldown(clean_dir, plug_report, manip_node.id, zoom=2, unfiltered_ir=False)
    drill_raw = build_node_stratum_drilldown(clean_dir, plug_report, manip_node.id, zoom=2, unfiltered_ir=True)
    assert "solver-internals" in drill_compact.active_plugins
    assert drill_compact.collapsed_thunk_count == 2
    assert drill_raw.collapsed_thunk_count == 0
    assert len(drill_raw.nodes) == len(drill_compact.nodes) + 2
    assert any(n.kind == "cpp_singleton" and n.label == "IntegerTrail" for n in drill_compact.nodes)
    assert EPISTEMIC_STAGE_NOTE in drill_compact.notes

    # 4. Companion handler (`handler_key="solver_internals"`)
    comp_map = run_plugin_companion_handlers(
        clean_dir,
        plug_report,
        handler_key="solver_internals",
        proto_descriptor=str(pb_path),
        compile_commands=str(cc_path),
        index_store=str(usr_path),
        strict_plugins=True,
    )
    comp = comp_map["solver_internals"]
    assert comp["plugin"] == "solver-internals"
    assert comp["target_code_executed"] is False
    assert comp["build_system_executed"] is False
    assert comp["automated_security_audit"] is False
    assert comp["upstream_benchmark_ref"] == UPSTREAM_ORTOOLS_REF
    assert comp["wall_ties"][0]["status"] == "intact"

    # 5. Non-solver repo & Wythe repo silence (`0` false positives)
    monkeypatch.setattr(plugin_registry, "get_active_stratum_artifacts", dict, raising=False)
    wythe_self = analyze_solver_internals(REPO_ROOT)
    assert wythe_self.solver_engine_detected is False
    assert wythe_self.findings == ()

    plain_web = tmp_path / "plain_web_app"
    (plain_web / "backend").mkdir(parents=True)
    (plain_web / "backend" / "service.py").write_text("def handle(): return {'ok': True}\n", encoding="utf-8")
    plain_res = analyze_solver_internals(plain_web)
    assert plain_res.solver_engine_detected is False
    assert plain_res.findings == ()


def test_hostile_pb_varints_oversized_lengths_nesting_symlinks_and_redos(tmp_path: Path) -> None:
    # 1. Hostile 70-bit continuation varint & 65..70-bit value varint -> ValueError, 0 hangs
    t0 = time.perf_counter()
    with pytest.raises(ValueError, match="varint"):
        parse_file_descriptor_set_bytes((b"\x80" * 10) + b"\x01")
    with pytest.raises(ValueError, match="varint"):
        parse_file_descriptor_set_bytes(_enc_varint((1 << 3) | 0) + (b"\xff" * 9) + b"\x7f")
    # 2. Oversized 34 GB length-delimited header & truncated payload -> ValueError
    oversized_pb = _enc_varint((1 << 3) | 2) + _enc_varint(34 * (1024**3)) + b"short"
    with pytest.raises(ValueError, match="Oversized or truncated"):
        parse_file_descriptor_set_bytes(oversized_pb)
    with pytest.raises(ValueError, match=r"(?i)truncated"):
        parse_file_descriptor_set_bytes(b"\x0a\x10\x0a\x03")
    assert (time.perf_counter() - t0) < 0.2

    # 3. Deeply nested (> 64 levels) binary `.pb`, JSON, and `.proto` -> ValueError
    nested_msg = _enc_str(1, "Leaf")
    for depth in range(70):
        nested_msg = _enc_str(1, f"M{depth}") + _enc_len(3, nested_msg)
    deep_pb = _enc_len(1, _enc_str(1, "deep.proto") + _enc_len(4, nested_msg))
    with pytest.raises(ValueError, match="nesting depth"):
        parse_file_descriptor_set_bytes(deep_pb)

    deep_json_file = tmp_path / "deep.json"
    cur_obj: dict[str, object] = {"name": "Leaf"}
    for depth in range(70):
        cur_obj = {"name": f"M{depth}", "nestedType": [cur_obj]}
    deep_json_file.write_text(json.dumps({"file": [{"name": "deep.proto", "messageType": [cur_obj]}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="depth"):
        parse_proto_descriptor_artifact(deep_json_file)

    deep_proto = ("message M { " * 70) + ("} " * 70)
    with pytest.raises(ValueError, match="nesting"):
        parse_proto_source_text(deep_proto)

    # 4. Symlinked leaf file, symlinked repo parent dir, and symlinked external parent dir
    repo_dir = tmp_path / "sym_repo"
    real_sub = repo_dir / "real_artifacts"
    real_sub.mkdir(parents=True)
    real_pb = real_sub / "valid.pb"
    real_pb.write_bytes(_build_ortools_descriptor_pb())

    leaf_sym = repo_dir / "leaf_link.pb"
    leaf_sym.symlink_to(real_pb)
    with pytest.raises(ValueError, match="symlink"):
        parse_proto_descriptor_artifact(leaf_sym, repo_root=repo_dir)

    sym_parent = repo_dir / "sym_artifacts"
    sym_parent.symlink_to(real_sub)
    with pytest.raises(ValueError, match="symlink"):
        parse_proto_descriptor_artifact(sym_parent / "valid.pb", repo_root=repo_dir.resolve())
    with pytest.raises(ValueError, match="symlink"):
        correlate_solver_internals_companion(
            repo_dir.resolve(),
            proto_descriptor=str(sym_parent / "valid.pb"),
        )

    ext_real = tmp_path / "ext_real"
    ext_real.mkdir()
    ext_pb = ext_real / "ext.pb"
    ext_pb.write_bytes(_build_ortools_descriptor_pb())
    ext_sym_dir = tmp_path / "ext_sym_dir"
    ext_sym_dir.symlink_to(ext_real)
    with pytest.raises(ValueError, match="symlink"):
        parse_proto_descriptor_artifact(ext_sym_dir / "ext.pb", repo_root=repo_dir.resolve())

    # 5. ReDoS resilience on unterminated 64-backslash strings & 16 KB lines
    redos_repo = tmp_path / "redos_repo"
    (redos_repo / "ortools" / "sat").mkdir(parents=True)
    (redos_repo / "ortools" / "sat" / "cp_model.proto").write_text(
        'syntax = "proto2";\n'
        "message SatParameters {\n"
        '  optional string tag = 1 [default = "' + ("\\" * 64) + "unterminated\n"
        "}\n",
        encoding="utf-8",
    )
    (redos_repo / "ortools" / "sat" / "cp_model_presolve.cc").write_text(
        "void Presolve() {\n"
        + ("  const char* s = \"" + ("\\" * 64) + "unterminated\n")
        + ("  int x = " + ("a + " * 4000) + "0;\n")
        + "}\n",
        encoding="utf-8",
    )
    t_redos = time.perf_counter()
    _ = analyze_solver_internals(redos_repo)
    assert (time.perf_counter() - t_redos) < 0.3


def test_singleton_3hop_and_self_cycles_vs_post_ctor_propagate_negative_control(
    tmp_path: Path,
) -> None:
    # 1. Negative control: A::A(Model*) -> B, while B::Propagate() -> A (post-ctor, NOT a ctor cycle!)
    acyclic_repo = tmp_path / "acyclic_post_ctor"
    (acyclic_repo / "ortools" / "sat").mkdir(parents=True)
    (acyclic_repo / "ortools" / "sat" / "propagators.h").write_text(
        "namespace operations_research { namespace sat {\n"
        "class Beta;\n"
        "class Alpha {\n"
        " public:\n"
        "  explicit Alpha(Model* model) : beta_(model->GetOrCreate<Beta>()) {}\n"
        " private:\n"
        "  Beta* beta_;\n"
        "};\n"
        "class Beta {\n"
        " public:\n"
        "  explicit Beta(Model* model) {}\n"
        "  bool Propagate(Model* model) {\n"
        "    auto* alpha = model->GetOrCreate<Alpha>();\n"
        "    return alpha != nullptr;\n"
        "  }\n"
        "};\n"
        "}}  // namespace operations_research::sat\n",
        encoding="utf-8",
    )
    acyclic_graph = extract_singleton_dependency_graph(acyclic_repo)
    assert acyclic_graph.cycles == ()
    assert acyclic_graph.findings == ()

    # 2. Positive control: 3-hop cycle (NodeA -> NodeB -> NodeC -> NodeA) + self-loop (SelfLoop -> SelfLoop)
    cyclic_repo = tmp_path / "cyclic_3hop"
    (cyclic_repo / "ortools" / "sat").mkdir(parents=True)
    (cyclic_repo / "ortools" / "sat" / "cycles.cc").write_text(
        "namespace operations_research { namespace sat {\n"
        "NodeA::NodeA(Model* model) { b_ = model->GetOrCreate<NodeB>(); }\n"
        "NodeB::NodeB(Model* model) { c_ = model->GetOrCreate<NodeC>(); }\n"
        "NodeC::NodeC(Model* model) { a_ = model->GetOrCreate<NodeA>(); }\n"
        "SelfLoop::SelfLoop(Model* model) { self_ = Model::GetOrCreate<SelfLoop>(); }\n"
        "}}  // namespace operations_research::sat\n",
        encoding="utf-8",
    )
    cyclic_graph = extract_singleton_dependency_graph(cyclic_repo)
    chains = {c.chain for c in cyclic_graph.cycles}
    assert (
        "operations_research::sat::NodeA",
        "operations_research::sat::NodeB",
        "operations_research::sat::NodeC",
        "operations_research::sat::NodeA",
    ) in chains
    assert (
        "operations_research::sat::SelfLoop",
        "operations_research::sat::SelfLoop",
    ) in chains
    assert len([f for f in cyclic_graph.findings if f.rule_code == "SAT-INT-003"]) == 2

    z2_nodes, z2_edges = build_singleton_zoom2_subgraph("m:solver:cycles", cyclic_graph)
    for zn in z2_nodes:
        assert validate_semantic_atlas_id(zn.id, field_name="focus_node_ids") == zn.id
    for ze in z2_edges:
        assert validate_semantic_atlas_id(ze.id, field_name="highlight_edge_ids") == ze.id


def test_swig_nanobind_deprecated_aliases_and_200_seed_binary_pb_fuzzer(tmp_path: Path) -> None:
    # 1. SWIG `.i`, nanobind `NB_MODULE`, and `@deprecated` Python wrapper alias detection
    wrap_repo = tmp_path / "wrap_shims"
    (wrap_repo / "ortools" / "sat" / "python").mkdir(parents=True)
    (wrap_repo / "ortools" / "sat" / "sat_parameters.proto").write_text(
        'syntax = "proto2";\n'
        "package operations_research.sat;\n"
        "message SatParameters {\n"
        "  optional int32 num_workers = 1 [default = 0];\n"
        "  optional int32 legacy_bve_limit = 2 [default = 10, deprecated = true];\n"
        "  optional double max_time_in_seconds = 3 [default = 60.0];\n"
        "  optional bool cp_model_presolve = 4 [default = true];\n"
        "}\n",
        encoding="utf-8",
    )
    (wrap_repo / "ortools" / "sat" / "python" / "cp_model.py").write_text(
        "def deprecated(fn):\n"
        "    return fn\n\n"
        "class CpSolver:\n"
        "    def __init__(self, params):\n"
        "        self.parameters = params\n"
        "    @deprecated\n"
        "    def set_threads_alias(self, k: int) -> None:\n"
        "        self.parameters.num_workers = k\n",
        encoding="utf-8",
    )
    (wrap_repo / "ortools" / "sat" / "python" / "sat_nanobind.cc").write_text(
        "#include <nanobind/nanobind.h>\n"
        "NB_MODULE(sat_nb, m) {\n"
        '  m.def_prop_rw("legacy_bve_limit", &SatParameters::legacy_bve_limit);\n'
        '  m.def_prop_rw("old_workers_alias", &SatParameters::num_workers);\n'
        "}\n",
        encoding="utf-8",
    )
    (wrap_repo / "ortools" / "sat" / "python" / "sat.i").write_text(
        '%module sat\n%rename("legacy_bve_limit") operations_research::sat::SatParameters::legacy_bve_limit;\n',
        encoding="utf-8",
    )
    res = analyze_solver_internals(wrap_repo)
    alias_names = {d.alias_name for d in res.wrapper_parity.deprecated_aliases}
    assert {"set_threads_alias", "legacy_bve_limit", "old_workers_alias"} <= alias_names
    assert all(f.rule_code == "SAT-INT-004" for f in res.wrapper_parity.findings)

    # Non-string artifact rejection
    with pytest.raises(ValueError, match="Invalid artifact path"):
        correlate_solver_internals_companion(wrap_repo, proto_descriptor=True)  # type: ignore[arg-type]

    # macOS `/var` vs `/private/var` symlinked parent directory check when `/var` alias applies
    resolved_tmp = str(tmp_path.resolve())
    if resolved_tmp.startswith("/private/var/"):
        real_d = tmp_path / "real_d"
        real_d.mkdir()
        p_file = real_d / "d.pb"
        p_file.write_bytes(_build_ortools_descriptor_pb())
        sym_d = tmp_path / "sym_d"
        sym_d.symlink_to(real_d)
        var_alias = "/var/" + str(sym_d.resolve().parent).removeprefix("/private/var/") + "/sym_d/d.pb"
        with pytest.raises(ValueError, match="symlink"):
            parse_proto_descriptor_artifact(var_alias, repo_root=tmp_path.resolve())

    # 2. 200-seed deterministic PRNG binary `.pb` fuzzer -> ONLY ValueError or dict, < 0.3s
    rng = random.Random(20261116)
    t0 = time.perf_counter()
    for _ in range(200):
        ln = rng.randint(0, 192)
        blob = bytes(rng.getrandbits(8) for _ in range(ln))
        try:
            parsed = parse_file_descriptor_set_bytes(blob)
            assert isinstance(parsed, dict)
        except ValueError:
            pass
    assert (time.perf_counter() - t0) < 0.3
