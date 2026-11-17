"""Pure-Python binary wire-format reader for `CpModelProto` and `CpSolverResponse`.

Aligned with upstream `ortools/sat/cp_model.proto` (`cp_model_pb2.DESCRIPTOR`) with
zero runtime dependency on `ortools` or `protobuf`.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from wythe_plugin_solver_chronicle.log_parser import (
        CpModelProtoSummary,
        CpSolverResponseSummary,
    )

_BINARY_CTRL_BYTES: Final[frozenset[int]] = frozenset(
    [*range(0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F]
)

_STATUS_BY_CODE: Final[dict[int, str]] = {
    0: "UNKNOWN",
    1: "MODEL_INVALID",
    2: "FEASIBLE",
    3: "INFEASIBLE",
    4: "OPTIMAL",
}

_CONSTRAINT_TAG_TO_KIND: Final[dict[int, str]] = {
    3: "bool_or",
    4: "bool_and",
    5: "bool_xor",
    7: "int_div",
    8: "int_mod",
    9: "int_max",
    10: "int_min",
    11: "int_prod",
    12: "linear",
    13: "all_diff",
    14: "element",
    15: "circuit",
    16: "table",
    17: "automaton",
    18: "inverse",
    19: "interval",
    20: "no_overlap",
    21: "no_overlap_2d",
    22: "cumulative",
    23: "routes",
    24: "reservoir",
    26: "at_most_one",
    27: "lin_max",
    29: "exactly_one",
    30: "dummy_constraint",
}


def is_binary_proto_payload(raw: bytes, path: Path | None = None) -> bool:
    """Return True when `raw` is a binary protobuf wire payload rather than JSON/pbtxt."""
    if not raw:
        return False
    if any(b in _BINARY_CTRL_BYTES for b in raw):
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{"):
        return False
    if path is not None and path.suffix.lower() in (".pb", ".bin", ".protobin"):
        head = stripped[:64]
        if not head.startswith("#") and ":" not in head and "{" not in head:
            return True
    return False


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    end = len(buf)
    while pos < end and shift < 70:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Truncated or invalid varint in binary protobuf companion.")


def _s64(uval: int) -> int:
    m = uval & 0xFFFFFFFFFFFFFFFF
    return m - (1 << 64) if m >= (1 << 63) else m


def _s32(uval: int) -> int:
    v = _s64(uval) & 0xFFFFFFFF
    return v - (1 << 32) if v >= (1 << 31) else v


def _iter_fields(buf: bytes) -> list[tuple[int, int, int | bytes]]:
    out: list[tuple[int, int, int | bytes]] = []
    pos = 0
    end = len(buf)
    while pos < end:
        tag, pos = _read_varint(buf, pos)
        fnum = tag >> 3
        wtype = tag & 0x07
        if fnum <= 0:
            raise ValueError("Invalid protobuf field number 0.")
        if wtype == 0:
            val, pos = _read_varint(buf, pos)
            out.append((fnum, 0, val))
        elif wtype == 1:
            if pos + 8 > end:
                raise ValueError("Truncated 64-bit fixed field in binary protobuf.")
            out.append((fnum, 1, buf[pos : pos + 8]))
            pos += 8
        elif wtype == 2:
            ln, pos = _read_varint(buf, pos)
            if pos + ln > end:
                raise ValueError("Truncated length-delimited field in binary protobuf.")
            out.append((fnum, 2, buf[pos : pos + ln]))
            pos += ln
        elif wtype == 5:
            if pos + 4 > end:
                raise ValueError("Truncated 32-bit fixed field in binary protobuf.")
            out.append((fnum, 5, buf[pos : pos + 4]))
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type {wtype} on field {fnum}.")
    return out


def _packed_ints(chunk: bytes, *, bits32: bool) -> list[int]:
    vals: list[int] = []
    pos = 0
    end = len(chunk)
    while pos < end:
        raw_v, pos = _read_varint(chunk, pos)
        vals.append(_s32(raw_v) if bits32 else _s64(raw_v))
    return vals


def _wire_double(wtype: int, payload: int | bytes) -> float:
    if wtype == 1 and isinstance(payload, bytes):
        return float(struct.unpack("<d", payload)[0])
    if wtype == 5 and isinstance(payload, bytes):
        return float(struct.unpack("<f", payload)[0])
    if wtype == 0 and isinstance(payload, int):
        return float(_s64(payload))
    raise ValueError("Unexpected wire type for protobuf floating-point field.")


def _lin_expr_vars(sub: bytes) -> list[int]:
    out: list[int] = []
    for ef, ew, ev in _iter_fields(sub):
        if ef == 1 and ew == 2 and isinstance(ev, bytes):
            out.extend(_packed_ints(ev, bits32=True))
        elif ef == 1 and ew == 0 and isinstance(ev, int):
            out.append(_s32(ev))
    return out


def _extract_binary_constraint_vars(ct_tag: int, payload: bytes) -> list[int]:
    refs: list[int] = []
    for sf, sw, sv in _iter_fields(payload):
        if ct_tag in (3, 4, 5, 26, 29, 12, 30):
            if sf == 1 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sf == 1 and sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
        elif ct_tag in (7, 8, 9, 10, 11, 27):
            if sf in (1, 2) and sw == 2 and isinstance(sv, bytes):
                refs.extend(_lin_expr_vars(sv))
        elif ct_tag == 13 and sf == 1 and sw == 2 and isinstance(sv, bytes):
            refs.extend(_lin_expr_vars(sv))
        elif ct_tag == 14:
            if sf in (1, 2, 3) and sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
            elif sf == 3 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sf in (4, 5, 6) and sw == 2 and isinstance(sv, bytes):
                refs.extend(_lin_expr_vars(sv))
        elif (ct_tag == 15 and sf == 5) or (ct_tag == 23 and sf == 3):
            if sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
        elif ct_tag == 16:
            if sf == 1 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sf == 1 and sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
            elif sf == 4 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_lin_expr_vars(sv))
        elif ct_tag == 17:
            if sf == 7 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sf == 7 and sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
            elif sf == 8 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_lin_expr_vars(sv))
        elif ct_tag == 18 and sf in (1, 2):
            if sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
        elif ct_tag == 19 and sf in (4, 5, 6):
            if sw == 2 and isinstance(sv, bytes):
                refs.extend(_lin_expr_vars(sv))
            elif sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
        elif ct_tag == 22 and sf in (1, 3) and sw == 2 and isinstance(sv, bytes):
            refs.extend(_lin_expr_vars(sv))
        elif ct_tag == 24:
            if sf in (3, 6) and sw == 2 and isinstance(sv, bytes):
                refs.extend(_lin_expr_vars(sv))
            elif sf == 5 and sw == 2 and isinstance(sv, bytes):
                refs.extend(_packed_ints(sv, bits32=True))
            elif sf == 5 and sw == 0 and isinstance(sv, int):
                refs.append(_s32(sv))
    return list(dict.fromkeys(refs))


def parse_binary_cp_model_proto(buf: bytes) -> CpModelProtoSummary:
    """Decode wire-format `CpModelProto` bytes into `CpModelProtoSummary`."""
    from wythe_plugin_solver_chronicle.log_parser import CpModelProtoSummary

    model_name = ""
    var_names: list[str] = []
    var_domains: list[tuple[int, int] | None] = []
    cst_names: list[str] = []
    cst_kinds: list[str] = []
    cst_vars: list[tuple[int, ...]] = []
    cst_enf: list[tuple[int, ...]] = []
    obj_vars: list[int] = []
    fp_vars: list[int] = []
    assumps: list[int] = []

    for fnum, wtype, val in _iter_fields(buf):
        if fnum == 1 and wtype == 2 and isinstance(val, bytes):
            model_name = val.decode("utf-8", errors="replace")
        elif fnum == 2 and wtype == 2 and isinstance(val, bytes):
            vn = ""
            vdom: list[int] = []
            for vf, vw, vv in _iter_fields(val):
                if vf == 1 and vw == 2 and isinstance(vv, bytes):
                    vn = vv.decode("utf-8", errors="replace")
                elif vf == 2 and vw == 2 and isinstance(vv, bytes):
                    vdom.extend(_packed_ints(vv, bits32=False))
                elif vf == 2 and vw == 0 and isinstance(vv, int):
                    vdom.append(_s64(vv))
            idx = len(var_names)
            var_names.append(vn or f"var_{idx}")
            var_domains.append((vdom[0], vdom[-1]) if len(vdom) >= 2 else None)
        elif fnum == 3 and wtype == 2 and isinstance(val, bytes):
            cn = ""
            cenf: list[int] = []
            ckind = "unknown"
            cvars: list[int] = []
            for cf, cw, cv in _iter_fields(val):
                if cf == 1 and cw == 2 and isinstance(cv, bytes):
                    cn = cv.decode("utf-8", errors="replace")
                elif cf == 2 and cw == 2 and isinstance(cv, bytes):
                    cenf.extend(_packed_ints(cv, bits32=True))
                elif cf == 2 and cw == 0 and isinstance(cv, int):
                    cenf.append(_s32(cv))
                elif cf >= 3:
                    ckind = _CONSTRAINT_TAG_TO_KIND.get(cf, f"tag_{cf}")
                    if cw == 2 and isinstance(cv, bytes):
                        cvars = _extract_binary_constraint_vars(cf, cv)
            idx = len(cst_names)
            cst_names.append(cn or f"constraint_{idx}")
            cst_kinds.append(ckind)
            cst_vars.append(tuple(cvars))
            cst_enf.append(tuple(cenf))
        elif fnum == 4 and wtype == 2 and isinstance(val, bytes):
            for of, ow, ov in _iter_fields(val):
                if of == 1 and ow == 2 and isinstance(ov, bytes):
                    obj_vars.extend(_packed_ints(ov, bits32=True))
                elif of == 1 and ow == 0 and isinstance(ov, int):
                    obj_vars.append(_s32(ov))
        elif fnum == 9 and wtype == 2 and isinstance(val, bytes):
            for ff, fw, fv in _iter_fields(val):
                if ff == 1 and fw == 2 and isinstance(fv, bytes):
                    fp_vars.extend(_packed_ints(fv, bits32=True))
                elif ff == 1 and fw == 0 and isinstance(fv, int):
                    fp_vars.append(_s32(fv))
        elif fnum == 7 and wtype == 2 and isinstance(val, bytes):
            assumps.extend(_packed_ints(val, bits32=True))
        elif fnum == 7 and wtype == 0 and isinstance(val, int):
            assumps.append(_s32(val))

    return CpModelProtoSummary(
        name=model_name,
        variable_names=tuple(var_names),
        variable_domains=tuple(var_domains),
        constraint_names=tuple(cst_names),
        constraint_kinds=tuple(cst_kinds),
        constraint_vars=tuple(cst_vars),
        constraint_enforcement_literals=tuple(cst_enf),
        objective_vars=tuple(obj_vars or fp_vars),
        assumptions=tuple(assumps),
    )


def parse_binary_cp_solver_response(buf: bytes) -> CpSolverResponseSummary:
    """Decode wire-format `CpSolverResponse` bytes into `CpSolverResponseSummary`."""
    from wythe_plugin_solver_chronicle.log_parser import CpSolverResponseSummary

    status_code: int | None = None
    obj_val: float | None = None
    best_bnd: float | None = None
    suff: list[int] = []
    num_bools: int | None = None
    num_confs: int | None = None
    num_brs: int | None = None
    wall_t: float | None = None
    user_t: float | None = None
    det_t: float | None = None
    sol_info = ""
    solve_log = ""

    for fnum, wtype, val in _iter_fields(buf):
        if fnum == 1 and wtype == 0 and isinstance(val, int):
            status_code = _s32(val)
        elif fnum == 3:
            obj_val = _wire_double(wtype, val)
        elif fnum == 4:
            best_bnd = _wire_double(wtype, val)
        elif fnum == 10 and wtype == 0 and isinstance(val, int):
            num_bools = _s64(val)
        elif fnum == 11 and wtype == 0 and isinstance(val, int):
            num_confs = _s64(val)
        elif fnum == 12 and wtype == 0 and isinstance(val, int):
            num_brs = _s64(val)
        elif fnum == 15:
            wall_t = _wire_double(wtype, val)
        elif fnum == 16:
            user_t = _wire_double(wtype, val)
        elif fnum == 17:
            det_t = _wire_double(wtype, val)
        elif fnum == 20 and wtype == 2 and isinstance(val, bytes):
            sol_info = val.decode("utf-8", errors="replace")
        elif fnum == 23 and wtype == 2 and isinstance(val, bytes):
            suff.extend(_packed_ints(val, bits32=True))
        elif fnum == 23 and wtype == 0 and isinstance(val, int):
            suff.append(_s32(val))
        elif fnum == 26 and wtype == 2 and isinstance(val, bytes):
            solve_log = val.decode("utf-8", errors="replace")

    status_str = (
        _STATUS_BY_CODE.get(status_code, f"STATUS_{status_code}")
        if status_code is not None
        else ("UNKNOWN" if buf else None)
    )
    return CpSolverResponseSummary(
        status=status_str,
        objective_value=obj_val,
        best_objective_bound=best_bnd,
        sufficient_assumptions_for_infeasibility=tuple(suff),
        num_booleans=num_bools if num_bools is not None else (0 if buf else None),
        num_conflicts=num_confs if num_confs is not None else (0 if buf else None),
        num_branches=num_brs if num_brs is not None else (0 if buf else None),
        wall_time=wall_t,
        solve_log=solve_log,
        user_time=user_t,
        deterministic_time=det_t,
        solution_info=sol_info,
    )
