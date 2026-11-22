"""Pure-Python reader and Z-wythe correlator for OR-Tools CpModelProto & CpSolverResponse.

Aligned with upstream `ortools/sat/cp_model.proto` at
`google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5` with zero runtime dependency
on `ortools` or `protobuf`.
"""

from __future__ import annotations

import json
import os
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from wythe_plugin_cpsat.ast_extractor import (
    CpSatRepoExtraction,
    extract_repo_cpsat_models,
)

UPSTREAM_ORTOOLS_PROTO_REF = "google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5"
_default_max_companion_bytes = 32 * 1024 * 1024
_binary_ctrl_bytes = frozenset(
    [*range(0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F]
)

_status_enum_by_code: dict[int, str] = {
    0: "UNKNOWN",
    1: "MODEL_INVALID",
    2: "FEASIBLE",
    3: "INFEASIBLE",
    4: "OPTIMAL",
}
_status_code_by_name: dict[str, int] = {v: k for k, v in _status_enum_by_code.items()}

_constraint_tag_names: dict[int, str] = {
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

_constraint_json_to_kind: dict[str, str] = {
    **{v: v for v in _constraint_tag_names.values()},
    "boolOr": "bool_or",
    "boolAnd": "bool_and",
    "boolXor": "bool_xor",
    "intDiv": "int_div",
    "intMod": "int_mod",
    "intMax": "int_max",
    "intMin": "int_min",
    "intProd": "int_prod",
    "allDiff": "all_diff",
    "noOverlap": "no_overlap",
    "noOverlap2d": "no_overlap_2d",
    "noOverlap2D": "no_overlap_2d",
    "atMostOne": "at_most_one",
    "linMax": "lin_max",
    "exactlyOne": "exactly_one",
    "dummyConstraint": "dummy_constraint",
}


@dataclass(frozen=True)
class ProtoVariableEntry:
    index: int
    name: str
    domain: tuple[int, ...]


@dataclass(frozen=True)
class ProtoConstraintEntry:
    index: int
    name: str
    kind: str
    enforcement_literals: tuple[int, ...]


@dataclass(frozen=True)
class CpModelProtoSummary:
    path: str
    format: Literal["json", "pbtxt", "binary"]
    name: str
    variables: tuple[ProtoVariableEntry, ...]
    constraints: tuple[ProtoConstraintEntry, ...]
    objective_vars: tuple[int, ...]
    objective_coeffs: tuple[int, ...]
    objective_scaling_factor: float
    assumptions: tuple[int, ...]


@dataclass(frozen=True)
class CpSolverResponseSummary:
    path: str
    format: Literal["json", "pbtxt", "binary"]
    status: str
    status_code: int
    objective_value: float
    best_objective_bound: float
    sufficient_assumptions_for_infeasibility: tuple[int, ...]
    num_booleans: int
    num_conflicts: int
    wall_time: float
    solve_log: str
    num_branches: int = 0
    user_time: float = 0.0
    deterministic_time: float = 0.0
    solution_info: str = ""


_OS_ROOT_SYMLINK_PREFIXES: frozenset[tuple[str, str]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)


def _read_companion_bytes(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = _default_max_companion_bytes,
) -> tuple[Path, bytes]:
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Companion artifact path must be a non-empty string without NUL bytes.")
    cand = Path(raw_path).expanduser()
    if cand.is_symlink():
        raise ValueError(f"Refusing symlinked companion artifact: '{raw_path}'.")

    if not cand.is_absolute():
        base_dir = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
        cur = base_dir
        for part in cand.parts:
            if part in ("", "."):
                continue
            cur = cur / part
            if cur.is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
        cand = cur
        if repo_root is not None and not cand.resolve().is_relative_to(base_dir):
            raise ValueError(
                f"Relative companion path '{raw_path}' escapes repository root."
            )
    else:
        if ".." in cand.parts:
            raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_path}'.")
        for k in range(2, len(cand.parts) + 1):
            if k == 2 and cand.parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
                continue
            if Path(*cand.parts[:k]).is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
        if repo_root is not None:
            real_root = repo_root.resolve()
            if not allow_external and not cand.resolve().is_relative_to(real_root):
                raise ValueError(f"Companion path '{raw_path}' escapes repository root.")
            for k in range(1, len(cand.parts) + 1):
                pref = Path(*cand.parts[:k])
                if pref.exists() and pref.resolve() == real_root:
                    walk = real_root
                    for part in cand.parts[k:]:
                        if part in ("", "."):
                            continue
                        walk = walk / part
                        if walk.is_symlink():
                            raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
                    break

    if cand.is_symlink() or not cand.exists():
        raise ValueError(f"Companion artifact '{raw_path}' must be an existing non-symlink file.")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(cand, flags)
    except OSError as exc:
        raise ValueError(f"Cannot safely open companion artifact '{raw_path}': {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Companion artifact '{raw_path}' must be a regular file.")
        if st.st_size > max_bytes:
            raise ValueError(
                f"Companion artifact '{raw_path}' ({st.st_size} bytes) exceeds {max_bytes}-byte limit."
            )
        chunks: list[bytes] = []
        rem = max_bytes + 1
        while rem > 0:
            blk = os.read(fd, min(65536, rem))
            if not blk:
                break
            chunks.append(blk)
            rem -= len(blk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValueError(f"Companion artifact '{raw_path}' exceeds {max_bytes}-byte limit.")
    finally:
        os.close(fd)

    return cand.resolve(), data


def _detect_proto_format(path: Path, raw: bytes) -> Literal["json", "pbtxt", "binary"]:
    if any(b in _binary_ctrl_bytes for b in raw):
        return "binary"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{"):
        return "json"
    suffix = path.suffix.lower()
    if suffix in (".pb", ".bin", ".protobin") and not re.match(
        r"^(?:#|[a-zA-Z_][a-zA-Z0-9_]*\s*[:{])", stripped
    ):
        return "binary"
    return "pbtxt"


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    n = len(buf)
    while pos < n and shift < 70:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Truncated or invalid varint in binary protobuf payload.")


def _to_signed_int64(uval: int) -> int:
    masked = uval & 0xFFFFFFFFFFFFFFFF
    return masked - (1 << 64) if masked >= (1 << 63) else masked


def _to_signed_int32(uval: int) -> int:
    s64 = _to_signed_int64(uval)
    masked32 = s64 & 0xFFFFFFFF
    return masked32 - (1 << 32) if masked32 >= (1 << 31) else masked32


def _iter_wire_fields(buf: bytes) -> list[tuple[int, int, int | bytes]]:
    fields: list[tuple[int, int, int | bytes]] = []
    pos = 0
    end = len(buf)
    while pos < end:
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num <= 0:
            raise ValueError("Invalid protobuf field number 0.")
        if wire_type == 0:
            val, pos = _read_varint(buf, pos)
            fields.append((field_num, 0, val))
        elif wire_type == 1:
            if pos + 8 > end:
                raise ValueError("Truncated 64-bit fixed field in binary protobuf.")
            fields.append((field_num, 1, buf[pos : pos + 8]))
            pos += 8
        elif wire_type == 2:
            ln, pos = _read_varint(buf, pos)
            if pos + ln > end:
                raise ValueError("Truncated length-delimited field in binary protobuf.")
            fields.append((field_num, 2, buf[pos : pos + ln]))
            pos += ln
        elif wire_type == 5:
            if pos + 4 > end:
                raise ValueError("Truncated 32-bit fixed field in binary protobuf.")
            fields.append((field_num, 5, buf[pos : pos + 4]))
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type {wire_type} on field {field_num}.")
    return fields


def _decode_packed_varints(chunk: bytes, *, bits32: bool = False) -> list[int]:
    vals: list[int] = []
    pos = 0
    end = len(chunk)
    while pos < end:
        raw_v, pos = _read_varint(chunk, pos)
        vals.append(_to_signed_int32(raw_v) if bits32 else _to_signed_int64(raw_v))
    return vals


def _decode_wire_double(wire_type: int, payload: int | bytes) -> float:
    if wire_type == 1 and isinstance(payload, bytes):
        return float(struct.unpack("<d", payload)[0])
    if wire_type == 5 and isinstance(payload, bytes):
        return float(struct.unpack("<f", payload)[0])
    if wire_type == 0 and isinstance(payload, int):
        return float(_to_signed_int64(payload))
    raise ValueError("Unexpected wire type for protobuf double field.")


def _parse_binary_cp_model_proto(resolved_str: str, buf: bytes) -> CpModelProtoSummary:
    model_name = ""
    vars_list: list[ProtoVariableEntry] = []
    cts_list: list[ProtoConstraintEntry] = []
    obj_vars: list[int] = []
    obj_coeffs: list[int] = []
    obj_scale = 0.0
    assumptions: list[int] = []

    for fnum, wtype, val in _iter_wire_fields(buf):
        if fnum == 1 and wtype == 2 and isinstance(val, bytes):
            model_name = val.decode("utf-8", errors="replace")
        elif fnum == 2 and wtype == 2 and isinstance(val, bytes):
            v_name = ""
            v_dom: list[int] = []
            for vf, vw, vv in _iter_wire_fields(val):
                if vf == 1 and vw == 2 and isinstance(vv, bytes):
                    v_name = vv.decode("utf-8", errors="replace")
                elif vf == 2 and vw == 2 and isinstance(vv, bytes):
                    v_dom.extend(_decode_packed_varints(vv, bits32=False))
                elif vf == 2 and vw == 0 and isinstance(vv, int):
                    v_dom.append(_to_signed_int64(vv))
            vars_list.append(
                ProtoVariableEntry(index=len(vars_list), name=v_name, domain=tuple(v_dom))
            )
        elif fnum == 3 and wtype == 2 and isinstance(val, bytes):
            c_name = ""
            c_enf: list[int] = []
            c_kind = "constraint"
            for cf, cw, cv in _iter_wire_fields(val):
                if cf == 1 and cw == 2 and isinstance(cv, bytes):
                    c_name = cv.decode("utf-8", errors="replace")
                elif cf == 2 and cw == 2 and isinstance(cv, bytes):
                    c_enf.extend(_decode_packed_varints(cv, bits32=True))
                elif cf == 2 and cw == 0 and isinstance(cv, int):
                    c_enf.append(_to_signed_int32(cv))
                elif cf >= 3:
                    c_kind = _constraint_tag_names.get(cf, f"tag_{cf}")
            cts_list.append(
                ProtoConstraintEntry(
                    index=len(cts_list),
                    name=c_name,
                    kind=c_kind,
                    enforcement_literals=tuple(c_enf),
                )
            )
        elif fnum == 4 and wtype == 2 and isinstance(val, bytes):
            for of, ow, ov in _iter_wire_fields(val):
                if of == 1 and ow == 2 and isinstance(ov, bytes):
                    obj_vars.extend(_decode_packed_varints(ov, bits32=True))
                elif of == 1 and ow == 0 and isinstance(ov, int):
                    obj_vars.append(_to_signed_int32(ov))
                elif of == 3:
                    obj_scale = _decode_wire_double(ow, ov)
                elif of == 4 and ow == 2 and isinstance(ov, bytes):
                    obj_coeffs.extend(_decode_packed_varints(ov, bits32=False))
                elif of == 4 and ow == 0 and isinstance(ov, int):
                    obj_coeffs.append(_to_signed_int64(ov))
        elif fnum == 9 and wtype == 2 and isinstance(val, bytes):
            fp_vars: list[int] = []
            for ff, fw, fv in _iter_wire_fields(val):
                if ff == 1 and fw == 2 and isinstance(fv, bytes):
                    fp_vars.extend(_decode_packed_varints(fv, bits32=True))
                elif ff == 1 and fw == 0 and isinstance(fv, int):
                    fp_vars.append(_to_signed_int32(fv))
            if fp_vars and not obj_vars:
                obj_vars.extend(fp_vars)
        elif fnum == 7 and wtype == 2 and isinstance(val, bytes):
            assumptions.extend(_decode_packed_varints(val, bits32=True))
        elif fnum == 7 and wtype == 0 and isinstance(val, int):
            assumptions.append(_to_signed_int32(val))

    return CpModelProtoSummary(
        path=resolved_str,
        format="binary",
        name=model_name,
        variables=tuple(vars_list),
        constraints=tuple(cts_list),
        objective_vars=tuple(obj_vars),
        objective_coeffs=tuple(obj_coeffs),
        objective_scaling_factor=obj_scale,
        assumptions=tuple(assumptions),
    )


def _parse_binary_cp_solver_response(resolved_str: str, buf: bytes) -> CpSolverResponseSummary:
    status_code = 0
    obj_val = 0.0
    best_bnd = 0.0
    suff_assump: list[int] = []
    num_bools = 0
    num_confs = 0
    num_brs = 0
    wall_t = 0.0
    user_t = 0.0
    det_t = 0.0
    sol_info = ""
    solve_log = ""

    for fnum, wtype, val in _iter_wire_fields(buf):
        if fnum == 1 and wtype == 0 and isinstance(val, int):
            status_code = _to_signed_int32(val)
        elif fnum == 3:
            obj_val = _decode_wire_double(wtype, val)
        elif fnum == 4:
            best_bnd = _decode_wire_double(wtype, val)
        elif fnum == 10 and wtype == 0 and isinstance(val, int):
            num_bools = _to_signed_int64(val)
        elif fnum == 11 and wtype == 0 and isinstance(val, int):
            num_confs = _to_signed_int64(val)
        elif fnum == 12 and wtype == 0 and isinstance(val, int):
            num_brs = _to_signed_int64(val)
        elif fnum == 15:
            wall_t = _decode_wire_double(wtype, val)
        elif fnum == 16:
            user_t = _decode_wire_double(wtype, val)
        elif fnum == 17:
            det_t = _decode_wire_double(wtype, val)
        elif fnum == 20 and wtype == 2 and isinstance(val, bytes):
            sol_info = val.decode("utf-8", errors="replace")
        elif fnum == 23 and wtype == 2 and isinstance(val, bytes):
            suff_assump.extend(_decode_packed_varints(val, bits32=True))
        elif fnum == 23 and wtype == 0 and isinstance(val, int):
            suff_assump.append(_to_signed_int32(val))
        elif fnum == 26 and wtype == 2 and isinstance(val, bytes):
            solve_log = val.decode("utf-8", errors="replace")

    return CpSolverResponseSummary(
        path=resolved_str,
        format="binary",
        status=_status_enum_by_code.get(status_code, f"STATUS_{status_code}"),
        status_code=status_code,
        objective_value=obj_val,
        best_objective_bound=best_bnd,
        sufficient_assumptions_for_infeasibility=tuple(suff_assump),
        num_booleans=num_bools,
        num_conflicts=num_confs,
        wall_time=wall_t,
        solve_log=solve_log,
        num_branches=num_brs,
        user_time=user_t,
        deterministic_time=det_t,
        solution_info=sol_info,
    )


def _unescape_pbtxt_string(raw_inner: str) -> str:
    out: list[str] = []
    i = 0
    n = len(raw_inner)
    while i < n:
        ch = raw_inner[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = raw_inner[i + 1]
        if nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "r":
            out.append("\r")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt in ('"', "'", "\\"):
            out.append(nxt)
            i += 2
        elif nxt == "x" and i + 3 < n:
            try:
                out.append(chr(int(raw_inner[i + 2 : i + 4], 16)))
                i += 4
            except ValueError:
                out.append(nxt)
                i += 2
        elif nxt in "01234567":
            oct_digits = nxt
            j = i + 2
            while j < n and len(oct_digits) < 3 and raw_inner[j] in "01234567":
                oct_digits += raw_inner[j]
                j += 1
            out.append(chr(int(oct_digits, 8)))
            i = j
        else:
            out.append(nxt)
            i += 2
    return "".join(out)


def _tokenize_pbtxt(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n,;":
            i += 1
            continue
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch in "{}:[]":
            tokens.append(("punct", ch))
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            start = i
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
            val = _unescape_pbtxt_string(text[start:i])
            i += 1
            # Protobuf text-format merges adjacent string literals
            if tokens and tokens[-1][0] == "str":
                tokens[-1] = ("str", tokens[-1][1] + val)
            else:
                tokens.append(("str", val))
            continue
        start = i
        while i < n and text[i] not in " \t\r\n,;{}:[]#\"'":
            i += 1
        tokens.append(("atom", text[start:i]))
    return tokens


_MAX_PBTXT_DEPTH = 64


def _parse_pbtxt_block(
    tokens: list[tuple[str, str]],
    pos: int,
    stop_punct: str | None,
    depth: int = 0,
) -> tuple[dict[str, list[Any]], int]:
    if depth > _MAX_PBTXT_DEPTH:
        raise ValueError(f"Corrupt or excessively nested .pbtxt message (> {_MAX_PBTXT_DEPTH} levels).")
    obj: dict[str, list[Any]] = {}
    n = len(tokens)

    def _coerce_atom(atom: str) -> Any:
        if atom in ("true", "True"):
            return True
        if atom in ("false", "False"):
            return False
        try:
            return int(atom, 0)
        except ValueError:
            pass
        try:
            return float(atom)
        except ValueError:
            return atom

    while pos < n:
        tk_kind, tk_val = tokens[pos]
        if stop_punct and tk_kind == "punct" and tk_val == stop_punct:
            return obj, pos + 1
        if tk_kind != "atom":
            pos += 1
            continue
        field_name = tk_val
        pos += 1
        if pos < n and tokens[pos] == ("punct", ":"):
            pos += 1
        if pos >= n:
            break
        vk, vv = tokens[pos]
        if vk == "punct" and vv == "{":
            sub_msg, pos = _parse_pbtxt_block(tokens, pos + 1, "}", depth + 1)
            obj.setdefault(field_name, []).append(sub_msg)
        elif vk == "punct" and vv == "[":
            pos += 1
            while pos < n and tokens[pos] != ("punct", "]"):
                ik, iv = tokens[pos]
                if ik == "punct" and iv == "{":
                    sub_msg, pos = _parse_pbtxt_block(tokens, pos + 1, "}", depth + 1)
                    obj.setdefault(field_name, []).append(sub_msg)
                elif ik == "str":
                    obj.setdefault(field_name, []).append(iv)
                    pos += 1
                elif ik == "atom":
                    obj.setdefault(field_name, []).append(_coerce_atom(iv))
                    pos += 1
                else:
                    pos += 1
            if pos < n and tokens[pos] == ("punct", "]"):
                pos += 1
        elif vk == "str":
            obj.setdefault(field_name, []).append(vv)
            pos += 1
        elif vk == "atom":
            obj.setdefault(field_name, []).append(_coerce_atom(vv))
            pos += 1
        else:
            pos += 1
    return obj, pos


def _as_list(val: Any) -> list[Any]:
    if val is None:
        return []
    return list(val) if isinstance(val, (list, tuple)) else [val]


def _first_scalar(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in mapping:
            raw = mapping[k]
            if isinstance(raw, list):
                return raw[-1] if raw else default
            return raw
    return default


def _coerce_proto_int(val: Any, field: str) -> int:
    if isinstance(val, bool) or val is None:
        raise ValueError(f"Invalid integer value in `{field}`: {val!r}")
    if isinstance(val, int):
        return val
    if isinstance(val, float) and val.is_integer():
        return int(val)
    if isinstance(val, str):
        cleaned = val.strip()
        try:
            base = 16 if cleaned.lower().startswith(("0x", "-0x", "+0x")) else 10
            return int(cleaned, base)
        except ValueError as exc:
            raise ValueError(f"Invalid integer value in `{field}`: {val!r}") from exc
    raise ValueError(f"Invalid integer value in `{field}`: {val!r}")


def _coerce_proto_float(val: Any, field: str) -> float:
    if isinstance(val, bool) or val is None:
        raise ValueError(f"Invalid numeric value in `{field}`: {val!r}")
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid numeric value in `{field}`: {val!r}") from exc
    raise ValueError(f"Invalid numeric value in `{field}`: {val!r}")


def _opt_proto_int(mapping: dict[str, Any], *keys: str, default: int = 0) -> int:
    raw = _first_scalar(mapping, *keys, default=None)
    if raw is None:
        return default
    return _coerce_proto_int(raw, keys[0])


def _opt_proto_float(mapping: dict[str, Any], *keys: str, default: float = 0.0) -> float:
    raw = _first_scalar(mapping, *keys, default=None)
    if raw is None:
        return default
    return _coerce_proto_float(raw, keys[0])


def _dict_to_cp_model_proto(
    resolved_str: str,
    fmt: Literal["json", "pbtxt"],
    data: dict[str, Any],
) -> CpModelProtoSummary:
    name = str(_first_scalar(data, "name", default="") or "")
    vars_out: list[ProtoVariableEntry] = []
    for idx, v_item in enumerate(_as_list(data.get("variables"))):
        if not isinstance(v_item, dict):
            raise ValueError(f"CpModelProto `variables[{idx}]` must be an object.")  # noqa: TRY004
        vn = str(_first_scalar(v_item, "name", default="") or "")
        dom = tuple(_coerce_proto_int(x, f"variables[{idx}].domain") for x in _as_list(v_item.get("domain")))
        vars_out.append(ProtoVariableEntry(index=idx, name=vn, domain=dom))

    cts_out: list[ProtoConstraintEntry] = []
    for idx, c_item in enumerate(_as_list(data.get("constraints"))):
        if not isinstance(c_item, dict):
            raise ValueError(f"CpModelProto `constraints[{idx}]` must be an object.")  # noqa: TRY004
        cn = str(_first_scalar(c_item, "name", default="") or "")
        enf_raw = (
            c_item["enforcement_literal"]
            if "enforcement_literal" in c_item
            else c_item.get("enforcementLiteral")
        )
        enf = tuple(
            _coerce_proto_int(x, f"constraints[{idx}].enforcement_literal") for x in _as_list(enf_raw)
        )
        ckind = "constraint"
        for k_cand in c_item:
            mapped_kind = _constraint_json_to_kind.get(k_cand)
            if mapped_kind is None:
                snake_k = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", k_cand).lower()
                mapped_kind = _constraint_json_to_kind.get(snake_k)
            if mapped_kind is not None:
                ckind = mapped_kind
                break
        cts_out.append(
            ProtoConstraintEntry(index=idx, name=cn, kind=ckind, enforcement_literals=enf)
        )

    obj_raw = _first_scalar(data, "objective", default=None)
    fp_obj_raw = _first_scalar(
        data, "floating_point_objective", "floatingPointObjective", default=None
    )
    if obj_raw is not None and not isinstance(obj_raw, dict):
        raise ValueError("CpModelProto `objective` must be an object.")
    if fp_obj_raw is not None and not isinstance(fp_obj_raw, dict):
        raise ValueError("CpModelProto `floating_point_objective` must be an object.")
    obj_dict = obj_raw if isinstance(obj_raw, dict) else {}
    fp_dict = fp_obj_raw if isinstance(fp_obj_raw, dict) else {}
    o_vars = tuple(_coerce_proto_int(x, "objective.vars") for x in _as_list(obj_dict.get("vars")))
    if not o_vars and fp_dict:
        o_vars = tuple(
            _coerce_proto_int(x, "floating_point_objective.vars")
            for x in _as_list(fp_dict.get("vars"))
        )
    o_coeffs = tuple(_coerce_proto_int(x, "objective.coeffs") for x in _as_list(obj_dict.get("coeffs")))
    o_scale = _opt_proto_float(obj_dict, "scaling_factor", "scalingFactor", default=0.0)
    assump = tuple(_coerce_proto_int(x, "assumptions") for x in _as_list(data.get("assumptions")))

    return CpModelProtoSummary(
        path=resolved_str,
        format=fmt,
        name=name,
        variables=tuple(vars_out),
        constraints=tuple(cts_out),
        objective_vars=o_vars,
        objective_coeffs=o_coeffs,
        objective_scaling_factor=o_scale,
        assumptions=assump,
    )


def _dict_to_cp_solver_response(
    resolved_str: str,
    fmt: Literal["json", "pbtxt"],
    data: dict[str, Any],
) -> CpSolverResponseSummary:
    raw_st = _first_scalar(data, "status", default=0)
    if isinstance(raw_st, bool):
        raise ValueError("Invalid boolean `status` in CpSolverResponse.")  # noqa: TRY004
    if isinstance(raw_st, int):
        st_code = raw_st
        st_name = _status_enum_by_code.get(st_code, f"STATUS_{st_code}")
    else:
        st_str = str(raw_st or "UNKNOWN").strip().upper()
        if st_str.isdigit():
            st_code = int(st_str)
            st_name = _status_enum_by_code.get(st_code, f"STATUS_{st_code}")
        else:
            st_code = _status_code_by_name.get(st_str, 0)
            st_name = st_str

    obj_v = _opt_proto_float(data, "objective_value", "objectiveValue", default=0.0)
    best_b = _opt_proto_float(data, "best_objective_bound", "bestObjectiveBound", default=0.0)
    suff_raw = (
        data["sufficient_assumptions_for_infeasibility"]
        if "sufficient_assumptions_for_infeasibility" in data
        else data.get("sufficientAssumptionsForInfeasibility")
    )
    suff = tuple(
        _coerce_proto_int(x, "sufficient_assumptions_for_infeasibility") for x in _as_list(suff_raw)
    )
    n_bools = _opt_proto_int(data, "num_booleans", "numBooleans", default=0)
    n_confs = _opt_proto_int(data, "num_conflicts", "numConflicts", default=0)
    n_brs = _opt_proto_int(data, "num_branches", "numBranches", default=0)
    wall_t = _opt_proto_float(data, "wall_time", "wallTime", default=0.0)
    user_t = _opt_proto_float(data, "user_time", "userTime", default=0.0)
    det_t = _opt_proto_float(data, "deterministic_time", "deterministicTime", default=0.0)
    sol_info = str(_first_scalar(data, "solution_info", "solutionInfo", default="") or "")
    s_log = str(_first_scalar(data, "solve_log", "solveLog", default="") or "")

    return CpSolverResponseSummary(
        path=resolved_str,
        format=fmt,
        status=st_name,
        status_code=st_code,
        objective_value=obj_v,
        best_objective_bound=best_b,
        sufficient_assumptions_for_infeasibility=suff,
        num_booleans=n_bools,
        num_conflicts=n_confs,
        wall_time=wall_t,
        solve_log=s_log,
        num_branches=n_brs,
        user_time=user_t,
        deterministic_time=det_t,
        solution_info=sol_info,
    )


def _check_json_depth(root: Any, max_depth: int = _MAX_PBTXT_DEPTH) -> None:
    visited: set[int] = set()
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        cur, d = stack.pop()
        if d > max_depth:
            raise ValueError(f"Corrupt or excessively nested JSON companion artifact (> {max_depth} levels).")
        oid = id(cur)
        if oid in visited:
            continue
        visited.add(oid)
        if isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, (dict, list)) and id(v) not in visited:
                    stack.append((v, d + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)) and id(v) not in visited:
                    stack.append((v, d + 1))


def parse_cp_model_proto(
    path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = _default_max_companion_bytes,
) -> CpModelProtoSummary:
    """Read a JSON, `.pbtxt`, or binary `.pb` `CpModelProto` without `ortools`/`protobuf`."""
    resolved, raw = _read_companion_bytes(
        path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    fmt = _detect_proto_format(resolved, raw)
    if fmt == "binary":
        return _parse_binary_cp_model_proto(str(resolved), raw)
    text = raw.decode("utf-8-sig")
    if fmt == "json":
        try:
            loaded = json.loads(text)
        except RecursionError as exc:
            raise ValueError("Corrupt or excessively nested JSON companion artifact.") from exc
        if not isinstance(loaded, dict):
            raise ValueError("CpModelProto JSON root must be an object.")
        _check_json_depth(loaded)
        return _dict_to_cp_model_proto(str(resolved), "json", loaded)
    tokens = _tokenize_pbtxt(text)
    parsed_dict, _ = _parse_pbtxt_block(tokens, 0, None)
    return _dict_to_cp_model_proto(str(resolved), "pbtxt", parsed_dict)


def parse_cp_solver_response(
    path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = _default_max_companion_bytes,
) -> CpSolverResponseSummary:
    """Read a JSON, `.pbtxt`, or binary `.pb` `CpSolverResponse` without `ortools`/`protobuf`."""
    resolved, raw = _read_companion_bytes(
        path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    fmt = _detect_proto_format(resolved, raw)
    if fmt == "binary":
        return _parse_binary_cp_solver_response(str(resolved), raw)
    text = raw.decode("utf-8-sig")
    if fmt == "json":
        try:
            loaded = json.loads(text)
        except RecursionError as exc:
            raise ValueError("Corrupt or excessively nested JSON companion artifact.") from exc
        if not isinstance(loaded, dict):
            raise ValueError("CpSolverResponse JSON root must be an object.")
        _check_json_depth(loaded)
        return _dict_to_cp_solver_response(str(resolved), "json", loaded)
    tokens = _tokenize_pbtxt(text)
    parsed_dict, _ = _parse_pbtxt_block(tokens, 0, None)
    return _dict_to_cp_solver_response(str(resolved), "pbtxt", parsed_dict)


def _match_prefix_anchor(
    proto_name: str,
    anchors: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any] | None:
    if not proto_name:
        return None
    for prefix, meta in anchors:
        if prefix and (proto_name == prefix or proto_name.startswith(prefix)):
            return meta
    return None


def correlate_cpsat_companions(
    repo_root: Path | str,
    report: Any,
    cp_model_proto_path: Path | str | None = None,
    cp_solver_response_path: Path | str | None = None,
    *,
    max_bytes: int = _default_max_companion_bytes,
    **_extra: object,
) -> dict[str, object]:
    """Correlate `Z=1` CpModelProto and `Z=2` CpSolverResponse back to `Z=0` source builders."""
    root_p = Path(repo_root)
    proto_arg = cp_model_proto_path or _extra.get("cp_model_proto")
    resp_arg = cp_solver_response_path or _extra.get("cp_solver_response")

    extraction: CpSatRepoExtraction = extract_repo_cpsat_models(root_p)
    node_by_file: dict[str, str] = {
        n.source_file: n.id for n in getattr(report, "nodes", ())
    }
    primary_solver_nids = [
        n.id
        for n in getattr(report, "nodes", ())
        if n.tier == "manipulate" and (n.subkind == "solver" or n.source_file in extraction.modules and extraction.modules[n.source_file].is_cpsat_module)
    ]

    var_anchors: list[tuple[str, dict[str, Any]]] = []
    ct_anchors: list[tuple[str, dict[str, Any]]] = []
    z0_vars_total = 0
    z0_cts_total = 0
    z0_objs_total = 0
    z0_assump_total = 0

    for sf, mod in sorted(extraction.modules.items()):
        if not mod.is_cpsat_module:
            continue
        nid = node_by_file.get(sf, f"m:solver:{sf}")
        z0_vars_total += len(mod.variables)
        z0_cts_total += len(mod.constraints)
        z0_objs_total += sum(len(o.terms) for o in mod.objectives)
        z0_assump_total += len(mod.assumption_vars)
        for v in mod.variables:
            meta_v = {
                "node_id": nid,
                "source_file": v.source_file,
                "line": v.line,
                "function_name": v.function_name,
                "symbol": v.symbol,
                "prefix": v.name_prefix,
            }
            for cand_p in dict.fromkeys((v.name_prefix, v.symbol)):
                if cand_p:
                    var_anchors.append((cand_p, meta_v))
        for c in mod.constraints:
            meta_c = {
                "node_id": nid,
                "source_file": c.source_file,
                "line": c.line,
                "function_name": c.function_name,
                "method": c.method,
                "prefix": c.name_prefix or c.function_name,
            }
            for cand_p in dict.fromkeys((c.name_prefix, c.function_name)):
                if cand_p:
                    ct_anchors.append((cand_p, meta_c))

    var_anchors.sort(key=lambda item: (-len(item[0]), item[0]))
    ct_anchors.sort(key=lambda item: (-len(item[0]), item[0]))

    proto_sum = (
        parse_cp_model_proto(
            proto_arg, repo_root=root_p, allow_external=True, max_bytes=max_bytes  # type: ignore[arg-type]
        )
        if proto_arg is not None
        else None
    )
    resp_sum = (
        parse_cp_solver_response(
            resp_arg, repo_root=root_p, allow_external=True, max_bytes=max_bytes  # type: ignore[arg-type]
        )
        if resp_arg is not None
        else None
    )

    return _build_companion_payload(
        report=report,
        primary_solver_nids=primary_solver_nids,
        z0_counts=(z0_vars_total, z0_cts_total, z0_objs_total, z0_assump_total),
        var_anchors=var_anchors,
        ct_anchors=ct_anchors,
        proto_sum=proto_sum,
        resp_sum=resp_sum,
    )


def _build_companion_payload(
    *,
    report: Any,
    primary_solver_nids: list[str],
    z0_counts: tuple[int, int, int, int],
    var_anchors: list[tuple[str, dict[str, Any]]],
    ct_anchors: list[tuple[str, dict[str, Any]]],
    proto_sum: CpModelProtoSummary | None,
    resp_sum: CpSolverResponseSummary | None,
) -> dict[str, object]:
    z0_vars, z0_cts, z0_objs, z0_assump = z0_counts
    wall_ties: list[dict[str, object]] = []
    default_nid = primary_solver_nids[0] if primary_solver_nids else "m:solver:default"

    z1_payload: dict[str, object] = {"present": False}
    if proto_sum is not None:
        builder_exp: dict[tuple[str, str, int], dict[str, Any]] = {}
        unmapped_vars: list[str] = []
        unmapped_cts: list[str] = []

        for pv in proto_sum.variables:
            hit = _match_prefix_anchor(pv.name, var_anchors)
            if hit is not None:
                bkey = (hit["node_id"], hit["function_name"], int(hit["line"]))
                rec = builder_exp.setdefault(
                    bkey,
                    {
                        "node_id": hit["node_id"],
                        "source_file": hit["source_file"],
                        "line": hit["line"],
                        "function_name": hit["function_name"],
                        "expanded_variables": 0,
                        "expanded_constraints": 0,
                    },
                )
                rec["expanded_variables"] += 1
            elif pv.name:
                unmapped_vars.append(pv.name)

        for pc in proto_sum.constraints:
            hit = _match_prefix_anchor(pc.name, ct_anchors) or _match_prefix_anchor(pc.name, var_anchors)
            if hit is not None:
                bkey = (hit["node_id"], hit["function_name"], int(hit["line"]))
                rec = builder_exp.setdefault(
                    bkey,
                    {
                        "node_id": hit["node_id"],
                        "source_file": hit["source_file"],
                        "line": hit["line"],
                        "function_name": hit["function_name"],
                        "expanded_variables": 0,
                        "expanded_constraints": 0,
                    },
                )
                rec["expanded_constraints"] += 1
            elif pc.name:
                unmapped_cts.append(pc.name)

        bloat = round(
            (len(proto_sum.variables) + len(proto_sum.constraints))
            / max(1, z0_vars + z0_cts),
            3,
        )
        attributions = sorted(
            builder_exp.values(),
            key=lambda item: (item["source_file"], item["line"], item["function_name"]),
        )
        z1_payload = {
            "present": True,
            "path": proto_sum.path,
            "format": proto_sum.format,
            "name": proto_sum.name,
            "variable_count": len(proto_sum.variables),
            "constraint_count": len(proto_sum.constraints),
            "objective_term_count": len(proto_sum.objective_vars),
            "assumption_count": len(proto_sum.assumptions),
            "expansion_bloat_ratio": bloat,
            "builder_attributions": attributions,
            "unmapped_variables": unmapped_vars[:25],
            "unmapped_constraints": unmapped_cts[:25],
        }
        seen_z1_nids: set[str] = set()
        for attr in attributions or [{"node_id": default_nid, "expanded_variables": len(proto_sum.variables), "expanded_constraints": len(proto_sum.constraints)}]:
            src_nid = str(attr["node_id"])
            if src_nid in seen_z1_nids:
                continue
            seen_z1_nids.add(src_nid)
            has_drift = bool(unmapped_vars or unmapped_cts or bloat >= 25.0)
            wall_ties.append(
                {
                    "id": f"wt:cpsat:z0->z1:{src_nid}",
                    "logical_key": src_nid,
                    "source_node_id": src_nid,
                    "target_node_id": f"z1:{src_nid}",
                    "from_wythe": 0,
                    "to_wythe": 1,
                    "status": "drift" if has_drift else "intact",
                    "kind": "plugin_stratum_mismatch" if has_drift else "plugin_stratum_tie",
                    "rule_code": None,
                    "label": (
                        f"Z=0->Z=1 CpModelProto ({len(proto_sum.variables)} vars, "
                        f"{len(proto_sum.constraints)} constraints, bloat={bloat}x)"
                    ),
                }
            )

    z2_payload: dict[str, object] = {"present": False}
    if resp_sum is not None:
        abs_gap = (
            round(abs(resp_sum.objective_value - resp_sum.best_objective_bound), 6)
            if resp_sum.status in ("OPTIMAL", "FEASIBLE")
            else None
        )
        rel_gap = (
            round(abs_gap / max(1.0, abs(resp_sum.objective_value)), 6)
            if abs_gap is not None
            else None
        )
        core_items: list[dict[str, object]] = []
        implicated_nids: set[str] = set()
        for lit in resp_sum.sufficient_assumptions_for_infeasibility:
            v_idx = lit if lit >= 0 else (-lit - 1)
            polarity = lit >= 0
            p_var_name = (
                proto_sum.variables[v_idx].name
                if proto_sum is not None and 0 <= v_idx < len(proto_sum.variables)
                else f"literal_{lit}"
            )
            enforced_cts = (
                [c.name for c in proto_sum.constraints if lit in c.enforcement_literals and c.name]
                if proto_sum is not None
                else []
            )
            hit = _match_prefix_anchor(p_var_name, var_anchors) or (
                _match_prefix_anchor(enforced_cts[0], ct_anchors) if enforced_cts else None
            )
            if hit is not None:
                implicated_nids.add(str(hit["node_id"]))
            core_items.append(
                {
                    "literal": lit,
                    "variable_index": v_idx,
                    "polarity": polarity,
                    "proto_variable_name": p_var_name,
                    "enforced_constraints": enforced_cts,
                    "z0_node_id": hit["node_id"] if hit else None,
                    "z0_source_file": hit["source_file"] if hit else None,
                    "z0_line": hit["line"] if hit else None,
                    "z0_function_name": hit["function_name"] if hit else None,
                }
            )

        z2_payload = {
            "present": True,
            "path": resp_sum.path,
            "format": resp_sum.format,
            "status": resp_sum.status,
            "status_code": resp_sum.status_code,
            "objective_value": resp_sum.objective_value,
            "best_objective_bound": resp_sum.best_objective_bound,
            "absolute_gap": abs_gap,
            "relative_gap": rel_gap,
            "num_booleans": resp_sum.num_booleans,
            "num_conflicts": resp_sum.num_conflicts,
            "wall_time": resp_sum.wall_time,
            "solve_log_present": bool(resp_sum.solve_log.strip()),
            "sufficient_assumptions_for_infeasibility": list(
                resp_sum.sufficient_assumptions_for_infeasibility
            ),
            "unsat_core_attributions": core_items,
        }
        tie_targets = sorted(implicated_nids) or [default_nid]
        from_w = 1 if proto_sum is not None else 0
        is_z2_drift = bool(
            resp_sum.status in ("INFEASIBLE", "MODEL_INVALID")
            or (resp_sum.status == "FEASIBLE" and abs_gap and abs_gap > 0.0)
        )
        for t_nid in tie_targets:
            src_id = f"z1:{t_nid}" if from_w == 1 else t_nid
            wall_ties.append(
                {
                    "id": f"wt:cpsat:z{from_w}->z2:{t_nid}",
                    "logical_key": t_nid,
                    "source_node_id": src_id,
                    "target_node_id": f"z2:{t_nid}",
                    "from_wythe": from_w,
                    "to_wythe": 2,
                    "status": "drift" if is_z2_drift else "intact",
                    "kind": "plugin_stratum_mismatch" if is_z2_drift else "plugin_stratum_tie",
                    "rule_code": None,
                    "label": (
                        f"Z={from_w}->Z=2 CpSolverResponse status={resp_sum.status}"
                        + (f", gap={abs_gap}" if abs_gap is not None else "")
                        + (f", unsat_core={len(core_items)}" if core_items else "")
                    ),
                }
            )

    return {
        "plugin": "cpsat",
        "target_slug": getattr(report, "target_slug", "unknown"),
        "source_commit": getattr(report, "source_commit", "unknown"),
        "z0_content_digest": getattr(report, "content_digest", ""),
        "target_code_executed": False,
        "automated_security_audit": False,
        "upstream_proto_ref": UPSTREAM_ORTOOLS_PROTO_REF,
        "z0_blueprint": {
            "solver_node_ids": primary_solver_nids,
            "ast_variable_decls": z0_vars,
            "ast_constraint_decls": z0_cts,
            "ast_objective_terms": z0_objs,
            "ast_assumption_decls": z0_assump,
        },
        "z1_cp_model_proto": z1_payload,
        "z2_cp_solver_response": z2_payload,
        "wall_ties": wall_ties,
    }
