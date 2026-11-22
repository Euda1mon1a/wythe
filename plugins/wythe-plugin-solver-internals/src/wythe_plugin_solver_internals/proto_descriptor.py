"""Pure-Python `.proto` source and wire-format `protoc` `FileDescriptorSet` parser.

Aligned with `google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5` (`ortools/sat/`)
with zero runtime dependency on `protobuf`, `ortools`, or external build toolchains.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

UPSTREAM_ORTOOLS_REF = "google/or-tools@100f66e6242ab8bf8d32feb8f3bf086db66ae2b5"
MAX_SOLVER_FILE_BYTES = 32 * 1024 * 1024  # 32 MiB hard ceiling
MAX_NESTING_DEPTH = 64
MAX_LINE_SCAN_CHARS = 4096

_OS_ROOT_SYMLINK_PREFIXES: frozenset[tuple[str, str]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)
_BINARY_CTRL_BYTES: frozenset[int] = frozenset(
    [*range(0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F]
)
_SKIP_WALK_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".next",
        "ui_dist",
        "plugins",
        "tests",
        "test",
    }
)
_LABEL_BY_CODE: dict[int, str] = {1: "optional", 2: "required", 3: "repeated"}
_SCALAR_TYPE_BY_CODE: dict[int, str] = {
    1: "double",
    2: "float",
    3: "int64",
    4: "uint64",
    5: "int32",
    6: "fixed64",
    7: "fixed32",
    8: "bool",
    9: "string",
    12: "bytes",
    13: "uint32",
    15: "sfixed32",
    16: "sfixed64",
    17: "sint32",
    18: "sint64",
}


@dataclass(frozen=True)
class ProtoFieldDef:
    name: str
    number: int
    label: str = "optional"
    type_name: str = "string"
    default_value: str | None = None
    deprecated: bool = False
    oneof_name: str | None = None
    source_file: str = ""
    line: int = 1


@dataclass(frozen=True)
class ProtoMessageDef:
    name: str
    full_name: str
    fields: tuple[ProtoFieldDef, ...] = ()
    oneofs: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source_file: str = ""
    line: int = 1


@dataclass(frozen=True)
class ConstraintCaseSpec:
    name: str
    number: int
    message_type: str
    cpp_enum_names: tuple[str, ...]
    source_file: str = ""
    line: int = 1


@dataclass(frozen=True)
class SolverProtoCatalog:
    constraint_cases: tuple[ConstraintCaseSpec, ...] = ()
    has_enforcement_literal: bool = False
    enforcement_literal_field: ProtoFieldDef | None = None
    sat_parameters: dict[str, ProtoFieldDef] = field(default_factory=dict)
    messages: dict[str, ProtoMessageDef] = field(default_factory=dict)
    descriptor_sources: tuple[str, ...] = ()


def snake_to_cpp_oneof_enums(field_name: str) -> tuple[str, ...]:
    """Return `protoc` C++ `ConstraintCase` enum identifiers (e.g. `no_overlap_2d` -> `kNoOverlap2D`)."""
    parts = [p for p in field_name.split("_") if p]
    if not parts:
        return ()
    simple = "k" + "".join(p[0].upper() + p[1:] for p in parts)
    protoc_parts: list[str] = []
    for part in parts:
        up = part[0].upper() + part[1:]
        up = re.sub(r"([0-9])([a-z])", lambda m: m.group(1) + m.group(2).upper(), up)
        protoc_parts.append(up)
    protoc_name = "k" + "".join(protoc_parts)
    return tuple(dict.fromkeys((protoc_name, simple)))


def _validate_non_symlink_repo_root(repo_root: Path) -> Path:
    if repo_root.is_symlink():
        raise ValueError(f"Refusing symlinked repository root: '{repo_root}'.")
    parts = repo_root.expanduser().parts
    for k in range(2, len(parts) + 1):
        if k == 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
            continue
        if Path(*parts[:k]).is_symlink():
            raise ValueError(f"Refusing symlinked path component in repository root '{repo_root}'.")
    return repo_root.resolve()


def read_safe_artifact_bytes(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> tuple[Path, bytes]:
    """Read a regular non-symlink file (`<= 32 MiB`), rejecting symlinks on every path component."""
    if max_bytes <= 0 or max_bytes > MAX_SOLVER_FILE_BYTES:
        max_bytes = MAX_SOLVER_FILE_BYTES
    if not isinstance(raw_path, (str, Path)):
        raise ValueError("Artifact path must be a string or Path.")  # noqa: TRY004
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Artifact path must be a non-empty string without NUL bytes.")
    cand = Path(raw_str).expanduser()
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_path}'.")
    if cand.is_symlink():
        raise ValueError(f"Refusing symlinked artifact path: '{raw_path}'.")

    if not cand.is_absolute():
        base_dir = (
            _validate_non_symlink_repo_root(repo_root)
            if repo_root is not None
            else Path.cwd().resolve()
        )
        cur = base_dir
        for part in cand.parts:
            if part in ("", "."):
                continue
            cur = cur / part
            if cur.is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
        cand = cur
        if repo_root is not None and not cand.resolve().is_relative_to(base_dir):
            raise ValueError(f"Relative artifact path '{raw_path}' escapes repository root.")
    else:
        for k in range(2, len(cand.parts) + 1):
            if k == 2 and cand.parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
                continue
            if Path(*cand.parts[:k]).is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
        if repo_root is not None:
            real_root = repo_root.resolve()
            if not allow_external and not cand.resolve().is_relative_to(real_root):
                raise ValueError(f"Artifact path '{raw_path}' escapes repository root.")
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
        raise ValueError(f"Artifact '{raw_path}' must be an existing non-symlink file.")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(cand, flags)
    except OSError as exc:
        raise ValueError(f"Cannot safely open artifact '{raw_path}': {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Artifact '{raw_path}' must be a regular file.")
        if st.st_size > max_bytes:
            raise ValueError(f"Artifact '{raw_path}' ({st.st_size} B) exceeds {max_bytes}-byte limit.")
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
            raise ValueError(f"Artifact '{raw_path}' exceeds {max_bytes}-byte limit.")
    finally:
        os.close(fd)
    return cand.resolve(), data


def read_safe_artifact_text(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
    errors: str = "strict",
) -> tuple[Path, str]:
    """Read UTF-8 text safely with symlink rejection and `<= 32 MiB` bound."""
    resolved, raw = read_safe_artifact_bytes(
        raw_path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    try:
        return resolved, raw.decode("utf-8-sig", errors=errors)
    except UnicodeDecodeError as exc:
        raise ValueError(f"Artifact '{raw_path}' is not valid UTF-8 text: {exc}") from exc


def check_json_depth(root: Any, *, max_depth: int = MAX_NESTING_DEPTH) -> None:
    """Enforce bounded JSON nesting depth iteratively without Python recursion."""
    visited: set[int] = set()
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth} levels).")
        oid = id(cur)
        if oid in visited:
            continue
        visited.add(oid)
        if isinstance(cur, dict):
            for val in cur.values():
                if isinstance(val, (dict, list)) and id(val) not in visited:
                    stack.append((val, depth + 1))
        elif isinstance(cur, list):
            for val in cur:
                if isinstance(val, (dict, list)) and id(val) not in visited:
                    stack.append((val, depth + 1))


def load_safe_json(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> tuple[Path, Any]:
    """Load JSON artifact with symlink rejection, size cap, and `<= 64` depth check."""
    resolved, text = read_safe_artifact_text(
        raw_path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    try:
        loaded = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"Malformed or excessively nested JSON in '{raw_path}': {exc}") from exc
    check_json_depth(loaded, max_depth=MAX_NESTING_DEPTH)
    return resolved, loaded


def iter_safe_repo_files(
    repo_root: Path,
    *,
    suffixes: frozenset[str],
    max_files: int = 2000,
) -> list[tuple[str, Path]]:
    """Walk `repo_root` without following symlinks, returning sorted `(rel_posix, abs_path)`."""
    if repo_root.is_symlink() or not repo_root.is_dir():
        return []
    try:
        real_root = _validate_non_symlink_repo_root(repo_root)
    except ValueError:
        return []

    found: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(real_root, topdown=True, followlinks=False):
        cur_dir = Path(dirpath)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in _SKIP_WALK_DIRS and not (cur_dir / d).is_symlink()
        )
        for fname in sorted(filenames):
            cand = cur_dir / fname
            if cand.suffix.lower() not in suffixes or cand.is_symlink():
                continue
            try:
                st = cand.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SOLVER_FILE_BYTES:
                    continue
                resolved = cand.resolve()
                if not resolved.is_relative_to(real_root):
                    continue
                rel_posix = resolved.relative_to(real_root).as_posix()
            except OSError:
                continue
            found.append((rel_posix, resolved))
            if len(found) >= max_files:
                found.sort(key=lambda item: item[0])
                return found
    found.sort(key=lambda item: item[0])
    return found


def strip_c_comments_and_strings(source: str, *, blank_strings: bool = True) -> str:
    """Linear O(N) C/C++/.proto comment stripper preserving exact newline positions."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
        elif ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
        elif ch in ('"', "'"):
            quote = ch
            out.append(quote)
            i += 1
            while i < n:
                c = source[i]
                if c == "\\":
                    if i + 1 < n:
                        sec = source[i + 1]
                        if blank_strings:
                            out.append(" ")
                            out.append("\n" if sec == "\n" else " ")
                        else:
                            out.append("\\")
                            out.append(sec)
                        i += 2
                        continue
                    out.append(" " if blank_strings else "\\")
                    i += 1
                    break
                if c == quote:
                    out.append(quote)
                    i += 1
                    break
                if c == "\n":
                    out.append("\n")
                    i += 1
                    break
                out.append(" " if blank_strings else c)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _read_varint(buf: bytes, pos: int, end: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < end and shift < 70:
        byte = buf[pos]
        pos += 1
        if shift == 63 and byte > 0x01:
            raise ValueError("Invalid protobuf varint exceeding 64-bit / 70-bit bound.")
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Truncated or oversized (>= 70-bit) varint in binary protobuf descriptor.")


def _to_signed_int32(uval: int) -> int:
    masked64 = uval & 0xFFFFFFFFFFFFFFFF
    s64 = masked64 - (1 << 64) if masked64 >= (1 << 63) else masked64
    masked32 = s64 & 0xFFFFFFFF
    return masked32 - (1 << 32) if masked32 >= (1 << 31) else masked32


def _iter_wire_fields(buf: bytes, start: int = 0, end: int | None = None) -> list[tuple[int, int, int | bytes]]:
    limit = len(buf) if end is None else end
    if start < 0 or limit > len(buf) or start > limit:
        raise ValueError("Invalid slice bounds in binary protobuf descriptor.")
    fields: list[tuple[int, int, int | bytes]] = []
    pos = start
    while pos < limit:
        tag, pos = _read_varint(buf, pos, limit)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num <= 0:
            raise ValueError("Invalid protobuf field number 0 in descriptor.")
        if wire_type == 0:
            val, pos = _read_varint(buf, pos, limit)
            fields.append((field_num, 0, val))
        elif wire_type == 1:
            if pos + 8 > limit:
                raise ValueError("Truncated 64-bit fixed field in protobuf descriptor.")
            fields.append((field_num, 1, buf[pos : pos + 8]))
            pos += 8
        elif wire_type == 2:
            ln, pos = _read_varint(buf, pos, limit)
            sub_end = pos + ln
            if ln < 0 or sub_end > limit:
                raise ValueError("Oversized or truncated length-delimited field in protobuf descriptor.")
            fields.append((field_num, 2, buf[pos:sub_end]))
            pos = sub_end
        elif wire_type == 5:
            if pos + 4 > limit:
                raise ValueError("Truncated 32-bit fixed field in protobuf descriptor.")
            fields.append((field_num, 5, buf[pos : pos + 4]))
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type {wire_type} on field {field_num}.")
    return fields


def _parse_field_options_wire(buf: bytes) -> bool:
    deprecated = False
    for fnum, wtype, val in _iter_wire_fields(buf):
        if fnum == 3 and wtype == 0 and isinstance(val, int):
            deprecated = val != 0
    return deprecated


def _parse_oneof_decl_wire(buf: bytes) -> str:
    for fnum, wtype, val in _iter_wire_fields(buf):
        if fnum == 1 and wtype == 2 and isinstance(val, bytes):
            return val.decode("utf-8", errors="replace").strip()
    return ""


def _parse_descriptor_proto_wire(
    buf: bytes,
    *,
    pkg_prefix: str,
    source_file: str,
    out: dict[str, ProtoMessageDef],
    depth: int,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError(f"Protobuf message nesting depth exceeds {MAX_NESTING_DEPTH}.")
    msg_name = ""
    raw_fields: list[tuple[str, int, str, str, str | None, bool, int | None, bool]] = []
    oneof_names: list[str] = []
    nested_blobs: list[bytes] = []

    for fnum, wtype, val in _iter_wire_fields(buf):
        if fnum == 1 and wtype == 2 and isinstance(val, bytes):
            msg_name = val.decode("utf-8", errors="replace").strip()
        elif fnum == 2 and wtype == 2 and isinstance(val, bytes):
            f_name = ""
            f_num = 0
            f_label = "optional"
            f_type = "message"
            f_type_name = ""
            f_default: str | None = None
            f_depr = False
            f_oneof_idx: int | None = None
            f_proto3_opt = False
            for ff, fw, fv in _iter_wire_fields(val):
                if ff == 1 and fw == 2 and isinstance(fv, bytes):
                    f_name = fv.decode("utf-8", errors="replace").strip()
                elif ff == 3 and fw == 0 and isinstance(fv, int):
                    f_num = _to_signed_int32(fv)
                elif ff == 4 and fw == 0 and isinstance(fv, int):
                    f_label = _LABEL_BY_CODE.get(_to_signed_int32(fv), "optional")
                elif ff == 5 and fw == 0 and isinstance(fv, int):
                    code = _to_signed_int32(fv)
                    f_type = _SCALAR_TYPE_BY_CODE.get(code, "enum" if code == 14 else "message")
                elif ff == 6 and fw == 2 and isinstance(fv, bytes):
                    f_type_name = fv.decode("utf-8", errors="replace").strip().lstrip(".")
                elif ff == 7 and fw == 2 and isinstance(fv, bytes):
                    f_default = fv.decode("utf-8", errors="replace")
                elif ff == 8 and fw == 2 and isinstance(fv, bytes):
                    f_depr = _parse_field_options_wire(fv)
                elif ff == 9 and fw == 0 and isinstance(fv, int):
                    f_oneof_idx = _to_signed_int32(fv)
                elif ff == 17 and fw == 0 and isinstance(fv, int):
                    f_proto3_opt = fv != 0
            if f_name:
                resolved_type = f_type_name.rsplit(".", 1)[-1] if f_type_name else f_type
                raw_fields.append(
                    (f_name, f_num, f_label, resolved_type, f_default, f_depr, f_oneof_idx, f_proto3_opt)
                )
        elif fnum == 3 and wtype == 2 and isinstance(val, bytes):
            nested_blobs.append(val)
        elif fnum == 8 and wtype == 2 and isinstance(val, bytes):
            oneof_names.append(_parse_oneof_decl_wire(val))

    if not msg_name:
        return
    full_name = f"{pkg_prefix}.{msg_name}" if pkg_prefix else msg_name
    fields_out: list[ProtoFieldDef] = []
    oneofs_map: dict[str, list[str]] = {}
    for f_name, f_num, f_label, r_type, f_def, f_depr, f_oidx, f_p3opt in raw_fields:
        oneof_name: str | None = None
        if f_oidx is not None and not f_p3opt and 0 <= f_oidx < len(oneof_names):
            cand_oname = oneof_names[f_oidx]
            if cand_oname and not cand_oname.startswith("_"):
                oneof_name = cand_oname
                oneofs_map.setdefault(oneof_name, []).append(f_name)
        fields_out.append(
            ProtoFieldDef(
                name=f_name,
                number=f_num,
                label=f_label,
                type_name=r_type,
                default_value=f_def,
                deprecated=f_depr,
                oneof_name=oneof_name,
                source_file=source_file,
                line=1,
            )
        )

    msg_def = ProtoMessageDef(
        name=msg_name,
        full_name=full_name,
        fields=tuple(fields_out),
        oneofs={k: tuple(v) for k, v in oneofs_map.items()},
        source_file=source_file,
        line=1,
    )
    out[full_name] = msg_def
    out.setdefault(msg_name, msg_def)

    for nested in nested_blobs:
        _parse_descriptor_proto_wire(
            nested,
            pkg_prefix=full_name,
            source_file=source_file,
            out=out,
            depth=depth + 1,
        )


def parse_file_descriptor_set_bytes(
    buf: bytes,
    *,
    source_label: str = "<descriptor.pb>",
) -> dict[str, ProtoMessageDef]:
    """Decode wire-format `google.protobuf.FileDescriptorSet` bytes without `protobuf`."""
    if len(buf) > MAX_SOLVER_FILE_BYTES:
        raise ValueError(f"Descriptor payload exceeds {MAX_SOLVER_FILE_BYTES}-byte limit.")
    messages: dict[str, ProtoMessageDef] = {}
    for fnum, wtype, val in _iter_wire_fields(buf):
        if fnum != 1 or wtype != 2 or not isinstance(val, bytes):
            continue
        proto_file = source_label
        package = ""
        msg_blobs: list[bytes] = []
        for ff, fw, fv in _iter_wire_fields(val):
            if ff == 1 and fw == 2 and isinstance(fv, bytes):
                proto_file = fv.decode("utf-8", errors="replace").strip() or source_label
            elif ff == 2 and fw == 2 and isinstance(fv, bytes):
                package = fv.decode("utf-8", errors="replace").strip()
            elif ff == 4 and fw == 2 and isinstance(fv, bytes):
                msg_blobs.append(fv)
        for mb in msg_blobs:
            _parse_descriptor_proto_wire(
                mb,
                pkg_prefix=package,
                source_file=proto_file,
                out=messages,
                depth=1,
            )
    return messages


def _parse_descriptor_json_msg(
    msg_obj: dict[str, Any],
    *,
    pkg_prefix: str,
    source_file: str,
    out: dict[str, ProtoMessageDef],
    depth: int,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError(f"JSON descriptor message nesting exceeds {MAX_NESTING_DEPTH}.")
    msg_name = str(msg_obj.get("name") or "").strip()
    if not msg_name:
        return
    full_name = f"{pkg_prefix}.{msg_name}" if pkg_prefix else msg_name
    raw_oneofs = msg_obj.get("oneofDecl", msg_obj.get("oneof_decl")) or []
    oneof_names = [
        str(o.get("name") or "").strip() if isinstance(o, dict) else ""
        for o in raw_oneofs
    ]
    fields_out: list[ProtoFieldDef] = []
    oneofs_map: dict[str, list[str]] = {}
    raw_fields = msg_obj.get("field") or []
    if not isinstance(raw_fields, list):
        raise ValueError("DescriptorProto `field` entry must be a list.")  # noqa: TRY004
    for f_obj in raw_fields:
        if not isinstance(f_obj, dict):
            raise ValueError("FieldDescriptorProto entry must be an object.")  # noqa: TRY004
        f_name = str(f_obj.get("name") or "").strip()
        if not f_name:
            continue
        raw_num = f_obj.get("number", 0)
        if isinstance(raw_num, bool) or not isinstance(raw_num, int):
            raise ValueError(f"Invalid field number for '{f_name}': {raw_num!r}")  # noqa: TRY004
        raw_lbl = f_obj.get("label", "optional")
        if isinstance(raw_lbl, int) and not isinstance(raw_lbl, bool):
            f_label = _LABEL_BY_CODE.get(raw_lbl, "optional")
        else:
            f_label = str(raw_lbl).lower().removeprefix("label_")
        t_name = str(f_obj.get("typeName") or f_obj.get("type_name") or "").strip().lstrip(".")
        if t_name:
            r_type = t_name.rsplit(".", 1)[-1]
        else:
            raw_t = f_obj.get("type", "string")
            if isinstance(raw_t, int) and not isinstance(raw_t, bool):
                r_type = _SCALAR_TYPE_BY_CODE.get(raw_t, "message")
            else:
                r_type = str(raw_t).lower().removeprefix("type_")
        def_val = f_obj.get("defaultValue", f_obj.get("default_value"))
        f_def = str(def_val) if def_val is not None else None
        opts = f_obj.get("options")
        f_depr = bool(opts.get("deprecated")) if isinstance(opts, dict) else False
        p3_opt = bool(f_obj.get("proto3Optional", f_obj.get("proto3_optional", False)))
        oidx = f_obj.get("oneofIndex", f_obj.get("oneof_index"))
        oneof_name: str | None = None
        if isinstance(oidx, int) and not isinstance(oidx, bool) and not p3_opt and 0 <= oidx < len(oneof_names):
            cand_o = oneof_names[oidx]
            if cand_o and not cand_o.startswith("_"):
                oneof_name = cand_o
                oneofs_map.setdefault(oneof_name, []).append(f_name)
        fields_out.append(
            ProtoFieldDef(
                name=f_name,
                number=raw_num,
                label=f_label,
                type_name=r_type,
                default_value=f_def,
                deprecated=f_depr,
                oneof_name=oneof_name,
                source_file=source_file,
                line=1,
            )
        )

    msg_def = ProtoMessageDef(
        name=msg_name,
        full_name=full_name,
        fields=tuple(fields_out),
        oneofs={k: tuple(v) for k, v in oneofs_map.items()},
        source_file=source_file,
        line=1,
    )
    out[full_name] = msg_def
    out.setdefault(msg_name, msg_def)

    nested_list = msg_obj.get("nestedType", msg_obj.get("nested_type")) or []
    if isinstance(nested_list, list):
        for nested in nested_list:
            if isinstance(nested, dict):
                _parse_descriptor_json_msg(
                    nested,
                    pkg_prefix=full_name,
                    source_file=source_file,
                    out=out,
                    depth=depth + 1,
                )


def parse_file_descriptor_set_json(
    data: Any,
    *,
    source_label: str = "<descriptor.json>",
) -> dict[str, ProtoMessageDef]:
    """Parse JSON `FileDescriptorSet` object with strict depth & type validation."""
    if not isinstance(data, dict):
        raise ValueError("JSON FileDescriptorSet root must be an object.")  # noqa: TRY004
    check_json_depth(data, max_depth=MAX_NESTING_DEPTH)
    files = data.get("file")
    if not isinstance(files, list):
        raise ValueError("JSON FileDescriptorSet requires a 'file' array.")  # noqa: TRY004
    messages: dict[str, ProtoMessageDef] = {}
    for f_entry in files:
        if not isinstance(f_entry, dict):
            raise ValueError("FileDescriptorProto entry in 'file' must be an object.")  # noqa: TRY004
        p_file = str(f_entry.get("name") or source_label).strip()
        pkg = str(f_entry.get("package") or "").strip()
        m_types = f_entry.get("messageType", f_entry.get("message_type")) or []
        if not isinstance(m_types, list):
            raise ValueError("FileDescriptorProto `message_type` must be a list.")  # noqa: TRY004
        for m_obj in m_types:
            if isinstance(m_obj, dict):
                _parse_descriptor_json_msg(
                    m_obj,
                    pkg_prefix=pkg,
                    source_file=p_file,
                    out=messages,
                    depth=1,
                )
    return messages


_PROTO_PKG_RE = re.compile(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$")
_PROTO_BLOCK_RE = re.compile(r"^\s*(message|oneof|enum|service|extend)\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$")
_PROTO_FIELD_RE = re.compile(
    r"^\s*(?:(optional|repeated|required)\s+)?"
    r"(map<\s*[A-Za-z0-9_.]+\s*,\s*[A-Za-z0-9_.]+\s*>|\.?[A-Za-z_][A-Za-z0-9_.]*)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)"
    r"(?:\s*\[([^\]]{0,1024})\])?\s*$"
)
_PROTO_DEFAULT_RE = re.compile(
    r"""\bdefault\s*=\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,\]]+)"""
)
_PROTO_DEPRECATED_RE = re.compile(r"\bdeprecated\s*=\s*true\b")


def parse_proto_source_text(
    text: str,
    *,
    source_file: str = "<memory>",
) -> dict[str, ProtoMessageDef]:
    """Parse `.proto` source text in linear O(N) time without `protoc`."""
    cleaned = strip_c_comments_and_strings(text, blank_strings=False)
    package = ""
    messages: dict[str, ProtoMessageDef] = {}
    stack: list[dict[str, Any]] = []
    buf_chars: list[str] = []
    stmt_has_token = False
    stmt_line = 1
    cur_line = 1
    in_quote: str | None = None
    i = 0
    n = len(cleaned)

    def _flush_stmt(delim: str, line_no: int) -> None:
        nonlocal package, stmt_has_token
        stmt = "".join(buf_chars).strip()
        buf_chars.clear()
        stmt_has_token = False
        bounded = stmt[:MAX_LINE_SCAN_CHARS]

        if delim == "{":
            if len(stack) >= MAX_NESTING_DEPTH:
                raise ValueError(f".proto block nesting exceeds {MAX_NESTING_DEPTH} levels.")
            m_blk = _PROTO_BLOCK_RE.match(bounded)
            if m_blk:
                bkind, bname = m_blk.group(1), m_blk.group(2)
                if bkind == "message":
                    msg_ancestors = [s["name"] for s in stack if s["kind"] == "message"]
                    prefix_parts = ([package] if package else []) + msg_ancestors
                    full = ".".join([*prefix_parts, bname])
                    stack.append(
                        {
                            "kind": "message",
                            "name": bname,
                            "full_name": full,
                            "fields": [],
                            "oneofs": {},
                            "line": line_no,
                        }
                    )
                    return
                if bkind == "oneof":
                    stack.append({"kind": "oneof", "name": bname, "line": line_no})
                    return
                stack.append({"kind": bkind, "name": bname, "line": line_no})
                return
            stack.append({"kind": "other", "name": "", "line": line_no})
            return

        if delim == "}":
            if not stack:
                return
            popped = stack.pop()
            if popped["kind"] == "message":
                mdef = ProtoMessageDef(
                    name=popped["name"],
                    full_name=popped["full_name"],
                    fields=tuple(popped["fields"]),
                    oneofs={k: tuple(v) for k, v in popped["oneofs"].items()},
                    source_file=source_file,
                    line=popped["line"],
                )
                messages[mdef.full_name] = mdef
                messages.setdefault(mdef.name, mdef)
            return

        if not bounded:
            return
        if not stack:
            m_pkg = _PROTO_PKG_RE.match(bounded)
            if m_pkg:
                package = m_pkg.group(1)
            return

        top = stack[-1]
        if top["kind"] not in ("message", "oneof") or bounded.startswith(("option ", "reserved ", "extensions ")):
            return
        msg_ctx = top if top["kind"] == "message" else (stack[-2] if len(stack) >= 2 and stack[-2]["kind"] == "message" else None)
        if msg_ctx is None:
            return
        m_fld = _PROTO_FIELD_RE.match(bounded)
        if not m_fld:
            return
        raw_lbl, raw_type, fname, raw_num, raw_opts = m_fld.groups()
        oneof_name = top["name"] if top["kind"] == "oneof" else None
        def_val: str | None = None
        depr = False
        if raw_opts:
            m_def = _PROTO_DEFAULT_RE.search(raw_opts)
            if m_def:
                def_val = m_def.group(1).strip("\"'")
            if _PROTO_DEPRECATED_RE.search(raw_opts):
                depr = True
        short_type = raw_type.lstrip(".").rsplit(".", 1)[-1]
        fdef = ProtoFieldDef(
            name=fname,
            number=int(raw_num),
            label=raw_lbl or "optional",
            type_name=short_type,
            default_value=def_val,
            deprecated=depr,
            oneof_name=oneof_name,
            source_file=source_file,
            line=stmt_line,
        )
        msg_ctx["fields"].append(fdef)
        if oneof_name:
            msg_ctx["oneofs"].setdefault(oneof_name, []).append(fname)

    while i < n:
        ch = cleaned[i]
        if ch == "\n":
            cur_line += 1
        if in_quote is not None:
            buf_chars.append(ch)
            if ch == "\\" and i + 1 < n:
                i += 1
                if cleaned[i] == "\n":
                    cur_line += 1
                buf_chars.append(cleaned[i])
            elif ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            if not stmt_has_token:
                stmt_line = cur_line
                stmt_has_token = True
            in_quote = ch
            buf_chars.append(ch)
            i += 1
            continue
        if ch in ("{", "}", ";"):
            _flush_stmt(ch, stmt_line)
            stmt_line = cur_line
            i += 1
            continue
        if not ch.isspace() and not stmt_has_token:
            stmt_line = cur_line
            stmt_has_token = True
        buf_chars.append(ch)
        i += 1

    return messages


def parse_proto_descriptor_artifact(
    path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> dict[str, ProtoMessageDef]:
    """Parse a `.pb` binary FileDescriptorSet, `.json` FileDescriptorSet, or `.proto` file."""
    resolved, raw = read_safe_artifact_bytes(
        path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    suffix = resolved.suffix.lower()
    if suffix == ".proto":
        return parse_proto_source_text(raw.decode("utf-8-sig"), source_file=str(resolved))
    is_binary = any(b in _BINARY_CTRL_BYTES for b in raw)
    if not is_binary:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            is_binary = True
        else:
            stripped = text.lstrip()
            if stripped.startswith("{"):
                try:
                    loaded = json.loads(text)
                except (json.JSONDecodeError, RecursionError) as exc:
                    raise ValueError(f"Invalid JSON FileDescriptorSet '{path}': {exc}") from exc
                return parse_file_descriptor_set_json(loaded, source_label=str(resolved))
            if suffix not in (".pb", ".bin", ".desc", ".protobin") and (
                "syntax" in stripped[:256] or "message " in stripped[:512]
            ):
                return parse_proto_source_text(text, source_file=str(resolved))
    return parse_file_descriptor_set_bytes(raw, source_label=str(resolved))


def _merge_proto_messages(
    dest: dict[str, ProtoMessageDef],
    incoming: dict[str, ProtoMessageDef],
) -> None:
    for key, msg in incoming.items():
        prev = dest.get(key)
        if prev is None:
            dest[key] = msg
            continue
        by_name = {f.name: f for f in prev.fields}
        merged_fields = list(prev.fields)
        for nf in msg.fields:
            existing_f = by_name.get(nf.name)
            if existing_f is None:
                merged_fields.append(nf)
            elif existing_f.line <= 1 and nf.line > 1:
                idx = merged_fields.index(existing_f)
                merged_fields[idx] = nf
        merged_oneofs = dict(prev.oneofs)
        for ok, ov in msg.oneofs.items():
            cur_o = list(merged_oneofs.get(ok, ()))
            for fn in ov:
                if fn not in cur_o:
                    cur_o.append(fn)
            merged_oneofs[ok] = tuple(cur_o)
        dest[key] = ProtoMessageDef(
            name=prev.name,
            full_name=prev.full_name,
            fields=tuple(merged_fields),
            oneofs=merged_oneofs,
            source_file=prev.source_file if prev.line > 1 else (msg.source_file or prev.source_file),
            line=prev.line if prev.line > 1 else msg.line,
        )


def build_solver_proto_catalog(
    repo_root: Path,
    *,
    descriptor_paths: Sequence[Path | str] = (),
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> SolverProtoCatalog:
    """Build merged `SolverProtoCatalog` from in-repo `.proto` files and `--proto-descriptor` sets."""
    merged_msgs: dict[str, ProtoMessageDef] = {}
    sources: list[str] = []

    for rel_posix, abs_p in iter_safe_repo_files(repo_root, suffixes=frozenset({".proto"})):
        _, text = read_safe_artifact_text(abs_p, repo_root=repo_root, max_bytes=max_bytes)
        if "ConstraintProto" not in text and "SatParameters" not in text:
            continue
        parsed = parse_proto_source_text(text, source_file=rel_posix)
        if parsed:
            _merge_proto_messages(merged_msgs, parsed)
            sources.append(rel_posix)

    for desc_p in descriptor_paths:
        parsed_desc = parse_proto_descriptor_artifact(
            desc_p, repo_root=repo_root, allow_external=True, max_bytes=max_bytes
        )
        if parsed_desc:
            _merge_proto_messages(merged_msgs, parsed_desc)
            sources.append(str(desc_p))

    ct_msg = merged_msgs.get("ConstraintProto") or next(
        (m for k, m in sorted(merged_msgs.items()) if k.endswith(".ConstraintProto")),
        None,
    )
    sat_msg = merged_msgs.get("SatParameters") or next(
        (m for k, m in sorted(merged_msgs.items()) if k.endswith(".SatParameters")),
        None,
    )

    cases: list[ConstraintCaseSpec] = []
    enf_field: ProtoFieldDef | None = None
    if ct_msg is not None:
        oneof_members = set(ct_msg.oneofs.get("constraint", ()))
        if not oneof_members and ct_msg.oneofs:
            first_key = min(ct_msg.oneofs)
            oneof_members = set(ct_msg.oneofs[first_key])
        for fld in sorted(ct_msg.fields, key=lambda f: (f.number, f.name)):
            if fld.name == "enforcement_literal":
                enf_field = fld
            if fld.name in oneof_members or fld.oneof_name == "constraint":
                cases.append(
                    ConstraintCaseSpec(
                        name=fld.name,
                        number=fld.number,
                        message_type=fld.type_name,
                        cpp_enum_names=snake_to_cpp_oneof_enums(fld.name),
                        source_file=fld.source_file or ct_msg.source_file,
                        line=fld.line,
                    )
                )

    sat_params: dict[str, ProtoFieldDef] = {}
    if sat_msg is not None:
        for fld in sorted(sat_msg.fields, key=lambda f: (f.number, f.name)):
            sat_params[fld.name] = fld

    return SolverProtoCatalog(
        constraint_cases=tuple(cases),
        has_enforcement_literal=enf_field is not None,
        enforcement_literal_field=enf_field,
        sat_parameters=sat_params,
        messages=merged_msgs,
        descriptor_sources=tuple(dict.fromkeys(sources)),
    )
