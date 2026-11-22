"""CPU <-> Metal GPU (`MSL` & `.metallib` `AIR`) compute seam verifier (`METAL-001..003`).

Extracts host Metal compute dispatches across Swift, Objective-C++, C++, and Python,
parses `.metal` shader kernels/buffers/structs and `--metallib` `AIR` disassembly or raw
`MTLB` binary headers, and verifies kernel presence, buffer-index contracts, and shared
host/GPU struct memory layouts without executing `xcrun` or shader compilers.
"""

from __future__ import annotations

import ast
import io
import json
import re
import struct
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from wythe_plugin_compiler_ir.usr_index import (
    iter_safe_repo_files,
    load_bounded_json_or_yaml,
    normalize_repo_relpath,
    read_safe_bytes,
    read_safe_text,
    validate_safe_path,
)

MAX_SOURCE_LINE_CHARS: Final[int] = 4096

METAL_AIR_EPISTEMIC_NOTE: Final[str] = (
    "Epistemic boundary (Metal AIR vs AGX ISA): Wythe verifies host compute dispatches "
    "against .metal shader sources and compiled .metallib LLVM-based Apple Intermediate "
    "Representation (AIR) bitcode/reflection metadata; final per-GPU machine ISA (such as "
    "Apple AGX instructions, register allocation, and threadgroup occupancy) is lowered at "
    "runtime by the OS Metal driver and remains outside static verification claims."
)

# (size_bytes, alignment_bytes) for MSL, Apple simd, C/C++, and Swift scalar/vector types
_TYPE_LAYOUT_TABLE: Final[dict[str, tuple[int, int]]] = {
    "bool": (1, 1),
    "Bool": (1, 1),
    "char": (1, 1),
    "signed char": (1, 1),
    "unsigned char": (1, 1),
    "uchar": (1, 1),
    "int8_t": (1, 1),
    "uint8_t": (1, 1),
    "Int8": (1, 1),
    "UInt8": (1, 1),
    "short": (2, 2),
    "unsigned short": (2, 2),
    "ushort": (2, 2),
    "int16_t": (2, 2),
    "uint16_t": (2, 2),
    "Int16": (2, 2),
    "UInt16": (2, 2),
    "half": (2, 2),
    "bfloat16_t": (2, 2),
    "bfloat": (2, 2),
    "__fp16": (2, 2),
    "Float16": (2, 2),
    "int": (4, 4),
    "signed int": (4, 4),
    "unsigned int": (4, 4),
    "unsigned": (4, 4),
    "uint": (4, 4),
    "int32_t": (4, 4),
    "uint32_t": (4, 4),
    "Int32": (4, 4),
    "UInt32": (4, 4),
    "float": (4, 4),
    "Float": (4, 4),
    "Float32": (4, 4),
    "atomic_int": (4, 4),
    "atomic_uint": (4, 4),
    "atomic_float": (4, 4),
    "long": (8, 8),
    "unsigned long": (8, 8),
    "ulong": (8, 8),
    "long long": (8, 8),
    "unsigned long long": (8, 8),
    "int64_t": (8, 8),
    "uint64_t": (8, 8),
    "size_t": (8, 8),
    "ptrdiff_t": (8, 8),
    "uintptr_t": (8, 8),
    "intptr_t": (8, 8),
    "double": (8, 8),
    "Double": (8, 8),
    "Int": (8, 8),
    "UInt": (8, 8),
    "Int64": (8, 8),
    "UInt64": (8, 8),
    # 2-component vectors
    "char2": (2, 2),
    "uchar2": (2, 2),
    "short2": (4, 4),
    "ushort2": (4, 4),
    "half2": (4, 4),
    "bfloat2": (4, 4),
    "float2": (8, 8),
    "int2": (8, 8),
    "uint2": (8, 8),
    "simd_float2": (8, 8),
    "simd::float2": (8, 8),
    "simd_int2": (8, 8),
    "simd_uint2": (8, 8),
    "SIMD2<Float>": (8, 8),
    "SIMD2<Int32>": (8, 8),
    "SIMD2<UInt32>": (8, 8),
    # 3-component vectors: 16-byte aligned/padded in MSL & Apple simd!
    "char3": (4, 4),
    "uchar3": (4, 4),
    "short3": (8, 8),
    "ushort3": (8, 8),
    "half3": (8, 8),
    "bfloat3": (8, 8),
    "float3": (16, 16),
    "int3": (16, 16),
    "uint3": (16, 16),
    "simd_float3": (16, 16),
    "simd::float3": (16, 16),
    "simd_int3": (16, 16),
    "simd_uint3": (16, 16),
    "SIMD3<Float>": (16, 16),
    "SIMD3<Int32>": (16, 16),
    "SIMD3<UInt32>": (16, 16),
    # Packed 3-component vectors: 12 bytes (align 4 for packed_float3 / MTLPackedFloat3)
    "packed_char3": (3, 1),
    "packed_uchar3": (3, 1),
    "packed_short3": (6, 2),
    "packed_ushort3": (6, 2),
    "packed_half3": (6, 2),
    "packed_float3": (12, 4),
    "packed_int3": (12, 4),
    "packed_uint3": (12, 4),
    "MTLPackedFloat3": (12, 4),
    # 4-component vectors & matrices
    "char4": (4, 4),
    "uchar4": (4, 4),
    "short4": (8, 8),
    "ushort4": (8, 8),
    "half4": (8, 8),
    "float4": (16, 16),
    "int4": (16, 16),
    "uint4": (16, 16),
    "simd_float4": (16, 16),
    "simd::float4": (16, 16),
    "simd_int4": (16, 16),
    "simd_uint4": (16, 16),
    "SIMD4<Float>": (16, 16),
    "float2x2": (16, 8),
    "simd_float2x2": (16, 8),
    "float3x3": (48, 16),
    "simd_float3x3": (48, 16),
    "float4x4": (64, 16),
    "simd_float4x4": (64, 16),
}


def strip_comments_preserve_lines(source: str) -> str:
    """Linear O(N) comment stripper preserving string literals and exact newline positions."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c2 = source[i]
                out.append(c2)
                i += 1
                if c2 == "\\" and i < n:
                    out.append(source[i])
                    i += 1
                elif c2 == quote or c2 == "\n":
                    break
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n:
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    rem = value % alignment
    return value if rem == 0 else value + (alignment - rem)


def _filter_metal_ifdefs(cleaned_source: str, *, is_metal: bool) -> str:
    """Resolve `#ifdef __METAL_VERSION__` / `#ifndef __METAL_VERSION__` preserving line numbers."""
    stack: list[bool] = []
    out_lines: list[str] = []
    for raw_line in cleaned_source.splitlines(keepends=True):
        nl = "\n" if raw_line.endswith("\n") else ""
        stripped = raw_line[:MAX_SOURCE_LINE_CHARS].strip()
        if stripped.startswith("#"):
            directive = stripped[1:].strip()
            if directive.startswith("ifdef ") and "__METAL_VERSION__" in directive:
                stack.append(is_metal)
                out_lines.append(nl)
                continue
            if directive.startswith("ifndef ") and "__METAL_VERSION__" in directive:
                stack.append(not is_metal)
                out_lines.append(nl)
                continue
            if directive.startswith("if ") and "__METAL_VERSION__" in directive:
                neg = "!defined" in directive or "! defined" in directive
                stack.append((not is_metal) if neg else is_metal)
                out_lines.append(nl)
                continue
            if directive.startswith("else") and stack:
                stack[-1] = not stack[-1]
                out_lines.append(nl)
                continue
            if directive.startswith("endif") and stack:
                stack.pop()
                out_lines.append(nl)
                continue
        if all(stack):
            out_lines.append(raw_line)
        else:
            out_lines.append(nl)
    return "".join(out_lines)


@dataclass(frozen=True)
class StructFieldLayout:
    """Computed byte offset, size, and alignment of one field in a host or MSL struct."""

    name: str
    type_name: str
    offset: int
    size: int
    alignment: int


@dataclass(frozen=True)
class StructLayoutSpec:
    """Computed memory layout of a C/C++/ObjC++/Swift/MSL `struct`."""

    name: str
    domain: str  # "host" | "metal"
    source_file: str
    line: int
    size: int
    stride: int
    alignment: int
    fields: tuple[StructFieldLayout, ...]


_STD_ARRAY_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:std::)?array<\s*([A-Za-z0-9_: ]+?)\s*,\s*(\d+)\s*>$"
)
_SWIFT_TUPLE_RE: Final[re.Pattern[str]] = re.compile(r"^\(([^()]{1,120})\)$")
_ALIGNAS_RE: Final[re.Pattern[str]] = re.compile(r"\balignas\(\s*(\d+)\s*\)")
_ATTR_ALIGN_RE: Final[re.Pattern[str]] = re.compile(r"aligned\(\s*(\d+)\s*\)")
_C_STRUCT_DECL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:typedef\s+)?struct\b([^;{]{0,160})\{",
)
_SWIFT_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:public\s+|internal\s+|private\s+)?(?:var|let)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^=;{\n]{1,120})"
)
_ARRAY_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"^(.*?)\[\s*(\d+)\s*\]$")
_IDENT_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"^(.*\S)\s+([A-Za-z_][A-Za-z0-9_]*)$")


def _parse_c_field_decl(stmt: str) -> tuple[str, str, str | None] | None:
    """Linear O(N) non-backtracking parser for C/C++/MSL struct field declarations."""
    head = stmt[:240].split("=", 1)[0].strip()
    if not head:
        return None
    arr_cnt: str | None = None
    am = _ARRAY_SUFFIX_RE.match(head)
    if am:
        head = am.group(1).strip()
        arr_cnt = am.group(2)
    im = _IDENT_SUFFIX_RE.match(head)
    if not im:
        return None
    ftype = im.group(1).strip()
    fname = im.group(2)
    if not ftype or any(ch in ftype for ch in ("(", ")", ";", "{", "}")):
        return None
    return ftype, fname, arr_cnt


def _resolve_type_layout(
    raw_type: str,
    known_structs: dict[str, StructLayoutSpec],
) -> tuple[str, int, int] | None:
    t = " ".join(raw_type.replace("const ", " ").replace("device ", " ").replace("constant ", " ").split())
    for prefix in ("metal::", "mlx::core::"):
        t = t.removeprefix(prefix)
    arr_m = _STD_ARRAY_RE.match(t)
    if arr_m:
        elem = _resolve_type_layout(arr_m.group(1), known_structs)
        if elem is None:
            return None
        cnt = int(arr_m.group(2))
        return (f"{elem[0]}[{cnt}]", _align_up(elem[1], elem[2]) * cnt, elem[2])
    tup_m = _SWIFT_TUPLE_RE.match(t)
    if tup_m:
        parts = [p.strip() for p in tup_m.group(1).split(",") if p.strip()]
        if parts:
            off = 0
            max_al = 1
            for pt in parts:
                sub = _resolve_type_layout(pt, known_structs)
                if sub is None:
                    return None
                off = _align_up(off, sub[2]) + sub[1]
                max_al = max(max_al, sub[2])
            return (t, _align_up(off, max_al), max_al)
    if t in _TYPE_LAYOUT_TABLE:
        sz, al = _TYPE_LAYOUT_TABLE[t]
        return (t, sz, al)
    bare = t.removeprefix("struct ")
    if bare in known_structs:
        st = known_structs[bare]
        return (bare, st.stride, st.alignment)
    return None


def parse_structs_from_source(
    source: str,
    *,
    source_file: str,
    is_metal: bool,
    is_swift: bool = False,
) -> dict[str, StructLayoutSpec]:
    """Extract deterministic struct layouts from C/C++/ObjC++/Swift or `.metal` source text."""
    cleaned = _filter_metal_ifdefs(strip_comments_preserve_lines(source), is_metal=is_metal)
    pragma_packed = "#pragma pack(push, 1)" in cleaned or "#pragma pack(1)" in cleaned
    structs: dict[str, StructLayoutSpec] = {}
    n = len(cleaned)

    for m in _C_STRUCT_DECL_RE.finditer(cleaned):
        header_mid = m.group(1)
        brace_open = m.end() - 1
        depth = 1
        pos = brace_open + 1
        while pos < n and depth > 0 and depth <= 64:
            if cleaned[pos] == "{":
                depth += 1
            elif cleaned[pos] == "}":
                depth -= 1
            pos += 1
        if depth != 0:
            continue
        body = cleaned[brace_open + 1 : pos - 1]
        after = cleaned[pos : min(n, pos + 120)]
        semi_idx = after.find(";")
        tail_decl = after[:semi_idx].strip() if semi_idx >= 0 else ""

        tokens = [
            tok
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", header_mid)
            if tok not in ("alignas", "__attribute__", "aligned", "packed", "final", "public")
        ]
        struct_name = tokens[-1] if tokens else ""
        if not struct_name and tail_decl:
            tail_ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail_decl)
            if tail_ids:
                struct_name = tail_ids[-1]
        if not struct_name:
            continue

        is_packed = pragma_packed or "packed" in header_mid or "packed" in tail_decl
        explicit_align = 1
        for am in (_ALIGNAS_RE.search(header_mid), _ATTR_ALIGN_RE.search(header_mid), _ATTR_ALIGN_RE.search(tail_decl)):
            if am:
                explicit_align = max(explicit_align, int(am.group(1)))

        line_no = cleaned.count("\n", 0, m.start()) + 1
        fields_out: list[StructFieldLayout] = []
        offset = 0
        struct_align = explicit_align
        unknown_field = False

        stmts = body.splitlines() if is_swift else body.replace("\n", " ").split(";")
        for raw_stmt in stmts:
            stmt = raw_stmt[:MAX_SOURCE_LINE_CHARS].strip()
            if not stmt:
                continue
            if not is_swift and "(" in stmt and ")" in stmt and not stmt.startswith("alignas"):
                continue
            field_align_override = 1
            fa_m = _ALIGNAS_RE.search(stmt)
            if fa_m:
                field_align_override = int(fa_m.group(1))
                stmt = _ALIGNAS_RE.sub("", stmt).strip()

            if is_swift:
                sm = _SWIFT_FIELD_RE.match(stmt)
                if not sm:
                    continue
                fname, ftype, arr_cnt = sm.group(1), sm.group(2).strip(), None
            else:
                parsed_c = _parse_c_field_decl(stmt)
                if parsed_c is None:
                    continue
                ftype, fname, arr_cnt = parsed_c

            resolved = _resolve_type_layout(ftype, structs)
            if resolved is None:
                unknown_field = True
                break
            norm_type, f_size, f_align = resolved
            if arr_cnt is not None:
                count = int(arr_cnt)
                f_size = _align_up(f_size, f_align) * count
                norm_type = f"{norm_type}[{count}]"
            eff_align = 1 if is_packed else max(f_align, field_align_override)
            offset = _align_up(offset, eff_align)
            fields_out.append(
                StructFieldLayout(
                    name=fname,
                    type_name=norm_type,
                    offset=offset,
                    size=f_size,
                    alignment=eff_align,
                )
            )
            offset += f_size
            struct_align = max(struct_align, eff_align)

        if unknown_field or not fields_out:
            continue
        if is_packed:
            struct_align = max(1, explicit_align)
        stride = _align_up(offset, struct_align)
        structs[struct_name] = StructLayoutSpec(
            name=struct_name,
            domain="metal" if is_metal else "host",
            source_file=source_file,
            line=line_no,
            size=offset,
            stride=stride,
            alignment=struct_align,
            fields=tuple(fields_out),
        )
    return structs


@dataclass(frozen=True)
class MetalBufferBinding:
    """Declared `[[buffer(N)]]` parameter on a `.metal` compute kernel."""

    index: int
    param_name: str
    raw_type: str
    struct_type: str | None = None


@dataclass(frozen=True)
class MetalKernelSpec:
    """Parsed `.metal` kernel entrypoint (including `[[host_name(...)]]` specializations)."""

    name: str
    source_file: str
    line: int
    buffers: dict[int, MetalBufferBinding] = field(default_factory=dict)
    is_template: bool = False
    base_template: str | None = None


@dataclass
class MetalSourceParseResult:
    """Aggregated kernels and struct layouts parsed from `.metal` shader sources."""

    kernels: dict[str, MetalKernelSpec] = field(default_factory=dict)
    structs: dict[str, StructLayoutSpec] = field(default_factory=dict)


_KERNEL_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\[\[\s*kernel\s*\]\]|\bkernel\b)\s+(?:void\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_BUFFER_ATTR_RE: Final[re.Pattern[str]] = re.compile(r"\[\[\s*buffer\(\s*(\d+)\s*\)\s*\]\]")
_HOST_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r'\[\[\s*host_name\(\s*"((?:\\.|[^"\\])*)"\s*\)\s*\]\]([^;{]{1,400})'
)
_INSTANTIATE_MACRO_RE: Final[re.Pattern[str]] = re.compile(
    r'\binstantiate_[A-Za-z0-9_]*\(\s*"((?:\\.|[^"\\])*)"\s*,\s*([A-Za-z_][A-Za-z0-9_]*)'
)
_TEMPLATE_REF_RE: Final[re.Pattern[str]] = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*<")


def _split_top_level_commas(param_block: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in param_block:
        if ch in ("<", "(", "["):
            depth += 1
        elif ch in (">", ")", "]") and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_buffer_struct_type(raw_param_prefix: str) -> str | None:
    cleaned = re.sub(r"\[\[[^\]]{0,80}\]\]", " ", raw_param_prefix)
    for kw in ("device", "constant", "threadgroup", "thread", "const", "volatile", "restrict", "struct"):
        cleaned = re.sub(rf"\b{kw}\b", " ", cleaned)
    cleaned = cleaned.replace("*", " ").replace("&", " ").strip()
    tokens = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_:]*", cleaned) if t]
    if len(tokens) >= 2:
        cand = tokens[-2].split("::")[-1]
        if cand not in _TYPE_LAYOUT_TABLE and cand not in ("T", "U", "V", "Op", "IdxT", "AccT"):
            return cand
    return None


def parse_metal_source(source: str, *, source_file: str) -> MetalSourceParseResult:
    """Parse `.metal` shader kernels, `[[buffer(N)]]` bindings, and MSL `struct` layouts."""
    res = MetalSourceParseResult()
    res.structs.update(parse_structs_from_source(source, source_file=source_file, is_metal=True))
    cleaned = strip_comments_preserve_lines(source)
    n = len(cleaned)

    for km in _KERNEL_MARKER_RE.finditer(cleaned):
        kname = km.group(1)
        if kname == "void":
            continue
        paren_open = km.end() - 1
        depth = 1
        pos = paren_open + 1
        while pos < n and depth > 0 and depth <= 64:
            if cleaned[pos] == "(":
                depth += 1
            elif cleaned[pos] == ")":
                depth -= 1
            pos += 1
        if depth != 0:
            continue
        param_text = cleaned[paren_open + 1 : pos - 1]
        line_no = cleaned.count("\n", 0, km.start()) + 1
        lookback = cleaned[max(0, km.start() - 160) : km.start()]
        is_tmpl = "template" in lookback

        buffers: dict[int, MetalBufferBinding] = {}
        for param in _split_top_level_commas(param_text):
            bm = _BUFFER_ATTR_RE.search(param)
            if not bm:
                continue
            b_idx = int(bm.group(1))
            before_attr = param[: bm.start()].strip()
            ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", before_attr)
            pname = ids[-1] if ids else f"arg_{b_idx}"
            st_type = _extract_buffer_struct_type(before_attr)
            buffers[b_idx] = MetalBufferBinding(
                index=b_idx,
                param_name=pname,
                raw_type=" ".join(before_attr.split()),
                struct_type=st_type,
            )

        res.kernels[kname] = MetalKernelSpec(
            name=kname,
            source_file=source_file,
            line=line_no,
            buffers=buffers,
            is_template=is_tmpl,
        )

    for hm in _HOST_NAME_RE.finditer(cleaned):
        exported = hm.group(1)
        tail = hm.group(2)
        line_no = cleaned.count("\n", 0, hm.start()) + 1
        trefs = _TEMPLATE_REF_RE.findall(tail)
        base_name = next((t for t in reversed(trefs) if t in res.kernels), trefs[-1] if trefs else None)
        inherited = dict(res.kernels[base_name].buffers) if base_name and base_name in res.kernels else {}
        res.kernels[exported] = MetalKernelSpec(
            name=exported,
            source_file=source_file,
            line=line_no,
            buffers=inherited,
            is_template=False,
            base_template=base_name,
        )

    for im in _INSTANTIATE_MACRO_RE.finditer(cleaned):
        exported, base_fn = im.group(1), im.group(2)
        line_no = cleaned.count("\n", 0, im.start()) + 1
        inherited = dict(res.kernels[base_fn].buffers) if base_fn in res.kernels else {}
        res.kernels.setdefault(
            exported,
            MetalKernelSpec(
                name=exported,
                source_file=source_file,
                line=line_no,
                buffers=inherited,
                is_template=False,
                base_template=base_fn,
            ),
        )

    return res


def parse_metal_file(
    path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> MetalSourceParseResult:
    """Safely read and parse a `.metal` source file."""
    resolved, text = read_safe_text(path, repo_root=repo_root, allow_external=allow_external)
    rel = normalize_repo_relpath(str(resolved), repo_root)
    return parse_metal_source(text, source_file=rel)


@dataclass(frozen=True)
class MetallibExport:
    """Exported `AIR` shader symbol from `xcrun metal-objdump` text or raw `MTLB` container."""

    name: str
    shader_kind: str = "kernel"  # "kernel" | "vertex" | "fragment"
    buffer_indices: tuple[int, ...] = ()


@dataclass
class MetallibParseResult:
    """Parsed `.metallib` `AIR` symbol table and reflection metadata."""

    format: str = "air_text"  # "mtlb_binary" | "air_text" | "json"
    exports: dict[str, MetallibExport] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


_OBJDUMP_SYM_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[0-9A-Fa-f]{8,16}\s+[gw]\s+(?:F\s+)?__TEXT,__text\s+|Function:\s*|name:\s*)([A-Za-z_][A-Za-z0-9_.$]*)\s*$"
)
_OBJDUMP_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^<([A-Za-z_][A-Za-z0-9_.$]*)>:\s*$")
_AIR_DEFINE_RE: Final[re.Pattern[str]] = re.compile(
    r'^\s*define\s+[^@]{1,120}@("(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_.$]*)\s*\('
)
_AIR_BUF_META_RE: Final[re.Pattern[str]] = re.compile(
    r'(?:!"air\.buffer"[^\n]{0,120}?i32\s+(\d+)|i32\s+(\d+)\s*,\s*!"air\.buffer"|\bbuffer\(\s*(\d+)\s*\))'
)


def _parse_mtlb_binary(raw: bytes) -> MetallibParseResult:
    if len(raw) < 64 or raw[:4] != b"MTLB":
        raise ValueError("Truncated or invalid MTLB binary header.")
    total_len = len(raw)
    file_size = struct.unpack_from("<Q", raw, 16)[0]
    fn_list_off, fn_list_sz = struct.unpack_from("<QQ", raw, 24)
    if file_size > total_len or fn_list_off < 24 or fn_list_off + fn_list_sz > total_len or fn_list_sz < 4:
        raise ValueError("Corrupt or truncated MTLB function directory bounds.")

    entry_count = struct.unpack_from("<I", raw, fn_list_off)[0]
    if entry_count > 65536:
        raise ValueError(f"Excessive MTLB function count ({entry_count}).")

    out = MetallibParseResult(format="mtlb_binary")
    pos = fn_list_off + 4
    dir_end = fn_list_off + fn_list_sz
    kind_map = {0: "vertex", 1: "fragment", 2: "kernel"}

    for _ in range(entry_count):
        if pos >= dir_end:
            raise ValueError("Truncated MTLB function entry stream.")
        if pos + 8 <= dir_end and raw[pos + 4 : pos + 8] in (b"NAME", b"TYPE", b"HASH", b"ENDT"):
            grp_sz = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
            if grp_sz > dir_end - pos:
                raise ValueError("Truncated MTLB tagged entry group.")
            grp_end = pos + grp_sz
        else:
            grp_end = dir_end

        sym_name = ""
        sym_kind = "kernel"
        bufs: list[int] = []
        tpos = pos
        saw_endt = False
        while tpos + 4 <= grp_end:
            tag = raw[tpos : tpos + 4]
            if tag == b"ENDT":
                tpos += 4
                if tpos + 2 <= grp_end and raw[tpos : tpos + 2] == b"\x00\x00":
                    tpos += 2
                saw_endt = True
                break
            if tpos + 6 > grp_end:
                raise ValueError("Truncated MTLB tag header.")
            tlen = struct.unpack_from("<H", raw, tpos + 4)[0]
            if tpos + 6 + tlen > grp_end:
                raise ValueError("Truncated MTLB tag payload.")
            payload = raw[tpos + 6 : tpos + 6 + tlen]
            tpos += 6 + tlen
            if tag == b"NAME":
                sym_name = payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
            elif tag == b"TYPE" and payload:
                sym_kind = kind_map.get(payload[0], "kernel")
            elif tag == b"BUFF":
                for b_off in range(0, len(payload) - 1, 2):
                    bufs.append(struct.unpack_from("<H", payload, b_off)[0])

        if not saw_endt:
            raise ValueError("Unterminated MTLB tag stream (missing ENDT).")
        pos = grp_end if grp_end < dir_end else tpos
        if sym_name:
            out.exports[sym_name] = MetallibExport(
                name=sym_name,
                shader_kind=sym_kind,
                buffer_indices=tuple(sorted(set(bufs))),
            )
    return out


def parse_metallib_bytes(raw: bytes, *, format_hint: str = "") -> MetallibParseResult:
    """Parse raw `MTLB` binary headers, JSON reflection, or `xcrun metal-objdump` AIR text."""
    if raw.startswith(b"MTLB"):
        return _parse_mtlb_binary(raw)
    if b"\x00" in raw[:256]:
        raise ValueError("Unrecognized binary metallib artifact (missing 'MTLB' magic).")

    text = raw.decode("utf-8", errors="replace")
    stripped = text.lstrip("\ufeff \t\r\n")
    if not stripped:
        return MetallibParseResult(format="air_text")

    if stripped.startswith(("{", "[")) or format_hint.lower().endswith(".json"):
        data = load_bounded_json_or_yaml(stripped)
        out_json = MetallibParseResult(format="json")
        items = data.get("kernels") or data.get("functions") if isinstance(data, dict) else data
        if isinstance(items, list):
            for entry in items:
                if isinstance(entry, dict) and entry.get("name"):
                    nm = str(entry["name"]).strip()
                    kind = str(entry.get("kind") or entry.get("type") or "kernel").strip()
                    raw_bufs = entry.get("buffers") or entry.get("buffer_indices") or ()
                    b_list = [int(b) for b in raw_bufs if isinstance(b, int) and not isinstance(b, bool)]
                    out_json.exports[nm] = MetallibExport(
                        name=nm,
                        shader_kind=kind,
                        buffer_indices=tuple(sorted(set(b_list))),
                    )
        return out_json

    out = MetallibParseResult(format="air_text")
    cur_sym: str | None = None
    buf_by_sym: dict[str, set[int]] = {}
    global_bufs: set[int] = set()

    for raw_ln in text.splitlines():
        ln = raw_ln[:MAX_SOURCE_LINE_CHARS].strip()
        if not ln:
            continue
        dm = _AIR_DEFINE_RE.match(ln)
        if dm:
            raw_s = dm.group(1).strip('"')
            if raw_s and not raw_s.startswith("llvm."):
                cur_sym = raw_s
                out.exports.setdefault(cur_sym, MetallibExport(name=cur_sym))
            continue
        lm = _OBJDUMP_LABEL_RE.match(ln)
        if lm:
            cur_sym = lm.group(1)
            out.exports.setdefault(cur_sym, MetallibExport(name=cur_sym))
            continue
        sm = _OBJDUMP_SYM_RE.match(ln)
        if sm:
            sym_n = sm.group(1).lstrip("_") if sm.group(1).startswith("__") else sm.group(1)
            cur_sym = sym_n
            out.exports.setdefault(sym_n, MetallibExport(name=sym_n))
            continue
        for bm in _AIR_BUF_META_RE.finditer(ln):
            idx_str = bm.group(1) or bm.group(2) or bm.group(3)
            if idx_str is not None:
                b_val = int(idx_str)
                if cur_sym is not None:
                    buf_by_sym.setdefault(cur_sym, set()).add(b_val)
                else:
                    global_bufs.add(b_val)

    if len(out.exports) == 1 and global_bufs:
        only_name = next(iter(out.exports))
        buf_by_sym.setdefault(only_name, set()).update(global_bufs)

    for sname, bset in buf_by_sym.items():
        prev = out.exports[sname]
        out.exports[sname] = MetallibExport(
            name=sname,
            shader_kind=prev.shader_kind,
            buffer_indices=tuple(sorted(bset)),
        )
    return out


def parse_metallib_artifact(
    path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> MetallibParseResult:
    """Safely read and parse a `.metallib` `MTLB` binary or `metal-objdump` AIR reflection file."""
    validated = validate_safe_path(
        path,
        repo_root=repo_root,
        allow_external=allow_external,
        allow_dir=True,
    )
    if validated.is_file():
        _, raw = read_safe_bytes(validated, repo_root=repo_root, allow_external=allow_external)
        return parse_metallib_bytes(raw, format_hint=validated.name)

    combined = MetallibParseResult(format="directory")
    for fpath, _ in iter_safe_repo_files(
        validated,
        suffixes=(".metallib", ".air", ".txt", ".objdump", ".json", ".ll"),
        max_files=128,
    ):
        _, raw = read_safe_bytes(
            fpath,
            repo_root=repo_root if not allow_external else None,
            allow_external=allow_external,
        )
        sub = parse_metallib_bytes(raw, format_hint=fpath.name)
        combined.exports.update(sub.exports)
    return combined


@dataclass(frozen=True)
class HostBufferArg:
    """Single host `setBuffer` / `setBytes` binding call within a compute dispatch."""

    index: int | None
    is_dynamic_index: bool
    line: int
    api: str
    struct_type: str | None = None


@dataclass
class HostMetalDispatch:
    """Host CPU Metal compute pipeline lookup, buffer bindings, and threadgroup dispatch."""

    source_file: str
    line: int
    enclosing_symbol: str
    language: str
    kernel_name: str | None
    kernel_expr: str
    is_dynamic_kernel: bool
    lookup_api: str
    has_pipeline_state: bool = False
    has_dispatch_call: bool = False
    buffer_args: list[HostBufferArg] = field(default_factory=list)
    encoder_name: str = ""
    uncertain_slots: set[int] = field(default_factory=set)
    all_slots_uncertain: bool = False
    uncertainty_reasons: list[str] = field(default_factory=list)
    binding_verification: str = "verified"
    is_fresh_encoder: bool = False
    observed_buffer_args: list[HostBufferArg] = field(default_factory=list)


_METAL_CONTEXT_TOKENS: Final[tuple[str, ...]] = (
    "MTL",
    "Metal",
    "metal::",
    "mlx::core::metal",
    "metal_kernel",
    "setComputePipelineState",
    "set_compute_pipeline_state",
    "makeComputePipelineState",
    "newComputePipelineState",
    "dispatchThreads",
    "dispatchThreadgroups",
    "dispatch_threads",
    "dispatch_threadgroups",
    "newDefaultLibrary",
    "makeDefaultLibrary",
)

_STATIC_STR_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    r'^@?"((?:\\.|[^"\\])*)"$|^\'((?:\\.|[^\'\\])*)\'$'
)
_NS_STRING_WRAP_RE: Final[re.Pattern[str]] = re.compile(
    r'(?:NS|MTL)::String::string\(\s*"((?:\\.|[^"\\])*)"'
)
_LOCAL_VAR_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:const\s+)?(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:[={;(]|$)"
)
_SWIFT_VAR_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:var|let)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"
)
_SWIFT_INIT_VAR_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:var|let)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("
)

_FN_DEF_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^\s*(?:public\s+|internal\s+|private\s+|fileprivate\s+)?func\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]"),
    re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"^\s*[-+]\s*\([^)]{1,60}\)\s*([A-Za-z_][A-Za-z0-9_:]*)"),
    re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_:<>*&]*\s+){1,6}([A-Za-z_][A-Za-z0-9_:]*)\s*\([^;]{0,240}\{\s*$"),
)

_LOOKUP_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("makeFunction", re.compile(r"\bmakeFunction\s*\(\s*(?:name\s*[:=]\s*)?([^,)\n]{1,240})")),
    ("newFunctionWithName", re.compile(r"\bnewFunctionWithName\s*:\s*([^\]\n;]{1,240})")),
    ("newFunctionWithName_", re.compile(r"\bnewFunctionWithName_\s*\(\s*([^,)\n]{1,240})")),
    ("newFunction", re.compile(r"\bnewFunction\s*\(\s*([^;\n]{1,240})\)\s*(?:;|$)")),
    ("get_kernel", re.compile(r"\bget_kernel\s*\(\s*([^,)\n]{1,240})")),
    ("metal_kernel", re.compile(r"\bmetal_kernel\s*\(\s*(?:name\s*=\s*)?([^,)\n]{1,240})")),
)

_SET_BUF_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("setBuffer", re.compile(r"\bsetBuffer\s*\(([^)]{1,320})\bindex\s*[:=]\s*([A-Za-z0-9_+*/ -]{1,40})")),
    ("setBytes", re.compile(r"\bsetBytes\s*\(([^)]{1,320})\bindex\s*[:=]\s*([A-Za-z0-9_+*/ -]{1,40})")),
    ("setBuffer:atIndex:", re.compile(r"\bsetBuffer\s*:([^\]]{1,320})\batIndex\s*:\s*([A-Za-z0-9_]{1,40})")),
    ("setBytes:atIndex:", re.compile(r"\bsetBytes\s*:([^\]]{1,320})\batIndex\s*:\s*([A-Za-z0-9_]{1,40})")),
    ("setBuffer_offset_atIndex_", re.compile(r"\bsetBuffer_offset_atIndex_\s*\(([^)]{1,240}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("setBytes_length_atIndex_", re.compile(r"\bsetBytes_length_atIndex_\s*\(([^)]{1,240}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("setBuffer(cpp)", re.compile(r"(?:->|\?\.|\.)setBuffer\s*\(([^,)]{1,120},\s*[^,)]{1,80}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("setBytes(cpp)", re.compile(r"(?:->|\?\.|\.)setBytes\s*\(([^,)]{1,120},\s*[^,)]{1,120}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("set_buffer", re.compile(r"\bset_buffer\s*\(([^)]{1,240})\bindex\s*=\s*([A-Za-z0-9_]{1,40})")),
    ("set_input_array", re.compile(r"\bset_input_array\s*\(([^,)]{1,160}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("set_output_array", re.compile(r"\bset_output_array\s*\(([^,)]{1,160}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("set_bytes", re.compile(r"\bset_bytes(?:\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>)?\s*\(([^,)]{1,160}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
    ("set_vector_bytes", re.compile(r"\bset_vector_bytes\s*\(([^)]{1,200}),\s*([A-Za-z0-9_]{1,40})\s*\)")),
)

_SIZEOF_STRUCT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\bsizeof\s*\(\s*(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\)|\bMemoryLayout<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>)"
)
_ADDR_VAR_RE: Final[re.Pattern[str]] = re.compile(r"&\s*([A-Za-z_][A-Za-z0-9_]*)")


def _classify_kernel_expr(expr: str, local_consts: dict[str, str], mutated_vars: set[str]) -> tuple[str | None, bool]:
    raw = expr.strip().rstrip(")];,")
    ns_m = _NS_STRING_WRAP_RE.search(raw)
    if ns_m:
        return ns_m.group(1), False
    lit_m = _STATIC_STR_LITERAL_RE.match(raw)
    if lit_m:
        val = lit_m.group(1) if lit_m.group(1) is not None else (lit_m.group(2) or "")
        if "\\(" in val:
            return None, True
        return val, False
    if raw.startswith(('f"', "f'")) or "+" in raw or "<<" in raw or "format(" in raw:
        return None, True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw):
        if raw in local_consts and raw not in mutated_vars:
            return local_consts[raw], False
        return None, True
    return None, True


def _coalesce_logical_statements(cleaned: str) -> list[tuple[int, str]]:
    lines = cleaned.splitlines()
    out: list[tuple[int, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        start_ln = i + 1
        acc = lines[i][:MAX_SOURCE_LINE_CHARS]
        paren_bal = acc.count("(") - acc.count(")") + acc.count("[") - acc.count("]")
        joined = 1
        while paren_bal > 0 and (i + 1) < n and joined < 8 and len(acc) < MAX_SOURCE_LINE_CHARS:
            i += 1
            joined += 1
            nxt = lines[i][:MAX_SOURCE_LINE_CHARS].strip()
            acc = f"{acc} {nxt}"
            paren_bal += nxt.count("(") - nxt.count(")") + nxt.count("[") - nxt.count("]")
        out.append((start_ln, acc[:MAX_SOURCE_LINE_CHARS]))
        i += 1
    return out


_INLINE_BRANCH_STMT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:\}\s*)*(?:else\s+if|if|elif|else|switch|case|default|for|while|guard)\b"
)
_FRESH_ENCODER_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*[^;\n]*\b"
    r"(?:makeComputeCommandEncoder|computeCommandEncoder|newComputeCommandEncoder|make_compute_command_encoder)\b"
)
_PIPELINE_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*([^;\n]*\b"
    r"(?:makeComputePipelineState|newComputePipelineState\w*|make_compute_pipeline_state)\b[^;\n]*)"
)
_SET_PSO_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:([A-Za-z_][A-Za-z0-9_?.]*?[A-Za-z0-9_]|[A-Za-z_])\s*(?:->|\?\.|\.)\s*(?:setComputePipelineState|set_compute_pipeline_state)\s*\(\s*([^,)\n]{1,160})"
    r"|\[\s*([A-Za-z_][A-Za-z0-9_.]*)\s+setComputePipelineState\s*:\s*([^\]\s;]{1,160}))"
)
_DISPATCH_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:([A-Za-z_][A-Za-z0-9_?.]*?[A-Za-z0-9_]|[A-Za-z_])\s*(?:->|\?\.|\.)\s*(?:dispatchThreads|dispatchThreadgroups|dispatch_threads|dispatch_threadgroups)\s*\("
    r"|\[\s*([A-Za-z_][A-Za-z0-9_.]*)\s+(?:dispatchThreads|dispatchThreadgroups)\s*:)"
)
_END_ENCODING_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:([A-Za-z_][A-Za-z0-9_?.]*?[A-Za-z0-9_]|[A-Za-z_])\s*(?:->|\?\.|\.)\s*(?:endEncoding|end_encoding)\s*\("
    r"|\[\s*([A-Za-z_][A-Za-z0-9_.]*)\s+endEncoding\b)"
)


@dataclass
class _PendingKernelLookup:
    kernel_name: str | None
    kernel_expr: str
    is_dynamic: bool
    lookup_api: str
    line: int
    fn_var: str | None = None
    dispatched: bool = False


@dataclass
class _EncoderState:
    name: str
    pipeline_lookup: _PendingKernelLookup | None = None
    has_pipeline_state: bool = False
    is_fresh: bool = False
    bound_slots: dict[int, HostBufferArg] = field(default_factory=dict)
    dynamic_args: list[HostBufferArg] = field(default_factory=list)
    observed_args: list[HostBufferArg] = field(default_factory=list)
    uncertain_slots: set[int] = field(default_factory=set)
    all_slots_uncertain: bool = False
    uncertainty_reasons: list[str] = field(default_factory=list)


@dataclass
class _BranchFrame:
    entry_depth: int
    prior_slots: dict[str, dict[int, HostBufferArg]]
    modified_slots: set[tuple[str, int]] = field(default_factory=set)


def _extract_encoder_receiver(stmt: str, match_start: int) -> str:
    prefix = stmt[:match_start].rstrip()
    if prefix.endswith(("->", "?.")):
        prefix = prefix[:-2].rstrip()
    elif prefix.endswith("."):
        prefix = prefix[:-1].rstrip()
    m_dot = re.search(r"([A-Za-z_][A-Za-z0-9_?.]*?[A-Za-z0-9_]|[A-Za-z_])$", prefix)
    if m_dot:
        cand = m_dot.group(1).replace("?.", ".")
        if cand not in ("return", "try", "await", "if", "else"):
            return cand
    m_objc = re.search(r"\[\s*([A-Za-z_][A-Za-z0-9_.]*)\s*$", prefix)
    if m_objc:
        return m_objc.group(1)
    return "__default_encoder__"


def _pop_branch_frame(frame: _BranchFrame, encoders: dict[str, _EncoderState]) -> None:
    for enc_k, idx in frame.modified_slots:
        enc_st = encoders.get(enc_k)
        if enc_st is None:
            continue
        prior_map = frame.prior_slots.get(enc_k, {})
        if idx in prior_map:
            enc_st.bound_slots[idx] = prior_map[idx]
        else:
            enc_st.bound_slots.pop(idx, None)
        enc_st.uncertain_slots.add(idx)
        reason = f"conditional binding on [[buffer({idx})]]"
        if reason not in enc_st.uncertainty_reasons:
            enc_st.uncertainty_reasons.append(reason)


_PY_KERNEL_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REPO_SKIP_WALK_DIRS: Final[frozenset[str]] = frozenset(
    {"tests", "test", "Tests", "plugins", ".next"}
)


def _sanitize_python_host_source(source: str) -> str:
    """Strip Python `#` comments and mask non-identifier string literals while preserving line numbers."""
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    fstring_end = getattr(tokenize, "FSTRING_END", None)
    skip_types = {
        tokenize.ENCODING,
        tokenize.ENDMARKER,
        tokenize.INDENT,
        tokenize.DEDENT,
    }
    out_parts: list[str] = []
    cur_line = 1
    cur_col = 0
    fstring_depth = 0
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            ttype, tstr, (sline, scol), (eline, ecol), _ = tok
            if ttype in skip_types:
                continue
            if sline > cur_line:
                out_parts.append("\n" * (sline - cur_line))
                cur_line = sline
                cur_col = 0
            if scol > cur_col and fstring_depth == 0 and ttype != tokenize.COMMENT:
                out_parts.append(" " * (scol - cur_col))
            span_newlines = max(0, eline - sline)
            if fstring_start is not None and ttype == fstring_start:
                if fstring_depth == 0:
                    out_parts.append('f"__dyn__"')
                fstring_depth += 1
            elif fstring_end is not None and ttype == fstring_end:
                fstring_depth = max(0, fstring_depth - 1)
            elif fstring_depth > 0 or ttype == tokenize.COMMENT:
                if span_newlines:
                    out_parts.append("\n" * span_newlines)
                cur_line = eline
                cur_col = ecol
                continue
            elif ttype in (tokenize.NEWLINE, tokenize.NL):
                out_parts.append("\n")
                cur_line = sline + 1
                cur_col = 0
                continue
            elif ttype == tokenize.STRING:
                q_idx = min(
                    (idx for idx in (tstr.find('"'), tstr.find("'")) if idx >= 0),
                    default=0,
                )
                prefix = tstr[:q_idx].lower()
                if "f" in prefix:
                    out_parts.append('f"__dyn__"')
                else:
                    kept: str | None = None
                    try:
                        val = ast.literal_eval(tstr)
                        if isinstance(val, str) and _PY_KERNEL_IDENT_RE.fullmatch(val):
                            kept = json.dumps(val)
                    except (SyntaxError, ValueError):
                        kept = None
                    out_parts.append(kept if kept is not None else '"__str__"')
            else:
                out_parts.append(tstr)
            if span_newlines:
                out_parts.append("\n" * span_newlines)
            cur_line = eline
            cur_col = ecol
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return "".join(out_parts)


def extract_host_metal_dispatches(
    source: str,
    *,
    source_file: str,
    language: str,
) -> tuple[list[HostMetalDispatch], dict[str, StructLayoutSpec]]:
    """Extract Metal compute kernel lookups, buffer bindings, and host struct layouts."""
    is_swift = language == "swift" or source_file.endswith(".swift")
    is_python = language == "python" or source_file.endswith(".py")
    host_structs: dict[str, StructLayoutSpec] = {}
    if not is_python:
        host_structs = parse_structs_from_source(
            source,
            source_file=source_file,
            is_metal=False,
            is_swift=is_swift,
        )

    if not any(tok in source for tok in _METAL_CONTEXT_TOKENS):
        return [], host_structs

    cleaned = (
        _sanitize_python_host_source(source)
        if is_python
        else strip_comments_preserve_lines(source)
    )
    if not any(tok in cleaned for tok in _METAL_CONTEXT_TOKENS):
        return [], host_structs
    dispatches: list[HostMetalDispatch] = []
    cur_scope = Path(source_file).stem
    local_str_consts: dict[str, str] = {}
    mutated_vars: set[str] = set()
    local_var_types: dict[str, str] = {}
    fn_lookups: list[_PendingKernelLookup] = []
    fn_var_to_lookup: dict[str, _PendingKernelLookup] = {}
    pso_var_to_lookup: dict[str, _PendingKernelLookup] = {}
    encoders: dict[str, _EncoderState] = {}
    known_encoder_vars: set[str] = set()
    branch_stack: list[_BranchFrame] = []
    brace_depth = 0

    def _flush_undispatched_lookups() -> None:
        for lk in fn_lookups:
            if not lk.dispatched:
                dispatches.append(
                    HostMetalDispatch(
                        source_file=source_file,
                        line=lk.line,
                        enclosing_symbol=cur_scope,
                        language=language,
                        kernel_name=lk.kernel_name,
                        kernel_expr=lk.kernel_expr,
                        is_dynamic_kernel=lk.is_dynamic,
                        lookup_api=lk.lookup_api,
                        has_dispatch_call=False,
                    )
                )

    def _get_enc(enc_name: str) -> _EncoderState:
        norm_enc = enc_name.replace("?.", ".")
        known_encoder_vars.add(norm_enc)
        st = encoders.get(norm_enc)
        if st is None:
            st = _EncoderState(name=norm_enc)
            encoders[norm_enc] = st
        return st

    for line_no, stmt in _coalesce_logical_statements(cleaned):
        stripped_stmt = stmt.strip()
        if not stripped_stmt:
            continue

        # 1. Process leading closing braces (or Python dedent) BEFORE evaluating statement body
        if is_python:
            cur_indent = len(stmt) - len(stmt.lstrip(" "))
            while branch_stack and cur_indent <= branch_stack[-1].entry_depth:
                _pop_branch_frame(branch_stack.pop(), encoders)
        else:
            lead_idx = 0
            while lead_idx < len(stripped_stmt) and stripped_stmt[lead_idx] in ("}", " ", "\t"):
                if stripped_stmt[lead_idx] == "}":
                    brace_depth = max(0, brace_depth - 1)
                    while branch_stack and brace_depth <= branch_stack[-1].entry_depth:
                        _pop_branch_frame(branch_stack.pop(), encoders)
                lead_idx += 1
            stmt_tail = stripped_stmt[lead_idx:]
        if is_python:
            stmt_tail = stripped_stmt

        # 2. Detect new function scope
        for fn_rx in _FN_DEF_PATTERNS:
            fm = fn_rx.match(stmt)
            if fm and fm.group(1) not in ("if", "for", "while", "switch", "return", "catch"):
                _flush_undispatched_lookups()
                cur_scope = fm.group(1)
                local_str_consts = {}
                mutated_vars = set()
                local_var_types = {}
                fn_lookups = []
                fn_var_to_lookup = {}
                pso_var_to_lookup = {}
                encoders = {}
                known_encoder_vars = set()
                branch_stack = []
                for pm in re.finditer(
                    r"\b([A-Za-z_]\w*)\s*:\s*(?:id\s*<\s*)?[A-Za-z_:]*ComputeCommandEncoder"
                    r"|\b[A-Za-z_:]*ComputeCommandEncoder\s*[*&>]?\s*([A-Za-z_]\w*)",
                    stmt,
                ):
                    p_enc = pm.group(1) or pm.group(2)
                    if p_enc:
                        _get_enc(p_enc)
                break

        # 3. Open conditional/branch frame if statement starts a control-flow branch
        is_branch_stmt = bool(_INLINE_BRANCH_STMT_RE.match(stmt))
        net_tail_braces = 0 if is_python else (stmt_tail.count("{") - stmt_tail.count("}"))
        temp_inline_frame = False
        if is_branch_stmt:
            entry_d = (len(stmt) - len(stmt.lstrip(" "))) if is_python else brace_depth
            frame = _BranchFrame(
                entry_depth=entry_d,
                prior_slots={ek: dict(es.bound_slots) for ek, es in encoders.items()},
            )
            branch_stack.append(frame)
            if is_python:
                body_after_colon = stmt_tail.partition(":")[2].strip()
                temp_inline_frame = bool(body_after_colon)
            else:
                temp_inline_frame = net_tail_braces <= 0

        # 4. Track local string constants, mutations, struct var types, & encoder lifecycle
        if "=" in stmt and '"' in stmt and "==" not in stmt:
            lhs_eq, _, rhs_eq = stmt.partition("=")
            lhs_ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", lhs_eq)
            lit_m = _STATIC_STR_LITERAL_RE.match(rhs_eq.strip().rstrip(";").strip())
            if lhs_ids and lit_m and lit_m.group(1) is not None and "\\(" not in lit_m.group(1):
                local_str_consts[lhs_ids[-1]] = lit_m.group(1)
        if "+=" in stmt or "<<" in stmt:
            lhs = stmt.split("+=", 1)[0].split("<<", 1)[0].strip()
            ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", lhs)
            if ids:
                mutated_vars.add(ids[-1])

        for v_rx, type_grp, var_grp in (
            (_LOCAL_VAR_TYPE_RE, 1, 2),
            (_SWIFT_VAR_TYPE_RE, 2, 1),
            (_SWIFT_INIT_VAR_RE, 2, 1),
        ):
            vm = v_rx.match(stmt)
            if vm:
                t_cand, v_cand = vm.group(type_grp), vm.group(var_grp)
                if t_cand not in ("return", "auto", "let", "var", "const", "if"):
                    local_var_types[v_cand] = t_cand

        fresh_m = _FRESH_ENCODER_ASSIGN_RE.search(stmt)
        if fresh_m:
            enc_nm = fresh_m.group(1)
            known_encoder_vars.add(enc_nm)
            encoders[enc_nm] = _EncoderState(name=enc_nm, is_fresh=True)
        elif "=" in stmt and "==" not in stmt:
            lhs_a, _, rhs_a = stmt.partition("=")
            rhs_clean = rhs_a.strip().rstrip(";").strip()
            lhs_toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", lhs_a)
            if lhs_toks and rhs_clean in known_encoder_vars and lhs_toks[-1] != rhs_clean:
                alias_nm = lhs_toks[-1]
                src_enc = _get_enc(rhs_clean)
                dst_enc = _get_enc(alias_nm)
                src_enc.all_slots_uncertain = True
                dst_enc.all_slots_uncertain = True
                src_enc.uncertainty_reasons.append(f"encoder aliased to `{alias_nm}`")
                dst_enc.uncertainty_reasons.append(f"encoder aliased from `{rhs_clean}`")

        for end_m in _END_ENCODING_RE.finditer(stmt):
            ended_enc = (end_m.group(1) or end_m.group(2) or "").replace("?.", ".")
            if ended_enc:
                encoders[ended_enc] = _EncoderState(name=ended_enc)

        # 5. Kernel function lookups & pipeline-state creation/selection
        for api_name, lk_rx in _LOOKUP_PATTERNS:
            lm = lk_rx.search(stmt)
            if lm:
                k_expr = lm.group(1).strip()
                k_static, is_dyn = _classify_kernel_expr(k_expr, local_str_consts, mutated_vars)
                lhs_fn_var: str | None = None
                if "=" in stmt[: lm.start()]:
                    lhs_ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stmt[: lm.start()].split("=")[0])
                    if lhs_ids:
                        lhs_fn_var = lhs_ids[-1]
                lk_obj = _PendingKernelLookup(
                    kernel_name=k_static,
                    kernel_expr=k_expr,
                    is_dynamic=is_dyn,
                    lookup_api=api_name,
                    line=line_no,
                    fn_var=lhs_fn_var,
                )
                fn_lookups.append(lk_obj)
                if lhs_fn_var:
                    fn_var_to_lookup[lhs_fn_var] = lk_obj
                break

        pm_assign = _PIPELINE_ASSIGN_RE.search(stmt)
        if pm_assign:
            pso_var, pso_rhs = pm_assign.group(1), pm_assign.group(2)
            matched_lk: _PendingKernelLookup | None = None
            for f_var, lk_cand in fn_var_to_lookup.items():
                if re.search(rf"\b{re.escape(f_var)}\b", pso_rhs):
                    matched_lk = lk_cand
                    break
            if matched_lk is None and fn_lookups and fn_lookups[-1].line == line_no:
                matched_lk = fn_lookups[-1]
            if matched_lk is not None:
                pso_var_to_lookup[pso_var] = matched_lk
            else:
                pso_var_to_lookup[pso_var] = _PendingKernelLookup(
                    kernel_name=None,
                    kernel_expr=pso_rhs.strip()[:80],
                    is_dynamic=True,
                    lookup_api="makeComputePipelineState",
                    line=line_no,
                    dispatched=True,
                )

        for sp_m in _SET_PSO_CALL_RE.finditer(stmt):
            enc_recv = (sp_m.group(1) or sp_m.group(3) or "__default_encoder__").replace("?.", ".")
            pso_arg = (sp_m.group(2) or sp_m.group(4) or "").strip().rstrip(")];!")
            enc_st = _get_enc(enc_recv)
            enc_st.has_pipeline_state = True
            arg_ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", pso_arg)
            bound_lk: _PendingKernelLookup | None = None
            for aid in arg_ids:
                if aid in pso_var_to_lookup:
                    bound_lk = pso_var_to_lookup[aid]
                    break
                if aid in fn_var_to_lookup:
                    bound_lk = fn_var_to_lookup[aid]
                    break
            if bound_lk is None and fn_lookups and len(fn_lookups) == 1:
                bound_lk = fn_lookups[-1]
            elif bound_lk is None:
                bound_lk = _PendingKernelLookup(
                    kernel_name=None,
                    kernel_expr=pso_arg or "dynamic_pipeline",
                    is_dynamic=True,
                    lookup_api="setComputePipelineState",
                    line=line_no,
                    dispatched=True,
                )
            enc_st.pipeline_lookup = bound_lk

        # 6. Stateful `setBuffer` / `setBytes` slot replacement per encoder
        had_setter_or_pso_or_disp = bool(_SET_PSO_CALL_RE.search(stmt) or _DISPATCH_CALL_RE.search(stmt))
        for b_api, b_rx in _SET_BUF_PATTERNS:
            for bm in b_rx.finditer(stmt):
                had_setter_or_pso_or_disp = True
                enc_recv = _extract_encoder_receiver(stmt, bm.start())
                enc_st = _get_enc(enc_recv)
                if b_api == "set_bytes":
                    tmpl_st, arg_body, idx_raw = bm.group(1), bm.group(2), bm.group(3).strip()
                else:
                    tmpl_st, arg_body, idx_raw = None, bm.group(1), bm.group(2).strip()
                st_name = tmpl_st
                if not st_name:
                    sz_m = _SIZEOF_STRUCT_RE.search(arg_body)
                    if sz_m:
                        st_name = sz_m.group(1) or sz_m.group(2)
                if not st_name:
                    av_m = _ADDR_VAR_RE.search(arg_body)
                    if av_m and av_m.group(1) in local_var_types:
                        st_name = local_var_types[av_m.group(1)]
                if not st_name:
                    first_arg = arg_body.split(",", 1)[0].strip()
                    if first_arg in local_var_types:
                        st_name = local_var_types[first_arg]
                if st_name in _TYPE_LAYOUT_TABLE:
                    st_name = None

                if idx_raw.isdigit():
                    slot_idx = int(idx_raw)
                    barg = HostBufferArg(
                        index=slot_idx,
                        is_dynamic_index=False,
                        line=line_no,
                        api=b_api,
                        struct_type=st_name,
                    )
                    enc_st.bound_slots[slot_idx] = barg
                    enc_st.observed_args.append(barg)
                    if branch_stack:
                        branch_stack[-1].modified_slots.add((enc_recv, slot_idx))
                    else:
                        enc_st.uncertain_slots.discard(slot_idx)
                else:
                    dyn_barg = HostBufferArg(
                        index=None,
                        is_dynamic_index=True,
                        line=line_no,
                        api=b_api,
                        struct_type=st_name,
                    )
                    enc_st.dynamic_args.append(dyn_barg)
                    enc_st.observed_args.append(dyn_barg)

        # Detect encoder passed as argument to a helper call (`helper(enc)` / `helper(encoder: enc)`)
        if known_encoder_vars and not had_setter_or_pso_or_disp and not fresh_m:
            for kv in list(known_encoder_vars):
                if (
                    kv != "__default_encoder__"
                    and re.search(rf"\(\s*(?:[^()]*[,\s:]\s*)?{re.escape(kv)}\s*(?:[,)]|$)", stmt)
                    and not stmt.lstrip().startswith(("func ", "def ", "- (", "+ ("))
                    and "ComputeCommandEncoder" not in stmt
                ):
                    st_h = _get_enc(kv)
                    st_h.all_slots_uncertain = True
                    st_h.uncertainty_reasons.append(f"encoder `{kv}` passed to helper at line {line_no}")

        # 7. Snapshot encoder state at `dispatchThreads` / `dispatchThreadgroups` without clearing slots
        for dm in _DISPATCH_CALL_RE.finditer(stmt):
            enc_recv = (dm.group(1) or dm.group(2) or "__default_encoder__").replace("?.", ".")
            enc_st = _get_enc(enc_recv)
            active_lk = enc_st.pipeline_lookup
            if active_lk is None:
                if len(fn_lookups) == 1:
                    active_lk = fn_lookups[0]
                elif len(fn_lookups) > 1:
                    active_lk = fn_lookups[-1]
                    enc_st.all_slots_uncertain = True
                    enc_st.uncertainty_reasons.append(
                        "multiple kernel lookups in function without explicit encoder setComputePipelineState"
                    )
            if active_lk is None:
                continue
            active_lk.dispatched = True
            snap_args = [
                enc_st.bound_slots[k] for k in sorted(enc_st.bound_slots)
            ] + list(enc_st.dynamic_args)
            dispatches.append(
                HostMetalDispatch(
                    source_file=source_file,
                    line=line_no,
                    enclosing_symbol=cur_scope,
                    language=language,
                    kernel_name=active_lk.kernel_name,
                    kernel_expr=active_lk.kernel_expr,
                    is_dynamic_kernel=active_lk.is_dynamic,
                    lookup_api=active_lk.lookup_api,
                    has_pipeline_state=enc_st.has_pipeline_state or bool(pso_var_to_lookup),
                    has_dispatch_call=True,
                    buffer_args=snap_args,
                    encoder_name=enc_recv,
                    uncertain_slots=set(enc_st.uncertain_slots),
                    all_slots_uncertain=enc_st.all_slots_uncertain,
                    uncertainty_reasons=list(enc_st.uncertainty_reasons),
                    is_fresh_encoder=enc_st.is_fresh or len(known_encoder_vars) > 1,
                    observed_buffer_args=list(enc_st.observed_args),
                )
            )

        # 8. Advance brace state for remaining characters on statement
        if not is_python:
            brace_depth = max(0, brace_depth + net_tail_braces)
            while branch_stack and not temp_inline_frame and brace_depth <= branch_stack[-1].entry_depth:
                _pop_branch_frame(branch_stack.pop(), encoders)
        if temp_inline_frame and branch_stack:
            _pop_branch_frame(branch_stack.pop(), encoders)

    _flush_undispatched_lookups()
    return dispatches, host_structs


@dataclass
class MetalSeamAnalysis:
    """Complete CPU <-> Metal `AIR` compute seam analysis result for a repository."""

    has_metal_surface: bool = False
    metal_kernels: dict[str, MetalKernelSpec] = field(default_factory=dict)
    metallib_exports: dict[str, MetallibExport] = field(default_factory=dict)
    host_dispatches: list[HostMetalDispatch] = field(default_factory=list)
    unresolved_dispatches: list[HostMetalDispatch] = field(default_factory=list)
    host_structs: dict[str, StructLayoutSpec] = field(default_factory=dict)
    metal_structs: dict[str, StructLayoutSpec] = field(default_factory=dict)
    findings: list[dict[str, object]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _describe_struct_mismatch(
    host_st: StructLayoutSpec,
    metal_st: StructLayoutSpec,
) -> str | None:
    diffs: list[str] = []
    if host_st.stride != metal_st.stride or host_st.size != metal_st.size:
        diffs.append(
            f"host size/stride={host_st.size}B/{host_st.stride}B vs MSL size/stride={metal_st.size}B/{metal_st.stride}B"
        )
    if host_st.alignment != metal_st.alignment:
        diffs.append(f"host align={host_st.alignment}B vs MSL align={metal_st.alignment}B")

    if len(host_st.fields) != len(metal_st.fields):
        diffs.append(f"field count host={len(host_st.fields)} vs MSL={len(metal_st.fields)}")
    else:
        for hf, mf in zip(host_st.fields, metal_st.fields):
            if hf.name != mf.name:
                diffs.append(f"field order drift (`{hf.name}` vs `{mf.name}` at offset {hf.offset}B/{mf.offset}B)")
                break
            if hf.offset != mf.offset or hf.size != mf.size or hf.alignment != mf.alignment:
                diffs.append(
                    f"field `{hf.name}` host `{hf.type_name}` (offset={hf.offset}B, size={hf.size}B, align={hf.alignment}B) "
                    f"vs MSL `{mf.type_name}` (offset={mf.offset}B, size={mf.size}B, align={mf.alignment}B)"
                )
    return "; ".join(diffs) if diffs else None


_HOST_LANG_BY_SUFFIX: Final[dict[str, str]] = {
    ".swift": "swift",
    ".mm": "objcpp",
    ".m": "objc",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".h": "cpp",
    ".hpp": "cpp",
    ".py": "python",
}


def verify_metal_compute_seams(
    repo_root: Path,
    *,
    metallib_paths: tuple[str | Path, ...] | list[str | Path] = (),
    extra_metal_files: tuple[str | Path, ...] | list[str | Path] = (),
    node_id_by_file: dict[str, str] | None = None,
) -> MetalSeamAnalysis:
    """Scan host dispatch sites, `.metal` shaders, and `--metallib` `AIR` exports for seam drift."""
    analysis = MetalSeamAnalysis()
    nid_map = node_id_by_file or {}

    for mpath, rel_metal in iter_safe_repo_files(
        repo_root,
        suffixes=(".metal",),
        exclude_dirs=_REPO_SKIP_WALK_DIRS,
    ):
        _, mtext = read_safe_text(mpath, repo_root=repo_root, allow_external=False)
        parsed_m = parse_metal_source(mtext, source_file=rel_metal)
        analysis.metal_kernels.update(parsed_m.kernels)
        analysis.metal_structs.update(parsed_m.structs)

    for ext_m in extra_metal_files:
        parsed_ext = parse_metal_file(ext_m, repo_root=repo_root, allow_external=True)
        analysis.metal_kernels.update(parsed_ext.kernels)
        analysis.metal_structs.update(parsed_ext.structs)

    for mlib in metallib_paths:
        parsed_lib = parse_metallib_artifact(mlib, repo_root=repo_root, allow_external=True)
        analysis.metallib_exports.update(parsed_lib.exports)

    for hpath, rel_host in iter_safe_repo_files(
        repo_root,
        suffixes=tuple(_HOST_LANG_BY_SUFFIX),
        exclude_dirs=_REPO_SKIP_WALK_DIRS,
    ):
        lang = _HOST_LANG_BY_SUFFIX[hpath.suffix.lower()]
        _, htext = read_safe_text(hpath, repo_root=repo_root, allow_external=False)
        disps, hstructs = extract_host_metal_dispatches(htext, source_file=rel_host, language=lang)
        analysis.host_dispatches.extend(disps)
        analysis.host_structs.update(hstructs)
        if hpath.suffix.lower() in (".h", ".hpp") and "__METAL_VERSION__" in htext:
            mstructs = parse_structs_from_source(htext, source_file=rel_host, is_metal=True)
            analysis.metal_structs.update(mstructs)

    analysis.has_metal_surface = bool(
        analysis.metal_kernels or analysis.metallib_exports or analysis.host_dispatches
    )
    if not analysis.has_metal_surface:
        return analysis

    analysis.notes.append(METAL_AIR_EPISTEMIC_NOTE)
    available_kernels = set(analysis.metal_kernels) | set(analysis.metallib_exports)
    checked_struct_pairs: set[tuple[str, str, str, str]] = set()

    for disp in analysis.host_dispatches:
        nid = nid_map.get(disp.source_file)
        if disp.is_dynamic_kernel or not disp.kernel_name:
            analysis.unresolved_dispatches.append(disp)
        elif disp.kernel_name not in available_kernels:
            analysis.findings.append(
                {
                    "rule_code": "METAL-001",
                    "node_id": nid,
                    "source_file": disp.source_file,
                    "line": disp.line,
                    "title": f"Static host Metal kernel `{disp.kernel_name}` is absent from `.metal` and `.metallib` AIR exports",
                    "detail": (
                        f"`{disp.source_file}:{disp.line}` (`{disp.enclosing_symbol}`) looks up static "
                        f"compute kernel `{disp.kernel_name}` via `{disp.lookup_api}`, but `{disp.kernel_name}` "
                        "is absent from all discovered `.metal` entrypoints and `.metallib` AIR exports."
                    ),
                    "remediation": (
                        f"Define `[[kernel]] void {disp.kernel_name}(...)` (or `[[host_name(\"{disp.kernel_name}\")]]`) "
                        "in the target `.metal` library or align the host kernel name."
                    ),
                    "confidence": "confirmed",
                    "evidence_strength": "ast_exact",
                }
            )

        bound_idxs = {barg.index for barg in disp.buffer_args if barg.index is not None}

        if disp.kernel_name and not disp.is_dynamic_kernel:
            kspec = analysis.metal_kernels.get(disp.kernel_name)
            mexp = analysis.metallib_exports.get(disp.kernel_name)
            declared_idxs: set[int] = (
                set(kspec.buffers)
                if kspec is not None and kspec.buffers
                else (set(mexp.buffer_indices) if mexp is not None else set())
            )
            has_dyn_idx = any(b.is_dynamic_index for b in disp.buffer_args)
            has_encoder_activity = bool(
                disp.buffer_args or disp.has_pipeline_state or disp.is_fresh_encoder
            )
            if disp.has_dispatch_call and declared_idxs and has_encoder_activity:
                if has_dyn_idx or disp.all_slots_uncertain:
                    disp.binding_verification = "unverified"
                    reason_str = (
                        "; ".join(disp.uncertainty_reasons)
                        if disp.uncertainty_reasons
                        else "dynamic buffer index expression"
                    )
                    note_txt = (
                        f"metal_air: `{disp.source_file}:{disp.line}` (`{disp.enclosing_symbol}`) "
                        f"encoder buffer state for `{disp.kernel_name}` is unverified ({reason_str}); "
                        "skipping exact METAL-002."
                    )
                    if note_txt not in analysis.notes:
                        analysis.notes.append(note_txt)
                else:
                    missing_all = sorted(declared_idxs - bound_idxs)
                    missing_definite = [i for i in missing_all if i not in disp.uncertain_slots]
                    missing_uncertain = [i for i in missing_all if i in disp.uncertain_slots]
                    if missing_definite:
                        miss_str = ", ".join(f"[[buffer({i})]]" for i in missing_definite)
                        enc_lbl = (
                            f" on encoder `{disp.encoder_name}`"
                            if disp.encoder_name and disp.encoder_name != "__default_encoder__"
                            else ""
                        )
                        analysis.findings.append(
                            {
                                "rule_code": "METAL-002",
                                "node_id": nid,
                                "source_file": disp.source_file,
                                "line": disp.line,
                                "title": f"Host dispatch to `{disp.kernel_name}` omits declared {miss_str} binding(s)",
                                "detail": (
                                    f"`{disp.source_file}:{disp.line}` (`{disp.enclosing_symbol}`){enc_lbl} "
                                    f"binds buffer indices {sorted(bound_idxs)}, omitting {miss_str} "
                                    f"declared on kernel `{disp.kernel_name}`."
                                ),
                                "remediation": f"Bind {miss_str} on the compute command encoder before `dispatchThreads`/`dispatchThreadgroups`.",
                                "confidence": "confirmed",
                                "evidence_strength": "ast_exact",
                            }
                        )
                    elif missing_uncertain:
                        disp.binding_verification = "unverified"
                        unc_str = ", ".join(f"[[buffer({i})]]" for i in missing_uncertain)
                        note_txt = (
                            f"metal_air: `{disp.source_file}:{disp.line}` (`{disp.enclosing_symbol}`) "
                            f"conditionally binds {unc_str} before dispatching `{disp.kernel_name}`; "
                            "buffer binding state remains unverified."
                        )
                        if note_txt not in analysis.notes:
                            analysis.notes.append(note_txt)

            if kspec is not None:
                args_to_check = disp.observed_buffer_args or disp.buffer_args
                for barg in args_to_check:
                    if barg.index is None or not barg.struct_type:
                        continue
                    kbuf = kspec.buffers.get(barg.index)
                    if kbuf is None or not kbuf.struct_type:
                        continue
                    hst = analysis.host_structs.get(barg.struct_type)
                    mst = analysis.metal_structs.get(kbuf.struct_type)
                    if hst is not None and mst is not None:
                        pkey = (hst.source_file, hst.name, mst.source_file, mst.name)
                        checked_struct_pairs.add(pkey)
                        mismatch = _describe_struct_mismatch(hst, mst)
                        if mismatch:
                            analysis.findings.append(
                                {
                                    "rule_code": "METAL-003",
                                    "node_id": nid,
                                    "source_file": disp.source_file,
                                    "line": barg.line,
                                    "title": f"Host `{hst.name}` vs Metal `{mst.name}` layout mismatch on `[[buffer({barg.index})]]`",
                                    "detail": (
                                        f"`{disp.source_file}:{barg.line}` binds host struct `{hst.name}` "
                                        f"(`{hst.source_file}:{hst.line}`) to `{disp.kernel_name}` `[[buffer({barg.index})]]` "
                                        f"(`{mst.name}` at `{mst.source_file}:{mst.line}`), but layouts diverge: {mismatch}."
                                    ),
                                    "remediation": (
                                        "Use `packed_float3` / `MTLPackedFloat3` or explicit padding fields so host and MSL "
                                        "struct size, stride, alignment, and field offsets match identically."
                                    ),
                                    "confidence": "confirmed",
                                    "evidence_strength": "ast_exact",
                                }
                            )

    for sname in sorted(set(analysis.host_structs) & set(analysis.metal_structs)):
        hst = analysis.host_structs[sname]
        mst = analysis.metal_structs[sname]
        pkey = (hst.source_file, hst.name, mst.source_file, mst.name)
        if pkey in checked_struct_pairs:
            continue
        checked_struct_pairs.add(pkey)
        mismatch = _describe_struct_mismatch(hst, mst)
        if mismatch:
            nid = nid_map.get(hst.source_file) or nid_map.get(mst.source_file)
            analysis.findings.append(
                {
                    "rule_code": "METAL-003",
                    "node_id": nid,
                    "source_file": hst.source_file,
                    "line": hst.line,
                    "title": f"Shared host/Metal struct `{sname}` layout mismatch ({hst.stride}B vs {mst.stride}B)",
                    "detail": (
                        f"Shared struct `{sname}` differs between host `{hst.source_file}:{hst.line}` "
                        f"and Metal `{mst.source_file}:{mst.line}`: {mismatch}."
                    ),
                    "remediation": (
                        "Align `float3` / `simd_float3` (16-byte aligned) vs `packed_float3` / `float[3]` (12-byte) "
                        "and keep field order identical across host and `.metal` declarations."
                    ),
                    "confidence": "confirmed",
                    "evidence_strength": "ast_exact",
                }
            )

    if analysis.unresolved_dispatches:
        sample = ", ".join(
            f"{d.source_file}:{d.line} ({d.kernel_expr})" for d in analysis.unresolved_dispatches[:5]
        )
        analysis.notes.append(
            f"Classified {len(analysis.unresolved_dispatches)} runtime/JIT-specialized Metal kernel "
            f"lookup(s) as unverified (unresolved): {sample}"
        )

    return analysis
