"""Pure-Python 64-bit & Universal Mach-O static binary parser (100% passive, zero execution)."""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, Literal

from wythe_plugin_binary.entitlement_drift import (
    MAX_BINARY_BYTES,
    aggregate_slice_entitlements_conservatively,
    extract_binary_string_witnesses,
    parse_safe_entitlements_xml,
    read_bounded_regular_bytes,
)
from wythe_plugin_binary.recorded_fixtures import (
    DemangledSymbol,
    LinkedLibraryRef,
    MachoBinaryCapabilities,
    RecordedBinaryCapture,
    ReflectionDescriptor,
    build_linked_library_ref,
    demangle_symbol_name,
)

MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
MH_MAGIC_64_BE = b"\xfe\xed\xfa\xcf"
FAT_MAGIC_BE = b"\xca\xfe\xba\xbe"
FAT_MAGIC_LE = b"\xbe\xba\xfe\xca"
FAT_MAGIC_64_BE = b"\xca\xfe\xba\xbf"
FAT_MAGIC_64_LE = b"\xbf\xba\xfe\xca"

LC_SYMTAB = 0x02
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_RPATH = 0x8000001C
LC_REEXPORT_DYLIB = 0x8000001F

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSSLOT_DER_ENTITLEMENTS = 7

MAX_LOAD_COMMANDS = 4096
MAX_SECTIONS_PER_SEG = 512
MAX_FAT_ARCHES = 32
MAX_MACHO_SYMBOLS = 262_144
MAX_CSTRINGS = 4096
MAX_SUPERBLOB_BLOBS = 256

_ZEROFILL_SECTION_TYPES: frozenset[int] = frozenset({0x01, 0x0C, 0x12})
_CPU_NAMES: dict[int, str] = {
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
    0x01000007: "x86_64",
    0x00000007: "i386",
    0x0000000C: "arm",
}


def is_macho_magic(buf: bytes) -> bool:
    """Return True if `buf` starts with a 64-bit Mach-O or Universal/Fat magic."""
    if len(buf) < 4:
        return False
    return buf[:4] in (
        MH_MAGIC_64_LE,
        MH_MAGIC_64_BE,
        FAT_MAGIC_BE,
        FAT_MAGIC_LE,
        FAT_MAGIC_64_BE,
        FAT_MAGIC_64_LE,
    )


def _decode_version_triple(ver: int) -> str:
    return f"{(ver >> 16) & 0xFFFF}.{(ver >> 8) & 0xFF}.{ver & 0xFF}"


def _read_cstring_at(buf: bytes, start: int, limit: int = 1024) -> str:
    if start < 0 or start >= len(buf):
        return ""
    end_bound = min(len(buf), start + limit)
    nul_pos = buf.find(b"\x00", start, end_bound)
    raw = buf[start:nul_pos] if nul_pos != -1 else buf[start:end_bound]
    decoded = raw.decode("utf-8", errors="replace")
    return "".join(ch for ch in decoded if ord(ch) >= 0x20 and ord(ch) != 0x7F).strip()


_NON_NUL_BYTE_RE = re.compile(b"[" + bytes([94, 0]) + b"]")


def _extract_printable_cstrings(sec_bytes: bytes, *, max_items: int = MAX_CSTRINGS) -> list[str]:
    out: list[str] = []
    pos = 0
    total_len = len(sec_bytes)
    scanned_steps = 0
    max_scan_steps = max_items * 64 + 65536
    while pos < total_len and len(out) < max_items:
        m = _NON_NUL_BYTE_RE.search(sec_bytes, pos)
        if m is None:
            break
        pos = m.start()
        scanned_steps += 1
        if scanned_steps > max_scan_steps:
            break
        nul = sec_bytes.find(b"\x00", pos)
        end = total_len if nul == -1 else nul
        chunk = sec_bytes[pos:end]
        pos = total_len if nul == -1 else end + 1
        if len(chunk) < 2 or len(chunk) > 512:
            continue
        try:
            s = chunk.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if all(0x20 <= ord(ch) <= 0x7E or ch == "\t" for ch in s):
            out.append(s)
    return out


def _vm_to_file_offset(
    vmaddr: int,
    seg_ranges: list[tuple[int, int, int, int]],
) -> int | None:
    masked = vmaddr & 0x0000FFFFFFFFFFFF if vmaddr > 0x0001000000000000 else vmaddr
    for cand_vm in (vmaddr, masked):
        for s_vm, s_vmsz, s_foff, s_fsz in seg_ranges:
            span = min(s_vmsz, s_fsz)
            if s_vm <= cand_vm < s_vm + span:
                return s_foff + (cand_vm - s_vm)
    return None


def _parse_code_signature_entitlements_detail(
    sig_bytes: bytes,
) -> tuple[dict[str, Any], bool, bool]:
    if len(sig_bytes) < 8:
        raise ValueError("Truncated Mach-O LC_CODE_SIGNATURE payload (< 8 bytes).")
    magic, total_len = struct.unpack_from(">II", sig_bytes, 0)
    if magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
        if total_len < 8 or total_len > len(sig_bytes):
            raise ValueError("Out-of-bounds CSMAGIC_EMBEDDED_ENTITLEMENTS blob length.")
        return parse_safe_entitlements_xml(sig_bytes[8:total_len]), True, False
    if magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
        if total_len < 8 or total_len > len(sig_bytes):
            raise ValueError("Out-of-bounds CSMAGIC_EMBEDDED_DER_ENTITLEMENTS blob length.")
        return {}, True, True
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return {}, False, False
    if len(sig_bytes) < 12 or total_len < 12 or total_len > len(sig_bytes):
        raise ValueError("Corrupt or truncated CSMAGIC_EMBEDDED_SIGNATURE superblob.")
    count = struct.unpack_from(">I", sig_bytes, 8)[0]
    if count > MAX_SUPERBLOB_BLOBS or 12 + count * 8 > total_len:
        raise ValueError("Out-of-bounds CS_SuperBlob index count.")

    xml_ents: dict[str, Any] = {}
    has_xml = False
    has_der = False
    for idx in range(count):
        btype, boff = struct.unpack_from(">II", sig_bytes, 12 + idx * 8)
        if boff < 12 or boff + 8 > total_len:
            raise ValueError("Out-of-bounds CS_BlobIndex offset in LC_CODE_SIGNATURE.")
        sub_magic, sub_len = struct.unpack_from(">II", sig_bytes, boff)
        if sub_len < 8 or boff + sub_len > total_len:
            raise ValueError("Out-of-bounds sub-blob length in LC_CODE_SIGNATURE.")
        if sub_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            xml_ents = parse_safe_entitlements_xml(sig_bytes[boff + 8 : boff + sub_len])
            has_xml = True
        elif btype == CSSLOT_DER_ENTITLEMENTS or sub_magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            has_der = True
    if has_xml:
        return xml_ents, True, False
    if has_der:
        return {}, True, True
    return {}, False, False


def _parse_code_signature_entitlements_with_presence(
    sig_bytes: bytes,
) -> tuple[dict[str, Any], bool]:
    ents, has_blob, _der_only = _parse_code_signature_entitlements_detail(sig_bytes)
    return ents, has_blob


def _parse_code_signature_entitlements(sig_bytes: bytes) -> dict[str, Any]:
    ent_map, _ = _parse_code_signature_entitlements_with_presence(sig_bytes)
    return ent_map


def _extract_swift_reflection(
    slice_buf: bytes,
    endian: str,
    sections: dict[tuple[str, str], tuple[int, int, int]],
    seg_ranges: list[tuple[int, int, int, int]],
) -> list[ReflectionDescriptor]:
    descriptors: list[ReflectionDescriptor] = []
    seen: set[tuple[str, str]] = set()

    def _add(sec_label: str, kind: Any, raw_ident: str) -> None:
        ident = raw_ident.strip()
        if (
            len(ident) < 2
            or len(ident) > 160
            or not all(ch.isalnum() or ch in "_.:$+-[] " for ch in ident)
            or not any(ch.isalpha() for ch in ident)
        ):
            return
        if (kind, ident) not in seen and len(descriptors) < 512:
            seen.add((kind, ident))
            descriptors.append(ReflectionDescriptor(section=sec_label, kind=kind, name=ident))

    for (seg, sect), rkind in (
        (("__TEXT", "__swift5_types"), "swift_type_descriptor"),
        (("__TEXT", "__swift5_proto"), "swift_protocol_conformance"),
        (("__TEXT", "__swift5_fieldmd"), "swift_field_metadata"),
    ):
        meta = sections.get((seg, sect))
        if meta is None:
            continue
        sec_vm, sec_off, sec_sz = meta
        sec_bytes = slice_buf[sec_off : sec_off + sec_sz]
        sec_label = f"{seg},{sect}"

        resolved_any = False
        if rkind == "swift_type_descriptor" and sec_sz >= 4 and sec_sz % 4 == 0:
            for pos in range(0, min(sec_sz, 4096), 4):
                rel = struct.unpack_from(f"{endian}i", sec_bytes, pos)[0]
                desc_vm = sec_vm + pos + rel
                desc_foff = _vm_to_file_offset(desc_vm, seg_ranges)
                if desc_foff is not None and desc_foff + 12 <= len(slice_buf):
                    name_rel = struct.unpack_from(f"{endian}i", slice_buf, desc_foff + 8)[0]
                    name_foff = _vm_to_file_offset(desc_vm + 8 + name_rel, seg_ranges)
                    if name_foff is not None:
                        nm = _read_cstring_at(slice_buf, name_foff, 128)
                        if nm and nm.isidentifier():
                            _add(sec_label, rkind, nm)
                            resolved_any = True

        if not resolved_any:
            for s in _extract_printable_cstrings(sec_bytes, max_items=256):
                _add(sec_label, rkind, s)

    return descriptors


def _extract_objc_reflection(
    slice_buf: bytes,
    endian: str,
    sections: dict[tuple[str, str], tuple[int, int, int]],
    seg_ranges: list[tuple[int, int, int, int]],
) -> list[ReflectionDescriptor]:
    out: list[ReflectionDescriptor] = []
    seen: set[tuple[str, str]] = set()

    def _add_objc(sec_label: str, kind: Any, raw_name: str) -> None:
        clean = raw_name.strip()
        if (
            len(clean) < 2
            or len(clean) > 160
            or not all(ch.isalnum() or ch in "_:$+-." for ch in clean)
            or not any(ch.isalpha() for ch in clean)
        ):
            return
        if (kind, clean) not in seen and len(out) < 512:
            seen.add((kind, clean))
            out.append(ReflectionDescriptor(section=sec_label, kind=kind, name=clean))

    for seg in ("__DATA_CONST", "__DATA"):
        cls_meta = sections.get((seg, "__objc_classlist"))
        if cls_meta is not None:
            _vm, c_off, c_sz = cls_meta
            sec_bytes = slice_buf[c_off : c_off + c_sz]
            sec_lbl = f"{seg},__objc_classlist"
            resolved = False
            if c_sz >= 8 and c_sz % 8 == 0:
                for pos in range(0, min(c_sz, 4096), 8):
                    ptr = struct.unpack_from(f"{endian}Q", sec_bytes, pos)[0]
                    foff = _vm_to_file_offset(ptr, seg_ranges)
                    if foff is not None:
                        cand_str = _read_cstring_at(slice_buf, foff, 128)
                        if cand_str and all(c.isalnum() or c in "_$" for c in cand_str):
                            _add_objc(sec_lbl, "objc_class", cand_str)
                            resolved = True
                        elif foff + 40 <= len(slice_buf):
                            ro_ptr = struct.unpack_from(f"{endian}Q", slice_buf, foff + 32)[0]
                            ro_foff = _vm_to_file_offset(ro_ptr & ~0x7, seg_ranges)
                            if ro_foff is not None and ro_foff + 32 <= len(slice_buf):
                                nm_ptr = struct.unpack_from(f"{endian}Q", slice_buf, ro_foff + 24)[0]
                                nm_foff = _vm_to_file_offset(nm_ptr, seg_ranges)
                                if nm_foff is not None:
                                    ro_name = _read_cstring_at(slice_buf, nm_foff, 128)
                                    if ro_name:
                                        _add_objc(sec_lbl, "objc_class", ro_name)
                                        resolved = True
            if not resolved:
                for s in _extract_printable_cstrings(sec_bytes, max_items=256):
                    _add_objc(sec_lbl, "objc_class", s)
                cls_names_meta = sections.get(("__TEXT", "__objc_classname"))
                if cls_names_meta is not None:
                    _, cn_off, cn_sz = cls_names_meta
                    for s in _extract_printable_cstrings(slice_buf[cn_off : cn_off + cn_sz], max_items=256):
                        _add_objc(sec_lbl, "objc_class", s)

        sel_meta = sections.get((seg, "__objc_selrefs"))
        if sel_meta is not None:
            _vm, s_off, s_sz = sel_meta
            sec_bytes = slice_buf[s_off : s_off + s_sz]
            sec_lbl = f"{seg},__objc_selrefs"
            resolved_sel = False
            if s_sz >= 8 and s_sz % 8 == 0:
                for pos in range(0, min(s_sz, 4096), 8):
                    ptr = struct.unpack_from(f"{endian}Q", sec_bytes, pos)[0]
                    foff = _vm_to_file_offset(ptr, seg_ranges)
                    if foff is not None:
                        sel_name = _read_cstring_at(slice_buf, foff, 128)
                        if sel_name and all(c.isalnum() or c in "_:" for c in sel_name):
                            _add_objc(sec_lbl, "objc_selector", sel_name)
                            resolved_sel = True
            if not resolved_sel:
                for s in _extract_printable_cstrings(sec_bytes, max_items=256):
                    _add_objc(sec_lbl, "objc_selector", s)
    return out


def _parse_macho_64_slice(
    slice_buf: bytes,
    *,
    source_name: str,
    fat_cpusubtype: int | None = None,
) -> RecordedBinaryCapture:
    if len(slice_buf) < 32:
        raise ValueError(f"Truncated 64-bit Mach-O header in '{source_name}' (< 32 bytes).")
    magic4 = slice_buf[:4]
    if magic4 == MH_MAGIC_64_LE:
        endian = "<"
    elif magic4 == MH_MAGIC_64_BE:
        endian = ">"
    else:
        raise ValueError(f"Unsupported Mach-O slice magic {magic4.hex()} in '{source_name}'.")

    _magic, cputype, _cpusubtype, _filetype, ncmds, sizeofcmds, _flags, _res = struct.unpack_from(
        f"{endian}IiiIIIII", slice_buf, 0
    )
    if ncmds > MAX_LOAD_COMMANDS:
        raise ValueError(f"Mach-O ncmds ({ncmds}) exceeds safety bound ({MAX_LOAD_COMMANDS}).")
    if sizeofcmds > len(slice_buf) - 32:
        raise ValueError("Truncated Mach-O load commands table (sizeofcmds exceeds buffer).")

    eff_subtype = _cpusubtype if (_cpusubtype & 0xFF) != 0 else (fat_cpusubtype or 0)
    if cputype == 0x0100000C and (eff_subtype & 0xFF) == 2:
        arch_name = "arm64e"
    elif cputype == 0x01000007 and (eff_subtype & 0xFF) == 8:
        arch_name = "x86_64h"
    else:
        arch_name = _CPU_NAMES.get(cputype, f"cputype_{cputype & 0xFFFFFFFF:#x}")
    raw_dylibs: list[tuple[str, Literal["required", "weak", "reexport", "lazy"], str, str]] = []
    rpaths: list[str] = []
    seg_ranges: list[tuple[int, int, int, int]] = []
    sections: dict[tuple[str, str], tuple[int, int, int]] = {}
    symtab_params: tuple[int, int, int, int] | None = None
    codesig_range: tuple[int, int] | None = None

    pos = 32
    cmds_end = 32 + sizeofcmds
    for _ in range(ncmds):
        if pos + 8 > cmds_end:
            raise ValueError("Truncated Mach-O load command header.")
        cmd, cmdsize = struct.unpack_from(f"{endian}II", slice_buf, pos)
        if cmdsize < 8 or pos + cmdsize > cmds_end:
            raise ValueError(f"Invalid Mach-O load command size ({cmdsize}) at offset {pos}.")
        cmd_bytes = slice_buf[pos : pos + cmdsize]

        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB):
            if cmdsize < 24:
                raise ValueError("Truncated Mach-O dylib_command (< 24 bytes).")
            _, _, name_off, _ts, curr_v, compat_v = struct.unpack_from(f"{endian}IIIIII", cmd_bytes, 0)
            if name_off < 24 or name_off >= cmdsize:
                raise ValueError("Out-of-bounds dylib_command name offset.")
            dpath = _read_cstring_at(cmd_bytes, name_off, cmdsize - name_off)
            lkind: Literal["required", "weak", "reexport", "lazy"] = (
                "weak"
                if cmd == LC_LOAD_WEAK_DYLIB
                else ("reexport" if cmd == LC_REEXPORT_DYLIB else ("lazy" if cmd == LC_LAZY_LOAD_DYLIB else "required"))
            )
            if dpath:
                raw_dylibs.append(
                    (dpath, lkind, _decode_version_triple(curr_v), _decode_version_triple(compat_v))
                )
        elif cmd == LC_RPATH:
            if cmdsize < 12:
                raise ValueError("Truncated Mach-O rpath_command (< 12 bytes).")
            _, _, path_off = struct.unpack_from(f"{endian}III", cmd_bytes, 0)
            if path_off < 12 or path_off >= cmdsize:
                raise ValueError("Out-of-bounds rpath_command path offset.")
            rp = _read_cstring_at(cmd_bytes, path_off, cmdsize - path_off)
            if rp and rp not in rpaths:
                rpaths.append(rp)
        elif cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise ValueError("Truncated Mach-O segment_command_64 (< 72 bytes).")
            (
                _,
                _,
                seg_raw,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                _maxp,
                _initp,
                nsects,
                _sflags,
            ) = struct.unpack_from(f"{endian}II16sQQQQiiII", cmd_bytes, 0)
            if nsects < 0 or nsects > MAX_SECTIONS_PER_SEG or 72 + nsects * 80 > cmdsize:
                raise ValueError("Out-of-bounds Mach-O section_64 count or size.")
            if filesize > 0 and fileoff + filesize > len(slice_buf):
                raise ValueError("Out-of-bounds Mach-O LC_SEGMENT_64 file range.")
            seg_name = seg_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
            if filesize > 0 and vmsize > 0:
                seg_ranges.append((vmaddr, vmsize, fileoff, filesize))
            for s_idx in range(nsects):
                (
                    sect_raw,
                    s_seg_raw,
                    s_addr,
                    s_size,
                    s_offset,
                    _align,
                    _reloff,
                    _nreloc,
                    s_flags,
                    _r1,
                    _r2,
                    _r3,
                ) = struct.unpack_from(f"{endian}16s16sQQIIIIIIII", cmd_bytes, 72 + s_idx * 80)
                sect_name = sect_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
                s_seg = s_seg_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip() or seg_name
                sec_type = s_flags & 0xFF
                if sec_type not in _ZEROFILL_SECTION_TYPES and s_size > 0:
                    if s_offset + s_size > len(slice_buf):
                        raise ValueError(
                            f"Out-of-bounds Mach-O section ({s_seg},{sect_name}) offset/size."
                        )
                    sections[(s_seg, sect_name)] = (s_addr, s_offset, s_size)
        elif cmd == LC_SYMTAB:
            if cmdsize < 24:
                raise ValueError("Truncated Mach-O symtab_command (< 24 bytes).")
            _, _, symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian}IIIIII", cmd_bytes, 0)
            if nsyms > MAX_MACHO_SYMBOLS:
                raise ValueError(f"Mach-O nsyms ({nsyms}) exceeds cap ({MAX_MACHO_SYMBOLS}).")
            if symoff + nsyms * 16 > len(slice_buf) or stroff + strsize > len(slice_buf):
                raise ValueError("Out-of-bounds Mach-O LC_SYMTAB symbol or string table.")
            symtab_params = (symoff, nsyms, stroff, strsize)
        elif cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise ValueError("Truncated Mach-O LC_CODE_SIGNATURE (< 16 bytes).")
            _, _, dataoff, datasize = struct.unpack_from(f"{endian}IIII", cmd_bytes, 0)
            if dataoff + datasize > len(slice_buf):
                raise ValueError("Out-of-bounds Mach-O LC_CODE_SIGNATURE payload.")
            codesig_range = (dataoff, datasize)

        pos += cmdsize

    rpath_tuple = tuple(rpaths)
    dylib_refs = tuple(
        build_linked_library_ref(
            dp,
            load_kind=lk,
            rpaths=rpath_tuple,
            current_version=cv,
            compatibility_version=cpv,
        )
        for dp, lk, cv, cpv in raw_dylibs
    )

    exported_syms: list[DemangledSymbol] = []
    imported_syms: list[DemangledSymbol] = []
    if symtab_params is not None:
        symoff, nsyms, stroff, strsize = symtab_params
        strtab = slice_buf[stroff : stroff + strsize]
        for idx in range(nsyms):
            n_strx, n_type, _n_sect, n_desc, n_value = struct.unpack_from(
                f"{endian}IBBHQ", slice_buf, symoff + idx * 16
            )
            if n_strx != 0 and n_strx >= strsize:
                raise ValueError("Out-of-bounds Mach-O nlist_64 string table index.")
            if n_type & 0xE0:
                continue
            sym_name = _read_cstring_at(strtab, n_strx, 512) if strsize > 0 and n_strx > 0 else ""
            if not sym_name:
                continue
            ntype_mask = n_type & 0x0E
            if ntype_mask == 0x0 and n_value == 0:
                ord_val = (n_desc >> 8) & 0xFF
                imported_syms.append(
                    demangle_symbol_name(
                        sym_name,
                        binding="imported",
                        is_macho=True,
                        library_ordinal=ord_val if ord_val > 0 else None,
                    )
                )
            elif ntype_mask in (0x0E, 0x02, 0x0A) and (n_type & 0x01) and not (n_type & 0x10):
                exported_syms.append(
                    demangle_symbol_name(sym_name, binding="exported", is_macho=True)
                )

    refl = [
        *_extract_swift_reflection(slice_buf, endian, sections, seg_ranges),
        *_extract_objc_reflection(slice_buf, endian, sections, seg_ranges),
    ]

    cstr_list: list[str] = []
    cstr_meta = sections.get(("__TEXT", "__cstring"))
    if cstr_meta is not None:
        _, cs_off, cs_sz = cstr_meta
        cstr_list.extend(_extract_printable_cstrings(slice_buf[cs_off : cs_off + cs_sz]))
    witnesses = extract_binary_string_witnesses(cstr_list, section="__TEXT,__cstring")

    entitlements: dict[str, Any] = {}
    has_ent_blob = False
    der_only = False
    if codesig_range is not None and codesig_range[1] > 0:
        cs_off, cs_sz = codesig_range
        entitlements, has_ent_blob, der_only = _parse_code_signature_entitlements_detail(
            slice_buf[cs_off : cs_off + cs_sz]
        )

    return RecordedBinaryCapture(
        name=source_name,
        binary_format="macho",
        source_kind="raw_binary",
        architectures=(arch_name,),
        is_universal=False,
        linked_libraries=dylib_refs,
        rpaths=rpath_tuple,
        runpaths=(),
        soname=None,
        exported_symbols=tuple(dict.fromkeys(exported_syms)),
        imported_symbols=tuple(dict.fromkeys(imported_syms)),
        reflection_descriptors=tuple(refl),
        string_witnesses=witnesses,
        entitlements=entitlements,
        linux_capabilities=(),
        slice_entitlements={arch_name: dict(entitlements)},
        slice_has_entitlements_blob={arch_name: has_ent_blob},
        slice_der_only_entitlements={arch_name: der_only},
    )


def parse_macho_bytes(
    buf: bytes,
    *,
    source_name: str = "macho-binary",
) -> RecordedBinaryCapture:
    """Parse a 64-bit or Universal/Fat Mach-O byte buffer into `RecordedBinaryCapture`."""
    if len(buf) > MAX_BINARY_BYTES:
        raise ValueError(f"Mach-O buffer ({len(buf)} bytes) exceeds {MAX_BINARY_BYTES}-byte limit.")
    if len(buf) < 8:
        raise ValueError(f"Truncated Mach-O buffer in '{source_name}' (< 8 bytes).")

    magic4 = buf[:4]
    if magic4 in (MH_MAGIC_64_LE, MH_MAGIC_64_BE):
        return _parse_macho_64_slice(buf, source_name=source_name)

    if magic4 in (FAT_MAGIC_BE, FAT_MAGIC_LE, FAT_MAGIC_64_BE, FAT_MAGIC_64_LE):
        fat_endian = ">" if magic4 in (FAT_MAGIC_BE, FAT_MAGIC_64_BE) else "<"
        is_fat64 = magic4 in (FAT_MAGIC_64_BE, FAT_MAGIC_64_LE)
        _fmagic, nfat_arch = struct.unpack_from(f"{fat_endian}II", buf, 0)
        if nfat_arch <= 0 or nfat_arch > MAX_FAT_ARCHES:
            raise ValueError(f"Invalid Universal Mach-O nfat_arch ({nfat_arch}).")
        arch_entry_sz = 32 if is_fat64 else 20
        if 8 + nfat_arch * arch_entry_sz > len(buf):
            raise ValueError("Truncated Universal Mach-O fat_arch header table.")

        slices: list[RecordedBinaryCapture] = []
        total_slice_bytes = 0
        seen_ranges: list[tuple[int, int]] = []
        for idx in range(nfat_arch):
            ent_pos = 8 + idx * arch_entry_sz
            if is_fat64:
                _cput, _cpusub, s_off, s_sz, _align, _res = struct.unpack_from(
                    f"{fat_endian}iiQQII", buf, ent_pos
                )
            else:
                _cput, _cpusub, s_off, s_sz, _align = struct.unpack_from(
                    f"{fat_endian}iiIII", buf, ent_pos
                )
            if s_sz < 32 or s_off < 8 or s_off + s_sz > len(buf):
                raise ValueError(f"Out-of-bounds Universal Mach-O slice #{idx}.")
            total_slice_bytes += s_sz
            if total_slice_bytes > MAX_BINARY_BYTES:
                raise ValueError(
                    f"Universal Mach-O cumulative slice bytes ({total_slice_bytes}) exceed {MAX_BINARY_BYTES}-byte limit."
                )
            s_end = s_off + s_sz
            for prev_start, prev_end in seen_ranges:
                if s_off < prev_end and prev_start < s_end:
                    raise ValueError(f"Overlapping Universal Mach-O slice #{idx} is forbidden.")
            seen_ranges.append((s_off, s_end))
            sub_buf = buf[s_off:s_end]
            if sub_buf[:4] in (FAT_MAGIC_BE, FAT_MAGIC_LE, FAT_MAGIC_64_BE, FAT_MAGIC_64_LE):
                raise ValueError("Nested Universal Mach-O headers are forbidden.")
            slices.append(
                _parse_macho_64_slice(sub_buf, source_name=source_name, fat_cpusubtype=_cpusub)
            )

        arches: list[str] = []
        libs_by_p: dict[str, LinkedLibraryRef] = {}
        rpaths: list[str] = []
        exp_syms: dict[str, DemangledSymbol] = {}
        imp_syms: dict[str, DemangledSymbol] = {}
        refl: dict[tuple[str, str], ReflectionDescriptor] = {}
        wit: dict[tuple[str, str], Any] = {}
        per_arch_slices: dict[str, list[tuple[dict[str, Any], bool, bool]]] = {}

        for sl in slices:
            for a in sl.architectures:
                if a not in arches:
                    arches.append(a)
                s_ent = dict(sl.slice_entitlements.get(a, sl.entitlements))
                s_blob = bool(sl.slice_has_entitlements_blob.get(a, bool(sl.entitlements)))
                s_der = bool(sl.slice_der_only_entitlements.get(a, False))
                per_arch_slices.setdefault(a, []).append((s_ent, s_blob, s_der))
            for lb in sl.linked_libraries:
                libs_by_p.setdefault(lb.raw_path, lb)
            for rp in sl.rpaths:
                if rp not in rpaths:
                    rpaths.append(rp)
            for es in sl.exported_symbols:
                exp_syms.setdefault(es.raw_name, es)
            for ims in sl.imported_symbols:
                imp_syms.setdefault(ims.raw_name, ims)
            for rf in sl.reflection_descriptors:
                refl.setdefault((rf.kind, rf.name), rf)
            for wt in sl.string_witnesses:
                wit.setdefault((wt.category, wt.value), wt)

        sorted_slice_ents: dict[str, dict[str, Any]] = {}
        sorted_slice_blobs: dict[str, bool] = {}
        sorted_slice_der_only: dict[str, bool] = {}
        for arch_k in sorted(per_arch_slices):
            entries_for_arch = per_arch_slices[arch_k]
            if len(entries_for_arch) == 1:
                sorted_slice_ents[arch_k] = entries_for_arch[0][0]
                sorted_slice_blobs[arch_k] = entries_for_arch[0][1]
                sorted_slice_der_only[arch_k] = entries_for_arch[0][2]
            else:
                ordered_dups = sorted(
                    entries_for_arch,
                    key=lambda triple: (triple[1], triple[2], repr(sorted(triple[0].items()))),
                )
                for dup_i, (d_ent, d_blob, d_der) in enumerate(ordered_dups, start=1):
                    dup_key = f"{arch_k}#{dup_i}"
                    sorted_slice_ents[dup_key] = d_ent
                    sorted_slice_blobs[dup_key] = d_blob
                    sorted_slice_der_only[dup_key] = d_der

        merged_ent = aggregate_slice_entitlements_conservatively(sorted_slice_ents)

        return RecordedBinaryCapture(
            name=source_name,
            binary_format="macho",
            source_kind="raw_binary",
            architectures=tuple(arches),
            is_universal=True,
            linked_libraries=tuple(libs_by_p.values()),
            rpaths=tuple(rpaths),
            runpaths=(),
            soname=None,
            exported_symbols=tuple(exp_syms.values()),
            imported_symbols=tuple(imp_syms.values()),
            reflection_descriptors=tuple(refl.values()),
            string_witnesses=tuple(wit.values()),
            entitlements=merged_ent,
            linux_capabilities=(),
            slice_entitlements=sorted_slice_ents,
            slice_has_entitlements_blob=sorted_slice_blobs,
            slice_der_only_entitlements=sorted_slice_der_only,
        )

    raise ValueError(f"Unsupported Mach-O header magic {magic4.hex()} in '{source_name}'.")


def parse_macho_file(
    path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_BINARY_BYTES,
) -> RecordedBinaryCapture:
    """Safely read a non-symlink Mach-O file and parse its headers, symbols, & entitlements."""
    resolved, raw = read_bounded_regular_bytes(
        path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    return parse_macho_bytes(raw, source_name=resolved.name)


__all__ = [
    "CSMAGIC_EMBEDDED_ENTITLEMENTS",
    "CSMAGIC_EMBEDDED_SIGNATURE",
    "MachoBinaryCapabilities",
    "is_macho_magic",
    "parse_macho_bytes",
    "parse_macho_file",
]
