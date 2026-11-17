"""Pure-Python 64-bit Linux ELF static binary & capability parser (zero `ldd` / zero execution)."""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

from wythe_plugin_binary.entitlement_drift import (
    MAX_BINARY_BYTES,
    extract_binary_string_witnesses,
    read_bounded_regular_bytes,
)
from wythe_plugin_binary.recorded_fixtures import (
    DemangledSymbol,
    LinkedLibraryRef,
    RecordedBinaryCapture,
    build_linked_library_ref,
    demangle_symbol_name,
)

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_DYNSYM = 11

PT_LOAD = 1
PT_DYNAMIC = 2
PT_NOTE = 4

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29

MAX_ELF_SECTIONS = 4096
MAX_ELF_PHDRS = 4096
MAX_ELF_DYN_ENTRIES = 16_384
MAX_ELF_SYMBOLS = 262_144
MAX_RODATA_STRINGS = 4096

_ELF_MACHINES: dict[int, str] = {
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv64",
}

_LINUX_CAP_NAMES: dict[int, str] = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    10: "CAP_NET_BIND_SERVICE",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    21: "CAP_SYS_ADMIN",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    27: "CAP_MKNOD",
    31: "CAP_SETFCAP",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


def is_elf_magic(buf: bytes) -> bool:
    """Return True if `buf` begins with `\\x7fELF`."""
    return len(buf) >= 4 and buf[:4] == ELF_MAGIC


def _read_elf_cstring(strtab: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(strtab):
        raise ValueError("Out-of-bounds ELF string table offset.")
    end = min(len(strtab), offset + limit)
    nul = strtab.find(b"\x00", offset, end)
    chunk = strtab[offset:nul] if nul != -1 else strtab[offset:end]
    decoded = chunk.decode("utf-8", errors="replace")
    return "".join(ch for ch in decoded if ord(ch) >= 0x20 and ord(ch) != 0x7F)


def _extract_rodata_strings(sec_bytes: bytes, *, max_items: int = MAX_RODATA_STRINGS) -> list[str]:
    out: list[str] = []
    for part in sec_bytes.split(b"\x00"):
        if len(part) < 3 or len(part) > 512:
            continue
        try:
            s = part.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if all(0x20 <= ord(ch) <= 0x7E or ch == "\t" for ch in s):
            out.append(s)
            if len(out) >= max_items:
                break
    return out


def _decode_vfs_cap_bytes(raw: bytes) -> list[str]:
    caps: list[str] = []
    if len(raw) >= 20:
        magic_etc, perm0, _inh0, perm1, _inh1 = struct.unpack_from("<IIIII", raw, 0)
        rev = magic_etc & 0xFF000000
        if rev in (0x02000000, 0x03000000):
            mask = perm0 | (perm1 << 32)
            for bit in range(64):
                if mask & (1 << bit):
                    caps.append(_LINUX_CAP_NAMES.get(bit, f"CAP_BIT_{bit}"))
    elif len(raw) >= 12:
        magic_etc, perm0, _inh0 = struct.unpack_from("<III", raw, 0)
        if (magic_etc & 0xFF000000) == 0x01000000:
            for bit in range(32):
                if perm0 & (1 << bit):
                    caps.append(_LINUX_CAP_NAMES.get(bit, f"CAP_BIT_{bit}"))

    text = raw.decode("utf-8", errors="ignore")
    for m in re.findall(r"\bcap_[a-z0-9_]+\b", text.lower()):
        upper = m.upper()
        if upper not in caps:
            caps.append(upper)
    return caps


def _parse_elf_notes_for_capabilities(
    sec_bytes: bytes,
    endian: str,
    *,
    align: int = 4,
) -> list[str]:
    caps: list[str] = []
    pos = 0
    end = len(sec_bytes)
    align_8 = align == 8
    steps = 0
    while pos + 12 <= end and steps < 512:
        steps += 1
        namesz, descsz, ntype = struct.unpack_from(f"{endian}III", sec_bytes, pos)
        if steps > 1 and (namesz == 0 and descsz == 0 or namesz > 256):
            break
        aligned_name = (namesz + 3) & ~3
        desc_mask = 7 if (align_8 and ntype == 5) else 3
        aligned_desc = (descsz + desc_mask) & ~desc_mask
        payload_end = pos + 12 + aligned_name + descsz
        if payload_end > end or payload_end <= pos:
            if steps == 1:
                raise ValueError("Corrupt or truncated ELF SHT_NOTE descriptor.")
            break
        next_pos = pos + 12 + aligned_name + aligned_desc
        name_raw = sec_bytes[pos + 12 : pos + 12 + namesz].rstrip(b"\x00")
        desc_raw = sec_bytes[pos + 12 + aligned_name : payload_end]
        name_txt = name_raw.decode("utf-8", errors="ignore").lower()
        if "cap" in name_txt or "security" in name_txt or b"cap_" in desc_raw.lower():
            for c in _decode_vfs_cap_bytes(desc_raw):
                if c not in caps:
                    caps.append(c)
        pos = next_pos
    return caps


def parse_elf_bytes(
    buf: bytes,
    *,
    source_name: str = "elf-binary",
    extra_capabilities: list[str] | None = None,
) -> RecordedBinaryCapture:
    """Parse a 64-bit Linux ELF byte buffer into `RecordedBinaryCapture`."""
    if len(buf) > MAX_BINARY_BYTES:
        raise ValueError(f"ELF buffer ({len(buf)} bytes) exceeds {MAX_BINARY_BYTES}-byte limit.")
    if len(buf) < 64 or buf[:4] != ELF_MAGIC:
        raise ValueError(f"Truncated or invalid ELF64 header in '{source_name}'.")

    ei_class = buf[4]
    ei_data = buf[5]
    if ei_class != ELFCLASS64:
        raise ValueError(f"Unsupported ELF class {ei_class} in '{source_name}' (expected ELF64=2).")
    if ei_data == ELFDATA2LSB:
        endian = "<"
    elif ei_data == ELFDATA2MSB:
        endian = ">"
    else:
        raise ValueError(f"Invalid ELF data encoding {ei_data} in '{source_name}'.")

    (
        _e_type,
        e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from(f"{endian}HHIQQQIHHHHHH", buf, 16)

    if e_shnum > MAX_ELF_SECTIONS:
        raise ValueError(f"ELF e_shnum ({e_shnum}) exceeds cap ({MAX_ELF_SECTIONS}).")
    if e_phnum > MAX_ELF_PHDRS:
        raise ValueError(f"ELF e_phnum ({e_phnum}) exceeds cap ({MAX_ELF_PHDRS}).")

    phdrs: list[tuple[int, int, int, int, int]] = []
    if e_phnum > 0:
        if e_phentsize < 56 or e_phentsize > 256 or e_phoff + e_phnum * e_phentsize > len(buf):
            raise ValueError("Out-of-bounds ELF64 program header table.")
        for p_idx in range(e_phnum):
            p_pos = e_phoff + p_idx * e_phentsize
            p_type, _p_flags, p_off, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = (
                struct.unpack_from(f"{endian}IIQQQQQQ", buf, p_pos)
            )
            if p_filesz > 0 and p_off + p_filesz > len(buf):
                raise ValueError(f"Out-of-bounds ELF64 program header #{p_idx} file range.")
            phdrs.append((p_type, p_off, p_vaddr, p_filesz, p_memsz))

    shdrs: list[tuple[int, int, int, int, int, int, int, int]] = []
    if e_shnum > 0:
        if e_shentsize < 64 or e_shentsize > 256 or e_shoff + e_shnum * e_shentsize > len(buf):
            raise ValueError("Out-of-bounds ELF64 section header table.")
        if e_shstrndx >= e_shnum and e_shstrndx != 0:
            raise ValueError("Out-of-bounds ELF64 e_shstrndx.")
        for s_idx in range(e_shnum):
            s_pos = e_shoff + s_idx * e_shentsize
            (
                sh_name,
                sh_type,
                _sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                _sh_info,
                sh_align,
                sh_entsize,
            ) = struct.unpack_from(f"{endian}IIQQQQIIQQ", buf, s_pos)
            if sh_type != SHT_NOBITS and sh_size > 0 and sh_offset + sh_size > len(buf):
                raise ValueError(f"Out-of-bounds ELF64 section #{s_idx} offset/size.")
            shdrs.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize, sh_align))

    shstrtab = b""
    if shdrs and 0 <= e_shstrndx < len(shdrs):
        _, st_t, _, st_off, st_sz, _, _, _ = shdrs[e_shstrndx]
        if st_t != SHT_NOBITS and st_sz > 0:
            shstrtab = buf[st_off : st_off + st_sz]

    sec_names: list[str] = []
    for sh_name, *_rest in shdrs:
        if shstrtab and 0 <= sh_name < len(shstrtab):
            sec_names.append(_read_elf_cstring(shstrtab, sh_name, 256))
        else:
            sec_names.append("")

    needed_libs: list[LinkedLibraryRef] = []
    rpaths: list[str] = []
    runpaths: list[str] = []
    soname: str | None = None
    exported_syms: list[DemangledSymbol] = []
    imported_syms: list[DemangledSymbol] = []
    rodata_strings: list[str] = []
    caps: list[str] = list(extra_capabilities or [])

    def _parse_dyn_bytes(dyn_bytes: bytes, dynstr: bytes) -> None:
        nonlocal soname
        n_ent = min(len(dyn_bytes) // 16, MAX_ELF_DYN_ENTRIES)
        for d_idx in range(n_ent):
            d_tag, d_val = struct.unpack_from(f"{endian}qQ", dyn_bytes, d_idx * 16)
            if d_tag == DT_NULL:
                break
            if not dynstr:
                continue
            if d_tag == DT_NEEDED:
                lib_s = _read_elf_cstring(dynstr, d_val)
                if lib_s:
                    needed_libs.append(build_linked_library_ref(lib_s, load_kind="required"))
            elif d_tag == DT_RPATH:
                rp_s = _read_elf_cstring(dynstr, d_val)
                rpaths.extend(p.strip() for p in rp_s.split(":") if p.strip())
            elif d_tag == DT_RUNPATH:
                runp_s = _read_elf_cstring(dynstr, d_val)
                runpaths.extend(p.strip() for p in runp_s.split(":") if p.strip())
            elif d_tag == DT_SONAME:
                so_s = _read_elf_cstring(dynstr, d_val)
                if so_s:
                    soname = so_s

    parsed_dyn = False
    for idx, (_sh_n, sh_type, _sh_a, sh_off, sh_sz, sh_link, sh_entsz, sh_align) in enumerate(shdrs):
        if sh_type == SHT_NOBITS or sh_sz == 0:
            continue
        sec_data = buf[sh_off : sh_off + sh_sz]
        sname = sec_names[idx]

        if sh_type == SHT_DYNAMIC:
            dynstr = b""
            if 0 <= sh_link < len(shdrs):
                _, lk_t, _, lk_off, lk_sz, _, _, _ = shdrs[sh_link]
                if lk_t != SHT_NOBITS and lk_sz > 0:
                    dynstr = buf[lk_off : lk_off + lk_sz]
            _parse_dyn_bytes(sec_data, dynstr)
            parsed_dyn = True

        elif sh_type in (SHT_DYNSYM, SHT_SYMTAB):
            ent_sz = max(sh_entsz, 24)
            n_syms = sh_sz // ent_sz
            if n_syms > MAX_ELF_SYMBOLS:
                raise ValueError(f"ELF symbol count ({n_syms}) exceeds cap ({MAX_ELF_SYMBOLS}).")
            if not (0 <= sh_link < len(shdrs)):
                raise ValueError("Out-of-bounds ELF symbol table sh_link.")
            _, lk_t, _, lk_off, lk_sz, _, _, _ = shdrs[sh_link]
            strtab = buf[lk_off : lk_off + lk_sz] if lk_t != SHT_NOBITS and lk_sz > 0 else b""
            for sym_i in range(1, n_syms):
                st_name, st_info, _st_other, st_shndx, _st_val, _st_sz = struct.unpack_from(
                    f"{endian}IBBHQQ", sec_data, sym_i * ent_sz
                )
                if st_name == 0 or not strtab:
                    continue
                if st_name >= len(strtab):
                    raise ValueError("Out-of-bounds ELF symbol st_name index.")
                st_bind = st_info >> 4
                st_type = st_info & 0x0F
                if st_type in (3, 4):
                    continue
                sym_str = _read_elf_cstring(strtab, st_name)
                if not sym_str:
                    continue
                if st_shndx == 0:
                    imported_syms.append(
                        demangle_symbol_name(sym_str, binding="imported", is_macho=False)
                    )
                elif st_bind in (1, 2):
                    exported_syms.append(
                        demangle_symbol_name(sym_str, binding="exported", is_macho=False)
                    )

        elif sname == ".rodata" or sname.startswith(".rodata."):
            if len(rodata_strings) < MAX_RODATA_STRINGS:
                rodata_strings.extend(
                    _extract_rodata_strings(
                        sec_data, max_items=MAX_RODATA_STRINGS - len(rodata_strings)
                    )
                )

        elif sh_type == SHT_NOTE:
            for c in _parse_elf_notes_for_capabilities(sec_data, endian, align=sh_align):
                if c not in caps:
                    caps.append(c)

        elif sname in ("security.capability", ".capabilities", ".linux.capabilities"):
            for c in _decode_vfs_cap_bytes(sec_data):
                if c not in caps:
                    caps.append(c)

    if not parsed_dyn and phdrs:
        load_segs = [(p_off, p_vaddr, p_filesz) for p_t, p_off, p_vaddr, p_filesz, _ in phdrs if p_t == PT_LOAD]
        for p_t, p_off, _pv, p_filesz, _ in phdrs:
            if p_t == PT_DYNAMIC and p_filesz >= 16:
                dyn_b = buf[p_off : p_off + p_filesz]
                str_va = 0
                str_sz = 0
                for d_i in range(min(len(dyn_b) // 16, MAX_ELF_DYN_ENTRIES)):
                    dt, dv = struct.unpack_from(f"{endian}qQ", dyn_b, d_i * 16)
                    if dt == DT_NULL:
                        break
                    if dt == DT_STRTAB:
                        str_va = dv
                    elif dt == DT_STRSZ:
                        str_sz = dv
                dynstr_fb = b""
                if str_va and str_sz:
                    for l_off, l_va, l_fsz in load_segs:
                        if l_va <= str_va < l_va + l_fsz:
                            s_foff = l_off + (str_va - l_va)
                            if s_foff + str_sz <= len(buf):
                                dynstr_fb = buf[s_foff : s_foff + str_sz]
                            break
                _parse_dyn_bytes(dyn_b, dynstr_fb)

    for p_t, p_off, _pv, p_filesz, _ in phdrs:
        if p_t == PT_NOTE and p_filesz >= 12:
            for c in _parse_elf_notes_for_capabilities(buf[p_off : p_off + p_filesz], endian):
                if c not in caps:
                    caps.append(c)

    arch = _ELF_MACHINES.get(e_machine, f"machine_{e_machine}")
    witnesses = extract_binary_string_witnesses(rodata_strings, section=".rodata")
    return RecordedBinaryCapture(
        name=soname or source_name,
        binary_format="elf",
        source_kind="raw_binary",
        architectures=(arch,),
        is_universal=False,
        linked_libraries=tuple(dict.fromkeys(needed_libs)),
        rpaths=tuple(dict.fromkeys(rpaths)),
        runpaths=tuple(dict.fromkeys(runpaths)),
        soname=soname,
        exported_symbols=tuple(dict.fromkeys(exported_syms)),
        imported_symbols=tuple(dict.fromkeys(imported_syms)),
        reflection_descriptors=(),
        string_witnesses=witnesses,
        entitlements={},
        linux_capabilities=tuple(dict.fromkeys(caps)),
    )


def _read_sidecar_elf_capabilities(elf_path: Path, repo_root: Path | None) -> list[str]:
    caps: list[str] = []
    for suf in (".capabilities", ".xattr.json"):
        sidecar = elf_path.with_name(f"{elf_path.name}{suf}")
        if sidecar.is_symlink() or not sidecar.exists():
            continue
        _, raw_sc = read_bounded_regular_bytes(sidecar, repo_root=repo_root, max_bytes=65536)
        txt = raw_sc.decode("utf-8", errors="ignore").strip()
        if txt.startswith("{"):
            try:
                obj = json.loads(txt)
                if isinstance(obj, dict):
                    raw_hex = obj.get("security.capability")
                    if isinstance(raw_hex, str):
                        h = raw_hex.removeprefix("0x")
                        if len(h) >= 24 and all(c in "0123456789abcdefABCDEF" for c in h):
                            caps.extend(_decode_vfs_cap_bytes(bytes.fromhex(h)))
                    if isinstance(obj.get("capabilities"), list):
                        for item in obj["capabilities"]:
                            c_up = str(item).strip().upper()
                            if c_up:
                                caps.append(c_up if c_up.startswith("CAP_") else f"CAP_{c_up}")
            except ValueError:
                pass
        for c in _decode_vfs_cap_bytes(raw_sc):
            if c not in caps:
                caps.append(c)
    return list(dict.fromkeys(caps))


def parse_elf_file(
    path: Path | str,
    *,
    repo_root: Path | None = None,
    max_bytes: int = MAX_BINARY_BYTES,
) -> RecordedBinaryCapture:
    """Safely read a non-symlink ELF64 file and parse its dynamic linkage, symbols, & capabilities."""
    resolved, raw = read_bounded_regular_bytes(path, repo_root=repo_root, max_bytes=max_bytes)
    side_caps = _read_sidecar_elf_capabilities(resolved, repo_root)
    return parse_elf_bytes(raw, source_name=resolved.name, extra_capabilities=side_caps)
