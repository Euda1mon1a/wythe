"""Passive recorded fixture parsers (`otool`, `dyld_info`, `nm`, `codesign`, `readelf`) & demangler."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from wythe_plugin_binary.entitlement_drift import (
    BinaryStringWitness,
    aggregate_slice_entitlements_conservatively,
    extract_binary_string_witnesses,
    parse_safe_entitlements_xml,
)

_MAX_JSON_DEPTH = 64
_MAX_FIXTURE_LINES = 65_536
_MAX_LINE_SCAN_CHARS = 4096


@dataclass(frozen=True)
class DemangledSymbol:
    """Normalized native binary symbol with language and boilerplate metadata."""

    raw_name: str
    demangled_name: str
    language: Literal["swift", "cpp", "rust", "objc", "c"]
    binding: Literal["exported", "imported"]
    version_tag: str = ""
    library_ordinal: int | None = None


@dataclass(frozen=True)
class LinkedLibraryRef:
    """Dynamic library edge extracted from Mach-O load commands or ELF `.dynamic`."""

    raw_path: str
    short_name: str
    load_kind: Literal["required", "weak", "reexport", "lazy"] = "required"
    rpath_token: str | None = None
    resolved_rpath_candidates: tuple[str, ...] = ()
    current_version: str | None = None
    compatibility_version: str | None = None


@dataclass(frozen=True)
class ReflectionDescriptor:
    """Swift or Objective-C static reflection metadata item."""

    section: str
    kind: Literal[
        "swift_type_descriptor",
        "swift_protocol_conformance",
        "swift_field_metadata",
        "objc_class",
        "objc_selector",
    ]
    name: str


@dataclass(frozen=True)
class RecordedBinaryCapture:
    """Unified passive binary representation shared by raw parsers and recorded fixtures."""

    name: str
    binary_format: Literal["macho", "elf"]
    source_kind: Literal["raw_binary", "recorded_fixture"]
    architectures: tuple[str, ...]
    is_universal: bool
    linked_libraries: tuple[LinkedLibraryRef, ...]
    rpaths: tuple[str, ...]
    runpaths: tuple[str, ...]
    soname: str | None
    exported_symbols: tuple[DemangledSymbol, ...]
    imported_symbols: tuple[DemangledSymbol, ...]
    reflection_descriptors: tuple[ReflectionDescriptor, ...]
    string_witnesses: tuple[BinaryStringWitness, ...]
    entitlements: dict[str, Any]
    linux_capabilities: tuple[str, ...]
    slice_entitlements: dict[str, dict[str, Any]] = field(default_factory=dict)
    slice_has_entitlements_blob: dict[str, bool] = field(default_factory=dict)


MachoBinaryCapabilities = RecordedBinaryCapture


def _read_len_ident(body: str, pos: int, *, allow_underscore_sep: bool = False) -> tuple[str | None, int]:
    n = len(body)
    if pos >= n or not body[pos].isdigit() or body[pos] == "0":
        return None, pos
    j = pos
    while j < n and j - pos < 4 and body[j].isdigit():
        j += 1
    seg_len = int(body[pos:j])
    if allow_underscore_sep and j < n and body[j] == "_" and j + 1 + seg_len <= n:
        j += 1
    if seg_len <= 0 or j + seg_len > n:
        return None, pos
    ident = body[j : j + seg_len]
    if not all(ch.isalnum() or ch in "_$" for ch in ident):
        return None, pos
    return ident, j + seg_len


def _demangle_swift_core(swift_core: str) -> str:
    body = swift_core[:512]
    is_stdlib = body.startswith("s") and len(body) > 1 and body[1].isdigit()
    scan = body[1:] if is_stdlib else body
    segs: list[str] = ["Swift"] if is_stdlib else []

    i = 0
    n = len(scan)
    if is_stdlib:
        fn_ident, _ = _read_len_ident(scan, 0)
        if fn_ident:
            segs.append(fn_ident)
    else:
        mod_ident, i = _read_len_ident(scan, 0)
        if mod_ident:
            segs.append(mod_ident)
            second_ident, i = _read_len_ident(scan, i)
            if second_ident:
                segs.append(second_ident)
                if i < n and scan[i] in "CVOP":
                    i += 1
                    if scan[i : i + 2] == "AA":
                        i += 2
                        proto_ident, i = _read_len_ident(scan, i)
                        if proto_ident:
                            segs.append(proto_ident)
                        while i < n and not (scan[i].isdigit() and scan[i] != "0"):
                            i += 1
                    member_ident, _ = _read_len_ident(scan, i)
                    if member_ident:
                        segs.append(member_ident)

    joined = ".".join(segs) if segs else f"Swift.{body[:32]}"
    if body.endswith(("TW", "TWo")) or "TWo" in body:
        return f"protocol witness for {joined}"
    if body.endswith(("TR", "Tr")):
        return f"reabstraction thunk for {joined}"
    return joined


def _demangle_rust_v0(rust_v0: str) -> str:
    body = rust_v0[:512]
    segs: list[str] = []
    i = 0
    n = len(body)
    while i < n and len(segs) < 12:
        ch = body[i]
        if ch in (".", "$"):
            break
        if ch == "s":
            us = body.find("_", i + 1, min(n, i + 18))
            if us != -1 and all(c.isalnum() for c in body[i + 1 : us]):
                i = us + 1
                continue
        if ch.isdigit() and ch != "0":
            ident, nxt = _read_len_ident(body, i, allow_underscore_sep=True)
            if ident is not None:
                segs.append(ident)
                i = nxt
                continue
        i += 1
    return "::".join(segs) if segs else body[:48]


def _is_rust_hash_tail(seg: str) -> bool:
    return len(seg) == 17 and seg[0] == "h" and all(c in "0123456789abcdefABCDEF" for c in seg[1:])


def _demangle_itanium_cpp(cpp_body: str, thunk_prefix: str) -> tuple[str, Literal["cpp", "rust"]] | None:
    s = cpp_body[:512]
    i = 0
    n = len(s)
    segs: list[str] = []
    if s.startswith("St3__1"):
        segs.append("std")
        i = 6
    elif s.startswith("St"):
        segs.append("std")
        i = 2

    while i < n and len(segs) < 12:
        while i < n and s[i] in "KVr":
            i += 1
        if i >= n or s[i] == "E" or s[i : i + 2] in ("C1", "C2", "C3", "D0", "D1", "D2"):
            break
        if s[i] == "I":
            depth = 1
            i += 1
            while i < n and depth > 0:
                if s[i] == "I":
                    depth += 1
                elif s[i] == "E":
                    depth -= 1
                i += 1
            continue
        if s[i].isdigit() and s[i] != "0":
            ident, nxt = _read_len_ident(s, i)
            if ident is None:
                break
            segs.append(ident)
            i = nxt
        else:
            break

    lang: Literal["cpp", "rust"] = "cpp"
    if segs and _is_rust_hash_tail(segs[-1]):
        segs = segs[:-1]
        lang = "rust"
    if not segs:
        return None
    return f"{thunk_prefix}{'::'.join(segs)}", lang


def demangle_symbol_name(
    raw_sym: str,
    *,
    binding: Literal["exported", "imported"] = "exported",
    is_macho: bool = True,
    library_ordinal: int | None = None,
) -> DemangledSymbol:
    """Demangle Swift (`_$s`), Itanium C++ (`_ZN`), Rust (`_RNv`), ObjC, and Mach-O C symbols."""
    trimmed = raw_sym.strip()[:512]
    base_sym, sep, ver_part = trimmed.partition("@")
    version_tag = ver_part.lstrip("@") if sep else ""
    work = base_sym

    if work.startswith(("-[", "+[")) and work.endswith("]"):
        return DemangledSymbol(
            raw_name=trimmed,
            demangled_name=work,
            language="objc",
            binding=binding,
            version_tag=version_tag,
            library_ordinal=library_ordinal,
        )

    if work.startswith(("_OBJC_CLASS_$_", "OBJC_CLASS_$_")):
        cls_name = work.split("$_", 1)[-1]
        return DemangledSymbol(
            raw_name=trimmed,
            demangled_name=cls_name or work,
            language="objc",
            binding=binding,
            version_tag=version_tag,
            library_ordinal=library_ordinal,
        )

    swift_core = ""
    if work.startswith(("_$s", "_$S")):
        swift_core = work[3:]
    elif work.startswith(("$s", "$S")):
        swift_core = work[2:]
    elif work.startswith("__T0"):
        swift_core = work[4:]
    elif work.startswith("_T0"):
        swift_core = work[3:]

    if swift_core:
        return DemangledSymbol(
            raw_name=trimmed,
            demangled_name=_demangle_swift_core(swift_core),
            language="swift",
            binding=binding,
            version_tag=version_tag,
            library_ordinal=library_ordinal,
        )

    rust_v0 = ""
    if work.startswith("__RNv"):
        rust_v0 = work[5:]
    elif work.startswith("_RNv"):
        rust_v0 = work[4:]
    if rust_v0:
        return DemangledSymbol(
            raw_name=trimmed,
            demangled_name=_demangle_rust_v0(rust_v0),
            language="rust",
            binding=binding,
            version_tag=version_tag,
            library_ordinal=library_ordinal,
        )

    cpp_body = ""
    thunk_prefix = ""
    for pfx, t_lbl in (
        ("__ZThn", "non-virtual thunk to "),
        ("_ZThn", "non-virtual thunk to "),
        ("__ZTv", "vtable thunk to "),
        ("_ZTv", "vtable thunk to "),
        ("__ZN", ""),
        ("_ZN", ""),
        ("__Z", ""),
        ("_Z", ""),
    ):
        if work.startswith(pfx) and len(work) > len(pfx):
            cpp_body = work[len(pfx) :]
            thunk_prefix = t_lbl
            break

    if cpp_body:
        cpp_res = _demangle_itanium_cpp(cpp_body, thunk_prefix)
        if cpp_res is not None:
            dem_cpp, cpp_lang = cpp_res
            return DemangledSymbol(
                raw_name=trimmed,
                demangled_name=dem_cpp,
                language=cpp_lang,
                binding=binding,
                version_tag=version_tag,
                library_ordinal=library_ordinal,
            )

    clean_c = work[1:] if is_macho and work.startswith("_") and not work.startswith("__") else work
    return DemangledSymbol(
        raw_name=trimmed,
        demangled_name=clean_c or trimmed,
        language="c",
        binding=binding,
        version_tag=version_tag,
        library_ordinal=library_ordinal,
    )


def build_linked_library_ref(
    raw_path: str,
    *,
    load_kind: Literal["required", "weak", "reexport", "lazy"] = "required",
    rpaths: tuple[str, ...] = (),
    current_version: str | None = None,
    compatibility_version: str | None = None,
) -> LinkedLibraryRef:
    """Build a `LinkedLibraryRef` and expand `@rpath` candidates against `LC_RPATH`."""
    clean = raw_path.strip()
    short = clean.rsplit("/", 1)[-1] or clean
    token: str | None = None
    for cand_tok in ("@rpath", "@executable_path", "@loader_path"):
        if clean == cand_tok or clean.startswith(f"{cand_tok}/"):
            token = cand_tok
            break
    resolved: list[str] = []
    if token == "@rpath":
        suffix = clean[len("@rpath") :].lstrip("/")
        for rp in rpaths:
            rp_clean = rp.rstrip("/")
            resolved.append(f"{rp_clean}/{suffix}" if suffix else rp_clean)
    return LinkedLibraryRef(
        raw_path=clean,
        short_name=short,
        load_kind=load_kind,
        rpath_token=token,
        resolved_rpath_candidates=tuple(dict.fromkeys(resolved)),
        current_version=current_version,
        compatibility_version=compatibility_version,
    )


def parse_otool_l_output(
    text: str,
    *,
    rpaths: tuple[str, ...] = (),
) -> tuple[str | None, list[LinkedLibraryRef]]:
    """Parse passive `otool -L` output into a binary header label and `LinkedLibraryRef` list."""
    header_target: str | None = None
    libs: list[LinkedLibraryRef] = []
    for raw_line in text.splitlines()[:_MAX_FIXTURE_LINES]:
        line = raw_line[:_MAX_LINE_SCAN_CHARS].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            header_target = stripped[:-1].strip().rsplit("/", 1)[-1] or stripped[:-1].strip()
            continue
        path_part, sep, paren_part = stripped.partition(" (")
        lib_path = path_part.strip()
        if not lib_path or lib_path.endswith(":"):
            continue
        compat_ver: str | None = None
        curr_ver: str | None = None
        kind: Literal["required", "weak", "reexport", "lazy"] = "required"
        if sep:
            meta = paren_part.rstrip(")")
            for piece in meta.split(","):
                p_clean = piece.strip().lower()
                if p_clean.startswith("compatibility version "):
                    compat_ver = piece.strip()[22:].strip()
                elif p_clean.startswith("current version "):
                    curr_ver = piece.strip()[16:].strip()
                elif "weak" in p_clean:
                    kind = "weak"
                elif "reexport" in p_clean or "re-export" in p_clean:
                    kind = "reexport"
                elif "lazy" in p_clean:
                    kind = "lazy"
        libs.append(
            build_linked_library_ref(
                lib_path,
                load_kind=kind,
                rpaths=rpaths,
                current_version=curr_ver,
                compatibility_version=compat_ver,
            )
        )
    return header_target, libs


def parse_dyld_info_output(
    text: str,
) -> tuple[list[LinkedLibraryRef], list[str], list[DemangledSymbol], list[DemangledSymbol]]:
    """Parse passive `xcrun dyld_info` (`-dependents`, `-rpaths`, `-imports`, `-exports`) text."""
    section = ""
    raw_libs: list[tuple[str, Literal["required", "weak", "reexport", "lazy"]]] = []
    rpaths: list[str] = []
    imports: list[DemangledSymbol] = []
    exports: list[DemangledSymbol] = []

    for raw_line in text.splitlines()[:_MAX_FIXTURE_LINES]:
        s = raw_line[:_MAX_LINE_SCAN_CHARS].strip()
        if not s:
            continue
        low = s.lower()
        if low.endswith("dependents:") or low == "dependents:":
            section = "dependents"
            continue
        if low.endswith("rpaths:") or low == "rpaths:":
            section = "rpaths"
            continue
        if low.endswith("imports:") or low == "imports:":
            section = "imports"
            continue
        if low.endswith("exports:") or low == "exports:":
            section = "exports"
            continue
        if low.startswith(("load-address", "attributes")):
            continue

        if section == "rpaths":
            cand = s.split()[-1]
            if cand.startswith(("@", "/")):
                rpaths.append(cand)
        elif section == "dependents":
            parts = s.split()
            path_tok = parts[-1]
            if path_tok.startswith(("@", "/")):
                attr = parts[0].lower() if len(parts) > 1 else ""
                lkind: Literal["required", "weak", "reexport", "lazy"] = "required"
                if "weak" in attr:
                    lkind = "weak"
                elif "re-export" in attr or "reexport" in attr:
                    lkind = "reexport"
                raw_libs.append((path_tok, lkind))
        elif section == "imports":
            sym_part, _, _ = s.partition(" (")
            tokens = sym_part.split()
            sym_tok = tokens[-1] if tokens else ""
            if sym_tok and not sym_tok.startswith("0x"):
                imports.append(demangle_symbol_name(sym_tok, binding="imported", is_macho=True))
        elif section == "exports":
            sym_part, _, _ = s.partition(" [")
            tokens = sym_part.split()
            sym_tok = tokens[-1] if tokens else ""
            if sym_tok and not sym_tok.startswith("0x"):
                exports.append(demangle_symbol_name(sym_tok, binding="exported", is_macho=True))

    rpath_tuple = tuple(dict.fromkeys(rpaths))
    libs = [build_linked_library_ref(p, load_kind=k, rpaths=rpath_tuple) for p, k in raw_libs]
    return libs, list(rpath_tuple), exports, imports


def parse_nm_output(
    text: str,
    *,
    is_macho: bool = True,
) -> tuple[list[DemangledSymbol], list[DemangledSymbol]]:
    """Parse passive `nm` / `nm -D` symbol table text into `(exported, imported)` lists."""
    exported: list[DemangledSymbol] = []
    imported: list[DemangledSymbol] = []
    for raw_line in text.splitlines()[:_MAX_FIXTURE_LINES]:
        s = raw_line[:_MAX_LINE_SCAN_CHARS].strip()
        if not s or s.endswith(":"):
            continue
        parts = s.split()
        if len(parts) >= 3 and len(parts[1]) == 1 and all(c in "0123456789abcdefABCDEF" for c in parts[0]):
            sym_type, sym_name = parts[1], parts[2]
        elif len(parts) >= 2 and len(parts[0]) == 1:
            sym_type, sym_name = parts[0], parts[1]
        else:
            continue
        if sym_type in ("U", "u", "w"):
            imported.append(demangle_symbol_name(sym_name, binding="imported", is_macho=is_macho))
        elif sym_type in ("T", "D", "R", "S", "B", "W", "V", "C"):
            exported.append(demangle_symbol_name(sym_name, binding="exported", is_macho=is_macho))
    return exported, imported


def parse_codesign_entitlements_output(raw: bytes | str) -> dict[str, Any]:
    """Parse `codesign -d --entitlements - --xml` output with strict XXE rejection."""
    return parse_safe_entitlements_xml(raw)


def parse_readelf_dynamic_output(
    text: str,
) -> tuple[list[LinkedLibraryRef], list[str], list[str], str | None, list[str]]:
    """Parse passive `readelf -d -W` output into `(needed_libs, rpaths, runpaths, soname, caps)`."""
    needed: list[LinkedLibraryRef] = []
    rpaths: list[str] = []
    runpaths: list[str] = []
    soname: str | None = None
    caps: list[str] = []

    for raw_line in text.splitlines()[:_MAX_FIXTURE_LINES]:
        s = raw_line[:_MAX_LINE_SCAN_CHARS].strip()
        if not s:
            continue
        lb = s.find("[")
        rb = s.rfind("]")
        bracket_val = s[lb + 1 : rb].strip() if 0 <= lb < rb else ""
        upper = s.upper()
        if "(NEEDED)" in upper and bracket_val:
            needed.append(build_linked_library_ref(bracket_val, load_kind="required"))
        elif "(RUNPATH)" in upper and bracket_val:
            runpaths.extend(p.strip() for p in bracket_val.split(":") if p.strip())
        elif "(RPATH)" in upper and bracket_val:
            rpaths.extend(p.strip() for p in bracket_val.split(":") if p.strip())
        elif "(SONAME)" in upper and bracket_val:
            soname = bracket_val
        elif "CAP_" in upper:
            for tok in re.findall(r"\bCAP_[A-Z0-9_]+\b", upper):
                if tok not in caps:
                    caps.append(tok)
    return needed, rpaths, runpaths, soname, caps


def _check_json_depth(root: Any, max_depth: int = _MAX_JSON_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        cur, d = stack.pop()
        if d > max_depth:
            raise ValueError(f"Recorded JSON fixture exceeds max nesting depth ({max_depth}).")
        if isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))


def _dedupe_libs(libs: list[LinkedLibraryRef], rpaths: tuple[str, ...]) -> tuple[LinkedLibraryRef, ...]:
    by_path: dict[str, LinkedLibraryRef] = {}
    for lib in libs:
        rebuilt = (
            build_linked_library_ref(
                lib.raw_path,
                load_kind=lib.load_kind,
                rpaths=rpaths,
                current_version=lib.current_version,
                compatibility_version=lib.compatibility_version,
            )
            if rpaths and lib.rpath_token == "@rpath" and not lib.resolved_rpath_candidates
            else lib
        )
        by_path.setdefault(rebuilt.raw_path, rebuilt)
    return tuple(by_path.values())


def _dedupe_syms(syms: list[DemangledSymbol]) -> tuple[DemangledSymbol, ...]:
    seen: dict[tuple[str, str], DemangledSymbol] = {}
    for sym in syms:
        seen.setdefault((sym.raw_name, sym.binding), sym)
    return tuple(seen.values())


def parse_recorded_fixture(
    raw_bytes: bytes,
    *,
    source_name: str = "recorded-fixture",
) -> RecordedBinaryCapture:
    """Parse a JSON or plain-text recorded passive binary capture (`otool`/`dyld_info`/`nm`/`codesign`/`readelf`)."""
    text = raw_bytes.decode("utf-8-sig")
    stripped = text.lstrip()

    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"Invalid recorded JSON binary fixture '{source_name}': {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("Recorded JSON binary fixture root must be an object.")
        _check_json_depth(payload)

        fmt_raw = str(payload.get("format") or "macho").strip().lower()
        fmt: Literal["macho", "elf"] = "elf" if fmt_raw == "elf" else "macho"
        is_macho = fmt == "macho"
        name = str(payload.get("name") or source_name)
        arches_raw = payload.get("architectures")
        arches = (
            tuple(str(a) for a in arches_raw if str(a).strip())
            if isinstance(arches_raw, list) and arches_raw
            else (("arm64",) if is_macho else ("x86_64",))
        )

        libs: list[LinkedLibraryRef] = []
        rpaths: list[str] = [str(x) for x in (payload.get("rpaths") or []) if isinstance(x, str)]
        runpaths: list[str] = [str(x) for x in (payload.get("runpaths") or []) if isinstance(x, str)]
        exports: list[DemangledSymbol] = []
        imports: list[DemangledSymbol] = []
        caps: list[str] = [str(x) for x in (payload.get("linux_capabilities") or []) if isinstance(x, str)]
        soname: str | None = str(payload["soname"]) if isinstance(payload.get("soname"), str) else None

        if isinstance(payload.get("dyld_info"), str):
            d_libs, d_rp, d_exp, d_imp = parse_dyld_info_output(payload["dyld_info"])
            libs.extend(d_libs)
            rpaths.extend(d_rp)
            exports.extend(d_exp)
            imports.extend(d_imp)
        if isinstance(payload.get("otool_l"), str):
            hdr, o_libs = parse_otool_l_output(payload["otool_l"], rpaths=tuple(rpaths))
            if hdr and name == source_name:
                name = hdr
            libs.extend(o_libs)
        if isinstance(payload.get("readelf_d"), str):
            fmt = "elf"
            is_macho = False
            e_libs, e_rp, e_runp, e_so, e_caps = parse_readelf_dynamic_output(payload["readelf_d"])
            libs.extend(e_libs)
            rpaths.extend(e_rp)
            runpaths.extend(e_runp)
            soname = soname or e_so
            caps.extend(e_caps)
        if isinstance(payload.get("nm"), str):
            n_exp, n_imp = parse_nm_output(payload["nm"], is_macho=is_macho)
            exports.extend(n_exp)
            imports.extend(n_imp)

        ent_dict: dict[str, Any] = {}
        has_ent_blob = False
        if isinstance(payload.get("codesign_xml"), str):
            ent_dict = parse_codesign_entitlements_output(payload["codesign_xml"])
            has_ent_blob = bool(payload["codesign_xml"].strip())
        elif isinstance(payload.get("entitlements"), dict):
            ent_dict = {str(k): v for k, v in payload["entitlements"].items()}
            has_ent_blob = True

        slice_ent_map: dict[str, dict[str, Any]] = {}
        slice_blob_map: dict[str, bool] = {}
        raw_slice_ents = payload.get("slice_entitlements")
        if isinstance(raw_slice_ents, dict):
            for s_arch, s_val in sorted(raw_slice_ents.items()):
                arch_k = str(s_arch).strip()
                if not arch_k:
                    continue
                if s_val is None:
                    slice_ent_map[arch_k] = {}
                    slice_blob_map[arch_k] = False
                elif isinstance(s_val, dict):
                    slice_ent_map[arch_k] = {str(k): v for k, v in s_val.items()}
                    slice_blob_map[arch_k] = True
            if slice_ent_map:
                ent_dict = aggregate_slice_entitlements_conservatively(slice_ent_map)
        elif fmt == "macho":
            for arch_k in arches:
                slice_ent_map[arch_k] = dict(ent_dict)
                slice_blob_map[arch_k] = has_ent_blob

        refl_out: list[ReflectionDescriptor] = []
        if isinstance(payload.get("reflection"), list):
            for item in payload["reflection"]:
                if isinstance(item, dict) and item.get("name"):
                    rkind = str(item.get("kind") or "swift_type_descriptor")
                    if rkind in (
                        "swift_type_descriptor",
                        "swift_protocol_conformance",
                        "swift_field_metadata",
                        "objc_class",
                        "objc_selector",
                    ):
                        refl_out.append(
                            ReflectionDescriptor(
                                section=str(item.get("section") or "__TEXT,__swift5_types"),
                                kind=rkind,  # type: ignore[arg-type]
                                name=str(item["name"]),
                            )
                        )

        raw_strings = [str(s) for s in (payload.get("strings") or []) if isinstance(s, str)]
        witnesses = extract_binary_string_witnesses(
            raw_strings,
            section="__TEXT,__cstring" if is_macho else ".rodata",
        )
        rpath_t = tuple(dict.fromkeys(rpaths))
        return RecordedBinaryCapture(
            name=name,
            binary_format=fmt,
            source_kind="recorded_fixture",
            architectures=arches,
            is_universal=len(arches) > 1,
            linked_libraries=_dedupe_libs(libs, rpath_t),
            rpaths=rpath_t,
            runpaths=tuple(dict.fromkeys(runpaths)),
            soname=soname,
            exported_symbols=_dedupe_syms(exports),
            imported_symbols=_dedupe_syms(imports),
            reflection_descriptors=tuple(refl_out),
            string_witnesses=witnesses,
            entitlements=ent_dict,
            linux_capabilities=tuple(dict.fromkeys(caps)),
            slice_entitlements=slice_ent_map,
            slice_has_entitlements_blob=slice_blob_map,
        )

    if "<plist" in stripped or stripped.startswith(("<?xml", "Executable=")):
        ent_dict = parse_codesign_entitlements_output(raw_bytes)
        return RecordedBinaryCapture(
            name=source_name,
            binary_format="macho",
            source_kind="recorded_fixture",
            architectures=("arm64",),
            is_universal=False,
            linked_libraries=(),
            rpaths=(),
            runpaths=(),
            soname=None,
            exported_symbols=(),
            imported_symbols=(),
            reflection_descriptors=(),
            string_witnesses=(),
            entitlements=ent_dict,
            linux_capabilities=(),
            slice_entitlements={"arm64": dict(ent_dict)},
            slice_has_entitlements_blob={"arm64": True},
        )

    if "(NEEDED)" in text or "(RUNPATH)" in text or "Dynamic section at offset" in text:
        e_libs, e_rp, e_runp, e_so, e_caps = parse_readelf_dynamic_output(text)
        n_exp, n_imp = parse_nm_output(text, is_macho=False)
        return RecordedBinaryCapture(
            name=e_so or source_name,
            binary_format="elf",
            source_kind="recorded_fixture",
            architectures=("x86_64",),
            is_universal=False,
            linked_libraries=tuple(e_libs),
            rpaths=tuple(dict.fromkeys(e_rp)),
            runpaths=tuple(dict.fromkeys(e_runp)),
            soname=e_so,
            exported_symbols=_dedupe_syms(n_exp),
            imported_symbols=_dedupe_syms(n_imp),
            reflection_descriptors=(),
            string_witnesses=(),
            entitlements={},
            linux_capabilities=tuple(e_caps),
        )

    if any(h in text.lower() for h in ("dependents:", "rpaths:", "exports:", "imports:")):
        d_libs, d_rp, d_exp, d_imp = parse_dyld_info_output(text)
        return RecordedBinaryCapture(
            name=source_name,
            binary_format="macho",
            source_kind="recorded_fixture",
            architectures=("arm64",),
            is_universal=False,
            linked_libraries=tuple(d_libs),
            rpaths=tuple(dict.fromkeys(d_rp)),
            runpaths=(),
            soname=None,
            exported_symbols=_dedupe_syms(d_exp),
            imported_symbols=_dedupe_syms(d_imp),
            reflection_descriptors=(),
            string_witnesses=(),
            entitlements={},
            linux_capabilities=(),
        )

    if "compatibility version" in text or "current version" in text:
        hdr, o_libs = parse_otool_l_output(text)
        return RecordedBinaryCapture(
            name=hdr or source_name,
            binary_format="macho",
            source_kind="recorded_fixture",
            architectures=("arm64",),
            is_universal=False,
            linked_libraries=tuple(o_libs),
            rpaths=(),
            runpaths=(),
            soname=None,
            exported_symbols=(),
            imported_symbols=(),
            reflection_descriptors=(),
            string_witnesses=(),
            entitlements={},
            linux_capabilities=(),
        )

    n_exp, n_imp = parse_nm_output(text, is_macho=True)
    if n_exp or n_imp:
        return RecordedBinaryCapture(
            name=source_name,
            binary_format="macho",
            source_kind="recorded_fixture",
            architectures=("arm64",),
            is_universal=False,
            linked_libraries=(),
            rpaths=(),
            runpaths=(),
            soname=None,
            exported_symbols=_dedupe_syms(n_exp),
            imported_symbols=_dedupe_syms(n_imp),
            reflection_descriptors=(),
            string_witnesses=(),
            entitlements={},
            linux_capabilities=(),
        )

    raise ValueError(f"Unrecognized binary or recorded fixture format in '{source_name}'.")
