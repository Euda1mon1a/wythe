"""Wave 4 (#78) tests: `wythe-plugin-binary` passive Zoom-3 Mach-O/ELF & `BIN-ENT-001` drift."""

from __future__ import annotations

import ast
import os
import random
import struct
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = REPO_ROOT / "plugins" / "wythe-plugin-binary"
PLUGIN_SRC = PLUGIN_DIR / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from app.adapters import plugin_registry
from app.adapters.plugin_registry import ENTRY_POINT_GROUP, discover_plugins
from app.db.session import get_session_factory
from app.main import initialize_database
from app.models import TargetProject
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    attach_zoom1_stratum_badges,
    build_node_stratum_drilldown,
)
from wythe_plugin_binary import (
    BINARY_INSPECTION_PLUGIN,
    CSMAGIC_EMBEDDED_ENTITLEMENTS,
    CSMAGIC_EMBEDDED_SIGNATURE,
    binary_inspection_scope,
    correlate_binary_companions,
    demangle_symbol_name,
    parse_elf_bytes,
    parse_macho_bytes,
    parse_recorded_fixture,
    parse_safe_entitlements_xml,
)

APPLE_CONTAINER_RUNTIME_ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.virtualization</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
</dict>
</plist>
"""

APPLE_CONTAINER_VMNET_ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.vm.networking</key>
    <true/>
</dict>
</plist>
"""


class _FakeDist:
    def __init__(self, version: str = "0.1.0") -> None:
        self.version = version


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, obj: object, version: str = "0.1.0") -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist(version)
        self._obj = obj

    def load(self) -> object:
        return self._obj


def _align8(b: bytes) -> bytes:
    rem = len(b) % 8
    return b if rem == 0 else b + b"\x00" * (8 - rem)


def _pad16(text: str) -> bytes:
    raw = text.encode("utf-8")[:16]
    return raw + b"\x00" * (16 - len(raw))


def _build_synthetic_macho64(
    *,
    cputype: int = 0x0100000C,
    entitlements_xml: str | None = APPLE_CONTAINER_RUNTIME_ENTITLEMENTS,
) -> bytes:
    """Construct a valid 64-bit Mach-O binary with dylibs, rpaths, Swift/ObjC reflection, & codesign."""
    # Section payloads
    type_name_cstr = b"ContainersService\x00"
    cstring_tail = (
        b"/api/v1/containers/{id}\x00"
        b"com.apple.container.apiserver\x00"
        b"CREATE TABLE container_leases (id TEXT PRIMARY KEY)\x00"
        b"/com.apple.container.build.v1.Builder/CreateBuild\x00"
        b"benign_version_0.1.0\x00"
    )
    cstring_data = _align8(type_name_cstr + cstring_tail)

    # NominalTypeDescriptor: Flags(4), Parent(4), Name(rel32 pointing back to type_name_cstr at offset 0)
    # Place descriptor right after cstring_data; __swift5_types holds rel32 to descriptor!
    desc_off_in_seg = len(cstring_data)
    name_rel = 0 - (desc_off_in_seg + 8)
    swift_nominal_desc = struct.pack("<IIiI", 0x00000050, 0, name_rel, 0)
    types_off_in_seg = desc_off_in_seg + len(swift_nominal_desc)
    swift5_types_data = struct.pack("<i", desc_off_in_seg - types_off_in_seg)
    swift5_proto_data = _align8(b"ContainerXPCServiceProtocol\x00")
    swift5_fieldmd_data = _align8(b"sandboxIdentifier\x00")

    objc_cls_data = _align8(b"VZVirtualMachineConfiguration\x00")
    objc_sel_data = _align8(b"startWithCompletionHandler:\x00")

    # Layout load commands first so exact file offsets are known
    def _dylib_cmd(cmd_id: int, path_s: str) -> bytes:
        p_bytes = path_s.encode("utf-8") + b"\x00"
        body = struct.pack("<IIIIII", cmd_id, 0, 24, 2, 0x00010200, 0x00010000) + p_bytes
        padded = _align8(body)
        return struct.pack("<II", cmd_id, len(padded)) + padded[8:]

    def _rpath_cmd(path_s: str) -> bytes:
        p_bytes = path_s.encode("utf-8") + b"\x00"
        body = struct.pack("<III", 0x8000001C, 0, 12) + p_bytes
        padded = _align8(body)
        return struct.pack("<II", 0x8000001C, len(padded)) + padded[8:]

    dylib_cmds = b"".join(
        [
            _dylib_cmd(0x0C, "@rpath/libContainerization.dylib"),
            _dylib_cmd(
                0x0C,
                "/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization",
            ),
            _dylib_cmd(0x80000018, "/usr/lib/libSystem.B.dylib"),
            _dylib_cmd(0x8000001F, "@loader_path/libContainerShim.dylib"),
            _rpath_cmd("@executable_path/../Frameworks"),
            _rpath_cmd("/usr/local/lib/container"),
        ]
    )

    text_seg_cmd_sz = 72 + 4 * 80
    data_seg_cmd_sz = 72 + 2 * 80
    symtab_cmd_sz = 24
    codesig_cmd_sz = 16 if entitlements_xml is not None else 0
    sizeofcmds = (
        len(dylib_cmds) + text_seg_cmd_sz + data_seg_cmd_sz + symtab_cmd_sz + codesig_cmd_sz
    )
    ncmds = 6 + 1 + 1 + 1 + (1 if entitlements_xml is not None else 0)

    seg_start = _align8(b"\x00" * (32 + sizeofcmds))
    foff_base = len(seg_start)
    vm_base = 0x100000000

    cstr_foff = foff_base
    desc_foff = cstr_foff + len(cstring_data)
    types_foff = desc_foff + len(swift_nominal_desc)
    proto_foff = types_foff + len(swift5_types_data)
    field_foff = proto_foff + len(swift5_proto_data)
    text_blob = (
        cstring_data
        + swift_nominal_desc
        + swift5_types_data
        + swift5_proto_data
        + swift5_fieldmd_data
    )
    text_blob = _align8(text_blob)

    data_foff = foff_base + len(text_blob)
    data_vm = vm_base + 0x10000
    cls_foff = data_foff
    sel_foff = cls_foff + len(objc_cls_data)
    data_blob = _align8(objc_cls_data + objc_sel_data)

    def _sec64(sect: str, seg: str, vm: int, sz: int, foff: int) -> bytes:
        return struct.pack(
            "<16s16sQQIIIIIIII",
            _pad16(sect),
            _pad16(seg),
            vm,
            sz,
            foff,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        )

    text_seg_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        text_seg_cmd_sz,
        _pad16("__TEXT"),
        vm_base,
        max(0x4000, len(text_blob)),
        foff_base,
        len(text_blob),
        5,
        5,
        4,
        0,
    ) + b"".join(
        [
            _sec64("__cstring", "__TEXT", vm_base + (cstr_foff - foff_base), len(cstring_data), cstr_foff),
            _sec64("__swift5_types", "__TEXT", vm_base + (types_foff - foff_base), len(swift5_types_data), types_foff),
            _sec64("__swift5_proto", "__TEXT", vm_base + (proto_foff - foff_base), len(swift5_proto_data), proto_foff),
            _sec64("__swift5_fieldmd", "__TEXT", vm_base + (field_foff - foff_base), len(swift5_fieldmd_data), field_foff),
        ]
    )

    data_seg_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        data_seg_cmd_sz,
        _pad16("__DATA_CONST"),
        data_vm,
        max(0x4000, len(data_blob)),
        data_foff,
        len(data_blob),
        3,
        3,
        2,
        0,
    ) + b"".join(
        [
            _sec64("__objc_classlist", "__DATA_CONST", data_vm, len(objc_cls_data), cls_foff),
            _sec64("__objc_selrefs", "__DATA_CONST", data_vm + len(objc_cls_data), len(objc_sel_data), sel_foff),
        ]
    )

    sym_specs = [
        ("_$s21ContainerRuntimeLinux17ContainersServiceC5startyyKF", 0x0F, 1, 0, vm_base + 0x100),
        ("_audit_token_to_pid", 0x0F, 1, 0, vm_base + 0x200),
        ("_$s21ContainerRuntimeLinux17ContainersServiceCAA8RunnableA2aDP5startyyKFTWo", 0x0F, 1, 0, vm_base + 0x300),
        ("_swift_retain", 0x01, 0, 0x0100, 0),
        ("_objc_release", 0x01, 0, 0x0300, 0),
        ("_$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_SSAHSus6UInt32VtF", 0x01, 0, 0x0100, 0),
    ]
    strtab = bytearray(b"\x00")
    nlist_bytes = bytearray()
    for s_name, n_type, n_sect, n_desc, n_val in sym_specs:
        s_idx = len(strtab)
        strtab.extend(s_name.encode("utf-8") + b"\x00")
        nlist_bytes.extend(struct.pack("<IBBHQ", s_idx, n_type, n_sect, n_desc, n_val))
    strtab_padded = _align8(bytes(strtab))

    symoff = data_foff + len(data_blob)
    stroff = symoff + len(nlist_bytes)
    symtab_cmd = struct.pack(
        "<IIIIII", 0x02, symtab_cmd_sz, symoff, len(sym_specs), stroff, len(strtab_padded)
    )

    sig_blob = b""
    codesig_cmd = b""
    if entitlements_xml is not None:
        ent_raw = entitlements_xml.encode("utf-8")
        ent_blob = struct.pack(">II", CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(ent_raw)) + ent_raw
        super_len = 12 + 8 + len(ent_blob)
        sig_blob = (
            struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, super_len, 1)
            + struct.pack(">II", 5, 20)
            + ent_blob
        )
        sig_off = stroff + len(strtab_padded)
        codesig_cmd = struct.pack("<IIII", 0x1D, 16, sig_off, len(sig_blob))

    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, cputype, 0, 2, ncmds, sizeofcmds, 0x200085, 0
    )
    cmds_all = dylib_cmds + text_seg_cmd + data_seg_cmd + symtab_cmd + codesig_cmd
    pad_after_cmds = b"\x00" * (foff_base - 32 - len(cmds_all))
    return (
        header
        + cmds_all
        + pad_after_cmds
        + text_blob
        + data_blob
        + bytes(nlist_bytes)
        + strtab_padded
        + sig_blob
    )


def _build_synthetic_fat_macho(
    entitlements_xml: str | None = APPLE_CONTAINER_RUNTIME_ENTITLEMENTS,
) -> bytes:
    arm_slice = _align8(_build_synthetic_macho64(cputype=0x0100000C, entitlements_xml=entitlements_xml))
    x86_slice = _align8(_build_synthetic_macho64(cputype=0x01000007, entitlements_xml=entitlements_xml))
    off_arm = 64
    off_x86 = off_arm + len(arm_slice)
    fat_hdr = (
        struct.pack(">II", 0xCAFEBABE, 2)
        + struct.pack(">iiIII", 0x0100000C, 0, off_arm, len(arm_slice), 3)
        + struct.pack(">iiIII", 0x01000007, 3, off_x86, len(x86_slice), 3)
    )
    pad = b"\x00" * (off_arm - len(fat_hdr))
    return fat_hdr + pad + arm_slice + x86_slice


def _build_synthetic_elf64(*, cap_bits: tuple[int, ...] = (12, 18)) -> bytes:
    """Construct a valid 64-bit Linux ELF with `.dynamic`, `.dynsym`, `.rodata`, and `SHT_NOTE`."""
    sh_names = [
        "",
        ".shstrtab",
        ".dynstr",
        ".dynamic",
        ".dynsym",
        ".rodata",
        ".note.linux.capabilities",
    ]
    shstrtab = bytearray()
    sh_name_offs: list[int] = []
    for sn in sh_names:
        sh_name_offs.append(len(shstrtab))
        shstrtab.extend(sn.encode("utf-8") + b"\x00")
    shstrtab_b = _align8(bytes(shstrtab))

    dynstr = bytearray(b"\x00")

    def _add_dstr(s: str) -> int:
        idx = len(dynstr)
        dynstr.extend(s.encode("utf-8") + b"\x00")
        return idx

    off_need1 = _add_dstr("libseccomp.so.2")
    off_need2 = _add_dstr("libc.so.6")
    off_runp = _add_dstr("$ORIGIN/../lib:/usr/lib/container")
    off_rpath = _add_dstr("/opt/container/lib")
    off_soname = _add_dstr("container-init-linux")
    off_sym_rust = _add_dstr("_RNvNtCs42_15container_agent5vsock5serve")
    off_sym_cpp = _add_dstr("_ZN19operations_research3sat8CpSolver5SolveEv")
    off_sym_std = _add_dstr("_ZNSt3__112basic_stringIcEC1Ev")
    off_sym_core = _add_dstr("_RNvNtCs11_4core3fmt5write")
    off_sym_imp = _add_dstr("seccomp_init@@LIBSECCOMP_2.5")
    dynstr_b = _align8(bytes(dynstr))

    dyn_entries = [
        (1, off_need1),
        (1, off_need2),
        (29, off_runp),
        (15, off_rpath),
        (14, off_soname),
        (0, 0),
    ]
    dynamic_b = b"".join(struct.pack("<qQ", t, v) for t, v in dyn_entries)

    # Elf64_Sym: st_name(I), st_info(B), st_other(B), st_shndx(H), st_value(Q), st_size(Q)
    syms = [
        (0, 0, 0, 0, 0, 0),
        (off_sym_rust, (1 << 4) | 2, 0, 5, 0x1000, 64),
        (off_sym_cpp, (1 << 4) | 2, 0, 5, 0x1040, 64),
        (off_sym_std, (1 << 4) | 2, 0, 5, 0x1080, 32),
        (off_sym_core, (1 << 4) | 2, 0, 5, 0x10A0, 32),
        (off_sym_imp, (1 << 4) | 2, 0, 0, 0, 0),
    ]
    dynsym_b = b"".join(struct.pack("<IBBHQQ", *sm) for sm in syms)

    rodata_b = _align8(
        b"/com.apple.containerization.sandbox.v1.SandboxContext/Create\x00"
        b"/v1/sandbox/health\x00"
        b"SELECT lease_id FROM sandbox_state\x00"
        b"plain_label\x00"
    )

    mask = 0
    for bit in cap_bits:
        mask |= 1 << bit
    vfs_cap = struct.pack(
        "<IIIII",
        0x02000001,
        mask & 0xFFFFFFFF,
        0,
        (mask >> 32) & 0xFFFFFFFF,
        0,
    )
    note_name = b"security.capability\x00"
    aligned_note_name = note_name + b"\x00" * ((4 - (len(note_name) % 4)) % 4)
    note_b = _align8(
        struct.pack("<III", len(note_name), len(vfs_cap), 1) + aligned_note_name + vfs_cap
    )

    data_off = 64
    sec_blobs = [b"", shstrtab_b, dynstr_b, dynamic_b, dynsym_b, rodata_b, note_b]
    sec_offs: list[int] = []
    cur = data_off
    for bl in sec_blobs:
        sec_offs.append(cur if bl else 0)
        cur += len(bl)
    e_shoff = cur

    def _shdr(
        name_o: int,
        sh_t: int,
        foff: int,
        sz: int,
        link: int = 0,
        entsz: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name_o, sh_t, 0, 0, foff, sz, link, 0, 8, entsz
        )

    shdrs = b"".join(
        [
            _shdr(sh_name_offs[0], 0, 0, 0),
            _shdr(sh_name_offs[1], 3, sec_offs[1], len(shstrtab_b)),
            _shdr(sh_name_offs[2], 3, sec_offs[2], len(dynstr_b)),
            _shdr(sh_name_offs[3], 6, sec_offs[3], len(dynamic_b), link=2, entsz=16),
            _shdr(sh_name_offs[4], 11, sec_offs[4], len(dynsym_b), link=2, entsz=24),
            _shdr(sh_name_offs[5], 1, sec_offs[5], len(rodata_b)),
            _shdr(sh_name_offs[6], 7, sec_offs[6], len(note_b)),
        ]
    )

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        62,
        1,
        0x1000,
        0,
        e_shoff,
        0,
        64,
        0,
        0,
        64,
        7,
        1,
    )
    return ehdr + b"".join(sec_blobs) + shdrs


def _build_container_service_repo(
    repo_dir: Path,
    *,
    runtime_entitlements: str = APPLE_CONTAINER_RUNTIME_ENTITLEMENTS,
    vmnet_entitlements: str = APPLE_CONTAINER_VMNET_ENTITLEMENTS,
) -> Path:
    (repo_dir / "backend" / "app" / "api").mkdir(parents=True, exist_ok=True)
    (repo_dir / "backend" / "app" / "services").mkdir(parents=True, exist_ok=True)
    (repo_dir / "signing").mkdir(parents=True, exist_ok=True)

    (repo_dir / "signing" / "container-runtime-linux.entitlements").write_text(
        runtime_entitlements, encoding="utf-8"
    )
    (repo_dir / "signing" / "container-network-vmnet.entitlements").write_text(
        vmnet_entitlements, encoding="utf-8"
    )
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE container_leases (id TEXT PRIMARY KEY, state TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "services" / "containers_service.py").write_text(
        "def audit_token_to_pid(db):\n"
        '    rows = db.execute("SELECT id, state FROM container_leases")\n'
        "    return list(rows)\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "api" / "containers.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.containers_service import audit_token_to_pid\n\n"
        "router = APIRouter()\n\n"
        '@router.get("/api/v1/containers")\n'
        "def list_containers(db):\n"
        "    return audit_token_to_pid(db)\n",
        encoding="utf-8",
    )
    return repo_dir


def _scan_repo(repo_dir: Path, *, slug: str, include_binary_plugin: bool = False) -> Any:
    initialize_database()
    factory = get_session_factory()
    local_mods = [str(PLUGIN_SRC / "wythe_plugin_binary" / "plugin.py")] if include_binary_plugin else None
    with factory() as session:
        target = TargetProject(
            slug=slug,
            name="Container Benchmark Repo",
            repo_path=str(repo_dir),
            backend_subdir="backend",
            frontend_subdir="",
            stack_profile_slug="python-services",
        )
        return run_target_scan(
            session,
            target,
            strict_gate=True,
            persist_snapshot=False,
            allow_local_plugins=include_binary_plugin,
            local_plugin_modules=local_mods,
        )


def test_plugin_packaging_discovery_and_static_non_execution_ast_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pyproject = tomllib.loads((PLUGIN_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    proj = pyproject["project"]
    assert proj["name"] == "wythe-plugin-binary"
    assert proj["authors"] == [{"name": "Euda1mon1a"}]
    assert proj["dependencies"] == []
    eps = proj["entry-points"]["wythe.plugins"]
    assert eps["binary"] == "wythe_plugin_binary.plugin:BINARY_INSPECTION_PLUGIN"

    forbidden_modules = {"subprocess", "pty", "ctypes"}
    py_files = sorted((PLUGIN_SRC / "wythe_plugin_binary").glob("*.py"))
    assert len(py_files) == 6
    for pf in py_files:
        src_text = pf.read_text(encoding="utf-8")
        assert "[^" not in src_text or not any(
            "\\" in chunk.split("]", 1)[0] for chunk in src_text.split("[^")[1:] if "]" in chunk
        ), f"Negated character class contains backslash in {pf.name}"
        tree = ast.parse(src_text, filename=str(pf))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden_modules
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_modules

    fake_ep = _FakeEntryPoint(
        "binary", "wythe_plugin_binary.plugin:BINARY_INSPECTION_PLUGIN", BINARY_INSPECTION_PLUGIN
    )
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda **_kw: [fake_ep],
    )
    specs = discover_plugins(include_builtins=False, include_entry_points=True)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.name == "binary"
    assert spec.kind == "stratum_inspector"
    assert spec.supported_zooms == (3,)
    assert [r.rule_code for r in spec.rules] == ["BIN-ENT-001"]
    assert "binary" in spec.companion_handlers
    meta = spec.to_metadata()
    assert meta["supported_zooms"] == [3]
    assert meta["rules"] == ["BIN-ENT-001"]


def test_synthetic_macho64_and_universal_fat_parser_and_demangling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _ban_exec(*_a: object, **_kw: object) -> None:
        raise AssertionError("Binary inspection must NEVER invoke subprocesses!")

    monkeypatch.setattr(subprocess, "run", _ban_exec)
    monkeypatch.setattr(subprocess, "Popen", _ban_exec)
    monkeypatch.setattr(os, "system", _ban_exec)

    raw_macho = _build_synthetic_macho64()
    cap = parse_macho_bytes(raw_macho, source_name="container-runtime-linux")
    assert cap.binary_format == "macho"
    assert cap.architectures == ("arm64",)
    assert cap.is_universal is False
    assert cap.rpaths == ("@executable_path/../Frameworks", "/usr/local/lib/container")

    lib_by_raw = {lb.raw_path: lb for lb in cap.linked_libraries}
    assert "@rpath/libContainerization.dylib" in lib_by_raw
    rpath_lib = lib_by_raw["@rpath/libContainerization.dylib"]
    assert rpath_lib.rpath_token == "@rpath"
    assert rpath_lib.resolved_rpath_candidates == (
        "@executable_path/../Frameworks/libContainerization.dylib",
        "/usr/local/lib/container/libContainerization.dylib",
    )
    assert lib_by_raw["/usr/lib/libSystem.B.dylib"].load_kind == "weak"
    assert lib_by_raw["@loader_path/libContainerShim.dylib"].load_kind == "reexport"
    assert lib_by_raw["@loader_path/libContainerShim.dylib"].rpath_token == "@loader_path"

    exp_demangled = {s.demangled_name for s in cap.exported_symbols}
    assert "ContainerRuntimeLinux.ContainersService.start" in exp_demangled
    assert "audit_token_to_pid" in exp_demangled
    assert any(d.startswith("protocol witness for ") for d in exp_demangled)

    imp_demangled = {s.demangled_name for s in cap.imported_symbols}
    assert "swift_retain" in imp_demangled
    assert "objc_release" in imp_demangled
    assert "Swift._assertionFailure" in imp_demangled

    refl_pairs = {(r.kind, r.name) for r in cap.reflection_descriptors}
    assert ("swift_type_descriptor", "ContainersService") in refl_pairs
    assert ("swift_protocol_conformance", "ContainerXPCServiceProtocol") in refl_pairs
    assert ("swift_field_metadata", "sandboxIdentifier") in refl_pairs
    assert ("objc_class", "VZVirtualMachineConfiguration") in refl_pairs
    assert ("objc_selector", "startWithCompletionHandler:") in refl_pairs

    wit_by_cat = {w.category: w for w in cap.string_witnesses}
    assert wit_by_cat["http_route"].value == "/api/v1/containers/{id}"
    assert wit_by_cat["xpc_mach_service"].value == "com.apple.container.apiserver"
    assert "CREATE TABLE container_leases" in wit_by_cat["sql_snippet"].value
    assert wit_by_cat["grpc_method"].value == "/com.apple.container.build.v1.Builder/CreateBuild"
    for w in cap.string_witnesses:
        assert w.kind == "binary_string_witness"
        assert w.verification == "unverified"

    assert cap.entitlements == {
        "com.apple.security.virtualization": True,
        "com.apple.security.network.client": True,
    }

    fat_cap = parse_macho_bytes(_build_synthetic_fat_macho(), source_name="container-runtime-linux")
    assert fat_cap.is_universal is True
    assert fat_cap.architectures == ("arm64", "x86_64")
    assert fat_cap.entitlements == cap.entitlements
    assert {r.name for r in fat_cap.reflection_descriptors} == {
        r.name for r in cap.reflection_descriptors
    }


def test_synthetic_elf64_dynamic_symbols_rodata_and_linux_capabilities(tmp_path: Path) -> None:
    elf_bytes = _build_synthetic_elf64(cap_bits=(12, 18))
    elf_cap = parse_elf_bytes(elf_bytes, source_name="container-init")
    assert elf_cap.binary_format == "elf"
    assert elf_cap.architectures == ("x86_64",)
    assert elf_cap.soname == "container-init-linux"
    assert [lb.raw_path for lb in elf_cap.linked_libraries] == ["libseccomp.so.2", "libc.so.6"]
    assert elf_cap.runpaths == ("$ORIGIN/../lib", "/usr/lib/container")
    assert elf_cap.rpaths == ("/opt/container/lib",)

    exp = {s.demangled_name for s in elf_cap.exported_symbols}
    assert "container_agent::vsock::serve" in exp
    assert "operations_research::sat::CpSolver::Solve" in exp
    assert "std::basic_string" in exp
    assert "core::fmt::write" in exp

    imp = {s.demangled_name for s in elf_cap.imported_symbols}
    assert "seccomp_init" in imp
    assert set(elf_cap.linux_capabilities) == {"CAP_NET_ADMIN", "CAP_SYS_CHROOT"}

    for w in elf_cap.string_witnesses:
        assert w.kind == "binary_string_witness"
        assert w.verification == "unverified"
    assert {w.category for w in elf_cap.string_witnesses} == {
        "grpc_method",
        "http_route",
        "sql_snippet",
    }

    # Verify unpacked ELF rootfs directory + sidecar `.capabilities` metadata
    rootfs = tmp_path / "unpacked_rootfs" / "usr" / "bin"
    rootfs.mkdir(parents=True)
    elf_file = rootfs / "container-init-linux"
    elf_file.write_bytes(_build_synthetic_elf64(cap_bits=()))
    (rootfs / "container-init-linux.capabilities").write_text(
        '{"capabilities": ["cap_net_bind_service"]}\n', encoding="utf-8"
    )
    repo = _build_container_service_repo(tmp_path / "elf_repo")
    rep = _scan_repo(repo, slug="elf-dir-scan")
    comp = correlate_binary_companions(repo, rep, binary_paths=[tmp_path / "unpacked_rootfs"])
    assert comp["artifact_count"] == 1
    assert comp["artifacts"][0]["linux_capabilities"] == ["CAP_NET_BIND_SERVICE"]
    assert comp["automated_security_audit"] is False


def test_recorded_passive_fixtures_apple_container_parity() -> None:
    otool_txt = (
        "/usr/local/libexec/container-runtime-linux:\n"
        "\t@rpath/libContainerXPC.dylib (compatibility version 1.0.0, current version 0.2.0)\n"
        "\t/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization "
        "(compatibility version 1.0.0, current version 214.0.0)\n"
        "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0, weak)\n"
    )
    dyld_txt = (
        "container-runtime-linux [arm64]:\n"
        "    -rpaths:\n"
        "        @executable_path/../Frameworks\n"
        "    -dependents:\n"
        "        attributes     load path\n"
        "                       @rpath/libContainerXPC.dylib\n"
        "        weak_import    /usr/lib/libSystem.B.dylib\n"
        "    -imports:\n"
        "        0x0001 _swift_retain (from libswiftCore)\n"
        "        0x0002 _objc_release (from libobjc)\n"
        "    -exports:\n"
        "        0x1040 _$s12ContainerXPC9XPCServerC6handle5routeySS_tF\n"
    )
    nm_txt = (
        "0000000100002100 T _audit_token_to_pid\n"
        "                 U _swift_retain\n"
        "                 U _objc_release\n"
    )
    codesign_txt = f"Executable=/usr/local/libexec/container-runtime-linux\n{APPLE_CONTAINER_RUNTIME_ENTITLEMENTS}"
    readelf_txt = (
        "Dynamic section at offset 0x2df0 contains 5 entries:\n"
        " 0x0000000000000001 (NEEDED)   Shared library: [libvsock.so.1]\n"
        " 0x000000000000001d (RUNPATH)  Library runpath: [$ORIGIN/../lib]\n"
        " 0x000000000000000e (SONAME)   Library soname: [libguest_agent.so]\n"
    )

    cap_otool = parse_recorded_fixture(otool_txt.encode("utf-8"), source_name="otool.txt")
    assert cap_otool.name == "container-runtime-linux"
    assert len(cap_otool.linked_libraries) == 3

    cap_dyld = parse_recorded_fixture(dyld_txt.encode("utf-8"), source_name="dyld.txt")
    assert cap_dyld.rpaths == ("@executable_path/../Frameworks",)
    assert {s.demangled_name for s in cap_dyld.exported_symbols} == {
        "ContainerXPC.XPCServer.handle"
    }
    assert {s.demangled_name for s in cap_dyld.imported_symbols} == {
        "swift_retain",
        "objc_release",
    }

    cap_nm = parse_recorded_fixture(nm_txt.encode("utf-8"), source_name="nm.txt")
    assert {s.demangled_name for s in cap_nm.exported_symbols} == {"audit_token_to_pid"}

    cap_cs = parse_recorded_fixture(codesign_txt.encode("utf-8"), source_name="codesign.xml")
    assert cap_cs.entitlements["com.apple.security.virtualization"] is True

    cap_elf = parse_recorded_fixture(readelf_txt.encode("utf-8"), source_name="readelf.txt")
    assert cap_elf.binary_format == "elf"
    assert cap_elf.soname == "libguest_agent.so"
    assert cap_elf.runpaths == ("$ORIGIN/../lib",)
    assert [l.raw_path for l in cap_elf.linked_libraries] == ["libvsock.so.1"]

    assert demangle_symbol_name("_RNvNtCs9_4core3mem4drop", is_macho=False).demangled_name == "core::mem::drop"
    assert demangle_symbol_name("_ZNSt3__16vectorIiEC1Ev", is_macho=True).demangled_name == "std::vector"


def test_zoom1_digest_invariance_zoom3_arc_compaction_and_unverified_string_witnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _build_container_service_repo(tmp_path / "z3_repo")
    bin_file = tmp_path / "container-runtime-linux"
    bin_file.write_bytes(_build_synthetic_macho64(entitlements_xml=APPLE_CONTAINER_RUNTIME_ENTITLEMENTS))

    baseline_report = _scan_repo(repo, slug="z3-base", include_binary_plugin=False)
    plugin_idle_report = _scan_repo(repo, slug="z3-idle", include_binary_plugin=True)
    assert plugin_idle_report.content_digest == baseline_report.content_digest
    assert [n.id for n in plugin_idle_report.nodes] == [n.id for n in baseline_report.nodes]
    assert [e.id for e in plugin_idle_report.edges] == [e.id for e in baseline_report.edges]

    # Verify active CLI `--binary` lookup via `plugin_registry.get_active_stratum_artifacts`
    monkeypatch.setattr(
        plugin_registry,
        "get_active_stratum_artifacts",
        lambda: {"binary": (str(bin_file),)},
        raising=False,
    )
    active_clean_report = _scan_repo(repo, slug="z3-active", include_binary_plugin=True)
    assert active_clean_report.content_digest == baseline_report.content_digest
    assert active_clean_report.gate.verdict == "PASS"

    svc_node = next(n for n in active_clean_report.nodes if "containers_service" in n.source_file)
    attach_zoom1_stratum_badges(repo, active_clean_report, plugins=[BINARY_INSPECTION_PLUGIN])
    assert active_clean_report.content_digest == baseline_report.content_digest
    svc_refreshed = next(n for n in active_clean_report.nodes if n.id == svc_node.id)
    badge_keys = {b.key for b in svc_refreshed.stratum_badges}
    assert {"binary_libs", "binary_symbols", "binary_reflection", "binary_witnesses"} <= badge_keys

    # Zoom 2 should not trigger Zoom-3-only binary inspector
    z2_drill = build_node_stratum_drilldown(
        repo, active_clean_report, svc_node.id, zoom=2, plugins=[BINARY_INSPECTION_PLUGIN]
    )
    assert z2_drill.nodes == []

    # Zoom 3 compacted (`unfiltered_ir=False`) folds ARC/stdlib/witness thunks
    z3_compacted = build_node_stratum_drilldown(
        repo,
        active_clean_report,
        svc_node.id,
        zoom=3,
        unfiltered_ir=False,
        plugins=[BINARY_INSPECTION_PLUGIN],
    )
    z3_unfiltered = build_node_stratum_drilldown(
        repo,
        active_clean_report,
        svc_node.id,
        zoom=3,
        unfiltered_ir=True,
        plugins=[BINARY_INSPECTION_PLUGIN],
    )
    assert z3_compacted.collapsed_thunk_count >= 4
    assert z3_compacted.compacted_node_count < z3_compacted.raw_node_count
    assert z3_unfiltered.collapsed_thunk_count == 0
    assert z3_unfiltered.compacted_node_count == z3_unfiltered.raw_node_count

    comp_labels = {n.label for n in z3_compacted.nodes}
    unfilt_labels = {n.label for n in z3_unfiltered.nodes}
    assert "swift_retain" not in comp_labels
    assert "objc_release" not in comp_labels
    assert "swift_retain" in unfilt_labels
    assert "objc_release" in unfilt_labels
    assert "audit_token_to_pid" in comp_labels
    assert "ContainersService" in comp_labels
    assert "VZVirtualMachineConfiguration" in comp_labels
    assert any(e.kind == "resolves_ffi_symbol" and e.verification == "verified" for e in z3_compacted.edges)
    assert any(e.kind == "collapsed_thunks" for e in z3_compacted.edges)

    # Epistemic invariant: every string witness node & edge stays strictly `unverified`
    witness_nodes = [n for n in z3_compacted.nodes if n.kind == "binary_string_witness"]
    assert len(witness_nodes) == 4
    for wn in witness_nodes:
        assert wn.verification == "unverified"
    witness_ids = {wn.id for wn in witness_nodes}
    for ed in z3_compacted.edges:
        if ed.target_id in witness_ids or ed.kind == "binary_string_witness":
            assert ed.verification == "unverified"
    assert active_clean_report.content_digest == baseline_report.content_digest


def test_bin_ent_001_privilege_drift_clean_match_omitted_warning_and_non_certification(
    tmp_path: Path,
) -> None:
    repo = _build_container_service_repo(tmp_path / "drift_repo")

    # 1. Clean `.app` bundle matching `signing/container-runtime-linux.entitlements`
    app_macos = tmp_path / "container-runtime-linux.app" / "Contents" / "MacOS"
    app_macos.mkdir(parents=True)
    (app_macos / "container-runtime-linux").write_bytes(
        _build_synthetic_macho64(entitlements_xml=APPLE_CONTAINER_RUNTIME_ENTITLEMENTS)
    )
    clean_rep = _scan_repo(repo, slug="drift-clean", include_binary_plugin=True)
    clean_comp = correlate_binary_companions(
        repo, clean_rep, binary_paths=[tmp_path / "container-runtime-linux.app"]
    )
    assert clean_comp["automated_security_audit"] is False
    assert clean_comp["target_code_executed"] is False
    assert clean_comp["privilege_drift_count"] == 0
    assert clean_comp["findings"] == []
    assert clean_comp["artifacts"][0]["drift_status"] == "clean"
    assert clean_comp["wall_ties"][0]["status"] == "intact"

    # 2. Undeclared privilege drift in `.xpc` bundle exceeding `container-network-vmnet.entitlements`
    escalated_vmnet_xml = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.vm.networking</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
</dict>
</plist>
"""
    xpc_macos = tmp_path / "container-network-vmnet.xpc" / "Contents" / "MacOS"
    xpc_macos.mkdir(parents=True)
    (xpc_macos / "container-network-vmnet").write_bytes(
        _build_synthetic_macho64(entitlements_xml=escalated_vmnet_xml)
    )

    with binary_inspection_scope(tmp_path / "container-network-vmnet.xpc"):
        drift_rep = _scan_repo(repo, slug="drift-fail", include_binary_plugin=True)
    bin_findings = [f for f in drift_rep.findings if f.rule_code == "BIN-ENT-001"]
    assert len(bin_findings) == 1
    assert bin_findings[0].severity == "blocking"
    assert bin_findings[0].blocks_gate is True
    assert drift_rep.gate.verdict == "FAIL"

    drift_comp = correlate_binary_companions(
        repo, drift_rep, binary_paths=[tmp_path / "container-network-vmnet.xpc"]
    )
    assert drift_comp["automated_security_audit"] is False
    assert drift_comp["privilege_drift_count"] == 1
    assert drift_comp["findings"][0]["rule_code"] == "BIN-ENT-001"
    assert drift_comp["findings"][0]["severity"] == "blocking"
    assert set(drift_comp["artifacts"][0]["undeclared_privileges"]) == {
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.device.camera",
    }
    assert drift_comp["wall_ties"][0]["status"] == "drift"
    assert drift_comp["wall_ties"][0]["rule_code"] == "BIN-ENT-001"

    # 3. Omitted capability emits warning note without blocking gate
    omitted_xml = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.security.virtualization</key>
    <true/>
</dict>
</plist>
"""
    omit_bin = tmp_path / "container-runtime-linux"
    omit_bin.write_bytes(_build_synthetic_macho64(entitlements_xml=omitted_xml))
    with binary_inspection_scope(omit_bin):
        omit_rep = _scan_repo(repo, slug="drift-omit", include_binary_plugin=True)
    assert [f for f in omit_rep.findings if f.rule_code == "BIN-ENT-001"] == []
    assert omit_rep.gate.verdict == "PASS"
    assert any("omits declared capability" in n for n in omit_rep.scan_notes)
    omit_comp = correlate_binary_companions(repo, omit_rep, binary_paths=[omit_bin])
    assert omit_comp["privilege_drift_count"] == 0
    assert omit_comp["omitted_capability_count"] == 1
    assert omit_comp["artifacts"][0]["omitted_capabilities"] == ["com.apple.security.network.client"]
    assert len(omit_comp["warnings"]) == 1


def test_xxe_entity_expansion_rejection_across_plists_and_embedded_codesign() -> None:
    xxe_payloads = [
        """<?xml version="1.0"?>
<!DOCTYPE plist [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<plist version="1.0"><dict><key>k</key><string>&xxe;</string></dict></plist>""",
        """<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" [
  <!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">
]>
<plist version="1.0"><dict><key>k</key><string>&lol2;</string></dict></plist>""",
        """<?xml version="1.0"?>
<!DOCTYPE plist SYSTEM "http://example.invalid/evil.dtd">
<plist version="1.0"><dict/></plist>""",
        """<?xml version="1.0"?>
<plist version="1.0"><dict><key>k</key><string>&customent;</string></dict></plist>""",
    ]
    for bad_xml in xxe_payloads:
        with pytest.raises(ValueError, match=r"(?i)XXE|DOCTYPE|ENTITY"):
            parse_safe_entitlements_xml(bad_xml)
        with pytest.raises(ValueError, match=r"(?i)XXE|DOCTYPE|ENTITY"):
            parse_recorded_fixture(bad_xml.encode("utf-8"), source_name="bad.codesign.xml")
        bad_macho = _build_synthetic_macho64(entitlements_xml=bad_xml)
        with pytest.raises(ValueError, match=r"(?i)XXE|DOCTYPE|ENTITY"):
            parse_macho_bytes(bad_macho, source_name="xxe-macho")


def test_truncated_and_corrupt_macho_and_elf_fuzz_inputs_fail_cleanly() -> None:
    valid_macho = _build_synthetic_macho64()
    valid_fat = _build_synthetic_fat_macho()
    valid_elf = _build_synthetic_elf64()

    t0 = time.perf_counter()
    # Deterministic truncations across headers, load commands, sections, and superblobs
    for cut in (0, 1, 4, 7, 16, 31, 32, 44, 80, 140, len(valid_macho) - 5):
        with pytest.raises(ValueError):
            parse_macho_bytes(valid_macho[:cut], source_name=f"trunc-macho-{cut}")
    for cut in (4, 8, 18, 28, 60, 96):
        with pytest.raises(ValueError):
            parse_macho_bytes(valid_fat[:cut], source_name=f"trunc-fat-{cut}")
    for cut in (0, 3, 4, 16, 63, 72, len(valid_elf) - 10):
        with pytest.raises(ValueError):
            parse_elf_bytes(valid_elf[:cut], source_name=f"trunc-elf-{cut}")

    # Crafted header count / offset bombs (`ncmds > 4096`, `e_shnum > 4096`, nested fat, bad note)
    ncmds_bomb = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 99999, 64, 0, 0) + b"\x00" * 64
    with pytest.raises(ValueError, match="ncmds"):
        parse_macho_bytes(ncmds_bomb)

    nested_fat = (
        struct.pack(">II", 0xCAFEBABE, 1)
        + struct.pack(">iiIII", 0x0100000C, 0, 32, 64, 3)
        + b"\x00" * 4
        + struct.pack(">II", 0xCAFEBABE, 1)
        + b"\x00" * 56
    )
    with pytest.raises(ValueError, match="Nested"):
        parse_macho_bytes(nested_fat)

    elf_shnum_bomb = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 9999, 0)
    )
    with pytest.raises(ValueError, match="e_shnum"):
        parse_elf_bytes(elf_shnum_bomb)

    # Seeded PRNG byte-corruption fuzzing (must never raise struct.error / IndexError / hang)
    rng = random.Random(20261116)
    for base_buf, parser_fn in ((valid_macho, parse_macho_bytes), (valid_elf, parse_elf_bytes)):
        for _ in range(40):
            mut = bytearray(base_buf)
            for _ in range(6):
                idx = rng.randrange(len(mut))
                mut[idx] = rng.randrange(256)
            try:
                parser_fn(bytes(mut))
            except ValueError:
                pass

    assert time.perf_counter() - t0 < 0.5


def test_symlink_rejection_on_every_path_component_and_bundle_interiors_plus_redos(
    tmp_path: Path,
) -> None:
    from wythe_plugin_binary.entitlement_drift import read_bounded_regular_bytes

    repo = _build_container_service_repo(tmp_path / "sym_repo")
    rep = _scan_repo(repo, slug="sym-scan")

    real_dir = repo / "build_out"
    real_dir.mkdir(parents=True)
    real_bin = real_dir / "container-runtime-linux"
    real_bin.write_bytes(_build_synthetic_macho64())

    # 1. Direct symlinked file
    sym_bin = repo / "sym-binary"
    sym_bin.symlink_to(real_bin)
    with pytest.raises(ValueError, match="(?i)symlink"):
        correlate_binary_companions(repo, rep, binary_paths=[sym_bin])

    # 2. Symlinked parent directory inside repo_root (relative, resolved, & `/var` vs `/private/var`)
    sym_parent = repo / "sym_dir"
    sym_parent.symlink_to(real_dir)
    with pytest.raises(ValueError, match="(?i)symlink"):
        correlate_binary_companions(repo, rep, binary_paths=["sym_dir/container-runtime-linux"])

    cand_repos = [repo]
    if str(repo).startswith("/private/var/"):
        var_alias = Path(str(repo).replace("/private/var/", "/var/", 1))
        if var_alias.exists():
            cand_repos.append(var_alias)
    for cand_r in cand_repos:
        for root_arg in (repo, repo.resolve()):
            with pytest.raises(ValueError, match="(?i)symlink"):
                correlate_binary_companions(
                    root_arg,
                    rep,
                    binary_paths=[cand_r / "sym_dir" / "container-runtime-linux"],
                )

    # 3. Symlinked external parent directory
    ext_real = tmp_path / "ext_real"
    ext_real.mkdir()
    (ext_real / "guest.elf").write_bytes(_build_synthetic_elf64())
    ext_sym = tmp_path / "ext_sym"
    ext_sym.symlink_to(ext_real)
    with pytest.raises(ValueError, match="(?i)symlink"):
        correlate_binary_companions(repo, rep, binary_paths=[ext_sym / "guest.elf"])

    # 4. Symlink inside `.app` / `.xpc` bundle interior (`Contents/MacOS/evil` -> real_bin)
    evil_app = tmp_path / "EvilHelper.app" / "Contents" / "MacOS"
    evil_app.mkdir(parents=True)
    (evil_app / "EvilHelper").symlink_to(real_bin)
    with pytest.raises(ValueError, match="(?i)symlink"):
        correlate_binary_companions(repo, rep, binary_paths=[tmp_path / "EvilHelper.app"])

    # 5. Bounded size ceiling check
    with pytest.raises(ValueError, match="exceeds"):
        read_bounded_regular_bytes(real_bin, max_bytes=32)

    # 6. ReDoS check on 64-backslash unterminated strings and 16 KB lines
    slashes = "\\" * 64
    long_line = "A" * 16_384
    t0 = time.perf_counter()
    with pytest.raises(ValueError):
        parse_recorded_fixture(
            f'{{"name": "{slashes}unterminated\n{long_line}'.encode(),
            source_name="unterminated.json",
        )
    otool_long = f"/bin/app:\n\t/usr/lib/libSystem.B.dylib (current version 1.0.0) {long_line}\n"
    parsed_long = parse_recorded_fixture(otool_long.encode("utf-8"), source_name="long.otool")
    assert len(parsed_long.linked_libraries) == 1
    assert time.perf_counter() - t0 < 0.1


def test_big_endian_stripped_phdr_elf_sandbox_weakening_and_symlinked_entitlements(
    tmp_path: Path,
) -> None:
    # 1. Big-endian MH_CIGAM_64 (`\xfe\xed\xfa\xcf`) & swapped FAT_CIGAM (`\xbe\xba\xfe\xca`)
    be_dylib_path = b"/usr/lib/libSystem.B.dylib\x00\x00\x00\x00\x00\x00"
    be_cmd = struct.pack(">IIIIII", 0x0C, 24 + len(be_dylib_path), 24, 2, 0x010000, 0x010000) + be_dylib_path
    be_macho = struct.pack(">IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(be_cmd), 0, 0) + be_cmd
    be_cap = parse_macho_bytes(be_macho, source_name="be-helper")
    assert be_cap.architectures == ("arm64",)
    assert [lb.raw_path for lb in be_cap.linked_libraries] == ["/usr/lib/libSystem.B.dylib"]

    le_fat = (
        struct.pack("<II", 0xCAFEBABE, 1)
        + struct.pack("<iiIII", 0x0100000C, 0, 32, len(be_macho), 3)
        + b"\x00" * 4
        + be_macho
    )
    fat_le_cap = parse_macho_bytes(le_fat, source_name="fat-cigam")
    assert fat_le_cap.is_universal is True
    assert [lb.raw_path for lb in fat_le_cap.linked_libraries] == ["/usr/lib/libSystem.B.dylib"]

    # 2. Sectionless stripped ELF64 (`e_shnum == 0`) with `PT_LOAD` + `PT_DYNAMIC` + `PT_NOTE`
    dynstr = _align8(b"\x00libcap.so.2\x00$ORIGIN/lib\x00")
    vaddr_base = 0x400000
    ehdr_sz = 64
    phdr_sz = 3 * 56
    payload_off = ehdr_sz + phdr_sz
    dynstr_va = vaddr_base + payload_off
    dyn_table = b"".join(
        [
            struct.pack("<qQ", 5, dynstr_va),
            struct.pack("<qQ", 10, len(dynstr)),
            struct.pack("<qQ", 1, 1),
            struct.pack("<qQ", 29, 13),
            struct.pack("<qQ", 0, 0),
        ]
    )
    vfs_sys_admin = struct.pack("<IIIII", 0x02000001, 1 << 21, 0, 0, 0)
    note_nm = b"security.capability\x00"
    note_blob = struct.pack("<III", len(note_nm), len(vfs_sys_admin), 1) + note_nm + vfs_sys_admin
    load_body = dynstr + dyn_table + note_blob
    dyn_off = payload_off + len(dynstr)
    note_off = dyn_off + len(dyn_table)

    phdrs = (
        struct.pack("<IIQQQQQQ", 1, 5, 0, vaddr_base, vaddr_base, payload_off + len(load_body), payload_off + len(load_body), 0x1000)
        + struct.pack("<IIQQQQQQ", 2, 4, dyn_off, vaddr_base + dyn_off, vaddr_base + dyn_off, len(dyn_table), len(dyn_table), 8)
        + struct.pack("<IIQQQQQQ", 4, 4, note_off, vaddr_base + note_off, vaddr_base + note_off, len(note_blob), len(note_blob), 4)
    )
    stripped_elf = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, vaddr_base, ehdr_sz, 0, 0, 64, 56, 3, 0, 0, 0)
        + phdrs
        + load_body
    )
    s_cap = parse_elf_bytes(stripped_elf, source_name="stripped-aarch64")
    assert s_cap.architectures == ("aarch64",)
    assert [lb.raw_path for lb in s_cap.linked_libraries] == ["libcap.so.2"]
    assert s_cap.runpaths == ("$ORIGIN/lib",)
    assert s_cap.linux_capabilities == ("CAP_SYS_ADMIN",)

    # 3. Sandbox weakening (`app-sandbox = true` in source vs `false` in signed Mach-O) -> BIN-ENT-001
    sb_src_xml = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>"""
    sb_bin_xml = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><false/></dict></plist>"""
    sb_repo = _build_container_service_repo(
        tmp_path / "sb_repo", runtime_entitlements=sb_src_xml
    )
    sb_bin = tmp_path / "container-runtime-linux"
    sb_bin.write_bytes(_build_synthetic_macho64(entitlements_xml=sb_bin_xml))
    sb_rep = _scan_repo(sb_repo, slug="sb-scan")
    sb_comp = correlate_binary_companions(sb_repo, sb_rep, binary_paths=[sb_bin])
    assert sb_comp["privilege_drift_count"] == 1
    assert "com.apple.security.app-sandbox=disabled" in sb_comp["artifacts"][0]["undeclared_privileges"]

    # 4. Undeclared ELF `CAP_SYS_ADMIN` -> BIN-ENT-001, and symlinked `.entitlements` rejected
    elf_priv = tmp_path / "stripped-aarch64"
    elf_priv.write_bytes(stripped_elf)
    elf_comp = correlate_binary_companions(sb_repo, sb_rep, binary_paths=[elf_priv])
    assert elf_comp["privilege_drift_count"] == 1
    assert elf_comp["findings"][0]["rule_code"] == "BIN-ENT-001"

    outside_ent = tmp_path / "outside.entitlements"
    outside_ent.write_text(sb_src_xml, encoding="utf-8")
    (sb_repo / "signing" / "sym.entitlements").symlink_to(outside_ent)
    with pytest.raises(ValueError, match="(?i)symlink"):
        correlate_binary_companions(sb_repo, sb_rep, binary_paths=[sb_bin])
