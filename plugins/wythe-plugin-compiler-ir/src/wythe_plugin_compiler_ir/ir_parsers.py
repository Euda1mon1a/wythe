"""Read-only Swift SIL (`.sil`) and LLVM IR (`.ll`) parsers for Zoom-2 strata.

Extracts compiler-resolved call graphs, protocol-witness dispatches, vtable thunks,
Objective-C message/method shims, Rust/C++ mangled symbols, Python C-extension entrypoints,
and Swift/ObjC ARC runtime helpers with strictly linear O(N) line-bounded scanning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from wythe_plugin_compiler_ir.usr_index import (
    UsrIndexBundle,
    iter_safe_repo_files,
    normalize_repo_relpath,
    read_safe_text,
    validate_safe_path,
)

MAX_IR_LINE_CHARS: Final[int] = 4096

_QUOTED_STR_PAT: Final[str] = r'"(?:\\.|[^"\\])*"'
_SIL_LOC_RE: Final[re.Pattern[str]] = re.compile(
    r'\bloc\s+"((?:\\.|[^"\\])*)"\s*:\s*(\d+)\s*:\s*(\d+)'
)
_SIL_CLANG_ATTR_RE: Final[re.Pattern[str]] = re.compile(r"\[clang\s+([A-Za-z_][A-Za-z0-9_]*)\]")
_SIL_FN_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(%[A-Za-z0-9_]+)\s*=\s*(?:dynamic_|prev_dynamic_)?function_ref\s+@(\"(?:\\.|[^\"\\])*\"|[^\s:]+)"
)
_SIL_WITNESS_METHOD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(%[A-Za-z0-9_]+)\s*=\s*witness_method\s+[^#]{1,300}#([A-Za-z0-9_.!]+)"
)
_SIL_CLASS_METHOD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(%[A-Za-z0-9_]+)\s*=\s*(?:class_method|super_method|objc_method)\s+[^#]{1,300}#([A-Za-z0-9_.!]+)"
)
_SIL_APPLY_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:try_apply|begin_apply|partial_apply|apply)\b(?:\s*\[[^\]]{0,120}\])*\s*(%[A-Za-z0-9_]+|@(?:\"(?:\\.|[^\"\\])*\"|[^\s(<]+))(?:\s*<[^>\n]{1,240}>)?\s*\("
)
_SIL_WTABLE_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*sil_witness_table\b[^{]{0,400}\{\s*$"
)
_SIL_WTABLE_METHOD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*method\s+#([A-Za-z0-9_.!]+)\s*:\s*[^@]{0,240}@(\"(?:\\.|[^\"\\])*\"|[^\s}]+)"
)
_SIL_VTABLE_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*sil_vtable\b\s*(?:\[[^\]]{0,80}\]\s*)*([A-Za-z0-9_.]+)\s*\{\s*$"
)
_SIL_VTABLE_ENTRY_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*#([A-Za-z0-9_.!]+)\s*:\s*[^@]{0,240}@(\"(?:\\.|[^\"\\])*\"|[^\s}\[]+)(?:\s*\[([A-Za-z0-9_]+)\])?"
)

_LLVM_SRC_FILE_RE: Final[re.Pattern[str]] = re.compile(
    r'^\s*source_filename\s*=\s*"((?:\\.|[^"\\])*)"'
)
_LLVM_META_ID_RE: Final[re.Pattern[str]] = re.compile(r"^\s*!(\d+)\s*=\s*(?:distinct\s+)?!([A-Za-z]+)\((.*)\)\s*$")
_LLVM_DBG_TAG_RE: Final[re.Pattern[str]] = re.compile(r"!dbg\s+!(\d+)")
_LLVM_GLOBAL_SYM_RE: Final[re.Pattern[str]] = re.compile(
    r'@("(?:\\.|[^"\\])*"|[A-Za-z0-9_.$]+)\s*\('
)
_LLVM_CALL_INSTR_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^\s*(?:%[A-Za-z0-9_.]+\s*=\s*)?)(?:tail\s+|musttail\s+|notail\s+)?(call|invoke)\b(.*)$"
)
_LLVM_INDIRECT_REG_RE: Final[re.Pattern[str]] = re.compile(r"\s(%[A-Za-z0-9_.]+)\s*\(")
_HEX_ESC_RE: Final[re.Pattern[str]] = re.compile(r"\\([0-9A-Fa-f]{2})")


def _unquote_ir_ident(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]

    def _sub_hex(match: re.Match[str]) -> str:
        val = int(match.group(1), 16)
        return "" if val <= 0x01 else chr(val)

    s = _HEX_ESC_RE.sub(_sub_hex, s)
    return s.replace('\\"', '"').replace("\\\\", "\\").strip()


def _decode_length_segments(body: str, max_parts: int = 8) -> list[str]:
    parts: list[str] = []
    idx = 0
    n = len(body)
    while idx < n and len(parts) < max_parts:
        if not body[idx].isdigit():
            idx += 1
            continue
        j = idx
        while j < n and body[j].isdigit() and (j - idx) < 4:
            j += 1
        seg_len = int(body[idx:j])
        if seg_len <= 0 or j + seg_len > n:
            break
        parts.append(body[j : j + seg_len])
        idx = j + seg_len
    return parts


def demangle_symbol_label(sym: str, comment_hint: str = "") -> tuple[str, str]:
    """Return `(human_label, language)` for a mangled Swift/C++/Rust/ObjC/C/Python IR symbol."""
    clean = _unquote_ir_ident(sym)
    hint = comment_hint.strip()
    if clean.startswith(("-[", "+[")):
        return (hint or clean, "objc")
    if clean.startswith(("PyInit_", "_Py", "pyx_pw_", "pybind11_init_")):
        return (hint or clean, "python")
    if clean.startswith(("_RNv", "_ZN4core", "_ZN3std", "_ZN5alloc")):
        r_body = clean[3:] if clean.startswith("_ZN") else clean[4:]
        if r_body.startswith("Cs") and "_" in r_body[:24]:
            r_body = r_body.split("_", 1)[1]
        segs = _decode_length_segments(r_body)
        lbl = "::".join(segs) if segs else clean
        return (hint or lbl, "rust")
    if clean.startswith(("$s", "_$s", "$S", "_$S")):
        body = clean.lstrip("_")[2:]
        is_witness = clean.endswith("TW") or "TWo" in clean
        if hint:
            if is_witness and not hint.lower().startswith("protocol witness for "):
                return (f"protocol witness for {hint}", "swift")
            return (hint, "swift")
        segs = _decode_length_segments(body)
        readable = ".".join(segs) if segs else clean
        if is_witness:
            return (f"protocol witness for {readable}", "swift")
        return (readable, "swift")
    if clean.startswith(("_ZThn", "__ZThn", "_ZTv", "__ZTv")):
        stripped = clean.lstrip("_")
        prefix = "non-virtual thunk to " if stripped.startswith("ZThn") else "vtable thunk for "
        segs = _decode_length_segments(stripped[4:])
        readable = "::".join(segs) if segs else clean
        if hint and hint.lower().startswith(("non-virtual thunk", "vtable thunk")):
            return (hint, "cpp")
        return (f"{prefix}{hint or readable}", "cpp")
    if clean.startswith(("_Z", "__Z")):
        stripped = clean.lstrip("_")
        segs = _decode_length_segments(stripped[2:] if stripped.startswith("ZN") else stripped[1:])
        readable = "::".join(segs) if segs else clean
        return (hint or readable, "cpp")
    if clean.startswith(("swift_", "objc_")):
        return (clean, "swift" if clean.startswith("swift_") else "objc")
    return (hint or clean, "c")


def symbol_to_usr(sym: str, *, clang_name: str = "", language: str = "") -> str:
    """Derive a canonical Unified Symbol Resolution (`USR`) string for an IR symbol."""
    clean = _unquote_ir_ident(sym)
    if clang_name:
        return f"c:@F@{clang_name}"
    if clean.startswith(("$s", "_$s", "$S", "_$S")):
        return f"s:{clean.lstrip('_')[2:]}"
    if clean.startswith(("-[", "+[")) and " " in clean and clean.endswith("]"):
        is_inst = clean.startswith("-[")
        inner = clean[2:-1]
        cls_name, _, sel = inner.partition(" ")
        tag = "im" if is_inst else "cm"
        return f"c:objc(cs){cls_name.strip()}({tag}){sel.strip()}"
    if clean.startswith(("_Z", "__Z")):
        return f"c:@F@{clean.lstrip('_')}"
    if language == "rust" or clean.startswith("_RNv"):
        return f"rust:{clean}"
    if language == "python" or clean.startswith("PyInit_"):
        return f"py:{clean}"
    return f"c:@F@{clean}"


@dataclass(frozen=True)
class IrFunctionNode:
    """Normalized compiler IR function/thunk/helper symbol from SIL or LLVM IR."""

    symbol: str
    label: str
    usr: str
    language: str
    ir_format: str  # "sil" | "llvm_ir"
    source_file: str = ""
    line: int = 1
    is_defined: bool = True
    is_thunk_or_arc: bool = False


@dataclass(frozen=True)
class IrCallEdge:
    """Normalized compiler IR call, witness-table, vtable, or FFI edge."""

    caller_symbol: str
    caller_label: str
    caller_usr: str
    callee_symbol: str
    callee_label: str
    callee_usr: str
    kind: str  # "calls_ir" | "witness_dispatch" | "vtable_dispatch" | "ffi_call" | "indirect_call"
    ir_format: str
    source_file: str = ""
    line: int = 1
    is_dynamic: bool = False


@dataclass
class CompilerIrBundle:
    """Combined USR + Swift SIL + LLVM IR representation for a scan or drill-down."""

    functions: dict[str, IrFunctionNode] = field(default_factory=dict)
    calls: list[IrCallEdge] = field(default_factory=list)
    usr_index: UsrIndexBundle = field(default_factory=UsrIndexBundle)
    notes: list[str] = field(default_factory=list)

    def add_function(self, fn: IrFunctionNode) -> None:
        prev = self.functions.get(fn.symbol)
        if prev is None or (not prev.is_defined and fn.is_defined) or (not prev.source_file and fn.source_file):
            self.functions[fn.symbol] = fn

    def add_call(self, edge: IrCallEdge) -> None:
        key = (edge.caller_symbol, edge.callee_symbol, edge.kind, edge.source_file, edge.line)
        if not hasattr(self, "_seen_calls"):
            self._seen_calls: set[tuple[str, str, str, str, int]] = {
                (e.caller_symbol, e.callee_symbol, e.kind, e.source_file, e.line)
                for e in self.calls
            }
        if key not in self._seen_calls:
            self._seen_calls.add(key)
            self.calls.append(edge)

    def merge(self, other: CompilerIrBundle) -> None:
        for fn in other.functions.values():
            self.add_function(fn)
        for call in other.calls:
            self.add_call(call)
        self.usr_index.merge(other.usr_index)
        for nt in other.notes:
            if nt not in self.notes:
                self.notes.append(nt)


def _is_thunk_or_arc_label(symbol: str, label: str) -> bool:
    low = label.strip().lower()
    if low.startswith(
        (
            "protocol witness for ",
            "thunk for ",
            "reabstraction thunk ",
            "vtable thunk",
            "non-virtual thunk to ",
        )
    ):
        return True
    for pref in ("swift_retain", "swift_release", "objc_retain", "objc_release", "objc_autorelease"):
        if symbol.startswith(pref) or label.startswith(pref):
            return True
    return symbol.startswith("_") and "TWo" in symbol


def _extract_sil_header_symbol(line: str) -> tuple[str, bool, str] | None:
    stripped = line.lstrip()
    if not stripped.startswith("sil ") and not stripped.startswith("sil\t"):
        return None
    if stripped.startswith(("sil_stage", "sil_vtable", "sil_witness_table", "sil_global", "sil_property", "sil_scope")):
        return None
    at_idx = stripped.find("@")
    if at_idx < 0:
        return None
    prefix = stripped[:at_idx]
    clang_m = _SIL_CLANG_ATTR_RE.search(prefix)
    clang_sym = clang_m.group(1) if clang_m else ""
    rest = stripped[at_idx + 1 :]
    if rest.startswith('"'):
        end_q = 1
        while end_q < len(rest):
            if rest[end_q] == "\\":
                end_q += 2
                continue
            if rest[end_q] == '"':
                break
            end_q += 1
        raw_sym = rest[: end_q + 1]
    else:
        colon_idx = rest.find(":")
        chunk = rest[:colon_idx] if colon_idx >= 0 else rest
        raw_sym = chunk.strip().split()[0] if chunk.strip() else ""
    if not raw_sym:
        return None
    is_def = stripped.rstrip().endswith("{")
    return _unquote_ir_ident(raw_sym), is_def, clang_sym


def parse_sil_text(
    raw_text: str,
    *,
    repo_root: Path | None = None,
    default_source_file: str = "",
) -> CompilerIrBundle:
    """Parse Swift Intermediate Language (`.sil`) text into `CompilerIrBundle`."""
    bundle = CompilerIrBundle()
    lines = raw_text.splitlines()
    witness_map: dict[str, str] = {}
    vtable_map: dict[str, tuple[str, bool]] = {}

    in_wtable = False
    in_vtable = False
    for raw_ln in lines:
        ln = raw_ln[:MAX_IR_LINE_CHARS]
        if in_wtable:
            if ln.strip() == "}":
                in_wtable = False
                continue
            wm = _SIL_WTABLE_METHOD_RE.match(ln)
            if wm:
                witness_map[wm.group(1)] = _unquote_ir_ident(wm.group(2))
            continue
        if in_vtable:
            if ln.strip() == "}":
                in_vtable = False
                continue
            vm = _SIL_VTABLE_ENTRY_RE.match(ln)
            if vm:
                vtable_map[vm.group(1)] = (_unquote_ir_ident(vm.group(2)), vm.group(3) == "override")
            continue
        if _SIL_WTABLE_HEADER_RE.match(ln):
            in_wtable = True
        elif _SIL_VTABLE_HEADER_RE.match(ln):
            in_vtable = True

    last_comment = ""
    cur_fn: IrFunctionNode | None = None
    ssa_targets: dict[str, tuple[str, str]] = {}
    clang_aliases: dict[str, str] = {}
    raw_edges: list[tuple[IrFunctionNode, str, str, str, int]] = []

    for raw_ln in lines:
        ln = raw_ln[:MAX_IR_LINE_CHARS]
        stripped = ln.strip()
        if not stripped:
            continue
        if stripped.startswith("//"):
            comment_body = stripped[2:].strip()
            if comment_body and not comment_body.startswith(("sil_stage", "%", "bb")):
                last_comment = comment_body
            continue

        hdr = _extract_sil_header_symbol(ln)
        if hdr is not None:
            sym, is_def, clang_sym = hdr
            if clang_sym:
                clang_aliases[sym] = clang_sym
            loc_m = _SIL_LOC_RE.search(ln)
            sf = normalize_repo_relpath(loc_m.group(1), repo_root) if loc_m else default_source_file
            line_no = int(loc_m.group(2)) if loc_m else 1
            lbl, lang = demangle_symbol_label(sym, last_comment)
            if clang_sym:
                lang = "c"
            usr = symbol_to_usr(sym, clang_name=clang_sym, language=lang)
            fn_node = IrFunctionNode(
                symbol=sym,
                label=lbl,
                usr=usr,
                language=lang,
                ir_format="sil",
                source_file=sf,
                line=line_no,
                is_defined=is_def,
                is_thunk_or_arc=_is_thunk_or_arc_label(sym, lbl),
            )
            bundle.add_function(fn_node)
            last_comment = ""
            cur_fn = fn_node if is_def else None
            ssa_targets = {}
            continue

        last_comment = ""
        if cur_fn is None:
            continue
        if stripped == "}":
            cur_fn = None
            ssa_targets = {}
            continue

        loc_m = _SIL_LOC_RE.search(ln)
        call_sf = normalize_repo_relpath(loc_m.group(1), repo_root) if loc_m else cur_fn.source_file
        call_ln = int(loc_m.group(2)) if loc_m else cur_fn.line
        if loc_m and not cur_fn.source_file and call_sf:
            cur_fn = IrFunctionNode(
                symbol=cur_fn.symbol,
                label=cur_fn.label,
                usr=cur_fn.usr,
                language=cur_fn.language,
                ir_format="sil",
                source_file=call_sf,
                line=call_ln,
                is_defined=True,
                is_thunk_or_arc=cur_fn.is_thunk_or_arc,
            )
            bundle.add_function(cur_fn)

        fref = _SIL_FN_REF_RE.match(ln)
        if fref:
            ssa_targets[fref.group(1)] = (_unquote_ir_ident(fref.group(2)), "calls_ir")
            continue
        wref = _SIL_WITNESS_METHOD_RE.match(ln)
        if wref:
            req = wref.group(2)
            mapped = witness_map.get(req, f"witness:{req}")
            ssa_targets[wref.group(1)] = (mapped, "witness_dispatch")
            continue
        cref = _SIL_CLASS_METHOD_RE.match(ln)
        if cref:
            req = cref.group(2)
            mapped_v = vtable_map.get(req, (f"vtable:{req}", False))[0]
            ssa_targets[cref.group(1)] = (mapped_v, "vtable_dispatch")
            continue

        app = _SIL_APPLY_RE.search(ln)
        if app:
            callee_tok = app.group(1)
            if callee_tok.startswith("@"):
                raw_edges.append((cur_fn, _unquote_ir_ident(callee_tok[1:]), "calls_ir", call_sf, call_ln))
            elif callee_tok in ssa_targets:
                tgt_sym, ekind = ssa_targets[callee_tok]
                raw_edges.append((cur_fn, tgt_sym, ekind, call_sf, call_ln))

    for caller_fn, tgt_sym, ekind, edge_sf, edge_ln in raw_edges:
        tgt_node = bundle.functions.get(tgt_sym)
        if tgt_node is None:
            if tgt_sym.startswith("witness:"):
                req_name = tgt_sym.split(":", 1)[1]
                lbl = f"protocol witness for {req_name}"
                lang = "swift"
                usr = f"s:witness:{req_name}"
            elif tgt_sym.startswith("vtable:"):
                req_name = tgt_sym.split(":", 1)[1]
                lbl = f"vtable thunk for {req_name}"
                lang = "swift"
                usr = f"s:vtable:{req_name}"
            else:
                c_alias = clang_aliases.get(tgt_sym, "")
                lbl, lang = demangle_symbol_label(tgt_sym)
                if c_alias:
                    lang = "c"
                usr = symbol_to_usr(tgt_sym, clang_name=c_alias, language=lang)
            tgt_node = IrFunctionNode(
                symbol=tgt_sym,
                label=lbl,
                usr=usr,
                language=lang,
                ir_format="sil",
                source_file="",
                line=1,
                is_defined=False,
                is_thunk_or_arc=_is_thunk_or_arc_label(tgt_sym, lbl),
            )
            bundle.add_function(tgt_node)

        final_kind = ekind
        if final_kind == "calls_ir" and caller_fn.language != tgt_node.language:
            final_kind = "ffi_call"
        bundle.add_call(
            IrCallEdge(
                caller_symbol=caller_fn.symbol,
                caller_label=caller_fn.label,
                caller_usr=caller_fn.usr,
                callee_symbol=tgt_node.symbol,
                callee_label=tgt_node.label,
                callee_usr=tgt_node.usr,
                kind=final_kind,
                ir_format="sil",
                source_file=edge_sf,
                line=edge_ln,
                is_dynamic=False,
            )
        )
    return bundle


def parse_sil_file(
    path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> CompilerIrBundle:
    """Load a `.sil` file or directory of `.sil` files safely without executing `swiftc`."""
    validated = validate_safe_path(
        path,
        repo_root=repo_root,
        allow_external=allow_external,
        allow_dir=True,
    )
    if validated.is_file():
        _, text = read_safe_text(validated, repo_root=repo_root, allow_external=allow_external)
        return parse_sil_text(text, repo_root=repo_root)

    out = CompilerIrBundle()
    for fpath, _ in iter_safe_repo_files(validated, suffixes=(".sil",), max_files=256):
        _, text = read_safe_text(
            fpath,
            repo_root=repo_root if not allow_external else None,
            allow_external=allow_external,
        )
        out.merge(parse_sil_text(text, repo_root=repo_root))
    return out


def _extract_meta_field(body: str, key: str) -> str:
    needle = f"{key}:"
    idx = body.find(needle)
    if idx < 0:
        return ""
    rest = body[idx + len(needle) :].lstrip()
    if rest.startswith('"'):
        end_q = 1
        while end_q < len(rest):
            if rest[end_q] == "\\":
                end_q += 2
                continue
            if rest[end_q] == '"':
                return rest[1:end_q]
            end_q += 1
        return rest[1:]
    end_tok = 0
    while end_tok < len(rest) and rest[end_tok] not in (",", ")", " ", "\t"):
        end_tok += 1
    return rest[:end_tok]


def parse_llvm_ir_text(
    raw_text: str,
    *,
    repo_root: Path | None = None,
    default_source_file: str = "",
) -> CompilerIrBundle:
    """Parse LLVM IR (`.ll`) text into `CompilerIrBundle` across C/C++/Swift/ObjC/Rust/Python."""
    bundle = CompilerIrBundle()
    lines = raw_text.splitlines()
    module_src = default_source_file

    di_files: dict[str, str] = {}
    di_subprograms: dict[str, tuple[str, int, str]] = {}
    di_locations: dict[str, tuple[str, int]] = {}
    raw_locs: list[tuple[str, int, str]] = []

    for raw_ln in lines:
        ln = raw_ln[:MAX_IR_LINE_CHARS]
        sm = _LLVM_SRC_FILE_RE.match(ln)
        if sm:
            module_src = normalize_repo_relpath(_unquote_ir_ident(sm.group(1)), repo_root)
            continue
        mm = _LLVM_META_ID_RE.match(ln)
        if not mm:
            continue
        mid, mkind, mbody = mm.group(1), mm.group(2), mm.group(3)
        if mkind == "DIFile":
            fname = _extract_meta_field(mbody, "filename")
            dname = _extract_meta_field(mbody, "directory")
            joined = f"{dname.rstrip('/')}/{fname}" if dname and not fname.startswith("/") else fname
            di_files[mid] = normalize_repo_relpath(joined, repo_root)
        elif mkind == "DISubprogram":
            f_ref = _extract_meta_field(mbody, "file").lstrip("!")
            ln_str = _extract_meta_field(mbody, "line")
            human_nm = _extract_meta_field(mbody, "name")
            di_subprograms[mid] = (f_ref, int(ln_str) if ln_str.isdigit() else 1, human_nm)
        elif mkind == "DILocation":
            ln_str = _extract_meta_field(mbody, "line")
            sc_ref = _extract_meta_field(mbody, "scope").lstrip("!")
            raw_locs.append((mid, int(ln_str) if ln_str.isdigit() else 1, sc_ref))

    resolved_subprog: dict[str, tuple[str, int, str]] = {}
    for sp_id, (f_ref, sp_ln, sp_nm) in di_subprograms.items():
        resolved_subprog[sp_id] = (di_files.get(f_ref, module_src), sp_ln, sp_nm)
    for loc_id, loc_ln, sc_ref in raw_locs:
        sp = resolved_subprog.get(sc_ref)
        di_locations[loc_id] = (sp[0] if sp else module_src, loc_ln)

    last_comment = ""
    cur_fn: IrFunctionNode | None = None
    pending_calls: list[tuple[IrFunctionNode, str, str, str, int, bool]] = []

    for raw_ln in lines:
        ln = raw_ln[:MAX_IR_LINE_CHARS]
        stripped = ln.strip()
        if not stripped:
            continue
        if stripped.startswith(";"):
            cbody = stripped.lstrip(";").strip()
            if cbody and not cbody.startswith(("ModuleID", "source_filename", "target ", "Function Attrs")):
                last_comment = cbody
            continue

        if stripped.startswith(("define ", "declare ")):
            is_def = stripped.startswith("define ")
            gm = _LLVM_GLOBAL_SYM_RE.search(stripped)
            if gm:
                sym = _unquote_ir_ident(gm.group(1))
                dbg_m = _LLVM_DBG_TAG_RE.search(stripped)
                sp_meta = resolved_subprog.get(dbg_m.group(1)) if dbg_m else None
                sf = sp_meta[0] if sp_meta and sp_meta[0] else (module_src if is_def else "")
                line_no = sp_meta[1] if sp_meta else 1
                hint = (sp_meta[2] if sp_meta and sp_meta[2] else "") or last_comment
                lbl, lang = demangle_symbol_label(sym, hint)
                usr = symbol_to_usr(sym, language=lang)
                fn_node = IrFunctionNode(
                    symbol=sym,
                    label=lbl,
                    usr=usr,
                    language=lang,
                    ir_format="llvm_ir",
                    source_file=sf,
                    line=line_no,
                    is_defined=is_def,
                    is_thunk_or_arc=_is_thunk_or_arc_label(sym, lbl),
                )
                bundle.add_function(fn_node)
                cur_fn = fn_node if is_def and stripped.endswith("{") else None
            last_comment = ""
            continue

        last_comment = ""
        if cur_fn is None:
            continue
        if stripped == "}":
            cur_fn = None
            continue

        cm = _LLVM_CALL_INSTR_RE.match(ln)
        if not cm:
            continue
        tail_part = cm.group(2)
        dbg_m = _LLVM_DBG_TAG_RE.search(tail_part)
        loc_info = di_locations.get(dbg_m.group(1)) if dbg_m else None
        call_sf = loc_info[0] if loc_info and loc_info[0] else cur_fn.source_file
        call_ln = loc_info[1] if loc_info else cur_fn.line

        at_pos = tail_part.find("@")
        if at_pos >= 0:
            after_at = tail_part[at_pos + 1 :]
            if after_at.startswith('"'):
                eq = 1
                while eq < len(after_at):
                    if after_at[eq] == "\\":
                        eq += 2
                        continue
                    if after_at[eq] == '"':
                        break
                    eq += 1
                raw_callee = after_at[: eq + 1]
            else:
                end_i = 0
                while end_i < len(after_at) and after_at[end_i] not in ("(", " ", ",", ")"):
                    end_i += 1
                raw_callee = after_at[:end_i]
            callee_sym = _unquote_ir_ident(raw_callee)
            if callee_sym and not callee_sym.startswith(("llvm.dbg.", "llvm.lifetime.")):
                pending_calls.append((cur_fn, callee_sym, "calls_ir", call_sf, call_ln, False))
        else:
            ind_m = _LLVM_INDIRECT_REG_RE.search(tail_part)
            if ind_m:
                reg_name = ind_m.group(1)
                pending_calls.append(
                    (cur_fn, f"indirect:{reg_name}", "indirect_call", call_sf, call_ln, True)
                )

    for caller_fn, callee_sym, ekind, c_sf, c_ln, is_dyn in pending_calls:
        tgt = bundle.functions.get(callee_sym)
        if tgt is None:
            if is_dyn:
                lbl, lang, usr = callee_sym, caller_fn.language, f"ir:{callee_sym}"
            else:
                lbl, lang = demangle_symbol_label(callee_sym)
                usr = symbol_to_usr(callee_sym, language=lang)
            tgt = IrFunctionNode(
                symbol=callee_sym,
                label=lbl,
                usr=usr,
                language=lang,
                ir_format="llvm_ir",
                source_file="",
                line=1,
                is_defined=False,
                is_thunk_or_arc=(not is_dyn) and _is_thunk_or_arc_label(callee_sym, lbl),
            )
            bundle.add_function(tgt)

        resolved_kind = (
            "ffi_call"
            if (not is_dyn and ekind == "calls_ir" and caller_fn.language != tgt.language)
            else ekind
        )
        bundle.add_call(
            IrCallEdge(
                caller_symbol=caller_fn.symbol,
                caller_label=caller_fn.label,
                caller_usr=caller_fn.usr,
                callee_symbol=tgt.symbol,
                callee_label=tgt.label,
                callee_usr=tgt.usr,
                kind=resolved_kind,
                ir_format="llvm_ir",
                source_file=c_sf,
                line=c_ln,
                is_dynamic=is_dyn,
            )
        )
    return bundle


def parse_llvm_ir_file(
    path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> CompilerIrBundle:
    """Load a read-only `.ll` file or directory of `.ll` files without invoking `clang`/`llvm-dis`."""
    validated = validate_safe_path(
        path,
        repo_root=repo_root,
        allow_external=allow_external,
        allow_dir=True,
    )
    if validated.is_file():
        _, text = read_safe_text(validated, repo_root=repo_root, allow_external=allow_external)
        return parse_llvm_ir_text(text, repo_root=repo_root)

    out = CompilerIrBundle()
    for fpath, _ in iter_safe_repo_files(validated, suffixes=(".ll",), max_files=256):
        _, text = read_safe_text(
            fpath,
            repo_root=repo_root if not allow_external else None,
            allow_external=allow_external,
        )
        out.merge(parse_llvm_ir_text(text, repo_root=repo_root))
    return out
