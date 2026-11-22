"""Pure-Python 3-wythe Swift, XPC, vsock/gRPC, C-FFI, store, launchd, and entitlements extractor."""

from __future__ import annotations

import plistlib
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal
from xml.parsers import expat

from app.adapters.base import RawCandidateFinding
from app.schemas.atlas import AtlasEdge, AtlasNode
from wythe_plugin_apple_ipc.package_manifest import (
    MAX_NESTING_DEPTH,
    MAX_SOURCE_FILE_BYTES,
    PackageManifest,
    find_matching_delim,
    iter_safe_repo_files,
    parse_package_manifest,
    read_bounded_bytes,
    read_bounded_text,
    sanitize_swift_source,
    split_top_level_spans,
    validate_safe_directory,
)

_PLIST_OPEN_CONTAINER_RE: Final[re.Pattern[bytes]] = re.compile(rb"<(dict|array)(?:\s|>)", re.IGNORECASE)
_PLIST_SELF_CLOSE_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"<(dict|array)\s*/>", re.IGNORECASE
)
_PLIST_CLOSE_CONTAINER_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"</(dict|array)\s*>", re.IGNORECASE
)
_PLIST_TAG_TOKEN_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"<(/?)(dict|array)(\s*/>|\s*>|\s+[^>]*>)", re.IGNORECASE
)


def _check_python_container_depth(obj: Any, *, max_depth: int = MAX_NESTING_DEPTH) -> None:
    visited: set[int] = set()
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(
                f"Plist structure exceeds maximum nesting depth ({max_depth})."
            )
        oid = id(cur)
        if oid in visited:
            continue
        visited.add(oid)
        if len(visited) > 65536:
            raise ValueError("Plist structure exceeds maximum unique container budget.")
        if isinstance(cur, dict):
            for val in cur.values():
                if isinstance(val, (dict, list, tuple)) and id(val) not in visited:
                    stack.append((val, depth + 1))
        elif isinstance(cur, (list, tuple)):
            for item in cur:
                if isinstance(item, (dict, list, tuple)) and id(item) not in visited:
                    stack.append((item, depth + 1))


_XML_BUILTIN_ENTITIES: Final[frozenset[str]] = frozenset({"amp", "lt", "gt", "apos", "quot"})
_APPLE_PLIST_DOCTYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"<!DOCTYPE\s+plist\s+PUBLIC\s+"
    r'["\']-//Apple(?:\s+Computer)?//DTD\s+PLIST\s+1\.0//EN["\']\s+'
    r'["\']https?://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd["\']\s*>',
    re.IGNORECASE,
)
_FORBIDDEN_XML_DECL_RE: Final[re.Pattern[str]] = re.compile(
    r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)\b",
    re.IGNORECASE,
)
_ENTITY_REF_RE: Final[re.Pattern[str]] = re.compile(r"&([A-Za-z_][A-Za-z0-9_.-]*);")


def parse_safe_plist_bytes(
    raw_bytes: bytes,
    *,
    source_label: str = "<plist>",
    max_bytes: int = MAX_SOURCE_FILE_BYTES,
    max_depth: int = MAX_NESTING_DEPTH,
) -> dict[str, Any]:
    """Safely parse XML/binary plist bytes while rejecting XXE `<!DOCTYPE`/`<!ENTITY` and deep nesting."""
    if len(raw_bytes) > max_bytes:
        raise ValueError(
            f"Plist '{source_label}' ({len(raw_bytes)} bytes) exceeds {max_bytes}-byte limit."
        )
    lowered_head = raw_bytes[:65536].lower()
    if b"<!entity" in lowered_head or b"<!entity" in raw_bytes.lower():
        raise ValueError(
            f"XML <!ENTITY declarations are forbidden in plist '{source_label}'."
        )

    if raw_bytes.startswith(b"bplist"):
        try:
            parsed = plistlib.loads(raw_bytes)
        except Exception as exc:
            raise ValueError(f"Malformed binary plist '{source_label}': {exc}") from exc
        _check_python_container_depth(parsed, max_depth=max_depth)
        return parsed if isinstance(parsed, dict) else {}

    xml_depth = 0
    for tm in _PLIST_TAG_TOKEN_RE.finditer(raw_bytes):
        is_close = bool(tm.group(1))
        tail = tm.group(3)
        if is_close:
            xml_depth = max(0, xml_depth - 1)
        elif not tail.rstrip().endswith(b"/>"):
            xml_depth += 1
            if xml_depth > max_depth:
                raise ValueError(
                    f"Plist '{source_label}' exceeds maximum XML nesting depth ({max_depth})."
                )

    try:
        xml_text = (
            raw_bytes.decode("utf-16")
            if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff"))
            else raw_bytes.decode("utf-8-sig")
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"Malformed XML plist encoding in '{source_label}': {exc}") from exc

    cleaned_xml = xml_text.strip("\x00 \t\r\n")
    if not cleaned_xml:
        return {}
    if "\x00" in cleaned_xml:
        raise ValueError(f"Plist '{source_label}' contains forbidden embedded NUL bytes.")

    stripped_doctype = _APPLE_PLIST_DOCTYPE_RE.sub("", cleaned_xml, count=1)
    if _FORBIDDEN_XML_DECL_RE.search(stripped_doctype):
        raise ValueError(
            f"Forbidden XML DOCTYPE/ENTITY declaration in plist '{source_label}' (XXE protection)."
        )
    for ent_match in _ENTITY_REF_RE.finditer(stripped_doctype):
        if ent_match.group(1) not in _XML_BUILTIN_ENTITIES:
            raise ValueError(
                f"Forbidden custom XML ENTITY reference '&{ent_match.group(1)};' in plist '{source_label}' (XXE protection)."
            )

    elem_depth = 0
    guard = expat.ParserCreate("UTF-8")

    def _on_doctype(_name: str, _sysid: str | None, _pubid: str | None, _has_subset: int) -> None:
        raise ValueError(
            f"Forbidden XML DOCTYPE/ENTITY declaration in plist '{source_label}' (XXE protection)."
        )

    def _on_entity(*_args: object) -> None:
        raise ValueError(
            f"XML <!ENTITY declarations are forbidden in plist '{source_label}'."
        )

    def _on_ext_ref(*_args: object) -> int:
        raise ValueError(
            f"Forbidden external XML ENTITY reference in plist '{source_label}' (XXE protection)."
        )

    def _on_start(_name: str, _attrs: dict[str, str]) -> None:
        nonlocal elem_depth
        elem_depth += 1
        if elem_depth > max_depth + 4:
            raise ValueError(
                f"Plist '{source_label}' exceeds maximum XML nesting depth ({max_depth})."
            )

    def _on_end(_name: str) -> None:
        nonlocal elem_depth
        elem_depth = max(0, elem_depth - 1)

    guard.StartDoctypeDeclHandler = _on_doctype
    guard.EntityDeclHandler = _on_entity
    guard.ExternalEntityRefHandler = _on_ext_ref
    guard.StartElementHandler = _on_start
    guard.EndElementHandler = _on_end
    encoded_clean = stripped_doctype.encode("utf-8")
    try:
        guard.Parse(encoded_clean, True)
        parsed = plistlib.loads(encoded_clean, fmt=plistlib.FMT_XML)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Malformed plist '{source_label}': {exc}") from exc

    _check_python_container_depth(parsed, max_depth=max_depth)
    return parsed if isinstance(parsed, dict) else {}


@dataclass(frozen=True)
class SwiftImportRef:
    module_name: str
    line: int
    is_exported: bool = False


@dataclass(frozen=True)
class SwiftNominalDecl:
    kind: Literal["struct", "class", "actor", "enum", "protocol", "extension"]
    name: str
    qualified_name: str
    conformances: tuple[str, ...]
    source_file: str
    target_name: str
    line: int
    body_clean: str
    body_skeleton: str
    is_main: bool = False


@dataclass(frozen=True)
class XpcRouteCase:
    enum_name: str
    case_name: str
    route_key: str
    source_file: str
    line: int


@dataclass(frozen=True)
class XpcClientSendSite:
    caller_file: str
    caller_type: str | None
    caller_func: str
    line: int
    kind: Literal["static_in_repo", "external_mach", "dynamic_runtime"]
    route_key: str
    display_route: str
    enum_name: str | None = None
    is_read_only: bool = False


@dataclass(frozen=True)
class GrpcServiceSpec:
    service_name: str
    package_name: str
    methods: tuple[str, ...]
    source_files: tuple[str, ...]
    primary_file: str
    line: int
    target_name: str
    uses_vsock: bool = False


@dataclass
class SwiftRepoExtraction:
    """Unified 3-tier extraction bundle for a Swift systems repository."""

    manifest: PackageManifest
    truth_nodes: list[AtlasNode] = field(default_factory=list)
    truth_symbol_map: dict[str, str] = field(default_factory=dict)
    manip_nodes: list[AtlasNode] = field(default_factory=list)
    manip_edges: list[AtlasEdge] = field(default_factory=list)
    disp_nodes: list[AtlasNode] = field(default_factory=list)
    disp_edges: list[AtlasEdge] = field(default_factory=list)
    findings: list[RawCandidateFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    excluded_symlinks: int = 0


_STR_LIT_RE: Final[re.Pattern[str]] = re.compile(r'"((?:\\.|[^"\\\n])*)"')
_SWIFT_IMPORT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*((?:@[A-Za-z_]\w*(?:\([^)\n]*\))?\s*)*)import\s+"
    r"(?:(?:struct|class|enum|protocol|actor|func|var|let|typealias)\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)
_SILGEN_RE: Final[re.Pattern[str]] = re.compile(
    r'@_silgen_name\s*\(\s*"((?:\\.|[^"\\\n])*)"\s*\)[^{;\n]*?\bfunc\s+([A-Za-z_][A-Za-z0-9_]*)'
)
_NOMINAL_DECL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:(@main)\s+)?"
    r"(?:(?:public|internal|package|private|fileprivate|open|final|indirect|distributed|nonisolated)\s+)*"
    r"\b(struct|class|actor|enum|protocol|extension)\s+"
    r"([A-Za-z_][A-Za-z0-9_.]*)"
    r"(?:\s*<[^{;\n]{0,240}>)?"
    r"(?:\s*:\s*([^{;\n]{1,320}))?"
    r"(?:\s+where\s+[^{;\n]{1,320})?"
    r"\s*\{"
)
_C_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"if", "for", "while", "switch", "return", "sizeof", "alignof", "typeof", "__attribute__"}
)
_C_FUNC_RE: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}()]{0,240}\)\s*(?:\{|;)"
)
_PROTO_PKG_RE: Final[re.Pattern[str]] = re.compile(r"\bpackage\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;")
_PROTO_SVC_RE: Final[re.Pattern[str]] = re.compile(r"\bservice\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
_PROTO_RPC_RE: Final[re.Pattern[str]] = re.compile(r"\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def extract_c_ffi_symbols(source: str) -> tuple[list[str], int]:
    """Extract exported/defined C function symbols and first symbol line from `.c`/`.h`."""
    _, skeleton = sanitize_swift_source(source)
    funcs: list[str] = []
    seen: set[str] = set()
    first_line = 1
    for m in _C_FUNC_RE.finditer(skeleton):
        fn_name = m.group(1)
        if fn_name in _C_KEYWORDS or fn_name.startswith("__"):
            continue
        line_prefix = skeleton[skeleton.rfind("\n", 0, m.start()) + 1 : m.start()].strip()
        if line_prefix.startswith("#") or line_prefix.endswith("="):
            continue
        if not seen:
            first_line = skeleton.count("\n", 0, m.start()) + 1
        if fn_name not in seen:
            seen.add(fn_name)
            funcs.append(fn_name)
    return funcs, first_line


def extract_proto_services(
    source: str,
    rel_file: str,
    target_name: str,
) -> list[GrpcServiceSpec]:
    """Extract `service <Name> { rpc ... }` definitions from `.proto` source."""
    _, skeleton = sanitize_swift_source(source)
    pkg_m = _PROTO_PKG_RE.search(skeleton)
    pkg_name = pkg_m.group(1) if pkg_m else ""
    uses_vsock = "vsock" in source.lower()
    specs: list[GrpcServiceSpec] = []
    cursor = 0
    while True:
        sm = _PROTO_SVC_RE.search(skeleton, cursor)
        if sm is None:
            break
        svc_name = sm.group(1)
        b_open = sm.end() - 1
        b_close = find_matching_delim(skeleton, b_open)
        if b_close == -1:
            break
        cursor = b_close + 1
        body = skeleton[b_open + 1 : b_close]
        methods = tuple(dict.fromkeys(rm.group(1) for rm in _PROTO_RPC_RE.finditer(body)))
        line_no = skeleton.count("\n", 0, sm.start()) + 1
        specs.append(
            GrpcServiceSpec(
                service_name=svc_name,
                package_name=pkg_name,
                methods=methods,
                source_files=(rel_file,),
                primary_file=rel_file,
                line=line_no,
                target_name=target_name,
                uses_vsock=uses_vsock,
            )
        )
    return specs


_GRPC_SWIFT_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)ClientMetadata\b"),
    re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)ServerMetadata\b"),
    re.compile(r"\bprotocol\s+([A-Za-z_][A-Za-z0-9_]*)AsyncClientProtocol\b"),
    re.compile(r"\bprotocol\s+([A-Za-z_][A-Za-z0-9_]*)AsyncProvider\b"),
    re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)AsyncClient\b"),
    re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)Client\b"),
)
_GRPC_ENUM_NS_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:public\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)
_GRPC_FUNC_RE: Final[re.Pattern[str]] = re.compile(r"\bfunc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def extract_grpc_swift_service(
    source: str,
    rel_file: str,
    target_name: str,
) -> GrpcServiceSpec | None:
    """Extract gRPC service metadata from `.grpc.swift` generated/hand-authored stubs."""
    clean, skeleton = sanitize_swift_source(source)
    svc_name: str | None = None
    line_no = 1
    for rx in _GRPC_SWIFT_PATTERNS:
        m = rx.search(skeleton)
        if m is not None and m.group(1):
            cand = m.group(1).split("_")[-1]
            svc_name = cand
            line_no = skeleton.count("\n", 0, m.start()) + 1
            break

    if svc_name is None:
        sd_m = re.search(
            r'ServiceDescriptor\s*\([^)]*?"((?:\\.|[^"\\\n])*)"',
            clean,
        )
        if sd_m is not None:
            fq = sd_m.group(1)
            svc_name = fq.rsplit(".", 1)[-1]
            line_no = clean.count("\n", 0, sd_m.start()) + 1

    if svc_name is None:
        em = _GRPC_ENUM_NS_RE.search(skeleton)
        if em is not None:
            svc_name = em.group(1).split("_")[-1]
            line_no = skeleton.count("\n", 0, em.start()) + 1
        else:
            stem = PurePosixPath(rel_file).name.removesuffix(".grpc.swift")
            svc_name = stem.split(".")[0]

    methods: list[str] = []
    for fm in _GRPC_FUNC_RE.finditer(skeleton):
        fn = fm.group(1)
        if fn not in ("init", "handle", "registerHandlers", "makeInterceptors") and fn not in methods:
            methods.append(fn)

    uses_vsock = any(
        tok in source.lower()
        for tok in ("vsock", "af_vsock", "vzvirtiosocket", "virtiosocket")
    )
    return GrpcServiceSpec(
        service_name=svc_name,
        package_name="",
        methods=tuple(methods[:24]),
        source_files=(rel_file,),
        primary_file=rel_file,
        line=line_no,
        target_name=target_name,
        uses_vsock=uses_vsock,
    )


def extract_swift_imports_and_silgen(
    clean: str,
    skeleton: str,
) -> tuple[list[SwiftImportRef], list[tuple[str, str, int]]]:
    """Extract `import` module names and `@_silgen_name("c_sym") func swift_fn` bindings."""
    imports: list[SwiftImportRef] = []
    for line_idx, skel_line in enumerate(skeleton.splitlines(), start=1):
        im = _SWIFT_IMPORT_RE.match(skel_line[:256])
        if im is not None:
            attrs = im.group(1) or ""
            mod_name = im.group(2)
            imports.append(
                SwiftImportRef(
                    module_name=mod_name,
                    line=line_idx,
                    is_exported="@_exported" in attrs,
                )
            )

    silgens: list[tuple[str, str, int]] = []
    for sm in _SILGEN_RE.finditer(clean):
        c_sym = sm.group(1).strip()
        swift_fn = sm.group(2).strip()
        if c_sym and swift_fn:
            silgens.append((swift_fn, c_sym, clean.count("\n", 0, sm.start()) + 1))
    return imports, silgens


def extract_swift_nominals(
    clean: str,
    skeleton: str,
    rel_file: str,
    target_name: str,
) -> list[SwiftNominalDecl]:
    """Recursively extract nominal Swift declarations and nested subcommands/types."""
    out: list[SwiftNominalDecl] = []

    def _walk_region(start: int, end: int, parent_qual: str, depth: int) -> None:
        if depth > 6:
            return
        pos = start
        while pos < end:
            m = _NOMINAL_DECL_RE.search(skeleton, pos, end)
            if m is None:
                break
            b_open = m.end() - 1
            b_close = find_matching_delim(skeleton, b_open)
            if b_close == -1 or b_close > end:
                pos = m.end()
                continue
            is_main = bool(m.group(1))
            d_kind = m.group(2)
            raw_name = m.group(3)
            raw_conf = m.group(4) or ""
            confs = tuple(
                c.strip().split("<", 1)[0].strip()
                for c in raw_conf.split(",")
                if c.strip()
            )
            short_name = raw_name.rsplit(".", 1)[-1]
            qual_name = (
                raw_name
                if "." in raw_name or not parent_qual
                else f"{parent_qual}.{short_name}"
            )
            line_no = skeleton.count("\n", 0, m.start()) + 1
            out.append(
                SwiftNominalDecl(
                    kind=d_kind,  # type: ignore[arg-type]
                    name=short_name,
                    qualified_name=qual_name,
                    conformances=confs,
                    source_file=rel_file,
                    target_name=target_name,
                    line=line_no,
                    body_clean=clean[b_open + 1 : b_close],
                    body_skeleton=skeleton[b_open + 1 : b_close],
                    is_main=is_main,
                )
            )
            _walk_region(b_open + 1, b_close, qual_name, depth + 1)
            pos = b_close + 1

    _walk_region(0, len(skeleton), "", 0)
    return out


_OS_MACH_NAMESPACE_PREFIXES: Final[tuple[str, ...]] = (
    "com.apple.system.",
    "com.apple.bsd.",
    "com.apple.security.",
    "com.apple.securityd",
    "com.apple.cfprefsd",
    "com.apple.FSEvents",
    "com.apple.DiskArbitration",
    "com.apple.PowerManagement",
    "com.apple.CoreServices",
    "com.apple.lsd",
    "com.apple.tccd",
    "com.apple.trustd",
    "com.apple.distributed_notifications",
)
_READ_ROUTE_TOKENS: Final[frozenset[str]] = frozenset(
    {"list", "get", "inspect", "info", "stat", "status", "version", "ping", "health", "fetch", "lookup", "read"}
)


def _is_read_like_name(name: str) -> bool:
    parts = [p for p in re.split(r"[^a-z0-9]+", name.lower()) if p]
    if not parts:
        return False
    return parts[0] in _READ_ROUTE_TOKENS or parts[-1] in _READ_ROUTE_TOKENS


def _bundle_namespace_prefix(identifier: str) -> str | None:
    clean = identifier.strip().split("/", 1)[0]
    segs = [s for s in clean.split(".") if s]
    if len(segs) >= 3 and segs[0] == "com" and segs[1] == "apple":
        cand = f"com.apple.{segs[2]}."
        if not any(cand.startswith(os_p) or os_p.startswith(cand.rstrip(".")) for os_p in _OS_MACH_NAMESPACE_PREFIXES):
            return cand
    return None


def is_external_apple_mach_service(
    service_key: str,
    in_repo_prefixes: set[str],
    in_repo_exact: set[str],
) -> bool:
    """Return True when `service_key` names an external macOS `com.apple.*` Mach service."""
    clean = service_key.strip()
    if not clean.startswith("com.apple."):
        return False
    if any(clean.startswith(os_p) for os_p in _OS_MACH_NAMESPACE_PREFIXES):
        return True
    if clean in in_repo_exact:
        return False
    return not any(clean.startswith(pfx) for pfx in in_repo_prefixes)


def extract_cli_command_config(
    decl: SwiftNominalDecl,
) -> tuple[str | None, tuple[str, ...]]:
    """Extract `(commandName, subcommand_type_names)` from `CommandConfiguration(...)`."""
    m = re.search(r"\bCommandConfiguration\s*\(", decl.body_skeleton)
    if m is None:
        return None, ()
    p_open = m.end() - 1
    p_close = find_matching_delim(decl.body_skeleton, p_open)
    if p_close == -1:
        return None, ()

    cmd_name: str | None = None
    subcmds: list[str] = []
    for a_s, a_e in split_top_level_spans(decl.body_skeleton, p_open + 1, p_close, ","):
        arg_skel = decl.body_skeleton[a_s:a_e]
        arg_clean = decl.body_clean[a_s:a_e]
        lm = re.match(r"^\s*([A-Za-z_]\w*)\s*:\s*", arg_skel)
        lbl = lm.group(1) if lm else ""
        if lbl == "commandName":
            sm = _STR_LIT_RE.search(arg_clean)
            if sm is not None:
                cmd_name = sm.group(1).strip()
        elif lbl == "subcommands":
            for sm in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_.]*)\.self\b", arg_skel):
                subcmds.append(sm.group(1))
    return cmd_name, tuple(dict.fromkeys(subcmds))


_ENUM_CASE_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r'\bcase\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*"((?:\\.|[^"\\\n])*)")?'
)


def is_xpc_route_enum(decl: SwiftNominalDecl) -> bool:
    if decl.kind != "enum":
        return False
    low = decl.name.lower()
    if "xpc" in low or low.endswith(("route", "routes", "method", "methods")):
        return True
    return any("XPC" in c or "Route" in c for c in decl.conformances)


def extract_xpc_route_cases(decl: SwiftNominalDecl) -> list[XpcRouteCase]:
    """Extract static `case <name> = "<route>"` entries from an XPC route enum."""
    cases: list[XpcRouteCase] = []
    # Only scan top-level body of the enum (brace depth 0 inside body_skeleton)
    depth = 0
    for line_offset, (raw_clean_ln, raw_skel_ln) in enumerate(
        zip(
            decl.body_clean.splitlines(),
            decl.body_skeleton.splitlines(),
        )
    ):
        cur_line = decl.line + line_offset
        if depth == 0:
            for cm in _ENUM_CASE_LINE_RE.finditer(raw_clean_ln):
                c_name = cm.group(1)
                raw_val = cm.group(2)
                r_key = raw_val.strip() if raw_val is not None else f"{decl.name}.{c_name}"
                if r_key and "\\(" not in r_key:
                    cases.append(
                        XpcRouteCase(
                            enum_name=decl.name,
                            case_name=c_name,
                            route_key=r_key,
                            source_file=decl.source_file,
                            line=cur_line,
                        )
                    )
        depth += raw_skel_ln.count("{") - raw_skel_ln.count("}")
    return cases


_SERVER_SUBSCRIPT_ENUM_RE: Final[re.Pattern[str]] = re.compile(
    r"\[\s*(?:([A-Za-z_]\w*)\s*)?\.\s*([A-Za-z_]\w*)(?:\s*\.\s*rawValue)?\s*\]\s*[:=]"
)
_SERVER_SUBSCRIPT_STR_RE: Final[re.Pattern[str]] = re.compile(
    r'\[\s*"((?:\\.|[^"\\\n])*)"\s*\]\s*[:=]'
)
_SERVER_REG_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:register|registerHandler|setHandler|on|handle|addRoute|bindRoute|route)\s*\("
    r"([^;\n]{1,220})"
)
_SWITCH_CASE_ENUM_RE: Final[re.Pattern[str]] = re.compile(
    r"\bcase\s+(?:([A-Za-z_]\w*)\s*)?\.\s*([A-Za-z_]\w*)\s*:"
)
_SWITCH_CASE_STR_RE: Final[re.Pattern[str]] = re.compile(
    r'\bcase\s+"((?:\\.|[^"\\\n])*)"\s*:'
)


def extract_server_registered_routes(
    clean: str,
    rel_file: str,
    cases_by_enum_case: dict[tuple[str, str], XpcRouteCase],
    cases_by_short: dict[str, list[XpcRouteCase]],
) -> set[str]:
    """Identify XPC route keys handled/registered in a server or service Swift source file."""
    registered: set[str] = set()
    mentioned_enums = {
        e_name for (e_name, _) in cases_by_enum_case if re.search(rf"\b{re.escape(e_name)}\b", clean)
    }

    def _resolve_enum_ref(enum_opt: str | None, case_name: str) -> str | None:
        if enum_opt:
            hit = cases_by_enum_case.get((enum_opt, case_name))
            return hit.route_key if hit else None
        cands = cases_by_short.get(case_name, [])
        if len(cands) == 1:
            return cands[0].route_key
        scoped = [c for c in cands if c.enum_name in mentioned_enums]
        if len(scoped) == 1:
            return scoped[0].route_key
        return None

    for m in _SERVER_SUBSCRIPT_ENUM_RE.finditer(clean):
        rk = _resolve_enum_ref(m.group(1), m.group(2))
        if rk:
            registered.add(rk)

    for m in _SERVER_SUBSCRIPT_STR_RE.finditer(clean):
        val = m.group(1).strip()
        if val and "\\(" not in val:
            registered.add(val)

    for m in _SERVER_REG_CALL_RE.finditer(clean):
        arg_chunk = m.group(1)
        for em in re.finditer(r"(?:([A-Za-z_]\w*)\s*)?\.\s*([A-Za-z_]\w*)", arg_chunk):
            if em.group(2) == "rawValue":
                continue
            rk = _resolve_enum_ref(em.group(1), em.group(2))
            if rk:
                registered.add(rk)
        for sm in _STR_LIT_RE.finditer(arg_chunk):
            val = sm.group(1).strip()
            if val and "\\(" not in val:
                registered.add(val)

    is_server_ctx = (
        "/Server/" in f"/{rel_file}"
        or "Server" in rel_file
        or "Service" in rel_file
        or "XPCServer" in clean
    )
    if is_server_ctx:
        for m in _SWITCH_CASE_ENUM_RE.finditer(clean):
            rk = _resolve_enum_ref(m.group(1), m.group(2))
            if rk:
                registered.add(rk)
        for m in _SWITCH_CASE_STR_RE.finditer(clean):
            val = m.group(1).strip()
            if val and "\\(" not in val:
                registered.add(val)

    return registered


_XPC_SEND_VERBS: Final[frozenset[str]] = frozenset(
    {
        "send",
        "sendSync",
        "sendAsync",
        "sendMessage",
        "sendWithReply",
        "sendBarrier",
        "call",
        "request",
        "invoke",
        "withContinuation",
    }
)
_XPC_STRICT_SEND_VERBS: Final[frozenset[str]] = frozenset(
    {"send", "sendSync", "sendAsync", "sendMessage", "sendWithReply", "sendBarrier"}
)
_XPC_NON_SEND_LIFECYCLE_METHODS: Final[frozenset[str]] = frozenset(
    {
        "activate",
        "resume",
        "suspend",
        "invalidate",
        "cancel",
        "close",
        "connect",
        "disconnect",
        "setEventHandler",
        "register",
        "registerHandler",
        "setHandler",
        "on",
        "handle",
        "addRoute",
        "bindRoute",
    }
)
_C_XPC_SEND_FUNCS: Final[frozenset[str]] = frozenset(
    {
        "xpc_connection_send_message",
        "xpc_connection_send_message_with_reply",
        "xpc_connection_send_message_with_reply_sync",
    }
)
_MACH_CONN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\b(?:XPCClient|NSXPCConnection)\s*\(\s*(?:machServiceName|serviceName|service)\s*:\s*"
    r"|\bxpc_connection_create_mach_service\s*\(\s*)"
    r"([^,)\n]{1,200})"
)
_XPC_RECEIVER_INIT_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:let|var)\s+([A-Za-z_]\w*)\s*(?::\s*[^=\n]+)?=\s*(?:try\s+|await\s+)*"
    r"(?:XPCClient|XPCSession|NSXPCConnection|xpc_connection_create_mach_service)\b"
)
_XPC_TYPED_DECL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Za-z_]\w*)\s*:\s*(?:any\s+|some\s+)?([A-Za-z_][A-Za-z0-9_.]*)"
)


@dataclass(frozen=True)
class _BoundRouteValue:
    kind: Literal["static_in_repo", "external_mach", "dynamic_runtime"]
    route_key: str
    display_route: str
    enum_name: str | None = None
    is_read_only: bool = False
    proven_xpc_payload: bool = False


def _unwrap_route_arg_expr(
    raw_clean: str,
    raw_skel: str,
    local_bindings: dict[str, _BoundRouteValue],
    local_str_consts: dict[str, str],
    cases_by_enum_case: dict[tuple[str, str], XpcRouteCase],
    cases_by_short: dict[str, list[XpcRouteCase]],
    in_repo_prefixes: set[str],
    in_repo_exact: set[str],
    *,
    in_xpc_context: bool,
) -> _BoundRouteValue | None:
    c_str = raw_clean.strip()
    s_str = raw_skel.strip()
    if not c_str:
        return None

    lbl_m = re.match(r"^([A-Za-z_]\w*)\s*:\s*", s_str)
    arg_label = ""
    if lbl_m is not None:
        arg_label = lbl_m.group(1)
        c_str = c_str[lbl_m.end() :].strip()
        s_str = s_str[lbl_m.end() :].strip()
        if arg_label in ("route", "endpoint", "routeKey"):
            in_xpc_context = True
        elif arg_label in ("timeout", "qos", "flags", "queue", "replyQueue", "handler", "completion"):
            return None

    for kw in ("try?", "try!", "try", "await"):
        while s_str.startswith(kw) and (len(s_str) == len(kw) or not s_str[len(kw)].isalnum()):
            c_str = c_str[len(kw) :].lstrip()
            s_str = s_str[len(kw) :].lstrip()

    while c_str.startswith("(") and c_str.endswith(")") and find_matching_delim(s_str, 0) == len(s_str) - 1:
        c_str = c_str[1:-1].strip()
        s_str = s_str[1:-1].strip()

    # Unwrap `XPCMessage(...)` / `XPCRequest(...)` message constructors
    msg_m = re.match(r"^(?:XPCMessage|XPCRequest)\s*\(", s_str)
    if msg_m is not None:
        p_open = msg_m.end() - 1
        p_close = find_matching_delim(s_str, p_open)
        if p_close != -1:
            spans = split_top_level_spans(s_str, p_open + 1, p_close, ",")
            chosen_span: tuple[int, int] | None = None
            for sp_s, sp_e in spans:
                if re.match(r"^\s*route\s*:", s_str[sp_s:sp_e]):
                    chosen_span = (sp_s, sp_e)
                    break
            if chosen_span is None and spans:
                chosen_span = spans[0]
            if chosen_span is not None:
                inner = _unwrap_route_arg_expr(
                    c_str[chosen_span[0] : chosen_span[1]],
                    s_str[chosen_span[0] : chosen_span[1]],
                    local_bindings,
                    local_str_consts,
                    cases_by_enum_case,
                    cases_by_short,
                    in_repo_prefixes,
                    in_repo_exact,
                    in_xpc_context=True,
                )
                if inner is not None:
                    return _BoundRouteValue(
                        kind=inner.kind,
                        route_key=inner.route_key,
                        display_route=inner.display_route,
                        enum_name=inner.enum_name,
                        is_read_only=inner.is_read_only,
                        proven_xpc_payload=True,
                    )
        return None

    # Reject comparisons, closures, and collection literals as direct route values
    if s_str.startswith(("[", "{")) or "==" in s_str or "!=" in s_str:
        return None

    no_raw_c = re.sub(r"\s*\.\s*rawValue\s*$", "", c_str).strip()
    enum_m = re.match(r"^([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)$", no_raw_c)
    if enum_m is not None:
        rc = cases_by_enum_case.get((enum_m.group(1), enum_m.group(2)))
        if rc is not None:
            return _BoundRouteValue(
                kind="static_in_repo",
                route_key=rc.route_key,
                display_route=f"{rc.enum_name}.{rc.case_name}",
                enum_name=rc.enum_name,
                is_read_only=_is_read_like_name(rc.case_name) or _is_read_like_name(rc.route_key),
                proven_xpc_payload=True,
            )

    if in_xpc_context:
        short_m = re.match(r"^\.\s*([A-Za-z_]\w*)$", no_raw_c)
        if short_m is not None:
            cands = cases_by_short.get(short_m.group(1), [])
            if len(cands) == 1:
                rc0 = cands[0]
                return _BoundRouteValue(
                    kind="static_in_repo",
                    route_key=rc0.route_key,
                    display_route=f"{rc0.enum_name}.{rc0.case_name}",
                    enum_name=rc0.enum_name,
                    is_read_only=_is_read_like_name(rc0.case_name) or _is_read_like_name(rc0.route_key),
                    proven_xpc_payload=True,
                )

    str_m = _STR_LIT_RE.fullmatch(c_str)
    if str_m is not None:
        lit_val = str_m.group(1).strip()
        if not lit_val:
            return None
        if "\\(" in lit_val:
            return _BoundRouteValue(
                kind="dynamic_runtime",
                route_key=lit_val,
                display_route=lit_val,
                proven_xpc_payload=in_xpc_context,
            )
        if is_external_apple_mach_service(lit_val, in_repo_prefixes, in_repo_exact):
            return _BoundRouteValue(
                kind="external_mach",
                route_key=lit_val,
                display_route=lit_val,
                proven_xpc_payload=in_xpc_context,
            )
        return _BoundRouteValue(
            kind="static_in_repo",
            route_key=lit_val,
            display_route=lit_val,
            is_read_only=_is_read_like_name(lit_val),
            proven_xpc_payload=in_xpc_context,
        )

    ident_m = re.match(r"^([A-Za-z_]\w*)(?:\s*\.\s*rawValue)?$", c_str)
    if ident_m is not None:
        ident = ident_m.group(1)
        if ident in local_bindings:
            bound = local_bindings[ident]
            if bound.proven_xpc_payload or in_xpc_context:
                return bound
        if ident in local_str_consts and in_xpc_context:
            c_val = local_str_consts[ident]
            if is_external_apple_mach_service(c_val, in_repo_prefixes, in_repo_exact):
                return _BoundRouteValue(
                    kind="external_mach",
                    route_key=c_val,
                    display_route=c_val,
                    proven_xpc_payload=True,
                )
            return _BoundRouteValue(
                kind="static_in_repo",
                route_key=c_val,
                display_route=c_val,
                is_read_only=_is_read_like_name(c_val),
                proven_xpc_payload=True,
            )
        if in_xpc_context and ident not in ("nil", "true", "false", "Data"):
            return _BoundRouteValue(
                kind="dynamic_runtime",
                route_key=ident,
                display_route=ident,
                proven_xpc_payload=True,
            )
        return None

    if in_xpc_context:
        compact = " ".join(c_str.split())[:120]
        return _BoundRouteValue(
            kind="dynamic_runtime",
            route_key=compact,
            display_route=compact,
            proven_xpc_payload=True,
        )
    return None


def extract_client_xpc_sends(
    clean: str,
    skeleton: str,
    rel_file: str,
    nominals_in_file: list[SwiftNominalDecl],
    cases_by_enum_case: dict[tuple[str, str], XpcRouteCase],
    cases_by_short: dict[str, list[XpcRouteCase]],
    in_repo_prefixes: set[str],
    in_repo_exact: set[str],
) -> list[XpcClientSendSite]:
    """Extract proven client-side XPC transport send invocations and Mach service targets."""
    sends: list[XpcClientSendSite] = []
    enum_decl_lines: set[int] = set()
    type_by_line: dict[int, str] = {}
    file_xpc_receivers: set[str] = set()

    for decl in nominals_in_file:
        span_lines = decl.body_clean.count("\n") + 2
        if is_xpc_route_enum(decl):
            for ln in range(decl.line, decl.line + span_lines):
                enum_decl_lines.add(ln)
        elif decl.kind in ("struct", "class", "actor", "extension"):
            for ln in range(decl.line, decl.line + span_lines):
                type_by_line[ln] = decl.qualified_name
            for rx_init in _XPC_RECEIVER_INIT_RE.finditer(decl.body_clean):
                file_xpc_receivers.add(rx_init.group(1))
            for rx_td in _XPC_TYPED_DECL_RE.finditer(decl.body_skeleton):
                t_nm = rx_td.group(2)
                if "XPC" in t_nm or t_nm == "xpc_connection_t":
                    file_xpc_receivers.add(rx_td.group(1))

    local_str_consts: dict[str, str] = {}
    for cm in re.finditer(
        r'\b(?:static\s+)?let\s+([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"((?:\\.|[^"\\\n])*)"',
        clean,
    ):
        c_val = cm.group(2).strip()
        if c_val and "\\(" not in c_val:
            local_str_consts[cm.group(1)] = c_val

    has_xpc_import = bool(re.search(r"^\s*(?:@\w+\s+)*import\s+\w*XPC\w*", skeleton, re.MULTILINE))
    line_starts = [0]
    for pos_nl, ch in enumerate(skeleton):
        if ch == "\n":
            line_starts.append(pos_nl + 1)

    def _line_at(offset: int) -> int:
        return bisect_right(line_starts, offset)

    clean_lines = clean.splitlines()
    skel_lines = skeleton.splitlines()
    seen_line_routes: set[tuple[int, str]] = set()
    func_by_line: dict[int, str] = {}

    # Walk function bodies (or file-level fallback) with local binding & XPC receiver state
    regions: list[tuple[int, int, str, set[str]]] = []
    for fm in re.finditer(r"\bfunc\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(", skeleton):
        fname = fm.group(1)
        p_open = fm.end() - 1
        p_close = find_matching_delim(skeleton, p_open)
        if p_close == -1:
            continue
        param_xpc: set[str] = set()
        for td in _XPC_TYPED_DECL_RE.finditer(skeleton[p_open + 1 : p_close]):
            if "XPC" in td.group(2) or td.group(2) == "xpc_connection_t":
                param_xpc.add(td.group(1))
        brace_m = re.search(r"\{", skeleton[p_close + 1 : p_close + 240])
        if brace_m is None:
            continue
        b_open = p_close + 1 + brace_m.start()
        b_close = find_matching_delim(skeleton, b_open)
        if b_close == -1:
            continue
        for ln in range(_line_at(fm.start()), _line_at(b_close) + 1):
            func_by_line[ln] = fname
        regions.append((b_open + 1, b_close, fname, file_xpc_receivers | param_xpc))

    if not regions:
        regions.append((0, len(skeleton), "run", set(file_xpc_receivers)))

    is_transport_def_file = PurePosixPath(rel_file).name in ("XPCClient.swift", "XPCServer.swift")
    route_enum_names = {e_n for (e_n, _) in cases_by_enum_case}

    for reg_s, reg_e, func_name, seed_xpc in regions:
        if is_transport_def_file:
            continue
        reg_clean = clean[reg_s:reg_e]
        reg_skel = skeleton[reg_s:reg_e]
        xpc_receivers = set(seed_xpc)
        for rx_init in _XPC_RECEIVER_INIT_RE.finditer(reg_clean):
            xpc_receivers.add(rx_init.group(1))

        # Collect chronological local `let`/`var` bindings and `xpc_dictionary_set_string` updates
        local_bindings: dict[str, _BoundRouteValue] = {}
        assigned_vars: set[str] = set()
        for bm in re.finditer(
            r"\b(let|var)\s+([A-Za-z_]\w*)\s*(?::\s*[^=\n]+)?=\s*([^\n;]+)",
            reg_skel,
        ):
            v_name = bm.group(2)
            rhs_s_off = bm.start(3)
            rhs_e_off = bm.end(3)
            # Extend RHS if an unclosed delimiter `(` starts on the assignment line
            open_p = reg_skel.find("(", rhs_s_off, rhs_e_off)
            if open_p != -1:
                close_p = find_matching_delim(reg_skel, open_p)
                if close_p != -1 and close_p + 1 > rhs_e_off:
                    rhs_e_off = close_p + 1
            cand = _unwrap_route_arg_expr(
                reg_clean[rhs_s_off:rhs_e_off],
                reg_skel[rhs_s_off:rhs_e_off],
                local_bindings,
                local_str_consts,
                cases_by_enum_case,
                cases_by_short,
                in_repo_prefixes,
                in_repo_exact,
                in_xpc_context=False,
            )
            rel_depth = reg_skel[: bm.start()].count("{") - reg_skel[: bm.start()].count("}")
            if v_name in assigned_vars or rel_depth > 0:
                if v_name in local_bindings or cand is not None:
                    local_bindings[v_name] = _BoundRouteValue(
                        kind="dynamic_runtime",
                        route_key=v_name,
                        display_route=v_name,
                        proven_xpc_payload=local_bindings.get(
                            v_name, _BoundRouteValue("dynamic_runtime", v_name, v_name)
                        ).proven_xpc_payload
                        or bool(cand and cand.proven_xpc_payload),
                    )
            elif cand is not None:
                local_bindings[v_name] = cand
            assigned_vars.add(v_name)

        for dm in re.finditer(
            r'\bxpc_dictionary_set_string\s*\(\s*([A-Za-z_]\w*)\s*,\s*"route"\s*,\s*([^,)\n]{1,200})',
            reg_clean,
        ):
            d_var = dm.group(1)
            val_c = dm.group(2)
            val_s = reg_skel[dm.start(2) : dm.end(2)]
            cand_d = _unwrap_route_arg_expr(
                val_c,
                val_s,
                local_bindings,
                local_str_consts,
                cases_by_enum_case,
                cases_by_short,
                in_repo_prefixes,
                in_repo_exact,
                in_xpc_context=True,
            )
            if cand_d is not None:
                local_bindings[d_var] = cand_d

        # Inspect actual transport invocations `<recv>.<method>(...)` & `xpc_connection_send_message*(...)`
        for call_m in re.finditer(
            r"(?:([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*([A-Za-z_]\w*)|\b(xpc_connection_send_message(?:_with_reply(?:_sync)?)?))\s*\(",
            reg_skel,
        ):
            abs_pos = reg_s + call_m.start()
            ln_no = _line_at(abs_pos)
            if ln_no in enum_decl_lines:
                continue
            line_clean = clean_lines[ln_no - 1] if 1 <= ln_no <= len(clean_lines) else ""
            if (
                _SERVER_SUBSCRIPT_ENUM_RE.search(line_clean)
                or _SERVER_SUBSCRIPT_STR_RE.search(line_clean)
                or _SERVER_REG_CALL_RE.search(line_clean)
            ):
                continue

            p_open = call_m.end() - 1
            p_close = find_matching_delim(reg_skel, p_open)
            if p_close == -1:
                continue

            recv_chain, method_nm, c_func_nm = call_m.group(1), call_m.group(2), call_m.group(3)
            arg_spans = split_top_level_spans(reg_skel, p_open + 1, p_close, ",")
            if not arg_spans:
                continue

            resolved_val: _BoundRouteValue | None = None
            if c_func_nm in _C_XPC_SEND_FUNCS and len(arg_spans) >= 2:
                ms, me = arg_spans[1]
                resolved_val = _unwrap_route_arg_expr(
                    reg_clean[ms:me],
                    reg_skel[ms:me],
                    local_bindings,
                    local_str_consts,
                    cases_by_enum_case,
                    cases_by_short,
                    in_repo_prefixes,
                    in_repo_exact,
                    in_xpc_context=True,
                )
            elif method_nm in _XPC_SEND_VERBS:
                recv_parts = [p for p in (recv_chain or "").split(".") if p]
                recv_leaf = recv_parts[-1] if recv_parts else ""
                recv_root = recv_parts[0] if recv_parts else ""
                if recv_root in route_enum_names or "rawValue" in recv_parts:
                    continue
                is_known_xpc_recv = (
                    recv_leaf in xpc_receivers
                    or recv_root in xpc_receivers
                    or recv_leaf.lower()
                    in ("xpc", "xpcclient", "xpcconnection", "xpcsession", "xpctransport", "xpcproxy")
                    or (
                        has_xpc_import
                        and method_nm in _XPC_STRICT_SEND_VERBS
                        and recv_leaf in ("client", "connection", "session", "proxy")
                    )
                )
                for a_s, a_e in arg_spans:
                    cand_v = _unwrap_route_arg_expr(
                        reg_clean[a_s:a_e],
                        reg_skel[a_s:a_e],
                        local_bindings,
                        local_str_consts,
                        cases_by_enum_case,
                        cases_by_short,
                        in_repo_prefixes,
                        in_repo_exact,
                        in_xpc_context=is_known_xpc_recv,
                    )
                    if cand_v is not None and (is_known_xpc_recv or cand_v.proven_xpc_payload):
                        resolved_val = cand_v
                        break

            if resolved_val is None:
                continue
            owner_type = type_by_line.get(ln_no)
            if resolved_val.kind == "static_in_repo":
                if (ln_no, resolved_val.route_key) in seen_line_routes:
                    continue
                seen_line_routes.add((ln_no, resolved_val.route_key))
            sends.append(
                XpcClientSendSite(
                    caller_file=rel_file,
                    caller_type=owner_type,
                    caller_func=func_name,
                    line=ln_no,
                    kind=resolved_val.kind,
                    route_key=resolved_val.route_key,
                    display_route=resolved_val.display_route,
                    enum_name=resolved_val.enum_name,
                    is_read_only=resolved_val.is_read_only,
                )
            )

    # Mach service endpoint connections (external `com.apple.*` vs dynamic runtime)
    for idx, (c_line, _s_line) in enumerate(zip(clean_lines, skel_lines), start=1):
        if idx in enum_decl_lines:
            continue
        owner_type = type_by_line.get(idx)
        cur_fn = func_by_line.get(idx, "run")
        for mm in _MACH_CONN_RE.finditer(c_line):
            svc_arg = mm.group(1).strip()
            str_m = _STR_LIT_RE.match(svc_arg)
            svc_lit = str_m.group(1).strip() if str_m is not None else local_str_consts.get(svc_arg)
            if svc_lit is not None:
                if "\\(" in svc_lit:
                    sends.append(
                        XpcClientSendSite(
                            caller_file=rel_file,
                            caller_type=owner_type,
                            caller_func=cur_fn,
                            line=idx,
                            kind="dynamic_runtime",
                            route_key=svc_lit,
                            display_route=svc_lit,
                        )
                    )
                elif is_external_apple_mach_service(svc_lit, in_repo_prefixes, in_repo_exact):
                    sends.append(
                        XpcClientSendSite(
                            caller_file=rel_file,
                            caller_type=owner_type,
                            caller_func=cur_fn,
                            line=idx,
                            kind="external_mach",
                            route_key=svc_lit,
                            display_route=svc_lit,
                        )
                    )
            elif not is_transport_def_file:
                sends.append(
                    XpcClientSendSite(
                        caller_file=rel_file,
                        caller_type=owner_type,
                        caller_func=cur_fn,
                        line=idx,
                        kind="dynamic_runtime",
                        route_key=svc_arg,
                        display_route=svc_arg,
                    )
                )

    return sends


_PERSISTENCE_BODY_SIGNALS: Final[tuple[str, ...]] = (
    "FileManager",
    "JSONEncoder",
    "JSONDecoder",
    "PropertyListEncoder",
    "PropertyListDecoder",
    "FileHandle",
    "sqlite3",
    "ContentDigest",
    "createDirectory",
    "contentsOfDirectory",
    "write(to:",
)
_WRITE_CALL_VERBS: Final[tuple[str, ...]] = (
    "create",
    "save",
    "put",
    "write",
    "store",
    "insert",
    "update",
    "delete",
    "remove",
    "unpack",
    "ingest",
    "commit",
    "pull",
    "prepare",
    "importImage",
    "saveSnapshot",
)
_READ_CALL_VERBS: Final[tuple[str, ...]] = (
    "get",
    "load",
    "list",
    "fetch",
    "read",
    "find",
    "exists",
    "resolve",
    "digest",
    "manifest",
    "inspect",
    "lookup",
)
_STORED_PROP_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:public\s+|private\s+|internal\s+|package\s+)?(?:let|var)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_.<>?\[\]\s:]{1,64})"
)


def _is_cli_decl(decl: SwiftNominalDecl, cli_extensions: set[str]) -> bool:
    if decl.kind not in ("struct", "class", "enum"):
        return False
    if decl.qualified_name in cli_extensions or decl.name in cli_extensions:
        return True
    return any(
        c in ("ParsableCommand", "AsyncParsableCommand")
        or c.endswith((".ParsableCommand", ".AsyncParsableCommand"))
        for c in decl.conformances
    )


def _is_launch_plist_decl(decl: SwiftNominalDecl) -> bool:
    if decl.kind not in ("struct", "class", "actor"):
        return False
    low_name = decl.name.lower()
    low_file = PurePosixPath(decl.source_file).name.lower()
    if "launchplist" in low_name or "launchdplist" in low_name or "launchplist" in low_file:
        return True
    return "plist" in low_name and (
        "MachServices" in decl.body_clean or "ProgramArguments" in decl.body_clean
    )


def _is_entity_store_decl(decl: SwiftNominalDecl, cli_extensions: set[str]) -> bool:
    if decl.kind not in ("actor", "class", "struct"):
        return False
    if _is_cli_decl(decl, cli_extensions) or _is_launch_plist_decl(decl):
        return False
    low = decl.name.lower()
    if low.endswith(("client", "routes", "route", "cli", "error", "options", "config")):
        return False
    if decl.name.endswith(("Store", "StoreService")):
        return True
    if ("Persistence" in decl.source_file or "Store" in decl.source_file) and any(
        sig in decl.body_clean for sig in _PERSISTENCE_BODY_SIGNALS
    ):
        return decl.name.endswith(("Repository", "Storage", "Catalog", "Vault"))
    return False


def _is_xpc_transport_decl(decl: SwiftNominalDecl) -> bool:
    if is_xpc_route_enum(decl):
        return True
    if decl.kind not in ("struct", "class", "actor"):
        return False
    low = decl.name.lower()
    return (
        "xpcclient" in low
        or "xpcserver" in low
        or "xpchandler" in low
        or "xpcrouter" in low
        or "xpcconnection" in low
    )


def _is_service_decl(decl: SwiftNominalDecl, cli_extensions: set[str]) -> bool:
    if decl.kind not in ("actor", "class", "struct"):
        return False
    if (
        _is_cli_decl(decl, cli_extensions)
        or _is_launch_plist_decl(decl)
        or _is_entity_store_decl(decl, cli_extensions)
        or _is_xpc_transport_decl(decl)
    ):
        return False
    if decl.source_file.endswith(".grpc.swift"):
        return False
    if decl.kind == "actor":
        return True
    return decl.name.endswith(
        (
            "Service",
            "Server",
            "Manager",
            "Handler",
            "Harness",
            "Client",
            "Loader",
            "Runtime",
            "Daemon",
            "Controller",
            "Agent",
        )
    )


def _extract_nominal_columns(decl: SwiftNominalDecl) -> list[str]:
    cols: list[str] = []
    seen: set[str] = set()
    for m in _STORED_PROP_RE.finditer(decl.body_skeleton):
        pname = m.group(1).strip()
        ptype = " ".join(m.group(2).split()).strip(",{=")
        if pname == "configuration" or pname in seen:
            continue
        seen.add(pname)
        cols.append(f"{pname}:{ptype}" if ptype else pname)
        if len(cols) >= 24:
            break
    return cols


def _classify_store_edges_in_text(
    clean_body: str,
    store_name: str,
) -> tuple[bool, bool]:
    """Return `(has_read, has_write)` when `clean_body` references `store_name`."""
    if not re.search(rf"\b{re.escape(store_name)}\b", clean_body):
        return False, False
    # Identify typed variables/properties holding `store_name` (plus camelCase stem)
    var_names: set[str] = {store_name, store_name[:1].lower() + store_name[1:]}
    if store_name.endswith("Service"):
        short_s = store_name[: -len("Service")]
        var_names.add(short_s[:1].lower() + short_s[1:])
    for vm in re.finditer(
        rf"\b([A-Za-z_]\w*)\s*(?::\s*{re.escape(store_name)}\b|=\s*(?:try\s+)?(?:await\s+)?{re.escape(store_name)}\b)",
        clean_body,
    ):
        var_names.add(vm.group(1))

    has_w = False
    has_r = False
    for vn in var_names:
        for wv in _WRITE_CALL_VERBS:
            if re.search(rf"\b{re.escape(vn)}\s*\.\s*{wv}\s*\(", clean_body):
                has_w = True
                break
        for rv in _READ_CALL_VERBS:
            if re.search(rf"\b{re.escape(vn)}\s*\.\s*{rv}\s*\(", clean_body):
                has_r = True
                break
    if not has_w and not has_r:
        for wv in _WRITE_CALL_VERBS:
            if re.search(rf"\.\s*{wv}\s*\(", clean_body):
                has_w = True
                break
        has_r = True
    return has_r, has_w



def _infer_fallback_target_name(rel_file: str, manifest: PackageManifest) -> str:
    hit = manifest.resolve_target_for_file(rel_file)
    if hit is not None:
        return hit.name
    parts = PurePosixPath(rel_file).parts
    if len(parts) >= 2 and parts[0] == "Sources":
        return parts[1]
    return manifest.package_name or "SwiftTarget"


def _add_unique_edge(
    edge_list: list[AtlasEdge],
    seen_ids: set[str],
    edge: AtlasEdge,
) -> None:
    if edge.id not in seen_ids:
        seen_ids.add(edge.id)
        edge_list.append(edge)


def extract_swift_systems_repo(repo_root: Path) -> SwiftRepoExtraction:
    """Extract all 3 tiers (Truth, Manipulate, Display) and IPC/manifest findings."""
    real_root = validate_safe_directory(repo_root)
    pkg_cand = real_root / "Package.swift"
    if pkg_cand.is_symlink():
        raise ValueError("Symlink component rejected in 'Package.swift'.")
    if pkg_cand.is_file():
        manifest = parse_package_manifest(pkg_cand, repo_root=real_root)
    else:
        manifest = PackageManifest(package_name=real_root.name)

    out = SwiftRepoExtraction(manifest=manifest)
    out.notes.extend(manifest.notes)

    raw_files, excl_links, walk_notes = iter_safe_repo_files(
        real_root,
        {".swift", ".c", ".h", ".proto", ".entitlements", ".plist"},
        include_tests=False,
    )
    out.excluded_symlinks = excl_links
    out.notes.extend(walk_notes)

    active_files: list[tuple[Path, str, str]] = []
    for fpath, rel_f in raw_files:
        if rel_f == "Package.swift" or rel_f.startswith(("Tests/", "Plugins/", "Examples/")):
            continue
        tgt_decl = manifest.resolve_target_for_file(rel_f)
        if tgt_decl is not None and (tgt_decl.is_test_target or not tgt_decl.path_valid):
            continue
        t_name = _infer_fallback_target_name(rel_f, manifest)
        active_files.append((fpath, rel_f, t_name))

    in_repo_mach_exact: set[str] = set()
    in_repo_mach_prefixes: set[str] = set()
    entitlement_keys_by_nid: dict[str, set[str]] = {}
    entitlement_stem_by_nid: dict[str, str] = {}
    launchd_keys_by_nid: dict[str, set[str]] = {}

    # 1. Entitlements & launchd XML plists (Truth: entitlement_spec)
    for fpath, rel_f, _ in active_files:
        if rel_f.endswith(".entitlements"):
            try:
                pdata = parse_safe_plist_bytes(read_bounded_bytes(fpath), source_label=rel_f)
            except ValueError as exc:
                out.notes.append(f"Skipped malformed entitlements '{rel_f}': {exc}")
                continue
            ekeys = sorted(str(k) for k in pdata)
            nid = f"t:entitlements:{rel_f}"
            fname = PurePosixPath(rel_f).name
            entitlement_keys_by_nid[nid] = set(ekeys)
            entitlement_stem_by_nid[nid] = PurePosixPath(rel_f).stem
            out.truth_nodes.append(
                AtlasNode(
                    id=nid,
                    tier="truth",
                    subkind="entitlement_spec",
                    label=fname,
                    source_file=rel_f,
                    line=1,
                    role="capability_policy",
                    cluster="signing",
                    summary=f"Code-signing entitlements `{rel_f}` ({len(ekeys)} key(s)).",
                    columns=ekeys,
                )
            )
            out.truth_symbol_map[fname] = nid
        elif rel_f.endswith(".plist"):
            try:
                pdata = parse_safe_plist_bytes(read_bounded_bytes(fpath), source_label=rel_f)
            except ValueError as exc:
                out.notes.append(f"Skipped malformed plist '{rel_f}': {exc}")
                continue
            mach_dict = pdata.get("MachServices")
            lbl_val = pdata.get("Label")
            if isinstance(mach_dict, dict) or (
                isinstance(lbl_val, str) and ("ProgramArguments" in pdata or "Program" in pdata)
            ):
                mkeys = sorted(str(k) for k in mach_dict) if isinstance(mach_dict, dict) else []
                if isinstance(lbl_val, str) and lbl_val not in mkeys:
                    mkeys.append(lbl_val)
                for mk in mkeys:
                    in_repo_mach_exact.add(mk)
                    bp = _bundle_namespace_prefix(mk)
                    if bp:
                        in_repo_mach_prefixes.add(bp)
                nid = f"t:launchd:{rel_f}"
                fname = PurePosixPath(rel_f).name
                launchd_keys_by_nid[nid] = set(mkeys)
                out.truth_nodes.append(
                    AtlasNode(
                        id=nid,
                        tier="truth",
                        subkind="entitlement_spec",
                        label=fname,
                        source_file=rel_f,
                        line=1,
                        role="launchd_spec",
                        cluster="launchd",
                        summary=f"Launchd Mach service plist `{rel_f}` ({len(mkeys)} service key(s)).",
                        columns=mkeys,
                    )
                )
                out.truth_symbol_map[fname] = nid

    # 2. C FFI targets (.c / .h) & Proto / gRPC files
    c_files_by_tgt: dict[str, list[tuple[Path, str]]] = {}
    grpc_by_name: dict[str, GrpcServiceSpec] = {}
    swift_sources: list[tuple[str, str, str, str]] = []  # (rel_f, t_name, clean, skeleton)

    for fpath, rel_f, t_name in active_files:
        if rel_f.endswith((".c", ".h")):
            c_files_by_tgt.setdefault(t_name, []).append((fpath, rel_f))
        elif rel_f.endswith(".proto"):
            try:
                ptxt = read_bounded_text(fpath)
                for gspec in extract_proto_services(ptxt, rel_f, t_name):
                    prev = grpc_by_name.get(gspec.service_name)
                    if prev is None:
                        grpc_by_name[gspec.service_name] = gspec
                    else:
                        grpc_by_name[gspec.service_name] = GrpcServiceSpec(
                            service_name=gspec.service_name,
                            package_name=gspec.package_name or prev.package_name,
                            methods=tuple(dict.fromkeys([*gspec.methods, *prev.methods])),
                            source_files=tuple(dict.fromkeys([*prev.source_files, rel_f])),
                            primary_file=prev.primary_file,
                            line=prev.line,
                            target_name=prev.target_name,
                            uses_vsock=prev.uses_vsock or gspec.uses_vsock,
                        )
            except ValueError as exc:
                out.notes.append(f"Skipped malformed proto '{rel_f}': {exc}")
        elif rel_f.endswith(".swift"):
            try:
                stxt = read_bounded_text(fpath)
                clean_s, skel_s = sanitize_swift_source(stxt)
            except ValueError as exc:
                out.notes.append(f"Skipped Swift file '{rel_f}': {exc}")
                continue
            swift_sources.append((rel_f, t_name, clean_s, skel_s))
            if rel_f.endswith(".grpc.swift"):
                gspec = extract_grpc_swift_service(stxt, rel_f, t_name)
                if gspec is not None:
                    prev = grpc_by_name.get(gspec.service_name)
                    if prev is None:
                        grpc_by_name[gspec.service_name] = gspec
                    else:
                        grpc_by_name[gspec.service_name] = GrpcServiceSpec(
                            service_name=gspec.service_name,
                            package_name=prev.package_name or gspec.package_name,
                            methods=tuple(dict.fromkeys([*prev.methods, *gspec.methods])),
                            source_files=tuple(dict.fromkeys([*prev.source_files, rel_f])),
                            primary_file=rel_f,
                            line=gspec.line,
                            target_name=gspec.target_name,
                            uses_vsock=prev.uses_vsock or gspec.uses_vsock,
                        )

    return _finalize_swift_graph(
        out=out,
        c_files_by_tgt=c_files_by_tgt,
        grpc_by_name=grpc_by_name,
        swift_sources=swift_sources,
        in_repo_mach_exact=in_repo_mach_exact,
        in_repo_mach_prefixes=in_repo_mach_prefixes,
        entitlement_keys_by_nid=entitlement_keys_by_nid,
        entitlement_stem_by_nid=entitlement_stem_by_nid,
        launchd_keys_by_nid=launchd_keys_by_nid,
    )



def _finalize_swift_graph(
    *,
    out: SwiftRepoExtraction,
    c_files_by_tgt: dict[str, list[tuple[Path, str]]],
    grpc_by_name: dict[str, GrpcServiceSpec],
    swift_sources: list[tuple[str, str, str, str]],
    in_repo_mach_exact: set[str],
    in_repo_mach_prefixes: set[str],
    entitlement_keys_by_nid: dict[str, set[str]],
    entitlement_stem_by_nid: dict[str, str],
    launchd_keys_by_nid: dict[str, set[str]],
) -> SwiftRepoExtraction:
    ffi_funcs_by_tgt: dict[str, set[str]] = {}
    ffi_nid_by_tgt: dict[str, str] = {}

    for t_name, c_entries in sorted(c_files_by_tgt.items()):
        all_c_syms: list[str] = []
        primary_rel = min(c_entries, key=lambda x: (0 if x[1].endswith(".c") else 1, x[1]))[1]
        primary_line = 1
        for fpath, rel_f in c_entries:
            try:
                syms, fline = extract_c_ffi_symbols(read_bounded_text(fpath))
            except ValueError:
                continue
            if rel_f == primary_rel:
                primary_line = fline
            for s in syms:
                if s not in all_c_syms:
                    all_c_syms.append(s)
        nid = f"m:ffi:{t_name}"
        ffi_nid_by_tgt[t_name] = nid
        ffi_funcs_by_tgt[t_name] = set(all_c_syms)
        out.manip_nodes.append(
            AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="ffi_shim",
                label=t_name,
                source_file=primary_rel,
                line=primary_line,
                role="ffi_bridge",
                cluster=t_name,
                summary=f"C FFI shim target `{t_name}` ({len(all_c_syms)} C function(s)).",
                columns=all_c_syms[:32],
            )
        )

    grpc_nid_by_name: dict[str, str] = {}
    for svc_name, gspec in sorted(grpc_by_name.items()):
        nid = f"m:ipc:{svc_name}"
        grpc_nid_by_name[svc_name] = nid
        transport_tag = "vsock gRPC" if gspec.uses_vsock else "gRPC"
        out.manip_nodes.append(
            AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="ipc_handler",
                label=svc_name,
                source_file=gspec.primary_file,
                line=gspec.line,
                role="ipc_router",
                cluster=gspec.target_name,
                summary=(
                    f"{transport_tag} service `{svc_name}` ({len(gspec.methods)} RPC method(s)) "
                    f"across {', '.join(gspec.source_files)}."
                ),
                columns=list(gspec.methods[:32]),
                verification_note=f"{transport_tag} contract" if gspec.uses_vsock else None,
            )
        )

    imports_by_file: dict[str, tuple[str, list[SwiftImportRef]]] = {}
    silgens_by_file: dict[str, list[tuple[str, str, int]]] = {}
    exported_by_tgt: dict[str, set[str]] = {}
    nominals_by_file: dict[str, list[SwiftNominalDecl]] = {}
    all_nominals: list[SwiftNominalDecl] = []
    cli_extensions: set[str] = set()

    for rel_f, t_name, clean_s, skel_s in swift_sources:
        imps, sils = extract_swift_imports_and_silgen(clean_s, skel_s)
        imports_by_file[rel_f] = (t_name, imps)
        if sils:
            silgens_by_file[rel_f] = sils
        for imp in imps:
            if imp.is_exported:
                exported_by_tgt.setdefault(t_name, set()).add(imp.module_name)
        noms = extract_swift_nominals(clean_s, skel_s, rel_f, t_name)
        nominals_by_file[rel_f] = noms
        all_nominals.extend(noms)
        for d in noms:
            if d.kind == "extension" and any(
                c in ("ParsableCommand", "AsyncParsableCommand") for c in d.conformances
            ):
                cli_extensions.add(d.qualified_name)
                cli_extensions.add(d.name)

    store_decls: dict[str, SwiftNominalDecl] = {}
    cli_decls: dict[str, SwiftNominalDecl] = {}
    cli_nid_by_key: dict[str, str] = {}
    manip_decls_by_nid: dict[str, SwiftNominalDecl] = {}
    route_cases_by_enum_case: dict[tuple[str, str], XpcRouteCase] = {}
    route_cases_by_short: dict[str, list[XpcRouteCase]] = {}
    seen_node_ids: set[str] = {n.id for n in (*out.truth_nodes, *out.manip_nodes)}

    for decl in all_nominals:
        if decl.kind == "extension":
            continue
        if _is_launch_plist_decl(decl):
            nid = f"t:launchd:{decl.name}"
            if nid in seen_node_ids:
                continue
            seen_node_ids.add(nid)
            cols = _extract_nominal_columns(decl)
            for sm in _STR_LIT_RE.finditer(decl.body_clean):
                sval = sm.group(1).strip()
                if sval.startswith("com.apple.") and "\\(" not in sval:
                    bp = _bundle_namespace_prefix(sval)
                    if bp:
                        in_repo_mach_prefixes.add(bp)
                        in_repo_mach_exact.add(sval)
            launchd_keys_by_nid[nid] = {decl.name, *cols}
            out.truth_nodes.append(
                AtlasNode(
                    id=nid,
                    tier="truth",
                    subkind="entitlement_spec",
                    label=decl.name,
                    source_file=decl.source_file,
                    line=decl.line,
                    role="launchd_spec",
                    cluster=decl.target_name,
                    summary=f"Launchd plist specification `{decl.name}` in `{decl.target_name}`.",
                    columns=cols or ["Label", "MachServices", "ProgramArguments"],
                )
            )
            out.truth_symbol_map[decl.name] = nid
        elif _is_entity_store_decl(decl, cli_extensions):
            nid = f"t:store:{decl.name}"
            if nid in seen_node_ids:
                continue
            seen_node_ids.add(nid)
            store_decls[nid] = decl
            cols = _extract_nominal_columns(decl)
            out.truth_nodes.append(
                AtlasNode(
                    id=nid,
                    tier="truth",
                    subkind="entity_store",
                    label=decl.name,
                    source_file=decl.source_file,
                    line=decl.line,
                    role="persistence",
                    cluster=decl.target_name,
                    summary=f"Persistent entity/content store `{decl.name}` in `{decl.target_name}`.",
                    columns=cols,
                )
            )
            out.truth_symbol_map[decl.name] = nid
        elif _is_cli_decl(decl, cli_extensions):
            lbl = decl.qualified_name if "." in decl.qualified_name else decl.name
            nid = f"d:cli:{lbl}"
            if nid in seen_node_ids:
                continue
            seen_node_ids.add(nid)
            cli_decls[nid] = decl
            cli_nid_by_key[decl.qualified_name] = nid
            cli_nid_by_key.setdefault(decl.name, nid)
            cmd_name, _ = extract_cli_command_config(decl)
            cmd_desc = f" (`{cmd_name}`)" if cmd_name else ""
            out.disp_nodes.append(
                AtlasNode(
                    id=nid,
                    tier="display",
                    subkind="cli",
                    label=lbl,
                    source_file=decl.source_file,
                    line=decl.line,
                    role="surface",
                    cluster=decl.target_name,
                    summary=f"ArgumentParser CLI command `{lbl}`{cmd_desc} in `{decl.target_name}`.",
                )
            )
        elif _is_xpc_transport_decl(decl):
            nid = f"m:ipc:{decl.name}"
            if nid in seen_node_ids:
                continue
            seen_node_ids.add(nid)
            manip_decls_by_nid[nid] = decl
            rc_list = extract_xpc_route_cases(decl) if is_xpc_route_enum(decl) else []
            for rc in rc_list:
                route_cases_by_enum_case[(rc.enum_name, rc.case_name)] = rc
                route_cases_by_short.setdefault(rc.case_name, []).append(rc)
                in_repo_mach_exact.add(rc.route_key)
                bp = _bundle_namespace_prefix(rc.route_key)
                if bp:
                    in_repo_mach_prefixes.add(bp)
            out.manip_nodes.append(
                AtlasNode(
                    id=nid,
                    tier="manipulate",
                    subkind="ipc_handler",
                    label=decl.name,
                    source_file=decl.source_file,
                    line=decl.line,
                    role="ipc_router",
                    cluster=decl.target_name,
                    summary=(
                        f"XPC route descriptor `{decl.name}` ({len(rc_list)} route case(s))."
                        if rc_list
                        else f"XPC IPC transport handler `{decl.name}` in `{decl.target_name}`."
                    ),
                    columns=[rc.route_key for rc in rc_list[:32]],
                )
            )
        elif _is_service_decl(decl, cli_extensions):
            nid = f"m:svc:{decl.name}"
            if nid in seen_node_ids or decl.name in grpc_nid_by_name:
                continue
            seen_node_ids.add(nid)
            manip_decls_by_nid[nid] = decl
            out.manip_nodes.append(
                AtlasNode(
                    id=nid,
                    tier="manipulate",
                    subkind="service",
                    label=decl.name,
                    source_file=decl.source_file,
                    line=decl.line,
                    role="service",
                    cluster=decl.target_name,
                    summary=f"Swift systems service `{decl.name}` in `{decl.target_name}`.",
                )
            )

    _wire_swift_edges_and_rules(
        out=out,
        swift_sources=swift_sources,
        imports_by_file=imports_by_file,
        silgens_by_file=silgens_by_file,
        exported_by_tgt=exported_by_tgt,
        nominals_by_file=nominals_by_file,
        store_decls=store_decls,
        cli_decls=cli_decls,
        cli_nid_by_key=cli_nid_by_key,
        manip_decls_by_nid=manip_decls_by_nid,
        ffi_funcs_by_tgt=ffi_funcs_by_tgt,
        ffi_nid_by_tgt=ffi_nid_by_tgt,
        grpc_by_name=grpc_by_name,
        grpc_nid_by_name=grpc_nid_by_name,
        route_cases_by_enum_case=route_cases_by_enum_case,
        route_cases_by_short=route_cases_by_short,
        in_repo_mach_exact=in_repo_mach_exact,
        in_repo_mach_prefixes=in_repo_mach_prefixes,
        entitlement_keys_by_nid=entitlement_keys_by_nid,
        entitlement_stem_by_nid=entitlement_stem_by_nid,
        launchd_keys_by_nid=launchd_keys_by_nid,
    )
    return out



def _wire_swift_edges_and_rules(
    *,
    out: SwiftRepoExtraction,
    swift_sources: list[tuple[str, str, str, str]],
    imports_by_file: dict[str, tuple[str, list[SwiftImportRef]]],
    silgens_by_file: dict[str, list[tuple[str, str, int]]],
    exported_by_tgt: dict[str, set[str]],
    nominals_by_file: dict[str, list[SwiftNominalDecl]],
    store_decls: dict[str, SwiftNominalDecl],
    cli_decls: dict[str, SwiftNominalDecl],
    cli_nid_by_key: dict[str, str],
    manip_decls_by_nid: dict[str, SwiftNominalDecl],
    ffi_funcs_by_tgt: dict[str, set[str]],
    ffi_nid_by_tgt: dict[str, str],
    grpc_by_name: dict[str, GrpcServiceSpec],
    grpc_nid_by_name: dict[str, str],
    route_cases_by_enum_case: dict[tuple[str, str], XpcRouteCase],
    route_cases_by_short: dict[str, list[XpcRouteCase]],
    in_repo_mach_exact: set[str],
    in_repo_mach_prefixes: set[str],
    entitlement_keys_by_nid: dict[str, set[str]],
    entitlement_stem_by_nid: dict[str, str],
    launchd_keys_by_nid: dict[str, set[str]],
) -> None:
    seen_manip_edges: set[str] = set()
    seen_disp_edges: set[str] = set()
    clean_by_file = {rel_f: clean_s for rel_f, _, clean_s, _ in swift_sources}

    # Synthesize service node for top-level server harness files that register XPC routes
    manip_nids_by_file: dict[str, list[str]] = {}
    for mn in out.manip_nodes:
        manip_nids_by_file.setdefault(mn.source_file, []).append(mn.id)
    truth_store_nids_by_file: dict[str, list[str]] = {
        tn.source_file: [tn.id]
        for tn in out.truth_nodes
        if tn.subkind == "entity_store"
    }

    reg_routes_by_file: dict[str, set[str]] = {}
    for rel_f, t_name, clean_s, _ in swift_sources:
        regs = extract_server_registered_routes(
            clean_s, rel_f, route_cases_by_enum_case, route_cases_by_short
        )
        if regs:
            reg_routes_by_file[rel_f] = regs
            for rk in regs:
                in_repo_mach_exact.add(rk)
                bp = _bundle_namespace_prefix(rk)
                if bp:
                    in_repo_mach_prefixes.add(bp)
            if rel_f not in manip_nids_by_file and rel_f not in truth_store_nids_by_file:
                stem = PurePosixPath(rel_f).stem
                syn_id = f"m:svc:{stem}"
                if syn_id not in {n.id for n in out.manip_nodes}:
                    out.manip_nodes.append(
                        AtlasNode(
                            id=syn_id,
                            tier="manipulate",
                            subkind="service",
                            label=stem,
                            source_file=rel_f,
                            line=1,
                            role="service",
                            cluster=t_name,
                            summary=f"Swift IPC route server harness `{stem}` in `{t_name}`.",
                        )
                    )
                    manip_nids_by_file.setdefault(rel_f, []).append(syn_id)

    # 1. CLI parent -> subcommand hierarchy in disp_edges
    for p_nid, p_decl in cli_decls.items():
        _, subcmds = extract_cli_command_config(p_decl)
        for sub_raw in subcmds:
            c_nid = cli_nid_by_key.get(f"{p_decl.qualified_name}.{sub_raw}") or cli_nid_by_key.get(sub_raw)
            if c_nid and c_nid != p_nid:
                _add_unique_edge(
                    out.disp_edges,
                    seen_disp_edges,
                    AtlasEdge(
                        id=f"e:{p_nid}->{c_nid}:calls_helper",
                        source_id=p_nid,
                        target_id=c_nid,
                        kind="calls_helper",
                        verification="verified",
                        evidence_path=p_decl.source_file,
                        evidence_note=f"`{p_decl.name}` registers CLI subcommand `{sub_raw}`.",
                        symbol_links=["*->*", f"{p_decl.name}->{sub_raw}"],
                    ),
                )
        for c_nid, c_decl in cli_decls.items():
            if c_nid != p_nid and c_decl.qualified_name.startswith(f"{p_decl.qualified_name}."):
                _add_unique_edge(
                    out.disp_edges,
                    seen_disp_edges,
                    AtlasEdge(
                        id=f"e:{p_nid}->{c_nid}:calls_helper",
                        source_id=p_nid,
                        target_id=c_nid,
                        kind="calls_helper",
                        verification="verified",
                        evidence_path=c_decl.source_file,
                        evidence_note=f"Nested CLI subcommand `{c_decl.qualified_name}`.",
                        symbol_links=["*->*", f"{p_decl.name}->{c_decl.name}"],
                    ),
                )

    # 2. Store-to-store delegation map (e.g. ContentStoreService -> SnapshotStore)
    delegated_stores: dict[str, list[tuple[str, bool, bool]]] = {}
    store_name_by_nid = {nid: d.name for nid, d in store_decls.items()}
    for s1_nid, s1_decl in store_decls.items():
        for s2_nid, s2_name in store_name_by_nid.items():
            if s1_nid == s2_nid:
                continue
            hr, hw = _classify_store_edges_in_text(s1_decl.body_clean, s2_name)
            if hr or hw:
                delegated_stores.setdefault(s1_nid, []).append((s2_nid, hr, hw))

    def _emit_store_access(
        src_nid: str,
        src_label: str,
        src_file: str,
        store_nid: str,
        has_r: bool,
        has_w: bool,
        note_prefix: str = "",
    ) -> None:
        s_name = store_name_by_nid.get(store_nid, store_nid)
        if has_w:
            _add_unique_edge(
                out.manip_edges,
                seen_manip_edges,
                AtlasEdge(
                    id=f"e:{src_nid}->{store_nid}:writes_truth",
                    source_id=src_nid,
                    target_id=store_nid,
                    kind="writes_truth",
                    verification="verified",
                    evidence_path=src_file,
                    evidence_note=f"{note_prefix}`{src_label}` mutates store `{s_name}`.",
                    symbol_links=["*->*", f"{src_label}->{s_name}"],
                ),
            )
        if has_r or not has_w:
            _add_unique_edge(
                out.manip_edges,
                seen_manip_edges,
                AtlasEdge(
                    id=f"e:{src_nid}->{store_nid}:reads_truth",
                    source_id=src_nid,
                    target_id=store_nid,
                    kind="reads_truth",
                    verification="verified",
                    evidence_path=src_file,
                    evidence_note=f"{note_prefix}`{src_label}` reads store `{s_name}`.",
                    symbol_links=["*->*", f"{src_label}->{s_name}"],
                ),
            )
        for del_nid, d_r, d_w in delegated_stores.get(store_nid, ()):
            _emit_store_access(
                src_nid,
                src_label,
                src_file,
                del_nid,
                d_r,
                d_w or has_w,
                note_prefix=f"Via `{s_name}`: ",
            )

    # 3. Manipulate -> Truth (stores, entitlements, launchd) & Manipulate -> C FFI / sibling services
    manip_by_id = {m.id: m for m in out.manip_nodes}
    for mnode in list(out.manip_nodes):
        if mnode.subkind == "ffi_shim":
            continue
        mdecl = manip_decls_by_nid.get(mnode.id)
        inspect_text = mdecl.body_clean if mdecl is not None else clean_by_file.get(mnode.source_file, "")
        file_text = clean_by_file.get(mnode.source_file, inspect_text)
        _, file_imps = imports_by_file.get(mnode.source_file, (mnode.cluster, []))
        imp_names = {i.module_name for i in file_imps}

        for st_nid, st_name in store_name_by_nid.items():
            hr, hw = _classify_store_edges_in_text(inspect_text, st_name)
            if hr or hw:
                _emit_store_access(mnode.id, mnode.label, mnode.source_file, st_nid, hr, hw)

        for ent_nid, ekeys in entitlement_keys_by_nid.items():
            stem = entitlement_stem_by_nid[ent_nid]
            matched_ent = (
                (stem and stem in file_text)
                or stem == mnode.cluster
                or any(ek in file_text for ek in ekeys)
                or (
                    "Virtualization" in imp_names
                    and any("virtualization" in ek or "hypervisor" in ek for ek in ekeys)
                )
            )
            if matched_ent:
                _add_unique_edge(
                    out.manip_edges,
                    seen_manip_edges,
                    AtlasEdge(
                        id=f"e:{mnode.id}->{ent_nid}:guards_truth",
                        source_id=mnode.id,
                        target_id=ent_nid,
                        kind="guards_truth",
                        verification="verified",
                        evidence_path=mnode.source_file,
                        evidence_note=f"`{mnode.label}` binds capability entitlements `{stem}`.",
                        symbol_links=["*->*", f"{mnode.label}->{stem}"],
                    ),
                )

        for ld_nid, lkeys in launchd_keys_by_nid.items():
            ld_label = ld_nid.rsplit(":", 1)[-1]
            if re.search(rf"\b{re.escape(ld_label)}\b", inspect_text) or any(
                lk in inspect_text for lk in lkeys if "." in lk
            ):
                _add_unique_edge(
                    out.manip_edges,
                    seen_manip_edges,
                    AtlasEdge(
                        id=f"e:{mnode.id}->{ld_nid}:reads_truth",
                        source_id=mnode.id,
                        target_id=ld_nid,
                        kind="reads_truth",
                        verification="verified",
                        evidence_path=mnode.source_file,
                        evidence_note=f"`{mnode.label}` references launchd specification `{ld_label}`.",
                        symbol_links=["*->*", f"{mnode.label}->{ld_label}"],
                    ),
                )

        for c_tgt, ffi_nid in ffi_nid_by_tgt.items():
            c_syms = ffi_funcs_by_tgt.get(c_tgt, set())
            called_c = [cs for cs in sorted(c_syms) if re.search(rf"\b{re.escape(cs)}\s*\(", inspect_text)]
            if c_tgt in imp_names and (called_c or re.search(rf"\b{re.escape(c_tgt)}\b", file_text)):
                sym_tail = called_c[0] if called_c else c_tgt
                _add_unique_edge(
                    out.manip_edges,
                    seen_manip_edges,
                    AtlasEdge(
                        id=f"e:{mnode.id}->{ffi_nid}:calls_helper",
                        source_id=mnode.id,
                        target_id=ffi_nid,
                        kind="calls_helper",
                        verification="verified",
                        evidence_path=mnode.source_file,
                        evidence_note=f"`{mnode.label}` invokes C FFI shim `{c_tgt}` (`{sym_tail}`).",
                        symbol_links=["*->*", f"{mnode.label}->{sym_tail}"],
                    ),
                )

        for swift_fn, c_sym, _ in silgens_by_file.get(mnode.source_file, ()):
            matched_ffi = next(
                (ffi_nid_by_tgt[ct] for ct, cset in ffi_funcs_by_tgt.items() if c_sym in cset),
                None,
            )
            if matched_ffi is None:
                matched_ffi = f"m:ffi:{c_sym}"
                if matched_ffi not in manip_by_id:
                    ffi_node = AtlasNode(
                        id=matched_ffi,
                        tier="manipulate",
                        subkind="ffi_shim",
                        label=c_sym,
                        source_file=mnode.source_file,
                        line=mnode.line,
                        role="ffi_bridge",
                        cluster=mnode.cluster,
                        summary=f"Swift `@_silgen_name(\"{c_sym}\")` C FFI symbol shim.",
                        columns=[c_sym],
                    )
                    out.manip_nodes.append(ffi_node)
                    manip_by_id[matched_ffi] = ffi_node
            _add_unique_edge(
                out.manip_edges,
                seen_manip_edges,
                AtlasEdge(
                    id=f"e:{mnode.id}->{matched_ffi}:calls_helper",
                    source_id=mnode.id,
                    target_id=matched_ffi,
                    kind="calls_helper",
                    verification="verified",
                    evidence_path=mnode.source_file,
                    evidence_note=f"`{mnode.label}` bridges `@_silgen_name(\"{c_sym}\")` via `{swift_fn}`.",
                    symbol_links=["*->*", f"{swift_fn}->{c_sym}"],
                ),
            )

    _wire_xpc_grpc_and_manifest_rules(
        out=out,
        swift_sources=swift_sources,
        imports_by_file=imports_by_file,
        exported_by_tgt=exported_by_tgt,
        nominals_by_file=nominals_by_file,
        store_decls=store_decls,
        cli_decls=cli_decls,
        manip_decls_by_nid=manip_decls_by_nid,
        manip_nids_by_file=manip_nids_by_file,
        truth_store_nids_by_file=truth_store_nids_by_file,
        reg_routes_by_file=reg_routes_by_file,
        grpc_by_name=grpc_by_name,
        grpc_nid_by_name=grpc_nid_by_name,
        route_cases_by_enum_case=route_cases_by_enum_case,
        route_cases_by_short=route_cases_by_short,
        in_repo_mach_exact=in_repo_mach_exact,
        in_repo_mach_prefixes=in_repo_mach_prefixes,
        emit_store_access=_emit_store_access,
        seen_manip_edges=seen_manip_edges,
        seen_disp_edges=seen_disp_edges,
    )



def _wire_xpc_grpc_and_manifest_rules(
    *,
    out: SwiftRepoExtraction,
    swift_sources: list[tuple[str, str, str, str]],
    imports_by_file: dict[str, tuple[str, list[SwiftImportRef]]],
    exported_by_tgt: dict[str, set[str]],
    nominals_by_file: dict[str, list[SwiftNominalDecl]],
    store_decls: dict[str, SwiftNominalDecl],
    cli_decls: dict[str, SwiftNominalDecl],
    manip_decls_by_nid: dict[str, SwiftNominalDecl],
    manip_nids_by_file: dict[str, list[str]],
    truth_store_nids_by_file: dict[str, list[str]],
    reg_routes_by_file: dict[str, set[str]],
    grpc_by_name: dict[str, GrpcServiceSpec],
    grpc_nid_by_name: dict[str, str],
    route_cases_by_enum_case: dict[tuple[str, str], XpcRouteCase],
    route_cases_by_short: dict[str, list[XpcRouteCase]],
    in_repo_mach_exact: set[str],
    in_repo_mach_prefixes: set[str],
    emit_store_access: Any,
    seen_manip_edges: set[str],
    seen_disp_edges: set[str],
) -> None:
    manip_by_id = {m.id: m for m in out.manip_nodes}
    all_nodes_by_file: dict[str, list[str]] = {}
    first_node_by_target: dict[str, str] = {}
    for node in (*out.manip_nodes, *out.disp_nodes, *out.truth_nodes):
        all_nodes_by_file.setdefault(node.source_file, []).append(node.id)
        first_node_by_target.setdefault(node.cluster, node.id)

    handlers_by_route: dict[str, set[str]] = {}
    for rel_f, regs in reg_routes_by_file.items():
        m_cands = [
            nid
            for nid in manip_nids_by_file.get(rel_f, ())
            if not nid.startswith("m:ipc:") or nid == "m:ipc:XPCServer"
        ]
        non_srv = [nid for nid in m_cands if nid != "m:ipc:XPCServer"]
        owners = non_srv or truth_store_nids_by_file.get(rel_f) or m_cands
        for rk in regs:
            handlers_by_route.setdefault(rk, set()).update(owners)

    for rc in route_cases_by_enum_case.values():
        enum_nid = f"m:ipc:{rc.enum_name}"
        if enum_nid not in manip_by_id:
            continue
        matched = handlers_by_route.get(rc.route_key, set())
        for h_nid in sorted(matched):
            if h_nid.startswith("t:store:"):
                emit_store_access(
                    enum_nid,
                    rc.enum_name,
                    rc.source_file,
                    h_nid,
                    True,
                    not _is_read_like_name(rc.case_name),
                )
            elif h_nid != enum_nid:
                _add_unique_edge(
                    out.manip_edges,
                    seen_manip_edges,
                    AtlasEdge(
                        id=f"e:{enum_nid}->{h_nid}:calls_helper",
                        source_id=enum_nid,
                        target_id=h_nid,
                        kind="calls_helper",
                        verification="verified",
                        evidence_path=rc.source_file,
                        evidence_note=f"XPC route `{rc.enum_name}.{rc.case_name}` dispatches to `{h_nid}`.",
                        symbol_links=["*->*", f"{rc.case_name}->{h_nid.rsplit(':', 1)[-1]}"],
                    ),
                )
        if matched:
            for xp_nid in ("m:ipc:XPCClient", "m:ipc:XPCServer"):
                if xp_nid in manip_by_id and xp_nid != enum_nid:
                    _add_unique_edge(
                        out.manip_edges,
                        seen_manip_edges,
                        AtlasEdge(
                            id=f"e:{enum_nid}->{xp_nid}:calls_helper",
                            source_id=enum_nid,
                            target_id=xp_nid,
                            kind="calls_helper",
                            verification="verified",
                            evidence_path=rc.source_file,
                            evidence_note=f"`{rc.enum_name}` routes over `{xp_nid.rsplit(':', 1)[-1]}`.",
                            symbol_links=["*->*"],
                        ),
                    )

    # Link gRPC services (`SandboxContext`, `Builder`) to same-target services/stores
    for svc_name, g_nid in grpc_nid_by_name.items():
        gspec = grpc_by_name[svc_name]
        for mnode in out.manip_nodes:
            if mnode.subkind == "service" and mnode.cluster == gspec.target_name:
                mdecl = manip_decls_by_nid.get(mnode.id)
                body_t = mdecl.body_clean if mdecl else ""
                if svc_name in body_t:
                    _add_unique_edge(
                        out.manip_edges,
                        seen_manip_edges,
                        AtlasEdge(
                            id=f"e:{g_nid}->{mnode.id}:calls_helper",
                            source_id=g_nid,
                            target_id=mnode.id,
                            kind="calls_helper",
                            verification="verified",
                            evidence_path=mnode.source_file,
                            evidence_note=f"gRPC service `{svc_name}` handled by `{mnode.label}`.",
                            symbol_links=["*->*", f"{svc_name}->{mnode.label}"],
                        ),
                    )

    cli_nid_by_qual = {d.qualified_name: nid for nid, d in cli_decls.items()}
    manip_nid_by_qual = {d.qualified_name: nid for nid, d in manip_decls_by_nid.items()}
    wrapper_ipc_targets: dict[str, list[tuple[str, bool, str]]] = {}

    for rel_f, _, clean_s, skel_s in swift_sources:
        noms = nominals_by_file.get(rel_f, [])
        sends = extract_client_xpc_sends(
            clean_s,
            skel_s,
            rel_f,
            noms,
            route_cases_by_enum_case,
            route_cases_by_short,
            in_repo_prefixes=in_repo_mach_prefixes,
            in_repo_exact=in_repo_mach_exact,
        )
        for send in sends:
            caller_nid = (
                (cli_nid_by_qual.get(send.caller_type) if send.caller_type else None)
                or (manip_nid_by_qual.get(send.caller_type) if send.caller_type else None)
                or (all_nodes_by_file.get(rel_f, [None])[0])
            )
            tgt_ipc = (
                f"m:ipc:{send.enum_name}"
                if send.enum_name and f"m:ipc:{send.enum_name}" in manip_by_id
                else (
                    "m:ipc:XPCClient"
                    if "m:ipc:XPCClient" in manip_by_id
                    else ("m:ipc:XPCServer" if "m:ipc:XPCServer" in manip_by_id else None)
                )
            )
            is_disp_caller = bool(caller_nid and caller_nid.startswith("d:cli:"))
            ekind: Literal["queries_endpoint", "mutates_endpoint", "calls_helper"] = (
                ("queries_endpoint" if send.is_read_only else "mutates_endpoint")
                if is_disp_caller
                else "calls_helper"
            )

            if send.kind == "external_mach":
                out.notes.append(
                    f"Unresolved external OS Mach service '{send.route_key}' at "
                    f"{send.caller_file}:{send.line} (outside repository scope)."
                )
                if caller_nid and tgt_ipc and caller_nid != tgt_ipc:
                    target_list = out.disp_edges if is_disp_caller else out.manip_edges
                    target_seen = seen_disp_edges if is_disp_caller else seen_manip_edges
                    _add_unique_edge(
                        target_list,
                        target_seen,
                        AtlasEdge(
                            id=f"e:extmach:{caller_nid}->{tgt_ipc}:{send.line}",
                            source_id=caller_nid,
                            target_id=tgt_ipc,
                            kind=ekind,
                            verification="unverified",
                            evidence_path=send.caller_file,
                            evidence_note=f"Unresolved external OS Mach service `{send.route_key}`.",
                            symbol_links=["*->*"],
                        ),
                    )
                continue

            if send.kind == "dynamic_runtime":
                out.notes.append(
                    f"Unresolved dynamic XPC endpoint '{send.display_route}' at "
                    f"{send.caller_file}:{send.line}; runtime route cannot be statically verified."
                )
                if caller_nid and tgt_ipc and caller_nid != tgt_ipc:
                    target_list = out.disp_edges if is_disp_caller else out.manip_edges
                    target_seen = seen_disp_edges if is_disp_caller else seen_manip_edges
                    _add_unique_edge(
                        target_list,
                        target_seen,
                        AtlasEdge(
                            id=f"e:dynxpc:{caller_nid}->{tgt_ipc}:{send.line}",
                            source_id=caller_nid,
                            target_id=tgt_ipc,
                            kind=ekind,
                            verification="unverified",
                            evidence_path=send.caller_file,
                            evidence_note=f"Unresolved dynamic runtime XPC endpoint `{send.display_route}`.",
                            symbol_links=["*->*"],
                        ),
                    )
                continue

            matched_h = handlers_by_route.get(send.route_key, set())
            if not matched_h:
                out.findings.append(
                    RawCandidateFinding(
                        rule_code="IPC-001",
                        node_id=caller_nid,
                        target_node_id=tgt_ipc,
                        source_file=send.caller_file,
                        line=send.line,
                        title=(
                            f"Static in-repo XPC route `{send.display_route}` has no registered "
                            "server handler"
                        ),
                        detail=(
                            f"`{send.caller_file}:{send.line}` sends static XPC route key "
                            f"`{send.route_key}` (`{send.display_route}`), which matched zero "
                            "registered server handlers in repository scope."
                        ),
                        remediation=(
                            f"Register an XPC server handler for `{send.route_key}` or align the "
                            "client call with an active in-repo XPC route."
                        ),
                        confidence="confirmed",
                        evidence_strength="structural_match",
                    )
                )
                if caller_nid and tgt_ipc and caller_nid != tgt_ipc:
                    target_list = out.disp_edges if is_disp_caller else out.manip_edges
                    target_seen = seen_disp_edges if is_disp_caller else seen_manip_edges
                    _add_unique_edge(
                        target_list,
                        target_seen,
                        AtlasEdge(
                            id=f"e:broken:{caller_nid}->{tgt_ipc}:{send.line}",
                            source_id=caller_nid,
                            target_id=tgt_ipc,
                            kind=ekind,
                            verification="broken",
                            evidence_path=send.caller_file,
                            evidence_note=f"Unmatched static XPC route `{send.route_key}`.",
                            symbol_links=["*->*", f"{send.caller_func}->{send.display_route}"],
                        ),
                    )
                continue

            if send.enum_name is None and tgt_ipc is not None:
                if tgt_ipc == "m:ipc:XPCClient" and "m:ipc:XPCServer" in manip_by_id:
                    _add_unique_edge(
                        out.manip_edges,
                        seen_manip_edges,
                        AtlasEdge(
                            id="e:m:ipc:XPCClient->m:ipc:XPCServer:calls_helper",
                            source_id="m:ipc:XPCClient",
                            target_id="m:ipc:XPCServer",
                            kind="calls_helper",
                            verification="verified",
                            evidence_path=send.caller_file,
                            evidence_note=f"`XPCClient` dispatches `{send.route_key}` to `XPCServer`.",
                            symbol_links=["*->*"],
                        ),
                    )
                for h_nid in sorted(matched_h):
                    if h_nid.startswith("t:store:"):
                        emit_store_access(tgt_ipc, "XPCClient", send.caller_file, h_nid, True, not send.is_read_only)
                    elif h_nid != tgt_ipc:
                        _add_unique_edge(
                            out.manip_edges,
                            seen_manip_edges,
                            AtlasEdge(
                                id=f"e:{tgt_ipc}->{h_nid}:calls_helper",
                                source_id=tgt_ipc,
                                target_id=h_nid,
                                kind="calls_helper",
                                verification="verified",
                                evidence_path=send.caller_file,
                                evidence_note=f"Static XPC route `{send.route_key}` handled by `{h_nid}`.",
                                symbol_links=["*->*", f"{send.caller_func}->{h_nid.rsplit(':', 1)[-1]}"],
                            ),
                        )

            if caller_nid and tgt_ipc and caller_nid != tgt_ipc:
                if is_disp_caller:
                    _add_unique_edge(
                        out.disp_edges,
                        seen_disp_edges,
                        AtlasEdge(
                            id=f"e:{caller_nid}->{tgt_ipc}:{ekind}",
                            source_id=caller_nid,
                            target_id=tgt_ipc,
                            kind=ekind,
                            verification="verified",
                            evidence_path=send.caller_file,
                            evidence_note=f"CLI `{caller_nid}` sends XPC route `{send.display_route}`.",
                            symbol_links=["*->*", f"{send.caller_func}->{send.display_route}"],
                        ),
                    )
                else:
                    wrapper_ipc_targets.setdefault(caller_nid, []).append(
                        (tgt_ipc, send.is_read_only, send.display_route)
                    )
                    _add_unique_edge(
                        out.manip_edges,
                        seen_manip_edges,
                        AtlasEdge(
                            id=f"e:{caller_nid}->{tgt_ipc}:calls_helper",
                            source_id=caller_nid,
                            target_id=tgt_ipc,
                            kind="calls_helper",
                            verification="verified",
                            evidence_path=send.caller_file,
                            evidence_note=f"`{caller_nid}` sends XPC route `{send.display_route}`.",
                            symbol_links=["*->*", f"{send.caller_func}->{send.display_route}"],
                        ),
                    )

    _finalize_cli_grpc_and_manifest_checks(
        out=out,
        imports_by_file=imports_by_file,
        exported_by_tgt=exported_by_tgt,
        store_decls=store_decls,
        cli_decls=cli_decls,
        manip_decls_by_nid=manip_decls_by_nid,
        all_nodes_by_file=all_nodes_by_file,
        first_node_by_target=first_node_by_target,
        wrapper_ipc_targets=wrapper_ipc_targets,
        grpc_by_name=grpc_by_name,
        grpc_nid_by_name=grpc_nid_by_name,
        emit_store_access=emit_store_access,
        seen_disp_edges=seen_disp_edges,
    )



def _finalize_cli_grpc_and_manifest_checks(
    *,
    out: SwiftRepoExtraction,
    imports_by_file: dict[str, tuple[str, list[SwiftImportRef]]],
    exported_by_tgt: dict[str, set[str]],
    store_decls: dict[str, SwiftNominalDecl],
    cli_decls: dict[str, SwiftNominalDecl],
    manip_decls_by_nid: dict[str, SwiftNominalDecl],
    all_nodes_by_file: dict[str, list[str]],
    first_node_by_target: dict[str, str],
    wrapper_ipc_targets: dict[str, list[tuple[str, bool, str]]],
    grpc_by_name: dict[str, GrpcServiceSpec],
    grpc_nid_by_name: dict[str, str],
    emit_store_access: Any,
    seen_disp_edges: set[str],
) -> None:
    grpc_has_truth_edge = {
        e.source_id
        for e in out.manip_edges
        if e.kind in ("reads_truth", "writes_truth", "guards_truth")
    }
    for m_nid in list(grpc_nid_by_name.values()):
        for e in out.manip_edges:
            if e.source_id == m_nid and e.target_id in grpc_has_truth_edge:
                grpc_has_truth_edge.add(m_nid)

    for c_nid, c_decl in cli_decls.items():
        # Do not scan nested subcommand bodies twice when inspecting an enclosing root command
        own_body = c_decl.body_clean
        for other_nid, other_decl in cli_decls.items():
            if other_nid != c_nid and other_decl.qualified_name.startswith(f"{c_decl.qualified_name}."):
                own_body = own_body.replace(other_decl.body_clean, "")

        # 1. CLI -> Manipulate XPC client wrapper forwarding
        for w_nid, ipc_targets in wrapper_ipc_targets.items():
            w_decl = manip_decls_by_nid.get(w_nid)
            if w_decl is None:
                continue
            if re.search(rf"\b{re.escape(w_decl.name)}\b", own_body):
                for tgt_ipc, is_ro, disp_route in ipc_targets:
                    ekind: Literal["queries_endpoint", "mutates_endpoint"] = (
                        "queries_endpoint" if is_ro else "mutates_endpoint"
                    )
                    _add_unique_edge(
                        out.disp_edges,
                        seen_disp_edges,
                        AtlasEdge(
                            id=f"e:{c_nid}->{tgt_ipc}:{ekind}",
                            source_id=c_nid,
                            target_id=tgt_ipc,
                            kind=ekind,
                            verification="verified",
                            evidence_path=c_decl.source_file,
                            evidence_note=(
                                f"CLI `{c_decl.qualified_name}` invokes `{w_decl.name}` -> `{disp_route}`."
                            ),
                            symbol_links=["*->*", f"run->{disp_route}"],
                        ),
                    )

        # 2. CLI -> gRPC / vsock services (`SandboxContext`, `Builder`)
        for svc_name, g_nid in grpc_nid_by_name.items():
            gspec = grpc_by_name[svc_name]
            if re.search(
                rf"\b{re.escape(svc_name)}(?:AsyncClient|Client)?\b",
                own_body,
            ):
                called_rpcs = [
                    m_rpc
                    for m_rpc in gspec.methods
                    if re.search(rf"\.\s*{re.escape(m_rpc[:1].lower() + m_rpc[1:])}\s*\(", own_body)
                    or re.search(rf"\.\s*{re.escape(m_rpc)}\s*\(", own_body)
                ]
                is_ro = bool(called_rpcs) and all(_is_read_like_name(r) for r in called_rpcs)
                if not called_rpcs:
                    is_ro = _is_read_like_name(c_decl.name)
                ekind_g: Literal["queries_endpoint", "mutates_endpoint"] = (
                    "queries_endpoint" if is_ro else "mutates_endpoint"
                )
                rpc_sym = f"{svc_name}.{called_rpcs[0]}" if called_rpcs else svc_name
                _add_unique_edge(
                    out.disp_edges,
                    seen_disp_edges,
                    AtlasEdge(
                        id=f"e:{c_nid}->{g_nid}:{ekind_g}",
                        source_id=c_nid,
                        target_id=g_nid,
                        kind=ekind_g,
                        verification="verified",
                        evidence_path=c_decl.source_file,
                        evidence_note=f"CLI `{c_decl.qualified_name}` invokes gRPC service `{rpc_sym}`.",
                        symbol_links=["*->*", f"run->{rpc_sym}"],
                    ),
                )
                if g_nid not in grpc_has_truth_edge:
                    for st_nid, st_decl in store_decls.items():
                        if st_decl.target_name == gspec.target_name:
                            hr, hw = _classify_store_edges_in_text(own_body, st_decl.name)
                            if hr or hw:
                                emit_store_access(
                                    g_nid, svc_name, c_decl.source_file, st_nid, hr, hw
                                )
                                grpc_has_truth_edge.add(g_nid)

    # Mirror nested same-file CLI subcommand cross-tier edges onto @main root command if unlinked
    disp_cross_by_src: dict[str, list[AtlasEdge]] = {}
    for de in list(out.disp_edges):
        if de.target_id.startswith("m:") and de.verification == "verified":
            disp_cross_by_src.setdefault(de.source_id, []).append(de)

    for root_nid, root_decl in cli_decls.items():
        if root_nid in disp_cross_by_src or "." in root_decl.qualified_name:
            continue
        for sub_nid, sub_decl in cli_decls.items():
            if (
                sub_decl.source_file == root_decl.source_file
                and sub_decl.qualified_name.startswith(f"{root_decl.qualified_name}.")
                and sub_nid in disp_cross_by_src
            ):
                for sub_e in disp_cross_by_src[sub_nid]:
                    _add_unique_edge(
                        out.disp_edges,
                        seen_disp_edges,
                        AtlasEdge(
                            id=f"e:{root_nid}->{sub_e.target_id}:{sub_e.kind}",
                            source_id=root_nid,
                            target_id=sub_e.target_id,
                            kind=sub_e.kind,
                            verification="verified",
                            evidence_path=root_decl.source_file,
                            evidence_note=(
                                f"Root CLI `{root_decl.name}` dispatches `{sub_decl.name}` -> `{sub_e.target_id}`."
                            ),
                            symbol_links=list(sub_e.symbol_links),
                        ),
                    )

    # 3. Package.swift target dependency boundary verification (`MANIP-006`)
    if out.manifest.targets:
        seen_m006: set[tuple[str, str]] = set()
        for rel_f, (t_name, imps) in sorted(imports_by_file.items()):
            t_decl = out.manifest.targets.get(t_name)
            if t_decl is None or not t_decl.is_runtime_target:
                continue
            allowed = out.manifest.allowed_sibling_imports(t_name, exported_by_tgt)
            for imp in imps:
                callee_t = imp.module_name
                if (
                    callee_t not in out.manifest.targets
                    or callee_t == t_name
                    or callee_t in allowed
                ):
                    continue
                if out.manifest.targets[callee_t].is_test_target:
                    continue
                dedup = (rel_f, callee_t)
                if dedup in seen_m006:
                    continue
                seen_m006.add(dedup)
                file_nids = all_nodes_by_file.get(rel_f, [])
                src_nid = file_nids[0] if file_nids else first_node_by_target.get(t_name)
                dst_nid = first_node_by_target.get(callee_t)
                allowed_desc = ", ".join(f"`{d}`" for d in sorted(allowed)) or "none"
                out.findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-006",
                        node_id=src_nid,
                        target_node_id=dst_nid,
                        source_file=rel_f,
                        line=imp.line,
                        title=(
                            f"Swift target `{t_name}` imports sibling target `{callee_t}` "
                            "omitted from `Package.swift` dependencies"
                        ),
                        detail=(
                            f"`{rel_f}:{imp.line}` (`{t_name}`) imports in-repo sibling target "
                            f"`{callee_t}`, which is omitted from `{t_name}` `dependencies` "
                            f"({allowed_desc}) in `{out.manifest.manifest_rel_path}`."
                        ),
                        remediation=(
                            f"Declare `\"{callee_t}\"` in `{t_name}` `dependencies` in "
                            f"`{out.manifest.manifest_rel_path}`, or remove the undeclared import."
                        ),
                        confidence="confirmed",
                        evidence_strength="structural_match",
                    )
                )

    # 4. Update read_by_count & written_by_count on Truth nodes
    readers_by_tid: dict[str, set[str]] = {}
    writers_by_tid: dict[str, set[str]] = {}
    for me in out.manip_edges:
        if me.kind in ("reads_truth", "guards_truth"):
            readers_by_tid.setdefault(me.target_id, set()).add(me.source_id)
        elif me.kind == "writes_truth":
            writers_by_tid.setdefault(me.target_id, set()).add(me.source_id)
    for idx, tnode in enumerate(out.truth_nodes):
        rc = len(readers_by_tid.get(tnode.id, ()))
        wc = len(writers_by_tid.get(tnode.id, ()))
        if rc or wc:
            out.truth_nodes[idx] = tnode.model_copy(
                update={"read_by_count": rc, "written_by_count": wc}
            )
