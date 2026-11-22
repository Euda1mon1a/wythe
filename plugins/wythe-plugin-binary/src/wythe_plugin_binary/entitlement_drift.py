"""Path-safe binary/XML readers, `binary_string_witness` tagging, and `BIN-ENT-001` drift checks."""

from __future__ import annotations

import os
import plistlib
import re
import stat
import struct
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from xml.parsers import expat

MAX_BINARY_BYTES = 64 * 1024 * 1024  # 64 MiB passive read ceiling
MAX_PLIST_BYTES = 1 * 1024 * 1024  # 1 MiB XML plist ceiling
MAX_WITNESSES_PER_BINARY = 128

ACTIVE_BINARY_PATHS_VAR: ContextVar[tuple[str, ...]] = ContextVar(
    "_wythe_plugin_binary_active_paths",
    default=(),
)

NON_CERTIFICATION_NOTICE = (
    "Bounded passive binary header, symbol, witness, and entitlement evidence only — "
    "NOT an automated security audit, signature cryptographic verification, taint proof, "
    "or runtime exploitability certification (see SECURITY.md). Target binaries were never executed."
)

_OS_ROOT_SYMLINK_PREFIXES: frozenset[tuple[str, str]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)
_SKIP_REPO_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "out", "Tests", "tests"}
)
_XML_BUILTIN_ENTITIES: frozenset[str] = frozenset({"amp", "lt", "gt", "apos", "quot"})
_APPLE_PLIST_DOCTYPE_RE = re.compile(
    r"<!DOCTYPE\s+plist\s+PUBLIC\s+"
    r'"-//Apple(?:\s+Computer)?//DTD\s+PLIST\s+1\.0//EN"\s+'
    r'"https?://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd"\s*>',
    re.IGNORECASE,
)
_FORBIDDEN_XML_DECL_RE = re.compile(
    r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)\b",
    re.IGNORECASE,
)
_ENTITY_REF_RE = re.compile(r"&([A-Za-z_][A-Za-z0-9_.-]*);")


def _check_absolute_non_symlink_components(abs_path: Path, raw_label: str) -> None:
    parts = abs_path.parts
    if ".." in parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_label}'.")
    for k in range(2, len(parts) + 1):
        if k == 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES and len(parts) > 2:
            continue
        if Path(*parts[:k]).is_symlink():
            raise ValueError(f"Refusing symlinked path component in '{raw_label}'.")
    if len(parts) >= 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
        walk = Path(*parts[:2]).resolve()
        for sub in parts[2:]:
            if sub in ("", "."):
                continue
            walk = walk / sub
            if walk.is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_label}'.")


def validate_non_symlink_path(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> Path:
    """Validate every path component before `.resolve()`, rejecting symlinks fail-closed."""
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Binary artifact path must be a non-empty string without NUL bytes.")
    cand = Path(raw_str).expanduser() if raw_str.startswith("~") else Path(raw_str)
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_path}'.")
    if cand.is_symlink():
        raise ValueError(f"Refusing symlinked artifact path: '{raw_path}'.")

    if not cand.is_absolute():
        base_raw = repo_root if repo_root is not None else Path.cwd()
        if base_raw.is_absolute():
            _check_absolute_non_symlink_components(base_raw, str(base_raw))
        base_dir = base_raw.resolve()
        cur = base_dir
        for part in cand.parts:
            if part in ("", "."):
                continue
            cur = cur / part
            if cur.is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
        resolved = cur.resolve()
        if repo_root is not None and not resolved.is_relative_to(base_dir):
            raise ValueError(f"Relative binary path '{raw_path}' escapes repository root.")
        cand = cur
    else:
        _check_absolute_non_symlink_components(cand, str(raw_path))
        if repo_root is not None:
            real_root = repo_root.resolve()
            if not allow_external and not cand.resolve().is_relative_to(real_root):
                raise ValueError(
                    f"Binary artifact path '{raw_path}' escapes repository root."
                )
            for k in range(1, len(cand.parts) + 1):
                pref = Path(*cand.parts[:k])
                if pref.exists() and pref.resolve() == real_root:
                    walk = real_root
                    for part in cand.parts[k:]:
                        if part in ("", "."):
                            continue
                        walk = walk / part
                        if walk.is_symlink():
                            raise ValueError(
                                f"Refusing symlinked path component in '{raw_path}'."
                            )
                    break

    if cand.is_symlink() or not cand.exists():
        raise ValueError(f"Binary artifact '{raw_path}' must exist and must not be a symlink.")
    return cand


def read_bounded_regular_bytes(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_BINARY_BYTES,
) -> tuple[Path, bytes]:
    """Read `<= max_bytes` from an existing non-symlink regular file via `O_NOFOLLOW`."""
    cand = validate_non_symlink_path(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(cand, flags)
    except OSError as exc:
        raise ValueError(f"Cannot safely open artifact '{raw_path}': {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Artifact '{raw_path}' must be a regular file.")
        if st.st_size > max_bytes:
            raise ValueError(
                f"Artifact '{raw_path}' ({st.st_size} bytes) exceeds {max_bytes}-byte limit."
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
            raise ValueError(f"Artifact '{raw_path}' exceeds {max_bytes}-byte limit.")
    finally:
        os.close(fd)
    return cand.resolve(), data


def collect_target_artifact_files(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_files: int = 64,
) -> list[Path]:
    """Resolve a regular file, `.app`/`.xpc` bundle, or unpacked ELF directory without symlinks."""
    cand = validate_non_symlink_path(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    lstat_res = os.lstat(cand)
    if stat.S_ISLNK(lstat_res.st_mode):
        raise ValueError(f"Refusing symlinked artifact '{raw_path}'.")
    if stat.S_ISREG(lstat_res.st_mode):
        return [cand]
    if not stat.S_ISDIR(lstat_res.st_mode):
        raise ValueError(f"Artifact '{raw_path}' must be a regular file or directory.")

    collected: list[Path] = []
    is_bundle = cand.name.lower().endswith((".app", ".xpc"))

    def _walk_strict_dir(cur_dir: Path, depth: int) -> None:
        if depth > 8 or len(collected) >= max_files:
            return
        with os.scandir(cur_dir) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            if entry.is_symlink():
                raise ValueError(
                    f"Refusing symlinked interior entry '{entry.path}' under '{raw_path}'."
                )
            if entry.is_dir(follow_symlinks=False):
                _walk_strict_dir(Path(entry.path), depth + 1)
            elif entry.is_file(follow_symlinks=False):
                p = Path(entry.path)
                if is_bundle:
                    parts = p.relative_to(cand).parts
                    if (
                        len(parts) >= 2
                        and parts[-2] == "MacOS"
                        and "Contents" in parts
                    ):
                        collected.append(p)
                elif not p.name.endswith((".capabilities", ".xattr.json", "Info.plist")):
                    collected.append(p)
            if len(collected) >= max_files:
                return

    _walk_strict_dir(cand, 0)
    return collected


def parse_safe_entitlements_xml(raw_xml: bytes | str) -> dict[str, Any]:
    """Safely parse a macOS XML entitlements plist while rejecting all XXE / DTD entity attacks."""
    if isinstance(raw_xml, bytes):
        data = raw_xml
        if len(data) >= 8:
            magic, blob_len = struct.unpack_from(">II", data, 0)
            if magic == 0xFADE7171:
                if blob_len < 8 or blob_len > len(data):
                    raise ValueError("Truncated CSMAGIC_EMBEDDED_ENTITLEMENTS header.")
                data = data[8:blob_len]
        if len(data) > MAX_PLIST_BYTES:
            raise ValueError(f"Entitlements XML exceeds {MAX_PLIST_BYTES}-byte limit.")
        if data.startswith(b"bplist"):
            raise ValueError("Binary plist format is rejected; expected XML entitlements plist.")
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        else:
            text = data.decode("utf-8-sig")
    else:
        if len(raw_xml.encode("utf-8")) > MAX_PLIST_BYTES:
            raise ValueError(f"Entitlements XML exceeds {MAX_PLIST_BYTES}-byte limit.")
        text = raw_xml

    cleaned_lines: list[str] = []
    saw_xml_start = False
    for line in text.splitlines():
        s_line = line.strip()
        if not saw_xml_start and s_line.startswith("Executable="):
            continue
        if "<" in s_line:
            saw_xml_start = True
        if saw_xml_start or s_line:
            cleaned_lines.append(line)
    xml_text = "\n".join(cleaned_lines).strip("\x00 \t\r\n")
    if not xml_text:
        return {}
    if "\x00" in xml_text:
        raise ValueError("Refusing XML plist containing embedded NUL bytes.")

    stripped_doctype = _APPLE_PLIST_DOCTYPE_RE.sub("", xml_text, count=1)
    if _FORBIDDEN_XML_DECL_RE.search(stripped_doctype):
        raise ValueError(
            "Refusing XML plist with forbidden DOCTYPE/ENTITY declaration (XXE protection)."
        )
    for ent_match in _ENTITY_REF_RE.finditer(stripped_doctype):
        if ent_match.group(1) not in _XML_BUILTIN_ENTITIES:
            raise ValueError(
                f"Refusing XML plist with custom entity reference '&{ent_match.group(1)};' (XXE)."
            )

    depth = 0
    elem_count = 0
    guard = expat.ParserCreate("UTF-8")

    def _on_doctype(_name: str, _sysid: str | None, _pubid: str | None, has_subset: int) -> None:
        if has_subset:
            raise ValueError("Refusing XML plist with internal DTD subset (XXE protection).")
        raise ValueError("Unexpected DOCTYPE remaining after Apple plist header normalization.")

    def _on_entity(*_args: object) -> None:
        raise ValueError("Refusing XML plist containing <!ENTITY declaration (XXE protection).")

    def _on_ext_ref(*_args: object) -> int:
        raise ValueError("Refusing external XML entity reference (XXE protection).")

    def _on_start(_name: str, _attrs: dict[str, str]) -> None:
        nonlocal depth, elem_count
        depth += 1
        elem_count += 1
        if depth > 32 or elem_count > 4096:
            raise ValueError("Refusing excessively nested or oversized XML plist.")

    def _on_end(_name: str) -> None:
        nonlocal depth
        depth = max(0, depth - 1)

    guard.StartDoctypeDeclHandler = _on_doctype
    guard.EntityDeclHandler = _on_entity
    guard.ExternalEntityRefHandler = _on_ext_ref
    guard.StartElementHandler = _on_start
    guard.EndElementHandler = _on_end
    try:
        guard.Parse(stripped_doctype.encode("utf-8"), True)
        parsed = plistlib.loads(stripped_doctype.encode("utf-8"), fmt=plistlib.FMT_XML)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Invalid entitlements XML plist: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("Entitlements XML plist root must be a <dict>.")  # noqa: TRY004
    return {str(k): v for k, v in parsed.items()}


WitnessCategory = Literal["http_route", "xpc_mach_service", "sql_snippet", "grpc_method"]


@dataclass(frozen=True)
class BinaryStringWitness:
    """Uncorroborated read-only literal extracted from `__cstring` or `.rodata`."""

    value: str
    category: WitnessCategory
    section: str
    kind: Literal["binary_string_witness"] = "binary_string_witness"
    verification: Literal["unverified"] = "unverified"


_GRPC_METHOD_RE = re.compile(
    r"^/[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_.]+/[A-Za-z_][A-Za-z0-9_]*$"
)
_HTTP_PREFIX_RE = re.compile(
    r"^(?:(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?/(?:api|v[0-9]+|containers|images|networks|volumes|healthz|sandbox|rpc)(?:/[A-Za-z0-9_{}.:-]+)*$"
)
_MACH_SERVICE_RE = re.compile(
    r"^(?:com|org|io|net)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}$"
)
def _looks_like_sql_snippet(s: str) -> bool:
    norm = " ".join(s.upper().split())
    if norm.startswith(("CREATE TABLE ", "ALTER TABLE ", "INSERT INTO ", "DELETE FROM ")):
        return True
    if norm.startswith("SELECT ") and " FROM " in norm:
        return True
    return norm.startswith("UPDATE ") and " SET " in norm


_NON_SERVICE_APPLE_PREFIXES: tuple[str, ...] = (
    "com.apple.security.",
    "com.apple.developer.",
    "com.apple.vm.",
    "com.apple.private.security.",
    "com.apple.application-identifier",
)


def classify_string_witness(raw: str) -> WitnessCategory | None:
    """Classify a single bounded string literal, returning `None` for ordinary strings."""
    s = raw.strip()
    if len(s) < 4 or len(s) > 320 or "\n" in s or "\r" in s:
        return None
    if _GRPC_METHOD_RE.match(s):
        return "grpc_method"
    if _HTTP_PREFIX_RE.match(s):
        return "http_route"
    if _looks_like_sql_snippet(s):
        return "sql_snippet"
    if (
        _MACH_SERVICE_RE.match(s)
        and not s.startswith(_NON_SERVICE_APPLE_PREFIXES)
        and not s.endswith((".dylib", ".so", ".swift", ".c", ".h", ".plist", ".entitlements"))
    ):
        return "xpc_mach_service"
    return None


def extract_binary_string_witnesses(
    strings: Sequence[str],
    *,
    section: str,
    max_witnesses: int = MAX_WITNESSES_PER_BINARY,
) -> tuple[BinaryStringWitness, ...]:
    """Extract deduplicated `binary_string_witness` items strictly marked `unverified`."""
    out: list[BinaryStringWitness] = []
    seen: set[tuple[str, str]] = set()
    for s in strings:
        cat = classify_string_witness(s)
        if cat is None:
            continue
        clean_val = s.strip()
        key = (cat, clean_val)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            BinaryStringWitness(
                value=clean_val,
                category=cat,
                section=section,
                kind="binary_string_witness",
                verification="unverified",
            )
        )
        if len(out) >= max_witnesses:
            break
    return tuple(out)


@dataclass(frozen=True)
class SourceEntitlementSpec:
    """Parsed source `.entitlements` plist inside `repo_root`."""

    rel_path: str
    stem: str
    entitlements: dict[str, Any]


@dataclass(frozen=True)
class SliceEntitlementDrift:
    """Architecture-qualified entitlement comparison for a single Mach-O slice."""

    architecture: str
    has_entitlements_blob: bool
    drift_status: Literal["clean", "exceeded", "omitted_only", "no_entitlements", "unverified"]
    undeclared_privileges: tuple[str, ...]
    omitted_capabilities: tuple[str, ...]


@dataclass(frozen=True)
class EntitlementDriftResult:
    """Comparison of signed binary entitlements/capabilities against source `.entitlements`."""

    matched_source_file: str | None
    drift_status: Literal["clean", "exceeded", "omitted_only", "no_entitlements", "unverified"]
    undeclared_privileges: tuple[str, ...]
    omitted_capabilities: tuple[str, ...]
    categorized_privileges: dict[str, list[str]]
    warning_notes: tuple[str, ...]
    slice_drift: dict[str, SliceEntitlementDrift] = field(default_factory=dict)


_RESTRICTIVE_TRUE_ENTITLEMENT_KEYS: frozenset[str] = frozenset(
    {
        "com.apple.security.app-sandbox",
        "com.apple.security.cs.hardened-runtime",
        "com.apple.security.library-validation",
    }
)


_BENIGN_SIGNING_IDENTITY_KEYS: frozenset[str] = frozenset(
    {
        "application-identifier",
        "com.apple.application-identifier",
        "com.apple.developer.team-identifier",
    }
)


def categorize_entitlement_key(key: str) -> str:
    """Classify macOS `codesign` entitlement or Linux capability keys into privilege families."""
    k = key.strip()
    if k.startswith(("CAP_", "cap_")):
        return "linux_capability"
    if k in (
        "com.apple.security.app-sandbox",
        "com.apple.private.security.no-sandbox",
    ) or k.startswith("com.apple.security.temporary-exception."):
        return "sandbox"
    if k in ("com.apple.security.virtualization", "com.apple.vm.hypervisor", "com.apple.vm.device-access"):
        return "virtualization"
    if k in (
        "com.apple.vm.networking",
        "com.apple.developer.networking.vmnet",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    ):
        return "vm_networking"
    if k.startswith("com.apple.security.cs.") or k == "com.apple.security.get-task-allow":
        return "hardened_runtime"
    if k.startswith(("com.apple.security.device.", "com.apple.security.personal-information.", "com.apple.security.automation.", "com.apple.security.files.")):
        return "tcc_privacy"
    return "other"


def _norm_stem(raw: str) -> str:
    base = raw.lower()
    for suf in (".entitlements", ".plist", ".app", ".xpc", ".dylib", ".so", ".bin", ".otool", ".codesign", ".xml", ".readelf", ".json"):
        base = base.removesuffix(suf)
    return re.sub(r"[^a-z0-9]+", "", base)


def discover_repo_entitlements(repo_root: Path) -> list[SourceEntitlementSpec]:
    """Discover non-symlink `*.entitlements` (and Linux `.capabilities`) plists in `repo_root`."""
    if not repo_root.exists():
        return []
    validate_non_symlink_path(repo_root)
    real_root = repo_root.resolve()
    found: list[SourceEntitlementSpec] = []

    def _scan(cur: Path, depth: int) -> None:
        if depth > 6 or len(found) >= 64:
            return
        try:
            with os.scandir(cur) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in _SKIP_REPO_DIRS:
                continue
            if entry.is_symlink():
                if entry.name.endswith(".entitlements") or entry.name == "signing":
                    raise ValueError(f"Refusing symlinked entitlements path: '{entry.path}'.")
                continue
            if entry.is_dir(follow_symlinks=False):
                _scan(Path(entry.path), depth + 1)
            elif entry.is_file(follow_symlinks=False) and entry.name.endswith(".entitlements"):
                p = Path(entry.path)
                rel = p.resolve().relative_to(real_root).as_posix()
                _, raw_bytes = read_bounded_regular_bytes(
                    p, repo_root=real_root, max_bytes=MAX_PLIST_BYTES
                )
                ent_map = parse_safe_entitlements_xml(raw_bytes)
                found.append(
                    SourceEntitlementSpec(
                        rel_path=rel,
                        stem=p.stem,
                        entitlements=ent_map,
                    )
                )

    _scan(real_root, 0)
    found.sort(key=lambda s: s.rel_path)
    return found


def _clean_priv_str(val: object) -> str:
    raw = str(val).strip()
    return "".join(ch for ch in raw if ord(ch) >= 0x20 and ord(ch) != 0x7F)[:256]


def _active_privilege_tokens(entitlements: dict[str, Any], linux_caps: Sequence[str]) -> set[str]:
    tokens: set[str] = set()
    for k, v in entitlements.items():
        clean_k = _clean_priv_str(k)
        if not clean_k or clean_k in _BENIGN_SIGNING_IDENTITY_KEYS:
            continue
        if isinstance(v, bool):
            if v:
                tokens.add(clean_k)
        elif isinstance(v, (list, tuple)):
            for item in v:
                tokens.add(f"{clean_k}={_clean_priv_str(item)}")
        elif v is not None and _clean_priv_str(v):
            tokens.add(f"{clean_k}={_clean_priv_str(v)}")
    for cap in linux_caps:
        clean_c = _clean_priv_str(cap).upper()
        if clean_c:
            tokens.add(clean_c if clean_c.startswith("CAP_") else f"CAP_{clean_c}")
    return tokens


def match_source_entitlement_spec(
    artifact_name: str,
    specs: Sequence[SourceEntitlementSpec],
    *,
    binary_format: Literal["macho", "elf"] = "macho",
) -> SourceEntitlementSpec | None:
    """Match a binary name or bundle against discovered `SourceEntitlementSpec`s."""
    if not specs:
        return None
    norm_bin = _norm_stem(artifact_name)
    for spec in specs:
        if _norm_stem(spec.stem) == norm_bin:
            return spec
    _plat_suffixes = ("linux", "macos", "darwin", "arm64", "arm64e", "x8664", "x86_64", "universal")

    def _strip_plat(stem_val: str) -> str:
        cur = stem_val
        for suf in _plat_suffixes:
            if cur.endswith(suf) and len(cur) > len(suf) + 2:
                cur = cur[: -len(suf)]
        return cur

    stripped_bin = _strip_plat(norm_bin)
    for spec in specs:
        ns = _strip_plat(_norm_stem(spec.stem))
        if ns and stripped_bin and ns == stripped_bin:
            return spec
    return None


def aggregate_slice_entitlements_conservatively(
    slice_entitlements: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate per-slice Mach-O entitlements conservatively and invariant to slice order."""
    if not slice_entitlements:
        return {}
    ordered_arches = sorted(slice_entitlements)
    all_keys = sorted({str(k) for arch in ordered_arches for k in slice_entitlements[arch]})
    merged: dict[str, Any] = {}
    for key in all_keys:
        present_vals = [slice_entitlements[a][key] for a in ordered_arches if key in slice_entitlements[a]]
        if key in _RESTRICTIVE_TRUE_ENTITLEMENT_KEYS:
            merged[key] = all(slice_entitlements[a].get(key) is True for a in ordered_arches)
        elif present_vals and all(isinstance(v, bool) for v in present_vals):
            merged[key] = any(v is True for v in present_vals)
        elif any(isinstance(v, (list, tuple)) for v in present_vals):
            items_by_repr: dict[str, Any] = {}
            for val in present_vals:
                seq = val if isinstance(val, (list, tuple)) else [val]
                for item in seq:
                    items_by_repr.setdefault(_clean_priv_str(item), item)
            merged[key] = [items_by_repr[rk] for rk in sorted(items_by_repr)]
        elif present_vals:
            by_str: dict[str, Any] = {_clean_priv_str(v): v for v in present_vals}
            if len(by_str) == 1:
                merged[key] = next(iter(by_str.values()))
            else:
                merged[key] = [by_str[sk] for sk in sorted(by_str)]
    return merged


def _evaluate_single_map_drift(
    *,
    signed_entitlements: Mapping[str, Any],
    linux_capabilities: Sequence[str],
    matched: SourceEntitlementSpec | None,
    binary_format: Literal["macho", "elf"],
) -> tuple[
    Literal["clean", "exceeded", "omitted_only", "no_entitlements"],
    tuple[str, ...],
    tuple[str, ...],
    set[str],
]:
    bin_tokens = _active_privilege_tokens(dict(signed_entitlements), linux_capabilities)
    if matched is None:
        if not bin_tokens:
            return "no_entitlements", (), (), bin_tokens
        return "exceeded", tuple(sorted(bin_tokens)), (), bin_tokens

    src_linux = matched.entitlements.get("linux.capabilities")
    src_caps = [str(x) for x in src_linux] if isinstance(src_linux, list) else []
    src_ent_filtered = (
        {k: v for k, v in matched.entitlements.items() if k != "linux.capabilities"}
        if binary_format == "macho"
        else {}
    )
    src_tokens = _active_privilege_tokens(src_ent_filtered, src_caps)

    undeclared = set(bin_tokens - src_tokens)
    omitted = set(src_tokens - bin_tokens)

    if binary_format == "macho":
        for rk in _RESTRICTIVE_TRUE_ENTITLEMENT_KEYS:
            if matched.entitlements.get(rk) is True and signed_entitlements.get(rk) is not True:
                undeclared.add(f"{rk}=disabled")
                omitted.discard(rk)

    if undeclared:
        state: Literal["clean", "exceeded", "omitted_only", "no_entitlements"] = "exceeded"
    elif omitted:
        state = "omitted_only"
    else:
        state = "clean"
    return state, tuple(sorted(undeclared)), tuple(sorted(omitted)), bin_tokens


def evaluate_entitlement_drift(
    *,
    artifact_name: str,
    signed_entitlements: dict[str, Any],
    linux_capabilities: Sequence[str],
    source_specs: Sequence[SourceEntitlementSpec],
    binary_format: Literal["macho", "elf"] = "macho",
    slice_entitlements: Mapping[str, Mapping[str, Any]] | None = None,
    slice_has_entitlements_blob: Mapping[str, bool] | None = None,
    slice_der_only_entitlements: Mapping[str, bool] | None = None,
) -> EntitlementDriftResult:
    """Compare embedded `codesign` entitlements & ELF capabilities against source `.entitlements`."""
    matched = match_source_entitlement_spec(
        artifact_name, source_specs, binary_format=binary_format
    )
    der_flags = slice_der_only_entitlements or {}

    if binary_format == "macho" and slice_entitlements:
        ordered_arches = sorted(slice_entitlements)
        slice_drift_map: dict[str, SliceEntitlementDrift] = {}
        union_tokens: set[str] = set()
        blob_flags = slice_has_entitlements_blob or {}
        any_slice_sandboxed = any(
            slice_entitlements[a].get("com.apple.security.app-sandbox") is True
            for a in ordered_arches
        )
        der_only_arches: list[str] = []

        for arch in ordered_arches:
            s_ent = slice_entitlements[arch]
            s_der_only = bool(der_flags.get(arch, False)) and not s_ent
            s_state: Literal["clean", "exceeded", "omitted_only", "no_entitlements", "unverified"]
            s_state, s_undecl, s_omit, s_toks = _evaluate_single_map_drift(
                signed_entitlements=s_ent,
                linux_capabilities=(),
                matched=matched,
                binary_format="macho",
            )
            union_tokens.update(s_toks)
            if (
                len(ordered_arches) > 1
                and any_slice_sandboxed
                and s_ent.get("com.apple.security.app-sandbox") is not True
                and "com.apple.security.app-sandbox=disabled" not in s_undecl
            ):
                s_undecl = tuple(sorted({*s_undecl, "com.apple.security.app-sandbox=disabled"}))
                s_state = "exceeded"
            if s_der_only:
                der_only_arches.append(arch)
                if s_state != "exceeded":
                    s_state = "unverified"
            has_blob = blob_flags.get(arch, bool(s_ent))
            slice_drift_map[arch] = SliceEntitlementDrift(
                architecture=arch,
                has_entitlements_blob=has_blob,
                drift_status=s_state,
                undeclared_privileges=s_undecl,
                omitted_capabilities=s_omit,
            )

        categorized: dict[str, list[str]] = {}
        for tok in sorted(union_tokens):
            key_head = tok.split("=", 1)[0]
            cat = categorize_entitlement_key(key_head)
            categorized.setdefault(cat, []).append(tok)

        is_multi = len(ordered_arches) > 1
        undecl_acc: list[str] = []
        omit_acc: list[str] = []
        for arch in ordered_arches:
            sd = slice_drift_map[arch]
            for up in sd.undeclared_privileges:
                undecl_acc.append(f"{arch}: {up}" if is_multi else up)
            for om in sd.omitted_capabilities:
                omit_acc.append(f"{arch}: {om}" if is_multi else om)

        warnings: list[str] = []
        if omit_acc and matched is not None:
            warnings.append(
                f"BIN-ENT-001 warning: binary '{artifact_name}' omits declared capability "
                f"key(s) {sorted(omit_acc)} from '{matched.rel_path}'."
            )
        if der_only_arches:
            warnings.append(
                f"BIN-ENT-001 unverified: binary '{artifact_name}' slices {der_only_arches} carry "
                "DER-only entitlements blobs (0xFADE7172 / CSSLOT_DER_ENTITLEMENTS=7) without an XML "
                "plist; static privilege claims remain unverified."
            )

        agg_status: Literal["clean", "exceeded", "omitted_only", "no_entitlements", "unverified"]
        if undecl_acc or any(sd.drift_status == "exceeded" for sd in slice_drift_map.values()):
            agg_status = "exceeded"
        elif any(sd.drift_status == "unverified" for sd in slice_drift_map.values()):
            agg_status = "unverified"
        elif omit_acc or any(sd.drift_status == "omitted_only" for sd in slice_drift_map.values()):
            agg_status = "omitted_only"
        elif all(sd.drift_status == "no_entitlements" for sd in slice_drift_map.values()):
            agg_status = "no_entitlements"
        else:
            agg_status = "clean"

        return EntitlementDriftResult(
            matched_source_file=matched.rel_path if matched is not None else None,
            drift_status=agg_status,
            undeclared_privileges=tuple(dict.fromkeys(undecl_acc)),
            omitted_capabilities=tuple(dict.fromkeys(omit_acc)),
            categorized_privileges=categorized,
            warning_notes=tuple(warnings),
            slice_drift=slice_drift_map,
        )

    drift_state: Literal["clean", "exceeded", "omitted_only", "no_entitlements", "unverified"]
    drift_state, undecl_t, omit_t, bin_tokens = _evaluate_single_map_drift(
        signed_entitlements=signed_entitlements,
        linux_capabilities=linux_capabilities,
        matched=matched,
        binary_format=binary_format,
    )
    single_der_only = any(der_flags.values()) and not signed_entitlements
    if single_der_only and drift_state != "exceeded":
        drift_state = "unverified"
    categorized_single: dict[str, list[str]] = {}
    for tok in sorted(bin_tokens):
        key_head = tok.split("=", 1)[0]
        cat = categorize_entitlement_key(key_head)
        categorized_single.setdefault(cat, []).append(tok)

    warnings_single: list[str] = []
    if omit_t and matched is not None:
        warnings_single.append(
            f"BIN-ENT-001 warning: binary '{artifact_name}' omits declared capability "
            f"key(s) {list(omit_t)} from '{matched.rel_path}'."
        )
    if single_der_only:
        warnings_single.append(
            f"BIN-ENT-001 unverified: binary '{artifact_name}' carries DER-only entitlements "
            "without an XML plist; static privilege claims remain unverified."
        )

    return EntitlementDriftResult(
        matched_source_file=matched.rel_path if matched is not None else None,
        drift_status=drift_state,
        undeclared_privileges=undecl_t,
        omitted_capabilities=omit_t,
        categorized_privileges=categorized_single,
        warning_notes=tuple(warnings_single),
    )
