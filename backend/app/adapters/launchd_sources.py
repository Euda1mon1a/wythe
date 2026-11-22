"""Static launchd declarations. No launchctl calls, shell execution, or runtime reads."""

from __future__ import annotations

import os
import plistlib
import re
import shlex
import stat
import struct
from pathlib import Path
from xml.parsers import expat
from xml.parsers.expat import ExpatError

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.deployment_sources import normalize_home
from app.adapters.plist_locations import command_locations
from app.adapters.service_sources import (
    EXCLUDED_PARTS,
    script_id,
    source_reference_with_mode,
)
from app.schemas.atlas import AtlasEdge, AtlasNode

MAX_PLIST_BYTES = 262_144
_MAX_PLIST_DEPTH = 32
_MAX_PLIST_XML_ELEMENTS = 4096
_MAX_PLIST_INT_BITS = 128
_XML_BUILTIN_ENTITIES = frozenset({"amp", "lt", "gt", "apos", "quot"})
_APPLE_PLIST_DOCTYPE_RE = re.compile(
    r"<!DOCTYPE\s+plist\s+PUBLIC\s+"
    r'["\']-//Apple(?:\s+Computer)?//DTD\s+PLIST\s+1\.0//EN["\']\s+'
    r'["\']https?://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd["\']\s*>',
    re.IGNORECASE,
)
_FORBIDDEN_XML_DECL_RE = re.compile(
    r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)\b",
    re.IGNORECASE,
)
_ENTITY_REF_RE = re.compile(r"&([A-Za-z_][A-Za-z0-9_.-]*);")
_SCRIPT_TOKEN = re.compile(r"[^\s\"'<>;|&()]+\.(?:py|sh)$")


def read_bounded_regular_bytes(path: Path, *, max_bytes: int = MAX_PLIST_BYTES) -> bytes:
    """Read a regular file safely with `O_NOFOLLOW | O_NONBLOCK` and an upper byte bound."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Not a regular file")
        if st.st_size > max_bytes:
            raise ValueError(f"File exceeds {max_bytes}-byte limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"File exceeds {max_bytes}-byte limit.")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _check_plist_scalar(val: object) -> None:
    if isinstance(val, int) and not isinstance(val, bool) and val.bit_length() > _MAX_PLIST_INT_BITS:
        raise ValueError(f"Plist integer exceeds {_MAX_PLIST_INT_BITS}-bit limit.")


def _validate_bplist_integer_widths(raw_bytes: bytes) -> None:
    if len(raw_bytes) < 40:
        raise ValueError("Malformed binary plist: truncated trailer.")
    offset_size, _ref_size, num_objects, _top_obj, offset_table_offset = struct.unpack(
        ">6xBBQQQ", raw_bytes[-32:]
    )
    if offset_size not in (1, 2, 4, 8) or num_objects > 65536:
        raise ValueError("Malformed or oversized binary plist offset table.")
    table_end = offset_table_offset + num_objects * offset_size
    if offset_table_offset < 8 or table_end > len(raw_bytes) - 32:
        raise ValueError("Malformed binary plist offset table bounds.")
    for idx in range(num_objects):
        pos = offset_table_offset + idx * offset_size
        obj_off = int.from_bytes(raw_bytes[pos : pos + offset_size], "big")
        if obj_off < 8 or obj_off >= len(raw_bytes) - 32:
            raise ValueError("Malformed binary plist object offset.")
        marker = raw_bytes[obj_off]
        if (marker & 0xF0) == 0x10 and (marker & 0x0F) > 4:
            raise ValueError("Binary plist integer object exceeds 16-byte (128-bit) limit.")


def _check_container_depth(obj: object, *, max_depth: int = _MAX_PLIST_DEPTH) -> None:
    _check_plist_scalar(obj)
    visited: set[int] = set()
    stack: list[tuple[object, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"Plist structure exceeds maximum nesting depth ({max_depth}).")
        oid = id(cur)
        if oid in visited:
            continue
        visited.add(oid)
        if len(visited) > 65536:
            raise ValueError("Plist structure exceeds maximum unique container budget.")
        if isinstance(cur, dict):
            for k, val in cur.items():
                _check_plist_scalar(k)
                _check_plist_scalar(val)
                if isinstance(val, (dict, list, tuple)) and id(val) not in visited:
                    stack.append((val, depth + 1))
        elif isinstance(cur, (list, tuple)):
            for item in cur:
                _check_plist_scalar(item)
                if isinstance(item, (dict, list, tuple)) and id(item) not in visited:
                    stack.append((item, depth + 1))


def parse_safe_plist_bytes(
    raw_bytes: bytes,
    *,
    max_bytes: int = MAX_PLIST_BYTES,
    max_depth: int = _MAX_PLIST_DEPTH,
) -> dict[str, object]:
    """Safely parse XML or binary plist bytes while rejecting XXE and deep nesting."""
    if not raw_bytes:
        raise ValueError("Empty plist.")
    if len(raw_bytes) > max_bytes:
        raise ValueError(f"Plist exceeds {max_bytes}-byte limit.")
    if raw_bytes.startswith(b"bplist"):
        _validate_bplist_integer_widths(raw_bytes)
        try:
            parsed = plistlib.loads(raw_bytes)
        except (plistlib.InvalidFileException, ValueError, RecursionError, OverflowError, MemoryError) as exc:
            raise ValueError(f"Malformed binary plist: {exc}") from exc
        _check_container_depth(parsed, max_depth=max_depth)
        if not isinstance(parsed, dict):
            raise ValueError("Plist root must be a dictionary.")
        return {str(k): v for k, v in parsed.items()}

    if b"<!entity" in raw_bytes.lower():
        raise ValueError("XML <!ENTITY declarations are forbidden in plist.")
    text = (
        raw_bytes.decode("utf-16")
        if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff"))
        else raw_bytes.decode("utf-8-sig")
    )
    cleaned = text.strip("\x00 \t\r\n")
    if not cleaned:
        raise ValueError("Empty XML plist.")
    if "\x00" in cleaned:
        raise ValueError("Refusing XML plist containing embedded NUL bytes.")
    stripped = _APPLE_PLIST_DOCTYPE_RE.sub("", cleaned, count=1)
    if _FORBIDDEN_XML_DECL_RE.search(stripped):
        raise ValueError("Refusing XML plist with forbidden DOCTYPE/ENTITY declaration (XXE).")
    for ent in _ENTITY_REF_RE.finditer(stripped):
        if ent.group(1) not in _XML_BUILTIN_ENTITIES:
            raise ValueError(f"Refusing XML plist with custom entity '&{ent.group(1)};' (XXE).")

    elem_depth = 0
    elem_count = 0
    guard = expat.ParserCreate("UTF-8")

    def _forbid(*_a: object) -> None:
        raise ValueError("Refusing XML plist DTD/entity construct (XXE protection).")

    def _forbid_ext(*_a: object) -> int:
        raise ValueError("Refusing external XML entity reference (XXE protection).")

    def _start(_n: str, _at: dict[str, str]) -> None:
        nonlocal elem_depth, elem_count
        elem_depth += 1
        elem_count += 1
        if elem_depth > max_depth + 4 or elem_count > _MAX_PLIST_XML_ELEMENTS:
            raise ValueError("Refusing excessively nested or oversized XML plist.")

    def _end(_n: str) -> None:
        nonlocal elem_depth
        elem_depth = max(0, elem_depth - 1)

    guard.StartDoctypeDeclHandler = _forbid
    guard.EntityDeclHandler = _forbid
    guard.ExternalEntityRefHandler = _forbid_ext
    guard.StartElementHandler = _start
    guard.EndElementHandler = _end
    encoded_clean = stripped.encode("utf-8")
    guard.Parse(encoded_clean, True)
    parsed = plistlib.loads(encoded_clean, fmt=plistlib.FMT_XML)
    _check_container_depth(parsed, max_depth=max_depth)
    parsed_dict = parsed if isinstance(parsed, dict) else None
    if parsed_dict is None:
        raise ValueError("Plist root must be a dictionary.")
    return {str(k): v for k, v in parsed_dict.items()}


def shell_references(text: str) -> set[str]:
    """Literal script tokens, including conditional commands, but never comments."""
    refs: set[str] = set()
    for line in text.splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            continue
        for token in tokens:
            # Shell assignments are declarations too (SCRIPT="worker.py").
            value = token.split("=", 1)[-1] if "=" in token else token
            if _SCRIPT_TOKEN.fullmatch(value):
                refs.add(value)
    return refs


def _discover_plist_files(repo_root: Path, real_root: Path) -> tuple[list[Path], bool]:
    if "\x00" in str(repo_root):
        return [], True
    try:
        if repo_root.is_symlink():
            return [], True
    except (OSError, ValueError):
        return [], True
    files: list[Path] = []
    has_unreadable = False
    walk_errors: list[OSError] = []
    for parent, dirs, names in os.walk(repo_root, followlinks=False, onerror=walk_errors.append):
        parent_path = Path(parent)
        keep: list[str] = []
        for name in sorted(dirs):
            if name in EXCLUDED_PARTS or name.startswith("."):
                continue
            if "\x00" in name or len(name.encode("utf-8", errors="surrogateescape")) > 255:
                has_unreadable = True
                continue
            dpath = parent_path / name
            try:
                within = not dpath.is_symlink() and dpath.resolve().is_relative_to(real_root)
            except (OSError, ValueError):
                within = False
            if not within:
                has_unreadable = True
                continue
            keep.append(name)
        dirs[:] = keep
        for name in sorted(names):
            if not name.endswith(".plist"):
                continue
            if "\x00" in name or len(name.encode("utf-8", errors="surrogateescape")) > 255:
                has_unreadable = True
                continue
            path = parent_path / name
            try:
                within = (
                    not path.is_symlink()
                    and path.is_file()
                    and path.resolve().is_relative_to(real_root)
                )
            except (OSError, ValueError):
                within = False
            if not within:
                has_unreadable = True
                continue
            files.append(path)
    if walk_errors:
        has_unreadable = True
    return sorted(files), has_unreadable


def add_launchd_sources(
    repo_root: Path,
    result: ManipulatorExtractionResult,
    deployments: dict[str, set[str]] | None = None,
) -> None:
    deployments = deployments or {}
    if "\x00" in str(repo_root):
        object.__setattr__(result, "coverage_complete", False)
        return
    try:
        real_root = repo_root.resolve()
    except (OSError, ValueError):
        object.__setattr__(result, "coverage_complete", False)
        return
    paths = {n.source_file for n in result.nodes if n.id.startswith("m:script:")}
    files, has_unreadable = _discover_plist_files(repo_root, real_root)
    if has_unreadable:
        object.__setattr__(result, "coverage_complete", False)
    declarations = linked = unresolved = 0
    for path in files:
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(real_root):
                object.__setattr__(result, "coverage_complete", False)
                continue
            rel = resolved.relative_to(real_root).as_posix()
        except OSError:
            object.__setattr__(result, "coverage_complete", False)
            continue
        try:
            raw = read_bounded_regular_bytes(resolved, max_bytes=MAX_PLIST_BYTES)
            data = parse_safe_plist_bytes(raw, max_bytes=MAX_PLIST_BYTES)
        except (OSError, UnicodeError, ValueError, plistlib.InvalidFileException, ExpatError, RecursionError):
            object.__setattr__(result, "coverage_complete", False)
            if "launchagents" in path.parts or "LaunchAgents" in path.parts:
                result.notes.append(
                    f"Could not parse launchd source {rel}; command evidence absent."
                )
            continue
        if not isinstance(data, dict) or not {"Program", "ProgramArguments"} & data.keys():
            continue
        declarations += 1
        nid = f"m:launchd:{rel}"
        result.nodes.append(
            AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="cli",
                label=path.stem,
                source_file=rel,
                cluster="launchd",
                summary=(
                    "Disabled launchd declaration. "
                    if data.get("Disabled") is True
                    else "Launchd command declaration. "
                )
                + "Source presence does not establish host installation, admission, or liveness.",
            )
        )
        program = data.get("Program")
        args = data.get("ProgramArguments", [])
        fields, argument_lines = (
            ({}, []) if raw.startswith(b"bplist") else command_locations(raw)
        )
        problem_line = fields.get("ProgramArguments", 1)
        problem = None
        if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
            problem = "ProgramArguments must be an array of strings."
            if isinstance(args, list):
                index = next(i for i, arg in enumerate(args) if not isinstance(arg, str))
                if index < len(argument_lines):
                    problem_line = argument_lines[index]
            args = []
        if program is not None and (not isinstance(program, str) or not program):
            problem = "Program must be a nonempty executable path."
            problem_line = fields.get("Program", 1)
            program = None
        if not problem and not program and (not args or not args[0]):
            problem = "No executable is supplied by Program or ProgramArguments."
        command = program or (args[0] if args else "")
        # Program selects the executable; argv[0] may be an arbitrary process name.
        if command.startswith(("~", "$")):
            problem = "The executable path requires expansion, but launchd does not invoke a shell."
            problem_line = (
                fields.get("Program", 1)
                if program
                else (argument_lines[0] if argument_lines else 1)
            )
        candidates = {command} if command else set()
        # Non-Python tools can load scripts too (for example a plugin flag). These
        # are references, not proof that launchd directly executes the script.
        candidates.update(a for a in args[1:] if _SCRIPT_TOKEN.fullmatch(a))
        executable = Path(command).name
        if executable in {"sh", "bash", "zsh", "dash", "ksh"}:
            for index, arg in enumerate(args[1:], 1):
                if arg.startswith("-") and "c" in arg[1:]:
                    if index + 1 < len(args):
                        candidates.update(shell_references(args[index + 1]))
                    break
            else:
                candidates.update(a for a in args[1:] if a.endswith(".sh"))
        elif re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
            # Only the interpreter's script operand matters; later args are application data.
            for index, arg in enumerate(args[1:], 1):
                if arg in {"-c", "-m", "-W", "-X"}:
                    break  # unsupported modes/options with operands remain unobserved
                if arg.startswith("-"):
                    continue
                if arg.endswith(".py"):
                    candidates.add(arg)
                    if arg.startswith(("~", "$")):
                        problem = "The Python script path is literal; launchd does not expand home or environment variables."
                        problem_line = argument_lines[index] if index < len(argument_lines) else 1
                break
        if problem:
            result.findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel,
                    line=problem_line,
                    title="Review invalid launchd command declaration",
                    detail=problem,
                    remediation="Check installation-time rendering; use concrete arguments or an explicit shell wrapper. Verify on the owning host before changing a service.",
                )
            )
        targets: dict[str, bool] = {}
        for candidate in candidates:
            mapped = deployments.get(normalize_home(candidate), set())
            if mapped:
                for m_target in mapped & paths:
                    targets[m_target] = False
            else:
                resolved = source_reference_with_mode(candidate, rel, paths)
                if resolved is not None:
                    target, mode = resolved
                    via_suffix = mode == "suffix"
                    if target not in targets:
                        targets[target] = via_suffix
                    elif not via_suffix:
                        targets[target] = False
        if not targets:
            unresolved += 1
        else:
            linked += 1
        for target, via_suffix in sorted(targets.items()):
            ev_note = (
                f"Launchd command suffix-matches `{target}` (`host_install_path_unverified`); "
                "deployed-path suffix matching does not prove host installation, launchd admission, or execution."
                if via_suffix
                else "Launchd command references a matching source path; deployed-path suffix matching does not prove execution."
            )
            result.edges.append(
                AtlasEdge(
                    id=f"e:launchd:{rel}:{target}",
                    source_id=nid,
                    target_id=script_id(target),
                    kind="calls_helper",
                    verification="declared",
                    evidence_path=f"{rel}:1",
                    evidence_note=ev_note,
                )
            )
    result.notes.append(
        f"Launchd source coverage: {declarations} declarations, {linked} with source references, "
        f"{unresolved} with external or unresolved commands. Shell variables, -m entry points, "
        "installation templates and runtime registration are not fully resolved; no services were queried."
    )
