"""Safe read-only artifact I/O and Unified Symbol Resolution (`USR`) index parser.

Parses pre-captured `IndexStoreDB`, `swift-symbolgraph`, and `clangd` symbol/occurrence
dumps (JSON, JSONL, TSV, YAML, or directory of dumps) without invoking `swiftc`, `clang`,
or external build tools.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

MAX_ARTIFACT_BYTES: Final[int] = 32 * 1024 * 1024
MAX_NESTING_DEPTH: Final[int] = 64
MAX_LINE_CHARS: Final[int] = 8192
MAX_TOTAL_USR_RELATIONS: Final[int] = 16384
MAX_TOTAL_USR_ENTRIES: Final[int] = 16384

_OS_ROOT_SYMLINK_PREFIXES: Final[frozenset[tuple[str, str]]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)
_IGNORED_WALK_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".build",
        "DerivedData",
        "ui_dist",
    }
)
# Official swiftlang/indexstore-db `CIndexStoreDB.h` (`indexstoredb_symbol_role_t`) bitmask:
_INDEXSTOREDB_ROLE_BITS: Final[tuple[tuple[int, str], ...]] = (
    (1 << 0, "declaration"),        # 1
    (1 << 1, "definition"),         # 2
    (1 << 2, "reference"),          # 4
    (1 << 3, "read"),               # 8
    (1 << 4, "write"),              # 16
    (1 << 5, "call"),               # 32
    (1 << 6, "dynamic"),            # 64
    (1 << 7, "addressOf"),          # 128
    (1 << 8, "implicit"),           # 256
    (1 << 9, "childOf"),            # 512
    (1 << 10, "baseOf"),            # 1024
    (1 << 11, "overrideOf"),        # 2048
    (1 << 12, "receivedBy"),        # 4096
    (1 << 13, "calledBy"),          # 8192
    (1 << 14, "extendedBy"),        # 16384
    (1 << 15, "accessorOf"),        # 32768
    (1 << 16, "containedBy"),       # 65536
    (1 << 17, "ibTypeOf"),          # 131072
    (1 << 18, "specializationOf"),  # 262144
)
_INDEX_ROLE_BITS: Final[tuple[tuple[int, str], ...]] = _INDEXSTOREDB_ROLE_BITS

# Upstream LLVM `clang::index::SymbolRole` (`clang/Index/IndexSymbol.h`), used ONLY when explicit `dialect="clang"`:
_CLANG_ROLE_BITS: Final[tuple[tuple[int, str], ...]] = (
    (1 << 0, "declaration"),
    (1 << 1, "definition"),
    (1 << 2, "reference"),
    (1 << 3, "read"),
    (1 << 4, "write"),
    (1 << 5, "call"),
    (1 << 6, "dynamic"),
    (1 << 7, "addressOf"),
    (1 << 8, "implicit"),
    (1 << 9, "undefinition"),
    (1 << 10, "childOf"),
    (1 << 11, "baseOf"),
    (1 << 12, "overrideOf"),
    (1 << 13, "receivedBy"),
    (1 << 14, "calledBy"),
    (1 << 15, "extendedBy"),
    (1 << 16, "accessorOf"),
    (1 << 17, "containedBy"),
    (1 << 18, "ibTypeOf"),
    (1 << 19, "specializationOf"),
)

_NON_CALLABLE_USR_KINDS: Final[frozenset[str]] = frozenset(
    {
        "variable",
        "var",
        "local",
        "field",
        "ivar",
        "property",
        "parameter",
        "param",
        "struct",
        "class",
        "enum",
        "enum-constant",
        "enumcase",
        "union",
        "namespace",
        "module",
        "typedef",
        "typealias",
        "associatedtype",
        "protocol",
        "interface",
        "category",
        "extension",
        "concept",
        "macro",
        "constant",
    }
)
_CALLABLE_USR_KINDS: Final[frozenset[str]] = frozenset(
    {
        "function",
        "method",
        "constructor",
        "destructor",
        "initializer",
        "deinitializer",
        "func",
        "instance-method",
        "class-method",
        "static-method",
        "cxx-method",
        "accessor",
        "getter",
        "setter",
        "subscript",
        "conversion",
        "operator",
    }
)


def _is_callable_symbol_kind(kind: str) -> bool:
    k = kind.strip().lower()
    if not k or k in _NON_CALLABLE_USR_KINDS:
        return False
    if k in _CALLABLE_USR_KINDS:
        return True
    return any(tok in k for tok in ("func", "method", "ctor", "dtor", "init", "witness"))


def _check_abs_parts_no_symlinks(parts: tuple[str, ...], raw_label: str) -> None:
    for k in range(2, len(parts) + 1):
        if k == 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
            continue
        if Path(*parts[:k]).is_symlink():
            raise ValueError(f"Refusing symlinked path component in '{raw_label}'.")


def validate_safe_path(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    allow_dir: bool = False,
) -> Path:
    """Validate `raw_path` rejecting symlinks on every path component before `.resolve()`."""
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Artifact path must be a non-empty string without NUL bytes.")
    try:
        cand = Path(raw_str).expanduser()
        if ".." in cand.parts:
            raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_str}'.")
        if cand.is_symlink():
            raise ValueError(f"Refusing symlinked artifact path '{raw_str}'.")

        real_root: Path | None = None
        if repo_root is not None:
            root_cand = Path(repo_root).expanduser()
            if root_cand.is_symlink():
                raise ValueError(f"Refusing symlinked repository root '{repo_root}'.")
            if root_cand.is_absolute():
                _check_abs_parts_no_symlinks(root_cand.parts, str(repo_root))
            real_root = root_cand.resolve()

        if not cand.is_absolute():
            base_dir = real_root if real_root is not None else Path.cwd().resolve()
            walk = base_dir
            for part in cand.parts:
                if part in ("", "."):
                    continue
                walk = walk / part
                if walk.is_symlink():
                    raise ValueError(f"Refusing symlinked path component in '{raw_str}'.")
            target = walk
            if real_root is not None and not allow_external and not target.resolve().is_relative_to(real_root):
                raise ValueError(f"Artifact path '{raw_str}' escapes repository root '{real_root}'.")
        else:
            _check_abs_parts_no_symlinks(cand.parts, raw_str)
            if real_root is not None:
                matched_k: int | None = None
                for k in range(1, len(cand.parts) + 1):
                    pref = Path(*cand.parts[:k])
                    if pref.exists() and pref.resolve() == real_root:
                        matched_k = k
                        break
                if matched_k is not None:
                    walk = real_root
                    for part in cand.parts[matched_k:]:
                        if part in ("", "."):
                            continue
                        walk = walk / part
                        if walk.is_symlink():
                            raise ValueError(f"Refusing symlinked path component in '{raw_str}'.")
                    target = walk
                elif not allow_external:
                    raise ValueError(f"Artifact path '{raw_str}' escapes repository root '{real_root}'.")
                else:
                    target = cand
            else:
                target = cand

        st = target.lstat()
    except OSError as exc:
        raise ValueError(f"Artifact path '{raw_str}' is not accessible: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"Refusing symlinked artifact path '{raw_str}'.")
    if allow_dir and stat.S_ISDIR(st.st_mode):
        return target
    if not stat.S_ISREG(st.st_mode):
        kind_desc = "regular file or directory" if allow_dir else "regular file"
        raise ValueError(f"Artifact path '{raw_str}' must be a non-symlink {kind_desc}.")
    return target


def read_safe_bytes(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_ARTIFACT_BYTES,
) -> tuple[Path, bytes]:
    """Read up to `max_bytes` from a verified non-symlink regular file using `O_NOFOLLOW`."""
    target = validate_safe_path(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        allow_dir=False,
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(target, flags)
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
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise ValueError(f"Artifact '{raw_path}' exceeds {max_bytes}-byte limit.")
    finally:
        os.close(fd)
    return target.resolve(), payload


def read_safe_text(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_ARTIFACT_BYTES,
) -> tuple[Path, str]:
    """Read UTF-8 text from a verified non-symlink regular file within `max_bytes`."""
    resolved, raw = read_safe_bytes(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        max_bytes=max_bytes,
    )
    return resolved, raw.decode("utf-8", errors="replace")


def iter_safe_repo_files(
    repo_root: Path,
    *,
    suffixes: Iterable[str],
    max_files: int = 2048,
    exclude_dirs: Iterable[str] = (),
) -> list[tuple[Path, str]]:
    """Walk `repo_root` without following symlinks, returning `(abs_path, rel_posix)` pairs."""
    validated_root = validate_safe_path(repo_root, allow_external=True, allow_dir=True)
    real_root = validated_root.resolve()
    wanted = frozenset(s.lower() for s in suffixes)
    skip_dirs = _IGNORED_WALK_DIRS | frozenset(exclude_dirs)
    found: list[tuple[Path, str]] = []

    for dirpath, dirnames, filenames in os.walk(
        validated_root,
        topdown=True,
        followlinks=False,
        onerror=lambda _exc: None,
    ):
        cur_dir = Path(dirpath)
        kept_dirs: list[str] = []
        for d in sorted(dirnames):
            if d in skip_dirs:
                continue
            dpath = cur_dir / d
            try:
                if dpath.is_symlink():
                    continue
            except OSError:
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for fname in sorted(filenames):
            fpath = cur_dir / fname
            if fpath.suffix.lower() not in wanted:
                continue
            try:
                if fpath.is_symlink():
                    continue
                resolved_f = fpath.resolve()
                if not resolved_f.is_relative_to(real_root):
                    continue
                rel_str = resolved_f.relative_to(real_root).as_posix()
            except (OSError, ValueError):
                continue
            found.append((fpath, rel_str))
            if len(found) >= max_files:
                return found
    return found


def check_nesting_depth_text(raw_text: str, *, max_depth: int = MAX_NESTING_DEPTH) -> None:
    """Reject JSON/YAML payloads exceeding `max_depth` before invoking recursive parsers."""
    depth = 0
    in_quote: str | None = None
    escaped = False
    for ch in raw_text:
        if in_quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
        elif ch in ("{", "["):
            depth += 1
            if depth > max_depth:
                raise ValueError(
                    f"Artifact exceeds maximum nesting depth of {max_depth} levels."
                )
        elif ch in ("}", "]") and depth > 0:
            depth -= 1

    indent_levels: list[int] = []
    for raw_line in raw_text.splitlines():
        line = raw_line[:MAX_LINE_CHARS]
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        while indent_levels and indent < indent_levels[-1]:
            indent_levels.pop()
        if not indent_levels or indent > indent_levels[-1]:
            indent_levels.append(indent)
            if len(indent_levels) > max_depth:
                raise ValueError(
                    f"YAML indentation exceeds maximum nesting depth of {max_depth} levels."
                )


def check_object_depth(root: Any, *, max_depth: int = MAX_NESTING_DEPTH) -> None:
    """Iteratively verify parsed JSON/YAML container depth <= `max_depth`."""
    visited: set[int] = set()
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(
                f"Parsed artifact exceeds maximum nesting depth of {max_depth} levels."
            )
        oid = id(cur)
        if oid in visited:
            continue
        visited.add(oid)
        if len(visited) > 65536:
            raise ValueError("Parsed artifact exceeds unique container budget.")
        if isinstance(cur, dict):
            for val in cur.values():
                if isinstance(val, (dict, list)) and id(val) not in visited:
                    stack.append((val, depth + 1))
        elif isinstance(cur, list):
            for val in cur:
                if isinstance(val, (dict, list)) and id(val) not in visited:
                    stack.append((val, depth + 1))


def _load_bounded_yaml(yaml_mod: Any, raw_text: str, *, max_depth: int = MAX_NESTING_DEPTH) -> Any:
    """Parse YAML using a SafeLoader with node, alias, merge, and depth budgets."""
    max_nodes = 4096

    class _BoundedSafeLoader(yaml_mod.SafeLoader):  # type: ignore[misc, name-defined]
        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._node_count = 0
            self._alias_count = 0
            self._merge_steps = 0
            self._cur_depth = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml_mod.AliasEvent):
                self._alias_count += 1
                if self._alias_count > max_nodes or (
                    self._node_count + self._alias_count
                ) > max_nodes:
                    raise yaml_mod.YAMLError(
                        f"YAML alias expansion exceeds budget ({max_nodes})."
                    )
                return super().compose_node(parent, index)
            self._node_count += 1
            if (self._node_count + self._alias_count) > max_nodes:
                raise yaml_mod.YAMLError(f"YAML node count exceeds budget ({max_nodes}).")
            self._cur_depth += 1
            if self._cur_depth > max_depth:
                raise yaml_mod.YAMLError(
                    f"YAML structure exceeds maximum nesting depth ({max_depth})."
                )
            try:
                return super().compose_node(parent, index)
            finally:
                self._cur_depth -= 1

        def flatten_mapping(self, node: Any) -> None:
            self._merge_steps += 1
            if self._merge_steps > max_nodes:
                raise yaml_mod.YAMLError(
                    f"YAML mapping merge exceeds budget ({max_nodes})."
                )
            super().flatten_mapping(node)
            if len(node.value) > max_nodes:
                raise yaml_mod.YAMLError(
                    f"YAML merged mapping exceeds budget ({max_nodes})."
                )

        def construct_yaml_int(self, node: Any) -> int:
            raw_val = getattr(node, "value", None)
            if isinstance(raw_val, str) and len(raw_val) > 4096:
                raise yaml_mod.YAMLError("YAML integer exceeds maximum bit length")
            val = super().construct_yaml_int(node)
            if isinstance(val, int) and not isinstance(val, bool) and val.bit_length() > 4096:
                raise yaml_mod.YAMLError("YAML integer exceeds maximum bit length")
            return val

    _BoundedSafeLoader.add_constructor(
        "tag:yaml.org,2002:int", _BoundedSafeLoader.construct_yaml_int
    )
    return yaml_mod.load(raw_text, Loader=_BoundedSafeLoader)


def load_bounded_json_or_yaml(
    raw_text: str,
    *,
    max_depth: int = MAX_NESTING_DEPTH,
) -> Any:
    """Parse JSON or YAML text with strict `depth <= max_depth` enforcement."""
    check_nesting_depth_text(raw_text, max_depth=max_depth)
    stripped = raw_text.lstrip("\ufeff \t\r\n")
    if not stripped:
        return {}
    if stripped[0] in ("{", "["):
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError(f"Malformed or excessively nested JSON artifact: {exc}") from exc
        check_object_depth(parsed, max_depth=max_depth)
        return parsed

    try:
        import yaml  # type: ignore[import-untyped]

        parsed_yaml = _load_bounded_yaml(yaml, stripped, max_depth=max_depth)
    except ImportError:
        parsed_yaml = _parse_minimal_yaml(stripped, max_depth=max_depth)
    except Exception as exc:
        raise ValueError(f"Malformed or excessively nested YAML artifact: {exc}") from exc
    check_object_depth(parsed_yaml, max_depth=max_depth)
    return parsed_yaml


def _parse_minimal_yaml(text: str, *, max_depth: int = MAX_NESTING_DEPTH) -> dict[str, Any]:
    """Pure-Python fallback parser for simple symbol/occurrence YAML lists."""
    result: dict[str, Any] = {}
    current_section: str | None = None
    current_item: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line[:MAX_LINE_CHARS].rstrip()
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent > max_depth * 4:
            raise ValueError(f"YAML nesting exceeds {max_depth} levels.")
        if indent == 0 and stripped.endswith(":"):
            current_section = stripped[:-1].strip()
            result.setdefault(current_section, [])
            current_item = None
        elif current_section is not None and stripped.startswith("- "):
            current_item = {}
            result[current_section].append(current_item)
            rest = stripped[2:].strip()
            if ":" in rest:
                k, _, v = rest.partition(":")
                current_item[k.strip()] = _unquote_scalar(v.strip())
        elif current_item is not None and ":" in stripped:
            k, _, v = stripped.partition(":")
            current_item[k.strip()] = _unquote_scalar(v.strip())
    return result


def _unquote_scalar(val: str) -> Any:
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        return [_unquote_scalar(p.strip()) for p in inner.split(",") if p.strip()] if inner else []
    try:
        return int(val)
    except ValueError:
        return val


def normalize_repo_relpath(raw_file: str | None, repo_root: Path | None = None) -> str:
    """Normalize an artifact source path to clean POSIX repo-relative form when possible."""
    if not raw_file:
        return ""
    cleaned = str(raw_file).strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned:
        return ""
    if repo_root is not None and cleaned.startswith("/"):
        try:
            real_root = repo_root.resolve().as_posix().rstrip("/") + "/"
            cand_norm = os.path.normpath(cleaned).replace("\\", "/")
            if cand_norm.startswith(real_root):
                return cand_norm[len(real_root) :]
            raw_root = repo_root.as_posix().rstrip("/") + "/"
            if cleaned.startswith(raw_root):
                return cleaned[len(raw_root) :]
        except OSError:
            pass
    return cleaned.lstrip("/") if not cleaned.startswith("/") else cleaned


def classify_usr_language(usr: str, explicit_lang: str = "") -> str:
    """Infer symbol language from Unified Symbol Resolution (`USR`) prefix."""
    low_lang = explicit_lang.strip().lower()
    if low_lang in ("swift", "c", "cpp", "c++", "objc", "objective-c", "objective-c++", "rust", "python"):
        return "cpp" if low_lang == "c++" else ("objc" if "objc" in low_lang or "objective" in low_lang else low_lang)
    u = usr.strip()
    if u.startswith(("s:", "$s", "_$s")):
        return "swift"
    if u.startswith("c:objc"):
        return "objc"
    if u.startswith(("c:@S@", "c:@N@", "_Z")) or "::" in u:
        return "cpp"
    if u.startswith("c:"):
        return "c"
    if u.startswith(("rust:", "_RN")):
        return "rust"
    if u.startswith("py:"):
        return "python"
    return low_lang or "unknown"


def _resolve_role_dialect(explicit_dialect: str | None) -> Literal["indexstoredb", "clang"]:
    if not explicit_dialect:
        return "indexstoredb"
    norm = explicit_dialect.strip().lower().replace("_", "-")
    if norm in ("clang", "clang-index", "llvm-clang"):
        return "clang"
    if norm in ("indexstoredb", "swift-indexstoredb", "indexstore", "cindexstoredb"):
        return "indexstoredb"
    raise ValueError(
        f"Unsupported USR role dialect '{explicit_dialect}'; expected 'indexstoredb' or 'clang'."
    )


def _decode_numeric_role_bits(
    raw_int: int,
    *,
    dialect: Literal["indexstoredb", "clang"] = "indexstoredb",
    default_roles: tuple[str, ...] = ("reference",),
) -> tuple[str, ...]:
    if raw_int <= 0:
        return default_roles
    table = _CLANG_ROLE_BITS if dialect == "clang" else _INDEXSTOREDB_ROLE_BITS
    known_mask = 0
    decoded: list[str] = []
    for bit, name in table:
        known_mask |= bit
        if raw_int & bit:
            decoded.append(name)
    rem = raw_int & ~known_mask
    steps = 0
    while rem > 0 and steps < 64:
        lsb = rem & -rem
        decoded.append(f"unknown_role_0x{lsb:x}")
        rem ^= lsb
        steps += 1
    return tuple(decoded) if decoded else default_roles


def _normalize_roles(
    raw_roles: Any,
    *,
    dialect: Literal["indexstoredb", "clang"] = "indexstoredb",
    default_roles: tuple[str, ...] = ("reference",),
) -> tuple[str, ...]:
    if isinstance(raw_roles, int) and not isinstance(raw_roles, bool):
        return _decode_numeric_role_bits(raw_roles, dialect=dialect, default_roles=default_roles)
    if isinstance(raw_roles, str):
        clean_s = raw_roles.strip()
        if clean_s.isdigit():
            return _decode_numeric_role_bits(
                int(clean_s), dialect=dialect, default_roles=default_roles
            )
        parts = [p.strip() for p in clean_s.replace("|", ",").split(",") if p.strip()]
        return tuple(parts) if parts else default_roles
    if isinstance(raw_roles, (list, tuple, set)):
        out: list[str] = []
        for x in raw_roles:
            if isinstance(x, int) and not isinstance(x, bool):
                out.extend(_decode_numeric_role_bits(x, dialect=dialect, default_roles=()))
            else:
                sx = str(x).strip()
                if sx:
                    out.append(sx)
        return tuple(dict.fromkeys(out)) if out else default_roles
    return default_roles


@dataclass(frozen=True)
class UsrSymbolRecord:
    """Compiler-indexed symbol definition/declaration keyed by USR."""

    usr: str
    name: str
    kind: str
    language: str
    source_file: str
    line: int = 1
    column: int = 1
    receiver_usr: str | None = None


@dataclass(frozen=True)
class UsrRelation:
    """Explicit compiler relation attached to a symbol occurrence."""

    usr: str
    roles: tuple[str, ...]
    name: str | None = None


@dataclass(frozen=True)
class UsrOccurrence:
    """Single symbol occurrence (definition, call, witness override, or FFI reference)."""

    usr: str
    roles: tuple[str, ...]
    source_file: str
    line: int = 1
    column: int = 1
    caller_usr: str | None = None
    caller_name: str | None = None
    caller_provenance: Literal[
        "compiler_called_by",
        "contained_by_callable",
        "enclosing_heuristic",
        "file_fallback",
        "none",
    ] = "none"
    container_usr: str | None = None
    relations: tuple[UsrRelation, ...] = ()


@dataclass(frozen=True)
class UsrCrossRefEdge:
    """Resolved caller->callee USR cross-reference across files or languages."""

    caller_usr: str
    caller_name: str
    caller_file: str
    caller_line: int
    callee_usr: str
    callee_name: str
    callee_file: str
    callee_line: int
    kind: str
    is_dynamic: bool = False
    verification: Literal["verified", "declared", "unverified"] = "verified"
    provenance: str = "compiler_called_by"


@dataclass
class UsrIndexBundle:
    """Aggregated `IndexStoreDB` / `clangd` USR symbol and cross-reference index."""

    symbols_by_usr: dict[str, UsrSymbolRecord] = field(default_factory=dict)
    occurrences: list[UsrOccurrence] = field(default_factory=list)
    cross_refs: list[UsrCrossRefEdge] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    dialect: str = "indexstoredb"
    dialects: tuple[str, ...] = ("indexstoredb",)
    truncated: bool = False
    _entry_count: int = field(default=0, repr=False, compare=False)
    _relation_count: int = field(default=0, repr=False, compare=False)
    _rel_obj_cache: dict[int, tuple[Any, UsrRelation | None, frozenset[str]]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _rel_list_cache: dict[
        int, tuple[list[Any], tuple[UsrRelation, ...], str | None, str | None, str | None]
    ] = field(default_factory=dict, repr=False, compare=False)

    def merge(self, other: UsrIndexBundle) -> None:
        for usr, rec in other.symbols_by_usr.items():
            prev = self.symbols_by_usr.get(usr)
            if prev is None or (not prev.source_file and rec.source_file):
                self.symbols_by_usr[usr] = rec
        self.occurrences.extend(other.occurrences)
        seen = {
            (e.caller_usr, e.callee_usr, e.caller_file, e.caller_line, e.kind)
            for e in self.cross_refs
        }
        for edge in other.cross_refs:
            key = (edge.caller_usr, edge.callee_usr, edge.caller_file, edge.caller_line, edge.kind)
            if key not in seen:
                seen.add(key)
                self.cross_refs.append(edge)
        merged_dials = tuple(dict.fromkeys([*self.dialects, *other.dialects]))
        self.dialects = merged_dials
        if len(merged_dials) == 1:
            self.dialect = merged_dials[0]
        if other.truncated:
            self.truncated = True
        self._entry_count += other._entry_count
        self._relation_count += other._relation_count
        for note in other.notes:
            if note not in self.notes:
                self.notes.append(note)


def _mark_usr_truncated(bundle: UsrIndexBundle) -> None:
    if not bundle.truncated:
        bundle.truncated = True
        note = (
            f"usr_index: truncated artifact after reaching entry/relation budget "
            f"({MAX_TOTAL_USR_RELATIONS})."
        )
        if note not in bundle.notes:
            bundle.notes.append(note)


def _safe_int(val: Any, default: int = 1) -> int:
    if isinstance(val, bool) or val is None:
        return default
    try:
        parsed = int(val)
        return parsed if parsed >= 1 else default
    except (TypeError, ValueError):
        return default


def _safe_scalar_str(val: Any) -> str:
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        if isinstance(val, int) and val.bit_length() > 128:
            return ""
        return str(val)
    return ""


def _extract_loc(entry: dict[str, Any], repo_root: Path | None) -> tuple[str, int, int]:
    loc = entry.get("location")
    if isinstance(loc, dict):
        raw_f = loc.get("path") or loc.get("file") or loc.get("uri") or entry.get("file")
        pos = loc.get("position")
        pos_dict = pos if isinstance(pos, dict) else {}
        ln = _safe_int(loc.get("line") or pos_dict.get("line"), 1)
        col = _safe_int(
            loc.get("column") or loc.get("col") or pos_dict.get("column") or pos_dict.get("col"),
            1,
        )
    else:
        raw_f = entry.get("source_file") or entry.get("file") or entry.get("path") or entry.get("uri")
        ln = _safe_int(entry.get("line"), 1)
        col = _safe_int(entry.get("column") or entry.get("col"), 1)
    f_str = _safe_scalar_str(raw_f).removeprefix("file://")
    return normalize_repo_relpath(f_str, repo_root), ln, col


def _ingest_entry_dict(
    entry: dict[str, Any],
    bundle: UsrIndexBundle,
    repo_root: Path | None,
    *,
    dialect: Literal["indexstoredb", "clang"] = "indexstoredb",
) -> None:
    if not isinstance(entry, dict):
        return
    if bundle.truncated or bundle._entry_count >= MAX_TOTAL_USR_ENTRIES:
        _mark_usr_truncated(bundle)
        return
    bundle._entry_count += 1
    usr = _safe_scalar_str(entry.get("usr") or entry.get("id")).strip()
    if not usr:
        return
    sf, ln, col = _extract_loc(entry, repo_root)
    raw_roles = entry.get("roles") if "roles" in entry else entry.get("role")
    has_name = bool(_safe_scalar_str(entry.get("name") or entry.get("symbol")).strip())
    norm_entry_roles = (
        _normalize_roles(raw_roles, dialect=dialect) if raw_roles is not None else ()
    )

    if has_name and (
        raw_roles is None
        or "definition" in norm_entry_roles
        or "declaration" in norm_entry_roles
        or "kind" in entry
    ):
        sym_name = _safe_scalar_str(entry.get("name") or entry.get("symbol")).strip() or usr
        sym_kind = _safe_scalar_str(entry.get("kind")).strip() or "function"
        sym_lang = classify_usr_language(
            usr, _safe_scalar_str(entry.get("language") or entry.get("lang"))
        )
        recv = _safe_scalar_str(entry.get("receiver_usr")).strip() or None
        prev = bundle.symbols_by_usr.get(usr)
        if prev is None or (not prev.source_file and sf):
            bundle.symbols_by_usr[usr] = UsrSymbolRecord(
                usr=usr,
                name=sym_name,
                kind=sym_kind,
                language=sym_lang,
                source_file=sf,
                line=ln,
                column=col,
                receiver_usr=recv,
            )

    if raw_roles is not None or entry.get("caller_usr") or entry.get("relations"):
        roles = norm_entry_roles or ("reference",)
        explicit_caller_usr = _safe_scalar_str(entry.get("caller_usr")).strip() or None
        caller_usr = explicit_caller_usr
        caller_name = _safe_scalar_str(entry.get("caller_name")).strip() or None
        caller_prov: Literal[
            "compiler_called_by",
            "contained_by_callable",
            "enclosing_heuristic",
            "file_fallback",
            "none",
        ] = "compiler_called_by" if explicit_caller_usr else "none"
        container_usr = _safe_scalar_str(entry.get("container_usr")).strip() or None

        parsed_rels_tuple: tuple[UsrRelation, ...] = ()
        relations = entry.get("relations")
        if isinstance(relations, list):
            rem = MAX_TOTAL_USR_RELATIONS - bundle._relation_count
            if rem <= 0:
                _mark_usr_truncated(bundle)
            else:
                cached_list = bundle._rel_list_cache.get(id(relations))
                if cached_list is not None and cached_list[0] is relations and len(relations) <= rem:
                    bundle._relation_count += len(relations)
                    parsed_rels_tuple = cached_list[1]
                    if caller_usr is None and cached_list[2] is not None:
                        caller_usr = cached_list[2]
                        caller_name = caller_name or cached_list[3]
                        caller_prov = "compiler_called_by"
                    if container_usr is None and cached_list[4] is not None:
                        container_usr = cached_list[4]
                else:
                    parsed_rels: list[UsrRelation] = []
                    first_cb_usr: str | None = None
                    first_cb_name: str | None = None
                    first_cont_usr: str | None = None
                    complete_list = True
                    for rel in relations:
                        if bundle._relation_count >= MAX_TOTAL_USR_RELATIONS:
                            _mark_usr_truncated(bundle)
                            complete_list = False
                            break
                        bundle._relation_count += 1
                        if not isinstance(rel, dict):
                            continue
                        rid = id(rel)
                        cached_rel = bundle._rel_obj_cache.get(rid)
                        if cached_rel is not None and cached_rel[0] is rel:
                            u_rel, rel_low = cached_rel[1], cached_rel[2]
                        else:
                            rel_sym = rel.get("symbol")
                            rel_sym_dict = rel_sym if isinstance(rel_sym, dict) else {}
                            rel_usr = _safe_scalar_str(
                                rel.get("usr") or rel_sym_dict.get("usr")
                            ).strip()
                            if not rel_usr:
                                u_rel, rel_low = None, frozenset()
                            else:
                                rel_name = (
                                    _safe_scalar_str(
                                        rel.get("name") or rel_sym_dict.get("name")
                                    ).strip()
                                    or None
                                )
                                rel_raw_roles = rel.get("roles") if "roles" in rel else rel.get("role")
                                rel_roles = _normalize_roles(
                                    rel_raw_roles, dialect=dialect, default_roles=()
                                )
                                u_rel = UsrRelation(usr=rel_usr, roles=rel_roles, name=rel_name)
                                rel_low = frozenset(r.lower() for r in rel_roles)
                            if len(bundle._rel_obj_cache) < 4096:
                                bundle._rel_obj_cache[rid] = (rel, u_rel, rel_low)
                        if u_rel is None:
                            continue
                        parsed_rels.append(u_rel)
                        if "calledby" in rel_low and first_cb_usr is None:
                            first_cb_usr = u_rel.usr
                            first_cb_name = u_rel.name
                        elif ("containedby" in rel_low or "childof" in rel_low) and first_cont_usr is None:
                            first_cont_usr = u_rel.usr
                    parsed_rels_tuple = tuple(parsed_rels)
                    if caller_usr is None and first_cb_usr is not None:
                        caller_usr = first_cb_usr
                        caller_name = caller_name or first_cb_name
                        caller_prov = "compiler_called_by"
                    if container_usr is None and first_cont_usr is not None:
                        container_usr = first_cont_usr
                    if complete_list and len(bundle._rel_list_cache) < 1024:
                        bundle._rel_list_cache[id(relations)] = (
                            relations,
                            parsed_rels_tuple,
                            first_cb_usr,
                            first_cb_name,
                            first_cont_usr,
                        )

        bundle.occurrences.append(
            UsrOccurrence(
                usr=usr,
                roles=roles,
                source_file=sf,
                line=ln,
                column=col,
                caller_usr=caller_usr,
                caller_name=caller_name,
                caller_provenance=caller_prov,
                container_usr=container_usr,
                relations=parsed_rels_tuple,
            )
        )


def _parse_tsv_usr_lines(
    lines: Sequence[str],
    bundle: UsrIndexBundle,
    repo_root: Path | None,
    *,
    dialect: Literal["indexstoredb", "clang"] = "indexstoredb",
) -> None:
    header_map: dict[str, int] | None = None
    for idx, raw_line in enumerate(lines):
        if bundle.truncated:
            break
        line = raw_line[:MAX_LINE_CHARS].strip()
        if not line or line.startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if header_map is None and any(
            h in ("usr", "roles", "kind", "record_type") for h in [c.lower() for c in cols]
        ):
            header_map = {c.lower(): i for i, c in enumerate(cols)}
            continue
        if header_map is not None:
            row = {k: (cols[i] if i < len(cols) else "") for k, i in header_map.items()}
            _ingest_entry_dict(row, bundle, repo_root, dialect=dialect)
            continue
        tag = cols[0].upper()
        if tag in ("SYM", "SYMBOL") and len(cols) >= 6:
            _ingest_entry_dict(
                {
                    "usr": cols[1],
                    "name": cols[2],
                    "kind": cols[3],
                    "language": cols[4],
                    "file": cols[5],
                    "line": cols[6] if len(cols) > 6 else 1,
                },
                bundle,
                repo_root,
                dialect=dialect,
            )
        elif tag in ("OCC", "OCCURRENCE", "REF") and len(cols) >= 5:
            _ingest_entry_dict(
                {
                    "usr": cols[1],
                    "roles": cols[2],
                    "file": cols[3],
                    "line": cols[4],
                    "caller_usr": cols[5] if len(cols) > 5 else "",
                    "caller_name": cols[6] if len(cols) > 6 else "",
                },
                bundle,
                repo_root,
                dialect=dialect,
            )
        elif len(cols) >= 5:
            _ingest_entry_dict(
                {
                    "usr": cols[0],
                    "name": cols[1],
                    "kind": cols[2],
                    "roles": cols[3],
                    "file": cols[4],
                    "line": cols[5] if len(cols) > 5 else 1,
                    "caller_usr": cols[6] if len(cols) > 6 else "",
                },
                bundle,
                repo_root,
                dialect=dialect,
            )


def _synthesize_usr_cross_refs(bundle: UsrIndexBundle) -> None:
    callable_defs_by_file: dict[str, list[UsrSymbolRecord]] = {}
    for sym in bundle.symbols_by_usr.values():
        if sym.source_file and _is_callable_symbol_kind(sym.kind):
            callable_defs_by_file.setdefault(sym.source_file, []).append(sym)
    for f_syms in callable_defs_by_file.values():
        f_syms.sort(key=lambda s: (s.line, s.column, s.usr))

    seen: set[tuple[str, str, str, int, str]] = set()
    unverified_caller_count = 0

    def _emit_edge(edge: UsrCrossRefEdge) -> None:
        dedup = (edge.caller_usr, edge.callee_usr, edge.caller_file, edge.caller_line, edge.kind)
        if dedup not in seen:
            seen.add(dedup)
            bundle.cross_refs.append(edge)

    for occ in bundle.occurrences:
        role_low = {r.lower() for r in occ.roles}
        occ_rec = bundle.symbols_by_usr.get(occ.usr)
        occ_name = occ_rec.name if occ_rec is not None else occ.usr
        occ_file = occ.source_file or (occ_rec.source_file if occ_rec is not None else "")

        # 1. Preserve explicit override, inheritance, and structural containment relations
        for rel in occ.relations:
            if rel.usr == occ.usr:
                continue
            rel_low = {r.lower() for r in rel.roles}
            rel_rec = bundle.symbols_by_usr.get(rel.usr)
            rel_name = rel.name or (
                rel_rec.name if rel_rec is not None else rel.usr.rsplit(":", 1)[-1]
            )
            rel_file = rel_rec.source_file if rel_rec is not None else ""
            rel_line = rel_rec.line if rel_rec is not None else occ.line

            if "overrideof" in rel_low:
                _emit_edge(
                    UsrCrossRefEdge(
                        caller_usr=occ.usr,
                        caller_name=occ_name,
                        caller_file=occ_file,
                        caller_line=occ.line,
                        callee_usr=rel.usr,
                        callee_name=rel_name,
                        callee_file=rel_file,
                        callee_line=rel_line,
                        kind="witness_dispatch",
                        is_dynamic=False,
                        verification="verified" if rel_file else "declared",
                        provenance="compiler_override_of",
                    )
                )
            if "baseof" in rel_low:
                if "definition" in role_low or "declaration" in role_low:
                    sub_u, sub_nm, sub_f, sub_ln = occ.usr, occ_name, occ_file, occ.line
                    base_u, base_nm, base_f, base_ln = rel.usr, rel_name, rel_file, rel_line
                else:
                    sub_u, sub_nm, sub_f, sub_ln = rel.usr, rel_name, rel_file or occ_file, occ.line
                    base_u, base_nm, base_f, base_ln = (
                        occ.usr,
                        occ_name,
                        occ_rec.source_file if occ_rec is not None else "",
                        occ_rec.line if occ_rec is not None else 1,
                    )
                _emit_edge(
                    UsrCrossRefEdge(
                        caller_usr=sub_u,
                        caller_name=sub_nm,
                        caller_file=sub_f,
                        caller_line=sub_ln,
                        callee_usr=base_u,
                        callee_name=base_nm,
                        callee_file=base_f,
                        callee_line=base_ln,
                        kind="inherits_usr",
                        is_dynamic=False,
                        verification="declared",
                        provenance="compiler_base_of",
                    )
                )
            if (rel_low & {"childof", "containedby"}) and role_low <= {"declaration", "definition"}:
                _emit_edge(
                    UsrCrossRefEdge(
                        caller_usr=rel.usr,
                        caller_name=rel_name,
                        caller_file=rel_file or occ_file,
                        caller_line=occ.line,
                        callee_usr=occ.usr,
                        callee_name=occ_name,
                        callee_file=occ_file,
                        callee_line=occ.line,
                        kind="contains_usr",
                        is_dynamic=False,
                        verification="declared",
                        provenance="compiler_containment",
                    )
                )

        # 2. Synthesize callable cross-references (`call`, `dynamic`, `addressOf`, or callable `reference`)
        if not (role_low & {"call", "reference", "dynamic", "addressof"}):
            continue
        if role_low <= {"definition", "declaration"}:
            continue
        has_explicit_call_role = bool(role_low & {"call", "dynamic", "addressof"})
        if not has_explicit_call_role and occ.caller_provenance != "compiler_called_by":
            if any(
                {r.lower() for r in rel.roles} & {"baseof", "ibtypeof", "extendedby", "overrideof"}
                for rel in occ.relations
            ):
                continue
            if occ_rec is not None and not _is_callable_symbol_kind(occ_rec.kind):
                continue

        callee_rec = occ_rec
        callee_name = occ_name
        callee_file = callee_rec.source_file if callee_rec is not None else ""
        callee_line = callee_rec.line if callee_rec is not None else 1
        callee_lang = callee_rec.language if callee_rec is not None else classify_usr_language(occ.usr)

        caller_usr = occ.caller_usr or ""
        caller_prov: str = occ.caller_provenance
        caller_rec = bundle.symbols_by_usr.get(caller_usr) if caller_usr else None

        if not caller_usr and occ.container_usr:
            cont_rec = bundle.symbols_by_usr.get(occ.container_usr)
            if cont_rec is not None and _is_callable_symbol_kind(cont_rec.kind):
                caller_rec = cont_rec
                caller_usr = cont_rec.usr
                caller_prov = "contained_by_callable"

        if not caller_usr and occ.source_file in callable_defs_by_file:
            enclosing = [
                s
                for s in callable_defs_by_file[occ.source_file]
                if s.line <= occ.line and s.usr != occ.usr
            ]
            if enclosing:
                caller_rec = enclosing[-1]
                caller_usr = caller_rec.usr
                caller_prov = "enclosing_heuristic"

        if not caller_usr:
            caller_usr = f"file:{occ.source_file or 'unknown'}"
            caller_prov = "file_fallback"
        if caller_usr == occ.usr:
            continue

        caller_name = (
            occ.caller_name
            or (caller_rec.name if caller_rec is not None else caller_usr.rsplit(":", 1)[-1])
        )
        caller_file = occ.source_file or (caller_rec.source_file if caller_rec is not None else "")
        caller_lang = caller_rec.language if caller_rec is not None else classify_usr_language(caller_usr)

        is_dyn = "dynamic" in role_low
        if callee_rec and "witness" in callee_rec.kind.lower():
            edge_kind = "witness_dispatch"
        elif caller_lang != "unknown" and callee_lang != "unknown" and caller_lang != callee_lang:
            edge_kind = "ffi_call"
        elif is_dyn:
            edge_kind = "dynamic_call"
        else:
            edge_kind = "calls_usr"

        if is_dyn or caller_prov != "compiler_called_by":
            edge_verif: Literal["verified", "declared", "unverified"] = "unverified"
            if caller_prov != "compiler_called_by":
                unverified_caller_count += 1
        elif callee_file:
            edge_verif = "verified"
        else:
            edge_verif = "declared"

        _emit_edge(
            UsrCrossRefEdge(
                caller_usr=caller_usr,
                caller_name=caller_name,
                caller_file=caller_file,
                caller_line=occ.line,
                callee_usr=occ.usr,
                callee_name=callee_name,
                callee_file=callee_file,
                callee_line=callee_line,
                kind=edge_kind,
                is_dynamic=is_dyn,
                verification=edge_verif,
                provenance=caller_prov,
            )
        )

    if unverified_caller_count > 0:
        bundle.notes.append(
            f"usr_index: {unverified_caller_count} call occurrence(s) lacked an explicit compiler "
            "`calledBy` relation; heuristic/container caller attribution remains `unverified`."
        )


def parse_usr_index_text(
    raw_text: str,
    *,
    repo_root: Path | None = None,
    format_hint: str = "",
    dialect: str | None = None,
) -> UsrIndexBundle:
    """Parse a JSON, JSONL, TSV, or YAML `IndexStoreDB` / `clangd` symbol+occurrence dump."""
    active_dialect = _resolve_role_dialect(dialect)
    bundle = UsrIndexBundle(dialect=active_dialect, dialects=(active_dialect,))
    stripped = raw_text.lstrip("\ufeff \t\r\n")
    if not stripped:
        return bundle

    lines = stripped.splitlines()
    for hdr_ln in lines[:8]:
        s_hdr = hdr_ln.strip()
        if not s_hdr.startswith("#"):
            break
        low_hdr = s_hdr[1:].strip().lower()
        if low_hdr.startswith("dialect:"):
            active_dialect = _resolve_role_dialect(low_hdr.split(":", 1)[1])
            bundle.dialect = active_dialect
            bundle.dialects = (active_dialect,)

    hint_low = format_hint.lower()
    if hint_low.endswith(".tsv") or ("\t" in lines[0] and not stripped.startswith(("{", "["))):
        if active_dialect == "clang":
            bundle.notes.append("usr_index: decoded numeric role bits using explicit dialect='clang'.")
        _parse_tsv_usr_lines(lines, bundle, repo_root, dialect=active_dialect)
        _synthesize_usr_cross_refs(bundle)
        return bundle

    if hint_low.endswith(".jsonl") or (
        len(lines) > 1 and lines[0].lstrip().startswith("{") and lines[1].lstrip().startswith("{")
    ):
        for raw_ln in lines:
            if bundle.truncated:
                break
            ln_clean = raw_ln.strip()
            if not ln_clean:
                continue
            obj = load_bounded_json_or_yaml(ln_clean)
            if isinstance(obj, dict):
                row_dial = (
                    _resolve_role_dialect(str(obj["dialect"]))
                    if dialect is None and "dialect" in obj and "usr" not in obj
                    else active_dialect
                )
                if "dialect" in obj and "usr" not in obj:
                    active_dialect = row_dial
                    bundle.dialect = active_dialect
                    bundle.dialects = (active_dialect,)
                    continue
                _ingest_entry_dict(obj, bundle, repo_root, dialect=active_dialect)
        if active_dialect == "clang":
            bundle.notes.append("usr_index: decoded numeric role bits using explicit dialect='clang'.")
        _synthesize_usr_cross_refs(bundle)
        return bundle

    data = load_bounded_json_or_yaml(stripped)
    if isinstance(data, dict) and dialect is None:
        meta_dial = data.get("dialect") or data.get("role_dialect") or data.get("index_dialect")
        if isinstance(meta_dial, str) and meta_dial.strip():
            active_dialect = _resolve_role_dialect(meta_dial)
            bundle.dialect = active_dialect
            bundle.dialects = (active_dialect,)
    if active_dialect == "clang":
        bundle.notes.append("usr_index: decoded numeric role bits using explicit dialect='clang'.")

    if isinstance(data, list):
        for item in data:
            if bundle.truncated:
                break
            if isinstance(item, dict):
                _ingest_entry_dict(item, bundle, repo_root, dialect=active_dialect)
    elif isinstance(data, dict):
        for key in ("symbols", "occurrences", "records", "refs", "entries"):
            if bundle.truncated:
                break
            seq = data.get(key)
            if isinstance(seq, list):
                for item in seq:
                    if bundle.truncated:
                        break
                    if isinstance(item, dict):
                        if key == "occurrences" and "roles" not in item and "role" not in item:
                            item = {**item, "roles": ["reference", "call"]}
                        _ingest_entry_dict(item, bundle, repo_root, dialect=active_dialect)
        units = data.get("units")
        if isinstance(units, list) and not bundle.truncated:
            for unit in units:
                if bundle.truncated:
                    break
                if isinstance(unit, dict):
                    for key in ("symbols", "occurrences", "records"):
                        if bundle.truncated:
                            break
                        sub = unit.get(key)
                        if isinstance(sub, list):
                            for item in sub:
                                if bundle.truncated:
                                    break
                                if isinstance(item, dict):
                                    _ingest_entry_dict(
                                        item, bundle, repo_root, dialect=active_dialect
                                    )
        if "usr" in data and not bundle.truncated:
            _ingest_entry_dict(data, bundle, repo_root, dialect=active_dialect)

    _synthesize_usr_cross_refs(bundle)
    return bundle


def parse_usr_index(
    path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    dialect: str | None = None,
) -> UsrIndexBundle:
    """Load a read-only `IndexStoreDB` / `clangd` file or directory of index dumps."""
    validated = validate_safe_path(
        path,
        repo_root=repo_root,
        allow_external=allow_external,
        allow_dir=True,
    )
    if validated.is_file():
        _, text = read_safe_text(validated, repo_root=repo_root, allow_external=allow_external)
        return parse_usr_index_text(
            text, repo_root=repo_root, format_hint=validated.name, dialect=dialect
        )

    combined = UsrIndexBundle()
    dump_files = iter_safe_repo_files(
        validated,
        suffixes=(".json", ".jsonl", ".tsv", ".yaml", ".yml"),
        max_files=512,
    )
    if not dump_files:
        combined.notes.append(
            f"Index directory '{validated.name}' contains no pre-exported JSON/TSV/YAML dumps; "
            "skipping raw binary store without invoking indexstore-db."
        )
        return combined
    for fpath, _ in dump_files:
        _, text = read_safe_text(
            fpath,
            repo_root=repo_root if not allow_external else None,
            allow_external=allow_external,
        )
        combined.merge(
            parse_usr_index_text(
                text, repo_root=repo_root, format_hint=fpath.name, dialect=dialect
            )
        )
    return combined
