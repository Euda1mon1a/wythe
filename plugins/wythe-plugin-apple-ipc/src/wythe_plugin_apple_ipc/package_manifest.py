"""Pure-Python `Package.swift` parser, safe source-tree walker, and target boundary verifier."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final, Literal

MAX_SOURCE_FILE_BYTES: Final[int] = 8 * 1024 * 1024  # 8 MiB ceiling per source/plist file
MAX_NESTING_DEPTH: Final[int] = 64

_OS_ROOT_SYMLINK_PREFIXES: Final[frozenset[tuple[str, str]]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)
EXCLUDED_REPO_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".build",
        ".swiftpm",
        "DerivedData",
        "Pods",
        "Carthage",
        "vendor",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "build",
        "dist",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)

TargetDeclKind = Literal[
    "executableTarget",
    "target",
    "systemLibrary",
    "testTarget",
    "plugin",
    "binaryTarget",
    "macro",
]

_QUOTED_STR_RE = re.compile(r'"((?:\\.|[^"\\\n])*)"')
_TOOLS_VERSION_RE = re.compile(r"//\s*swift-tools-version\s*:\s*([0-9]+(?:\.[0-9]+){0,2})")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _check_non_os_symlinks_in_abs_parts(parts: tuple[str, ...], raw_str: str) -> None:
    for k in range(2, len(parts) + 1):
        if k == 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
            continue
        if Path(*parts[:k]).is_symlink():
            raise ValueError(f"Symlink component rejected in path '{raw_str}'.")


def validate_safe_directory(raw_dir: str | Path) -> Path:
    """Validate `raw_dir` has zero non-OS symlink path components before `.resolve()`."""
    raw_str = str(raw_dir).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Directory path must be a non-empty string without NUL bytes.")
    cand = Path(raw_str).expanduser()
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_str}'.")
    if cand.is_absolute():
        _check_non_os_symlinks_in_abs_parts(cand.parts, raw_str)
        target = cand
    else:
        walk = Path.cwd().resolve()
        for part in cand.parts:
            if part in ("", "."):
                continue
            walk = walk / part
            if walk.is_symlink():
                raise ValueError(f"Symlink component rejected in path '{raw_str}'.")
        target = walk
    try:
        st = target.lstat()
    except OSError as exc:
        raise ValueError(f"Directory '{raw_str}' is not accessible: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"Path '{raw_str}' must be a non-symlink directory.")
    return target.resolve()


def resolve_safe_source_path(
    raw_path: str | Path,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_SOURCE_FILE_BYTES,
) -> Path:
    """Validate every path component for symlinks before `.resolve()` and enforce size bounds."""
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Source path must be a non-empty string without NUL bytes.")
    cand = Path(raw_str).expanduser()
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_str}'.")

    real_root = validate_safe_directory(repo_root) if repo_root is not None else None
    if not cand.is_absolute():
        base = real_root if real_root is not None else Path.cwd().resolve()
        walk = base
        for part in cand.parts:
            if part in ("", "."):
                continue
            walk = walk / part
            if walk.is_symlink():
                raise ValueError(f"Symlink component rejected in path '{raw_str}'.")
        target = walk
        if real_root is not None and not allow_external and not target.resolve().is_relative_to(real_root):
            raise ValueError(f"Path '{raw_str}' escapes repository root '{real_root}'.")
    elif real_root is not None and not allow_external:
        matched_k: int | None = None
        for k in range(1, len(cand.parts) + 1):
            pref = Path(*cand.parts[:k])
            if k >= 2 and not (k == 2 and cand.parts[:2] in _OS_ROOT_SYMLINK_PREFIXES) and pref.is_symlink():
                raise ValueError(f"Symlink component rejected in path '{raw_str}'.")
            if pref.exists() and pref.resolve() == real_root:
                matched_k = k
                break
        if matched_k is None:
            raise ValueError(f"Path '{raw_str}' escapes repository root '{real_root}'.")
        walk = real_root
        for part in cand.parts[matched_k:]:
            if part in ("", "."):
                continue
            walk = walk / part
            if walk.is_symlink():
                raise ValueError(f"Symlink component rejected in path '{raw_str}'.")
        target = walk
        if not target.resolve().is_relative_to(real_root):
            raise ValueError(f"Path '{raw_str}' escapes repository root '{real_root}'.")
    else:
        _check_non_os_symlinks_in_abs_parts(cand.parts, raw_str)
        target = cand

    try:
        st = target.lstat()
    except OSError as exc:
        raise ValueError(f"Path '{raw_str}' is not accessible: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Path '{raw_str}' must be a non-symlink regular file.")
    if st.st_size > max_bytes:
        raise ValueError(
            f"File '{raw_str}' ({st.st_size} bytes) exceeds {max_bytes}-byte limit."
        )
    return target.resolve()


def read_bounded_bytes(path: Path, *, max_bytes: int = MAX_SOURCE_FILE_BYTES) -> bytes:
    """Read at most `max_bytes` from a verified non-symlink regular file using `O_NOFOLLOW`."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        l_st = path.lstat()
        if stat.S_ISLNK(l_st.st_mode):
            raise ValueError(f"Symlink file rejected: '{path}'.")
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"File '{path}' is not accessible or is a symlink: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"File '{path}' must be a regular file.")
        if st.st_size > max_bytes:
            raise ValueError(f"File '{path}' ({st.st_size} bytes) exceeds {max_bytes}-byte limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            buf = os.read(fd, min(65536, max_bytes + 1 - total))
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
            if total > max_bytes:
                raise ValueError(
                    f"File '{path}' grew past {max_bytes}-byte limit during read."
                )
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_bounded_text(path: Path, *, max_bytes: int = MAX_SOURCE_FILE_BYTES) -> str:
    """Read UTF-8 text from a verified non-symlink regular file within `max_bytes`."""
    return read_bounded_bytes(path, max_bytes=max_bytes).decode("utf-8", errors="replace")


def sanitize_swift_source(
    source: str,
    *,
    max_depth: int = MAX_NESTING_DEPTH,
) -> tuple[str, str]:
    """Single-pass O(N) Swift/C comment stripper and string-interior masker.

    Returns `(clean_with_strings, skeleton_masked_strings)` with identical char
    offsets and preserved `\\n` line breaks. Enforces `<= max_depth` on nested block
    comments and `()`/`[]`/`{}` delimiters without regex backtracking.
    """
    n = len(source)
    clean_chars: list[str] = []
    skel_chars: list[str] = []
    i = 0
    delim_depth = 0

    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                clean_chars.append(" ")
                skel_chars.append(" ")
                i += 1
            continue

        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            c_depth = 1
            clean_chars.extend((" ", " "))
            skel_chars.extend((" ", " "))
            i += 2
            while i < n and c_depth > 0:
                if source[i] == "/" and i + 1 < n and source[i + 1] == "*":
                    c_depth += 1
                    if c_depth > max_depth:
                        raise ValueError(
                            f"Block comment exceeds maximum nesting depth ({max_depth})."
                        )
                    clean_chars.extend((" ", " "))
                    skel_chars.extend((" ", " "))
                    i += 2
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    c_depth -= 1
                    clean_chars.extend((" ", " "))
                    skel_chars.extend((" ", " "))
                    i += 2
                else:
                    out_c = "\n" if source[i] == "\n" else " "
                    clean_chars.append(out_c)
                    skel_chars.append(out_c)
                    i += 1
            continue

        if ch == '"' and i + 2 < n and source[i + 1] == '"' and source[i + 2] == '"':
            clean_chars.extend(('"', '"', '"'))
            skel_chars.extend(('"', " ", " "))
            i += 3
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    c1, c2 = source[i], source[i + 1]
                    clean_chars.extend((c1, c2))
                    skel_chars.extend((" ", "\n" if c2 == "\n" else " "))
                    i += 2
                    continue
                if (
                    source[i] == '"'
                    and i + 2 < n
                    and source[i + 1] == '"'
                    and source[i + 2] == '"'
                ):
                    clean_chars.extend(('"', '"', '"'))
                    skel_chars.extend((" ", " ", '"'))
                    i += 3
                    break
                out_c = "\n" if source[i] == "\n" else " "
                clean_chars.append(source[i])
                skel_chars.append(out_c)
                i += 1
            continue

        if ch == '"':
            clean_chars.append('"')
            skel_chars.append('"')
            i += 1
            interp_depth = 0
            while i < n:
                sc = source[i]
                if sc == "\n":
                    clean_chars.append("\n")
                    skel_chars.append("\n")
                    i += 1
                    break
                if sc == "\\" and i + 1 < n and source[i + 1] == "(":
                    interp_depth += 1
                    if delim_depth + interp_depth > max_depth:
                        raise ValueError(
                            f"String interpolation exceeds maximum nesting depth ({max_depth})."
                        )
                    clean_chars.extend(("\\", "("))
                    skel_chars.extend((" ", " "))
                    i += 2
                    continue
                if sc == "\\" and i + 1 < n and source[i + 1] != "\n":
                    clean_chars.extend((sc, source[i + 1]))
                    skel_chars.extend((" ", " "))
                    i += 2
                    continue
                if interp_depth > 0:
                    if sc == "(":
                        interp_depth += 1
                    elif sc == ")":
                        interp_depth -= 1
                    clean_chars.append(sc)
                    skel_chars.append(" ")
                    i += 1
                    continue
                if sc == '"':
                    clean_chars.append('"')
                    skel_chars.append('"')
                    i += 1
                    break
                clean_chars.append(sc)
                skel_chars.append(" ")
                i += 1
            continue

        if ch in "([{":
            delim_depth += 1
            if delim_depth > max_depth:
                raise ValueError(
                    f"Source file exceeds maximum delimiter nesting depth ({max_depth})."
                )
        elif ch in ")]}" and delim_depth > 0:
            delim_depth -= 1

        clean_chars.append(ch)
        skel_chars.append(ch)
        i += 1

    return "".join(clean_chars), "".join(skel_chars)


def find_matching_delim(skeleton: str, open_idx: int) -> int:
    """Find matching closing delimiter in `skeleton` (where comments & strings are masked)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    open_ch = skeleton[open_idx]
    close_ch = pairs[open_ch]
    depth = 1
    i = open_idx + 1
    n = len(skeleton)
    while i < n:
        ch = skeleton[i]
        if ch == open_ch:
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                raise ValueError(
                    f"Source delimiter exceeds maximum nesting depth ({MAX_NESTING_DEPTH})."
                )
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def split_top_level_spans(
    skeleton: str,
    start: int,
    end: int,
    sep: str = ",",
) -> list[tuple[int, int]]:
    """Split `skeleton[start:end]` on `sep` at delimiter depth 0."""
    spans: list[tuple[int, int]] = []
    cur = start
    depth = 0
    for i in range(start, end):
        ch = skeleton[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        elif ch == sep and depth == 0:
            if skeleton[cur:i].strip():
                spans.append((cur, i))
            cur = i + 1
    if skeleton[cur:end].strip():
        spans.append((cur, end))
    return spans


@dataclass(frozen=True)
class SwiftTargetDependency:
    """Normalized `Package.swift` target or product dependency item."""

    name: str
    kind: Literal["target", "product"] = "target"
    package: str | None = None


@dataclass(frozen=True)
class SwiftTargetDecl:
    """Normalized `Package.swift` target declaration."""

    name: str
    kind: TargetDeclKind
    rel_path: str
    dependencies: tuple[SwiftTargetDependency, ...] = ()
    public_headers_path: str | None = None
    exclude: tuple[str, ...] = ()
    line: int = 1
    is_c_target: bool = False
    path_valid: bool = True

    @property
    def is_test_target(self) -> bool:
        return (
            self.kind == "testTarget"
            or self.rel_path == "Tests"
            or self.rel_path.startswith("Tests/")
        )

    @property
    def is_runtime_target(self) -> bool:
        return (
            self.path_valid
            and not self.is_test_target
            and self.kind in ("executableTarget", "target", "systemLibrary")
        )


@dataclass(frozen=True)
class PackageManifest:
    """Parsed `Package.swift` manifest model."""

    package_name: str
    manifest_rel_path: str = "Package.swift"
    tools_version: str | None = None
    products: dict[str, tuple[str, ...]] = field(default_factory=dict)
    targets: dict[str, SwiftTargetDecl] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def resolve_target_for_file(self, rel_posix: str) -> SwiftTargetDecl | None:
        """Return the most specific `SwiftTargetDecl` owning `rel_posix`, or `None`."""
        best: SwiftTargetDecl | None = None
        best_parts = -1
        for tgt in self.targets.values():
            if not tgt.path_valid:
                continue
            tp = tgt.rel_path.strip("/")
            if not tp:
                continue
            if rel_posix == tp or rel_posix.startswith(f"{tp}/"):
                sub_rel = rel_posix[len(tp) :].lstrip("/")
                if any(
                    sub_rel == ex.strip("/") or sub_rel.startswith(f"{ex.strip('/')}/")
                    for ex in tgt.exclude
                    if ex.strip("/")
                ):
                    continue
                n_parts = len(PurePosixPath(tp).parts)
                if n_parts > best_parts:
                    best = tgt
                    best_parts = n_parts
        return best

    def allowed_sibling_imports(
        self,
        target_name: str,
        exported_by_target: dict[str, set[str]] | None = None,
    ) -> frozenset[str]:
        """Return in-repo target names that `target_name` is permitted to `import`."""
        tgt = self.targets.get(target_name)
        if tgt is None:
            return frozenset()
        in_repo = set(self.targets)
        direct = {
            dep.name
            for dep in tgt.dependencies
            if dep.name in in_repo
            and (dep.kind == "target" or dep.package is None)
        }
        allowed = set(direct)
        if exported_by_target:
            frontier = list(direct)
            while frontier:
                cur = frontier.pop()
                for re_exp in exported_by_target.get(cur, ()):
                    if re_exp in in_repo and re_exp not in allowed:
                        allowed.add(re_exp)
                        frontier.append(re_exp)
        return frozenset(allowed)


_TARGET_CTOR_RE = re.compile(
    r"\.\s*(executableTarget|target|systemLibrary|testTarget|plugin|binaryTarget|macro)\s*\("
)
_DEP_ITEM_RE = re.compile(
    r"\.\s*(target|targetItem|byName|byNameItem|product|productItem)\s*\("
)
_PRODUCT_CTOR_RE = re.compile(r"\.\s*(executable|library)\s*\(")
_ARG_LABEL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*")


def _unescape_swift_string(raw_inner: str) -> str:
    return (
        raw_inner.replace('\\"', '"')
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
    )


def _first_string_in(clean_slice: str) -> str | None:
    m = _QUOTED_STR_RE.search(clean_slice)
    if m is None:
        return None
    val = _unescape_swift_string(m.group(1)).strip()
    if "\\(" in val:
        return None
    return val


def _all_strings_in(clean_slice: str) -> list[str]:
    out: list[str] = []
    for m in _QUOTED_STR_RE.finditer(clean_slice):
        val = _unescape_swift_string(m.group(1)).strip()
        if val and "\\(" not in val:
            out.append(val)
    return out


def _parse_dependency_array(
    clean: str,
    skeleton: str,
    arr_start: int,
    arr_end: int,
) -> tuple[SwiftTargetDependency, ...]:
    deps: list[SwiftTargetDependency] = []
    for s_idx, e_idx in split_top_level_spans(skeleton, arr_start + 1, arr_end, ","):
        item_skel = skeleton[s_idx:e_idx]
        item_clean = clean[s_idx:e_idx]
        dm = _DEP_ITEM_RE.search(item_skel)
        if dm is not None:
            ctor_kind = dm.group(1)
            open_p = s_idx + dm.end() - 1
            close_p = find_matching_delim(skeleton, open_p)
            if close_p == -1:
                continue
            dep_name: str | None = None
            pkg_name: str | None = None
            for a_s, a_e in split_top_level_spans(skeleton, open_p + 1, close_p, ","):
                arg_skel = skeleton[a_s:a_e]
                arg_clean = clean[a_s:a_e]
                lm = _ARG_LABEL_RE.match(arg_skel)
                lbl = lm.group(1) if lm else ""
                sval = _first_string_in(arg_clean)
                if sval and (lbl == "name" or (not lbl and dep_name is None)):
                    dep_name = sval
                elif sval and lbl == "package":
                    pkg_name = sval
            if dep_name:
                kind: Literal["target", "product"] = (
                    "product" if ctor_kind in ("product", "productItem") else "target"
                )
                deps.append(SwiftTargetDependency(name=dep_name, kind=kind, package=pkg_name))
            continue

        bare = _first_string_in(item_clean)
        if bare and _IDENT_RE.match(bare):
            deps.append(SwiftTargetDependency(name=bare, kind="target"))
    return tuple(deps)


def _default_target_rel_path(name: str, kind: TargetDeclKind) -> str:
    if kind == "testTarget":
        return f"Tests/{name}"
    if kind == "plugin":
        return f"Plugins/{name}"
    return f"Sources/{name}"


def _validate_target_rel_path(
    raw_rel: str,
    target_name: str,
    real_root: Path | None,
    notes: list[str],
) -> tuple[str, bool]:
    cleaned = raw_rel.strip().replace("\\", "/").strip("/")
    if (
        not cleaned
        or "\x00" in cleaned
        or raw_rel.strip().startswith("/")
        or ".." in PurePosixPath(cleaned).parts
    ):
        notes.append(
            f"Package.swift target '{target_name}' custom path '{raw_rel}' rejected (unsafe path)."
        )
        return cleaned or f"Sources/{target_name}", False

    if real_root is not None:
        walk = real_root
        for part in PurePosixPath(cleaned).parts:
            if part in ("", "."):
                continue
            walk = walk / part
            if walk.is_symlink():
                notes.append(
                    f"Package.swift target '{target_name}' path '{cleaned}' rejected (symlink component)."
                )
                return cleaned, False
        if walk.exists() and not walk.resolve().is_relative_to(real_root):
            notes.append(
                f"Package.swift target '{target_name}' path '{cleaned}' escapes repository root."
            )
            return cleaned, False
    return cleaned, True


def _dir_looks_like_c_target(target_dir: Path) -> bool:
    if not target_dir.exists() or target_dir.is_symlink() or not target_dir.is_dir():
        return False
    has_c_or_hdr = False
    has_swift = False
    for parent, dirs, names in os.walk(target_dir, followlinks=False):
        dirs[:] = [
            d
            for d in sorted(dirs)
            if not d.startswith(".") and not (Path(parent) / d).is_symlink()
        ]
        for fname in names:
            fp = Path(parent) / fname
            if fp.is_symlink():
                continue
            if fp.suffix == ".swift":
                has_swift = True
            elif fp.suffix in (".c", ".h", ".m", ".mm", ".cpp", ".cc") or fname == "module.modulemap":
                has_c_or_hdr = True
    return has_c_or_hdr and not has_swift


def parse_package_manifest_text(
    source: str,
    *,
    manifest_rel_path: str = "Package.swift",
    real_root: Path | None = None,
) -> PackageManifest:
    """Parse `Package.swift` source text into a deterministic `PackageManifest`."""
    tv_match = _TOOLS_VERSION_RE.search(source[:512])
    tools_version = tv_match.group(1) if tv_match else None
    clean, skeleton = sanitize_swift_source(source)
    notes: list[str] = []

    pkg_name = "SwiftPackage"
    pkg_match = re.search(r"\bPackage\s*\(", skeleton)
    if pkg_match is not None:
        p_open = pkg_match.end() - 1
        p_close = find_matching_delim(skeleton, p_open)
        if p_close != -1:
            for a_s, a_e in split_top_level_spans(skeleton, p_open + 1, p_close, ","):
                lm = _ARG_LABEL_RE.match(skeleton[a_s:a_e])
                if lm and lm.group(1) == "name":
                    found_n = _first_string_in(clean[a_s:a_e])
                    if found_n:
                        pkg_name = found_n
                    break

    products: dict[str, tuple[str, ...]] = {}
    prod_cursor = 0
    while True:
        pm = _PRODUCT_CTOR_RE.search(skeleton, prod_cursor)
        if pm is None:
            break
        p_open = pm.end() - 1
        p_close = find_matching_delim(skeleton, p_open)
        if p_close == -1:
            break
        prod_cursor = p_close + 1
        p_name: str | None = None
        p_targets: list[str] = []
        for a_s, a_e in split_top_level_spans(skeleton, p_open + 1, p_close, ","):
            lm = _ARG_LABEL_RE.match(skeleton[a_s:a_e])
            lbl = lm.group(1) if lm else ""
            if lbl == "name" or (not lbl and p_name is None):
                p_name = _first_string_in(clean[a_s:a_e])
            elif lbl == "targets":
                p_targets.extend(_all_strings_in(clean[a_s:a_e]))
        if p_name:
            products[p_name] = tuple(p_targets)

    targets: dict[str, SwiftTargetDecl] = {}
    cursor = 0
    while True:
        tm = _TARGET_CTOR_RE.search(skeleton, cursor)
        if tm is None:
            break
        t_kind: TargetDeclKind = tm.group(1)  # type: ignore[assignment]
        t_open = tm.end() - 1
        t_close = find_matching_delim(skeleton, t_open)
        if t_close == -1:
            break
        cursor = t_close + 1

        prefix_ctx = skeleton[max(0, tm.start() - 96) : tm.start()]
        if "Target.Dependency" in prefix_ctx:
            continue

        t_name: str | None = None
        custom_path: str | None = None
        pub_headers: str | None = None
        excludes: list[str] = []
        deps: tuple[SwiftTargetDependency, ...] = ()
        arg_spans = split_top_level_spans(skeleton, t_open + 1, t_close, ",")
        seen_labels: set[str] = set()

        for a_s, a_e in arg_spans:
            arg_skel = skeleton[a_s:a_e]
            arg_clean = clean[a_s:a_e]
            lm = _ARG_LABEL_RE.match(arg_skel)
            lbl = lm.group(1) if lm else ""
            if lbl:
                seen_labels.add(lbl)
            if lbl == "name" or (not lbl and t_name is None):
                t_name = _first_string_in(arg_clean)
            elif lbl == "path":
                custom_path = _first_string_in(arg_clean)
            elif lbl == "publicHeadersPath":
                pub_headers = _first_string_in(arg_clean)
            elif lbl == "exclude":
                excludes.extend(_all_strings_in(arg_clean))
            elif lbl == "dependencies":
                br_idx = arg_skel.find("[")
                if br_idx != -1:
                    abs_br = a_s + br_idx
                    abs_close = find_matching_delim(skeleton, abs_br)
                    if abs_close != -1:
                        deps = _parse_dependency_array(clean, skeleton, abs_br, abs_close)

        if not t_name:
            continue
        if (
            t_kind == "target"
            and t_name in targets
            and seen_labels <= {"name", "condition"}
        ):
            continue

        line_no = source.count("\n", 0, tm.start()) + 1
        if custom_path is not None:
            rel_p, p_ok = _validate_target_rel_path(custom_path, t_name, real_root, notes)
        else:
            rel_p = _default_target_rel_path(t_name, t_kind)
            _, p_ok = _validate_target_rel_path(rel_p, t_name, real_root, notes)

        c_flag = t_kind == "systemLibrary" or pub_headers is not None
        if not c_flag and p_ok and real_root is not None:
            c_flag = _dir_looks_like_c_target(real_root / PurePosixPath(rel_p))

        targets[t_name] = SwiftTargetDecl(
            name=t_name,
            kind=t_kind,
            rel_path=rel_p,
            dependencies=deps,
            public_headers_path=pub_headers,
            exclude=tuple(excludes),
            line=line_no,
            is_c_target=c_flag,
            path_valid=p_ok,
        )

    return PackageManifest(
        package_name=pkg_name,
        manifest_rel_path=manifest_rel_path,
        tools_version=tools_version,
        products=products,
        targets=targets,
        notes=notes,
    )


def parse_package_manifest(
    manifest_or_repo: str | Path,
    *,
    repo_root: Path | None = None,
) -> PackageManifest:
    """Safely read and parse `Package.swift` from a file or repository root."""
    cand = Path(manifest_or_repo)
    if cand.name == "Package.swift" or str(manifest_or_repo).endswith(".swift"):
        root = repo_root if repo_root is not None else cand.parent
        safe_manifest = resolve_safe_source_path(cand, repo_root=root)
        real_root = validate_safe_directory(root)
    else:
        real_root = validate_safe_directory(cand)
        safe_manifest = resolve_safe_source_path("Package.swift", repo_root=real_root)

    rel_p = safe_manifest.relative_to(real_root).as_posix()
    text = read_bounded_text(safe_manifest)
    return parse_package_manifest_text(text, manifest_rel_path=rel_p, real_root=real_root)


def iter_safe_repo_files(
    repo_root: Path,
    suffixes: set[str],
    *,
    include_tests: bool = False,
) -> tuple[list[tuple[Path, str]], int, list[str]]:
    """Walk `repo_root` without following symlinks and enforce bounded file sizes."""
    real_root = validate_safe_directory(repo_root)
    collected: list[tuple[Path, str]] = []
    excluded_links = 0
    notes: list[str] = []

    for parent, dirs, names in os.walk(real_root, followlinks=False):
        parent_path = Path(parent)
        kept_dirs: list[str] = []
        for dname in sorted(dirs):
            dpath = parent_path / dname
            if dpath.is_symlink():
                excluded_links += 1
                rel_link = dpath.relative_to(real_root).as_posix()
                notes.append(f"Excluded symlinked directory '{rel_link}'.")
                continue
            if dname in EXCLUDED_REPO_DIRS or dname.startswith("."):
                continue
            if not include_tests and (dname in ("Tests", "tests", "Test") or dname.endswith("Tests")):
                continue
            kept_dirs.append(dname)
        dirs[:] = kept_dirs

        for fname in sorted(names):
            fpath = parent_path / fname
            if fpath.suffix not in suffixes:
                continue
            try:
                st = fpath.lstat()
            except OSError:
                continue
            rel_file = fpath.relative_to(real_root).as_posix()
            if stat.S_ISLNK(st.st_mode):
                excluded_links += 1
                notes.append(f"Excluded symlinked source file '{rel_file}'.")
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size > MAX_SOURCE_FILE_BYTES:
                notes.append(
                    f"Skipped oversized file '{rel_file}' ({st.st_size} bytes > {MAX_SOURCE_FILE_BYTES})."
                )
                continue
            collected.append((fpath, rel_file))

    return collected, excluded_links, notes
