"""Bounded source discovery; never follow links or inspect installed runtime paths."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Literal

EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "vendor",
        "__pycache__",
        "tests",
        "test",
        "fixtures",
        "docs",
        "archive",
        "archived",
        "disabled",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)


def source_files(
    root: Path,
    suffixes: set[str],
    *,
    skipped_out: list[str] | None = None,
) -> tuple[list[Path], int]:
    """Return eligible regular source files and number of excluded directories/links."""
    try:
        if root.is_symlink():
            if skipped_out is not None:
                skipped_out.append(f"{root}: symlink")
            return [], 1
        if not root.exists():
            return [], 0
    except OSError as exc:
        if skipped_out is not None:
            skipped_out.append(f"{root}: {exc}")
        return [], 1

    files: list[Path] = []
    excluded = 0

    def _on_walk_error(exc: OSError) -> None:
        nonlocal excluded
        excluded += 1
        if skipped_out is not None:
            err_path = getattr(exc, "filename", None) or str(root)
            skipped_out.append(f"{err_path}: {exc}")

    for parent, dirs, names in os.walk(root, followlinks=False, onerror=_on_walk_error):
        keep: list[str] = []
        for name in sorted(dirs):
            if name in EXCLUDED_PARTS or name.startswith("."):
                excluded += 1
                continue
            dpath = Path(parent) / name
            try:
                is_sym = dpath.is_symlink()
            except OSError as exc:
                excluded += 1
                if skipped_out is not None:
                    skipped_out.append(f"{dpath}: {exc}")
                continue
            if is_sym:
                excluded += 1
                if skipped_out is not None:
                    skipped_out.append(f"{dpath}: symlink")
            else:
                keep.append(name)
        dirs[:] = keep
        for name in sorted(names):
            path = Path(parent) / name
            if path.suffix not in suffixes:
                continue
            try:
                st = path.lstat()
            except OSError as exc:
                excluded += 1
                if skipped_out is not None:
                    skipped_out.append(f"{path}: {exc}")
                continue
            if stat.S_ISLNK(st.st_mode):
                excluded += 1
                if skipped_out is not None:
                    skipped_out.append(f"{path}: symlink")
            elif stat.S_ISREG(st.st_mode):
                files.append(path)
            else:
                excluded += 1
                if skipped_out is not None:
                    skipped_out.append(f"{path}: non-regular file")
    return sorted(files), excluded


def source_reference_with_mode(
    raw: str, owner: str, paths: set[str]
) -> tuple[str, Literal["exact", "sibling", "suffix"]] | None:
    """Resolve a local source reference and report whether matching used `exact`, `sibling`, or `suffix`.

    Suffix matching is declaration evidence only: it never proves installation or
    the value of a variable. Bare names only resolve next to the referring file.
    Ambiguous suffixes remain unresolved instead of choosing an arbitrary file.
    """
    value = raw.strip().replace("\\", "/")
    if not value or "\x00" in value or "://" in value or ".." in PurePosixPath(value).parts:
        return None
    value = value.removeprefix("./")
    if value in paths:
        return value, "exact"
    sibling = str(PurePosixPath(owner).parent / value)
    if sibling in paths:
        return sibling, "sibling"
    parts = PurePosixPath(value).parts
    for count in range(len(parts), 1, -1):
        suffix = "/".join(parts[-count:])
        if re.search(r"[$~{}]", suffix):
            continue
        matches = sorted(p for p in paths if p == suffix or p.endswith("/" + suffix))
        if len(matches) == 1:
            return matches[0], "suffix"
        if matches:
            return None
    return None


def source_reference(raw: str, owner: str, paths: set[str]) -> str | None:
    """Resolve a local source reference, or a unique multi-part deployed-path suffix."""
    resolved = source_reference_with_mode(raw, owner, paths)
    return resolved[0] if resolved is not None else None


def script_id(path: str) -> str:
    return f"m:script:{path}"
