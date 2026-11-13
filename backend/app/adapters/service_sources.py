"""Bounded source discovery; never follow links or inspect installed runtime paths."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

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


def source_files(root: Path, suffixes: set[str]) -> tuple[list[Path], int]:
    """Return eligible regular source files and number of excluded directories/links."""
    files: list[Path] = []
    excluded = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        keep = []
        for name in sorted(dirs):
            if name in EXCLUDED_PARTS or name.startswith(".") or (Path(parent) / name).is_symlink():
                excluded += 1
            else:
                keep.append(name)
        dirs[:] = keep
        for name in sorted(names):
            path = Path(parent) / name
            if path.suffix not in suffixes:
                continue
            if path.is_symlink():
                excluded += 1
            elif path.is_file():
                files.append(path)
    return sorted(files), excluded


def source_reference(raw: str, owner: str, paths: set[str]) -> str | None:
    """Resolve a local source reference, or a unique multi-part deployed-path suffix.

    Suffix matching is declaration evidence only: it never proves installation or
    the value of a variable. Bare names only resolve next to the referring file.
    Ambiguous suffixes remain unresolved instead of choosing an arbitrary file.
    """
    value = raw.strip().replace("\\", "/")
    if not value or "\x00" in value or "://" in value or ".." in PurePosixPath(value).parts:
        return None
    value = value.removeprefix("./")
    if value in paths:
        return value
    sibling = str(PurePosixPath(owner).parent / value)
    if sibling in paths:
        return sibling
    parts = PurePosixPath(value).parts
    for count in range(len(parts), 1, -1):
        suffix = "/".join(parts[-count:])
        if re.search(r"[$~{}]", suffix):
            continue
        matches = sorted(p for p in paths if p == suffix or p.endswith("/" + suffix))
        if len(matches) == 1:
            return matches[0]
        if matches:
            return None
    return None


def script_id(path: str) -> str:
    return f"m:script:{path}"
