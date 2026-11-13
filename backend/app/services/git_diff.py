"""Read exact Git diff sides and materialize a base tree without checkout hooks."""

from __future__ import annotations

import io
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

_HUNK = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    try:
        return subprocess.run(
            ["git", *args], cwd=root, input=input, capture_output=True, check=True, timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"Cannot read Git evidence ({args[0]}); check the repository and base ref") from exc


@dataclass
class GitChanges:
    base_commit: str
    before: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    after: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


def collect_git_changes(root: Path, base_ref: str) -> GitChanges:
    ref = "HEAD" if base_ref.upper() == "WORKING" else base_ref
    sha = _git(root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    changes = GitChanges(sha.decode().strip())
    # NUL-delimited raw paths handle spaces, quotes, tabs and Unicode without decoding
    # Git's quoted patch headers. Disabling rename detection preserves both paths.
    raw = _git(root, "diff", "--raw", "-z", "--patch", "--no-color", "--no-renames", "--no-ext-diff",
               "--no-textconv", "--unified=0", changes.base_commit, "--")
    if raw:
        metadata, separator, patch = raw.partition(b"\0\0")
        fields = metadata.split(b"\0")
        blocks = re.split(rb"^diff --git .*\n", patch, flags=re.MULTILINE)[1:]
        if not separator or len(fields) % 2 or len(blocks) != len(fields) // 2:
            raise ValueError("Git diff evidence changed or could not be parsed completely")
        for i, block in enumerate(blocks):
            status = fields[i * 2].split()[-1]
            path = fields[i * 2 + 1].decode("utf-8", errors="surrogateescape")
            if status != b"A":
                changes.before[path] = []
            if status != b"D":
                changes.after[path] = []
                if b"Binary files " in block:
                    changes.after[path] = [(1, 1_000_000)]
            for match in _HUNK.finditer(block):
                old, old_count, new, new_count = match.groups()
                for ranges, start, count in (
                    (changes.before, old, old_count), (changes.after, new, new_count),
                ):
                    length = int(count) if count is not None else 1
                    if path in ranges and length:
                        ranges[path].append((int(start), int(start) + length - 1))
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    for path in untracked.split(b"\0"):
        if path:
            changes.after[path.decode("utf-8", errors="surrogateescape")] = [(1, 1_000_000)]
    return changes


def materialize_base_tree(root: Path, base_commit: str, destination: Path) -> None:
    """Copy committed blobs exactly, including export-ignored files; never execute code.

    Unsupported symlinks and submodules fail explicitly instead of inventing a
    complete before-image. The caller reports incomplete evidence in that case.
    """
    entries = _git(root, "ls-tree", "-r", "-z", "--full-tree", base_commit)
    paths_by_oid: dict[bytes, list[Path]] = {}
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = header.split()
        path = PurePosixPath(raw_path.decode("utf-8", errors="surrogateescape"))
        if path.is_absolute() or any(p in ("..", ".git") for p in path.parts):
            raise ValueError("Unsafe path in base tree")
        if mode not in (b"100644", b"100755") or kind != b"blob":
            raise ValueError(f"Base tree contains an unresolved symlink or submodule: {path}")
        paths_by_oid.setdefault(oid, []).append(destination.joinpath(*path.parts))
    if not paths_by_oid:
        return
    data = io.BytesIO(_git(root, "cat-file", "--batch", input=b"\n".join(paths_by_oid) + b"\n"))
    for oid, paths in paths_by_oid.items():
        header = data.readline().split()
        if len(header) != 3 or header[:2] != [oid, b"blob"]:
            raise ValueError("Incomplete base blob evidence")
        size = int(header[2])
        contents = data.read(size)
        if len(contents) != size or data.read(1) != b"\n":
            raise ValueError("Truncated base blob evidence")
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
