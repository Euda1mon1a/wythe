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


def _resolve_intra_repo_symlink(
    link_path: PurePosixPath,
    symlink_targets: dict[str, str],
) -> str:
    cur_link = link_path
    seen: set[str] = {cur_link.as_posix()}
    for _ in range(8):
        raw_target = symlink_targets[cur_link.as_posix()]
        if (
            not raw_target
            or "\x00" in raw_target
            or "\n" in raw_target
            or raw_target.startswith(("/", "~"))
        ):
            raise ValueError(f"Base tree contains an unresolved symlink or submodule: {link_path}")
        cur_parts = list(cur_link.parent.parts)
        parts = [p for p in raw_target.replace("\\", "/").split("/") if p not in ("", ".")]
        if not parts:
            raise ValueError(f"Base tree contains an unresolved symlink or submodule: {link_path}")
        for idx, part in enumerate(parts):
            if part == ".git":
                raise ValueError(f"Base tree contains an unsafe symlink target: {link_path}")
            if part == "..":
                if not cur_parts:
                    raise ValueError(
                        f"Base tree contains an unresolved symlink or submodule: {link_path}"
                    )
                cur_parts.pop()
            else:
                cur_parts.append(part)
            if idx < len(parts) - 1 and "/".join(cur_parts) in symlink_targets:
                raise ValueError(
                    f"Base tree contains an unresolved symlink or submodule: {link_path}"
                )
        if not cur_parts:
            raise ValueError(f"Base tree contains an unresolved symlink or submodule: {link_path}")
        resolved_rel = "/".join(cur_parts)
        if resolved_rel not in symlink_targets:
            return resolved_rel
        if resolved_rel in seen:
            raise ValueError(f"Base tree contains a symlink cycle: {link_path}")
        seen.add(resolved_rel)
        cur_link = PurePosixPath(resolved_rel)
    raise ValueError(f"Base tree contains an excessively deep symlink chain: {link_path}")


def materialize_base_tree(root: Path, base_commit: str, destination: Path) -> None:
    """Copy committed blobs exactly, including export-ignored files; never execute code.

    Committed intra-repo relative file symlinks (`120000`) whose normalized target is a
    committed regular file inside the same base tree are materialized as regular file
    copies strictly inside `destination` so downstream `O_NOFOLLOW` readers stay safe.
    Repo-escaping symlinks, directory symlinks, intermediate symlink hops, dangling/untracked
    targets, and submodules fail closed (`INCOMPLETE`).
    """
    entries = _git(root, "ls-tree", "-r", "-z", "--full-tree", base_commit)
    dest_real = destination.resolve()
    paths_by_oid: dict[bytes, list[Path]] = {}
    regular_oid_by_rel: dict[str, bytes] = {}
    symlink_oid_by_rel: dict[str, tuple[PurePosixPath, bytes]] = {}
    all_tracked_rels: set[str] = set()
    needed_oids: list[bytes] = []
    seen_oids: set[bytes] = set()

    for entry in entries.split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = header.split()
        path = PurePosixPath(raw_path.decode("utf-8", errors="surrogateescape"))
        if path.is_absolute() or any(p in ("..", ".git") for p in path.parts):
            raise ValueError("Unsafe path in base tree")
        rel_posix = path.as_posix()
        all_tracked_rels.add(rel_posix)
        if mode in (b"100644", b"100755") and kind == b"blob":
            regular_oid_by_rel[rel_posix] = oid
            paths_by_oid.setdefault(oid, []).append(destination.joinpath(*path.parts))
            if oid not in seen_oids:
                seen_oids.add(oid)
                needed_oids.append(oid)
        elif mode == b"120000" and kind == b"blob":
            symlink_oid_by_rel[rel_posix] = (path, oid)
            if oid not in seen_oids:
                seen_oids.add(oid)
                needed_oids.append(oid)
        else:
            raise ValueError(f"Base tree contains an unresolved symlink or submodule: {path}")

    if not needed_oids:
        return
    data = io.BytesIO(_git(root, "cat-file", "--batch", input=b"\n".join(needed_oids) + b"\n"))
    blobs_by_oid: dict[bytes, bytes] = {}
    for oid in needed_oids:
        header = data.readline().split()
        if len(header) != 3 or header[:2] != [oid, b"blob"]:
            raise ValueError("Incomplete base blob evidence")
        size = int(header[2])
        contents = data.read(size)
        if len(contents) != size or data.read(1) != b"\n":
            raise ValueError("Truncated base blob evidence")
        blobs_by_oid[oid] = contents

    if symlink_oid_by_rel:
        symlink_targets: dict[str, str] = {}
        for rel, (_, oid) in symlink_oid_by_rel.items():
            raw_bytes = blobs_by_oid[oid]
            if len(raw_bytes) > 4096:
                raise ValueError(f"Base tree contains an unresolved symlink or submodule: {rel}")
            symlink_targets[rel] = raw_bytes.decode("utf-8", errors="surrogateescape")
        for lpath, _oid in symlink_oid_by_rel.values():
            resolved_rel = _resolve_intra_repo_symlink(lpath, symlink_targets)
            if resolved_rel in regular_oid_by_rel:
                tgt_oid = regular_oid_by_rel[resolved_rel]
                paths_by_oid.setdefault(tgt_oid, []).append(destination.joinpath(*lpath.parts))
            else:
                raise ValueError(f"Base tree contains an unresolved symlink or submodule: {lpath}")

    for oid, paths in paths_by_oid.items():
        contents = blobs_by_oid[oid]
        for path in paths:
            if not path.resolve().is_relative_to(dest_real):
                raise ValueError("Unsafe destination path in base tree")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
