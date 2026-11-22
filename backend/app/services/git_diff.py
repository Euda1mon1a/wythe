"""Read exact Git diff sides and materialize a base tree without checkout hooks."""

from __future__ import annotations

import io
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.safe_git import SafeGitError, run_safe_git

_HUNK = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    try:
        proc = run_safe_git(
            root,
            *args,
            input_bytes=input,
            text=False,
            check=True,
            timeout=60.0,
        )
        return bytes(proc.stdout)
    except (OSError, subprocess.SubprocessError, SafeGitError) as exc:
        raise ValueError(
            f"Cannot read Git evidence ({args[0]}); check the repository and base ref"
        ) from exc


@dataclass
class GitChanges:
    base_commit: str
    before: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    after: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


def collect_git_changes(root: Path, base_ref: str) -> GitChanges:
    cleaned_ref = base_ref.strip()
    if not cleaned_ref or cleaned_ref.startswith("-"):
        raise ValueError("Invalid Git base ref")
    ref = "HEAD" if cleaned_ref.upper() == "WORKING" else cleaned_ref
    sha = _git(root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    changes = GitChanges(sha.decode().strip())
    # `--relative` scopes paths to `root` when scanning a monorepo subdirectory so
    # `changed_ranges` keys match `target.repo_path`-relative `BoundaryFinding.source_file`s.
    raw = _git(
        root,
        "diff",
        "--relative",
        "--ignore-submodules=all",
        "--raw",
        "-z",
        "--patch",
        "--no-color",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=0",
        changes.base_commit,
        "--",
    )
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
                old_len = int(old_count) if old_count is not None else 1
                new_len = int(new_count) if new_count is not None else 1
                if path in changes.before and old_len:
                    changes.before[path].append((int(old), int(old) + old_len - 1))
                if path in changes.after:
                    if new_len:
                        changes.after[path].append((int(new), int(new) + new_len - 1))
                    else:
                        # Pure-deletion hunk (`+start,0`): anchor adjacent line so hunk-only
                        # fallback when `base_report` is unavailable still sees the edit site.
                        anchor = max(1, int(new))
                        changes.after[path].append((anchor, anchor + 1))
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "--full-name", "-z")
    prefix = _git(root, "rev-parse", "--show-prefix").decode("utf-8", errors="surrogateescape").strip()
    for raw_untracked in untracked.split(b"\0"):
        if not raw_untracked:
            continue
        u_str = raw_untracked.decode("utf-8", errors="surrogateescape")
        if prefix:
            if not u_str.startswith(prefix):
                continue
            u_str = u_str[len(prefix) :]
        if u_str:
            changes.after[u_str] = [(1, 1_000_000)]
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
    """Copy committed blobs for `root`'s git subtree into `destination` without executing code."""
    prefix = _git(root, "rev-parse", "--show-prefix").decode("utf-8", errors="surrogateescape").strip()
    entries = _git(root, "ls-tree", "-r", "-z", "--full-tree", base_commit)
    dest_real = destination.resolve()
    paths_by_oid: dict[bytes, list[Path]] = {}
    regular_oid_by_rel: dict[str, bytes] = {}
    symlink_oid_by_rel: dict[str, tuple[PurePosixPath, bytes]] = {}
    needed_oids: list[bytes] = []
    seen_oids: set[bytes] = set()

    def _in_target_subtree(rel_posix: str) -> str | None:
        if not prefix:
            return rel_posix
        if rel_posix.startswith(prefix):
            sub = rel_posix[len(prefix) :]
            return sub if sub else None
        return None

    for entry in entries.split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = header.split()
        path = PurePosixPath(raw_path.decode("utf-8", errors="surrogateescape"))
        if path.is_absolute() or any(p in ("..", ".git") for p in path.parts):
            raise ValueError("Unsafe path in base tree")
        rel_posix = path.as_posix()
        sub_rel = _in_target_subtree(rel_posix)
        if mode in (b"100644", b"100755") and kind == b"blob":
            regular_oid_by_rel[rel_posix] = oid
            if sub_rel is not None:
                sub_parts = PurePosixPath(sub_rel).parts
                paths_by_oid.setdefault(oid, []).append(destination.joinpath(*sub_parts))
                if oid not in seen_oids:
                    seen_oids.add(oid)
                    needed_oids.append(oid)
        elif mode == b"120000" and kind == b"blob":
            symlink_oid_by_rel[rel_posix] = (path, oid)
            if oid not in seen_oids:
                seen_oids.add(oid)
                needed_oids.append(oid)
        elif mode == b"160000" and kind == b"commit":
            if sub_rel is not None:
                sub_dir = destination.joinpath(*PurePosixPath(sub_rel).parts)
                if not sub_dir.resolve().is_relative_to(dest_real):
                    raise ValueError("Unsafe destination path in base tree")
                sub_dir.mkdir(parents=True, exist_ok=True)
        elif sub_rel is not None:
            raise ValueError(f"Base tree contains an unresolved symlink or submodule: {path}")

    if symlink_oid_by_rel:
        # Ensure target blobs of intra-repo symlinks inside `sub_rel` are fetched too
        symlink_oids = [oid for _, oid in symlink_oid_by_rel.values()]
        sym_data = io.BytesIO(_git(root, "cat-file", "--batch", input=b"\n".join(symlink_oids) + b"\n"))
        symlink_targets: dict[str, str] = {}
        for (_, oid), rel in zip(symlink_oid_by_rel.values(), symlink_oid_by_rel.keys(), strict=True):
            hdr = sym_data.readline().split()
            if len(hdr) != 3 or hdr[:2] != [oid, b"blob"]:
                raise ValueError("Incomplete base symlink blob evidence")
            sz = int(hdr[2])
            raw_b = sym_data.read(sz)
            if len(raw_b) != sz or sym_data.read(1) != b"\n":
                raise ValueError("Truncated base symlink blob evidence")
            if len(raw_b) > 4096:
                raise ValueError(f"Base tree contains an unresolved symlink or submodule: {rel}")
            symlink_targets[rel] = raw_b.decode("utf-8", errors="surrogateescape")

        for lpath, _oid in symlink_oid_by_rel.values():
            sub_rel = _in_target_subtree(lpath.as_posix())
            if sub_rel is None:
                continue
            resolved_rel = _resolve_intra_repo_symlink(lpath, symlink_targets)
            if resolved_rel not in regular_oid_by_rel:
                raise ValueError(f"Base tree contains an unresolved symlink or submodule: {lpath}")
            if prefix and not resolved_rel.startswith(prefix):
                raise ValueError(f"Base tree symlink escapes target subdirectory: {lpath}")
            tgt_oid = regular_oid_by_rel[resolved_rel]
            paths_by_oid.setdefault(tgt_oid, []).append(
                destination.joinpath(*PurePosixPath(sub_rel).parts)
            )
            if tgt_oid not in seen_oids:
                seen_oids.add(tgt_oid)
                needed_oids.append(tgt_oid)

    blob_oids = [oid for oid in needed_oids if oid in paths_by_oid]
    if not blob_oids:
        return
    data = io.BytesIO(_git(root, "cat-file", "--batch", input=b"\n".join(blob_oids) + b"\n"))
    blobs_by_oid: dict[bytes, bytes] = {}
    for oid in blob_oids:
        header = data.readline().split()
        if len(header) != 3 or header[:2] != [oid, b"blob"]:
            raise ValueError("Incomplete base blob evidence")
        size = int(header[2])
        contents = data.read(size)
        if len(contents) != size or data.read(1) != b"\n":
            raise ValueError("Truncated base blob evidence")
        blobs_by_oid[oid] = contents

    for oid, paths in paths_by_oid.items():
        contents = blobs_by_oid[oid]
        for path in paths:
            if not path.resolve().is_relative_to(dest_real):
                raise ValueError("Unsafe destination path in base tree")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
