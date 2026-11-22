"""Read-only repository source-snippet reader bounded strictly to target repo root."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from app.schemas.atlas import SourceSnippetLine, SourceSnippetRead

_BLOCKED_DIRS = frozenset(
    {
        ".git",
        "secrets",
        ".secrets",
        "node_modules",
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
    }
)
_BLOCKED_SUFFIXES = frozenset(
    {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".db3",
        ".der",
        ".env",
        ".envrc",
        ".kubeconfig",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".pgpass",
    }
)
_BLOCKED_EXACT_NAMES = frozenset(
    {
        ".env",
        ".envrc",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".pgpass",
        "kubeconfig",
        "credentials",
        "credentials.json",
        "client_secret.json",
    }
)
_BLOCKED_PREFIXES = (
    ".env.",
    "secrets.",
    "kubeconfig.",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
)
_MAX_BYTES = 2_000_000

_LANG_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "jsx",
    ".sql": "sql",
    ".rs": "rust",
    ".go": "go",
    ".vue": "vue",
    ".svelte": "svelte",
    ".prisma": "prisma",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
}


class SourcePeekPermissionError(ValueError):
    """Raised when a requested path escapes the repository root or touches a secret."""


def is_blocked_secret_path(rel_path: Path | str) -> bool:
    """Return True if `rel_path` matches any blocked secret, credential, key, or DB pattern."""
    rel = Path(rel_path)
    for part in rel.parts:
        low = part.lower()
        if low in _BLOCKED_DIRS or low in _BLOCKED_EXACT_NAMES:
            return True
        if low.startswith(_BLOCKED_PREFIXES) or low.endswith(".env") or ".env." in low:
            return True
        if "credentials" in low and low.endswith((".json", ".ini", ".toml", ".yaml", ".yml", "")):
            return True
        if ".sqlite" in low or low.endswith((".db-wal", ".db-shm", ".db-journal")):
            return True
    return rel.suffix.lower() in _BLOCKED_SUFFIXES


def read_target_source_snippet(
    repo_root: Path,
    target_slug: str,
    rel_path: str,
    *,
    focus_line: int = 1,
    context_lines: int = 12,
) -> SourceSnippetRead:
    """Return bounded lines around `focus_line` inside `repo_root / rel_path`."""
    if "\x00" in rel_path or repo_root.is_symlink():
        raise SourcePeekPermissionError("Requested path escapes repository root.")
    clean_root = repo_root.resolve()
    rel_obj = Path(rel_path)
    if rel_obj.is_absolute() or ".." in rel_obj.parts:
        raise SourcePeekPermissionError("Requested path escapes repository root.")

    cur = clean_root
    for part in rel_obj.parts:
        if part in ("", "."):
            continue
        cur = cur / part
        if cur.is_symlink():
            raise SourcePeekPermissionError("Symlinked source path is blocked.")

    candidate = cur.resolve()
    if not candidate.is_relative_to(clean_root):
        raise SourcePeekPermissionError("Requested path escapes repository root.")

    rel = candidate.relative_to(clean_root)
    if is_blocked_secret_path(rel):
        raise SourcePeekPermissionError("Sensitive, credential, database, or key path is blocked.")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(cur, flags)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Source file '{rel.as_posix()}' does not exist.") from exc
    except OSError as exc:
        raise SourcePeekPermissionError(f"Source file '{rel.as_posix()}' cannot be opened safely.") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SourcePeekPermissionError("Source path must be a regular file.")
        if st.st_size > _MAX_BYTES:
            raise SourcePeekPermissionError("Source file exceeds 2 MB snippet preview limit.")
        chunks: list[bytes] = []
        rem = _MAX_BYTES + 1
        while rem > 0:
            blk = os.read(fd, min(65536, rem))
            if not blk:
                break
            chunks.append(blk)
            rem -= len(blk)
        raw_bytes = b"".join(chunks)
    finally:
        os.close(fd)

    if len(raw_bytes) > _MAX_BYTES:
        raise SourcePeekPermissionError("Source file exceeds 2 MB snippet preview limit.")

    raw = raw_bytes.decode("utf-8", errors="replace")
    all_lines = raw.splitlines()
    total = len(all_lines)
    if total == 0:
        return SourceSnippetRead(
            target_slug=target_slug,
            rel_path=rel.as_posix(),
            abs_path=str(candidate),
            focus_line=1,
            start_line=1,
            end_line=1,
            total_lines=0,
            language=_LANG_BY_SUFFIX.get(candidate.suffix.lower(), "text"),
            lines=[],
        )

    clamped_focus = max(1, min(focus_line, total))
    start = max(1, clamped_focus - context_lines)
    end = min(total, clamped_focus + context_lines)
    snippet_lines = [
        SourceSnippetLine(
            line_number=ln,
            text=all_lines[ln - 1],
            is_focus=(ln == clamped_focus),
        )
        for ln in range(start, end + 1)
    ]
    return SourceSnippetRead(
        target_slug=target_slug,
        rel_path=rel.as_posix(),
        abs_path=str(candidate),
        focus_line=clamped_focus,
        start_line=start,
        end_line=end,
        total_lines=total,
        language=_LANG_BY_SUFFIX.get(candidate.suffix.lower(), "text"),
        lines=snippet_lines,
    )
