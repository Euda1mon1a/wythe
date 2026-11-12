"""Read-only repository source-snippet reader bounded strictly to target repo root."""

from __future__ import annotations

from pathlib import Path

from app.schemas.atlas import SourceSnippetLine, SourceSnippetRead

_BLOCKED_DIRS = {".git", "secrets", ".secrets", "node_modules"}
_BLOCKED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db", ".der"}
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


def read_target_source_snippet(
    repo_root: Path,
    target_slug: str,
    rel_path: str,
    *,
    focus_line: int = 1,
    context_lines: int = 12,
) -> SourceSnippetRead:
    """Return bounded lines around `focus_line` inside `repo_root / rel_path`."""
    clean_root = repo_root.resolve()
    candidate = (clean_root / rel_path).resolve()
    if not candidate.is_relative_to(clean_root):
        raise SourcePeekPermissionError("Requested path escapes repository root.")

    rel = candidate.relative_to(clean_root)
    for part in rel.parts:
        lower = part.lower()
        if lower in _BLOCKED_DIRS or lower == ".env" or lower.startswith(".env."):
            raise SourcePeekPermissionError("Sensitive or ignored path is blocked.")
    if candidate.suffix.lower() in _BLOCKED_SUFFIXES:
        raise SourcePeekPermissionError("Binary or key file extension is blocked.")
    if not candidate.is_file():
        raise FileNotFoundError(f"Source file '{rel.as_posix()}' does not exist.")
    if candidate.stat().st_size > _MAX_BYTES:
        raise SourcePeekPermissionError("Source file exceeds 2 MB snippet preview limit.")

    raw = candidate.read_text(encoding="utf-8", errors="replace")
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
