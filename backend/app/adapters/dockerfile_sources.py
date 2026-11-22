"""Static Dockerfile and .dockerignore lineage adapter.

Inspects build declarations without invoking `docker`, executing shell commands,
or following symlinks outside the repository root.
"""

from __future__ import annotations

import ast
import functools
import json
import os
import re
import shlex
import stat
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.service_sources import EXCLUDED_PARTS
from app.schemas.atlas import AtlasEdge, AtlasNode

MAX_ENV_VALUE_LEN = 8192
MAX_ENV_BINDINGS = 2048
MAX_DOCKERIGNORE_RULES = 2048

_DOCKERFILE_EXACT = frozenset({"Dockerfile", "Containerfile"})
_DOCKERFILE_PREFIXES = ("Dockerfile.", "Containerfile.")
_DOCKERFILE_SUFFIXES = (".Dockerfile", ".dockerfile", ".Containerfile", ".containerfile")
_IGNORED_DOCKERFILE_SUFFIXES = (".dockerignore", ".bak", ".orig", ".swp", ".tmp")
_COMPOSE_FILENAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
_COMPOSE_VARIANT_RE = re.compile(r"^(?:docker-)?compose(?:\.[A-Za-z0-9_.-]+)?\.(?:ya?ml)$")
ALLOWED_CONTAINER_DOT_DIRS = frozenset({".docker"})
CONTAINER_NODE_PREFIXES = ("m:dockerfile:", "m:compose:", "m:k8s:", "m:launchd:", "m:systemd:")
CONTAINER_EDGE_PREFIXES = (
    "e:deployment:",
    "e:launchd:",
    "e:systemd:",
    "e:dockerfile:",
    "e:compose:",
    "e:k8s:",
)
_SHELL_BINARIES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
_VAR_TOKEN_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})")
_ESCAPE_DIRECTIVE_RE = re.compile(r"^\s*#\s*escape\s*=\s*([\\`])\s*$", re.IGNORECASE)
_PY_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_compose_filename(name: str) -> bool:
    return bool(_COMPOSE_VARIANT_RE.match(name))


def _has_safe_path_segments(path_or_str: Path | str, *, max_segment_bytes: int = 255) -> bool:
    if isinstance(path_or_str, str):
        if not path_or_str or "\x00" in path_or_str:
            return False
        path_obj = Path(path_or_str)
    else:
        raw_s = str(path_or_str)
        if not raw_s or "\x00" in raw_s:
            return False
        path_obj = path_or_str
    anchor = path_obj.anchor
    for part in path_obj.parts:
        if part == anchor or part in ("", "."):
            continue
        if "\x00" in part or len(part.encode("utf-8", errors="surrogateescape")) > max_segment_bytes:
            return False
    return True


def _is_within_root(candidate: Path, real_root: Path) -> bool:
    if not _has_safe_path_segments(candidate):
        return False
    try:
        return candidate.resolve().is_relative_to(real_root)
    except (OSError, ValueError):
        return False


def _safe_is_symlink(path: Path) -> bool:
    if not _has_safe_path_segments(path):
        return False
    try:
        return path.is_symlink()
    except (OSError, ValueError):
        return False


def _safe_is_file(path: Path) -> bool:
    if not _has_safe_path_segments(path):
        return False
    try:
        return path.is_file()
    except (OSError, ValueError):
        return False


def _safe_is_dir(path: Path) -> bool:
    if not _has_safe_path_segments(path):
        return False
    try:
        return path.is_dir()
    except (OSError, ValueError):
        return False


def _safe_exists(path: Path) -> bool:
    if not _has_safe_path_segments(path):
        return False
    try:
        return path.exists()
    except (OSError, ValueError):
        return False


def _safe_resolve(path: Path) -> Path | None:
    if not _has_safe_path_segments(path):
        return None
    try:
        return path.resolve()
    except (OSError, ValueError):
        return None


def _safe_contained_file(path: Path, real_root: Path) -> str | None:
    if not _has_safe_path_segments(path):
        return None
    try:
        if path.is_symlink() or not path.is_file():
            return None
        resolved = path.resolve()
        if not resolved.is_relative_to(real_root):
            return None
        return resolved.relative_to(real_root).as_posix()
    except (OSError, ValueError):
        return None


def _safe_contained_dir(path: Path, real_root: Path) -> Path | None:
    if not _has_safe_path_segments(path):
        return None
    try:
        if path.is_symlink() or not path.is_dir():
            return None
        resolved = path.resolve()
        if not resolved.is_relative_to(real_root):
            return None
        return resolved
    except (OSError, ValueError):
        return None


def _safe_contained_entry(path: Path, real_root: Path) -> tuple[str, bool, bool] | None:
    if not _has_safe_path_segments(path):
        return None
    try:
        if path.is_symlink() or not path.exists():
            return None
        resolved = path.resolve()
        if not resolved.is_relative_to(real_root):
            return None
        rel = "." if resolved == real_root else resolved.relative_to(real_root).as_posix()
        return rel, path.is_file(), path.is_dir()
    except (OSError, ValueError):
        return None


MAX_DOCKER_STAGES = 128
MAX_STAGE_MAPPINGS = 2048
MAX_GLOB_MATCHES = 4096


def _safe_glob(root: Path, pattern: str) -> list[Path]:
    if not pattern or "\x00" in pattern or not _has_safe_path_segments(root):
        return []
    raw_segs = [s for s in pattern.replace("\\", "/").split("/") if s and s != "."]
    if not raw_segs or len(raw_segs) > 32:
        return []
    dedup_segs: list[str] = []
    wildcard_segs = 0
    for seg in raw_segs:
        if seg == "**" and dedup_segs and dedup_segs[-1] == "**":
            continue
        if any(ch in seg for ch in "*?["):
            wildcard_segs += 1
            if wildcard_segs > 12:
                return []
        elif len(seg.encode("utf-8", errors="surrogateescape")) > 255:
            return []
        dedup_segs.append(seg)
    norm_pattern = "/".join(dedup_segs)
    try:
        matched: list[Path] = []
        for p in root.glob(norm_pattern):
            matched.append(p)
            if len(matched) >= MAX_GLOB_MATCHES:
                break
        return sorted(matched)
    except (OSError, ValueError):
        return []


def _read_bounded_regular_text(
    path: Path,
    *,
    max_bytes: int = 1_048_576,
    real_root: Path | None = None,
    encoding: str = "utf-8",
) -> str:
    if not _has_safe_path_segments(path):
        raise OSError("Unsafe path segments")
    if real_root is not None and (_safe_is_symlink(path) or not _is_within_root(path, real_root)):
        raise OSError("Path outside repository root or symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Not a regular file")
        if st.st_size > max_bytes:
            raise ValueError(f"File exceeds {max_bytes}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"File exceeds {max_bytes}-byte limit")
    finally:
        os.close(fd)
    return b"".join(chunks).decode(encoding)


def _make_bounded_yaml_loader(max_nodes: int = 4096, max_depth: int = 64) -> type[yaml.SafeLoader]:
    class _BoundedSafeLoader(yaml.SafeLoader):
        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._node_count = 0
            self._alias_count = 0
            self._merge_steps = 0
            self._cur_depth = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                self._alias_count += 1
                if (self._node_count + self._alias_count) > max_nodes:
                    raise yaml.YAMLError(f"YAML alias expansion exceeds budget ({max_nodes}).")
                return super().compose_node(parent, index)
            self._node_count += 1
            if (self._node_count + self._alias_count) > max_nodes:
                raise yaml.YAMLError(f"YAML node count exceeds budget ({max_nodes}).")
            self._cur_depth += 1
            if self._cur_depth > max_depth:
                raise yaml.YAMLError(
                    f"YAML structure exceeds maximum nesting depth ({max_depth})."
                )
            try:
                return super().compose_node(parent, index)
            finally:
                self._cur_depth -= 1

        def flatten_mapping(self, node: Any) -> None:
            self._merge_steps += 1
            if self._merge_steps > max_nodes:
                raise yaml.YAMLError(f"YAML mapping merge exceeds budget ({max_nodes}).")
            raw_pairs = getattr(node, "value", ())
            projected = len(raw_pairs)
            if projected > max_nodes:
                raise yaml.YAMLError(f"YAML merged mapping exceeds budget ({max_nodes}).")
            for k_node, v_node in raw_pairs:
                if getattr(k_node, "tag", "") == "tag:yaml.org,2002:merge":
                    if isinstance(v_node, yaml.MappingNode):
                        self.flatten_mapping(v_node)
                        projected += len(v_node.value)
                    elif isinstance(v_node, yaml.SequenceNode):
                        for subnode in v_node.value:
                            if isinstance(subnode, yaml.MappingNode):
                                self.flatten_mapping(subnode)
                                projected += len(subnode.value)
                    if projected > max_nodes:
                        raise yaml.YAMLError(f"YAML merged mapping exceeds budget ({max_nodes}).")
            super().flatten_mapping(node)
            if len(getattr(node, "value", ())) > max_nodes:
                raise yaml.YAMLError(f"YAML merged mapping exceeds budget ({max_nodes}).")

        def construct_yaml_int(self, node: Any) -> int:
            if isinstance(node.value, str) and len(node.value) > 4096:
                raise yaml.YAMLError("YAML integer exceeds maximum bit length")
            val = super().construct_yaml_int(node)
            if isinstance(val, int) and not isinstance(val, bool) and val.bit_length() > 4096:
                raise yaml.YAMLError("YAML integer exceeds maximum bit length")
            return val

    _BoundedSafeLoader.add_constructor(
        "tag:yaml.org,2002:int", _BoundedSafeLoader.construct_yaml_int
    )
    return _BoundedSafeLoader


def _load_bounded_yaml(
    raw_text: str, *, max_nodes: int = 4096, max_depth: int = 64
) -> object:
    return yaml.load(raw_text, Loader=_make_bounded_yaml_loader(max_nodes, max_depth))


def _load_bounded_yaml_all(
    raw_text: str, *, max_nodes: int = 4096, max_depth: int = 64
) -> list[object]:
    return list(yaml.load_all(raw_text, Loader=_make_bounded_yaml_loader(max_nodes, max_depth)))


def _normalize_posix_rel(raw: str) -> str | None:
    cleaned = raw.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    if not cleaned or cleaned == ".":
        return "."
    parts: list[str] = []
    for part in cleaned.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts) if parts else "."


@functools.lru_cache(maxsize=8192)
def _compile_segment_tokens(seg: str) -> tuple[tuple[Any, ...], ...] | None:
    if not any(ch in seg for ch in "*?["):
        return (("exact", seg),)
    if "?" not in seg and "[" not in seg:
        collapsed = re.sub(r"\*+", "*", seg)
        if collapsed == "*":
            return (("star",),)
        if collapsed.count("*") == 1:
            if collapsed.startswith("*"):
                return (("suffix", collapsed[1:]),)
            if collapsed.endswith("*"):
                return (("prefix", collapsed[:-1]),)
    tokens: list[tuple[Any, ...]] = []
    i = 0
    n = len(seg)
    while i < n:
        ch = seg[i]
        if ch == "*":
            while i + 1 < n and seg[i + 1] == "*":
                i += 1
            if not tokens or tokens[-1] != ("star",):
                tokens.append(("star",))
            i += 1
        elif ch == "?":
            tokens.append(("any",))
            i += 1
        elif ch == "[":
            end = seg.find("]", i + 1)
            if end == -1:
                tokens.append(("lit", "["))
                i += 1
            else:
                body = seg[i + 1 : end]
                negated = False
                if body.startswith(("!", "^")):
                    negated = True
                    body = body[1:]
                if not body:
                    return None
                chars: set[str] = set()
                ranges: list[tuple[str, str]] = []
                j = 0
                m = len(body)
                while j < m:
                    if j + 2 < m and body[j + 1] == "-":
                        lo, hi = body[j], body[j + 2]
                        if ord(lo) > ord(hi):
                            return None
                        ranges.append((lo, hi))
                        j += 3
                    else:
                        chars.add(body[j])
                        j += 1
                tokens.append(("cls", negated, frozenset(chars), tuple(ranges)))
                i = end + 1
        else:
            tokens.append(("lit", ch))
            i += 1
    return tuple(tokens)


def _token_matches_char(tok: tuple[Any, ...], ch: str) -> bool:
    kind = tok[0]
    if kind == "any":
        return True
    if kind == "lit":
        return ch == tok[1]
    _, negated, chars, ranges = tok
    hit = ch in chars or any(lo <= ch <= hi for lo, hi in ranges)
    return not hit if negated else hit


@functools.lru_cache(maxsize=16384)
def _match_segment(tokens: tuple[tuple[Any, ...], ...], text: str) -> bool:
    if len(tokens) == 1:
        t0 = tokens[0]
        k0 = t0[0]
        if k0 == "exact":
            return text == t0[1]
        if k0 == "star":
            return True
        if k0 == "suffix":
            return text.endswith(t0[1])
        if k0 == "prefix":
            return text.startswith(t0[1])
    ti = 0
    si = 0
    tn = len(tokens)
    sn = len(text)
    star_ti = -1
    star_si = 0
    while si < sn:
        if ti < tn and tokens[ti][0] == "star":
            star_ti = ti
            star_si = si
            ti += 1
        elif ti < tn and _token_matches_char(tokens[ti], text[si]):
            ti += 1
            si += 1
        elif star_ti != -1:
            ti = star_ti + 1
            star_si += 1
            si = star_si
        else:
            return False
    while ti < tn and tokens[ti][0] == "star":
        ti += 1
    return ti == tn


@dataclass(frozen=True)
class _DockerIgnoreMatcher:
    segments: tuple[tuple[tuple[Any, ...], ...] | None, ...]

    def matches(self, rel_path: str) -> bool:
        if not rel_path or rel_path == ".":
            return False
        path_segs = [s for s in rel_path.split("/") if s]
        n = len(path_segs)
        if n == 0:
            return False
        dp = [True] + [False] * n
        for pseg in self.segments:
            if pseg is None:
                for j in range(1, n + 1):
                    dp[j] = dp[j] or dp[j - 1]
            else:
                new_dp = [False] * (n + 1)
                any_hit = False
                for j in range(1, n + 1):
                    if dp[j - 1] and _match_segment(pseg, path_segs[j - 1]):
                        new_dp[j] = True
                        any_hit = True
                if not any_hit:
                    return False
                dp = new_dp
        return dp[n]

    def matches_any_prefix(self, path_segs: tuple[str, ...]) -> bool:
        n = len(path_segs)
        if n == 0:
            return False
        dp = [True] + [False] * n
        for pseg in self.segments:
            if pseg is None:
                for j in range(1, n + 1):
                    if dp[j - 1]:
                        for k in range(j, n + 1):
                            dp[k] = True
                        break
            else:
                new_dp = [False] * (n + 1)
                any_hit = False
                for j in range(1, n + 1):
                    if dp[j - 1] and _match_segment(pseg, path_segs[j - 1]):
                        new_dp[j] = True
                        any_hit = True
                if not any_hit:
                    return False
                dp = new_dp
        return any(dp[1:])

    def match(self, rel_path: str) -> bool:
        return self.matches(rel_path)


@functools.lru_cache(maxsize=4096)
def _compile_dockerignore_glob(pattern: str) -> _DockerIgnoreMatcher | None:
    if len(pattern) > 4096:
        return None
    norm = pattern.strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.strip("/")
    if not norm or norm == ".":
        return None
    raw_segs = [s for s in norm.split("/") if s]
    seg_matchers: list[tuple[tuple[Any, ...], ...] | None] = []
    for seg in raw_segs:
        if seg == "**":
            if not seg_matchers or seg_matchers[-1] is not None:
                seg_matchers.append(None)
        else:
            compiled_seg = _compile_segment_tokens(seg)
            if compiled_seg is None:
                return None
            seg_matchers.append(compiled_seg)
    return _DockerIgnoreMatcher(segments=tuple(seg_matchers))


@dataclass(frozen=True)
class DockerIgnoreSpec:
    """Compiled `.dockerignore` rule list evaluated in declaration order."""

    source_rel: str | None = None
    rules: tuple[tuple[_DockerIgnoreMatcher, bool], ...] = ()
    _cache: dict[str, bool] = field(
        default_factory=dict, init=False, repr=False, compare=False, hash=False
    )

    def is_excluded(self, rel_ctx: str) -> bool:
        if not self.rules:
            return False
        norm = _normalize_posix_rel(rel_ctx)
        if norm is None or norm == ".":
            return False
        cached = self._cache.get(norm)
        if cached is not None:
            return cached
        parts = tuple(norm.split("/"))
        active_rules = (
            self.rules[-MAX_DOCKERIGNORE_RULES:]
            if len(self.rules) > MAX_DOCKERIGNORE_RULES
            else self.rules
        )
        excluded = False
        for matcher, negated in reversed(active_rules):
            if matcher.matches_any_prefix(parts):
                excluded = not negated
                break
        if len(self._cache) < 4096:
            self._cache[norm] = excluded
        return excluded

    def is_dir_completely_excluded(self, dir_fs: Path, rel_ctx: str, real_root: Path) -> bool:
        if not self.rules:
            return False
        has_any_file = False
        for parent, dirs, names in os.walk(dir_fs, followlinks=False, onerror=lambda _e: None):
            dirs[:] = [
                d for d in sorted(dirs)
                if _safe_contained_dir(Path(parent) / d, real_root) is not None
            ]
            for name in sorted(names):
                fpath = Path(parent) / name
                if _safe_contained_file(fpath, real_root) is None:
                    continue
                has_any_file = True
                try:
                    sub_rel = fpath.relative_to(dir_fs).as_posix()
                except ValueError:
                    continue
                full_ctx = sub_rel if rel_ctx in ("", ".") else f"{rel_ctx}/{sub_rel}"
                if not self.is_excluded(full_ctx):
                    return False
        return has_any_file or self.is_excluded(rel_ctx)


def parse_dockerignore(
    context_root: Path,
    dockerfile_path: Path | None,
    repo_root: Path,
    *,
    notes_out: list[str] | None = None,
) -> DockerIgnoreSpec:
    real_root = _safe_resolve(repo_root)
    if real_root is None:
        return DockerIgnoreSpec()
    candidates: list[Path] = []
    if dockerfile_path is not None:
        candidates.append(dockerfile_path.with_name(dockerfile_path.name + ".dockerignore"))
    candidates.append(context_root / ".dockerignore")
    for cand in candidates:
        if not _has_safe_path_segments(cand):
            continue
        if _safe_is_symlink(cand) or (_safe_exists(cand) and not _safe_is_file(cand)) or (
            _safe_exists(cand) and not _is_within_root(cand, real_root)
        ):
            if notes_out is not None:
                notes_out.append(
                    f"Skipped symlink or non-regular .dockerignore {cand.name}; ignore rules absent."
                )
            continue
        if not _safe_exists(cand):
            continue
        try:
            text = _read_bounded_regular_text(cand, max_bytes=262_144, real_root=real_root)
        except (OSError, UnicodeError, ValueError):
            if notes_out is not None:
                notes_out.append(
                    f"Could not read .dockerignore {cand.name}; ignore rules absent."
                )
            continue
        compiled: list[tuple[_DockerIgnoreMatcher, bool]] = []
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped or raw_line.lstrip().startswith("#") or len(stripped) > 4096:
                continue
            negated = stripped.startswith("!")
            pat_str = stripped[1:].strip() if negated else stripped
            if not pat_str:
                continue
            matcher = _compile_dockerignore_glob(pat_str)
            if matcher is not None:
                entry = (matcher, negated)
                if not compiled or compiled[-1] != entry:
                    compiled.append(entry)
                if len(compiled) >= MAX_DOCKERIGNORE_RULES:
                    break
        rel = _safe_contained_file(cand, real_root)
        if rel is None:
            continue
        return DockerIgnoreSpec(source_rel=rel, rules=tuple(compiled))
    return DockerIgnoreSpec()


def _is_dockerfile_name(name: str) -> bool:
    if name.endswith(_IGNORED_DOCKERFILE_SUFFIXES):
        return False
    if name in _DOCKERFILE_EXACT:
        return True
    if name.startswith(_DOCKERFILE_PREFIXES) and len(name.split(".", 1)[1]) > 0:
        return True
    return name.endswith(_DOCKERFILE_SUFFIXES)


def discover_dockerfiles(
    repo_root: Path,
    *,
    skipped_notes: list[str] | None = None,
) -> tuple[list[Path], int]:
    """Discover repository Dockerfiles/Containerfiles without following symlinks."""
    if not _has_safe_path_segments(repo_root) or _safe_is_symlink(repo_root):
        if skipped_notes is not None:
            skipped_notes.append(
                "Skipped symlink or unsafe repository root; Dockerfile declarations absent."
            )
        return [], 1
    real_root = _safe_resolve(repo_root)
    if real_root is None:
        if skipped_notes is not None:
            skipped_notes.append(
                "Skipped unreadable repository root; Dockerfile declarations absent."
            )
        return [], 1
    found: list[Path] = []
    excluded = 0
    walk_errors: list[OSError] = []
    for parent, dirs, names in os.walk(repo_root, followlinks=False, onerror=walk_errors.append):
        keep: list[str] = []
        for dname in sorted(dirs):
            dpath = Path(parent) / dname
            if dname in EXCLUDED_PARTS or (
                dname.startswith(".") and dname not in ALLOWED_CONTAINER_DOT_DIRS
            ):
                excluded += 1
            elif _safe_contained_dir(dpath, real_root) is None:
                excluded += 1
                if skipped_notes is not None:
                    try:
                        rel_d = dpath.relative_to(repo_root).as_posix()
                    except ValueError:
                        rel_d = dname
                    skipped_notes.append(
                        f"Skipped symlink or out-of-root directory {rel_d}; Dockerfile declarations absent."
                    )
            else:
                keep.append(dname)
        dirs[:] = keep
        for fname in sorted(names):
            if not _is_dockerfile_name(fname):
                continue
            fpath = Path(parent) / fname
            if _safe_contained_file(fpath, real_root) is None:
                excluded += 1
                if skipped_notes is not None:
                    try:
                        rel_f = fpath.relative_to(repo_root).as_posix()
                    except ValueError:
                        rel_f = fname
                    skipped_notes.append(
                        f"Skipped symlink or non-regular Dockerfile {rel_f}; build declarations absent."
                    )
            else:
                found.append(fpath)
    if walk_errors:
        excluded += len(walk_errors)
        if skipped_notes is not None:
            skipped_notes.append(
                "Skipped unreadable directory during Dockerfile discovery; build declarations absent."
            )
    return sorted(found), excluded


def _compose_context_hints(repo_root: Path) -> dict[str, Path]:
    """Map repo-relative Dockerfile paths to explicit compose `build.context` roots."""
    real_root = _safe_resolve(repo_root)
    if real_root is None:
        return {}
    hints: dict[str, Path] = {}
    search_dirs = [repo_root]
    try:
        for child in sorted(repo_root.iterdir()):
            if (
                _safe_contained_dir(child, real_root) is not None
                and (not child.name.startswith(".") or child.name in ALLOWED_CONTAINER_DOT_DIRS)
                and child.name not in EXCLUDED_PARTS
            ):
                search_dirs.append(child)
    except OSError:
        return hints

    for sdir in search_dirs:
        try:
            entries = sorted(sdir.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for cpath in entries:
            if not is_compose_filename(cpath.name):
                continue
            if _safe_contained_file(cpath, real_root) is None:
                continue
            try:
                raw_compose = _read_bounded_regular_text(
                    cpath, max_bytes=1_048_576, real_root=real_root
                )
                data = _load_bounded_yaml(raw_compose, max_nodes=4096, max_depth=64)
            except (OSError, UnicodeError, ValueError, RecursionError, yaml.YAMLError):
                continue
            if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
                continue
            for svc in data["services"].values():
                if not isinstance(svc, dict) or "build" not in svc:
                    continue
                build = svc["build"]
                if isinstance(build, str):
                    ctx_raw, df_raw = build, "Dockerfile"
                elif isinstance(build, dict):
                    raw_ctx_val = build.get("context")
                    raw_df_val = build.get("dockerfile")
                    ctx_raw = raw_ctx_val if isinstance(raw_ctx_val, str) and raw_ctx_val else "."
                    df_raw = (
                        raw_df_val if isinstance(raw_df_val, str) and raw_df_val else "Dockerfile"
                    )
                else:
                    continue
                ctx_dir = _safe_contained_dir(cpath.parent / ctx_raw, real_root)
                if ctx_dir is None:
                    continue
                if not _has_safe_path_segments(df_raw):
                    continue
                df_cand = ctx_dir / df_raw
                df_rel = _safe_contained_file(df_cand, real_root)
                if df_rel is None:
                    df_cand = cpath.parent / df_raw
                    df_rel = _safe_contained_file(df_cand, real_root)
                if df_rel is not None:
                    hints.setdefault(df_rel, ctx_dir)
    return hints


def _repo_rel_to_ctx_rel(repo_rel: str, context_rel_root: str) -> str | None:
    if context_rel_root in ("", "."):
        return repo_rel
    if repo_rel == context_rel_root:
        return "."
    if repo_rel.startswith(context_rel_root + "/"):
        return repo_rel[len(context_rel_root) + 1 :]
    return None


def _norm_container_path(raw: str, workdir: str = "/") -> str:
    val = raw.strip().replace("\\", "/")
    base = PurePosixPath(val) if val.startswith("/") else PurePosixPath(workdir or "/") / val
    parts: list[str] = []
    for part in base.parts:
        if part in ("/", ".", ""):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


@dataclass(frozen=True)
class LogicalInstruction:
    keyword: str
    raw_args: str
    line: int


@dataclass(frozen=True)
class StageCopyMapping:
    container_path: str
    repo_rel: str
    is_dir: bool
    context_rel_root: str
    ignore_spec: DockerIgnoreSpec


@dataclass(frozen=True)
class CommandDeclaration:
    kind: str  # "ENTRYPOINT" | "CMD"
    raw_args: str
    is_exec: bool
    argv: tuple[str, ...]
    shell_cmd: str | None
    line: int


@dataclass
class DockerStage:
    index: int
    name: str | None
    base_image: str
    line: int
    workdir: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    known_dirs: set[str] = field(
        default_factory=lambda: {"/", "/bin", "/usr/bin", "/usr/local/bin", "/opt", "/srv", "/etc", "/tmp"}
    )
    mappings: list[StageCopyMapping] = field(default_factory=list)
    entrypoint: CommandDeclaration | None = None
    cmd: CommandDeclaration | None = None
    installs_local_package: bool = False

    def resolve_container_file(self, raw_path: str, real_root: Path) -> str | None:
        cpath = _norm_container_path(raw_path, self.workdir)
        for mapping in reversed(self.mappings):
            if not mapping.is_dir:
                if cpath != mapping.container_path:
                    continue
                ctx_rel = _repo_rel_to_ctx_rel(mapping.repo_rel, mapping.context_rel_root)
                if ctx_rel is not None and mapping.ignore_spec.is_excluded(ctx_rel):
                    continue
                if _safe_contained_file(real_root / mapping.repo_rel, real_root) is not None:
                    return mapping.repo_rel
            else:
                mp = mapping.container_path.rstrip("/") or "/"
                if mp == "/":
                    sub = cpath.lstrip("/")
                elif cpath.startswith(mp + "/"):
                    sub = cpath[len(mp) + 1 :]
                else:
                    continue
                if not sub:
                    continue
                cand_rel = sub if mapping.repo_rel in ("", ".") else f"{mapping.repo_rel}/{sub}"
                ctx_rel = _repo_rel_to_ctx_rel(cand_rel, mapping.context_rel_root)
                if ctx_rel is not None and mapping.ignore_spec.is_excluded(ctx_rel):
                    continue
                if _safe_contained_file(real_root / cand_rel, real_root) is not None:
                    return cand_rel
        return None

    def covers_repo_file(self, repo_rel: str) -> tuple[bool, str | None]:
        excluded_by_ignore = False
        for mapping in self.mappings:
            matches = (
                mapping.repo_rel == repo_rel
                if not mapping.is_dir
                else (
                    mapping.repo_rel in ("", ".")
                    or repo_rel == mapping.repo_rel
                    or repo_rel.startswith(mapping.repo_rel + "/")
                )
            )
            if not matches:
                continue
            ctx_rel = _repo_rel_to_ctx_rel(repo_rel, mapping.context_rel_root)
            if ctx_rel is not None and mapping.ignore_spec.is_excluded(ctx_rel):
                excluded_by_ignore = True
            else:
                return True, None
        if excluded_by_ignore:
            return False, "excluded_by_dockerignore"
        return False, "omitted_from_copy"


@dataclass
class ParsedDockerfile:
    rel_path: str
    context_root: Path
    context_rel_root: str
    ignore_spec: DockerIgnoreSpec
    stages: list[DockerStage]
    findings: list[RawCandidateFinding] = field(default_factory=list)

    def select_stage(self, target: str | None = None) -> DockerStage | None:
        if not self.stages:
            return None
        if target:
            t_low = target.strip().lower()
            for stg in self.stages:
                if stg.name == t_low:
                    return stg
        return self.stages[-1]


def _split_dockerfile_instructions(text: str) -> list[LogicalInstruction]:
    lines = text.splitlines()
    escape_ch = "\\"
    idx = 0
    while idx < len(lines):
        raw = lines[idx]
        m = _ESCAPE_DIRECTIVE_RE.match(raw)
        if m:
            escape_ch = m.group(1)
            idx += 1
            continue
        if not raw.strip() or raw.lstrip().startswith("#"):
            idx += 1
            continue
        break

    instructions: list[LogicalInstruction] = []
    buf: list[str] = []
    start_line = 1
    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not buf:
            if not stripped or raw.lstrip().startswith("#"):
                continue
            start_line = line_no
        else:
            if raw.lstrip().startswith("#"):
                continue
            if not stripped:
                full = " ".join(buf).strip()
                buf.clear()
                parts = full.split(None, 1)
                if parts:
                    instructions.append(
                        LogicalInstruction(parts[0].upper(), parts[1] if len(parts) > 1 else "", start_line)
                    )
                continue

        rstripped = raw.rstrip()
        if rstripped.endswith(escape_ch) and not rstripped.endswith(escape_ch * 2):
            buf.append(rstripped[:-1].strip())
        else:
            buf.append(stripped)
            full = " ".join(buf).strip()
            buf.clear()
            parts = full.split(None, 1)
            if parts:
                instructions.append(
                    LogicalInstruction(parts[0].upper(), parts[1] if len(parts) > 1 else "", start_line)
                )

    if buf:
        full = " ".join(buf).strip()
        parts = full.split(None, 1)
        if parts:
            instructions.append(
                LogicalInstruction(parts[0].upper(), parts[1] if len(parts) > 1 else "", start_line)
            )
    return instructions


_BUILD_VAR_EXPAND_RE = re.compile(
    r"\$(?:(?P<braced>\{(?P<bname>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<bop>:-|\+|:\+|-)(?P<bdef>[^}]*))?\})|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)


def _expand_build_vars(
    value: str,
    bindings: dict[str, str],
    *,
    max_len: int = MAX_ENV_VALUE_LEN,
) -> tuple[str, bool]:
    if "$" not in value:
        return (value[:max_len] if len(value) > max_len else value), False
    unresolved = False
    parts: list[str] = []
    cur_len = 0
    last_end = 0
    for match in _BUILD_VAR_EXPAND_RE.finditer(value):
        lit = value[last_end : match.start()]
        if lit:
            rem = max_len - cur_len
            if rem <= 0:
                break
            if len(lit) >= rem:
                parts.append(lit[:rem])
                cur_len = max_len
                break
            parts.append(lit)
            cur_len += len(lit)
        last_end = match.end()
        if match.group("plain"):
            key = match.group("plain")
            if key in bindings:
                chunk = bindings[key]
            else:
                unresolved = True
                chunk = match.group(0)
        else:
            key = match.group("bname")
            op = match.group("bop")
            default = match.group("bdef") or ""
            cur = bindings.get(key)
            if op in (":-", "-"):
                chunk = cur if (cur is not None and (cur != "" or op == "-")) else default
            elif op in (":+", "+"):
                chunk = default if cur else ""
            elif cur is not None:
                chunk = cur
            else:
                unresolved = True
                chunk = match.group(0)
        if chunk:
            rem = max_len - cur_len
            if rem <= 0:
                break
            if len(chunk) >= rem:
                parts.append(chunk[:rem])
                cur_len = max_len
                break
            parts.append(chunk)
            cur_len += len(chunk)
    else:
        tail = value[last_end:]
        if tail and cur_len < max_len:
            parts.append(tail[: max_len - cur_len])
    return "".join(parts), unresolved


def _shlex_tokens(raw: str) -> list[str]:
    try:
        return shlex.split(raw, posix=True)
    except ValueError:
        return raw.split()


def _store_bounded_binding(target: dict[str, str], key: str, value: str) -> None:
    if not key:
        return
    if key in target or len(target) < MAX_ENV_BINDINGS:
        target[key] = value[:MAX_ENV_VALUE_LEN]


def _parse_arg_bindings(raw_args: str, current: dict[str, str], global_args: dict[str, str]) -> None:
    for tok in _shlex_tokens(raw_args):
        if "=" in tok:
            k, v = tok.split("=", 1)
            expanded, _ = _expand_build_vars(v, current, max_len=MAX_ENV_VALUE_LEN)
            _store_bounded_binding(current, k, expanded)
        elif tok in global_args and tok not in current:
            _store_bounded_binding(current, tok, global_args[tok])


def _parse_env_bindings(raw_args: str, current: dict[str, str]) -> None:
    stripped = raw_args.strip()
    if not stripped:
        return
    tokens = _shlex_tokens(stripped)
    if not tokens:
        return
    if "=" not in tokens[0]:
        key = tokens[0]
        rest = stripped[len(tokens[0]) :].strip()
        if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in ("'", '"'):
            rest = rest[1:-1]
        expanded, _ = _expand_build_vars(rest, current, max_len=MAX_ENV_VALUE_LEN)
        _store_bounded_binding(current, key, expanded)
        return
    for tok in tokens:
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k:
            expanded, _ = _expand_build_vars(v, current, max_len=MAX_ENV_VALUE_LEN)
            _store_bounded_binding(current, k, expanded)


def _parse_bounded_json_int(raw_digits: str) -> int:
    s = raw_digits.strip()
    digits = s.removeprefix("-")
    if not digits or not digits.isascii() or not digits.isdigit() or len(digits) > 64:
        return 0
    return int(s)


def _parse_copy_args(raw_args: str) -> tuple[str | None, list[str], str | None]:
    rest = raw_args.strip()
    from_ref: str | None = None
    while rest.startswith("--"):
        parts = rest.split(None, 1)
        flag = parts[0]
        rest = parts[1].strip() if len(parts) > 1 else ""
        if flag.startswith("--from="):
            from_ref = flag.split("=", 1)[1].strip().strip("'\"")
    if rest.startswith("[") and rest.endswith("]"):
        try:
            arr = json.loads(rest, parse_int=_parse_bounded_json_int)
            if isinstance(arr, list) and len(arr) >= 2 and all(isinstance(x, str) for x in arr):
                return from_ref, arr[:-1], arr[-1]
        except (json.JSONDecodeError, ValueError):
            pass
    tokens = _shlex_tokens(rest)
    if len(tokens) < 2:
        return from_ref, [], None
    return from_ref, tokens[:-1], tokens[-1]


def _propagate_from_stage_mappings(
    src_stage: DockerStage,
    dst_stage: DockerStage,
    sources: list[str],
    dest_exp: str,
    real_root: Path,
) -> None:
    if src_stage.installs_local_package:
        dst_stage.installs_local_package = True
    dest_abs = _norm_container_path(dest_exp, dst_stage.workdir)
    dest_is_dir = (
        dest_exp.endswith("/")
        or dest_exp in (".", "..")
        or len(sources) > 1
        or dest_abs in dst_stage.known_dirs
    )
    src_snapshot = tuple(src_stage.mappings)
    for src_raw in sources:
        if len(dst_stage.mappings) >= MAX_STAGE_MAPPINGS:
            return
        src_exp, _ = _expand_build_vars(src_raw, dst_stage.env)
        sp = _norm_container_path(src_exp, src_stage.workdir)
        sp_prefix = sp.rstrip("/")
        for m in src_snapshot:
            if len(dst_stage.mappings) >= MAX_STAGE_MAPPINGS:
                return
            if not m.is_dir:
                if m.container_path == sp:
                    c_dest = (
                        _norm_container_path(f"{dest_abs.rstrip('/')}/{PurePosixPath(sp).name}")
                        if dest_is_dir
                        else dest_abs
                    )
                    dst_stage.mappings.append(
                        StageCopyMapping(c_dest, m.repo_rel, False, m.context_rel_root, m.ignore_spec)
                    )
                elif sp != "/" and m.container_path.startswith(sp_prefix + "/"):
                    rel_in = m.container_path[len(sp_prefix) + 1 :]
                    c_dest = _norm_container_path(f"{dest_abs.rstrip('/')}/{rel_in}")
                    dst_stage.mappings.append(
                        StageCopyMapping(c_dest, m.repo_rel, False, m.context_rel_root, m.ignore_spec)
                    )
            else:
                mp = m.container_path.rstrip("/") or "/"
                if mp == "/" or sp == mp or sp.startswith(mp + "/"):
                    sub = sp.lstrip("/") if mp == "/" else ("" if sp == mp else sp[len(mp) + 1 :])
                    cand_repo = (
                        (sub or ".")
                        if m.repo_rel in ("", ".")
                        else (m.repo_rel if not sub else f"{m.repo_rel}/{sub}")
                    )
                    fs = real_root if cand_repo == "." else real_root / cand_repo
                    entry_info = _safe_contained_entry(fs, real_root)
                    if entry_info is None:
                        continue
                    _, fs_is_file, fs_is_dir = entry_info
                    if fs_is_dir:
                        dst_stage.mappings.append(
                            StageCopyMapping(dest_abs, cand_repo, True, m.context_rel_root, m.ignore_spec)
                        )
                        dst_stage.known_dirs.add(dest_abs)
                    elif fs_is_file:
                        c_dest = (
                            _norm_container_path(f"{dest_abs.rstrip('/')}/{PurePosixPath(sp).name}")
                            if dest_is_dir
                            else dest_abs
                        )
                        dst_stage.mappings.append(
                            StageCopyMapping(c_dest, cand_repo, False, m.context_rel_root, m.ignore_spec)
                        )
                elif sp != "/" and mp.startswith(sp_prefix + "/"):
                    rel_in = mp[len(sp_prefix) + 1 :]
                    c_dest = _norm_container_path(f"{dest_abs.rstrip('/')}/{rel_in}")
                    dst_stage.mappings.append(
                        StageCopyMapping(c_dest, m.repo_rel, True, m.context_rel_root, m.ignore_spec)
                    )
                    dst_stage.known_dirs.add(c_dest)


def _exec_invokes_shell(argv: list[str]) -> bool:
    unwrapped, _ = _unwrap_launcher_prefix(argv, None)
    if not unwrapped:
        return False
    exe = PurePosixPath(unwrapped[0]).name
    if exe not in _SHELL_BINARIES:
        return False
    for tok in unwrapped[1:]:
        if tok == "--":
            break
        if tok.startswith("-") and "c" in tok[1:]:
            return True
    return False


def _parse_command_declaration(
    keyword: str,
    raw_args: str,
    line: int,
    stage: DockerStage,
    nid: str,
    rel_path: str,
    findings: list[RawCandidateFinding],
) -> CommandDeclaration | None:
    stripped = raw_args.strip()
    if not stripped or stripped in {'""', "''"}:
        findings.append(
            RawCandidateFinding(
                rule_code="MANIP-004",
                node_id=nid,
                source_file=rel_path,
                line=line,
                title=f"Empty container `{keyword}` declaration",
                detail=f"`{keyword}` at `{rel_path}:{line}` supplies no executable command.",
                remediation="Provide a concrete exec-form command array or non-empty shell command.",
            )
        )
        return None

    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            parsed = json.loads(stripped, parse_int=_parse_bounded_json_int)
        except (json.JSONDecodeError, ValueError):
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel_path,
                    line=line,
                    title=f"Malformed exec-form `{keyword}` JSON array",
                    detail=(
                        f"`{keyword}` at `{rel_path}:{line}` looks like exec-form JSON but is invalid JSON; "
                        "Docker falls back to `/bin/sh -c` on malformed arrays."
                    ),
                    remediation="Use strict double-quoted JSON string array syntax for exec-form commands.",
                )
            )
            return None
        if not isinstance(parsed, list) or any(not isinstance(x, str) for x in parsed):
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel_path,
                    line=line,
                    title=f"Invalid exec-form `{keyword}` argument types",
                    detail=f"`{keyword}` at `{rel_path}:{line}` must be an array of strings.",
                    remediation="Ensure every element in the exec-form JSON array is a string.",
                )
            )
            return None
        if not parsed:
            if keyword == "CMD" and stage.entrypoint is not None and stage.entrypoint.argv:
                return CommandDeclaration(keyword, stripped, True, (), None, line)
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel_path,
                    line=line,
                    title=f"Empty exec-form `{keyword}` array",
                    detail=f"`{keyword} []` at `{rel_path}:{line}` supplies no executable.",
                    remediation="Specify an executable in `ENTRYPOINT` or `CMD`.",
                )
            )
            return None
        if not parsed[0].strip():
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel_path,
                    line=line,
                    title=f"Empty executable in `{keyword}` array",
                    detail=f"`{keyword}` at `{rel_path}:{line}` has an empty first argument.",
                    remediation="Provide a concrete executable path or binary name as the first element.",
                )
            )
            return None

        bad_tokens: list[str] = []
        entrypoint_invokes_shell = (
            keyword == "CMD"
            and stage.entrypoint is not None
            and stage.entrypoint.is_exec
            and _exec_invokes_shell(list(stage.entrypoint.argv))
        )
        if not entrypoint_invokes_shell:
            first = parsed[0]
            if _VAR_TOKEN_RE.search(first) or first == "~" or first.startswith("~/"):
                bad_tokens.append(first)
            elif not _exec_invokes_shell(parsed):
                for tok in parsed[1:]:
                    if _VAR_TOKEN_RE.search(tok) or tok == "~" or tok.startswith("~/"):
                        bad_tokens.append(tok)
        if bad_tokens:
            sample = ", ".join(f"`{t}`" for t in bad_tokens[:3])
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel_path,
                    line=line,
                    title=f"Exec-form `{keyword}` uses unexpanded shell syntax ({sample})",
                    detail=(
                        f"`{keyword}` at `{rel_path}:{line}` uses JSON exec-form with {sample}, "
                        "but exec-form invokes `execve` directly without a shell to expand `$VAR` or `~`."
                    ),
                    remediation='Wrap the command in `["sh", "-c", "..."]` or replace variables with concrete paths.',
                )
            )
        return CommandDeclaration(keyword, stripped, True, tuple(parsed), None, line)

    return CommandDeclaration(keyword, stripped, False, (), stripped, line)


def _infer_context_root(
    df_path: Path,
    instructions: list[LogicalInstruction],
    repo_root: Path,
    context_override: Path | None,
) -> Path:
    real_root = _safe_resolve(repo_root) or repo_root
    if context_override is not None and _is_within_root(context_override, real_root):
        resolved_ovr = _safe_resolve(context_override)
        if resolved_ovr is not None:
            return resolved_ovr
    df_dir = _safe_resolve(df_path.parent) or real_root
    if df_dir == real_root:
        return real_root
    if _safe_is_file(df_dir / ".dockerignore") and not _safe_is_symlink(df_dir / ".dockerignore"):
        return df_dir

    dir_hits = root_hits = 0
    for instr in instructions:
        if instr.keyword not in ("COPY", "ADD"):
            continue
        from_ref, sources, _ = _parse_copy_args(instr.raw_args)
        if from_ref is not None:
            continue
        for src in sources:
            if "://" in src or _VAR_TOKEN_RE.search(src) or any(c in src for c in "*?["):
                continue
            norm = _normalize_posix_rel(src)
            if norm is None or norm == ".":
                continue
            if _safe_exists(df_dir / norm):
                dir_hits += 1
            if _safe_exists(real_root / norm):
                root_hits += 1
    return real_root if root_hits > dir_hits else df_dir


def _parse_from_args(raw_args: str, bindings: dict[str, str]) -> tuple[str, str | None]:
    tokens = _shlex_tokens(raw_args)
    filtered = [t for t in tokens if not t.startswith("--")]
    if not filtered:
        return "scratch", None
    base_raw = filtered[0]
    base_exp, _ = _expand_build_vars(base_raw, bindings)
    stage_name: str | None = None
    if len(filtered) >= 3 and filtered[1].upper() == "AS":
        stage_name = filtered[2].strip().lower()
    return base_exp, stage_name


def parse_dockerfile(
    df_path: Path,
    repo_root: Path,
    context_override: Path | None = None,
    *,
    notes_out: list[str] | None = None,
) -> ParsedDockerfile | None:
    real_root = _safe_resolve(repo_root)
    rel_path = _safe_contained_file(df_path, real_root) if real_root is not None else None
    if rel_path is None:
        if notes_out is not None:
            notes_out.append(
                f"Skipped symlink or non-regular Dockerfile {df_path.name}; build declarations absent."
            )
        return None
    try:
        text = _read_bounded_regular_text(df_path, max_bytes=1_048_576, real_root=real_root)
    except (OSError, UnicodeError, ValueError):
        if notes_out is not None:
            notes_out.append(
                f"Could not read Dockerfile {df_path.name}; build declarations absent."
            )
        return None

    nid = f"m:dockerfile:{rel_path}"
    instructions = _split_dockerfile_instructions(text)
    context_root = _infer_context_root(df_path, instructions, repo_root, context_override)
    ctx_rel_root = (
        "." if context_root == real_root else context_root.relative_to(real_root).as_posix()
    )
    ignore_spec = parse_dockerignore(context_root, df_path, repo_root, notes_out=notes_out)

    global_args: dict[str, str] = {}
    stages: list[DockerStage] = []
    stages_by_name: dict[str, DockerStage] = {}
    findings: list[RawCandidateFinding] = []
    current_stage: DockerStage | None = None

    for instr in instructions:
        kw = instr.keyword
        if kw == "ARG" and current_stage is None:
            _parse_arg_bindings(instr.raw_args, global_args, global_args)
            continue
        if kw == "FROM":
            if len(stages) >= MAX_DOCKER_STAGES:
                break
            base_image, stage_name = _parse_from_args(instr.raw_args, global_args)
            parent = stages_by_name.get(base_image.lower())
            if parent is not None:
                current_stage = DockerStage(
                    index=len(stages),
                    name=stage_name,
                    base_image=base_image,
                    line=instr.line,
                    workdir=parent.workdir,
                    env=dict(parent.env),
                    known_dirs=set(parent.known_dirs),
                    mappings=list(parent.mappings[:MAX_STAGE_MAPPINGS]),
                    entrypoint=parent.entrypoint,
                    cmd=parent.cmd,
                    installs_local_package=parent.installs_local_package,
                )
            else:
                current_stage = DockerStage(
                    index=len(stages),
                    name=stage_name,
                    base_image=base_image,
                    line=instr.line,
                    env=dict(global_args),
                )
            stages.append(current_stage)
            if stage_name:
                stages_by_name[stage_name] = current_stage
            continue

        if current_stage is None:
            continue

        if kw == "ARG":
            _parse_arg_bindings(instr.raw_args, current_stage.env, global_args)
        elif kw == "ENV":
            _parse_env_bindings(instr.raw_args, current_stage.env)
        elif kw == "WORKDIR":
            wd_exp, _ = _expand_build_vars(instr.raw_args.strip(), current_stage.env)
            if wd_exp:
                current_stage.workdir = _norm_container_path(wd_exp, current_stage.workdir)
                parts = [p for p in current_stage.workdir.split("/") if p]
                for idx in range(1, len(parts) + 1):
                    current_stage.known_dirs.add("/" + "/".join(parts[:idx]))
        elif kw == "RUN":
            if re.search(
                r"\b(?:pip3?\s+(?:install\s+(?:-[^\s]+\s+)*(?:\.|/[^\s]*\.whl)|wheel\b)|"
                r"uv\s+sync\b|poetry\s+install\b|cargo\s+build\b|go\s+build\b)",
                instr.raw_args,
            ):
                current_stage.installs_local_package = True
        elif kw in ("ENTRYPOINT", "CMD"):
            decl = _parse_command_declaration(
                kw, instr.raw_args, instr.line, current_stage, nid, rel_path, findings
            )
            if kw == "ENTRYPOINT":
                current_stage.entrypoint = decl
                current_stage.cmd = None
            else:
                current_stage.cmd = decl
        elif kw in ("COPY", "ADD"):
            _handle_copy_or_add(
                kw,
                instr,
                current_stage,
                stages,
                stages_by_name,
                context_root,
                ctx_rel_root,
                ignore_spec,
                real_root,
                nid,
                rel_path,
                findings,
            )

    return ParsedDockerfile(
        rel_path=rel_path,
        context_root=context_root,
        context_rel_root=ctx_rel_root,
        ignore_spec=ignore_spec,
        stages=stages,
        findings=findings,
    )


def _handle_copy_or_add(
    kw: str,
    instr: LogicalInstruction,
    current_stage: DockerStage,
    stages: list[DockerStage],
    stages_by_name: dict[str, DockerStage],
    context_root: Path,
    ctx_rel_root: str,
    ignore_spec: DockerIgnoreSpec,
    real_root: Path,
    nid: str,
    rel_path: str,
    findings: list[RawCandidateFinding],
) -> None:
    from_ref, sources, dest_raw = _parse_copy_args(instr.raw_args)
    if not sources or dest_raw is None:
        return
    dest_exp, _ = _expand_build_vars(dest_raw, current_stage.env)

    if from_ref is not None:
        ref_exp, _ = _expand_build_vars(from_ref, current_stage.env)
        src_stage = stages_by_name.get(ref_exp.lower())
        if src_stage is not None and src_stage.index >= current_stage.index:
            src_stage = None
        if src_stage is None and ref_exp.isascii() and ref_exp.isdigit() and len(ref_exp) <= 6:
            idx = int(ref_exp)
            if 0 <= idx < current_stage.index:
                src_stage = stages[idx]
        if src_stage is not None:
            _propagate_from_stage_mappings(src_stage, current_stage, sources, dest_exp, real_root)
        return

    dest_abs = _norm_container_path(dest_exp, current_stage.workdir)
    dest_is_dir = (
        dest_exp.endswith("/")
        or dest_exp in (".", "..")
        or len(sources) > 1
        or dest_abs in current_stage.known_dirs
    )

    for src_raw in sources:
        if kw == "ADD" and (
            src_raw.startswith(("http://", "https://", "git://", "git@")) or "://" in src_raw
        ):
            continue
        src_exp, has_unresolved = _expand_build_vars(src_raw, current_stage.env)
        if has_unresolved:
            continue

        norm = _normalize_posix_rel(src_exp)
        if norm is None:
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-005",
                    node_id=nid,
                    source_file=rel_path,
                    line=instr.line,
                    title=f"Container `{kw}` source `{src_raw}` escapes build context",
                    detail=(
                        f"`{kw}` at `{rel_path}:{instr.line}` references `{src_raw}`, "
                        "which traverses outside the build context root."
                    ),
                    remediation="Keep build-context paths inside the build context directory or widen `build.context`.",
                )
            )
            continue

        if any(ch in norm for ch in "*?["):
            matched = [
                p
                for p in _safe_glob(context_root, norm)
                if not _safe_is_symlink(p) and _is_within_root(p, real_root)
            ]
            if not matched:
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-005",
                        node_id=nid,
                        source_file=rel_path,
                        line=instr.line,
                        title=f"Container `{kw}` pattern `{src_raw}` matches no source files",
                        detail=f"No files in `{ctx_rel_root}` matched `{src_raw}` declared at `{rel_path}:{instr.line}`.",
                        remediation="Restore the expected files or update the `COPY`/`ADD` glob pattern.",
                    )
                )
                continue
            kept = 0
            for mp in matched:
                mp_info = _safe_contained_entry(mp, real_root)
                if mp_info is None:
                    continue
                m_repo_rel, mp_is_file, mp_is_dir = mp_info
                mp_res = _safe_resolve(mp)
                if mp_res is None:
                    continue
                try:
                    m_ctx_rel = mp_res.relative_to(context_root).as_posix()
                except ValueError:
                    continue
                if mp_is_file and not ignore_spec.is_excluded(m_ctx_rel):
                    kept += 1
                    c_dest = (
                        _norm_container_path(f"{dest_abs.rstrip('/')}/{mp.name}")
                        if dest_is_dir
                        else dest_abs
                    )
                    current_stage.mappings.append(
                        StageCopyMapping(c_dest, m_repo_rel, False, ctx_rel_root, ignore_spec)
                    )
                elif mp_is_dir and not ignore_spec.is_dir_completely_excluded(mp, m_ctx_rel, real_root):
                    kept += 1
                    current_stage.mappings.append(
                        StageCopyMapping(dest_abs, m_repo_rel, True, ctx_rel_root, ignore_spec)
                    )
                    current_stage.known_dirs.add(dest_abs)
            if kept == 0:
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-005",
                        node_id=nid,
                        source_file=rel_path,
                        line=instr.line,
                        title=f"Container `{kw}` source `{src_raw}` is excluded by `.dockerignore`",
                        detail=(
                            f"All files matching `{src_raw}` at `{rel_path}:{instr.line}` are excluded "
                            f"by `{ignore_spec.source_rel or '.dockerignore'}`."
                        ),
                        remediation="Add a `!` negation exception in `.dockerignore` or remove the stale `COPY`.",
                    )
                )
            continue

        src_fs = context_root if norm == "." else context_root / norm
        entry_info = _safe_contained_entry(src_fs, real_root)
        if entry_info is None:
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-005",
                    node_id=nid,
                    source_file=rel_path,
                    line=instr.line,
                    title=f"Container `{kw}` source `{src_raw}` does not exist",
                    detail=(
                        f"`{kw}` at `{rel_path}:{instr.line}` names literal build-context source `{src_raw}`, "
                        f"which is absent under `{ctx_rel_root}`."
                    ),
                    remediation="Restore the missing source path or update the container build declaration.",
                )
            )
            continue

        repo_rel, src_is_file, src_is_dir = entry_info
        if src_is_file:
            if ignore_spec.is_excluded(norm):
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-005",
                        node_id=nid,
                        source_file=rel_path,
                        line=instr.line,
                        title=f"Container `{kw}` source `{src_raw}` is excluded by `.dockerignore`",
                        detail=(
                            f"`{src_raw}` exists on disk, but `{ignore_spec.source_rel or '.dockerignore'}` "
                            "excludes it from the container build context."
                        ),
                        remediation="Add a `!` re-inclusion rule in `.dockerignore` or adjust the excluded pattern.",
                    )
                )
                continue
            c_dest = (
                _norm_container_path(f"{dest_abs.rstrip('/')}/{src_fs.name}")
                if dest_is_dir
                else dest_abs
            )
            current_stage.mappings.append(
                StageCopyMapping(c_dest, repo_rel, False, ctx_rel_root, ignore_spec)
            )
        elif src_is_dir:
            if norm != "." and ignore_spec.is_dir_completely_excluded(src_fs, norm, real_root):
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-005",
                        node_id=nid,
                        source_file=rel_path,
                        line=instr.line,
                        title=f"Container `{kw}` directory `{src_raw}` is excluded by `.dockerignore`",
                        detail=(
                            f"Directory `{src_raw}` at `{rel_path}:{instr.line}` is excluded from the build context "
                            f"by `{ignore_spec.source_rel or '.dockerignore'}`."
                        ),
                        remediation="Un-ignore required files with `!` in `.dockerignore` or update the `COPY` source.",
                    )
                )
                continue
            current_stage.mappings.append(
                StageCopyMapping(dest_abs, repo_rel, True, ctx_rel_root, ignore_spec)
            )
            current_stage.known_dirs.add(dest_abs)


_VALUE_FLAGS_ASGI = frozenset(
    {
        "-h",
        "--host",
        "-p",
        "--port",
        "-w",
        "--workers",
        "-b",
        "--bind",
        "-k",
        "--worker-class",
        "-t",
        "--timeout",
        "--threads",
        "--graceful-timeout",
        "--keep-alive",
        "--log-level",
        "--log-config",
        "--env-file",
        "--ssl-keyfile",
        "--ssl-certfile",
        "--root-path",
        "--limit-concurrency",
        "--limit-max-requests",
        "--timeout-keep-alive",
        "--backlog",
        "--uds",
        "--fd",
        "--loop",
        "--http",
        "--ws",
        "--interface",
        "--access-logfile",
        "--error-logfile",
        "-n",
        "--name",
        "--pid",
        "--user",
        "--group",
        "--worker-tmp-dir",
        "--max-requests",
        "--max-requests-jitter",
    }
)
_PY_RUNNERS = frozenset(
    {"uvicorn", "gunicorn", "hypercorn", "daphne", "granian", "celery", "flask", "fastapi", "dramatiq", "arq"}
)
_NODE_BINS = frozenset({"node", "nodejs", "tsx", "ts-node", "bun", "deno"})


@dataclass(frozen=True)
class CommandTarget:
    kind: str  # "file" | "py_module" | "node_script"
    value: str
    base_dir: str | None = None
    symbol: str | None = None


def _split_module_and_symbol(spec: str) -> tuple[str, str | None]:
    if ":" not in spec:
        return spec.strip(), None
    mod_part, attr_raw = spec.split(":", 1)
    cand = attr_raw.strip().split("(", 1)[0].split(".", 1)[0].strip()
    sym = cand if cand and _PY_IDENT_RE.match(cand) else None
    return mod_part.strip(), sym


def _split_shell_segments(cmd: str) -> list[list[str]]:
    segments: list[list[str]] = []
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = cmd.split()
    cur: list[str] = []
    for tok in tokens:
        if set(tok) <= set(";&|()"):
            if cur:
                segments.append(cur)
                cur = []
        else:
            cur.append(tok)
    if cur:
        segments.append(cur)
    return segments


def _unwrap_launcher_prefix(argv: list[str], base_dir: str | None) -> tuple[list[str], str | None]:
    tokens = list(argv)
    cur_dir = base_dir
    for _ in range(8):
        while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
            tokens.pop(0)
        if not tokens:
            return [], cur_dir
        exe = PurePosixPath(tokens[0]).name
        if exe in {"exec", "nohup"}:
            tokens.pop(0)
            continue
        if exe in {"tini", "dumb-init"}:
            idx = 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                if tokens[idx] == "--":
                    idx += 1
                    break
                idx += 1
            tokens = tokens[idx:]
            continue
        if exe == "env":
            idx = 1
            while idx < len(tokens):
                t = tokens[idx]
                if t in {"-u", "--unset", "-C", "--chdir"} and idx + 1 < len(tokens):
                    if t in {"-C", "--chdir"}:
                        cur_dir = tokens[idx + 1]
                    idx += 2
                elif t.startswith("-") or "=" in t:
                    idx += 1
                else:
                    break
            tokens = tokens[idx:]
            continue
        if exe == "uv" and len(tokens) >= 2 and tokens[1] == "run":
            idx = 2
            while idx < len(tokens) and tokens[idx].startswith("-"):
                t = tokens[idx]
                if t in {"--directory", "--project"} and idx + 1 < len(tokens):
                    cur_dir = tokens[idx + 1]
                    idx += 2
                elif t in {"--package", "--python", "--env-file"} and idx + 1 < len(tokens):
                    idx += 2
                else:
                    idx += 1
            tokens = tokens[idx:]
            continue
        if exe in {"poetry", "pipenv", "pdm"} and len(tokens) >= 2 and tokens[1] == "run":
            tokens = tokens[2:]
            continue
        if exe in {"npx", "bunx"}:
            idx = 1
            while idx < len(tokens) and tokens[idx] in {"-y", "--yes", "--no-install"}:
                idx += 1
            tokens = tokens[idx:]
            continue
        break
    return tokens, cur_dir


def extract_command_targets_from_argv(
    raw_argv: list[str],
    env: dict[str, str] | None = None,
    base_dir: str | None = None,
) -> list[CommandTarget]:
    bindings = env or {}
    expanded_argv = [_expand_build_vars(t, bindings)[0] for t in raw_argv]
    argv, cur_dir = _unwrap_launcher_prefix(expanded_argv, base_dir)
    if not argv:
        return []
    exe = PurePosixPath(argv[0]).name
    out: list[CommandTarget] = []

    if exe in _SHELL_BINARIES:
        for idx, tok in enumerate(argv[1:], start=1):
            if tok == "--":
                break
            if tok.startswith("-") and "c" in tok[1:]:
                if idx + 1 < len(argv):
                    out.extend(extract_command_targets_from_shell(argv[idx + 1], bindings, cur_dir))
                return out
        for tok in argv[1:]:
            if not tok.startswith("-"):
                out.append(CommandTarget("file", tok, cur_dir))
                break
        return out

    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?|pypy3?", exe):
        idx = 1
        while idx < len(argv):
            tok = argv[idx]
            if tok == "-m" and idx + 1 < len(argv):
                mod = argv[idx + 1]
                if mod in _PY_RUNNERS:
                    out.extend(extract_command_targets_from_argv([mod, *argv[idx + 2 :]], bindings, cur_dir))
                else:
                    out.append(CommandTarget("py_module", mod, cur_dir))
                return out
            if tok == "-c":
                return out
            if tok in {"-W", "-X", "--check-hash-based-pycs"}:
                idx += 2
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            out.append(CommandTarget("file", tok, cur_dir))
            return out
        return out

    if exe in {"uvicorn", "gunicorn", "hypercorn", "daphne", "granian"}:
        sub_dir = cur_dir
        idx = 1
        while idx < len(argv):
            tok = argv[idx]
            if tok in {"--app-dir", "--chdir"} and idx + 1 < len(argv):
                sub_dir = argv[idx + 1]
                idx += 2
            elif tok.startswith(("--app-dir=", "--chdir=")):
                sub_dir = tok.split("=", 1)[1]
                idx += 1
            elif exe == "gunicorn" and tok in {"-c", "--config"} and idx + 1 < len(argv):
                if argv[idx + 1].endswith(".py"):
                    out.append(CommandTarget("file", argv[idx + 1], sub_dir))
                idx += 2
            elif tok in _VALUE_FLAGS_ASGI:
                idx += 2
            elif tok.startswith("-"):
                idx += 1
            else:
                mod_part, sym = _split_module_and_symbol(tok)
                if mod_part:
                    kind = "file" if (mod_part.endswith(".py") or "/" in mod_part) else "py_module"
                    out.append(CommandTarget(kind, mod_part, sub_dir, sym))
                break
        return out

    if exe == "celery":
        sub_dir = cur_dir
        app_ref: str | None = None
        idx = 1
        while idx < len(argv):
            tok = argv[idx]
            if tok in {"-A", "--app"} and idx + 1 < len(argv):
                app_ref = argv[idx + 1]
                idx += 2
            elif tok.startswith("--app="):
                app_ref = tok.split("=", 1)[1]
                idx += 1
            elif tok == "--workdir" and idx + 1 < len(argv):
                sub_dir = argv[idx + 1]
                idx += 2
            elif tok.startswith("--workdir="):
                sub_dir = tok.split("=", 1)[1]
                idx += 1
            else:
                idx += 1
        if app_ref:
            mod_part, sym = _split_module_and_symbol(app_ref)
            if mod_part:
                out.append(CommandTarget("py_module", mod_part, sub_dir, sym))
        return out

    if exe == "fastapi":
        app_sym: str | None = None
        target_tok: str | None = None
        idx = 1
        while idx < len(argv):
            tok = argv[idx]
            if tok in {"run", "dev"}:
                idx += 1
            elif tok == "--app" and idx + 1 < len(argv):
                cand = argv[idx + 1].strip()
                app_sym = cand if _PY_IDENT_RE.match(cand) else None
                idx += 2
            elif tok.startswith("--app="):
                cand = tok.split("=", 1)[1].strip()
                app_sym = cand if _PY_IDENT_RE.match(cand) else None
                idx += 1
            elif tok in _VALUE_FLAGS_ASGI:
                idx += 2
            elif tok.startswith("-"):
                idx += 1
            elif target_tok is None:
                target_tok = tok
                idx += 1
            else:
                idx += 1
        if target_tok:
            mod_part, colon_sym = _split_module_and_symbol(target_tok)
            if mod_part:
                kind = "file" if (mod_part.endswith(".py") or "/" in mod_part) else "py_module"
                out.append(CommandTarget(kind, mod_part, cur_dir, app_sym or colon_sym))
        return out

    if exe == "flask":
        app_ref = bindings.get("FLASK_APP")
        idx = 1
        while idx < len(argv):
            tok = argv[idx]
            if tok in {"-A", "--app"} and idx + 1 < len(argv):
                app_ref = argv[idx + 1]
                idx += 2
            elif tok.startswith("--app="):
                app_ref = tok.split("=", 1)[1]
                idx += 1
            else:
                idx += 1
        if app_ref:
            mod_part, sym = _split_module_and_symbol(app_ref)
            if mod_part:
                kind = "file" if (mod_part.endswith(".py") or "/" in mod_part) else "py_module"
                out.append(CommandTarget(kind, mod_part, cur_dir, sym))
        return out

    if exe in {"dramatiq", "arq"}:
        for tok in argv[1:]:
            if not tok.startswith("-"):
                mod_part, sym = _split_module_and_symbol(tok)
                if mod_part:
                    out.append(CommandTarget("py_module", mod_part, cur_dir, sym))
                break
        return out

    if exe in _NODE_BINS:
        idx = 1
        while idx < len(argv):
            tok = argv[idx]
            if idx == 1 and exe in {"bun", "deno"} and tok == "run":
                idx += 1
            elif tok in {"-r", "--require", "--import", "--loader", "--env-file", "-e", "--eval"}:
                idx += 2
            elif tok.startswith("-"):
                idx += 1
            else:
                out.append(CommandTarget("node_script", tok, cur_dir))
                break
        return out

    out.append(CommandTarget("file", argv[0], cur_dir))
    for tok in argv[1:]:
        if not tok.startswith("-") and tok.endswith((".py", ".sh")):
            out.append(CommandTarget("file", tok, cur_dir))
    return out


def extract_command_targets_from_shell(
    shell_cmd: str,
    env: dict[str, str] | None = None,
    base_dir: str | None = None,
) -> list[CommandTarget]:
    out: list[CommandTarget] = []
    for seg in _split_shell_segments(shell_cmd):
        out.extend(extract_command_targets_from_argv(seg, env, base_dir))
    return out


def extract_stage_command_targets(stage: DockerStage) -> tuple[list[CommandTarget], int]:
    targets: list[CommandTarget] = []
    line = stage.line
    ep = stage.entrypoint
    cmd = stage.cmd
    if ep is not None:
        line = ep.line
        if ep.is_exec and ep.argv:
            targets.extend(extract_command_targets_from_argv(list(ep.argv), stage.env, stage.workdir))
        elif ep.shell_cmd:
            targets.extend(extract_command_targets_from_shell(ep.shell_cmd, stage.env, stage.workdir))
    if cmd is not None:
        line = cmd.line
        if cmd.is_exec and cmd.argv:
            targets.extend(extract_command_targets_from_argv(list(cmd.argv), stage.env, stage.workdir))
        elif cmd.shell_cmd:
            targets.extend(extract_command_targets_from_shell(cmd.shell_cmd, stage.env, stage.workdir))
    if ep is not None and cmd is not None and ep.is_exec and cmd.is_exec and ep.argv and cmd.argv:
        targets.extend(
            extract_command_targets_from_argv([*ep.argv, *cmd.argv], stage.env, stage.workdir)
        )
    return list(dict.fromkeys(targets)), line


def _py_module_rel_candidates(dotted: str) -> list[str]:
    clean = dotted.strip().strip(".")
    if not clean:
        return []
    parts = [p for p in clean.split(".") if p]
    if not parts:
        return []
    prefix = "/".join(parts)
    cands = [f"{prefix}.py", f"{prefix}/__main__.py", f"{prefix}/__init__.py", f"{prefix}/celery.py"]
    if len(parts) >= 2:
        parent = "/".join(parts[:-1])
        cands.extend([f"{parent}.py", f"{parent}/__init__.py"])
    return cands


_ROUTE_DECORATOR_NAMES = frozenset(
    {
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "options",
        "head",
        "trace",
        "route",
        "api_route",
        "websocket",
    }
)
_TASK_DECORATOR_NAMES = frozenset(
    {
        "task",
        "shared_task",
        "periodic_task",
        "actor",
        "cron",
    }
)
_ROUTER_MOUNT_ATTRS = frozenset(
    {
        "include_router",
        "register_blueprint",
        "add_api_route",
        "add_url_rule",
        "mount",
    }
)


def _decorator_leaf_names(stmt: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for dec in stmt.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _collect_top_level_callables(
    stmts: list[ast.stmt],
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]:
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = {}
    try_types = (ast.Try, *((ast.TryStar,) if hasattr(ast, "TryStar") else ()))
    stack: list[ast.stmt] = list(reversed(stmts))
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found[stmt.name] = stmt
        elif isinstance(stmt, ast.If):
            stack.extend(reversed(stmt.orelse))
            if not _is_type_checking_guard(stmt.test):
                stack.extend(reversed(stmt.body))
        elif isinstance(stmt, try_types):
            stack.extend(reversed(stmt.finalbody))
            stack.extend(reversed(stmt.orelse))
            for handler in reversed(stmt.handlers):
                stack.extend(reversed(handler.body))
            stack.extend(reversed(stmt.body))
    return found


def _filter_callable_entrypoint_symbols(
    real_root: Path,
    repo_rel: str,
    candidate_syms: set[str],
) -> tuple[str, ...]:
    """Return sorted callable symbols when safe to scope, or `()` for whole-module entrypoints."""
    if not candidate_syms or not repo_rel.endswith(".py"):
        return ()
    py_path = real_root / repo_rel
    try:
        raw_py = _read_bounded_regular_text(
            py_path, max_bytes=262_144, real_root=real_root, encoding="utf-8-sig"
        )
        tree = ast.parse(raw_py)
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
        return ()

    callable_defs = _collect_top_level_callables(tree.body)
    if any(sym not in callable_defs for sym in candidate_syms):
        return ()

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _ROUTER_MOUNT_ATTRS
        ):
            return ()

    cand_are_task_handlers = all(
        isinstance(callable_defs[sym], (ast.FunctionDef, ast.AsyncFunctionDef))
        and bool(_decorator_leaf_names(callable_defs[sym]) & _TASK_DECORATOR_NAMES)  # type: ignore[arg-type]
        for sym in candidate_syms
    )
    for name, def_stmt in callable_defs.items():
        if name in candidate_syms or not isinstance(def_stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dec_names = _decorator_leaf_names(def_stmt)
        if dec_names & _ROUTE_DECORATOR_NAMES:
            return ()
        if (dec_names & _TASK_DECORATOR_NAMES) and not cand_are_task_handlers:
            return ()

    return tuple(sorted(candidate_syms))


def effective_node_symbol_links(
    target_node_id: str,
    syms: tuple[str, ...],
    result: ManipulatorExtractionResult,
) -> list[str]:
    """Avoid narrowing `symbol_links` into a node whose outgoing edges lack symbol tracking."""
    if not syms:
        return []
    out_edges = [e for e in result.edges if e.source_id == target_node_id]
    if out_edges and not any(e.symbol_links for e in out_edges):
        return []
    return [f"*->{s}" for s in syms]


def resolve_command_targets_with_symbols(
    targets: list[CommandTarget],
    real_root: Path,
    stage: DockerStage | None,
    fallback_roots: list[Path],
    known_source_files: set[str],
) -> list[tuple[str, bool, tuple[str, ...]]]:
    resolved: dict[str, bool] = {}
    syms_by_rel: dict[str, set[str]] = {}
    whole_mod_rels: set[str] = set()

    def _record(repo_rel: str, via_copy: bool, sym: str | None) -> None:
        prev = resolved.get(repo_rel)
        if prev is None or (via_copy and not prev):
            resolved[repo_rel] = via_copy
        if sym and _PY_IDENT_RE.match(sym):
            syms_by_rel.setdefault(repo_rel, set()).add(sym)
        else:
            whole_mod_rels.add(repo_rel)

    py_dirs: list[str] = []
    if stage is not None:
        raw_pp = stage.env.get("PYTHONPATH", "")
        for item in raw_pp.split(":"):
            if item.strip():
                py_dirs.append(_norm_container_path(item.strip(), stage.workdir))

    for tgt in targets:
        if _VAR_TOKEN_RE.search(tgt.value):
            continue
        search_cdirs: list[str] = []
        if stage is not None:
            bdir = _norm_container_path(tgt.base_dir, stage.workdir) if tgt.base_dir else stage.workdir
            search_cdirs.append(bdir)
            for pdir in py_dirs:
                if pdir not in search_cdirs:
                    search_cdirs.append(pdir)

        if tgt.kind in ("file", "node_script"):
            hit_copy = False
            if stage is not None:
                cpath = _norm_container_path(tgt.value, search_cdirs[0])
                r_rel = stage.resolve_container_file(cpath, real_root)
                if r_rel is not None:
                    _record(r_rel, True, tgt.symbol)
                    hit_copy = True
            if not hit_copy:
                rel_cands: list[str] = []
                if stage is not None and stage.workdir != "/":
                    cpath_wd = _norm_container_path(tgt.value, search_cdirs[0])
                    wd_prefix = stage.workdir.rstrip("/") + "/"
                    if cpath_wd.startswith(wd_prefix):
                        rel_wd = _normalize_posix_rel(cpath_wd[len(wd_prefix) :])
                        if rel_wd and rel_wd != ".":
                            rel_cands.append(rel_wd)
                norm_val = _normalize_posix_rel(tgt.value)
                if norm_val and norm_val != "." and norm_val not in rel_cands:
                    rel_cands.append(norm_val)
                for rc in rel_cands:
                    for froot in fallback_roots:
                        rel_hit = _safe_contained_file(froot / rc, real_root)
                        if rel_hit is not None:
                            _record(rel_hit, False, tgt.symbol)
                            hit_copy = True
                            break
                    if hit_copy:
                        break
                if not hit_copy and norm_val and norm_val != "." and tgt.kind == "node_script":
                    stripped = re.sub(r"^(?:dist|build)/", "", norm_val)
                    stem = str(PurePosixPath(stripped).with_suffix(""))
                    ts_cands = [f"src/{stem}.ts", f"{stem}.ts", f"src/{stem}.js", f"{stem}.js"]
                    matches = [
                        rel_hit
                        for froot in fallback_roots
                        for tc in ts_cands
                        if (rel_hit := _safe_contained_file(froot / tc, real_root)) is not None
                    ]
                    uniq = sorted(set(matches))
                    if len(uniq) == 1:
                        _record(uniq[0], False, tgt.symbol)

        elif tgt.kind == "py_module":
            mod_cands = _py_module_rel_candidates(tgt.value)
            mod_parts = [p for p in tgt.value.strip().strip(".").split(".") if p]
            tail_sym = mod_parts[-1] if len(mod_parts) >= 2 and _PY_IDENT_RE.match(mod_parts[-1]) else None
            hit_copy = False
            if stage is not None:
                for cdir in search_cdirs:
                    for mc_idx, mc in enumerate(mod_cands):
                        cpath = _norm_container_path(mc, cdir)
                        r_rel = stage.resolve_container_file(cpath, real_root)
                        if r_rel is not None:
                            eff_sym = tgt.symbol or (tail_sym if mc_idx >= 4 else None)
                            _record(r_rel, True, eff_sym)
                            hit_copy = True
                            break
                    if hit_copy:
                        break
            if not hit_copy:
                for froot in fallback_roots:
                    for mc_idx, mc in enumerate(mod_cands):
                        rel_hit = _safe_contained_file(froot / mc, real_root)
                        if rel_hit is not None:
                            eff_sym = tgt.symbol or (tail_sym if mc_idx >= 4 else None)
                            _record(rel_hit, False, eff_sym)
                            hit_copy = True
                            break
                    if hit_copy:
                        break
                if not hit_copy:
                    suffix_matches = [
                        sf for mc in mod_cands[:3] for sf in known_source_files if sf == mc or sf.endswith("/" + mc)
                    ]
                    uniq = sorted(set(suffix_matches))
                    if len(uniq) == 1:
                        _record(uniq[0], False, tgt.symbol)

    return [
        (
            k,
            resolved[k],
            ()
            if k in whole_mod_rels
            else _filter_callable_entrypoint_symbols(real_root, k, syms_by_rel.get(k, set())),
        )
        for k in sorted(resolved)
    ]


def resolve_command_targets_to_repo(
    targets: list[CommandTarget],
    real_root: Path,
    stage: DockerStage | None,
    fallback_roots: list[Path],
    known_source_files: set[str],
) -> list[tuple[str, bool]]:
    return [
        (rel, via_copy)
        for rel, via_copy, _ in resolve_command_targets_with_symbols(
            targets, real_root, stage, fallback_roots, known_source_files
        )
    ]


def index_nodes_by_source(result: ManipulatorExtractionResult) -> dict[str, list[AtlasNode]]:
    by_src: dict[str, list[AtlasNode]] = {}
    for node in result.nodes:
        if not node.id.startswith(CONTAINER_NODE_PREFIXES):
            by_src.setdefault(node.source_file, []).append(node)
    return by_src


def ensure_repo_target_nodes(
    repo_rel: str,
    real_root: Path,
    result: ManipulatorExtractionResult,
    by_src: dict[str, list[AtlasNode]],
    stage: DockerStage | None,
    fallback_roots: list[Path],
    seen_edge_ids: set[str],
) -> list[AtlasNode]:
    existing = by_src.get(repo_rel)
    if existing:
        target_nodes = existing
    else:
        if _safe_contained_file(real_root / repo_rel, real_root) is None:
            return []
        script_node = AtlasNode(
            id=f"m:script:{repo_rel}",
            tier="manipulate",
            subkind="cli",
            label=PurePosixPath(repo_rel).name,
            source_file=repo_rel,
            cluster="containers",
            summary="Container-referenced repository script; runtime execution is not observed.",
        )
        result.nodes.append(script_node)
        by_src[repo_rel] = [script_node]
        target_nodes = [script_node]

    if repo_rel.endswith(".sh"):
        sh_fs = real_root / repo_rel
        if _safe_contained_file(sh_fs, real_root) is not None:
            try:
                sh_text = _read_bounded_regular_text(sh_fs, max_bytes=65_536, real_root=real_root)
            except (OSError, UnicodeError, ValueError):
                sh_text = ""
            sh_targets: list[CommandTarget] = []
            for raw_line in sh_text.splitlines():
                sline = raw_line.strip()
                if not sline or sline.startswith("#"):
                    continue
                sh_targets.extend(
                    extract_command_targets_from_shell(
                        sline, stage.env if stage else None, stage.workdir if stage else None
                    )
                )
            sub_resolved = resolve_command_targets_with_symbols(
                sh_targets, real_root, stage, fallback_roots, set(by_src)
            )
            sh_nid = target_nodes[0].id
            for sub_rel, _, sub_syms in sub_resolved:
                if sub_rel == repo_rel:
                    continue
                for sub_node in by_src.get(sub_rel, []):
                    eid = f"e:script:{repo_rel}:{sub_node.id}"
                    if eid not in seen_edge_ids:
                        seen_edge_ids.add(eid)
                        result.edges.append(
                            AtlasEdge(
                                id=eid,
                                source_id=sh_nid,
                                target_id=sub_node.id,
                                kind="calls_helper",
                                verification="declared",
                                evidence_path=f"{repo_rel}:1",
                                evidence_note="Shell entrypoint script references this repository module.",
                                symbol_links=effective_node_symbol_links(
                                    sub_node.id, sub_syms, result
                                ),
                            )
                        )
    return target_nodes


def _is_type_checking_guard(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _iter_runtime_import_stmts(stmts: list[ast.stmt]) -> list[ast.Import | ast.ImportFrom]:
    found: list[ast.Import | ast.ImportFrom] = []
    try_types = (ast.Try, *((ast.TryStar,) if hasattr(ast, "TryStar") else ()))
    stack: list[ast.stmt] = list(reversed(stmts))
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            found.append(stmt)
        elif isinstance(stmt, ast.If):
            stack.extend(reversed(stmt.orelse))
            if not _is_type_checking_guard(stmt.test):
                stack.extend(reversed(stmt.body))
        elif isinstance(stmt, try_types):
            stack.extend(reversed(stmt.finalbody))
            stack.extend(reversed(stmt.orelse))
            for handler in reversed(stmt.handlers):
                stack.extend(reversed(handler.body))
            stack.extend(reversed(stmt.body))
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(reversed(stmt.body))
    return found


def _resolve_dotted_to_repo(dotted: str, base_dir: Path, real_root: Path) -> list[str]:
    parts = [p for p in dotted.split(".") if p]
    if not parts:
        return []
    if any(not _has_safe_path_segments(p) for p in parts[:-1]):
        return []
    out: list[str] = []
    py_cand = base_dir.joinpath(*parts[:-1], f"{parts[-1]}.py")
    init_cand = base_dir.joinpath(*parts, "__init__.py")
    for cand in (py_cand, init_cand):
        rel_hit = _safe_contained_file(cand, real_root)
        if rel_hit is not None:
            out.append(rel_hit)
    return out


def _extract_py_import_files(
    py_fs: Path, real_root: Path, import_roots: list[Path]
) -> list[str]:
    try:
        raw_py = _read_bounded_regular_text(py_fs, max_bytes=262_144, real_root=real_root)
        tree = ast.parse(raw_py)
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
        return []
    resolved: list[str] = []
    for stmt in _iter_runtime_import_stmts(tree.body):
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                for root in import_roots:
                    resolved.extend(_resolve_dotted_to_repo(alias.name, root, real_root))
        elif stmt.level > 0:
            rel_base = py_fs.parent
            for _ in range(stmt.level - 1):
                rel_base = rel_base.parent
            if not _is_within_root(rel_base, real_root):
                continue
            if stmt.module:
                resolved.extend(_resolve_dotted_to_repo(stmt.module, rel_base, real_root))
            for alias in stmt.names:
                if alias.name != "*":
                    sub = f"{stmt.module}.{alias.name}" if stmt.module else alias.name
                    resolved.extend(_resolve_dotted_to_repo(sub, rel_base, real_root))
        elif stmt.module:
            for root in import_roots:
                resolved.extend(_resolve_dotted_to_repo(stmt.module, root, real_root))
                for alias in stmt.names:
                    if alias.name != "*":
                        resolved.extend(
                            _resolve_dotted_to_repo(f"{stmt.module}.{alias.name}", root, real_root)
                        )
    return sorted(set(resolved))


def _check_unpacked_runtime_dependencies(
    df_nid: str,
    df_rel: str,
    cmd_line: int,
    final_stage: DockerStage,
    seed_nodes: list[AtlasNode],
    real_root: Path,
    import_roots: list[Path],
    result: ManipulatorExtractionResult,
) -> None:
    if not final_stage.mappings or not seed_nodes:
        return
    node_by_id = {n.id: n for n in result.nodes}
    nodes_by_rel: dict[str, list[str]] = {}
    for n in result.nodes:
        if not n.id.startswith(CONTAINER_NODE_PREFIXES):
            nodes_by_rel.setdefault(n.source_file, []).append(n.id)
    adj: dict[str, list[str]] = {}
    for edge in result.edges:
        if edge.kind != "calls_helper" or edge.verification not in ("declared", "verified"):
            continue
        if edge.id.startswith(CONTAINER_EDGE_PREFIXES):
            continue
        adj.setdefault(edge.source_id, []).append(edge.target_id)

    queue: deque[str] = deque()
    trails: dict[str, tuple[str, ...]] = {}
    for snode in seed_nodes:
        srel = snode.source_file
        if srel and srel not in trails:
            trails[srel] = (srel,)
            queue.append(srel)

    flagged_files: set[str] = set()
    while queue and len(flagged_files) < 15:
        cur_rel = queue.popleft()
        cur_trail = trails[cur_rel]
        cur_fs = real_root / cur_rel
        valid_fs = _safe_contained_file(cur_fs, real_root) is not None
        if valid_fs:
            covered, reason = final_stage.covers_repo_file(cur_rel)
            if not covered and cur_rel not in flagged_files:
                flagged_files.add(cur_rel)
                via_str = " -> ".join(dict.fromkeys(cur_trail))
                if reason == "excluded_by_dockerignore":
                    ign_name = final_stage.mappings[-1].ignore_spec.source_rel or ".dockerignore"
                    result.findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-005",
                            node_id=df_nid,
                            source_file=df_rel,
                            line=cmd_line,
                            title=f"Container entrypoint dependency `{cur_rel}` is excluded by `.dockerignore`",
                            detail=(
                                f"Final-stage command at `{df_rel}:{cmd_line}` reaches `{cur_rel}` "
                                f"(via `{via_str}`), which is excluded from build context by `{ign_name}`."
                            ),
                            remediation=(
                                "Re-include the required runtime module in `.dockerignore` "
                                "or decouple the container entrypoint from that import."
                            ),
                        )
                    )
                else:
                    result.findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-005",
                            node_id=df_nid,
                            source_file=df_rel,
                            line=cmd_line,
                            title=f"Container entrypoint imports `{cur_rel}` omitted from final-stage `COPY`",
                            detail=(
                                f"Final-stage command at `{df_rel}:{cmd_line}` reaches `{cur_rel}` "
                                f"(via `{via_str}`), but no final-stage `COPY`/`ADD` packs `{cur_rel}` into the image."
                            ),
                            remediation=(
                                "Copy the missing package/module into the runtime stage (or via `COPY --from=builder`) "
                                "so the container entrypoint can import it."
                            ),
                        )
                    )

        next_rels: set[str] = set()
        for nid in nodes_by_rel.get(cur_rel, ()):
            for nxt_id in adj.get(nid, ()):
                nxt_node = node_by_id.get(nxt_id)
                if nxt_node and not nxt_id.startswith(CONTAINER_NODE_PREFIXES):
                    next_rels.add(nxt_node.source_file)
        if valid_fs and cur_rel.endswith(".py"):
            next_rels.update(_extract_py_import_files(cur_fs, real_root, import_roots))

        for nxt_rel in sorted(next_rels):
            if nxt_rel not in trails and len(trails) < 256:
                trails[nxt_rel] = (*cur_trail, nxt_rel)
                queue.append(nxt_rel)


def augment_dockerfile_sources(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
) -> dict[str, object]:
    """Discover Dockerfiles, add `m:dockerfile:*` nodes/edges, and check build/runtime drift."""
    from app.adapters.container_launchers import augment_container_launchers

    skipped_notes: list[str] = []
    df_paths, _ = discover_dockerfiles(repo_root, skipped_notes=skipped_notes)
    if skipped_notes:
        object.__setattr__(result, "coverage_complete", False)
        for sn in skipped_notes:
            if sn not in result.notes:
                result.notes.append(sn)
    if not df_paths:
        di_notes: list[str] = []
        parse_dockerignore(repo_root, None, repo_root, notes_out=di_notes)
        if di_notes:
            object.__setattr__(result, "coverage_complete", False)
            for dn in di_notes:
                if dn not in result.notes:
                    result.notes.append(dn)
        augment_container_launchers(repo_root, backend_subdir, result, dockerfiles={})
        return {}

    real_root = _safe_resolve(repo_root)
    if real_root is None:
        object.__setattr__(result, "coverage_complete", False)
        return {}
    compose_hints = _compose_context_hints(repo_root)
    by_src = index_nodes_by_source(result)
    seen_node_ids = {n.id for n in result.nodes}
    seen_edge_ids = {e.id for e in result.edges}

    parsed_map: dict[str, object] = {}
    linked_count = 0
    unresolved_count = 0

    for df_path in df_paths:
        rel_guess = _safe_contained_file(df_path, real_root)
        if rel_guess is None:
            object.__setattr__(result, "coverage_complete", False)
            continue
        df_notes: list[str] = []
        parsed = parse_dockerfile(
            df_path, repo_root, context_override=compose_hints.get(rel_guess), notes_out=df_notes
        )
        if df_notes:
            object.__setattr__(result, "coverage_complete", False)
            for dn in df_notes:
                if dn not in result.notes:
                    result.notes.append(dn)
        if parsed is None:
            object.__setattr__(result, "coverage_complete", False)
            continue
        parsed_map[parsed.rel_path] = parsed
        nid = f"m:dockerfile:{parsed.rel_path}"
        final_stage = parsed.select_stage()
        stage_count = len(parsed.stages)
        base_desc = f"from `{final_stage.base_image}`" if final_stage else "with no stages"
        stage_desc = f"{stage_count}-stage build ({base_desc})" if stage_count > 1 else f"Build ({base_desc})"

        if nid not in seen_node_ids:
            seen_node_ids.add(nid)
            result.nodes.append(
                AtlasNode(
                    id=nid,
                    tier="manipulate",
                    subkind="cli",
                    label=PurePosixPath(parsed.rel_path).name
                    if parsed.rel_path == PurePosixPath(parsed.rel_path).name
                    else parsed.rel_path,
                    source_file=parsed.rel_path,
                    line=final_stage.line if final_stage else 1,
                    cluster="containers",
                    summary=(
                        f"Container {stage_desc}. "
                        "Container build declaration; image build and runtime execution are not observed."
                    ),
                )
            )
        result.findings.extend(parsed.findings)

        if final_stage is None:
            unresolved_count += 1
            continue

        cmd_targets, cmd_line = extract_stage_command_targets(final_stage)
        fallback_roots = [parsed.context_root]
        bdir = (
            _safe_contained_dir(repo_root / backend_subdir, real_root)
            if backend_subdir
            else real_root
        )
        if bdir is not None and bdir not in fallback_roots:
            fallback_roots.append(bdir)

        resolved_triples = resolve_command_targets_with_symbols(
            cmd_targets, real_root, final_stage, fallback_roots, set(by_src)
        )
        if not resolved_triples:
            unresolved_count += 1
            continue

        linked_count += 1
        unpack_seeds: list[AtlasNode] = []
        for repo_rel, via_copy, syms in resolved_triples:
            tnodes = ensure_repo_target_nodes(
                repo_rel, real_root, result, by_src, final_stage, fallback_roots, seen_edge_ids
            )
            for tnode in tnodes:
                eid = f"e:dockerfile:{parsed.rel_path}:{tnode.id}"
                if eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    result.edges.append(
                        AtlasEdge(
                            id=eid,
                            source_id=nid,
                            target_id=tnode.id,
                            kind="calls_helper",
                            verification="declared",
                            evidence_path=f"{parsed.rel_path}:{cmd_line}",
                            evidence_note=(
                                "Dockerfile entrypoint/command resolves to this repository source; "
                                "image build and runtime execution are not observed."
                            ),
                            symbol_links=effective_node_symbol_links(tnode.id, syms, result),
                        )
                    )
                _, cov_reason = final_stage.covers_repo_file(repo_rel)
                if (
                    via_copy
                    or cov_reason == "excluded_by_dockerignore"
                    or not final_stage.installs_local_package
                ):
                    unpack_seeds.append(tnode)

        import_roots = list(dict.fromkeys([real_root, *fallback_roots]))
        _check_unpacked_runtime_dependencies(
            nid,
            parsed.rel_path,
            cmd_line,
            final_stage,
            unpack_seeds,
            real_root,
            import_roots,
            result,
        )

    if parsed_map:
        result.notes.append(
            f"Dockerfile source coverage: {len(parsed_map)} declaration(s), "
            f"{linked_count} linked to repository entrypoints, "
            f"{unresolved_count} with external or unresolved commands. "
            "Build args passed at CI time, external base image contents, and container runtime state are not observed."
        )
    augment_container_launchers(repo_root, backend_subdir, result, dockerfiles=parsed_map)
    return parsed_map
