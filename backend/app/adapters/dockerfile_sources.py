"""Static Dockerfile and .dockerignore lineage adapter.

Inspects build declarations without invoking `docker`, executing shell commands,
or following symlinks outside the repository root.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.service_sources import EXCLUDED_PARTS
from app.schemas.atlas import AtlasEdge, AtlasNode

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


def _is_within_root(candidate: Path, real_root: Path) -> bool:
    try:
        return candidate.resolve().is_relative_to(real_root)
    except OSError:
        return False


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


def _compile_dockerignore_glob(pattern: str) -> re.Pattern[str] | None:
    norm = pattern.strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.strip("/")
    if not norm or norm == ".":
        return re.compile(r"^.*$") if pattern.strip() in {"*", "**"} else None
    out: list[str] = ["^"]
    i = 0
    n = len(norm)
    while i < n:
        if norm[i : i + 3] == "**/":
            out.append("(?:.+/)?")
            i += 3
        elif norm[i : i + 3] == "/**":
            out.append("(?:/.*)?")
            i += 3
        elif norm[i : i + 2] == "**":
            out.append(".*")
            i += 2
        elif norm[i] == "*":
            out.append("[^/]*")
            i += 1
        elif norm[i] == "?":
            out.append("[^/]")
            i += 1
        elif norm[i] == "[":
            end = norm.find("]", i + 1)
            if end != -1:
                cls_body = norm[i + 1 : end]
                if cls_body.startswith("!"):
                    cls_body = "^" + cls_body[1:]
                out.append(f"[{cls_body}]")
                i = end + 1
            else:
                out.append(re.escape("["))
                i += 1
        else:
            out.append(re.escape(norm[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))


@dataclass(frozen=True)
class DockerIgnoreSpec:
    """Compiled `.dockerignore` rule list evaluated in declaration order."""

    source_rel: str | None = None
    rules: tuple[tuple[re.Pattern[str], bool], ...] = ()

    def is_excluded(self, rel_ctx: str) -> bool:
        if not self.rules:
            return False
        norm = _normalize_posix_rel(rel_ctx)
        if norm is None or norm == ".":
            return False
        parts = norm.split("/")
        ancestors = ["/".join(parts[:idx]) for idx in range(1, len(parts) + 1)]
        excluded = False
        for regex, negated in self.rules:
            if any(regex.match(anc) for anc in ancestors):
                excluded = not negated
        return excluded

    def is_dir_completely_excluded(self, dir_fs: Path, rel_ctx: str, real_root: Path) -> bool:
        if not self.rules:
            return False
        has_any_file = False
        for parent, dirs, names in os.walk(dir_fs, followlinks=False):
            dirs[:] = [
                d for d in sorted(dirs)
                if not (Path(parent) / d).is_symlink()
                and _is_within_root(Path(parent) / d, real_root)
            ]
            for name in sorted(names):
                fpath = Path(parent) / name
                if fpath.is_symlink() or not fpath.is_file():
                    continue
                if not _is_within_root(fpath, real_root):
                    continue
                has_any_file = True
                sub_rel = fpath.relative_to(dir_fs).as_posix()
                full_ctx = sub_rel if rel_ctx in ("", ".") else f"{rel_ctx}/{sub_rel}"
                if not self.is_excluded(full_ctx):
                    return False
        return has_any_file or self.is_excluded(rel_ctx)


def parse_dockerignore(
    context_root: Path,
    dockerfile_path: Path | None,
    repo_root: Path,
) -> DockerIgnoreSpec:
    real_root = repo_root.resolve()
    candidates: list[Path] = []
    if dockerfile_path is not None:
        candidates.append(dockerfile_path.with_name(dockerfile_path.name + ".dockerignore"))
    candidates.append(context_root / ".dockerignore")
    for cand in candidates:
        if cand.is_symlink() or not cand.is_file() or not _is_within_root(cand, real_root):
            continue
        try:
            text = cand.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        compiled: list[tuple[re.Pattern[str], bool]] = []
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped or raw_line.lstrip().startswith("#"):
                continue
            negated = stripped.startswith("!")
            pat_str = stripped[1:].strip() if negated else stripped
            if not pat_str:
                continue
            rx = _compile_dockerignore_glob(pat_str)
            if rx is not None:
                compiled.append((rx, negated))
        rel = cand.resolve().relative_to(real_root).as_posix()
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


def discover_dockerfiles(repo_root: Path) -> tuple[list[Path], int]:
    """Discover repository Dockerfiles/Containerfiles without following symlinks."""
    if repo_root.is_symlink():
        return [], 1
    real_root = repo_root.resolve()
    found: list[Path] = []
    excluded = 0
    for parent, dirs, names in os.walk(repo_root, followlinks=False):
        keep: list[str] = []
        for dname in sorted(dirs):
            dpath = Path(parent) / dname
            if (
                dname in EXCLUDED_PARTS
                or (dname.startswith(".") and dname not in ALLOWED_CONTAINER_DOT_DIRS)
                or dpath.is_symlink()
                or not _is_within_root(dpath, real_root)
            ):
                excluded += 1
            else:
                keep.append(dname)
        dirs[:] = keep
        for fname in sorted(names):
            if not _is_dockerfile_name(fname):
                continue
            fpath = Path(parent) / fname
            if fpath.is_symlink() or not _is_within_root(fpath, real_root):
                excluded += 1
            elif fpath.is_file():
                found.append(fpath)
    return sorted(found), excluded


def _compose_context_hints(repo_root: Path) -> dict[str, Path]:
    """Map repo-relative Dockerfile paths to explicit compose `build.context` roots."""
    real_root = repo_root.resolve()
    hints: dict[str, Path] = {}
    search_dirs = [repo_root]
    try:
        for child in sorted(repo_root.iterdir()):
            if (
                not child.is_symlink()
                and child.is_dir()
                and (not child.name.startswith(".") or child.name in ALLOWED_CONTAINER_DOT_DIRS)
                and child.name not in EXCLUDED_PARTS
                and _is_within_root(child, real_root)
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
            if cpath.is_symlink() or not cpath.is_file() or not _is_within_root(cpath, real_root):
                continue
            try:
                data = yaml.safe_load(cpath.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError):
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
                    ctx_raw = str(build.get("context") or ".")
                    df_raw = str(build.get("dockerfile") or "Dockerfile")
                else:
                    continue
                ctx_dir = (cpath.parent / ctx_raw).resolve()
                if not _is_within_root(ctx_dir, real_root) or not ctx_dir.is_dir():
                    continue
                df_cand = ctx_dir / df_raw
                if not df_cand.is_file():
                    df_cand = cpath.parent / df_raw
                if not df_cand.is_symlink() and df_cand.is_file() and _is_within_root(df_cand, real_root):
                    df_rel = df_cand.resolve().relative_to(real_root).as_posix()
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
                fs = real_root / mapping.repo_rel
                if not fs.is_symlink() and fs.is_file() and _is_within_root(fs, real_root):
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
                fs = real_root / cand_rel
                if not fs.is_symlink() and fs.is_file() and _is_within_root(fs, real_root):
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


def _expand_build_vars(value: str, bindings: dict[str, str]) -> tuple[str, bool]:
    unresolved = False

    def _repl(match: re.Match[str]) -> str:
        nonlocal unresolved
        if match.group("plain"):
            key = match.group("plain")
            if key in bindings:
                return bindings[key]
            unresolved = True
            return match.group(0)
        key = match.group("bname")
        op = match.group("bop")
        default = match.group("bdef") or ""
        cur = bindings.get(key)
        if op in (":-", "-"):
            if cur is not None and (cur != "" or op == "-"):
                return cur
            return default
        if op in (":+", "+"):
            if cur:
                return default
            return ""
        if cur is not None:
            return cur
        unresolved = True
        return match.group(0)

    return _BUILD_VAR_EXPAND_RE.sub(_repl, value), unresolved


def _shlex_tokens(raw: str) -> list[str]:
    try:
        return shlex.split(raw, posix=True)
    except ValueError:
        return raw.split()


def _parse_arg_bindings(raw_args: str, current: dict[str, str], global_args: dict[str, str]) -> None:
    for tok in _shlex_tokens(raw_args):
        if "=" in tok:
            k, v = tok.split("=", 1)
            expanded, _ = _expand_build_vars(v, current)
            if k:
                current[k] = expanded
        elif tok in global_args and tok not in current:
            current[tok] = global_args[tok]


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
        expanded, _ = _expand_build_vars(rest, current)
        current[key] = expanded
        return
    for tok in tokens:
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k:
            expanded, _ = _expand_build_vars(v, current)
            current[k] = expanded


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
            arr = json.loads(rest)
            if isinstance(arr, list) and len(arr) >= 2 and all(isinstance(x, str) for x in arr):
                return from_ref, arr[:-1], arr[-1]
        except json.JSONDecodeError:
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
    for src_raw in sources:
        src_exp, _ = _expand_build_vars(src_raw, dst_stage.env)
        sp = _norm_container_path(src_exp, src_stage.workdir)
        sp_prefix = sp.rstrip("/")
        for m in src_stage.mappings:
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
                    if fs.is_symlink() or not _is_within_root(fs, real_root):
                        continue
                    if fs.is_dir():
                        dst_stage.mappings.append(
                            StageCopyMapping(dest_abs, cand_repo, True, m.context_rel_root, m.ignore_spec)
                        )
                        dst_stage.known_dirs.add(dest_abs)
                    elif fs.is_file():
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
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
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
    real_root = repo_root.resolve()
    if context_override is not None and _is_within_root(context_override, real_root):
        return context_override.resolve()
    df_dir = df_path.parent.resolve()
    if df_dir == real_root:
        return real_root
    if (df_dir / ".dockerignore").is_file() and not (df_dir / ".dockerignore").is_symlink():
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
            if (df_dir / norm).exists():
                dir_hits += 1
            if (real_root / norm).exists():
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
) -> ParsedDockerfile | None:
    real_root = repo_root.resolve()
    if df_path.is_symlink() or not df_path.is_file() or not _is_within_root(df_path, real_root):
        return None
    try:
        text = df_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None

    rel_path = df_path.resolve().relative_to(real_root).as_posix()
    nid = f"m:dockerfile:{rel_path}"
    instructions = _split_dockerfile_instructions(text)
    context_root = _infer_context_root(df_path, instructions, repo_root, context_override)
    ctx_rel_root = (
        "." if context_root == real_root else context_root.relative_to(real_root).as_posix()
    )
    ignore_spec = parse_dockerignore(context_root, df_path, repo_root)

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
                    mappings=list(parent.mappings),
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
        if src_stage is None and ref_exp.isdigit():
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
                for p in sorted(context_root.glob(norm))
                if not p.is_symlink() and _is_within_root(p, real_root)
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
                m_ctx_rel = mp.resolve().relative_to(context_root).as_posix()
                m_repo_rel = mp.resolve().relative_to(real_root).as_posix()
                if mp.is_file() and not ignore_spec.is_excluded(m_ctx_rel):
                    kept += 1
                    c_dest = (
                        _norm_container_path(f"{dest_abs.rstrip('/')}/{mp.name}")
                        if dest_is_dir
                        else dest_abs
                    )
                    current_stage.mappings.append(
                        StageCopyMapping(c_dest, m_repo_rel, False, ctx_rel_root, ignore_spec)
                    )
                elif mp.is_dir() and not ignore_spec.is_dir_completely_excluded(mp, m_ctx_rel, real_root):
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
        if src_fs.is_symlink() or not _is_within_root(src_fs, real_root) or not src_fs.exists():
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

        repo_rel = (
            "."
            if src_fs.resolve() == real_root
            else src_fs.resolve().relative_to(real_root).as_posix()
        )
        if src_fs.is_file():
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
        elif src_fs.is_dir():
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
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found[stmt.name] = stmt
        elif isinstance(stmt, ast.If):
            if not _is_type_checking_guard(stmt.test):
                found.update(_collect_top_level_callables(stmt.body))
            found.update(_collect_top_level_callables(stmt.orelse))
        elif isinstance(stmt, ast.Try):
            found.update(_collect_top_level_callables(stmt.body))
            for handler in stmt.handlers:
                found.update(_collect_top_level_callables(handler.body))
            found.update(_collect_top_level_callables(stmt.orelse))
            found.update(_collect_top_level_callables(stmt.finalbody))
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
        if (
            py_path.is_symlink()
            or not py_path.is_file()
            or not _is_within_root(py_path, real_root)
            or py_path.stat().st_size > 262144
        ):
            return ()
        tree = ast.parse(py_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, SyntaxError, ValueError):
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
                        cand_fs = froot / rc
                        if not cand_fs.is_symlink() and cand_fs.is_file() and _is_within_root(cand_fs, real_root):
                            _record(cand_fs.resolve().relative_to(real_root).as_posix(), False, tgt.symbol)
                            hit_copy = True
                            break
                    if hit_copy:
                        break
                if not hit_copy and norm_val and norm_val != "." and tgt.kind == "node_script":
                    stripped = re.sub(r"^(?:dist|build)/", "", norm_val)
                    stem = str(PurePosixPath(stripped).with_suffix(""))
                    ts_cands = [f"src/{stem}.ts", f"{stem}.ts", f"src/{stem}.js", f"{stem}.js"]
                    matches = [
                        (froot / tc).resolve().relative_to(real_root).as_posix()
                        for froot in fallback_roots
                        for tc in ts_cands
                        if not (froot / tc).is_symlink()
                        and (froot / tc).is_file()
                        and _is_within_root(froot / tc, real_root)
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
                        cand_fs = froot / mc
                        if not cand_fs.is_symlink() and cand_fs.is_file() and _is_within_root(cand_fs, real_root):
                            eff_sym = tgt.symbol or (tail_sym if mc_idx >= 4 else None)
                            _record(cand_fs.resolve().relative_to(real_root).as_posix(), False, eff_sym)
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
        fs = real_root / repo_rel
        if fs.is_symlink() or not fs.is_file() or not _is_within_root(fs, real_root):
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
        if not sh_fs.is_symlink() and sh_fs.is_file() and sh_fs.stat().st_size <= 65536:
            try:
                sh_text = sh_fs.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
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
    for stmt in stmts:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            found.append(stmt)
        elif isinstance(stmt, ast.If):
            if not _is_type_checking_guard(stmt.test):
                found.extend(_iter_runtime_import_stmts(stmt.body))
            found.extend(_iter_runtime_import_stmts(stmt.orelse))
        elif isinstance(stmt, ast.Try):
            found.extend(_iter_runtime_import_stmts(stmt.body))
            for handler in stmt.handlers:
                found.extend(_iter_runtime_import_stmts(handler.body))
            found.extend(_iter_runtime_import_stmts(stmt.orelse))
            found.extend(_iter_runtime_import_stmts(stmt.finalbody))
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.extend(_iter_runtime_import_stmts(stmt.body))
    return found


def _resolve_dotted_to_repo(dotted: str, base_dir: Path, real_root: Path) -> list[str]:
    parts = [p for p in dotted.split(".") if p]
    if not parts:
        return []
    out: list[str] = []
    py_cand = base_dir.joinpath(*parts[:-1], f"{parts[-1]}.py")
    init_cand = base_dir.joinpath(*parts, "__init__.py")
    for cand in (py_cand, init_cand):
        if not cand.is_symlink() and cand.is_file() and _is_within_root(cand, real_root):
            out.append(cand.resolve().relative_to(real_root).as_posix())
    return out


def _extract_py_import_files(
    py_fs: Path, real_root: Path, import_roots: list[Path]
) -> list[str]:
    try:
        if py_fs.stat().st_size > 262144:
            return []
        tree = ast.parse(py_fs.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
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
        valid_fs = not cur_fs.is_symlink() and cur_fs.is_file() and _is_within_root(cur_fs, real_root)
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

    df_paths, _ = discover_dockerfiles(repo_root)
    if not df_paths:
        augment_container_launchers(repo_root, backend_subdir, result, dockerfiles={})
        return {}

    real_root = repo_root.resolve()
    compose_hints = _compose_context_hints(repo_root)
    by_src = index_nodes_by_source(result)
    seen_node_ids = {n.id for n in result.nodes}
    seen_edge_ids = {e.id for e in result.edges}

    parsed_map: dict[str, object] = {}
    linked_count = 0
    unresolved_count = 0

    for df_path in df_paths:
        rel_guess = df_path.resolve().relative_to(real_root).as_posix()
        parsed = parse_dockerfile(df_path, repo_root, context_override=compose_hints.get(rel_guess))
        if parsed is None:
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
        bdir = (repo_root / backend_subdir).resolve() if backend_subdir else real_root
        if _is_within_root(bdir, real_root) and bdir.is_dir() and bdir not in fallback_roots:
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
