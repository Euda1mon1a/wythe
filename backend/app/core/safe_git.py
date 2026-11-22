"""Hardened read-only Git subprocess wrapper (`target_code_executed=False`).

Neutralizes repository-controlled Git execution vectors (`core.fsmonitor`,
`core.hooksPath`, `diff.external`, `core.pager`, `filter.*`, `protocol.*`,
`log.showSignature`, `gpg.*`, `core.attributesFile`, `submodule.recurse`,
`core.alternateRefsCommand`, and global/system config hooks) and pre-validates
`.git` symlinks, worktree back-pointers, and repository configs before spawning `git`.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Final

SAFE_GIT_CONFIG_ARGS: Final[tuple[str, ...]] = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.excludesFile=/dev/null",
    "-c",
    "mailmap.file=/dev/null",
    "-c",
    "mailmap.blob=",
    "-c",
    "core.alternateRefsCommand=false",
    "-c",
    "core.sshCommand=/bin/false",
    "-c",
    "core.askPass=/bin/false",
    "-c",
    "diff.external=",
    "-c",
    "core.pager=cat",
    "-c",
    "log.showSignature=false",
    "-c",
    "gpg.program=/bin/false",
    "-c",
    "gpg.openpgp.program=/bin/false",
    "-c",
    "gpg.ssh.program=/bin/false",
    "-c",
    "gpg.x509.program=/bin/false",
    "-c",
    "credential.helper=",
    "-c",
    "submodule.recurse=false",
    "-c",
    "diff.ignoreSubmodules=all",
    "-c",
    "status.submoduleSummary=false",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.http.allow=never",
    "-c",
    "protocol.https.allow=never",
    "-c",
    "protocol.ssh.allow=never",
    "-c",
    "protocol.git.allow=never",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "filter.lfs.process=",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.clean=",
    "-c",
    "filter.lfs.required=false",
)

_SAFE_PATH_DEFAULT: Final[str] = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
_MAX_POINTER_BYTES: Final[int] = 4096
_MAX_CONFIG_BYTES: Final[int] = 1_048_576
_OS_ROOT_SYMLINK_DIRS: Final[frozenset[str]] = frozenset({"tmp", "var", "etc"})

_FORBIDDEN_CONFIG_SECTIONS: Final[frozenset[str]] = frozenset(
    {
        "include",
        "includeif",
        "protocol",
        "uploadpack",
        "receivepack",
    }
)
_FORBIDDEN_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {"worktree", "gitproxy", "excludesfile"}
)
_FORBIDDEN_DIFF_KEYS: Final[frozenset[str]] = frozenset(
    {"external", "command", "textconv", "orderfile"}
)
_FORBIDDEN_REMOTE_KEYS: Final[frozenset[str]] = frozenset(
    {"promisor", "vcs", "uploadpack", "receivepack", "proxy"}
)
_ALLOWED_LFS_FILTER_KEYS: Final[frozenset[str]] = frozenset(
    {"clean", "smudge", "process", "required"}
)


class SafeGitError(ValueError):
    """Raised when `.git` containment fails or safe Git execution fails."""


def _is_os_root_alias(path: Path) -> bool:
    return path.parent == Path(path.anchor) and path.name in _OS_ROOT_SYMLINK_DIRS


def _reject_symlink_walk_from(base: Path, target: Path, *, label: str) -> None:
    cur = base
    for part in target.relative_to(base).parts:
        if part in ("", "."):
            continue
        cur = cur / part
        if cur.is_symlink():
            raise SafeGitError(f"Refusing symlink component in {label}: {cur}")


def _reject_symlink_in_path_expr(base: Path, raw_target: str, *, label: str) -> None:
    cand = Path(raw_target)
    if cand.is_absolute():
        cur = Path(cand.anchor)
        parts = cand.parts[1:]
    else:
        cur = base
        parts = cand.parts
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            cur = cur.parent
            continue
        cur = cur / part
        if cur.is_symlink():
            if _is_os_root_alias(cur):
                cur = cur.resolve()
            else:
                raise SafeGitError(f"Refusing symlink component in {label}: {cur}")


def _read_regular_nofollow_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    if path.is_symlink():
        raise SafeGitError(f"Refusing symlinked {label}: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise SafeGitError(f"Refusing non-regular {label}: {path}")
            if st.st_size > max_bytes:
                raise SafeGitError(f"{label} exceeds {max_bytes} byte limit: {path}")
            raw = fh.read(max_bytes + 1)
    except SafeGitError:
        raise
    except OSError as exc:
        raise SafeGitError(f"Failed reading {label}: {path}") from exc
    if len(raw) > max_bytes:
        raise SafeGitError(f"{label} exceeds {max_bytes} byte limit: {path}")
    if b"\x00" in raw:
        raise SafeGitError(f"Null byte in {label}: {path}")
    return raw


def _lex_git_config_logical_lines(text: str) -> list[str]:
    """Lex git config physical lines into logical lines matching Git's `config.c`.

    - Outside quotes, `#` or `;` discards the rest of the **physical** line
      without honoring any trailing `\\` as a continuation, and finishes any
      active logical line.
    - Outside comments, `\\\\` / `\\"` / `\\<char>` consumes the next character
      (so `\\"` outside quotes stays a literal `"` without entering quotes),
      and a trailing `\\` immediately before `\\n` (or `\\r\\n`) joins the next
      physical line whether inside or outside quotes.
    """
    logical_lines: list[str] = []
    logical_buf: list[str] = []
    in_quotes = False
    for line in text.replace("\r\n", "\n").split("\n"):
        continued = False
        idx = 0
        line_len = len(line)
        while idx < line_len:
            ch = line[idx]
            if ch == "\\":
                if idx + 1 < line_len:
                    logical_buf.append(ch)
                    logical_buf.append(line[idx + 1])
                    idx += 2
                    continue
                continued = True
                break
            if not in_quotes and ch in ("#", ";"):
                break
            if ch == '"':
                in_quotes = not in_quotes
            logical_buf.append(ch)
            idx += 1
        if not continued:
            logical_lines.append("".join(logical_buf))
            logical_buf.clear()
            in_quotes = False
    if logical_buf:
        logical_lines.append("".join(logical_buf))
    return logical_lines


def _find_closing_bracket(line: str) -> int:
    in_quotes = False
    escaped = False
    for idx in range(1, len(line)):
        ch = line[idx]
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if not in_quotes and ch == "]":
            return idx
    return -1


def _parse_git_config_header(header: str, path: Path) -> tuple[str, str | None]:
    if '"' in header:
        q_start = header.index('"')
        sec_name = header[:q_start].strip().lower()
        sub_chars: list[str] = []
        idx = q_start + 1
        closed = False
        while idx < len(header):
            ch = header[idx]
            if ch == "\\" and idx + 1 < len(header):
                sub_chars.append(header[idx + 1])
                idx += 2
                continue
            if ch == '"':
                closed = True
                idx += 1
                break
            sub_chars.append(ch)
            idx += 1
        if not closed or header[idx:].strip():
            raise SafeGitError(f"Malformed git config subsection header in {path}")
        return sec_name, "".join(sub_chars)
    parts = header.split()
    if not parts:
        return "", None
    if len(parts) > 1:
        raise SafeGitError(f"Malformed unquoted git config subsection header in {path}")
    if "." in parts[0]:
        sec_raw, sub_raw = parts[0].split(".", 1)
        return sec_raw.strip().lower(), sub_raw.strip().lower()
    return parts[0].strip().lower(), None


def _validate_git_config_file(path: Path) -> None:
    raw = _read_regular_nofollow_bytes(path, max_bytes=_MAX_CONFIG_BYTES, label="git config")
    text = raw.decode("utf-8-sig", errors="replace")
    current_section = ""
    current_sub: str | None = None
    for logical_line in _lex_git_config_logical_lines(text):
        rest = logical_line.strip()
        while rest:
            if rest.startswith("["):
                end_idx = _find_closing_bracket(rest)
                if end_idx <= 1:
                    raise SafeGitError(f"Malformed git config section header in {path}")
                header = rest[1:end_idx].strip()
                sec_name, sub_name = _parse_git_config_header(header, path)
                if not sec_name:
                    raise SafeGitError(f"Empty git config section name in {path}")
                if sec_name in _FORBIDDEN_CONFIG_SECTIONS:
                    raise SafeGitError(
                        f"Forbidden git config section [{sec_name}] in {path}"
                    )
                if sec_name == "filter" and sub_name != "lfs":
                    raise SafeGitError(
                        f"Forbidden non-LFS git config filter [{header}] in {path}"
                    )
                current_section = sec_name
                current_sub = sub_name
                rest = rest[end_idx + 1 :].strip()
                continue
            stmt = rest
            rest = ""
            if not stmt:
                continue
            raw_key = stmt.split("=", 1)[0].strip()
            leaf_key = raw_key.rsplit(".", 1)[-1].strip().lower()
            full_key_lc = raw_key.lower()
            if current_section == "core" and (
                leaf_key in _FORBIDDEN_CORE_KEYS or full_key_lc in _FORBIDDEN_CORE_KEYS
            ):
                raise SafeGitError(f"Forbidden git config directive core.{leaf_key} in {path}")
            if current_section == "diff" and leaf_key in _FORBIDDEN_DIFF_KEYS:
                raise SafeGitError(f"Forbidden git config directive diff.{leaf_key} in {path}")
            if current_section == "remote" and leaf_key in _FORBIDDEN_REMOTE_KEYS:
                raise SafeGitError(f"Forbidden git config directive remote.{leaf_key} in {path}")
            if current_section == "extensions" and (
                leaf_key == "partialclone" or full_key_lc == "partialclone"
            ):
                raise SafeGitError(f"Forbidden git config directive extensions.partialClone in {path}")
            if current_section == "filter" and (
                current_sub != "lfs" or leaf_key not in _ALLOWED_LFS_FILTER_KEYS
            ):
                raise SafeGitError(f"Forbidden git config directive filter.{raw_key} in {path}")


def _reject_symlinks_in_git_tree(root_dir: Path, *, label: str) -> None:
    if root_dir.is_symlink():
        raise SafeGitError(f"Refusing symlinked {label}: {root_dir}")
    if not root_dir.is_dir():
        return
    stack: list[Path] = [root_dir]
    while stack:
        cur_dir = stack.pop()
        try:
            with os.scandir(cur_dir) as it:
                for entry in it:
                    if entry.is_symlink():
                        raise SafeGitError(
                            f"Refusing symlink inside {label}: {Path(entry.path)}"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
        except SafeGitError:
            raise
        except OSError as exc:
            raise SafeGitError(f"Failed inspecting {label}: {cur_dir}") from exc


def _validate_git_alternates(
    objects_dir: Path,
    allowed_git_roots: tuple[Path, ...],
    *,
    _visited: set[Path] | None = None,
    _depth: int = 0,
) -> None:
    if _depth > 5:
        raise SafeGitError(f"Git alternates chain exceeds maximum depth (5): {objects_dir}")
    seen = _visited if _visited is not None else set()
    if objects_dir.exists():
        obj_real = objects_dir.resolve()
        if obj_real in seen:
            return
        seen.add(obj_real)
    obj_info = objects_dir / "info"
    http_alt = obj_info / "http-alternates"
    if http_alt.is_symlink() or http_alt.exists():
        raw_http = _read_regular_nofollow_bytes(
            http_alt, max_bytes=_MAX_CONFIG_BYTES, label="objects/info/http-alternates"
        )
        for ln in raw_http.decode("utf-8", errors="replace").split("\n"):
            if ln == "" or ln.startswith("#"):
                continue
            raise SafeGitError(f"Refusing external git http-alternates entry in {http_alt}")
    alt_file = obj_info / "alternates"
    if alt_file.is_symlink() or alt_file.exists():
        raw_alt = _read_regular_nofollow_bytes(
            alt_file, max_bytes=_MAX_CONFIG_BYTES, label="objects/info/alternates"
        )
        for ln in raw_alt.decode("utf-8", errors="replace").split("\n"):
            if ln == "" or ln.startswith("#"):
                continue
            if "\r" in ln or ln != ln.strip():
                raise SafeGitError(
                    f"Refusing whitespace-padded or CR git alternates entry in {alt_file}"
                )
            if ln.startswith('"'):
                raise SafeGitError(f"Refusing quoted git alternates entry in {alt_file}")
            _reject_symlink_in_path_expr(objects_dir, ln, label="objects/info/alternates")
            cand = objects_dir / ln if not Path(ln).is_absolute() else Path(ln)
            if cand.is_symlink():
                raise SafeGitError(f"Refusing symlinked git alternates target: {cand}")
            resolved_alt = cand.resolve()
            if not any(resolved_alt.is_relative_to(r) for r in allowed_git_roots):
                raise SafeGitError(
                    f"Refusing external git alternates directory outside repository: {ln}"
                )
            if resolved_alt.exists():
                _reject_symlinks_in_git_tree(resolved_alt, label="internal git alternates")
                _validate_git_alternates(
                    resolved_alt,
                    allowed_git_roots,
                    _visited=seen,
                    _depth=_depth + 1,
                )


def _validate_git_dir_contents(
    git_dir: Path,
    *,
    check_head: bool = True,
    allow_commondir: bool = False,
    allowed_git_roots: tuple[Path, ...] | None = None,
) -> None:
    if not allow_commondir:
        commondir_path = git_dir / "commondir"
        if commondir_path.exists() or commondir_path.is_symlink():
            raise SafeGitError(
                f"Refusing git commondir outside validated worktree layout: {commondir_path}"
            )
    for top_name in (
        "objects",
        "refs",
        "reftable",
        "packed-refs",
        "index",
        "logs",
        "hooks",
        "info",
        "shallow",
        "worktrees",
        "FETCH_HEAD",
        "ORIG_HEAD",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "AUTO_MERGE",
    ):
        top_entry = git_dir / top_name
        if top_entry.is_symlink():
            raise SafeGitError(f"Refusing symlinked git {top_name}: {top_entry}")
    for reg_name in (
        "packed-refs",
        "index",
        "shallow",
        "FETCH_HEAD",
        "ORIG_HEAD",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "AUTO_MERGE",
    ):
        reg_entry = git_dir / reg_name
        if reg_entry.exists():
            st_reg = reg_entry.lstat()
            if not stat.S_ISREG(st_reg.st_mode):
                raise SafeGitError(f"Refusing non-regular git {reg_name}: {reg_entry}")
    if check_head:
        head = git_dir / "HEAD"
        if not head.exists() and not head.is_symlink():
            raise SafeGitError(f"Malformed .git directory (missing regular HEAD): {git_dir}")
        _read_regular_nofollow_bytes(head, max_bytes=_MAX_POINTER_BYTES, label="HEAD")
    for cfg_name in ("config", "config.worktree"):
        cfg_path = git_dir / cfg_name
        if cfg_path.is_symlink():
            raise SafeGitError(f"Refusing symlinked git {cfg_name}: {cfg_path}")
        if cfg_path.exists():
            _validate_git_config_file(cfg_path)
    for sub_tree in ("info", "refs", "reftable", "logs", "hooks", "objects"):
        _reject_symlinks_in_git_tree(git_dir / sub_tree, label=f"git {sub_tree}")
    attrs_path = git_dir / "info" / "attributes"
    if attrs_path.exists():
        _read_regular_nofollow_bytes(attrs_path, max_bytes=_MAX_CONFIG_BYTES, label="info/attributes")
    roots = allowed_git_roots or (git_dir.resolve(),)
    _validate_git_alternates(git_dir / "objects", roots)


def _validate_and_resolve_cwd(cwd: Path) -> Path:
    """Walk raw `cwd` segments before any `..` collapse; reject symlinks & return realpath."""
    cwd_path = Path(cwd)
    if cwd_path.is_symlink() and not _is_os_root_alias(cwd_path):
        raise SafeGitError(f"Refusing symlinked repository path: {cwd_path}")
    if cwd_path.is_absolute():
        cur = Path(cwd_path.anchor)
        parts = cwd_path.parts[1:]
    else:
        base_cwd = Path.cwd()
        for anc in (base_cwd, *base_cwd.parents):
            if anc.is_symlink() and not _is_os_root_alias(anc):
                raise SafeGitError(f"Refusing symlinked repository ancestor: {anc}")
        cur = base_cwd.resolve()
        parts = cwd_path.parts

    for idx, part in enumerate(parts):
        if part in ("", "."):
            continue
        if part == "..":
            cur = cur.parent
            continue
        cur = cur / part
        if cur.is_symlink():
            if _is_os_root_alias(cur):
                cur = cur.resolve()
            elif idx == len(parts) - 1:
                raise SafeGitError(f"Refusing symlinked repository path: {cur}")
            else:
                raise SafeGitError(f"Refusing symlinked repository ancestor: {cur}")

    resolved = cur.resolve()
    for anc in (resolved, *resolved.parents):
        if anc.is_symlink() and not _is_os_root_alias(anc):
            raise SafeGitError(f"Refusing symlinked repository ancestor: {anc}")
    return resolved


def _validate_git_dir_and_cwd(cwd: Path) -> tuple[Path | None, Path]:
    resolved_cwd = _validate_and_resolve_cwd(cwd)
    for ancestor in (resolved_cwd, *resolved_cwd.parents):
        marker = ancestor / ".git"
        if marker.is_symlink():
            raise SafeGitError(f"Refusing symlinked .git entry: {marker}")
        if not marker.exists():
            continue
        _reject_symlink_walk_from(ancestor, resolved_cwd, label="repository path")
        resolved_ancestor = ancestor.resolve()
        if marker.is_dir():
            resolved_gitdir = marker.resolve()
            _validate_git_dir_contents(resolved_gitdir, check_head=True)
            return resolved_gitdir, resolved_cwd
        if marker.is_file():
            raw = _read_regular_nofollow_bytes(marker, max_bytes=_MAX_POINTER_BYTES, label=".git file")
            text = raw.decode("utf-8", errors="replace").strip()
            if not text.startswith("gitdir:") or "\n" in text or "\r" in text:
                raise SafeGitError(f"Malformed .git file pointer: {marker}")
            raw_target = text.split(":", 1)[1].strip()
            if not raw_target:
                raise SafeGitError(f"Empty gitdir pointer in: {marker}")
            _reject_symlink_in_path_expr(marker.parent, raw_target, label="gitdir target")
            target_cand = (
                marker.parent / raw_target
                if not Path(raw_target).is_absolute()
                else Path(raw_target)
            )
            if target_cand.is_symlink():
                raise SafeGitError(f"Refusing symlinked gitdir target: {target_cand}")
            resolved_gitdir = target_cand.resolve()
            if not resolved_gitdir.is_dir():
                raise SafeGitError(f"gitdir pointer does not reference a valid Git directory: {marker}")
            is_inside_ancestor = resolved_gitdir.is_relative_to(resolved_ancestor)
            resolved_commondir: Path | None = None
            is_valid_worktree = False
            if resolved_gitdir.parent.name == "worktrees":
                commondir_file = resolved_gitdir / "commondir"
                back_gitdir_file = resolved_gitdir / "gitdir"
                if commondir_file.exists() or commondir_file.is_symlink():
                    cd_text = (
                        _read_regular_nofollow_bytes(
                            commondir_file, max_bytes=_MAX_POINTER_BYTES, label="commondir"
                        )
                        .decode("utf-8", errors="replace")
                        .strip()
                    )
                    if not cd_text or "\n" in cd_text or "\r" in cd_text:
                        raise SafeGitError(f"Malformed worktree commondir file: {commondir_file}")
                    _reject_symlink_in_path_expr(resolved_gitdir, cd_text, label="commondir target")
                    cd_cand = (
                        resolved_gitdir / cd_text
                        if not Path(cd_text).is_absolute()
                        else Path(cd_text)
                    )
                    resolved_commondir = cd_cand.resolve()
                if back_gitdir_file.exists() or back_gitdir_file.is_symlink():
                    bg_text = (
                        _read_regular_nofollow_bytes(
                            back_gitdir_file, max_bytes=_MAX_POINTER_BYTES, label="worktree gitdir"
                        )
                        .decode("utf-8", errors="replace")
                        .strip()
                    )
                    if not bg_text or "\n" in bg_text or "\r" in bg_text:
                        raise SafeGitError(f"Malformed worktree gitdir file: {back_gitdir_file}")
                    _reject_symlink_in_path_expr(resolved_gitdir, bg_text, label="worktree back-pointer")
                    bg_cand = (
                        resolved_gitdir / bg_text
                        if not Path(bg_text).is_absolute()
                        else Path(bg_text)
                    )
                    back_ok = not bg_cand.is_symlink() and bg_cand.resolve() == marker.resolve()
                else:
                    back_ok = False
                if (
                    resolved_commondir is not None
                    and back_ok
                    and resolved_gitdir.parent.parent.resolve() == resolved_commondir
                ):
                    _validate_git_dir_contents(
                        resolved_commondir,
                        check_head=True,
                        allowed_git_roots=(resolved_commondir,),
                    )
                    is_valid_worktree = True

            if not (is_inside_ancestor or is_valid_worktree):
                raise SafeGitError(
                    f"Refusing untrusted external gitdir redirect outside worktree layout: {marker}"
                )
            wt_roots = (
                (resolved_gitdir, resolved_commondir)
                if (is_valid_worktree and resolved_commondir is not None)
                else (resolved_gitdir,)
            )
            _validate_git_dir_contents(
                resolved_gitdir,
                check_head=True,
                allow_commondir=is_valid_worktree,
                allowed_git_roots=wt_roots,
            )
            if is_inside_ancestor and resolved_gitdir != (resolved_ancestor / ".git"):
                root_git = resolved_ancestor / ".git"
                if root_git.is_dir() and not root_git.is_symlink():
                    _validate_git_dir_contents(root_git.resolve(), check_head=True)
            return resolved_gitdir, resolved_cwd
        raise SafeGitError(f"Unsupported .git entry type: {marker}")
    return None, resolved_cwd


def validate_git_dir_containment(cwd: Path) -> Path | None:
    """Validate `.git` on `cwd` or its ancestors; reject symlinks, unsafe redirects & configs."""
    git_dir, _resolved_cwd = _validate_git_dir_and_cwd(cwd)
    return git_dir


def build_safe_git_env() -> dict[str, str]:
    """Return a minimal environment stripping proxy/SSH/hook/config overrides."""
    return {
        "PATH": os.environ.get("PATH") or _SAFE_PATH_DEFAULT,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_ASKPASS": "/bin/false",
        "GIT_SSH_COMMAND": "/bin/false",
        "GIT_EDITOR": "/bin/false",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "LC_ALL": "C",
    }


def run_safe_git(
    cwd: Path,
    *args: str,
    input_bytes: bytes | None = None,
    text: bool = False,
    check: bool = True,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str]:
    """Execute `git` read-only with config/hook execution vectors disabled."""
    git_dir, resolved_cwd = _validate_git_dir_and_cwd(cwd)
    if git_dir is None:
        raise SafeGitError(f"Not inside a Git repository: {cwd}")
    cmd = ["git", "--no-pager", *SAFE_GIT_CONFIG_ARGS, *args]
    return subprocess.run(
        cmd,
        cwd=resolved_cwd,
        input=input_bytes,
        capture_output=True,
        text=text,
        check=check,
        timeout=timeout,
        env=build_safe_git_env(),
    )
