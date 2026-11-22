"""Display-tier anti-confabulation checks for fabricated fallbacks (#119) & freshness (#121)."""

from __future__ import annotations

import json
import os
import re
import stat
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

from app.adapters.a11y_inspect import (
    _can_start_js_regex,
    _skip_js_regex,
    js_code_mask,
    scan_open_tag_end,
)
from app.adapters.base import DisplayExtractionResult, RawCandidateFinding
from app.adapters.ts_workspace import (
    MAX_FRONTEND_FILE_BYTES,
    safe_read_repo_bytes,
    safe_read_repo_text,
    safe_resolve_contained_path,
)

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "__tests__",
        "tests",
        "test",
        "ui_dist",
        ".next",
        "dist",
        "build",
        "vendor",
    }
)
_SENTINEL_STRINGS = frozenset(
    {
        "",
        "-",
        "--",
        "—",
        "–",
        "n/a",
        "na",
        "none",
        "null",
        "undefined",
        "unknown",
        "unmeasured",
        "unresolved",
        "could not measure",
        "could_not_measure",
        "unavailable",
        "not_recorded",
        "not recorded",
        "unverified",
        "static_inference",
        "uncommitted",
        "default",
        "auto",
        "pending",
    }
)
_UI_TOKEN_PROPS = frozenset(
    {
        "tier",
        "section",
        "bucket",
        "lane",
        "mode",
        "lens",
        "groupby",
        "group_by",
        "theme",
        "badgetone",
        "variant",
        "role",
        "type",
        "classname",
        "appearance",
        "preset",
        "polygonmode",
        "active_tab",
        "activetab",
        "epistemic_kind",
    }
)
_LAYOUT_NUMERIC_PROPS = frozenset(
    {
        "width",
        "height",
        "clientwidth",
        "clientheight",
        "scalemult",
        "zoom_stratum",
        "zoomstratum",
        "line",
        "limit",
        "page",
        "timeout",
        "tabindex",
        "cols",
        "rows",
        "stepindex",
        "active_phase_index",
        "focus_revision",
        "camera_revision",
        "seq",
    }
)
_COUNT_SCORE_RE = re.compile(
    r"(?:^|_)(?:count|counts|failed|failures|errors|pending|score|rate|pct|percent|dirty)$"
    r"|(?:Count|Counts|Failed|Failures|Errors|Score|Rate|Pct|Percent)$"
)
_ACTION_PROP_RE = re.compile(
    r"\b(?:href|url|action|actions|decide|consent|disposition|target_?id|subject_?id|onClick)\b",
    re.IGNORECASE,
)
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2})?)?")


@dataclass
class DisplayCallReadSet:
    """Resolved route/slice consumer and property paths read from its response (#120)."""

    route_key: str
    source_file: str
    call_line: int
    node_id: str | None
    read_paths: dict[str, int] = field(default_factory=dict)  # path -> first line
    action_or_status_paths: set[str] = field(default_factory=set)


def _read_contained_governance_json(repo_root: Path, rel: str) -> dict[str, object] | None:
    try:
        if repo_root.is_symlink():
            return None
        raw_bytes = safe_read_repo_bytes(repo_root / rel, repo_root, max_bytes=2_000_000)
        parsed = json.loads(raw_bytes.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (OSError, ValueError):
        return None


def load_fabricated_allowlist(repo_root: Path, *, strict: bool = False) -> set[str]:
    """Load file or `file:line` fixture/demo allowlist entries from `.wythe/governance.json`."""
    if strict:
        return set()
    try:
        if repo_root.is_symlink():
            return set()
    except OSError:
        return set()
    allow: set[str] = set()
    for rel in (".wythe/governance.json", ".truth-atlas/governance.json"):
        raw = _read_contained_governance_json(repo_root, rel)
        if raw is None:
            continue
        for item in raw.get("fabricated_fallback_allowlist") or []:
            if isinstance(item, str) and item.strip():
                allow.add(item.strip().lstrip("./"))
        for ex in raw.get("reference_exemplars") or []:
            if not isinstance(ex, dict):
                continue
            text_blob = f"{ex.get('title', '')} {ex.get('rationale', '')}".lower()
            ptr = str(ex.get("pointer") or "").strip().lstrip("./")
            if ptr and any(tok in text_blob for tok in ("demo", "fixture", "disp-009", "disp-010")):
                allow.add(ptr)
        for rl in raw.get("audit_rulings") or []:
            if not isinstance(rl, dict):
                continue
            if rl.get("disposition") == "intentional_exception":
                for sc in rl.get("evidence_scope") or []:
                    if isinstance(sc, str) and sc.strip():
                        allow.add(sc.strip().removeprefix("file:").lstrip("./"))
    return allow


def strip_js_comments_keep_lines(source: str) -> str:
    """Replace `//...` and `/*...*/` comments with spaces while preserving newlines, strings & regexes."""
    out: list[str] = []
    i, n = 0, len(source)
    in_tpl = False
    tpl_bdepth: list[int] = []
    expr_floors: list[int] = [0]
    prev_sig_pos = -1
    while i < n:
        if in_tpl:
            ch = source[i]
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(source[i + 1])
                i += 2
                continue
            if ch == "$" and i + 1 < n and source[i + 1] == "{":
                out.append("${")
                tpl_bdepth.append(0)
                expr_floors.append(i + 2)
                in_tpl = False
                prev_sig_pos = i + 1
                i += 2
                continue
            if ch == "`":
                out.append(ch)
                in_tpl = False
                prev_sig_pos = i
                i += 1
                continue
            out.append(ch)
            i += 1
            continue

        ch = source[i]
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = source[i]
                if c == "\\" and i + 1 < n:
                    out.append(c)
                    out.append(source[i + 1])
                    i += 2
                    continue
                out.append(c)
                if c == quote or c == "\n":
                    if c == quote:
                        prev_sig_pos = i
                    i += 1
                    break
                i += 1
            continue
        if ch == "`":
            out.append(ch)
            in_tpl = True
            i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n:
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            continue
        if ch == "/" and _can_start_js_regex(source, prev_sig_pos, expr_floors[-1]):
            rend = _skip_js_regex(source, i, n)
            if rend is not None:
                out.append(source[i:rend])
                prev_sig_pos = rend - 1
                i = rend
                continue
        if ch == "{":
            if tpl_bdepth:
                tpl_bdepth[-1] += 1
            expr_floors.append(i + 1)
        elif ch == "}":
            if tpl_bdepth:
                if tpl_bdepth[-1] == 0:
                    tpl_bdepth.pop()
                    if len(expr_floors) > 1:
                        expr_floors.pop()
                    in_tpl = True
                    out.append(ch)
                    prev_sig_pos = i
                    i += 1
                    continue
                tpl_bdepth[-1] -= 1
            if len(expr_floors) > 1:
                expr_floors.pop()
        out.append(ch)
        if not ch.isspace():
            prev_sig_pos = i
        i += 1
    return "".join(out)


_FETCH_BIND_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?"
    r"(?:[\w$.]+\.)?(fetch|fetchSlice|getSlice|loadSlice|get|post)\s*\(\s*([`'\"])([^`'\"]+)\3"
)
_JSON_UNWRAP_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\.json\s*\(\s*\)"
)
_ALIAS_SUBPATH_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*){1,3})"
)
_FALLBACK_EXPR_RE = re.compile(
    r"(?<![.\w$])([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+)\s*(\?\?|\|\|)\s*"
    r"(-?\d+(?:\.\d+)?|'[^'\n]*'|\"[^\"\n]*\")"
)
_PROP_ACCESS_RE = re.compile(r"(?<![.\w$])([A-Za-z_$][\w$]*)(?:\??\.([A-Za-z_$][\w$]*)){1,3}")
_UNTYPED_FN_PARAM_RE = re.compile(
    r"(?:function\s+[A-Za-z_$][\w$]*\s*\(\s*|export\s+function\s+[A-Za-z_$][\w$]*\s*\(\s*)"
    r"([A-Za-z_$][\w$]*)\s*(?:,|\))"
)
_JS_IMPORT_RE = re.compile(
    r"""(?<![.\w$])(?:import\s+(?:[^'"\n]+?\s+from\s+)?|import\s*\()\s*['"]([^'"]+)['"]"""
)
_EMPTY_BRANCH_SYNTH_RE = re.compile(
    r"(?:!\s*[A-Za-z_$][\w$.]*\.length\b|[A-Za-z_$][\w$.]*\.length\s*===\s*0"
    r"|\(\s*[A-Za-z_$][\w$.]*\s*\?\?\s*[1-9]\d*\s*\)\s*>\s*0)"
)
_PROTOTYPE_METHODS = frozenset(
    {
        "then",
        "catch",
        "finally",
        "json",
        "text",
        "ok",
        "status",
        "headers",
        "length",
        "map",
        "filter",
        "forEach",
        "reduce",
        "some",
        "every",
        "find",
        "includes",
        "slice",
        "join",
        "split",
        "trim",
        "keys",
        "values",
        "entries",
        "toString",
        "valueOf",
        "hasOwnProperty",
    }
)
_STATUS_COUNT_ACTION_LEAF_RE = re.compile(
    r"(?:^|_)(?:status|state|health|stale|ok|healthy|degraded|error|errors|failed|failures|"
    r"count|counts|total|pending|action|actions|proposals|candidates|decisions|href|url)$"
    r"|(?:Status|State|Health|Count|Counts|Actions|Proposals|Candidates)$"
)


def _check_dir_accessible(path: Path) -> None:
    if not os.access(path, os.R_OK | os.X_OK):
        raise PermissionError(f"Directory is not readable/traversable: {path}")
    with os.scandir(path):
        pass


def _inspect_contained_rel_path(repo_res: Path, rel_p: Path, label: str) -> tuple[bool, str | None]:
    """Check `rel_p` under `repo_res` with `lstat` only; return `(is_absent, reject_or_error_reason)`."""
    cur = repo_res
    for part in rel_p.parts:
        if part in ("", "."):
            continue
        cur = cur / part
        try:
            st = cur.lstat()
        except FileNotFoundError:
            return True, None
        except OSError as exc:
            return False, f"Unreadable {label} {rel_p}: {exc}"
        if stat.S_ISLNK(st.st_mode):
            return False, f"Rejected symlink/out-of-repo {label}: {rel_p}"
        if stat.S_ISDIR(st.st_mode) and not os.access(cur, os.R_OK | os.X_OK):
            return False, f"Unreadable {label} {rel_p}: directory is not readable/traversable ({cur})"
    return False, None


def _iter_display_files(
    repo_root: Path,
    frontend_subdir: str,
    disp: DisplayExtractionResult,
    coverage_notes: list[str] | None = None,
) -> list[tuple[str, Path, str | None]]:
    node_by_file = {n.source_file: n.id for n in disp.nodes}
    seen: set[str] = set()
    out: list[tuple[str, Path, str | None]] = []

    try:
        if repo_root.is_symlink():
            if coverage_notes is not None:
                coverage_notes.append(f"Rejected symlink repository root: {repo_root}")
            return out
        repo_res = repo_root.resolve(strict=True)
        if not repo_res.is_dir():
            if coverage_notes is not None:
                coverage_notes.append(f"Repository root {repo_root} is not a directory")
            return out
        _check_dir_accessible(repo_res)
    except OSError as exc:
        if coverage_notes is not None:
            coverage_notes.append(f"Unreadable repository root {repo_root}: {exc}")
        return out

    roots: list[Path] = []
    if frontend_subdir in ("", "."):
        roots.append(repo_res)
    else:
        sub_p = Path(frontend_subdir)
        if sub_p.is_absolute() or ".." in sub_p.parts or "\x00" in frontend_subdir:
            if coverage_notes is not None:
                coverage_notes.append(f"Rejected out-of-repo frontend_subdir: {frontend_subdir}")
        else:
            fe_safe = safe_resolve_contained_path(sub_p, repo_root)
            if fe_safe is not None:
                try:
                    fe_st = fe_safe.lstat()
                    if stat.S_ISLNK(fe_st.st_mode):
                        if coverage_notes is not None:
                            coverage_notes.append(f"Rejected symlink/out-of-repo frontend_subdir: {frontend_subdir}")
                    elif stat.S_ISDIR(fe_st.st_mode):
                        _check_dir_accessible(fe_safe)
                        roots.append(fe_safe)
                    elif coverage_notes is not None:
                        coverage_notes.append(f"Rejected non-directory frontend_subdir: {frontend_subdir}")
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    if coverage_notes is not None:
                        coverage_notes.append(f"Unreadable frontend_subdir {frontend_subdir}: {exc}")
            else:
                sub_absent, bad_reason = _inspect_contained_rel_path(repo_res, sub_p, "frontend_subdir")
                if bad_reason is not None:
                    if coverage_notes is not None:
                        coverage_notes.append(bad_reason)
                elif not sub_absent and coverage_notes is not None:
                    coverage_notes.append(f"Rejected symlink/out-of-repo frontend_subdir: {frontend_subdir}")

    for rel_f in node_by_file:
        rel_p = Path(rel_f)
        if rel_p.is_absolute() or ".." in rel_p.parts or "\x00" in rel_f:
            if coverage_notes is not None:
                coverage_notes.append(f"Rejected out-of-repo display node path: {rel_f}")
            continue
        safe_fp = safe_resolve_contained_path(rel_p, repo_root)
        if safe_fp is None:
            node_absent, bad_reason = _inspect_contained_rel_path(repo_res, rel_p, "display node path")
            if bad_reason is not None and coverage_notes is not None:
                coverage_notes.append(bad_reason)
            elif not node_absent and coverage_notes is not None:
                coverage_notes.append(f"Rejected symlink/out-of-repo display node path: {rel_f}")
            continue
        try:
            fp_st = safe_fp.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            if coverage_notes is not None:
                coverage_notes.append(f"Unreadable display node path {rel_f}: {exc}")
            continue
        if stat.S_ISLNK(fp_st.st_mode):
            if coverage_notes is not None:
                coverage_notes.append(f"Skipped symlink display file: {safe_fp}")
            continue
        if not stat.S_ISREG(fp_st.st_mode):
            if coverage_notes is not None:
                coverage_notes.append(f"Skipped non-regular display file: {safe_fp}")
            continue
        if rel_f not in seen:
            seen.add(rel_f)
            out.append((rel_f, safe_fp, node_by_file.get(rel_f)))

    for base in roots:
        def _on_walk_error(exc: OSError, *, _base: Path = base) -> None:
            if coverage_notes is not None:
                coverage_notes.append(f"Unreadable directory during display walk {exc.filename or _base}: {exc}")

        for root, dirs, files in os.walk(base, followlinks=False, onerror=_on_walk_error):
            kept_dirs: list[str] = []
            for d in sorted(dirs):
                if d in _SKIP_DIRS or d.startswith("."):
                    continue
                d_path = Path(root) / d
                try:
                    d_st = d_path.lstat()
                except OSError as exc:
                    if coverage_notes is not None:
                        coverage_notes.append(f"Unreadable directory {d_path}: {exc}")
                    continue
                if stat.S_ISLNK(d_st.st_mode):
                    if coverage_notes is not None:
                        coverage_notes.append(f"Skipped symlink directory: {d_path}")
                    continue
                if stat.S_ISDIR(d_st.st_mode):
                    if not os.access(d_path, os.R_OK | os.X_OK):
                        if coverage_notes is not None:
                            coverage_notes.append(f"Unreadable directory {d_path}")
                        continue
                    kept_dirs.append(d)
            dirs[:] = kept_dirs
            for fname in sorted(files):
                if not fname.endswith((".js", ".mjs", ".jsx", ".ts", ".tsx", ".html")):
                    continue
                if any(fname.endswith(suf) for suf in (".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.js", ".d.ts")) or fname == "api-generated.ts":
                    continue
                fpath = Path(root) / fname
                try:
                    f_st = fpath.lstat()
                except OSError as exc:
                    if coverage_notes is not None:
                        coverage_notes.append(f"Unreadable display file {fpath}: {exc}")
                    continue
                if stat.S_ISLNK(f_st.st_mode):
                    if coverage_notes is not None:
                        coverage_notes.append(f"Skipped symlink display file: {fpath}")
                    continue
                if not stat.S_ISREG(f_st.st_mode):
                    if coverage_notes is not None:
                        coverage_notes.append(f"Skipped non-regular display file: {fpath}")
                    continue
                safe_fp = safe_resolve_contained_path(fpath, repo_root)
                if safe_fp is None:
                    if coverage_notes is not None:
                        coverage_notes.append(f"Rejected out-of-repo display file: {fpath}")
                    continue
                rel = safe_fp.relative_to(repo_res).as_posix()
                if rel not in seen:
                    seen.add(rel)
                    out.append((rel, safe_fp, node_by_file.get(rel)))
    return out


def _build_js_scope_map(code: str) -> tuple[list[int], list[int], list[int], dict[int, int | None]]:
    """Build lexical `{...}` scope transitions for `code`, ignoring strings/template text/regex."""
    n = len(code)
    line_starts: list[int] = [0]
    for idx, ch in enumerate(code):
        if ch == "\n":
            line_starts.append(idx + 1)

    trans_pos: list[int] = [0]
    trans_sid: list[int] = [0]
    parent_scope: dict[int, int | None] = {0: None}
    scope_stack: list[int] = [0]
    next_sid = 0
    expr_floors: list[int] = [0]
    prev_sig_pos = -1

    # Mode stack: ("code",) | ("str", quote) | ("tpl",)
    # tpl_bdepth tracks `{` nesting inside `${...}` before returning to template literal text.
    tpl_bdepth: list[int] = []
    i = 0
    in_tpl = False
    while i < n:
        if in_tpl:
            ch = code[i]
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "$" and i + 1 < n and code[i + 1] == "{":
                tpl_bdepth.append(0)
                expr_floors.append(i + 2)
                in_tpl = False
                prev_sig_pos = i + 1
                i += 2
                continue
            if ch == "`":
                in_tpl = False
                prev_sig_pos = i
                i += 1
                continue
            i += 1
            continue

        ch = code[i]
        if ch in ("'", '"'):
            quote = ch
            i += 1
            while i < n:
                c = code[i]
                if c == "\\" and i + 1 < n:
                    i += 2
                    continue
                if c == quote or c == "\n":
                    if c == quote:
                        prev_sig_pos = i
                        i += 1
                    break
                i += 1
            continue
        if ch == "`":
            in_tpl = True
            i += 1
            continue
        if ch == "/" and _can_start_js_regex(code, prev_sig_pos, expr_floors[-1]):
            rend = _skip_js_regex(code, i, n)
            if rend is not None:
                prev_sig_pos = rend - 1
                i = rend
                continue
        if ch == "{":
            if tpl_bdepth:
                tpl_bdepth[-1] += 1
            next_sid += 1
            cur_sid = scope_stack[-1]
            parent_scope[next_sid] = cur_sid
            scope_stack.append(next_sid)
            trans_pos.append(i + 1)
            trans_sid.append(next_sid)
            expr_floors.append(i + 1)
            prev_sig_pos = i
            i += 1
            continue
        if ch == "}":
            if tpl_bdepth:
                if tpl_bdepth[-1] == 0:
                    tpl_bdepth.pop()
                    if len(expr_floors) > 1:
                        expr_floors.pop()
                    in_tpl = True
                    prev_sig_pos = i
                    i += 1
                    continue
                tpl_bdepth[-1] -= 1
            if len(scope_stack) > 1:
                scope_stack.pop()
                trans_pos.append(i + 1)
                trans_sid.append(scope_stack[-1])
                if len(expr_floors) > 1:
                    expr_floors.pop()
            prev_sig_pos = i
            i += 1
            continue
        if not ch.isspace():
            prev_sig_pos = i
        i += 1

    return line_starts, trans_pos, trans_sid, parent_scope


def _scope_at_offset(offset: int, trans_pos: list[int], trans_sid: list[int]) -> int:
    idx = bisect_right(trans_pos, offset) - 1
    return trans_sid[idx] if idx >= 0 else 0


_SHADOWED = object()
_NON_FN_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "with", "return", "throw", "await", "typeof", "delete", "void", "new"}
)
_DECL_KW_RE = re.compile(r"(?<![.\w$])(?:const|let|var)\b")
_CATCH_OPEN_RE = re.compile(r"(?<![.\w$])catch\s*\(")
_FN_HEAD_RE = re.compile(
    r"(?<![.\w$])function(?![\w$])(?:\s*\*)?(?:\s+[A-Za-z_$][\w$]*(?![\w$]))?(?:\s*<[^;{}()\n<>]*>)?\s*\("
    r"|(?<![.\w$])([A-Za-z_$][\w$]*)(?![\w$])[ \t]*=>\s*\{"
    r"|(?<![.\w$])([A-Za-z_$][\w$]*)(?![\w$])(?:\s*<[^;{}()\n<>]*>)?\s*\("
    r"|(?<![.\w$)])(?:<[^;{}()\n<>]*>\s*)?\("
)
_LONG_WS_RUN_RE = re.compile(r"\s{64,}")
_JS_IDENT_EXACT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_MAX_JS_DECL_DEPTH = 64


def _lookup_scoped(
    table: dict[tuple[int, str], object],
    scope_id: int,
    name: str,
    parent_scope: dict[int, int | None],
) -> tuple[bool, object]:
    cur: int | None = scope_id
    while cur is not None:
        key = (cur, name)
        if key in table:
            val = table[key]
            if val is _SHADOWED:
                return False, None
            return True, val
        cur = parent_scope.get(cur)
    return False, None


def _lookup_scoped_with_owner(
    table: dict[tuple[int, str], object],
    scope_id: int,
    name: str,
    parent_scope: dict[int, int | None],
) -> tuple[bool, int, object]:
    cur: int | None = scope_id
    while cur is not None:
        key = (cur, name)
        if key in table:
            val = table[key]
            if val is _SHADOWED:
                return False, 0, None
            return True, cur, val
        cur = parent_scope.get(cur)
    return False, 0, None


def _split_js_top_level(text: str, sep: str = ",") -> list[str]:
    if sep not in text:
        return [text]
    parts: list[str] = []
    start = 0
    paren = bracket = brace = angle = 0
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")" and paren > 0:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket > 0:
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}" and brace > 0:
            brace -= 1
        elif ch == "<":
            angle += 1
        elif ch == ">" and angle > 0 and not (i > 0 and text[i - 1] == "="):
            angle -= 1
        elif ch == sep and paren == 0 and bracket == 0 and brace == 0 and angle == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def _find_top_level_char(text: str, target: str) -> int:
    if target not in text:
        return -1
    paren = bracket = brace = angle = 0
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")" and paren > 0:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket > 0:
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}" and brace > 0:
            brace -= 1
        elif ch == "<":
            angle += 1
        elif ch == ">" and angle > 0 and not (i > 0 and text[i - 1] == "="):
            angle -= 1
        elif ch == target and paren == 0 and bracket == 0 and brace == 0 and angle == 0:
            if target == "=" and ((i + 1 < n and text[i + 1] in ("=", ">")) or (i > 0 and text[i - 1] in ("=", "!", "<", ">"))):
                i += 1
                continue
            return i
        i += 1
    return -1


def _extract_js_decl_names(raw_lhs: str) -> list[str]:
    names: list[str] = []
    stack: list[tuple[str, int]] = [(raw_lhs, 0)]
    scanned_chars = 0
    while stack:
        cur_raw, depth = stack.pop()
        if depth > _MAX_JS_DECL_DEPTH or scanned_chars > 65_536:
            continue
        lhs = cur_raw.strip().rstrip("!")
        if not lhs:
            continue
        if lhs.startswith("{") and lhs.endswith("}"):
            inner = lhs[1:-1]
            if "," in inner:
                scanned_chars += len(inner)
            sub_items: list[tuple[str, int]] = []
            for raw_item in _split_js_top_level(inner):
                item = raw_item.strip()
                if not item:
                    continue
                if item.startswith("..."):
                    sub_items.append((item[3:].strip(), depth + 1))
                    continue
                if "=" in item:
                    scanned_chars += len(item)
                    eq_idx = _find_top_level_char(item, "=")
                    if eq_idx != -1:
                        item = item[:eq_idx].strip()
                key_colon = re.match(r"^[A-Za-z_$][\w$]*\s*:", item)
                if key_colon is not None:
                    sub_items.append((item[key_colon.end() :].strip(), depth + 1))
                    continue
                if ":" in item:
                    scanned_chars += len(item)
                    col_idx = _find_top_level_char(item, ":")
                    if col_idx != -1:
                        sub_items.append((item[col_idx + 1 :].strip(), depth + 1))
                        continue
                if _JS_IDENT_EXACT_RE.fullmatch(item):
                    sub_items.append((item, depth + 1))
            stack.extend(reversed(sub_items))
            continue
        if lhs.startswith("[") and lhs.endswith("]"):
            inner = lhs[1:-1]
            if "," in inner:
                scanned_chars += len(inner)
            sub_items = []
            for raw_item in _split_js_top_level(inner):
                item = raw_item.strip()
                if not item:
                    continue
                if item.startswith("..."):
                    sub_items.append((item[3:].strip(), depth + 1))
                    continue
                if "=" in item:
                    scanned_chars += len(item)
                    eq_idx = _find_top_level_char(item, "=")
                    if eq_idx != -1:
                        item = item[:eq_idx].strip()
                sub_items.append((item, depth + 1))
            stack.extend(reversed(sub_items))
            continue
        if _JS_IDENT_EXACT_RE.fullmatch(lhs):
            names.append(lhs)
    return names


def _extract_js_param_names(raw_params: str) -> list[str]:
    names: list[str] = []
    for raw_item in _split_js_top_level(raw_params):
        item = raw_item.strip()
        if not item:
            continue
        if item.startswith("..."):
            item = item[3:].strip()
        while True:
            mod_m = re.match(r"^(?:public|private|protected|readonly)\s+", item)
            if not mod_m:
                break
            item = item[mod_m.end() :].strip()
        eq_idx = _find_top_level_char(item, "=")
        if eq_idx != -1:
            item = item[:eq_idx].strip()
        col_idx = _find_top_level_char(item, ":")
        if col_idx != -1:
            item = item[:col_idx].strip()
        item = item.rstrip("?").strip()
        names.extend(_extract_js_decl_names(item))
    return names


def _find_matching_pair(text: str, open_idx: int, open_ch: str, close_ch: str) -> int | None:
    depth = 1
    quote: str | None = None
    i = open_idx + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote or (quote in ("'", '"') and ch == "\n"):
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _non_ws_spans(code: str) -> list[tuple[int, int]]:
    n = len(code)
    if not code or code.isspace():
        return []
    spans: list[tuple[int, int]] = []
    cur = 0
    for m in _LONG_WS_RUN_RE.finditer(code):
        if m.start() > cur and not code[cur : m.start()].isspace():
            spans.append((cur, m.start()))
        cur = m.end()
    if cur < n and not code[cur:].isspace():
        spans.append((cur, n))
    return spans


def _precompute_paren_pairs(code: str, code_mask: list[bool]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    limit = min(len(code), len(code_mask))
    for idx in range(limit):
        if not code_mask[idx]:
            continue
        ch = code[idx]
        if ch == "(":
            stack.append(idx)
        elif ch == ")" and stack:
            pairs[stack.pop()] = idx
    return pairs


def _collect_js_shadow_decls(
    code: str,
    code_mask: list[bool],
    trans_pos: list[int],
    trans_sid: list[int],
    untyped_payload_fn_scopes: set[tuple[int, str]],
    *,
    is_untyped_js: bool,
) -> list[tuple[int, str]]:
    """Return `(scope_id, name)` pairs for JS/TS variable and parameter declarations."""
    spans = _non_ws_spans(code)
    if not spans:
        return []
    decls: list[tuple[int, str]] = []
    n = len(code)
    paren_pairs = _precompute_paren_pairs(code, code_mask)

    def _skip_ws(idx: int) -> int:
        while idx < n and code[idx].isspace():
            idx += 1
        return idx

    # 1. const / let / var declarations (including destructuring and `for (const ...)` headers)
    for c_start, c_end in spans:
        for m in _DECL_KW_RE.finditer(code, c_start, c_end):
            if m.start() >= len(code_mask) or not code_mask[m.start()]:
                continue
            # Skip `... as const`
            back = code[max(0, m.start() - 16) : m.start()].rstrip()
            if re.search(r"(?<![.\w$])as$", back):
                continue
            cur = _skip_ws(m.end())
            if cur >= n or not (code[cur] in ("{", "[") or code[cur].isalpha() or code[cur] in ("_", "$")):
                continue
            enclosing_sid = _scope_at_offset(m.start(), trans_pos, trans_sid)
            target_sid = enclosing_sid
            pre_ctx = code[max(0, m.start() - 32) : m.start()]
            for_m = re.search(r"(?<![.\w$])for(?:\s+await)?\s*\(\s*$", pre_ctx)
            if for_m is not None:
                for_open = code.rfind("(", max(0, m.start() - 32), m.start())
                if for_open != -1:
                    for_close = paren_pairs.get(for_open)
                    if for_close is None:
                        continue
                    after_for = _skip_ws(for_close + 1)
                    if after_for >= n or code[after_for] != "{":
                        continue
                    body_sid = _scope_at_offset(after_for + 1, trans_pos, trans_sid)
                    if body_sid <= enclosing_sid:
                        continue
                    target_sid = body_sid

            while cur < n:
                cur = _skip_ws(cur)
                if cur >= n:
                    break
                if code[cur] in ("{", "["):
                    close_ch = "}" if code[cur] == "{" else "]"
                    end_pat = _find_matching_pair(code, cur, code[cur], close_ch)
                    if end_pat is None:
                        break
                    for nm in _extract_js_decl_names(code[cur : end_pat + 1]):
                        decls.append((target_sid, nm))
                    cur = end_pat + 1
                else:
                    id_m = re.match(r"[A-Za-z_$][\w$]*", code[cur:])
                    if id_m is None:
                        break
                    decls.append((target_sid, id_m.group(0)))
                    cur += id_m.end()
                # Advance past optional `: Type` and `= init` to check for `,` or `;`
                paren = bracket = brace = 0
                quote: str | None = None
                has_comma = False
                while cur < n:
                    ch = code[cur]
                    if quote is not None:
                        if ch == "\\" and cur + 1 < n:
                            cur += 2
                            continue
                        if ch == quote or (quote in ("'", '"') and ch == "\n"):
                            quote = None
                        cur += 1
                        continue
                    if ch in ("'", '"', "`"):
                        quote = ch
                    elif ch == "(":
                        paren += 1
                    elif ch == ")" and paren > 0:
                        paren -= 1
                    elif ch == "[":
                        bracket += 1
                    elif ch == "]" and bracket > 0:
                        bracket -= 1
                    elif ch == "{":
                        brace += 1
                    elif ch == "}" and brace > 0:
                        brace -= 1
                    elif paren == 0 and bracket == 0 and brace == 0:
                        if ch == ",":
                            cur += 1
                            has_comma = True
                            break
                        if ch in (";", ")") or (ch == "\n" and not code[cur + 1 :].lstrip().startswith(("=", "?", ":", ".", "+"))):
                            break
                    cur += 1
                if not has_comma:
                    break

        # 2. catch (err) { ... }
        for cm in _CATCH_OPEN_RE.finditer(code, c_start, c_end):
            if cm.start() >= len(code_mask) or not code_mask[cm.start()]:
                continue
            open_p = cm.end() - 1
            close_p = paren_pairs.get(open_p)
            if close_p is None:
                continue
            after = _skip_ws(close_p + 1)
            if after < n and code[after] == "{":
                enclosing_sid = _scope_at_offset(cm.start(), trans_pos, trans_sid)
                body_sid = _scope_at_offset(after + 1, trans_pos, trans_sid)
                if body_sid > enclosing_sid:
                    for pn in _extract_js_param_names(code[open_p + 1 : close_p]):
                        decls.append((body_sid, pn))

        # 3. function / arrow / method parameters
        for fm in _FN_HEAD_RE.finditer(code, c_start, c_end):
            if fm.start() >= len(code_mask) or not code_mask[fm.start()]:
                continue
            enclosing_sid = _scope_at_offset(fm.start(), trans_pos, trans_sid)
            arrow_ident = fm.group(1)
            if arrow_ident is not None:
                brace_pos = fm.end() - 1
                body_sid = _scope_at_offset(brace_pos + 1, trans_pos, trans_sid)
                if body_sid > enclosing_sid and not (
                    is_untyped_js and (body_sid, arrow_ident) in untyped_payload_fn_scopes
                ):
                    decls.append((body_sid, arrow_ident))
                continue

            method_ident = fm.group(2)
            open_p = fm.end() - 1
            close_p = paren_pairs.get(open_p)
            if close_p is None:
                continue
            cursor = _skip_ws(close_p + 1)
            is_arrow = False
            if cursor < n and code[cursor] == ":":
                cursor += 1
                max_ret_end = min(n, cursor + 256)
                ang = par = brk = brc = 0
                while cursor < max_ret_end:
                    if not code_mask[cursor]:
                        cursor += 1
                        continue
                    ch = code[cursor]
                    if ch == ";" and par == 0 and brk == 0 and brc == 0:
                        break
                    if ch == "<":
                        ang += 1
                    elif ch == ">" and ang > 0 and not (cursor > 0 and code[cursor - 1] == "="):
                        ang -= 1
                    elif ch == "(":
                        par += 1
                    elif ch == ")":
                        if par == 0 and brk == 0 and brc == 0:
                            break
                        if par > 0:
                            par -= 1
                    elif ch == "[":
                        brk += 1
                    elif ch == "]" and brk > 0:
                        brk -= 1
                    elif ch == "{":
                        if ang == 0 and par == 0 and brk == 0 and brc == 0:
                            break
                        brc += 1
                    elif ch == "}":
                        if brc == 0 and par == 0 and brk == 0:
                            break
                        if brc > 0:
                            brc -= 1
                    elif ang == 0 and par == 0 and brk == 0 and brc == 0:
                        if code.startswith("=>", cursor):
                            is_arrow = True
                            break
                        if ch in (",", "\n"):
                            break
                    cursor += 1
            if code.startswith("=>", cursor):
                is_arrow = True
                cursor = _skip_ws(cursor + 2)
            if method_ident in _NON_FN_KEYWORDS and not is_arrow:
                continue
            if cursor >= n or code[cursor] != "{":
                continue
            is_function_kw = code.startswith("function", fm.start())
            if not is_arrow and not is_function_kw and not method_ident:
                continue
            body_sid = _scope_at_offset(cursor + 1, trans_pos, trans_sid)
            if body_sid <= enclosing_sid:
                continue
            for pn in _extract_js_param_names(code[open_p + 1 : close_p]):
                if is_untyped_js and (body_sid, pn) in untyped_payload_fn_scopes:
                    continue
                decls.append((body_sid, pn))

    return decls


def _extract_script_text(raw: str, is_html: bool) -> str:
    if not is_html:
        return strip_js_comments_keep_lines(raw)
    # Keep exact 1-based line numbers outside `<script>` blocks by replacing non-script text with spaces/newlines
    buf = ["\n" if c == "\n" else " " for c in raw]
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", raw, flags=re.IGNORECASE | re.DOTALL):
        cleaned = strip_js_comments_keep_lines(m.group(1))
        start = m.start(1)
        for idx, ch in enumerate(cleaned):
            buf[start + idx] = ch
    return "".join(buf)


_JSX_TAG_NAME_RE = re.compile(r"[A-Za-z_$][\w.:$-]*")
_JSX_OPEN_PREV_CHARS = frozenset("({[,;=!&|?+~^*%-<>:}")
_JSX_OPEN_PREV_KEYWORDS = frozenset(
    {"return", "yield", "throw", "await", "case", "else", "do", "void"}
)


def _build_jsx_comparison_safe_code(code: str, code_mask: list[bool]) -> tuple[str, str]:
    """Return `(code_only, cmp_safe_code)` with non-code and JSX/arrow/generic `<`/`>` blanked."""
    n = len(code)
    mask_len = len(code_mask)
    code_chars = [
        code[idx] if (idx < mask_len and code_mask[idx]) or code[idx] == "\n" else " "
        for idx in range(n)
    ]
    code_only = "".join(code_chars)
    cmp_chars = list(code_chars)
    jsx_gt_indices: set[int] = set()
    prev_sig = -1
    i = 0
    while i < n:
        ch = code_only[i]
        if ch.isspace():
            i += 1
            continue
        if i in jsx_gt_indices:
            cmp_chars[i] = " "
            prev_sig = i
            i += 1
            continue
        if code_only.startswith("=>", i) or code_only.startswith("/>", i):
            cmp_chars[i] = " "
            cmp_chars[i + 1] = " "
            if code_only.startswith("/>", i):
                jsx_gt_indices.add(i + 1)
            prev_sig = i + 1
            i += 2
            continue
        if ch == "<":
            if code_only.startswith("</", i):
                end_gt = i + 2
                while end_gt < n and code_only[end_gt] not in (">", "<", "{", ";"):
                    end_gt += 1
                if end_gt < n and code_only[end_gt] == ">":
                    for k in range(i, end_gt + 1):
                        if cmp_chars[k] != "\n":
                            cmp_chars[k] = " "
                    jsx_gt_indices.add(end_gt)
                    prev_sig = end_gt
                    i = end_gt + 1
                    continue
            if code_only.startswith("<>", i):
                cmp_chars[i] = " "
                cmp_chars[i + 1] = " "
                jsx_gt_indices.add(i + 1)
                prev_sig = i + 1
                i += 2
                continue
            tag_m = _JSX_TAG_NAME_RE.match(code_only, i + 1)
            if tag_m is not None:
                is_jsx_pos = prev_sig < 0 or prev_sig in jsx_gt_indices
                if not is_jsx_pos:
                    prev_ch = code_only[prev_sig]
                    if prev_ch in _JSX_OPEN_PREV_CHARS:
                        is_jsx_pos = True
                    elif prev_ch.isalnum() or prev_ch in ("_", "$"):
                        w = prev_sig
                        while w >= 0 and (code_only[w].isalnum() or code_only[w] in ("_", "$")):
                            w -= 1
                        is_jsx_pos = code_only[w + 1 : prev_sig + 1] in _JSX_OPEN_PREV_KEYWORDS
                if is_jsx_pos:
                    open_end = scan_open_tag_end(code, tag_m.end())
                    if open_end is not None and open_end <= n:
                        for k in range(i, tag_m.end()):
                            if cmp_chars[k] != "\n":
                                cmp_chars[k] = " "
                        cmp_chars[open_end - 1] = " "
                        if open_end >= 2 and code_only[open_end - 2] == "/":
                            cmp_chars[open_end - 2] = " "
                        jsx_gt_indices.add(open_end - 1)
                        prev_sig = tag_m.end() - 1
                        i = tag_m.end()
                        continue
                elif prev_sig >= 0 and (code_only[prev_sig].isalnum() or code_only[prev_sig] in ("_", "$")):
                    gen_end = scan_open_tag_end(code, i + 1)
                    if gen_end is not None and gen_end <= n:
                        after_gen = gen_end
                        while after_gen < n and code_only[after_gen].isspace():
                            after_gen += 1
                        if after_gen < n and code_only[after_gen] == "(":
                            cmp_chars[i] = " "
                            cmp_chars[gen_end - 1] = " "
        prev_sig = i
        i += 1
    return code_only, "".join(cmp_chars)


def _normalize_call_route(method_name: str, raw_arg: str) -> str | None:
    cleaned = re.sub(r"^\$\{[^}]+\}", "", raw_arg.strip())
    if method_name in ("fetchSlice", "getSlice", "loadSlice"):
        slug = cleaned.strip("/")
        return f"slice:{slug}" if slug and "{" not in slug else None
    if cleaned.startswith("/"):
        verb = "POST" if method_name == "post" else "GET"
        norm = cleaned.split("?", 1)[0].rstrip("/") or "/"
        if verb == "GET" and "/api/v1/slices/" in norm and "${" not in norm:
            return f"slice:{norm.split('/api/v1/slices/', 1)[1].strip('/')}"
        if "${" not in norm:
            return f"{verb} {norm}"
    return None


def analyze_display_confabulation_and_reads(
    repo_root: Path,
    frontend_subdir: str,
    disp: DisplayExtractionResult,
    known_slice_slugs: frozenset[str] = frozenset(),
    *,
    strict: bool = False,
    trusted_allowlist: frozenset[str] | set[str] | None = None,
    coverage_notes: list[str] | None = None,
) -> tuple[list[RawCandidateFinding], list[DisplayCallReadSet]]:
    """Evaluate `#119` (`DISP-009`, `DISP-010`), `#121` (`DISP-014`), & `#120` read sets."""
    findings: list[RawCandidateFinding] = []
    read_sets: list[DisplayCallReadSet] = []
    if strict:
        allowlist: set[str] = set()
    elif trusted_allowlist is not None:
        allowlist = {
            entry.strip().lstrip("./")
            for entry in trusted_allowlist
            if isinstance(entry, str) and entry.strip()
        }
    else:
        allowlist = set()
    files = _iter_display_files(repo_root, frontend_subdir, disp, coverage_notes=coverage_notes)
    known_files = {rel for rel, _, _ in files}

    for rel, fpath, node_id in files:
        try:
            raw_text = safe_read_repo_text(
                fpath, repo_root, max_bytes=MAX_FRONTEND_FILE_BYTES, encoding="utf-8"
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            if coverage_notes is not None:
                coverage_notes.append(f"Unreadable display file {rel}: {exc}")
            continue
        is_untyped_js = rel.endswith((".js", ".mjs", ".jsx", ".html"))
        file_allowlisted = rel in allowlist
        code = _extract_script_text(raw_text, is_html=rel.endswith(".html"))
        if not code or code.isspace():
            continue
        code_mask = js_code_mask(code)
        code_only, cmp_safe_code = _build_jsx_comparison_safe_code(code, code_mask)
        lines = code.splitlines()
        code_only_lines = code_only.splitlines()
        line_starts, trans_pos, trans_sid, parent_scope = _build_js_scope_map(code)

        # Check live imports into allowlisted demo/fixture modules (#119)
        if not file_allowlisted and allowlist:
            base_dir = Path(rel).parent
            for lno, ln in enumerate(lines, start=1):
                if not ln or ln.isspace():
                    continue
                ln_off = line_starts[lno - 1] if lno - 1 < len(line_starts) else 0
                for imp_m in _JS_IMPORT_RE.finditer(ln):
                    imp_pos = ln_off + imp_m.start()
                    if imp_pos >= len(code_mask) or not code_mask[imp_pos]:
                        continue
                    spec = imp_m.group(1)
                    if not spec.startswith("."):
                        continue
                    cand_base = os.path.normpath((base_dir / spec).as_posix())
                    for ext in ("", ".js", ".mjs", ".ts", ".tsx", ".jsx"):
                        target_rel = f"{cand_base}{ext}"
                        if target_rel in known_files and target_rel in allowlist:
                            findings.append(
                                RawCandidateFinding(
                                    rule_code="DISP-010",
                                    node_id=node_id,
                                    source_file=rel,
                                    line=lno,
                                    title=f"Live display module imports allowlisted fixture/demo `{target_rel}`",
                                    detail=f"{rel}:{lno} imports `{target_rel}`, which is allowlisted as a demo/fixture module and must remain unreachable in live mode.",
                                    remediation="Remove the live import of the demo/fixture module or gate fixture loading behind an isolated offline test harness.",
                                )
                            )

        # Resolve fetched payload variables & route bindings (per lexical scope)
        raw_fetch_vars: dict[tuple[int, str], object] = {}
        payload_roots: dict[tuple[int, str], object] = {}
        call_lines: dict[tuple[int, str], int] = {}
        bound_in_scope: set[tuple[int, str]] = set()
        untyped_payload_fn_scopes: set[tuple[int, str]] = set()

        for lno, ln in enumerate(lines, start=1):
            ln_off = line_starts[lno - 1] if lno - 1 < len(line_starts) else 0
            for fm in _FETCH_BIND_RE.finditer(ln):
                pos = ln_off + fm.start()
                if pos < len(code_mask) and not code_mask[pos]:
                    continue
                sid = _scope_at_offset(pos, trans_pos, trans_sid)
                var_name, fn_name, _, arg_val = fm.groups()
                rk = _normalize_call_route(fn_name, arg_val)
                bound_in_scope.add((sid, var_name))
                if fn_name == "fetch" and ".json(" not in ln:
                    raw_fetch_vars[(sid, var_name)] = (rk or "", lno)
                else:
                    payload_roots[(sid, var_name)] = rk
                    if rk:
                        call_lines[(sid, var_name)] = lno
            for jm in _JSON_UNWRAP_RE.finditer(ln):
                pos = ln_off + jm.start()
                if pos < len(code_mask) and not code_mask[pos]:
                    continue
                sid = _scope_at_offset(pos, trans_pos, trans_sid)
                dest_var, resp_var = jm.groups()
                found_rf, rf_val = _lookup_scoped(raw_fetch_vars, sid, resp_var, parent_scope)
                rk, c_line = rf_val if found_rf and isinstance(rf_val, tuple) else ("", lno)
                bound_in_scope.add((sid, dest_var))
                payload_roots[(sid, dest_var)] = rk or None
                if rk:
                    call_lines[(sid, dest_var)] = c_line
            if is_untyped_js:
                for pm in _UNTYPED_FN_PARAM_RE.finditer(ln):
                    pos = ln_off + pm.start()
                    if pos < len(code_mask) and not code_mask[pos]:
                        continue
                    pname = pm.group(1)
                    if pname not in (
                        "data",
                        "payload",
                        "raw",
                        "slice",
                        "snapshot",
                        "resp",
                        "summary",
                        "serverJson",
                        "state",
                    ):
                        continue
                    search_from = ln_off + pm.end()
                    brace_idx = code.find("{", search_from, min(len(code), search_from + 240))
                    target_sid = (
                        _scope_at_offset(brace_idx + 1, trans_pos, trans_sid)
                        if brace_idx != -1
                        else _scope_at_offset(pos, trans_pos, trans_sid)
                    )
                    untyped_payload_fn_scopes.add((target_sid, pname))
                    if not _lookup_scoped(payload_roots, target_sid, pname, parent_scope)[0]:
                        inherited_rk: str | None = None
                        cur_anc: int | None = target_sid
                        while cur_anc is not None and inherited_rk is None:
                            for (psid, _), prk in payload_roots.items():
                                if psid == cur_anc and isinstance(prk, str) and prk:
                                    inherited_rk = prk
                                    break
                            cur_anc = parent_scope.get(cur_anc)
                        bound_in_scope.add((target_sid, pname))
                        payload_roots[(target_sid, pname)] = inherited_rk

        for sh_sid, sh_name in _collect_js_shadow_decls(
            code,
            code_mask,
            trans_pos,
            trans_sid,
            untyped_payload_fn_scopes,
            is_untyped_js=is_untyped_js,
        ):
            if (sh_sid, sh_name) not in bound_in_scope:
                payload_roots.setdefault((sh_sid, sh_name), _SHADOWED)
                raw_fetch_vars.setdefault((sh_sid, sh_name), _SHADOWED)

        alias_prefix: dict[tuple[int, str], object] = {
            (sh_sid, sh_name): _SHADOWED
            for (sh_sid, sh_name), val in payload_roots.items()
            if val is _SHADOWED
        }
        for _pass in range(3):
            for lno, ln in enumerate(lines, start=1):
                ln_off = line_starts[lno - 1] if lno - 1 < len(line_starts) else 0
                for am in _ALIAS_SUBPATH_RE.finditer(ln):
                    pos = ln_off + am.start()
                    if pos < len(code_mask) and not code_mask[pos]:
                        continue
                    sid = _scope_at_offset(pos, trans_pos, trans_sid)
                    alias_var, rhs_chain = am.groups()
                    c_parts = [p for p in re.split(r"\??\.", rhs_chain) if p]
                    if len(c_parts) < 2 or c_parts[1] in _PROTOTYPE_METHODS:
                        continue
                    base_var, rest_p = c_parts[0], c_parts[1:]
                    found_pr, owner_sid, rk_b_obj = _lookup_scoped_with_owner(
                        payload_roots, sid, base_var, parent_scope
                    )
                    if found_pr:
                        rk_b = rk_b_obj if isinstance(rk_b_obj, str) else None
                        if rk_b is None and rest_p[0] in known_slice_slugs:
                            slice_rk = f"slice:{rest_p[0]}"
                            if len(rest_p) == 1:
                                payload_roots[(sid, alias_var)] = slice_rk
                                call_lines.setdefault((sid, alias_var), lno)
                            else:
                                alias_prefix[(sid, alias_var)] = (".".join(rest_p[1:]), slice_rk, sid)
                        else:
                            alias_prefix[(sid, alias_var)] = (".".join(rest_p), rk_b, owner_sid)
                    else:
                        found_ap, ap_val = _lookup_scoped(alias_prefix, sid, base_var, parent_scope)
                        if found_ap and isinstance(ap_val, tuple):
                            prev_pref, prev_rk, prev_owner = ap_val
                            alias_prefix[(sid, alias_var)] = (
                                f"{prev_pref}.{'.'.join(rest_p)}",
                                prev_rk,
                                prev_owner,
                            )

        # Collect #120 property read sets for resolved route/slice bindings
        reads_by_route: dict[tuple[int, str], DisplayCallReadSet] = {}
        for (owner_sid, var_name), rk in payload_roots.items():
            if isinstance(rk, str) and rk and (owner_sid, rk) not in reads_by_route:
                reads_by_route[(owner_sid, rk)] = DisplayCallReadSet(
                    route_key=rk,
                    source_file=rel,
                    call_line=call_lines.get((owner_sid, var_name), 1),
                    node_id=node_id,
                )
        for (alias_sid, alias_var), ap_entry in alias_prefix.items():
            if not isinstance(ap_entry, tuple):
                continue
            _, rk, owner_sid = ap_entry
            if isinstance(rk, str) and rk and (owner_sid, rk) not in reads_by_route:
                reads_by_route[(owner_sid, rk)] = DisplayCallReadSet(
                    route_key=rk,
                    source_file=rel,
                    call_line=call_lines.get((alias_sid, alias_var), 1),
                    node_id=node_id,
                )

        reads_valid_until_line: int | None = None
        reads_evidence_state_line: int | None = None
        compares_valid_until = bool(
            re.search(
                r"\bvalid_until\b[\s\S]{0,160}(?:Date\.parse|new\s+Date|Date\.now\s*\(|[<>]=?|\bisStale\b|\bisExpired\b)"
                r"|(?:Date\.parse|new\s+Date|Date\.now\s*\(|[<>]=?)[\s\S]{0,160}\bvalid_until\b",
                cmp_safe_code,
            )
        )
        branches_evidence_state = bool(
            re.search(
                r"\bevidence_state\s*(?:===|!==|==|!=|\bin\b)|"
                r"(?:===|!==|==|!=)\s*[A-Za-z_$][\w$.?]*\bevidence_state\b",
                code_only,
            )
            or any(
                m_es.start() + 1 < len(code_mask) and not code_mask[m_es.start() + 1]
                for m_es in re.finditer(r"""['"`](?:source_error|could_not_measure)['"`]""", code)
            )
        )

        for lno, ln in enumerate(lines, start=1):
            if not ln or ln.isspace():
                continue
            ln_off = line_starts[lno - 1] if lno - 1 < len(line_starts) else 0
            ln_code = code_only_lines[lno - 1] if lno - 1 < len(code_only_lines) else ""
            for pm in _PROP_ACCESS_RE.finditer(ln):
                pm_start = ln_off + pm.start()
                pm_end = ln_off + pm.end()
                if pm_end > len(code_mask) or not all(code_mask[k] for k in range(pm_start, pm_end)):
                    continue
                full = pm.group(0)
                parts = [p for p in re.split(r"\??\.", full) if p]
                if len(parts) < 2:
                    continue
                root_v, rest = parts[0], parts[1:]
                if rest[0] in _PROTOTYPE_METHODS:
                    continue
                sid = _scope_at_offset(pm_start, trans_pos, trans_sid)
                rk_hit: str | None = None
                owner_sid = 0
                rel_parts: list[str] = []
                found_pr, pr_owner, pr_rk = _lookup_scoped_with_owner(
                    payload_roots, sid, root_v, parent_scope
                )
                if found_pr:
                    rk_hit = pr_rk if isinstance(pr_rk, str) else None
                    owner_sid = pr_owner
                    rel_parts = rest
                else:
                    found_ap, ap_val = _lookup_scoped(alias_prefix, sid, root_v, parent_scope)
                    if found_ap and isinstance(ap_val, tuple):
                        pref, ap_rk, ap_owner = ap_val
                        rk_hit = ap_rk if isinstance(ap_rk, str) else None
                        owner_sid = ap_owner
                        rel_parts = [pref, *rest]
                    else:
                        continue

                leaf = rel_parts[-1]
                if leaf == "valid_until" and reads_valid_until_line is None:
                    reads_valid_until_line = lno
                if leaf == "evidence_state" and reads_evidence_state_line is None:
                    reads_evidence_state_line = lno

                if rk_hit and (owner_sid, rk_hit) in reads_by_route:
                    rs = reads_by_route[(owner_sid, rk_hit)]
                    top_p = rel_parts[0]
                    rs.read_paths.setdefault(top_p, lno)
                    if len(rel_parts) >= 2 and rel_parts[1] not in _PROTOTYPE_METHODS:
                        sub_p = f"{rel_parts[0]}.{rel_parts[1]}"
                        rs.read_paths.setdefault(sub_p, lno)
                        if _STATUS_COUNT_ACTION_LEAF_RE.search(rel_parts[1]) or _ACTION_PROP_RE.search(ln_code):
                            rs.action_or_status_paths.add(sub_p)
                    if _STATUS_COUNT_ACTION_LEAF_RE.search(top_p) or _ACTION_PROP_RE.search(ln_code):
                        rs.action_or_status_paths.add(top_p)

            if file_allowlisted or f"{rel}:{lno}" in allowlist:
                continue

            # #119: Check `?? <literal>` and `|| <literal>` on fetched payload roots
            for fbm in _FALLBACK_EXPR_RE.finditer(ln):
                lhs_start, lhs_end = ln_off + fbm.start(1), ln_off + fbm.end(1)
                op_start, op_end = ln_off + fbm.start(2), ln_off + fbm.end(2)
                if op_end > len(code_mask) or not (
                    all(code_mask[k] for k in range(lhs_start, lhs_end))
                    and all(code_mask[k] for k in range(op_start, op_end))
                ):
                    continue
                lhs, op, rhs = fbm.groups()
                if rhs[0] not in ("'", '"'):
                    rhs_start, rhs_end = ln_off + fbm.start(3), ln_off + fbm.end(3)
                    if rhs_end > len(code_mask) or not all(code_mask[k] for k in range(rhs_start, rhs_end)):
                        continue
                parts = [p for p in re.split(r"\??\.", lhs) if p]
                root_v, leaf = parts[0], parts[-1]
                sid = _scope_at_offset(lhs_start, trans_pos, trans_sid)
                if (
                    not _lookup_scoped(payload_roots, sid, root_v, parent_scope)[0]
                    and not _lookup_scoped(alias_prefix, sid, root_v, parent_scope)[0]
                ):
                    continue
                if leaf in ("length", "size") or leaf.lower() in _LAYOUT_NUMERIC_PROPS:
                    continue

                flagged_reason: str | None = None
                if rhs[0] in ("'", '"'):
                    str_val = rhs[1:-1].strip()
                    if _ISO_DATE_RE.match(str_val):
                        flagged_reason = f"hard-coded ISO date `{rhs}`"
                    elif str_val.lower() not in _SENTINEL_STRINGS and leaf.lower() not in _UI_TOKEN_PROPS:
                        flagged_reason = f"non-sentinel string literal `{rhs}`"
                else:
                    num_val = float(rhs)
                    if num_val != 0.0:
                        flagged_reason = f"non-zero numeric literal `{rhs}`"
                    elif _COUNT_SCORE_RE.search(leaf):
                        # Exclude boolean comparison guards `(x ?? 0) > 0` / `=== 0`
                        after = ln_code[fbm.end() :].lstrip()
                        if not re.match(r"^\)\s*(?:[<>!=]=?)", after) and "queryKey" not in ln_code:
                            flagged_reason = f"`0` on count/metric `{leaf}` (turns missing measurement into all-clear)"

                if flagged_reason:
                    window_code = "\n".join(
                        code_only_lines[max(0, lno - 2) : min(len(code_only_lines), lno + 3)]
                    )
                    feeds_action = bool(
                        _ACTION_PROP_RE.search(window_code) or _EMPTY_BRANCH_SYNTH_RE.search(window_code)
                    )
                    rcode = "DISP-010" if feeds_action else "DISP-009"
                    findings.append(
                        RawCandidateFinding(
                            rule_code=rcode,
                            node_id=node_id,
                            source_file=rel,
                            line=lno,
                            title=f"Display fallback `{lhs} {op} {rhs}` fabricates missing payload data",
                            detail=f"{rel}:{lno} substitutes {flagged_reason} when `{lhs}` is absent from the fetched payload.",
                            remediation="Render an explicit sentinel (`null`, `'—'`, `'unmeasured'`) or branch on payload presence instead of fabricating a literal value.",
                        )
                    )

            # #119: Empty-list / missing-count `if (...)` branch synthesizing literal object items (`DISP-010`)
            if_m = re.search(r"\bif\s*\(", ln_code)
            if if_m and _EMPTY_BRANCH_SYNTH_RE.search(ln_code):
                sid = _scope_at_offset(ln_off + if_m.start(), trans_pos, trans_sid)
                cond_roots = {
                    m.group(1) for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*(?:\?\.|\.)", ln_code)
                }
                if any(
                    _lookup_scoped(payload_roots, sid, cr, parent_scope)[0]
                    or _lookup_scoped(alias_prefix, sid, cr, parent_scope)[0]
                    for cr in cond_roots
                ):
                    ahead = "\n".join(lines[lno - 1 : min(len(lines), lno + 10)])
                    ahead_base = ln_off
                    synth_m = re.search(
                        r"(?:\.push\s*\(\s*\{|return\s*\[\s*\{|=\s*\[\s*\{)[^}]*"
                        r"(?:id|title|headline|href|action)\s*:\s*['\"]",
                        ahead,
                        re.DOTALL,
                    )
                    if synth_m and ahead_base + synth_m.start() < len(code_mask) and code_mask[ahead_base + synth_m.start()]:
                        findings.append(
                            RawCandidateFinding(
                                rule_code="DISP-010",
                                node_id=node_id,
                                source_file=rel,
                                line=lno,
                                title="Display synthesizes a literal item when live payload list is empty",
                                detail=f"{rel}:{lno} constructs and renders a literal object item on an empty-list or fallback-count branch.",
                                remediation="Render an empty/unmeasured state when the live list is empty; never synthesize actionable or decision cards from literals.",
                            )
                        )

        # #121: `valid_until` read without clock comparison / `evidence_state` stored without branching
        if reads_valid_until_line is not None and not compares_valid_until:
            findings.append(
                RawCandidateFinding(
                    rule_code="DISP-014",
                    node_id=node_id,
                    source_file=rel,
                    line=reads_valid_until_line,
                    title="Display reads `valid_until` without comparing it against a clock",
                    detail=f"{rel}:{reads_valid_until_line} reads `valid_until` from a payload without evaluating expiry on any path to rendering.",
                    remediation="Compare `Date.parse(payload.valid_until)` against the reference clock and render an explicit stale badge after expiry.",
                )
            )
        if reads_evidence_state_line is not None and not branches_evidence_state:
            findings.append(
                RawCandidateFinding(
                    rule_code="DISP-014",
                    node_id=node_id,
                    source_file=rel,
                    line=reads_evidence_state_line,
                    title="Display reads `evidence_state` without branching on degraded/error states",
                    detail=f"{rel}:{reads_evidence_state_line} accesses `evidence_state` without branching on `source_error` / `could_not_measure` or degraded values.",
                    remediation="Branch on `evidence_state` before rendering an HTTP 200 payload as a healthy measurement.",
                )
            )

        read_sets.extend(reads_by_route.values())

    return findings, read_sets
