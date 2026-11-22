"""Shared frontend display extraction utilities for React SPA, Vue/Nuxt, and SvelteKit."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from app.adapters.a11y_inspect import (
    _can_start_js_regex,
    _skip_js_regex,
    is_js_module_stmt_in_code,
    js_code_mask,
    make_local_component_resolver,
)
from app.adapters.a11y_inspect import (
    scan_a11y_markup_findings as _raw_scan_a11y_markup_findings,
)
from app.adapters.base import FrontendHttpCall, RawCandidateFinding
from app.adapters.ts_reachability import _SKIP_DIRS as _REACH_SKIP_DIRS
from app.adapters.ts_reachability import GRAPH_SUFFIXES
from app.adapters.ts_workspace import (
    TsConfigPaths,
    WorkspaceResolver,
    load_tsconfig_paths,
    probe_ts_candidate,
    safe_read_repo_text,
    safe_resolve_contained_path,
)
from app.adapters.typescript_nextjs import (
    _CLOCK_UTIL_FILES,
    _IMPORT_RE,
    _RAW_NEW_DATE_RE,
    _TS_POLICY_CONST_RE,
    _UI_SAFE_TOKENS,
    _UTC_SLICE_RE,
    _build_scoped_url_consts,
    _extract_ts_http_calls,
    _fetch_method_from_call_tail,
    _is_raw_clock_read,
    _normalize_ts_url,
    _strip_ts_comments,
    has_generated_contract_provenance,
)
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasNode

_SFC_SCRIPT_RE = re.compile(r"<script\b[^>]*>(?P<body>[\s\S]*?)</script>", re.IGNORECASE)
_HTML_SCRIPT_TAG_RE = re.compile(r"<script\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_HTML_SCRIPT_SRC_ATTR_RE = re.compile(r"""\bsrc\s*=\s*(?:'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")""", re.IGNORECASE)
_HTML_SCRIPT_TYPE_ATTR_RE = re.compile(r"""\btype\s*=\s*(?:'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")""", re.IGNORECASE)
_HTML_COMMENT_OR_EMBED_RE = re.compile(
    r"<!--[\s\S]*?(?:-->|$)|<(?P<etag>script|style)\b[^>]*>[\s\S]*?(?:</(?P=etag)\s*>|$)",
    re.IGNORECASE,
)
_HTML_BASE_TAG_RE = re.compile(
    r"""<base\b[^>]*\bhref\s*=\s*(?:'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")""", re.IGNORECASE
)
_HTML_META_TAG_RE = re.compile(r"<meta\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_HTML_META_NAME_RE = re.compile(r"""\bname\s*=\s*(?:'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")""", re.IGNORECASE)
_HTML_META_CONTENT_RE = re.compile(r"""\bcontent\s*=\s*(?:'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")""", re.IGNORECASE)
_HTML_MARKUP_TEMPLATE_RE = re.compile(
    r"<(?:img|button|input|select|textarea|div|span)\b[^>]*>", re.IGNORECASE
)
_JS_TAG_CHECK_RE = re.compile(r"<(?:img|button|input|select|textarea|div|span)\b", re.IGNORECASE)
_VUE_SFC_FETCH_RE = re.compile(
    r"""(?<![.\w$])(?:\$fetch|useFetch|useLazyFetch)\b\s*(?:<[^;()\n]{0,180}>)?\s*\(\s*(?P<quote>['"`])"""
)


def _extract_vue_sfc_fetch_calls(cleaned_txt: str) -> list[tuple[str, str, int]]:
    """Extract `(verb, url, lineno)` for Vue/Nuxt `$fetch`/`useFetch`/`useLazyFetch` calls."""
    if not any(tok in cleaned_txt for tok in ("$fetch", "useFetch", "useLazyFetch")):
        return []
    mask = js_code_mask(cleaned_txt)
    n = len(cleaned_txt)
    calls: list[tuple[str, str, int]] = []
    for vm in _VUE_SFC_FETCH_RE.finditer(cleaned_txt):
        if vm.start() >= len(mask) or not mask[vm.start()]:
            continue
        quote = vm.group("quote")
        i = vm.end()
        buf: list[str] = []
        closed = False
        if quote != "`":
            while i < n and cleaned_txt[i] not in ("\n", "\r"):
                ch = cleaned_txt[i]
                if ch == "\\" and i + 1 < n:
                    buf.append(ch)
                    buf.append(cleaned_txt[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    closed = True
                    break
                buf.append(ch)
                i += 1
        else:
            bdepth = 0
            while i < n:
                ch = cleaned_txt[i]
                if bdepth == 0:
                    if ch == "\\" and i + 1 < n:
                        buf.append(ch)
                        buf.append(cleaned_txt[i + 1])
                        i += 2
                        continue
                    if ch == "`":
                        closed = True
                        break
                    if ch == "$" and i + 1 < n and cleaned_txt[i + 1] == "{":
                        bdepth = 1
                        buf.append("${")
                        i += 2
                        continue
                    buf.append(ch)
                    i += 1
                else:
                    if ch == "{":
                        bdepth += 1
                    elif ch == "}":
                        bdepth -= 1
                    buf.append(ch)
                    i += 1
        if not closed:
            continue
        raw_url = "".join(buf)
        if not raw_url.startswith("/") or raw_url.startswith("//") or "\n" in raw_url:
            continue
        verb = _fetch_method_from_call_tail(cleaned_txt, i)
        lineno = cleaned_txt.count("\n", 0, vm.start()) + 1
        calls.append((verb, raw_url, lineno))
    return calls


def _blank_html_comments_style_script(raw_source: str) -> str:
    """Blank `<!-- ... -->` comments and `<style>`/`<script>` blocks preserving exact newlines."""
    chars = list(raw_source)
    for m in _HTML_COMMENT_OR_EMBED_RE.finditer(raw_source):
        for idx in range(m.start(), m.end()):
            if chars[idx] != "\n":
                chars[idx] = " "
    return "".join(chars)


def _blank_html_comments_only(raw_source: str) -> str:
    """Blank `<!-- ... -->` comments outside `<script>`/`<style>` preserving line offsets."""
    chars = list(raw_source)
    for m in re.finditer(r"<!--[\s\S]*?(?:-->|$)", raw_source):
        for idx in range(m.start(), m.end()):
            if chars[idx] != "\n":
                chars[idx] = " "
    return "".join(chars)


def _norm_html_mount_path(raw_val: str, *, allow_http_path: bool = False) -> str | None:
    val = raw_val.strip()
    if not val:
        return None
    if val.startswith(("http://", "https://")):
        if not allow_http_path:
            return None
        val = urlparse(val).path or ""
    if not val.startswith("/") or val.startswith("//"):
        return None
    cleaned = "/" + val.strip("/") if val.strip("/") else ""
    return cleaned or None


def extract_html_mount_info(
    fe_dir: Path,
    src_root: Path | None = None,
    *,
    repo_root: Path | None = None,
    errors_out: list[str] | None = None,
) -> tuple[tuple[str, ...], str | None]:
    """Read `<base href>` and `<meta name='api-base'>` prefixes from companion HTML entrypoints."""
    bound_root = repo_root if repo_root is not None else fe_dir
    candidates: list[Path] = []
    seen: set[Path] = set()
    search_dirs = [fe_dir]
    if src_root is not None and src_root != fe_dir:
        search_dirs.append(src_root)
    for d in search_dirs:
        safe_d = safe_resolve_contained_path(d, bound_root)
        if safe_d is None:
            continue
        try:
            if not safe_d.is_dir():
                continue
            if not os.access(safe_d, os.R_OK | os.X_OK):
                raise PermissionError(f"Directory is not readable/traversable: {safe_d}")
            entries = sorted(safe_d.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            if errors_out is not None:
                errors_out.append(f"Unreadable HTML mount directory {safe_d}: {exc}")
            continue
        entry_by_name = {item.name: item for item in entries}
        ordered_entries: list[Path] = []
        for idx_name in ("index.html", "index.htm"):
            if idx_name in entry_by_name:
                ordered_entries.append(entry_by_name[idx_name])
        for item in entries:
            if item.name not in ("index.html", "index.htm") and item.suffix.lower() in (".html", ".htm"):
                ordered_entries.append(item)
        for p in ordered_entries:
            try:
                st = p.lstat()
            except OSError as exc:
                if errors_out is not None:
                    errors_out.append(f"Unreadable HTML mount file {p}: {exc}")
                continue
            if stat.S_ISLNK(st.st_mode):
                if errors_out is not None:
                    errors_out.append(f"Skipped symlink HTML mount file: {p}")
                continue
            if not stat.S_ISREG(st.st_mode):
                if errors_out is not None:
                    errors_out.append(f"Skipped non-regular HTML mount file: {p}")
                continue
            rp = safe_resolve_contained_path(p, bound_root)
            if rp is not None and rp not in seen:
                seen.add(rp)
                candidates.append(rp)

    mount_prefixes: list[str] = []
    api_base_meta: str | None = None
    for html_path in candidates:
        try:
            raw = safe_read_repo_text(html_path, bound_root, encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            if errors_out is not None:
                errors_out.append(f"Unreadable HTML file {html_path}: {exc}")
            continue
        no_comments = _blank_html_comments_only(raw)
        bm = _HTML_BASE_TAG_RE.search(no_comments)
        if bm:
            raw_href = bm.group("sq") if bm.group("sq") is not None else (bm.group("dq") or "")
            pref = _norm_html_mount_path(raw_href, allow_http_path=True)
            if pref and not re.match(r"^/api(?:/|$)", pref) and pref not in mount_prefixes:
                mount_prefixes.append(pref)
        for mm in _HTML_META_TAG_RE.finditer(no_comments):
            attrs = mm.group("attrs")
            nm = _HTML_META_NAME_RE.search(attrs)
            if not nm:
                continue
            mname = (nm.group("sq") if nm.group("sq") is not None else (nm.group("dq") or "")).strip().lower()
            if mname != "api-base":
                continue
            cm = _HTML_META_CONTENT_RE.search(attrs)
            if not cm:
                continue
            raw_content = cm.group("sq") if cm.group("sq") is not None else (cm.group("dq") or "")
            norm_meta = _norm_html_mount_path(raw_content, allow_http_path=False)
            if norm_meta:
                if api_base_meta is None:
                    api_base_meta = norm_meta
                if not re.match(r"^/api(?:/|$)", norm_meta) and norm_meta not in mount_prefixes:
                    mount_prefixes.append(norm_meta)
    mount_prefixes.sort(key=len, reverse=True)
    return tuple(mount_prefixes), api_base_meta


def extract_html_script_specs(
    raw_source: str,
    *,
    base_prefixes: tuple[str, ...] = (),
) -> list[str]:
    """Extract local `<script src='...'>` module/script references from HTML after blanking comments."""
    no_comments = _blank_html_comments_only(raw_source)
    specs: list[str] = []
    for m in _HTML_SCRIPT_TAG_RE.finditer(no_comments):
        attrs = m.group("attrs")
        tm = _HTML_SCRIPT_TYPE_ATTR_RE.search(attrs)
        if tm:
            tval = (tm.group("sq") if tm.group("sq") is not None else (tm.group("dq") or "")).strip().lower()
            if tval and tval != "module" and "javascript" not in tval:
                continue
        sm = _HTML_SCRIPT_SRC_ATTR_RE.search(attrs)
        if not sm:
            continue
        raw_src = (sm.group("sq") if sm.group("sq") is not None else (sm.group("dq") or "")).strip()
        s_val = raw_src.split("?", 1)[0].split("#", 1)[0].strip()
        if not s_val or s_val.startswith(("http://", "https://", "//", "data:", "blob:", "javascript:")):
            continue
        if not s_val.startswith(("/", ".", "@/", "~/")):
            specs.append(f"./{s_val}")
        else:
            specs.append(s_val)
            for pref in base_prefixes:
                if pref and s_val.startswith(f"{pref}/"):
                    specs.append(s_val[len(pref) :])
    return specs


def _extract_js_literal_markup_only(source: str) -> str:
    """Keep only string/template literal text (blanking code, comments, regexes) preserving newlines."""
    cleaned = _strip_ts_comments(source)
    mask = js_code_mask(cleaned)
    n = len(cleaned)
    out = ["\n" if ch == "\n" else " " for ch in cleaned]
    stack: list[str] = []
    expr_floors = [0]
    prev_sig_pos = -1
    i = 0
    while i < n:
        ch = cleaned[i]
        top = stack[-1] if stack else ""
        if top == "`":
            if ch == "\\":
                if i + 1 < n and cleaned[i + 1] != "\n":
                    out[i] = ch
                    out[i + 1] = cleaned[i + 1]
                i += 2
                continue
            if ch == "`":
                stack.pop()
                prev_sig_pos = i
                i += 1
                continue
            if cleaned.startswith("${", i):
                out[i] = "$"
                stack.append("{")
                expr_floors.append(i + 2)
                prev_sig_pos = i + 1
                i += 2
                continue
            out[i] = ch
            i += 1
            continue
        if ch in ("'", '"') and not mask[i]:
            j = i + 1
            while j < n and cleaned[j] not in (ch, "\n"):
                if cleaned[j] == "\\" and j + 1 < n:
                    out[j] = cleaned[j]
                    if cleaned[j + 1] != "\n":
                        out[j + 1] = cleaned[j + 1]
                    j += 2
                    continue
                out[j] = cleaned[j]
                j += 1
            prev_sig_pos = min(j, n - 1)
            i = j + 1
            continue
        if ch == "/" and not mask[i] and _can_start_js_regex(cleaned, prev_sig_pos, expr_floors[-1]):
            rend = _skip_js_regex(cleaned, i, n)
            if rend is not None:
                prev_sig_pos = rend - 1
                i = rend
                continue
        if ch == "`" and not mask[i]:
            stack.append("`")
            i += 1
            continue
        if ch == "{" and mask[i]:
            stack.append("{")
            expr_floors.append(i + 1)
        elif ch == "}" and mask[i] and stack and stack[-1] == "{":
            stack.pop()
            if len(expr_floors) > 1:
                expr_floors.pop()
        if mask[i] and not ch.isspace():
            prev_sig_pos = i
        i += 1

    lit_only = "".join(out)
    # Neutralize non-HTML `<tag` tokens inside prose/type-example strings (`Promise<input>`, `x<img && y>0`).
    out_chars = list(lit_only)
    for tm in _JS_TAG_CHECK_RE.finditer(lit_only):
        pos = tm.start()
        if pos > 0 and (lit_only[pos - 1].isalnum() or lit_only[pos - 1] in ("_", "$")):
            out_chars[pos] = " "
            continue
        gt = lit_only.find(">", tm.end(), min(n, tm.end() + 400))
        if gt >= 0 and re.search(r"&&|\|\|", lit_only[tm.end() : gt]):
            out_chars[pos] = " "
    return "".join(out_chars)


def scan_a11y_markup_findings(
    raw_source: str,
    node_id: str,
    rel_repo: str,
    *,
    component_resolver: Callable[[str, str, str], str] | None = None,
    unobserved_out: list[str] | None = None,
) -> list[RawCandidateFinding]:
    """Extend WCAG DISP-005 inspection to `.html`/`.htm` and literal templates in `.js`/`.mjs`/`.ts`."""
    low = rel_repo.lower()
    if low.endswith((".html", ".htm")):
        target = _blank_html_comments_style_script(raw_source)
    elif low.endswith((".js", ".mjs", ".ts")):
        target = _blank_html_comments_only(_extract_js_literal_markup_only(raw_source))
        if not _HTML_MARKUP_TEMPLATE_RE.search(target):
            return []
    else:
        target = raw_source
    return _raw_scan_a11y_markup_findings(
        target,
        node_id,
        rel_repo,
        component_resolver=component_resolver,
        unobserved_out=unobserved_out,
    )


def extract_script_preserving_lines(raw_source: str, suffix: str) -> str:
    """For .vue / .svelte / .html files, replace non-script regions with spaces/newlines preserving lines."""
    if suffix.lower() not in (".vue", ".svelte", ".html", ".htm"):
        return _strip_ts_comments(raw_source)

    chars = ["\n" if ch == "\n" else " " for ch in raw_source]
    for m in _SFC_SCRIPT_RE.finditer(raw_source):
        start, end = m.span("body")
        cleaned = _strip_ts_comments(m.group("body"))
        for idx, ch in enumerate(cleaned):
            if start + idx < end:
                chars[start + idx] = ch
    return "".join(chars)


_NAMED_IMPORT_STMT_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*import\s+(?!type\b)(?:[A-Za-z_$][\w$]*\s*,\s*)?\{(?P<clause>[^}]+)\}\s*from\s*['"](?P<spec>[^'"]+)['"]""",
)
_EXPORT_CONST_NAME_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+(?:default\s+)?(?:const|let|var|async\s+function|function|class)\s+(?P<name>[A-Za-z_$][\w$]*)\b""",
)
_EXPORT_LOCAL_CLAUSE_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+(?!type\b)\{(?P<clause>[^}]+)\}(?=[ \t]*(?:[;\r\n]|$))""",
)
_REEXPORT_FROM_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+(?!type\b)\{(?P<clause>[^}]+)\}\s*from\s*['"](?P<spec>[^'"]+)['"]""",
)
_REEXPORT_ALL_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+\*\s+from\s*['"](?P<spec>[^'"]+)['"]""",
)


def _parse_specifier_pairs(clause: str) -> list[tuple[str, str]]:
    """Return `(exported_or_local_name, alias_name)` pairs, skipping inline `type Foo`."""
    pairs: list[tuple[str, str]] = []
    for raw_item in clause.split(","):
        item = raw_item.strip()
        if not item or item.startswith("type "):
            continue
        parts = re.split(r"\s+as\s+", item, maxsplit=1)
        src_name = parts[0].strip()
        dst_name = parts[1].strip() if len(parts) == 2 else src_name
        if re.fullmatch(r"[A-Za-z_$][\w$]*", src_name) and re.fullmatch(r"[A-Za-z_$][\w$]*", dst_name):
            pairs.append((src_name, dst_name))
    return pairs


def resolve_frontend_import(
    spec: str,
    current_file: Path,
    src_root: Path,
    extensions: tuple[str, ...],
    *,
    repo_root: Path | None = None,
) -> Path | None:
    spec = spec.split("?", 1)[0].split("#", 1)[0].strip()
    if not spec or "\x00" in spec:
        return None
    bound_root = repo_root if repo_root is not None else src_root
    fallback_bases: list[Path] = []
    if spec.startswith(("@/", "~/")):
        base = src_root / spec[2:]
    elif spec.startswith(("$lib/", "#lib/")):
        safe_lib = safe_resolve_contained_path(src_root / "lib", bound_root)
        try:
            lib_ok = safe_lib is not None and safe_lib.is_dir() and os.access(safe_lib, os.R_OK | os.X_OK)
        except OSError:
            lib_ok = False
        lib_dir = safe_lib if (lib_ok and safe_lib is not None) else src_root
        base = lib_dir / spec[5:]
    elif spec.startswith("."):
        base = current_file.parent / spec
    elif spec.startswith("/") and not spec.startswith("//"):
        rel_spec = spec.lstrip("/")
        if src_root.name == "src" and rel_spec.startswith("src/"):
            base = src_root.parent / rel_spec
        else:
            base = src_root / rel_spec
            if src_root.name == "src":
                fallback_bases.append(src_root.parent / rel_spec)
    else:
        return None

    for b in (base, *fallback_bases):
        candidates = [b]
        if b.suffix in (".js", ".mjs"):
            for alt in (".ts", ".tsx", ".mts", ".svelte", ".vue"):
                candidates.append(b.with_suffix(alt))
        for ext in extensions:
            candidates.append(Path(f"{b}{ext}"))
        for ext in extensions:
            candidates.append(b / f"index{ext}")
        for cand in candidates:
            safe_cand = safe_resolve_contained_path(cand, bound_root)
            if safe_cand is not None:
                try:
                    if safe_cand.is_file():
                        return safe_cand
                except OSError:
                    continue
    return None


def build_frontend_url_const_resolver(
    src_root: Path,
    extensions: tuple[str, ...],
    *,
    cleaned_cache: dict[Path, str] | None = None,
    html_api_base: str | None = None,
    repo_root: Path | None = None,
    read_errors_out: list[str] | None = None,
) -> Callable[[Path, str], dict[str, str]]:
    """Return `imported_consts_for(file_path, cleaned_txt)` resolving static same-origin URL exports."""
    bound_root = repo_root if repo_root is not None else src_root
    export_cache: dict[Path, dict[str, str]] = {}
    text_cache: dict[Path, str] = dict(cleaned_cache) if cleaned_cache is not None else {}
    parsed_cache: dict[Path, tuple[str, list[tuple[Path, list[tuple[str, str]]]], list[Path], list[tuple[Path | None, list[tuple[str, str]]]], list[str], list[tuple[str, str]]]] = {}
    scoped_const_cache: dict[tuple[Path, tuple[tuple[str, str], ...]], dict[str, str]] = {}

    def _read_cleaned(fpath: Path) -> str:
        if fpath not in text_cache:
            try:
                raw = safe_read_repo_text(fpath, bound_root, encoding="utf-8", errors="replace")
            except (OSError, UnicodeError) as exc:
                if read_errors_out is not None:
                    read_errors_out.append(f"Unreadable frontend constant source {fpath}: {exc}")
                text_cache[fpath] = ""
            else:
                text_cache[fpath] = extract_script_preserving_lines(raw, fpath.suffix)
        return text_cache[fpath]

    def _parse_module(fpath: Path):
        cached = parsed_cache.get(fpath)
        if cached is not None:
            return cached
        cleaned = _read_cleaned(fpath)
        if not cleaned:
            empty = ("", [], [], [], [], [])
            parsed_cache[fpath] = empty
            return empty
        mask = js_code_mask(cleaned)
        named_imports: list[tuple[Path, list[tuple[str, str]]]] = []
        for im in _NAMED_IMPORT_STMT_RE.finditer(cleaned):
            if not is_js_module_stmt_in_code(cleaned, mask, im):
                continue
            target = resolve_frontend_import(
                im.group("spec"), fpath, src_root, extensions, repo_root=bound_root
            )
            if target is not None:
                named_imports.append((target, _parse_specifier_pairs(im.group("clause"))))
        reexport_all: list[Path] = []
        for rm in _REEXPORT_ALL_RE.finditer(cleaned):
            if not is_js_module_stmt_in_code(cleaned, mask, rm):
                continue
            target = resolve_frontend_import(
                rm.group("spec"), fpath, src_root, extensions, repo_root=bound_root
            )
            if target is not None:
                reexport_all.append(target)
        reexport_from: list[tuple[Path | None, list[tuple[str, str]]]] = []
        for rm in _REEXPORT_FROM_RE.finditer(cleaned):
            if not is_js_module_stmt_in_code(cleaned, mask, rm):
                continue
            target = resolve_frontend_import(
                rm.group("spec"), fpath, src_root, extensions, repo_root=bound_root
            )
            reexport_from.append((target, _parse_specifier_pairs(rm.group("clause"))))
        exported_names: list[str] = []
        for em in _EXPORT_CONST_NAME_RE.finditer(cleaned):
            if is_js_module_stmt_in_code(cleaned, mask, em):
                exported_names.append(em.group("name"))
        exported_local_pairs: list[tuple[str, str]] = []
        for lm in _EXPORT_LOCAL_CLAUSE_RE.finditer(cleaned):
            if is_js_module_stmt_in_code(cleaned, mask, lm):
                exported_local_pairs.extend(_parse_specifier_pairs(lm.group("clause")))
        entry = (
            cleaned,
            named_imports,
            reexport_all,
            reexport_from,
            exported_names,
            exported_local_pairs,
        )
        parsed_cache[fpath] = entry
        return entry

    def _exports_of(
        fpath: Path,
        visiting: frozenset[Path],
        depth: int,
        run_memo: dict[Path, tuple[int, frozenset[Path], dict[str, str], frozenset[Path], bool]],
        budget: list[int],
    ) -> tuple[dict[str, str], frozenset[Path], bool]:
        if fpath in export_cache:
            return export_cache[fpath], frozenset(), False
        if fpath in visiting:
            return {}, frozenset({fpath}), False
        if depth > 8 or budget[0] <= 0:
            return {}, frozenset(), True
        prev = run_memo.get(fpath)
        if prev is not None:
            prev_depth, prev_visiting, prev_exp, prev_cyc, prev_trunc = prev
            if (not prev_trunc and prev_cyc.issubset(visiting)) or (
                prev_depth <= depth and prev_visiting.issubset(visiting)
            ):
                return prev_exp, prev_cyc, prev_trunc
        budget[0] -= 1
        cleaned, named_imports, reexport_all, reexport_from, exported_names, exported_local_pairs = _parse_module(fpath)
        if not cleaned or (not reexport_all and not reexport_from and not exported_names and not exported_local_pairs):
            export_cache[fpath] = {}
            return {}, frozenset(), False

        next_visiting = visiting | {fpath}
        cycle_deps: set[Path] = set()
        truncated = False
        imported: dict[str, str] = {}
        if exported_names or exported_local_pairs:
            for target, pairs in named_imports:
                target_exports, cyc_set, trunc = _exports_of(target, next_visiting, depth + 1, run_memo, budget)
                cycle_deps.update(cyc_set)
                truncated = truncated or trunc
                for orig_name, local_name in pairs:
                    if orig_name in target_exports:
                        imported[local_name] = target_exports[orig_name]

        if exported_names or exported_local_pairs:
            sc_key = (fpath, tuple(sorted(imported.items())))
            local_consts = scoped_const_cache.get(sc_key)
            if local_consts is None:
                local_consts, _ = _build_scoped_url_consts(
                    cleaned, imported_consts=imported, html_api_base=html_api_base
                )
                scoped_const_cache[sc_key] = local_consts
        else:
            local_consts = {}

        exported: dict[str, str] = {}
        for target in reexport_all:
            target_exports, cyc_set, trunc = _exports_of(target, next_visiting, depth + 1, run_memo, budget)
            cycle_deps.update(cyc_set)
            truncated = truncated or trunc
            exported.update(target_exports)
        for target, pairs in reexport_from:
            if target is not None:
                target_exports, cyc_set, trunc = _exports_of(target, next_visiting, depth + 1, run_memo, budget)
                cycle_deps.update(cyc_set)
                truncated = truncated or trunc
                for orig_name, export_name in pairs:
                    if orig_name in target_exports:
                        exported[export_name] = target_exports[orig_name]
                    else:
                        exported.pop(export_name, None)
            else:
                for _orig_name, export_name in pairs:
                    exported.pop(export_name, None)
        for cname in exported_names:
            if cname in local_consts:
                exported[cname] = local_consts[cname]
            else:
                exported.pop(cname, None)
        for local_name, export_name in exported_local_pairs:
            if local_name in local_consts:
                exported[export_name] = local_consts[local_name]
            else:
                exported.pop(export_name, None)

        remaining_cycles = frozenset(cycle_deps - {fpath})
        if not remaining_cycles and not truncated:
            export_cache[fpath] = exported
        else:
            prev = run_memo.get(fpath)
            if prev is None or depth < prev[0] or (not truncated and prev[4]):
                run_memo[fpath] = (depth, visiting, exported, remaining_cycles, truncated)
        return exported, remaining_cycles, truncated

    def imported_consts_for(fpath: Path, cleaned_txt: str) -> dict[str, str]:
        resolved_path = safe_resolve_contained_path(fpath, bound_root)
        if resolved_path is None:
            return {}
        text_cache.setdefault(resolved_path, cleaned_txt)
        _, named_imports, _, _, _, _ = _parse_module(resolved_path)
        if not named_imports:
            return {}
        imported: dict[str, str] = {}
        run_memo: dict[Path, tuple[int, frozenset[Path], dict[str, str], frozenset[Path], bool]] = {}
        budget = [256]
        for target, pairs in named_imports:
            if target == resolved_path:
                continue
            target_exports, _, _ = _exports_of(target, frozenset({resolved_path}), 0, run_memo, budget)
            for orig_name, local_name in pairs:
                if orig_name in target_exports:
                    imported[local_name] = target_exports[orig_name]
        return imported

    return imported_consts_for


def build_a11y_component_resolver(
    src_root: Path,
    extensions: tuple[str, ...],
    *,
    repo_root: Path | None = None,
) -> Callable[[Path, str], Callable[[str, str, str], str]]:
    """Build a per-scan factory returning depth-bounded component text-semantics resolvers."""
    bound_root = repo_root if repo_root is not None else src_root
    shared_cache: dict[
        tuple[Path, str],
        tuple[dict[str, str], dict[str, str], str, dict[str, tuple[str, str]], Path, str, int],
    ] = {}
    shared_lexical_cache: dict[Path, dict[str, list[tuple[int, tuple[int, int]]]]] = {}

    def _resolve_imp(spec: str, current_file: Path) -> Path | None:
        return resolve_frontend_import(spec, current_file, src_root, extensions, repo_root=bound_root)

    def resolver_for(caller_file: Path, caller_raw_source: str) -> Callable[[str, str, str], str]:
        safe_caller = safe_resolve_contained_path(caller_file, bound_root)
        if safe_caller is None:
            def _fail_closed_resolver(
                _tag_name: str,
                _attrs: str,
                _inner_status: str,
                **_kwargs: object,
            ) -> str:
                return "opaque"

            return _fail_closed_resolver
        return make_local_component_resolver(
            safe_caller,
            caller_raw_source,
            _resolve_imp,
            _cache=shared_cache,
            _lexical_cache=shared_lexical_cache,
        )

    return resolver_for


def format_unobserved_a11y_note(unobserved: list[str]) -> str | None:
    """Summarize controls skipped from definite DISP-005 reporting due to opaque components."""
    if not unobserved:
        return None
    return (
        f"DISP-005 left {len(unobserved)} <button> control(s) with uninspected opaque child "
        f"components unobserved (e.g. {unobserved[0]})."
    )


def collect_safe_graph_files(
    fe_dir: Path,
    repo_root: Path,
    *,
    skip_dirs: frozenset[str] | None = None,
    errors_out: list[str] | None = None,
) -> set[Path]:
    """Collect contained, regular JS/TS graph modules under `fe_dir` without following symlinks."""
    skip = (
        skip_dirs
        if skip_dirs is not None
        else (_REACH_SKIP_DIRS | {"__tests__", ".git", ".venv", "venv"})
    )
    found: set[Path] = set()
    safe_fe = safe_resolve_contained_path(fe_dir, repo_root)
    try:
        fe_ok = safe_fe is not None and safe_fe.is_dir()
        if fe_ok and safe_fe is not None:
            if not os.access(safe_fe, os.R_OK | os.X_OK):
                raise PermissionError(f"Directory is not readable/traversable: {safe_fe}")
            with os.scandir(safe_fe):
                pass
    except OSError as exc:
        if errors_out is not None:
            errors_out.append(
                f"Unreadable frontend directory `{fe_dir}` ({exc}); display coverage is incomplete."
            )
        return found
    if not fe_ok or safe_fe is None:
        if errors_out is not None:
            errors_out.append(
                f"Frontend directory `{fe_dir}` is missing or outside repository root; display coverage is incomplete."
            )
        return found

    def _on_walk_err(exc: OSError) -> None:
        if errors_out is not None:
            errors_out.append(
                f"Unreadable frontend directory `{exc.filename or safe_fe}` ({exc}); display coverage is incomplete."
            )

    for root, dirs, files in os.walk(safe_fe, followlinks=False, onerror=_on_walk_err):
        kept_dirs: list[str] = []
        for d in sorted(dirs):
            if d in skip:
                continue
            d_path = Path(root) / d
            try:
                st = d_path.lstat()
            except OSError as exc:
                if errors_out is not None:
                    errors_out.append(
                        f"Unreadable frontend directory `{d_path}` ({exc}); display coverage is incomplete."
                    )
                continue
            if stat.S_ISLNK(st.st_mode):
                if errors_out is not None:
                    errors_out.append(
                        f"Skipped symlink directory `{d_path}`; display coverage is incomplete."
                    )
                continue
            if stat.S_ISDIR(st.st_mode):
                if not os.access(d_path, os.R_OK | os.X_OK):
                    if errors_out is not None:
                        errors_out.append(
                            f"Unreadable frontend directory `{d_path}`; display coverage is incomplete."
                        )
                    continue
                kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in GRAPH_SUFFIXES:
                continue
            if (
                fname.endswith(".d.ts")
                or any(tag in fname for tag in (".test.", ".spec.", ".stories."))
                or fname == "api-generated.ts"
            ):
                continue
            try:
                st = fpath.lstat()
            except OSError as exc:
                if errors_out is not None:
                    errors_out.append(
                        f"Unreadable graph source `{fpath}` ({exc}); display coverage is incomplete."
                    )
                continue
            if stat.S_ISLNK(st.st_mode):
                if errors_out is not None:
                    errors_out.append(
                        f"Skipped symlink graph source `{fpath}`; display coverage is incomplete."
                    )
                continue
            if not stat.S_ISREG(st.st_mode):
                if errors_out is not None:
                    errors_out.append(
                        f"Skipped non-regular graph source `{fpath}`; display coverage is incomplete."
                    )
                continue
            safe_fp = safe_resolve_contained_path(fpath, repo_root)
            if safe_fp is None:
                if errors_out is not None:
                    errors_out.append(
                        f"Rejected out-of-repo graph source `{fpath}`; display coverage is incomplete."
                    )
                continue
            found.add(safe_fp)
    return found


def make_safe_graph_resolver(
    fe_dir: Path,
    src_root: Path,
    repo_root: Path,
    known_files: set[Path],
    *,
    ws_resolver: WorkspaceResolver,
    errors_out: list[str] | None = None,
) -> Callable[[str, Path], Path | None]:
    """Build a contained TS/JS import resolver using `WorkspaceResolver` and safe `jsconfig.json` reads."""
    safe_fe = safe_resolve_contained_path(fe_dir, repo_root)
    js_cfg: TsConfigPaths | None = None
    if safe_fe is None and errors_out is not None:
        errors_out.append(
            f"Frontend directory `{fe_dir}` is outside repository root or symlinked; display coverage is incomplete."
        )
    for cfg_name in ("tsconfig.json", "jsconfig.json") if safe_fe is not None else ():
        cfg_cand = safe_fe / cfg_name
        try:
            st = cfg_cand.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            if errors_out is not None:
                errors_out.append(
                    f"Unreadable frontend config `{cfg_cand}` ({exc}); display coverage is incomplete."
                )
            continue
        if stat.S_ISLNK(st.st_mode):
            if errors_out is not None:
                errors_out.append(
                    f"Skipped symlink frontend config `{cfg_cand}`; display coverage is incomplete."
                )
            continue
        if not stat.S_ISREG(st.st_mode):
            if errors_out is not None:
                errors_out.append(
                    f"Skipped non-regular frontend config `{cfg_cand}`; display coverage is incomplete."
                )
            continue
        safe_cfg = safe_resolve_contained_path(cfg_cand, repo_root)
        if safe_cfg is None:
            if errors_out is not None:
                errors_out.append(
                    f"Rejected out-of-repo frontend config `{cfg_cand}`; display coverage is incomplete."
                )
            continue
        try:
            safe_read_repo_text(safe_cfg, repo_root, encoding="utf-8", errors="strict")
        except (OSError, UnicodeError) as exc:
            if errors_out is not None:
                errors_out.append(
                    f"Unreadable frontend config `{cfg_cand}` ({exc}); display coverage is incomplete."
                )
            continue
        if cfg_name == "jsconfig.json" and safe_fe not in ws_resolver.tsconfigs:
            js_cfg = load_tsconfig_paths(safe_cfg, repo_root=repo_root)

    cache: dict[tuple[str, Path], Path | None] = {}

    def resolve_import_spec(spec: str, current_file: Path) -> Path | None:
        clean_spec = spec.split("?", 1)[0].split("#", 1)[0].strip()
        if not clean_spec or "\x00" in clean_spec:
            return None
        key = (clean_spec, current_file.parent)
        if key in cache:
            return cache[key]

        hit = ws_resolver.resolve_import(clean_spec, current_file, exts=GRAPH_SUFFIXES)
        if hit is not None and hit in known_files:
            cache[key] = hit
            return hit

        if clean_spec.startswith("@/"):
            alias_hit = probe_ts_candidate(src_root / clean_spec[2:], repo_root, exts=GRAPH_SUFFIXES)
            if alias_hit is not None and alias_hit in known_files:
                cache[key] = alias_hit
                return alias_hit

        if js_cfg is not None:
            matches: list[tuple[int, str, list[tuple[Path, str]]]] = []
            for pat, targets in js_cfg.paths.items():
                if "*" in pat:
                    pre, suf = pat.split("*", 1)
                    if (
                        clean_spec.startswith(pre)
                        and clean_spec.endswith(suf)
                        and len(clean_spec) >= len(pre) + len(suf)
                    ):
                        star_val = clean_spec[
                            len(pre) : len(clean_spec) - len(suf) if suf else len(clean_spec)
                        ]
                        matches.append((len(pre) + len(suf), star_val, targets))
                elif clean_spec == pat:
                    matches.append((len(pat) + 1000, "", targets))
            matches.sort(key=lambda item: item[0], reverse=True)
            for _score, star_val, targets in matches:
                for tgt_pre, tgt_suf in targets:
                    sub = f"{star_val}{tgt_suf}".lstrip("/") if star_val or tgt_suf else ""
                    cand = tgt_pre / sub if sub else tgt_pre
                    js_hit = probe_ts_candidate(cand, repo_root, exts=GRAPH_SUFFIXES)
                    if js_hit is not None and js_hit in known_files:
                        cache[key] = js_hit
                        return js_hit
            if not clean_spec.startswith(("#", "@/", "$lib/", "#lib/", ".")):
                js_hit = probe_ts_candidate(
                    js_cfg.base_url / clean_spec, repo_root, exts=GRAPH_SUFFIXES
                )
                if js_hit is not None and js_hit in known_files:
                    cache[key] = js_hit
                    return js_hit

        cache[key] = None
        return None

    return resolve_import_spec


def scan_display_module_semantics(
    node: AtlasNode,
    cleaned_txt: str,
    rel_repo: str,
    raw_source: str | None = None,
    *,
    imported_url_consts: dict[str, str] | None = None,
    component_resolver: Callable[[str, str, str], str] | None = None,
    unobserved_a11y_out: list[str] | None = None,
    has_generator_config: bool = False,
    sdk_calls: tuple[tuple[str, str, int], ...] | list[tuple[str, str, int]] = (),
    uses_typed_sdk: bool = False,
    mount_prefixes: tuple[str, ...] = (),
    html_api_base: str | None = None,
) -> tuple[list[str], list[FrontendHttpCall], list[RawCandidateFinding]]:
    """Extract imports, HTTP calls, and DISP-001..005 findings for a single display node."""
    imported_specs = [m.group("spec") for m in _IMPORT_RE.finditer(cleaned_txt)]
    if raw_source and rel_repo.lower().endswith((".html", ".htm")):
        imported_specs.extend(extract_html_script_specs(raw_source, base_prefixes=mount_prefixes))
    uses_schema_types = has_generated_contract_provenance(
        imported_specs,
        raw_source=raw_source,
        source_file=rel_repo,
        has_generator_config=has_generator_config,
    ) or uses_typed_sdk

    raw_calls = list(
        _extract_ts_http_calls(
            cleaned_txt,
            imported_consts=imported_url_consts,
            mount_prefixes=mount_prefixes,
            html_api_base=html_api_base,
        )
    )
    if sdk_calls:
        seen_calls = set(raw_calls)
        for item in sdk_calls:
            if item not in seen_calls:
                seen_calls.add(item)
                raw_calls.append(item)
    raw_calls.extend(_extract_vue_sfc_fetch_calls(cleaned_txt))

    http_calls: list[FrontendHttpCall] = []
    methods_seen: list[str] = []
    paths_seen: list[str] = []
    seen_call_keys: set[tuple[str, str, int]] = set()
    for verb, raw_u, lineno in raw_calls:
        if (verb, raw_u, lineno) in seen_call_keys:
            continue
        seen_call_keys.add((verb, raw_u, lineno))
        norm_u = _normalize_ts_url(raw_u, mount_prefixes=mount_prefixes)
        if verb not in methods_seen:
            methods_seen.append(verb)
        if norm_u not in paths_seen:
            paths_seen.append(norm_u)
        http_calls.append(
            FrontendHttpCall(
                caller_node_id=node.id,
                http_method=verb,
                raw_path=raw_u,
                normalized_path=norm_u,
                source_file=rel_repo,
                line=lineno,
            )
        )
    node.http_methods = methods_seen
    node.http_paths = paths_seen[:25]
    if len(paths_seen) > 25 and "total paths" not in node.summary:
        node.summary = (
            f"{node.summary.rstrip('.')} "
            f"({len(paths_seen)} total paths; {len(paths_seen) - 25} omitted beyond 25-path cap)."
        )

    findings: list[RawCandidateFinding] = []
    if node.subkind == "api_client" and http_calls and not uses_schema_types:
        node.status = "gray_zone"
        findings.append(
            RawCandidateFinding(
                rule_code="DISP-003",
                node_id=node.id,
                source_file=rel_repo,
                line=1,
                title=f"API client `{node.label}` does not bind generated schema types",
                detail=f"{rel_repo} issues {len(http_calls)} HTTP call(s) without importing OpenAPI/generated schema contracts.",
                remediation="Import generated schema types (`openapi-typescript` / OpenAPI client).",
            )
        )

    active_tokens = get_active_policy_tokens()
    for m in _TS_POLICY_CONST_RE.finditer(cleaned_txt):
        cname = m.group("name")
        if name_has_policy_token(cname, active_tokens) and not any(
            safe in cname for safe in _UI_SAFE_TOKENS
        ):
            lineno = cleaned_txt.count("\n", 0, m.start()) + 1
            node.status = "policy_in_code"
            findings.append(
                RawCandidateFinding(
                    rule_code="DISP-001",
                    node_id=node.id,
                    source_file=rel_repo,
                    line=lineno,
                    title=f"Client-side domain policy constant `{cname}`",
                    detail=f"{rel_repo}:{lineno} defines domain threshold/policy `{cname}` in display code.",
                    remediation="Read policy values from backend API responses backed by database truth.",
                )
            )

    if not rel_repo.endswith(_CLOCK_UTIL_FILES):
        for m in _UTC_SLICE_RE.finditer(cleaned_txt):
            lineno = cleaned_txt.count("\n", 0, m.start()) + 1
            node.status = "duplicated_truth"
            findings.append(
                RawCandidateFinding(
                    rule_code="DISP-002",
                    node_id=node.id,
                    source_file=rel_repo,
                    line=lineno,
                    title="UTC `.toISOString()` date slicing in display code",
                    detail=f"{rel_repo}:{lineno} slices a UTC ISO string into a calendar date.",
                    remediation="Format instants with explicit timezone helpers.",
                )
            )
        for m in _RAW_NEW_DATE_RE.finditer(cleaned_txt):
            args_str = m.group("args").strip()
            if _is_raw_clock_read(cleaned_txt, m):
                lineno = cleaned_txt.count("\n", 0, m.start()) + 1
                if node.status == "clean":
                    node.status = "gray_zone"
                findings.append(
                    RawCandidateFinding(
                        rule_code="DISP-002",
                        node_id=node.id,
                        source_file=rel_repo,
                        line=lineno,
                        title=f"Direct `new Date({args_str})` in display module",
                        detail=f"{rel_repo}:{lineno} constructs `Date` directly instead of shared clock utilities.",
                        remediation="Route timestamp formatting and 'today' reads through centralized clock helpers.",
                    )
                )

    if raw_source and rel_repo.lower().endswith(
        (".tsx", ".jsx", ".vue", ".svelte", ".html", ".htm", ".js", ".mjs", ".ts")
    ):
        a11y_hits = scan_a11y_markup_findings(
            raw_source,
            node.id,
            rel_repo,
            component_resolver=component_resolver,
            unobserved_out=unobserved_a11y_out,
        )
        if a11y_hits:
            if node.status == "clean":
                node.status = "gray_zone"
            findings.extend(a11y_hits)

    return imported_specs, http_calls, findings
