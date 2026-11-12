"""Tier 3 Adapter: TypeScript + Next.js App Router + TanStack Query + OpenAPI Display Graph."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.adapters.a11y_inspect import scan_a11y_markup_findings
from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    RawCandidateFinding,
)
from app.adapters.treesitter_engine import (
    blank_comments_cst,
    extract_ts_http_calls_cst,
    resolve_url_const_head,
)
from app.adapters.ts_reachability import (
    MODULE_SYMBOL,
    ReachabilityIndex,
    build_nextjs_reachability,
)
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasEdge, AtlasNode

_IMPORT_RE = re.compile(
    r"""(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?['"](?P<spec>[^'"]+)['"]""",
    re.MULTILINE,
)
_REEXPORT_NAMED_RE = re.compile(
    r"""export\s*\{(?P<names>[^}]+)\}\s*from\s*['"](?P<spec>[^'"]+)['"]""",
    re.MULTILINE,
)
_REEXPORT_STAR_RE = re.compile(
    r"""export\s*\*\s*from\s*['"](?P<spec>[^'"]+)['"]""",
    re.MULTILINE,
)
_HTTP_CALL_START_RE = re.compile(
    r"""\b(?:api\.|axios\.|http\.|client\.|ky\.)?(?P<verb>get|post|put|patch|del|delete|fetch|apiRequest|request|httpClient|ofetch)\s*(?:<[^;()]{0,220}?>)?\s*\(\s*(?:[A-Za-z_$][A-Za-z0-9_$.]*\s*\?\s*)?(?P<quote>['"`])"""
)
_FETCH_LIKE_VERBS = frozenset({"FETCH", "APIREQUEST", "REQUEST", "HTTPCLIENT", "OFETCH"})
_FETCH_METHOD_RE = re.compile(r"""method\s*:\s*['"](?P<m>GET|POST|PUT|PATCH|DELETE)['"]""", re.IGNORECASE)
_RTK_BASE_URL_RE = re.compile(r"""fetchBaseQuery\s*\(\s*\{[\s\S]{0,160}?baseUrl\s*:\s*['"](?P<base>[^'"]+)['"]""")
_RTK_ENDPOINT_RE = re.compile(
    r"""builder\.(?P<kind>query|mutation)\s*(?:<[^;()]{0,220}?>)?\s*\(\s*\{[\s\S]{0,260}?url\s*:\s*(?P<quote>['"`])(?P<url>[^'"`\n]+)(?P=quote)"""
)
_TAURI_INVOKE_RE = re.compile(
    r"""\binvoke\s*(?:<[^;()]{0,260}?>)?\s*\(\s*['"](?P<cmd>[a-z_][a-z0-9_]*)['"]"""
)
_TAURI_READ_CMD_PREFIXES = ("get_", "list_", "fetch_", "load_", "find_", "query_", "read_", "detect_", "estimate_", "scope_")


_URL_CONST_RE = re.compile(
    r"""(?:^|[;{])[ \t]*(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*"""
    r"""(?P<q>['"`])(?P<val>(?:/|\$\{)[^'"`\n]*)(?P=q)\s*(?:as\s+const\s*)?(?=[;\n}])""",
    re.MULTILINE,
)
_TEMPLATE_HEAD_CONST_RE = re.compile(r"\$\{\s*(?P<name>[A-Za-z_$][\w$]*)\s*\}")
_URL_CALL_IDENT_RE = re.compile(
    r"""\b(?:api\.|axios\.|http\.|client\.|ky\.)?(?P<verb>get|post|put|patch|del|delete|fetch|apiRequest|request|httpClient|ofetch)\s*(?:<[^;()]{0,220}?>)?\s*\(\s*(?P<ident>[A-Za-z_$][\w$]*)\s*[,)]"""
)


def _collect_url_consts(txt: str) -> dict[str, str]:
    """Top-level `const NAME = '/path'` values usable as module-wide URL prefixes."""
    return _build_scoped_url_consts(txt)[0]


_FN_PARAM_HEAD_RE = re.compile(
    r"""(?:\bfunction\b[A-Za-z0-9_$\s]*(?:<[^>{}()]*>)?\s*\((?P<fparams>[^)]*)\)\s*(?::[^{=]+)?\s*\{|\((?P<aparams>[^()]*)\)\s*(?::[^=]+)?=>|(?P<sparam>[A-Za-z_$][\w$]*)\s*=>)"""
)
_LOCAL_BIND_RE = re.compile(r"""\b(?:const|let|var|function)\s+(?P<name>[A-Za-z_$][\w$]*)\b""")
_PARAM_MODIFIER_RE = re.compile(r"^(?:(?:public|private|protected|readonly|override)\s+)+")


def _split_top_level_ts(s: str, sep: str) -> list[str]:
    parts: list[str] = []
    pdepth = bdepth = cdepth = adepth = 0
    quote: str | None = None
    start = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            pdepth += 1
        elif ch == ")":
            pdepth = max(0, pdepth - 1)
        elif ch == "[":
            bdepth += 1
        elif ch == "]":
            bdepth = max(0, bdepth - 1)
        elif ch == "{":
            cdepth += 1
        elif ch == "}":
            cdepth = max(0, cdepth - 1)
        elif ch == "<":
            adepth += 1
        elif ch == ">" and (i == 0 or s[i - 1] != "="):
            adepth = max(0, adepth - 1)
        elif ch == sep and pdepth == 0 and bdepth == 0 and cdepth == 0 and adepth == 0:
            if sep == "=" and (
                (i > 0 and s[i - 1] in ("=", "!", "<", ">"))
                or (i + 1 < n and s[i + 1] in ("=", ">"))
            ):
                i += 1
                continue
            parts.append(s[start:i])
            start = i + 1
        i += 1
    parts.append(s[start:])
    return parts


def _collect_pattern_bound_names(pat: str, out: set[str], *, allow_type_colon: bool) -> None:
    lhs = _split_top_level_ts(pat, "=")[0].strip()
    if allow_type_colon:
        lhs = _split_top_level_ts(lhs, ":")[0].strip()
    lhs = _PARAM_MODIFIER_RE.sub("", lhs).strip().removeprefix("...").strip().removesuffix("?").strip()
    if not lhs:
        return
    if lhs.startswith("{") and lhs.endswith("}"):
        for prop in _split_top_level_ts(lhs[1:-1], ","):
            no_def = _split_top_level_ts(prop, "=")[0].strip()
            if not no_def:
                continue
            kv = _split_top_level_ts(no_def, ":")
            target = kv[1] if len(kv) >= 2 else kv[0]
            _collect_pattern_bound_names(target, out, allow_type_colon=False)
    elif lhs.startswith("[") and lhs.endswith("]"):
        for elem in _split_top_level_ts(lhs[1:-1], ","):
            _collect_pattern_bound_names(elem, out, allow_type_colon=False)
    elif re.fullmatch(r"[A-Za-z_$][\w$]*", lhs) and lhs != "this":
        out.add(lhs)


def _extract_param_bound_names(raw_params: str) -> set[str]:
    out: set[str] = set()
    for item in _split_top_level_ts(raw_params, ","):
        _collect_pattern_bound_names(item, out, allow_type_colon=True)
    return out


def _find_matching_delim(txt: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    n = len(txt)
    depth = 1
    i = open_idx + 1
    quote: str | None = None
    while i < n and depth > 0:
        ch = txt[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
        i += 1
    return i


def _find_arrow_expr_end(txt: str, start: int) -> int:
    n = len(txt)
    i = start
    while i < n and txt[i].isspace():
        i += 1
    if i < n and txt[i] == "{":
        return _find_matching_delim(txt, i, "{", "}")
    pdepth = bdepth = cdepth = 0
    quote: str | None = None
    while i < n:
        ch = txt[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            pdepth += 1
        elif ch == ")":
            if pdepth == 0:
                break
            pdepth -= 1
        elif ch == "[":
            bdepth += 1
        elif ch == "]":
            if bdepth == 0:
                break
            bdepth -= 1
        elif ch == "{":
            cdepth += 1
        elif ch == "}":
            if cdepth == 0:
                break
            cdepth -= 1
        elif ch in (";", ",") and pdepth == 0 and bdepth == 0 and cdepth == 0:
            break
        i += 1
    return i


def _apply_url_scope_map(
    outer: dict[str, str], outer_bound: set[str], bmap: dict[str, str | None]
) -> tuple[dict[str, str], set[str]]:
    next_bound = outer_bound | set(bmap)
    merged = {k: v for k, v in outer.items() if k not in bmap}
    pending = {
        k: v
        for k, v in bmap.items()
        if v is not None and (k not in outer_bound or outer.get(k) == v)
    }
    if not pending:
        return merged, next_bound
    working = {**merged, **pending}
    for _ in range(3):
        for k in list(pending):
            working[k] = resolve_url_const_head(
                working[k],
                {ok: ov for ok, ov in working.items() if ok != k and ov.startswith("/")},
            )
    for k in pending:
        if working[k].startswith("/"):
            merged[k] = working[k]
    return merged, next_bound


def _build_scoped_url_consts(txt: str) -> tuple[dict[str, str], Callable[[int], dict[str, str]]]:
    """Return `(root_consts, consts_at)` preserving local URL constants while shadowing rebindings."""
    n = len(txt)
    root_span = (0, n)
    block_stack: list[int] = []
    i = 0
    quote: str | None = None
    block_spans: list[tuple[int, int]] = []
    while i < n:
        ch = txt[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "{":
            block_stack.append(i)
        elif ch == "}" and block_stack:
            bstart = block_stack.pop()
            block_spans.append((bstart, i + 1))
        i += 1

    def innermost_block(pos: int) -> tuple[int, int]:
        return min(
            (sp for sp in block_spans if sp[0] < pos < sp[1]),
            key=lambda sp: sp[1] - sp[0],
            default=root_span,
        )

    block_decls: dict[tuple[int, int], dict[str, str | None]] = {}
    url_name_positions: set[int] = set()
    for m in _URL_CONST_RE.finditer(txt):
        name, val = m.group("name"), m.group("val")
        npos = m.start("name")
        url_name_positions.add(npos)
        bmap = block_decls.setdefault(innermost_block(npos), {})
        if m.group("q") != "`" and "${" in val:
            bmap[name] = None
        else:
            bmap[name] = val if bmap.get(name, val) == val else None

    for dm in _LOCAL_BIND_RE.finditer(txt):
        npos = dm.start("name")
        if npos in url_name_positions:
            continue
        block_decls.setdefault(innermost_block(npos), {})[dm.group("name")] = None

    param_scopes: list[tuple[int, int, set[str]]] = []
    for m in _FN_PARAM_HEAD_RE.finditer(txt):
        raw_params = m.group("fparams") or m.group("aparams") or m.group("sparam") or ""
        bound = _extract_param_bound_names(raw_params)
        if not bound:
            continue
        if m.group("fparams") is not None:
            span = (m.end() - 1, _find_matching_delim(txt, m.end() - 1, "{", "}"))
        else:
            span = (m.end(), _find_arrow_expr_end(txt, m.end()))
        param_scopes.append((span[0], span[1], bound))

    root_consts, root_bound = _apply_url_scope_map({}, set(), block_decls.get(root_span, {}))
    inner_blocks = [(s, e, bmap) for (s, e), bmap in block_decls.items() if (s, e) != root_span]

    def consts_at(pos: int) -> dict[str, str]:
        if not inner_blocks and not param_scopes:
            return root_consts
        events: list[tuple[int, int, str, Any]] = []
        for s, e, pnames in param_scopes:
            if s <= pos < e:
                events.append((e - s, 1, "params", pnames))
        for s, e, bmap in inner_blocks:
            if s <= pos < e:
                events.append((e - s, 0, "block", bmap))
        if not events:
            return root_consts
        events.sort(key=lambda item: (item[0], item[1]), reverse=True)
        env = dict(root_consts)
        bound = set(root_bound)
        for _span_len, _prio, kind, payload in events:
            if kind == "params":
                for pname in payload:
                    env.pop(pname, None)
                    bound.add(pname)
            else:
                env, bound = _apply_url_scope_map(env, bound, payload)
        return env

    return root_consts, consts_at


def _fetch_method_from_call_tail(txt: str, pos: int) -> str:
    n = len(txt)
    pdepth = 1
    j = pos
    limit = min(n, pos + 260)
    while j < limit and pdepth > 0:
        if txt[j] == "(":
            pdepth += 1
        elif txt[j] == ")":
            pdepth -= 1
        j += 1
    mm = _FETCH_METHOD_RE.search(txt[pos:j])
    return mm.group("m").upper() if mm else "GET"


def _extract_ts_http_calls(txt: str) -> list[tuple[str, str, int]]:
    """Extract (verb, raw_url, lineno) via Tree-sitter TSX CST (with character-scanner fallback)."""
    root_consts, consts_at = _build_scoped_url_consts(txt)
    cst_calls = extract_ts_http_calls_cst(txt, is_tsx=True, url_consts=root_consts)
    if cst_calls is not None:
        results = list(cst_calls)
        if "createApi" in txt and "builder." in txt:
            bm = _RTK_BASE_URL_RE.search(txt)
            rtk_base = (
                ("/" + bm.group("base").strip("/"))
                if bm and not bm.group("base").startswith("http")
                else ""
            )
            for rm in _RTK_ENDPOINT_RE.finditer(txt):
                rverb = "GET" if rm.group("kind") == "query" else "POST"
                sub_u = rm.group("url").strip()
                joined_u = "/" + "/".join(p for p in (rtk_base.strip("/"), sub_u.strip("/")) if p)
                lineno = txt.count("\n", 0, rm.start()) + 1
                results.append((rverb, joined_u or "/", lineno))
        return results

    results = []
    n = len(txt)
    for m in _HTTP_CALL_START_RE.finditer(txt):
        local_consts = consts_at(m.start())
        verb = m.group("verb").upper()
        if verb == "DEL":
            verb = "DELETE"
        quote = m.group("quote")
        i = m.end()
        buf: list[str] = []
        if quote == "`":
            hm = _TEMPLATE_HEAD_CONST_RE.match(txt, i)
            if hm and hm.group("name") in local_consts:
                buf.append(local_consts[hm.group("name")])
                i = hm.end()
        if i >= n or (not buf and txt[i] != "/"):
            continue
        if quote != "`":
            while i < n and txt[i] not in (quote, "\n"):
                buf.append(txt[i])
                i += 1
        else:
            brace_depth = 0
            while i < n:
                ch = txt[i]
                nxt = txt[i + 1] if i + 1 < n else ""
                if brace_depth == 0:
                    if ch == "`":
                        break
                    if ch == "$" and nxt == "{":
                        brace_depth = 1
                        buf.append("${")
                        i += 2
                        continue
                    buf.append(ch)
                    i += 1
                else:
                    if ch == "{":
                        brace_depth += 1
                    elif ch == "}":
                        brace_depth -= 1
                    buf.append(ch)
                    i += 1
        if verb in _FETCH_LIKE_VERBS:
            verb = _fetch_method_from_call_tail(txt, i)
        raw_url = "".join(buf)
        if raw_url.startswith("/"):
            lineno = txt.count("\n", 0, m.start()) + 1
            results.append((verb, raw_url, lineno))
    for im in _URL_CALL_IDENT_RE.finditer(txt):
        local_consts = consts_at(im.start())
        ident = im.group("ident")
        if ident in local_consts:
            iverb = im.group("verb").upper()
            if iverb == "DEL":
                iverb = "DELETE"
            elif iverb in _FETCH_LIKE_VERBS:
                iverb = _fetch_method_from_call_tail(txt, im.end()) if txt[im.end() - 1] == "," else "GET"
            results.append((iverb, local_consts[ident], txt.count("\n", 0, im.start()) + 1))
    if "createApi" in txt and "builder." in txt:
        bm = _RTK_BASE_URL_RE.search(txt)
        rtk_base = ("/" + bm.group("base").strip("/")) if bm and not bm.group("base").startswith("http") else ""
        for rm in _RTK_ENDPOINT_RE.finditer(txt):
            rverb = "GET" if rm.group("kind") == "query" else "POST"
            sub_u = rm.group("url").strip()
            joined_u = "/" + "/".join(p for p in (rtk_base.strip("/"), sub_u.strip("/")) if p)
            lineno = txt.count("\n", 0, rm.start()) + 1
            results.append((rverb, joined_u or "/", lineno))
    if "@tauri-apps" in txt or "__TAURI__" in txt:
        for tm in _TAURI_INVOKE_RE.finditer(txt):
            cmd = tm.group("cmd")
            tverb = "GET" if cmd.startswith(_TAURI_READ_CMD_PREFIXES) else "POST"
            lineno = txt.count("\n", 0, tm.start()) + 1
            results.append((tverb, f"/tauri/{cmd}", lineno))
    return results
_TS_POLICY_CONST_RE = re.compile(
    r"""^[ \t]*(?:export\s+)?const\s+(?P<name>[A-Z][A-Z0-9_]{3,})\s*(?::[^=]+)?=\s*(?P<val>[^\n;]+)""",
    re.MULTILINE,
)
_UTC_SLICE_RE = re.compile(r"""\.toISOString\(\)\s*\.\s*(?:slice\(\s*0\s*,\s*10\s*\)|split\(\s*['"]T['"]\s*\))""")
_RAW_NEW_DATE_RE = re.compile(r"""\bnew\s+Date\s*\((?P<args>[^)\n]{0,80})\)""")
# `new Date().toISOString()` / `.getTime()` serialize the current *instant* (UTC `Z` or epoch
# ms): zone-free, so not a calendar "today". A sliced ISO string is caught by _UTC_SLICE_RE.
_INSTANT_ONLY_TAIL_RE = re.compile(
    r"""\s*\.\s*(?:toISOString\(\)(?!\s*\.\s*(?:slice|split|substring|substr)\b)|getTime\(\)|valueOf\(\))"""
)


def _is_raw_clock_read(txt: str, m: re.Match[str]) -> bool:
    """True when a `new Date(...)` match reads the device clock or copies an unknown date."""
    args_str = m.group("args").strip()
    if args_str == "":
        return not _INSTANT_ONLY_TAIL_RE.match(txt, m.end())
    return "," not in args_str and "Date." not in args_str

_TS_POLICY_TOKENS = (
    "CAPACITY",
    "DUTY_HOUR",
    "WORK_HOUR",
    "WORKLOAD",
    "SHIFT_CAP",
    "HOUR_LIMIT",
    "HOURS_LIMIT",
    "SUPERVISION",
    "PENALTY",
    "CLINIC_MAX",
    "CLINIC_MIN",
    "WEEKLY_MAX",
    "CALL_CAP",
    "THRESHOLD",
)
_UI_SAFE_TOKENS = ("COLOR", "STYLE", "WIDTH", "HEIGHT", "TIMEOUT", "SETTLE", "DELAY", "CAMERA", "ZOOM")
_CLOCK_UTIL_FILES = ("date-utils.ts", "clock.ts", "time.ts", "programTime.ts")


# Directories never scanned as display code: build output, server-only code, and tests,
# mocks or fixtures (matched against the path inside the frontend directory only).
_SKIP_DIR_PARTS = frozenset(
    {
        "node_modules", ".next", "out", "ui_dist", "dist", "build", "prisma", "drizzle", "server",
        "__tests__", "__mocks__", "mocks", "__fixtures__", "fixtures", "test-utils", "testing", "e2e",
        "stories", "__snapshots__",
    }
)
_GENERIC_STEMS = frozenset({"hooks", "api", "client", "types", "constants", "utils", "helpers", "index"})
_HOOK_STEM_RE = re.compile(r"^use[A-Z0-9]")


def _strip_ts_comments(source: str) -> str:
    """Remove // and /* */ comments while preserving string literals and exact line numbers."""
    cst_cleaned = blank_comments_cst(source, "tsx")
    if cst_cleaned is not None:
        return cst_cleaned
    out: list[str] = []
    i = 0
    n = len(source)
    in_str: str | None = None
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n and not (source[i] == "*" and (i + 1 < n and source[i + 1] == "/")):
                if source[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_QUERY_SUFFIX_NAMES = frozenset(
    {"query", "qs", "querystring", "querystr", "search", "searchparams", "params", "urlparams", "queryparams"}
)
_QUERY_SUFFIX_CALL_RE = re.compile(r"^[\w$.]*?(?:query|querystring|searchparams)[\w$]*\s*\(", re.IGNORECASE)
_QUOTED_QUESTION_RE = re.compile(r"""[`'"]\?""")
# `${...}` glued onto a literal segment (`/preview${suffix}`) at the end of the URL.
_GLUED_SUFFIX_RE = re.compile(r"(?i)(?:suffix|query|qs|params?|search)\s*$")


def _skip_template_expr(raw_url: str, start: int) -> int:
    """Return the index just past the `}` closing a `${` that opened before `start`."""
    depth = 1
    j = start
    n = len(raw_url)
    quote: str | None = None
    while j < n and depth > 0:
        ch = raw_url[j]
        if quote:
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        j += 1
    return j


def _is_query_suffix_expr(expr: str) -> bool:
    """True when a `${...}` that ends the URL yields a query string rather than a path segment."""
    stripped = expr.strip()
    # `${qs ? `?${qs}` : ''}` or `${p ? '?' + p : ''}` build a query string.
    if _QUOTED_QUESTION_RE.search(stripped):
        return True
    compact = stripped.replace(" ", "")
    if re.fullmatch(r"[A-Za-z_$][\w$]*", compact):
        low = compact.lower()
        return low in _QUERY_SUFFIX_NAMES or low.endswith(("querystring", "searchparams", "query", "qs"))
    if compact.endswith(".toString()") and re.fullmatch(r"[A-Za-z_$][\w$]*\.toString\(\)", compact):
        return compact.split(".", 1)[0].lower() in _QUERY_SUFFIX_NAMES or "param" in compact.lower()
    return bool(_QUERY_SUFFIX_CALL_RE.match(stripped))


def _normalize_ts_url(raw_url: str) -> str:
    """Normalize a URL literal/template: `${...}` path segments become `{param}`, query strings drop.

    A `${...}` is a path segment unless it ends the URL *and* evidently builds a query string,
    so `${params.id}`, `${encodeURIComponent(id ?? '')}` and `${searchId}` stay path segments.
    """
    out: list[str] = []
    i = 0
    n = len(raw_url)
    while i < n:
        ch = raw_url[i]
        if ch in ("?", "#"):
            break
        if ch == "$" and i + 1 < n and raw_url[i + 1] == "{":
            j = _skip_template_expr(raw_url, i + 2)
            expr = raw_url[i + 2 : j - 1]
            at_end = j >= n or raw_url[j] in ("?", "#")
            glued = bool(out) and out[-1] != "/"
            if at_end and (_is_query_suffix_expr(expr) or (glued and _GLUED_SUFFIX_RE.search(expr))):
                break
            out.append("{param}")
            i = j
            continue
        out.append(ch)
        i += 1
    cleaned = re.sub(r"/+", "/", "".join(out)).rstrip("/")
    return cleaned or "/"


def _nextjs_route_label(rel_src: str) -> str:
    parts = [
        p
        for p in Path(rel_src).parts[1:-1]
        if not (p.startswith("(") and p.endswith(")"))
    ]
    return "/" + "/".join(parts) if parts else "/"


def _resolve_ts_import(spec: str, current_file: Path, src_root: Path) -> Path | None:
    if spec.startswith("@/"):
        base = src_root / spec[2:]
    elif spec.startswith("."):
        base = (current_file.parent / spec).resolve()
    else:
        return None
    for candidate in (
        base,
        Path(f"{base}.ts"),
        Path(f"{base}.tsx"),
        base / "index.ts",
        base / "index.tsx",
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


class TypeScriptNextJsAdapter:
    """Extracts Next.js pages, components, hooks, API clients, HTTP calls, and DISP rules."""

    name = "typescript-nextjs"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        fe_dir = repo_root.resolve() if frontend_subdir in ("", ".") else (repo_root / frontend_subdir).resolve()
        src_root = (fe_dir / "src").resolve() if (fe_dir / "src").is_dir() else fe_dir
        if not fe_dir.is_dir():
            return DisplayExtractionResult(nodes=[], edges=[], http_calls=[], findings=[])

        ts_files: list[Path] = []
        barrel_targets: dict[Path, list[Path]] = {}
        cleaned_texts: dict[Path, str] = {}
        raw_texts: dict[Path, str] = {}

        scan_roots = [src_root]
        if src_root != fe_dir:
            for extra_dir in ("pages", "app"):
                if (fe_dir / extra_dir).is_dir():
                    scan_roots.append((fe_dir / extra_dir).resolve())

        seen_resolved: set[Path] = set()
        for sroot in scan_roots:
            for fpath in sorted(sroot.rglob("*")):
                if not fpath.is_file() or fpath.suffix not in (".ts", ".tsx"):
                    continue
                fe_parts = fpath.relative_to(fe_dir).parts if fpath.is_relative_to(fe_dir) else fpath.parts
                if any(p in _SKIP_DIR_PARTS for p in fe_parts[:-1]):
                    continue
                resolved = fpath.resolve()
                if resolved in seen_resolved:
                    continue
                seen_resolved.add(resolved)
                rel_src = (
                    resolved.relative_to(src_root).as_posix()
                    if resolved.is_relative_to(src_root)
                    else resolved.relative_to(fe_dir).as_posix()
                )
                if (
                    ".test." in fpath.name
                    or ".spec." in fpath.name
                    or ".stories." in fpath.name
                    or fpath.name.endswith(".d.ts")
                    or rel_src.endswith(("/route.ts", "types/api-generated.ts"))
                    or rel_src.startswith("pages/api/")
                    or rel_src in ("lib/api.ts", "app/layout.tsx")
                ):
                    continue
                try:
                    raw_txt = fpath.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                clean_txt = _strip_ts_comments(raw_txt)
                cleaned_texts[resolved] = clean_txt
                raw_texts[resolved] = raw_txt
                if fpath.name in ("index.ts", "index.tsx") and not rel_src.startswith("pages/"):
                    targets: list[Path] = []
                    for rex in (_REEXPORT_STAR_RE, _REEXPORT_NAMED_RE):
                        for m in rex.finditer(clean_txt):
                            t = _resolve_ts_import(m.group("spec"), resolved, src_root)
                            if t is not None:
                                targets.append(t)
                    barrel_targets[resolved] = targets
                    continue
                ts_files.append(resolved)

        reach: ReachabilityIndex | None = None
        local_route_patterns: list[str] = []
        try:
            reach, local_route_patterns = build_nextjs_reachability(
                fe_dir,
                src_root,
                repo_root.resolve(),
                _strip_ts_comments,
                pre_cleaned=cleaned_texts,
            )
        except (OSError, ValueError, RecursionError):
            reach = None  # reachability unknown: unbacked calls stay blocking

        nodes_by_path: dict[Path, AtlasNode] = {}
        for fpath in ts_files:
            rel_src = (
                fpath.relative_to(src_root).as_posix()
                if fpath.is_relative_to(src_root)
                else fpath.relative_to(fe_dir).as_posix()
            )
            rel_repo = fpath.relative_to(repo_root.resolve()).as_posix()
            parts = Path(rel_src).parts
            head = parts[0] if parts else ""
            stem_slug = rel_src.removesuffix(".tsx").removesuffix(".ts").replace("/", ".")

            if head == "app" and fpath.name == "page.tsx":
                route_lbl = _nextjs_route_label(rel_src)
                subkind, label, cluster, role = "page", route_lbl, "pages", "surface"
            elif head == "pages" and fpath.suffix == ".tsx" and not fpath.name.startswith("_"):
                sub_lbl = "/" + rel_src.removeprefix("pages/").removesuffix(".tsx").removesuffix("/index").removesuffix("index")
                subkind, label, cluster, role = "page", sub_lbl or "/", "pages", "surface"
            elif head in ("hooks", "store", "stores") and "services" not in parts and fpath.stem != "api":
                subkind, label, cluster, role = "hook", fpath.stem, "hooks", "surface"
            elif head in ("api", "client", "clients", "services") or "services" in parts or fpath.stem in ("api", "client"):
                subkind, label, cluster, role = "api_client", fpath.stem, "api_clients", "surface"
            elif head in ("components", "app"):
                subkind, label, cluster, role = "component", fpath.stem, head, "surface"
            elif len(parts) >= 2:
                # Feature folders, lib/, utils/, constants/ ...: same rules, named by role.
                label = f"{fpath.parent.name}/{fpath.stem}" if fpath.stem in _GENERIC_STEMS else fpath.stem
                is_hook = fpath.stem == "hooks" or bool(_HOOK_STEM_RE.match(fpath.stem))
                subkind = "hook" if is_hook else "component"
                cluster, role = head, "surface"
            else:
                continue

            nodes_by_path[fpath] = AtlasNode(
                id=f"d:{subkind}:{stem_slug}",
                tier="display",
                subkind=subkind,  # type: ignore[arg-type]
                label=label,
                source_file=rel_repo,
                line=1,
                status="clean",
                role=role,
                cluster=cluster,
                summary=f"TypeScript {subkind.replace('_', ' ')} `{label}` ({rel_repo}).",
            )

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        def add_edge(src: str, dst: str, kind: str, path: str, note: str) -> None:
            key = (src, dst, kind)
            if src == dst or key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(
                AtlasEdge(
                    id=f"e:{src}->{dst}:{kind}",
                    source_id=src,
                    target_id=dst,
                    kind=kind,  # type: ignore[arg-type]
                    verification="verified",
                    evidence_path=path,
                    evidence_note=note,
                )
            )

        for fpath, node in nodes_by_path.items():
            txt = cleaned_texts[fpath]
            rel_repo = node.source_file

            # 1. Resolve intra-tier imports (including barrel index.ts files)
            imported_Specs = [m.group("spec") for m in _IMPORT_RE.finditer(txt)]
            uses_generated_types = any("api-generated" in s for s in imported_Specs)

            for spec in imported_Specs:
                target_path = _resolve_ts_import(spec, fpath, src_root)
                if target_path is None:
                    continue
                expanded = barrel_targets.get(target_path, [target_path])
                for exp in expanded:
                    dst_node = nodes_by_path.get(exp)
                    if dst_node is None:
                        continue
                    if exp.stem not in txt and target_path != exp:
                        continue
                    kind = "uses_hook" if dst_node.subkind == "hook" else "uses_client"
                    add_edge(node.id, dst_node.id, kind, rel_repo, f"Imports `{dst_node.label}`.")

            # 2. Extract HTTP calls
            file_calls = 0
            methods_seen: list[str] = []
            paths_seen: list[str] = []
            for verb, raw_u, lineno in _extract_ts_http_calls(txt):
                norm_u = _normalize_ts_url(raw_u)
                file_calls += 1
                if verb not in methods_seen:
                    methods_seen.append(verb)
                if norm_u not in paths_seen:
                    paths_seen.append(norm_u)
                caller_sym: str | None = None
                live: bool | None = None
                trail: tuple[str, ...] = ()
                if reach is not None:
                    sym = reach.enclosing_symbol(fpath, lineno)
                    caller_sym = None if sym == MODULE_SYMBOL else sym
                    if reach.has_roots:
                        live = reach.is_live(fpath, sym)
                        trail = reach.trail(fpath, sym) if live else ()
                http_calls.append(
                    FrontendHttpCall(
                        caller_node_id=node.id,
                        http_method=verb,
                        raw_path=raw_u,
                        normalized_path=norm_u,
                        source_file=rel_repo,
                        line=lineno,
                        caller_symbol=caller_sym,
                        reachable=live,
                        reach_trail=trail,
                    )
                )
            node.http_methods = methods_seen
            node.http_paths = paths_seen[:25]

            # 3. DISP-003: API client bypassing OpenAPI-generated types
            if node.subkind == "api_client" and file_calls > 0 and not uses_generated_types:
                node.status = "gray_zone"
                findings.append(
                    RawCandidateFinding(
                        rule_code="DISP-003",
                        node_id=node.id,
                        source_file=rel_repo,
                        line=1,
                        title=f"API client `{node.label}` does not bind OpenAPI-generated types",
                        detail=f"{rel_repo} issues {file_calls} HTTP call(s) without importing `api-generated` schemas.",
                        remediation="Import schema contracts from `@/types/api-generated` (`openapi-typescript`).",
                    )
                )

            # 4. DISP-001: Client policy shadows
            active_tokens = get_active_policy_tokens()
            for m in _TS_POLICY_CONST_RE.finditer(txt):
                cname = m.group("name")
                if name_has_policy_token(cname, active_tokens) and not any(
                    safe in cname for safe in _UI_SAFE_TOKENS
                ):
                    lineno = txt.count("\n", 0, m.start()) + 1
                    node.status = "policy_in_code"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="DISP-001",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Client-side domain policy constant `{cname}`",
                            detail=f"{rel_repo}:{lineno} defines domain threshold/policy `{cname}` in TypeScript.",
                            remediation="Expose domain policy from PostgreSQL through the API response instead of duplicating in UI.",
                        )
                    )

            # 5. DISP-002: Raw browser clock / UTC ISO date slicing
            if not rel_repo.endswith(_CLOCK_UTIL_FILES):
                for m in _UTC_SLICE_RE.finditer(txt):
                    lineno = txt.count("\n", 0, m.start()) + 1
                    node.status = "duplicated_truth"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="DISP-002",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title="UTC `.toISOString()` date slicing in display code",
                            detail=f"{rel_repo}:{lineno} slices UTC ISO string into a date, shifting calendar days in non-UTC zones.",
                            remediation="Use shared program-timezone formatting helpers from `lib/clock` or `lib/date-utils`.",
                        )
                    )
                for m in _RAW_NEW_DATE_RE.finditer(txt):
                    args_str = m.group("args").strip()
                    if _is_raw_clock_read(txt, m):
                        lineno = txt.count("\n", 0, m.start()) + 1
                        if node.status == "clean":
                            node.status = "gray_zone"
                        findings.append(
                            RawCandidateFinding(
                                rule_code="DISP-002",
                                node_id=node.id,
                                source_file=rel_repo,
                                line=lineno,
                                title=f"Direct `new Date({args_str})` in display component",
                                detail=f"{rel_repo}:{lineno} constructs `Date` directly instead of using shared timezone/clock helpers.",
                                remediation="Route timestamp formatting and 'today' reads through centralized clock utilities.",
                            )
                        )

            # 6. DISP-005: WCAG static accessibility markup checks on JSX/TSX modules
            if fpath.suffix == ".tsx":
                a11y_hits = scan_a11y_markup_findings(raw_texts[fpath], node.id, rel_repo)
                if a11y_hits:
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.extend(a11y_hits)

        return DisplayExtractionResult(
            nodes=list(nodes_by_path.values()),
            edges=edges,
            http_calls=http_calls,
            findings=findings,
            local_route_patterns=local_route_patterns,
        )
