"""Tier 3 Adapter: TypeScript + Next.js App Router + TanStack Query + OpenAPI Display Graph."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.adapters.a11y_inspect import (
    _REGEX_PREV_CHARS,
    _can_start_js_regex,
    _skip_js_regex,
)
from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    RawCandidateFinding,
)
from app.adapters.treesitter_engine import (
    _CALLEE_WRAPPERS,
    _ENV_MOUNT_RHS_RE,
    _FETCH_HELPERS,
    _HTTP_VERBS,
    _MOUNT_EXPR_RE,
    _collect_cst_imported_idents,
    _collect_cst_pattern_idents,
    _collect_hoisted_cst_vars,
    _collect_mutated_cst_vars,
    _cst_static_pair_key,
    _get_parser,
    _unquote_node,
    _unwrap_cst_expr,
    blank_comments_cst,
    extract_ts_http_calls_cst,
    is_resolvable_url_const_value,
    is_same_origin_url_path,
    resolve_url_const_head,
)
from app.adapters.ts_reachability import (
    GRAPH_SUFFIXES,
    MODULE_SYMBOL,
    ReachabilityIndex,
    _ModuleInfo,
    is_nextjs_entry,
    nextjs_route_handler_patterns,
    parse_module,
)
from app.adapters.ts_sdk import WorkspaceSdkIndex
from app.adapters.ts_trpc import extract_trpc_client_calls
from app.adapters.ts_workspace import (
    WorkspaceResolver,
    extract_ts_import_bindings,
    safe_read_repo_text,
    safe_resolve_contained_path,
)
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasEdge, AtlasNode

_IMPORT_IDENT = r"[A-Za-z_$][\w$]*"
_IMPORT_BINDINGS = rf"(?:\{{[^{{}};]*\}}|\*(?:\s+as\s+{_IMPORT_IDENT})?)"
# A static declaration's binding clause cannot wander through arbitrary statements.
# In particular, `export let` plus blanked Svelte markup must not scan/backtrack to EOF.
_IMPORT_RE = re.compile(
    rf"\b(?:import\s+(?=['\"])|(?:import|export)\s+(?:type\s+)?"
    rf"(?:{_IMPORT_IDENT}(?:\s*,\s*{_IMPORT_BINDINGS})?|{_IMPORT_BINDINGS})\s+from\s+)"
    r"""(?P<quote>['"])(?P<spec>[^'"\r\n]+)(?P=quote)""",
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
    r"""\b(?:new\s+(?:window\.|globalThis\.)?(?P<es_verb>EventSource)|(?:api\.|axios\.|http\.|client\.|ky\.)?(?P<verb>get|post|put|patch|del|delete|fetch|apiRequest|request|httpClient|ofetch))\s*(?:<[^;()]{0,220}?>)?\s*\(\s*(?:[A-Za-z_$][A-Za-z0-9_$.]*\s*\?\s*)?(?P<quote>['"`])"""
)
_CONCAT_HTTP_CALL_RE = re.compile(
    r"""\b(?:new\s+(?:window\.|globalThis\.)?(?P<es_verb>EventSource)|(?:api\.|axios\.|http\.|client\.|ky\.)?(?P<verb>get|post|put|patch|del|delete|fetch|apiRequest|request|httpClient|ofetch))\s*(?:<[^;()]{0,220}?>)?\s*\(\s*(?:\(\s*)?(?P<lhs>(?:this\.)?[A-Za-z_$][\w$.]*)(?:\s*(?:\|\||\?\?)\s*(?:''|""|``)\s*\))?\s*\+\s*(?P<quote>['"`])(?P<tail>/[^'"`\n]*)(?P=quote)"""
)
_FETCH_LIKE_VERBS = frozenset({"FETCH", "APIREQUEST", "REQUEST", "HTTPCLIENT", "OFETCH"})
_VALID_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_FETCH_OPTION_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_MAX_CST_DEPTH = 4096
_MAX_CST_NODES = 250_000
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
    r"""(?P<q>['"`])(?P<val>(?:(?:/|\$\{)[^'"`\n]*)?)(?P=q)[ \t]*(?:as\s+const[ \t]*)?(?:[ \t]*/\*[^*\r\n]*\*/)*[ \t]*(?://[^\r\n]*)?(?=[;\r\n}]|$)""",
    re.MULTILINE,
)
_URL_ALIAS_CONST_RE = re.compile(
    r"""(?:^|[;{])[ \t]*(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*"""
    r"""(?P<rhs>[A-Za-z_$][\w$]*)[ \t]*(?:as\s+const[ \t]*)?(?:[ \t]*/\*[^*\r\n]*\*/)*[ \t]*(?://[^\r\n]*)?(?=[;\r\n}]|$)""",
    re.MULTILINE,
)
_TEMPLATE_HEAD_CONST_RE = re.compile(r"\$\{\s*(?P<name>[A-Za-z_$][\w$]*)\s*\}")
_URL_CALL_IDENT_RE = re.compile(
    r"""\b(?:new\s+(?:window\.|globalThis\.)?(?P<es_verb>EventSource)|(?:api\.|axios\.|http\.|client\.|ky\.)?(?P<verb>get|post|put|patch|del|delete|fetch|apiRequest|request|httpClient|ofetch))\s*(?:<[^;()]{0,220}?>)?\s*\(\s*(?P<ident>[A-Za-z_$][\w$]*)\s*[,)]"""
)
_NEXT_API_CLIENT_SUFFIXES = (
    "-client",
    "_client",
    "-api",
    "_api",
    "-service",
    "_service",
    "-transport",
    "_transport",
    "-stream",
    "_stream",
)
_NEXT_HTML_SCRIPT_RE = re.compile(r"<script\b[^>]*>(?P<body>[\s\S]*?)</script>", re.IGNORECASE)
_NEXT_HTML_MARKUP_RE = re.compile(
    r"<(?:img|button|input|select|textarea|div|span)\b[^>]*>", re.IGNORECASE
)


_GENERATOR_CONFIG_NAMES = (
    "openapi-ts.config.ts",
    "openapi-ts.config.js",
    "openapi-ts.config.mjs",
    "openapi-ts.config.cjs",
    "openapi-ts.config.json",
    "orval.config.ts",
    "orval.config.js",
    "orval.config.mjs",
)
_SCHEMA_BIND_MARKERS = (
    "api-generated",
    "openapi",
    ".schema",
    "generated/",
    "/types",
    "./types",
    ".gen",
    "@hey-api/",
    "oazapfts",
    "orval",
    "@trpc/",
    "trpc/react",
    "/trpc",
)
_GENERATED_HEADER_MARKERS = (
    "@hey-api/openapi-ts",
    "generated using oazapfts",
    "openapi-generator",
    "openapi-typescript",
    "swagger-typescript-api",
    "generated by orval",
    "auto-generated by",
    "this file has been generated",
)


def has_frontend_generator_config(fe_dir: Path, *, repo_root: Path | None = None) -> bool:
    """True when the frontend directory configures an OpenAPI client generator."""
    bound = repo_root if repo_root is not None else fe_dir
    for name in _GENERATOR_CONFIG_NAMES:
        cand = fe_dir / name
        try:
            st = cand.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            continue
        safe_c = safe_resolve_contained_path(cand, bound)
        if safe_c is not None:
            try:
                if safe_c.is_file():
                    return True
            except OSError:
                continue
    return False


def has_generated_contract_provenance(
    imported_specs: list[str],
    *,
    raw_source: str | None = None,
    source_file: str = "",
    has_generator_config: bool = False,
) -> bool:
    """True when a display client binds OpenAPI/generated contracts or is itself generator output."""
    if any(any(marker in spec for marker in _SCHEMA_BIND_MARKERS) for spec in imported_specs):
        return True
    if has_generator_config and any(
        spec == "@/client" or spec.endswith(("/client", "/client/index")) for spec in imported_specs
    ):
        return True
    if source_file.endswith((".gen.ts", ".gen.tsx", ".generated.ts", ".generated.tsx")):
        return True
    if raw_source:
        if "createTRPC" in raw_source:
            return True
        head_low = raw_source[:2000].lower()
        if any(marker in head_low for marker in _GENERATED_HEADER_MARKERS):
            return True
    return False


def _collect_url_consts(
    txt: str,
    *,
    imported_consts: dict[str, str] | None = None,
) -> dict[str, str]:
    """Top-level `const NAME = '' | '/path'` values usable as module-wide URL prefixes."""
    return _build_scoped_url_consts(txt, imported_consts=imported_consts)[0]


_LOCATION_EXPR_RE = re.compile(
    r"(?:\b(?:window|document|self|globalThis)\s*(?:\?\.)?\.\s*location\b|(?<![.\w$])location\s*(?:\?\.)?\.)"
)
_EXTERNAL_LIT_IN_EXPR_RE = re.compile(r"""['"`]\s*(?:https?:|wss?:|//)""", re.IGNORECASE)
_SAFE_STANDALONE_MOUNT_RE = re.compile(
    r"""^\s*(?:\(\s*)?(?:(?:import\.meta\.env|process\.env)\.[A-Za-z_$][\w$]*|(?:this|window|globalThis)(?:\?\.)?\.[A-Za-z_$][\w$.]*)(?:\s*(?:\?\?|\|\|)\s*(?:''|""|``))?(?:\s*\))?\s*$"""
)
_EXPR_JS_KEYWORDS = frozenset({"true", "false", "null", "undefined", "void", "typeof", "this", "super", "import"})


def _extract_leading_mount_prefix(raw_url: str) -> tuple[str, str] | None:
    """Return `(expr, tail)` when `raw_url` begins with balanced `${expr}` followed by `/...`."""
    if not raw_url.startswith("${"):
        return None
    j = _skip_template_expr(raw_url, 2)
    if j <= 2 or j > len(raw_url) or raw_url[j - 1] != "}":
        return None
    tail = raw_url[j:]
    if not tail.startswith("/") or tail.startswith("//"):
        return None
    return raw_url[2 : j - 1], tail


def _match_leading_mount_interp(txt: str, pos: int) -> int | None:
    """Return closing index just after `${...}` at `pos` when immediately followed by same-origin `/`."""
    if not txt.startswith("${", pos):
        return None
    j = _skip_template_expr(txt, pos + 2)
    if j <= pos + 2 or j > len(txt) or txt[j - 1] != "}":
        return None
    if j < len(txt) and txt[j] == "/" and not txt.startswith("//", j):
        return j
    return None


def _extract_mount_expr_root_info(expr: str) -> tuple[bool, set[str], bool]:
    """Return `(is_location, ident_roots, is_safe_mount)` for a leading template interpolation."""
    stripped = expr.strip()
    if not stripped:
        return False, set(), False
    if stripped == "location" or _LOCATION_EXPR_RE.search(stripped):
        return True, set(), False
    if _EXTERNAL_LIT_IN_EXPR_RE.search(stripped):
        return False, set(), False

    # Mask quoted strings and regexes inside `expr` before collecting root identifiers.
    chars: list[str] = []
    i = 0
    n = len(stripped)
    prev_sig = -1
    while i < n:
        ch = stripped[i]
        if ch in ("'", '"', "`"):
            q = ch
            chars.append(" ")
            i += 1
            while i < n:
                if stripped[i] == "\\":
                    chars.extend("  ")
                    i += 2
                    continue
                if stripped[i] == q:
                    chars.append(" ")
                    prev_sig = i
                    i += 1
                    break
                chars.append(" ")
                i += 1
            continue
        if ch == "/" and _can_start_js_regex(stripped, prev_sig, 0):
            rend = _skip_js_regex(stripped, i, n)
            if rend is not None:
                chars.extend(" " * (rend - i))
                prev_sig = rend - 1
                i = rend
                continue
        if not ch.isspace():
            prev_sig = i
        chars.append(ch)
        i += 1

    masked = "".join(chars)
    roots: set[str] = set()
    for im in re.finditer(r"[A-Za-z_$][\w$]*", masked):
        word = im.group(0)
        if word in _EXPR_JS_KEYWORDS:
            continue
        k = im.start() - 1
        while k >= 0 and masked[k].isspace():
            k -= 1
        if k >= 0 and masked[k] == ".":
            continue
        roots.add(word)
    return False, roots, True


def resolve_url_const_head_ext(
    url_val: str,
    url_consts: dict[str, str] | None,
    *,
    strip_unresolved_mount: bool = True,
    blocked_names: set[str] | frozenset[str] | None = None,
) -> str:
    """Expand static `${NAME}` constants and normalize unblocked leading mount-prefix interpolations."""
    if "${" not in url_val:
        return url_val
    cur = resolve_url_const_head(
        url_val,
        url_consts,
        strip_unresolved_mount=False,
        blocked_names=blocked_names,
    )
    if strip_unresolved_mount and cur.startswith("${"):
        lead = _extract_leading_mount_prefix(cur)
        if lead is not None:
            expr, tail = lead
            is_location, ident_roots, is_safe_mount = _extract_mount_expr_root_info(expr)
            is_blocked = bool(blocked_names and (ident_roots & blocked_names))
            if not is_location and is_safe_mount and not is_blocked:
                cur = tail
    return cur


def _resolve_standalone_mount_const(val: str, blocked_names: set[str] | frozenset[str] | None) -> str:
    """Resolve `const X = window.__BASE_PATH__ ?? ''` style standalone mount vars to `''` if unblocked."""
    if not (val.startswith("${") and val.endswith("}")):
        return val
    inner = val[2:-1]
    if not _SAFE_STANDALONE_MOUNT_RE.fullmatch(inner):
        return val
    is_location, ident_roots, is_safe_mount = _extract_mount_expr_root_info(inner)
    if is_location or not is_safe_mount:
        return val
    if blocked_names and (ident_roots & blocked_names):
        return val
    return ""


_FN_KW_RE = re.compile(r"\bfunction\b(?:\s*\*)?(?:\s+[A-Za-z_$][\w$]*)?")
_CATCH_KW_RE = re.compile(r"\bcatch\s*\(")
_ARROW_TOKEN_RE = re.compile(r"=>")
_METHOD_EXCLUDED_KW = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "with",
        "function",
        "return",
        "throw",
        "typeof",
        "void",
        "delete",
        "await",
        "yield",
        "new",
        "super",
        "import",
        "export",
        "else",
        "do",
        "try",
        "case",
        "of",
        "in",
        "instanceof",
        "as",
        "satisfies",
        "extends",
        "implements",
    }
)
_METHOD_MODIFIER_KW = frozenset(
    {"async", "static", "public", "private", "protected", "readonly", "override", "abstract", "get", "set"}
)
_METHOD_BAD_PREV_CHARS = frozenset(".?:=([+-*/%&|^!~<>")
_METHOD_BAD_PREV_WORDS = frozenset(
    {"return", "throw", "case", "new", "typeof", "void", "delete", "await", "yield", "else", "extends", "implements", "of", "in", "instanceof"}
)


def _find_matching_delim_reverse(txt: str, close_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 1
    i = close_idx - 1
    while i >= 0 and depth > 0:
        ch = txt[i]
        if ch == close_ch:
            depth += 1
        elif ch == open_ch:
            depth -= 1
        i -= 1
    return i + 1 if depth == 0 else -1


def _skip_optional_return_type_to_brace(code_only: str, pos: int) -> int:
    """Advance past optional `: ReturnType` (including object `{...}` types) to body `{`, or -1."""
    n = len(code_only)
    i = pos
    while i < n and code_only[i].isspace():
        i += 1
    if i < n and code_only[i] == "{":
        return i
    if i >= n or code_only[i] != ":":
        return -1
    i += 1
    pdepth = bdepth = adepth = 0
    while i < n:
        ch = code_only[i]
        if ch == "(":
            pdepth += 1
        elif ch == ")":
            pdepth = max(0, pdepth - 1)
        elif ch == "[":
            bdepth += 1
        elif ch == "]":
            bdepth = max(0, bdepth - 1)
        elif ch == "<":
            adepth += 1
        elif ch == ">" and (i == 0 or code_only[i - 1] != "="):
            adepth = max(0, adepth - 1)
        elif ch == "{":
            if pdepth == 0 and bdepth == 0 and adepth == 0:
                # Object return type `: { a: number } {` vs function body `{`:
                close_brace = _find_matching_delim(code_only, i, "{", "}")
                k = close_brace
                while k < n and code_only[k].isspace():
                    k += 1
                if k < n and code_only[k] in ("{", "|", "&", "["):
                    i = close_brace
                    continue
                return i
            else:
                i = _find_matching_delim(code_only, i, "{", "}")
                continue
        elif ch == ";" and pdepth == 0 and bdepth == 0 and adepth == 0:
            return -1
        i += 1
    return -1


def _find_arrow_params_open_paren(code_only: str, arrow_start: int) -> tuple[int, int] | None:
    """Locate `(params)` preceding `=>` at `arrow_start`, allowing `: ReturnType` in between."""
    i = arrow_start - 1
    while i >= 0 and code_only[i].isspace():
        i -= 1
    if i < 0:
        return None
    if code_only[i] == ")":
        open_p = _find_matching_delim_reverse(code_only, i, "(", ")")
        if open_p >= 0:
            return (open_p, i)
    # Walk backwards over optional `: ReturnType` (balanced `>`, `}`, `]`, `)`) to find `):`
    pdepth = bdepth = cdepth = adepth = 0
    k = i
    while k >= 0:
        ch = code_only[k]
        if ch == ")":
            pdepth += 1
        elif ch == "(":
            if pdepth == 0:
                return None
            pdepth -= 1
        elif ch == "]":
            bdepth += 1
        elif ch == "[":
            if bdepth == 0:
                return None
            bdepth -= 1
        elif ch == "}":
            cdepth += 1
        elif ch == "{":
            if cdepth == 0:
                return None
            cdepth -= 1
        elif ch == ">" and (k == 0 or code_only[k - 1] != "="):
            adepth += 1
        elif ch == "<":
            if adepth > 0:
                adepth -= 1
        elif ch == ":" and pdepth == 0 and bdepth == 0 and cdepth == 0 and adepth == 0:
            j = k - 1
            while j >= 0 and code_only[j].isspace():
                j -= 1
            if j >= 0 and code_only[j] == ")":
                open_p = _find_matching_delim_reverse(code_only, j, "(", ")")
                if open_p >= 0:
                    return (open_p, j)
            return None
        elif ch in (";", "=") and pdepth == 0 and bdepth == 0 and cdepth == 0 and adepth == 0:
            return None
        k -= 1
    return None


def _skip_ts_generic_params(code_only: str, idx: int) -> int:
    """Advance past `<...>` generic type parameters (ignoring `=>`), returning `idx` if unclosed."""
    n = len(code_only)
    if idx >= n or code_only[idx] != "<":
        return idx
    adepth = pdepth = bdepth = cdepth = 0
    i = idx
    while i < n:
        ch = code_only[i]
        if ch == "<":
            adepth += 1
        elif ch == ">" and (i == 0 or code_only[i - 1] != "="):
            if pdepth == 0 and bdepth == 0 and cdepth == 0:
                adepth -= 1
                if adepth == 0:
                    return i + 1
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
        elif ch == ";" and pdepth == 0 and bdepth == 0 and cdepth == 0:
            return idx
        i += 1
    return idx


def _is_valid_method_header_prefix(code_only: str, start_idx: int) -> bool:
    """True when text before a candidate method name allows a class/object method declaration."""
    p = start_idx - 1
    while p >= 0:
        while p >= 0 and code_only[p].isspace():
            p -= 1
        if p >= 0 and code_only[p] == "*":
            p -= 1
            continue
        if p >= 0 and (code_only[p].isalnum() or code_only[p] in ("_", "$")):
            w_end = p + 1
            while p >= 0 and (code_only[p].isalnum() or code_only[p] in ("_", "$")):
                p -= 1
            word = code_only[p + 1 : w_end]
            if word in _METHOD_MODIFIER_KW:
                continue
            return word not in _METHOD_BAD_PREV_WORDS
        break
    return p < 0 or code_only[p] not in _METHOD_BAD_PREV_CHARS


def _iter_ts_fn_and_catch_scopes(
    code_only: str,
) -> tuple[list[tuple[int, int]], list[tuple[int, int, set[str]]]]:
    """Extract `(fn_scopes, param_scopes)` with balanced type-annotation and ES6 method support."""
    n = len(code_only)
    fn_scopes: list[tuple[int, int]] = [(0, n)]
    param_scopes: list[tuple[int, int, set[str]]] = []
    fn_param_parens: set[int] = set()

    for m in _FN_KW_RE.finditer(code_only):
        i = m.end()
        while i < n and code_only[i].isspace():
            i += 1
        if i < n and code_only[i] == "<":
            i = _skip_ts_generic_params(code_only, i)
            while i < n and code_only[i].isspace():
                i += 1
        if i >= n or code_only[i] != "(":
            continue
        open_p = i
        close_p = _find_matching_delim(code_only, open_p, "(", ")")
        if close_p <= open_p:
            continue
        fn_param_parens.add(open_p)
        brace_pos = _skip_optional_return_type_to_brace(code_only, close_p)
        if brace_pos < 0:
            continue
        span = (brace_pos, _find_matching_delim(code_only, brace_pos, "{", "}"))
        fn_scopes.append(span)
        bound = _extract_param_bound_names(code_only[open_p + 1 : close_p - 1])
        if bound:
            param_scopes.append((span[0], span[1], bound))

    for m in _CATCH_KW_RE.finditer(code_only):
        open_p = m.end() - 1
        close_p = _find_matching_delim(code_only, open_p, "(", ")")
        k = close_p
        while k < n and code_only[k].isspace():
            k += 1
        if k < n and code_only[k] == "{":
            span = (k, _find_matching_delim(code_only, k, "{", "}"))
            bound = _extract_param_bound_names(code_only[open_p + 1 : close_p - 1])
            if bound:
                param_scopes.append((span[0], span[1], bound))

    for m in _ARROW_TOKEN_RE.finditer(code_only):
        arrow_start, arrow_end = m.start(), m.end()
        # Check single-identifier `param => ...` first
        j = arrow_start - 1
        while j >= 0 and code_only[j].isspace():
            j -= 1
        raw_params: str | None = None
        if j >= 0 and (code_only[j].isalnum() or code_only[j] in ("_", "$")):
            id_end = j + 1
            while j >= 0 and (code_only[j].isalnum() or code_only[j] in ("_", "$")):
                j -= 1
            ident = code_only[j + 1 : id_end]
            prev_k = j
            while prev_k >= 0 and code_only[prev_k].isspace():
                prev_k -= 1
            if (prev_k < 0 or code_only[prev_k] != ":") and ident not in (
                "async",
                "void",
                "typeof",
                "keyof",
                "readonly",
            ):
                raw_params = ident
        if raw_params is None:
            pbounds = _find_arrow_params_open_paren(code_only, arrow_start)
            if pbounds is not None and pbounds[0] not in fn_param_parens:
                raw_params = code_only[pbounds[0] + 1 : pbounds[1]]
        if raw_params is not None:
            span = (arrow_end, _find_arrow_expr_end(code_only, arrow_end))
            fn_scopes.append(span)
            bound = _extract_param_bound_names(raw_params)
            if bound:
                param_scopes.append((span[0], span[1], bound))

    for m in re.finditer(r"\b(?P<name>[A-Za-z_$][\w$]*)\b", code_only):
        name = m.group("name")
        if name in _METHOD_EXCLUDED_KW:
            continue
        i = m.end()
        while i < n and code_only[i].isspace():
            i += 1
        if i < n and code_only[i] == "<":
            nxt = _skip_ts_generic_params(code_only, i)
            if nxt == i:
                continue
            i = nxt
            while i < n and code_only[i].isspace():
                i += 1
        if i >= n or code_only[i] != "(" or i in fn_param_parens:
            continue
        if not _is_valid_method_header_prefix(code_only, m.start()):
            continue
        open_p = i
        close_p = _find_matching_delim(code_only, open_p, "(", ")")
        if close_p <= open_p:
            continue
        brace_pos = _skip_optional_return_type_to_brace(code_only, close_p)
        if brace_pos < 0:
            continue
        fn_param_parens.add(open_p)
        span = (brace_pos, _find_matching_delim(code_only, brace_pos, "{", "}"))
        fn_scopes.append(span)
        bound = _extract_param_bound_names(code_only[open_p + 1 : close_p - 1])
        if bound:
            param_scopes.append((span[0], span[1], bound))

    return fn_scopes, param_scopes
_LOCAL_BIND_RE = re.compile(r"""\b(?P<kw>const|let|var|function)\s+(?P<name>[A-Za-z_$][\w$]*)\b""")
_DESTRUCT_BIND_RE = re.compile(r"""\b(?P<kw>const|let|var)\s+(?P<pat>\{[^;\n]{1,200}\}|\[[^;\n]{1,200}\])\s*=""")
_REASSIGN_STMT_RE = re.compile(
    r"""(?:^|[;{}])[ \t]*(?P<name>[A-Za-z_$][\w$]*)\s*(?:\+\+|--|(?:\+=|-=|\?\?=|\|\|=|=(?!=)))""",
    re.MULTILINE,
)
_FOR_HEADER_RE = re.compile(r"(?<![.\w$])for\s*(?:await\s*)?\(")
_FOR_INNER_HEAD_RE = re.compile(r"(?:for\s*(?:await\s*)?|while\s*|with\s*)\(")
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
    stack: list[tuple[str, bool]] = [(pat, allow_type_colon)]
    steps = 0
    while stack and steps < 10_000:
        cur_pat, cur_allow = stack.pop()
        steps += 1
        lhs = _split_top_level_ts(cur_pat, "=")[0].strip()
        if cur_allow:
            lhs = _split_top_level_ts(lhs, ":")[0].strip()
        lhs = _PARAM_MODIFIER_RE.sub("", lhs).strip().removeprefix("...").strip().removesuffix("?").strip()
        if not lhs:
            continue
        if lhs.startswith("{") and lhs.endswith("}"):
            for prop in _split_top_level_ts(lhs[1:-1], ","):
                no_def = _split_top_level_ts(prop, "=")[0].strip()
                if not no_def:
                    continue
                kv = _split_top_level_ts(no_def, ":")
                target = kv[1] if len(kv) >= 2 else kv[0]
                stack.append((target, False))
        elif lhs.startswith("[") and lhs.endswith("]"):
            for elem in _split_top_level_ts(lhs[1:-1], ","):
                stack.append((elem, False))
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


_ARROW_CONT_TRAILING_KW_RE = re.compile(
    r"\b(?:await|typeof|void|delete|new|in|instanceof|as|satisfies|keyof|readonly|yield)$"
)
_ARROW_GENERIC_TAIL_RE = re.compile(r"<[^<>=\r\n]+>$")
_ARROW_CONT_LEADING_RE = re.compile(
    r"^(?:\.|\?|:|\|\||&&|\?\?|[|&^*%/=>]|!=|\+(?!\+)|-(?!-)|<=|<<|<(?=\s)|(?:as|satisfies|instanceof|in)\b)"
)


def _arrow_continues_across_newline(txt: str, body_start: int, nl_pos: int) -> bool:
    prefix = txt[body_start:nl_pos].rstrip(" \t")
    if not prefix:
        return True
    last = prefix[-1]
    if not prefix.endswith(("++", "--")):
        if last in "+-*/%=&|^?:.~<":
            return True
        if last == ">" and (prefix.endswith("=>") or not _ARROW_GENERIC_TAIL_RE.search(prefix)):
            return True
    if _ARROW_CONT_TRAILING_KW_RE.search(prefix):
        return True
    k = nl_pos
    n = len(txt)
    while k < n and txt[k].isspace():
        k += 1
    if k >= n:
        return False
    return bool(_ARROW_CONT_LEADING_RE.match(txt, k))


def _find_arrow_expr_end(txt: str, start: int) -> int:
    n = len(txt)
    i = start
    while i < n and txt[i].isspace():
        i += 1
    if i < n and txt[i] == "{":
        return _find_matching_delim(txt, i, "{", "}")
    body_start = i
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
        elif pdepth == 0 and bdepth == 0 and cdepth == 0:
            if ch in (";", ","):
                break
            if ch in ("\n", "\r") and not _arrow_continues_across_newline(txt, body_start, i):
                break
        i += 1
    return i


def _collect_fallback_imported_idents(code_only: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(
        r"""(?:^|[;\r\n])[ \t]*import\s+(?!type\b)(?P<clause>[^;'"\r\n]+?)\s+from\s*['"]""",
        code_only,
    ):
        clause = m.group("clause").strip()
        if "{" in clause and "}" in clause:
            before, rest = clause.split("{", 1)
            inside, _ = rest.split("}", 1)
            def_name = before.rstrip(",").strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", def_name):
                names.add(def_name)
            for raw_it in inside.split(","):
                it = raw_it.strip()
                if not it or it.startswith("type "):
                    continue
                parts = re.split(r"\s+as\s+", it, maxsplit=1)
                al = parts[-1].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", al):
                    names.add(al)
        elif "* as " in clause:
            al = clause.split("* as ", 1)[1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", al):
                names.add(al)
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", clause):
            names.add(clause)
    return names


def _apply_url_scope_map(
    outer: dict[str, str],
    bmap: dict[str, str | None],
    outer_blocked: frozenset[str] = frozenset(),
) -> tuple[dict[str, str], frozenset[str]]:
    merged = {k: v for k, v in outer.items() if k not in bmap}
    local_invalid = {k for k, v in bmap.items() if v is None}
    pending = {k: v for k, v in bmap.items() if v is not None}
    cur_blocked = (outer_blocked - set(pending)) | local_invalid
    if not pending:
        return merged, frozenset(cur_blocked)
    working = {**merged, **pending}
    for _ in range(4):
        for k in list(pending):
            working[k] = resolve_url_const_head_ext(
                working[k],
                {ok: ov for ok, ov in working.items() if ok != k and is_resolvable_url_const_value(ov)},
                strip_unresolved_mount=False,
            )
    unresolved_pending = {k for k in pending if not is_resolvable_url_const_value(working[k])}
    eff_blocked = cur_blocked | unresolved_pending
    for k in list(pending):
        resolved_val = resolve_url_const_head_ext(
            working[k],
            {ok: ov for ok, ov in working.items() if ok != k and is_resolvable_url_const_value(ov)},
            strip_unresolved_mount=True,
            blocked_names=eff_blocked,
        )
        working[k] = _resolve_standalone_mount_const(resolved_val, eff_blocked)
    final_blocked = set(cur_blocked)
    for k in pending:
        if is_resolvable_url_const_value(working[k]):
            merged[k] = working[k]
            final_blocked.discard(k)
        else:
            final_blocked.add(k)
    return merged, frozenset(final_blocked)


def _has_closing_line_quote(src: str, start: int, quote_ch: str) -> bool:
    k = start + 1
    limit = len(src)
    while k < limit:
        ch = src[k]
        if ch == "\\":
            k += 2
            continue
        if ch == quote_ch:
            return True
        if ch in ("\n", "\r"):
            return False
        k += 1
    return False


_CONST_ASSIGN_HEAD_RE = re.compile(
    r"""(?:^|[;{}])[ \t]*(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=[ \t]*""",
    re.MULTILINE,
)
_META_API_BASE_DOM_RE = re.compile(
    r"""^document\.querySelector\(\s*['"]meta\[name\s*=\s*['"]?api-base['"]?\]['"]\s*\)(?:\?\.|\.)(?:getAttribute\(\s*['"]content['"]\s*\)|content)(?:\s*(?:\?\?|\|\|)\s*(?:''|""|``))?$"""
)


def _scan_balanced_tpl_const(txt: str, start: int) -> tuple[str, int] | None:
    """Scan a single-line backtick template literal (allowing quotes inside `${...}`) at `start`."""
    n = len(txt)
    if start >= n or txt[start] != "`":
        return None
    i = start + 1
    bdepth = 0
    while i < n:
        ch = txt[i]
        if bdepth == 0:
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                return txt[start + 1 : i], i + 1
            if ch in ("\n", "\r"):
                return None
            if ch == "$" and i + 1 < n and txt[i + 1] == "{":
                bdepth = 1
                i += 2
                continue
            i += 1
        else:
            if ch in ("'", '"', "`"):
                _, i = _skip_ts_quoted(txt, i)
                continue
            if ch == "{":
                bdepth += 1
            elif ch == "}":
                bdepth -= 1
            i += 1
    return None


def _scan_const_mount_rhs(
    txt: str,
    code_only: str,
    start: int,
    *,
    html_api_base: str | None = None,
) -> str | None:
    """Extract a template literal or safe mount-prefix RHS at `start` when terminated cleanly."""
    n = len(txt)
    if start >= n:
        return None
    if txt[start] == "`":
        tpl_res = _scan_balanced_tpl_const(txt, start)
        if tpl_res is None:
            return None
        val, end_q = tpl_res
        tail_m = re.match(
            r"""[ \t]*(?:as\s+const[ \t]*)?(?:[ \t]*/\*[^*\r\n]*\*/)*[ \t]*(?://[^\r\n]*)?(?=[;\r\n}]|$)""",
            txt[end_q:],
        )
        if tail_m is None:
            return None
        if val == "" or val.startswith(("/", "${")):
            return val
        return None
    if txt[start] in ("'", '"'):
        return None
    end = start
    pdepth = 0
    quote: str | None = None
    while end < n:
        ch = txt[end]
        if quote:
            if ch == "\\":
                end += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            pdepth += 1
        elif ch == ")" and pdepth > 0:
            pdepth -= 1
        elif pdepth == 0 and (ch in (";", "\n", "\r", "}") or code_only.startswith("//", end)):
            break
        end += 1
    rhs = re.sub(r"\s+as\s+(?:string|const)\s*$", "", txt[start:end].strip())
    if not rhs:
        return None
    if html_api_base is not None and _META_API_BASE_DOM_RE.fullmatch(rhs):
        return html_api_base
    if _SAFE_STANDALONE_MOUNT_RE.fullmatch(rhs):
        return f"${{{rhs}}}"
    return None


def _build_scoped_url_consts(
    txt: str,
    *,
    imported_consts: dict[str, str] | None = None,
    html_api_base: str | None = None,
) -> tuple[dict[str, str], Callable[[int], dict[str, str]]]:
    """Return `(root_consts, consts_at)` preserving local URL constants while shadowing rebindings."""
    n = len(txt)
    root_span = (0, n)
    block_stack: list[int] = []
    tpl_brace_depths: list[int] = []
    code_chars: list[str] = []
    i = 0
    prev_sig_pos = -1
    quote: str | None = None
    block_spans: list[tuple[int, int]] = []
    while i < n:
        ch = txt[i]
        if quote in ("'", '"'):
            if ch == "\\" and i + 1 < n:
                code_chars.append(" ")
                code_chars.append("\n" if txt[i + 1] == "\n" else " ")
                i += 2
                continue
            if ch in ("\n", "\r"):
                quote = None
                code_chars.append(ch)
                i += 1
                continue
            if ch == quote:
                quote = None
                prev_sig_pos = i
                code_chars.append(ch)
            else:
                code_chars.append(" ")
            i += 1
            continue
        if quote == "`":
            if ch == "\\" and i + 1 < n:
                code_chars.append(" ")
                code_chars.append("\n" if txt[i + 1] == "\n" else " ")
                i += 2
                continue
            if ch == "`":
                quote = None
                prev_sig_pos = i
                code_chars.append("`")
                i += 1
                continue
            if ch == "$" and i + 1 < n and txt[i + 1] == "{":
                tpl_brace_depths.append(0)
                quote = None
                prev_sig_pos = i + 1
                code_chars.append(" ")
                code_chars.append(" ")
                i += 2
                continue
            code_chars.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if ch == "/" and i + 1 < n and txt[i + 1] == "/":
            while i < n and txt[i] != "\n":
                code_chars.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and txt[i + 1] == "*":
            end = txt.find("*/", i + 2)
            stop = n if end < 0 else end + 2
            while i < stop:
                code_chars.append("\n" if txt[i] == "\n" else " ")
                i += 1
            continue
        if (
            ch == "/"
            and not (i > 0 and txt[i - 1] == "<")
            and not (
                i + 1 < n
                and txt[i + 1] == ">"
                and (prev_sig_pos < 0 or txt[prev_sig_pos] not in _REGEX_PREV_CHARS)
            )
            and _can_start_js_regex(txt, prev_sig_pos, 0)
        ):
            reg_end = _skip_js_regex(txt, i, n)
            if reg_end is not None:
                code_chars.extend(" " * (reg_end - i))
                prev_sig_pos = reg_end - 1
                i = reg_end
                continue
        if ch in ("'", '"') and _has_closing_line_quote(txt, i, ch):
            quote = ch
            prev_sig_pos = i
            code_chars.append(ch)
        elif ch == "`":
            quote = "`"
            prev_sig_pos = i
            code_chars.append("`")
        elif ch == "{":
            if tpl_brace_depths:
                tpl_brace_depths[-1] += 1
            block_stack.append(i)
            prev_sig_pos = i
            code_chars.append("{")
        elif ch == "}":
            if tpl_brace_depths and tpl_brace_depths[-1] == 0:
                tpl_brace_depths.pop()
                quote = "`"
                prev_sig_pos = i
                code_chars.append(" ")
                i += 1
                continue
            if tpl_brace_depths:
                tpl_brace_depths[-1] -= 1
            if block_stack:
                bstart = block_stack.pop()
                block_spans.append((bstart, i + 1))
            prev_sig_pos = i
            code_chars.append("}")
        else:
            if not ch.isspace():
                prev_sig_pos = i
            code_chars.append(ch)
        i += 1
    code_only = "".join(code_chars)

    loop_headers: list[tuple[int, int, int]] = []
    loop_spans: list[tuple[int, int]] = []
    for fm in _FOR_HEADER_RE.finditer(code_only):
        open_p = fm.end() - 1
        close_p = _find_matching_delim(code_only, open_p, "(", ")")
        if close_p <= open_p + 1:
            continue
        loop_end = _find_ts_loop_end(code_only, close_p)
        loop_headers.append((open_p, close_p, loop_end))
        loop_spans.append((open_p, loop_end))

    lexical_spans = [*block_spans, *loop_spans]

    def innermost_lexical_block(pos: int) -> tuple[int, int]:
        return min(
            (sp for sp in lexical_spans if sp[0] < pos < sp[1]),
            key=lambda sp: sp[1] - sp[0],
            default=root_span,
        )

    block_decls: dict[tuple[int, int], dict[str, str | None]] = {}
    url_name_positions: set[int] = set()
    for m in _URL_CONST_RE.finditer(txt):
        name, val = m.group("name"), m.group("val")
        npos = m.start("name")
        if code_only[npos : m.end("name")] != name:
            continue
        url_name_positions.add(npos)
        bmap = block_decls.setdefault(innermost_lexical_block(npos), {})
        if m.group("q") != "`" and "${" in val:
            bmap[name] = None
        else:
            bmap[name] = val if bmap.get(name, val) == val else None

    for m in _CONST_ASSIGN_HEAD_RE.finditer(code_only):
        name = m.group("name")
        npos = m.start("name")
        if npos in url_name_positions:
            continue
        cand_val = _scan_const_mount_rhs(txt, code_only, m.end(), html_api_base=html_api_base)
        if cand_val is None:
            continue
        url_name_positions.add(npos)
        bmap = block_decls.setdefault(innermost_lexical_block(npos), {})
        bmap[name] = cand_val if bmap.get(name, cand_val) == cand_val else None

    for m in _URL_ALIAS_CONST_RE.finditer(code_only):
        name, rhs = m.group("name"), m.group("rhs")
        npos = m.start("name")
        if npos in url_name_positions or rhs in ("true", "false", "null", "undefined"):
            continue
        url_name_positions.add(npos)
        bmap = block_decls.setdefault(innermost_lexical_block(npos), {})
        alias_val = f"${{{rhs}}}"
        bmap[name] = alias_val if bmap.get(name, alias_val) == alias_val else None

    for m in re.finditer(
        r"""(?:^|[;{])[ \t]*(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*"""
        r"""(?:\(\s*)?(?P<lhs>(?:this\.)?[A-Za-z_$][\w$.]*)(?:\s*(?:\|\||\?\?)\s*(?:''|""|``)\s*\))?\s*\+\s*(?P<q>['"`])(?P<tail>/[^'"`\n]*)(?P=q)[ \t]*(?:as\s+const[ \t]*)?(?=[;\r\n}]|$)""",
        txt,
        re.MULTILINE,
    ):
        name, lhs_ident, tail = m.group("name"), m.group("lhs"), m.group("tail")
        npos = m.start("name")
        if npos in url_name_positions or code_only[npos : m.end("name")] != name:
            continue
        url_name_positions.add(npos)
        bmap = block_decls.setdefault(innermost_lexical_block(npos), {})
        if m.group("q") != "`" and "${" in tail:
            bmap[name] = None
        else:
            concat_val = f"${{{lhs_ident}}}{tail}"
            bmap[name] = concat_val if bmap.get(name, concat_val) == concat_val else None

    fn_scopes, param_scopes = _iter_ts_fn_and_catch_scopes(code_only)

    def innermost_fn_scope(pos: int) -> tuple[int, int]:
        return min(
            (sp for sp in fn_scopes if sp[0] <= pos < sp[1]),
            key=lambda sp: sp[1] - sp[0],
            default=root_span,
        )

    for dm in _LOCAL_BIND_RE.finditer(code_only):
        npos = dm.start("name")
        if npos in url_name_positions:
            continue
        url_name_positions.add(npos)
        target_span = (
            innermost_fn_scope(npos)
            if dm.group("kw") == "var"
            else innermost_lexical_block(npos)
        )
        block_decls.setdefault(target_span, {})[dm.group("name")] = None

    for dsm in _DESTRUCT_BIND_RE.finditer(code_only):
        dbound: set[str] = set()
        _collect_pattern_bound_names(dsm.group("pat"), dbound, allow_type_colon=True)
        if not dbound:
            continue
        target_span = (
            innermost_fn_scope(dsm.start())
            if dsm.group("kw") == "var"
            else innermost_lexical_block(dsm.start())
        )
        dmap = block_decls.setdefault(target_span, {})
        for dname in dbound:
            dmap[dname] = None

    for open_p, close_p, loop_end in loop_headers:
        hdr_kw, hdr_bound = _extract_for_header_binds(code_only[open_p + 1 : close_p - 1])
        if not hdr_bound:
            continue
        hdr_span = (open_p, loop_end) if hdr_kw in ("const", "let") else innermost_fn_scope(open_p)
        hdr_map = block_decls.setdefault(hdr_span, {})
        for bname in hdr_bound:
            if hdr_kw == "var":
                hdr_map[bname] = None
            else:
                hdr_map.setdefault(bname, None)

    for rm in _REASSIGN_STMT_RE.finditer(code_only):
        rpos = rm.start("name")
        if rpos in url_name_positions:
            continue
        if re.search(r"<[A-Za-z][\w.]*(?:\s|$)[^>]*$", code_only[max(0, rpos - 300) : rpos]):
            continue
        rname = rm.group("name")
        binding_spans = [
            sp
            for sp, bmap in block_decls.items()
            if sp[0] <= rpos < sp[1] and rname in bmap
        ] + [
            (s, e)
            for s, e, pnames in param_scopes
            if s <= rpos < e and rname in pnames
        ]
        target_span = (
            min(binding_spans, key=lambda sp: sp[1] - sp[0])
            if binding_spans
            else innermost_fn_scope(rpos)
        )
        block_decls.setdefault(target_span, {})[rname] = None

    base_outer = {
        k: v
        for k, v in (imported_consts or {}).items()
        if is_resolvable_url_const_value(v)
    }
    init_blocked = frozenset(_collect_fallback_imported_idents(code_only) - set(base_outer))
    root_consts, root_blocked = _apply_url_scope_map(
        base_outer, block_decls.get(root_span, {}), init_blocked
    )
    inner_blocks = [(s, e, bmap) for (s, e), bmap in block_decls.items() if (s, e) != root_span]

    def scope_state_at(pos: int) -> tuple[dict[str, str], frozenset[str]]:
        if not inner_blocks and not param_scopes:
            return root_consts, root_blocked
        events: list[tuple[int, int, str, Any]] = []
        for s, e, pnames in param_scopes:
            if s <= pos < e:
                events.append((e - s, 1, "params", pnames))
        for s, e, bmap in inner_blocks:
            if s <= pos < e:
                events.append((e - s, 0, "block", bmap))
        if not events:
            return root_consts, root_blocked
        events.sort(key=lambda item: (item[0], item[1]), reverse=True)
        env = dict(root_consts)
        blocked = set(root_blocked)
        for _span_len, _prio, kind, payload in events:
            if kind == "params":
                for pname in payload:
                    env.pop(pname, None)
                    blocked.add(pname)
            else:
                env, b_next = _apply_url_scope_map(env, payload, frozenset(blocked))
                blocked = set(b_next)
        return env, frozenset(blocked)

    def consts_at(pos: int) -> dict[str, str]:
        return scope_state_at(pos)[0]

    consts_at._scope_state_at = scope_state_at  # type: ignore[attr-defined]
    return root_consts, consts_at


def _find_ts_loop_end(code_only: str, after_paren: int) -> int:
    n = len(code_only)
    cur_pos = after_paren
    pending_ifs = 0
    steps = 0
    while steps < 4096:
        steps += 1
        idx = _skip_ts_ws_and_comments(code_only, cur_pos)
        if idx >= n:
            return n
        if code_only[idx] == "{":
            end_idx = _find_matching_delim(code_only, idx, "{", "}")
        elif code_only[idx] == ";":
            end_idx = idx + 1
        else:
            m_inner = _FOR_INNER_HEAD_RE.match(code_only, idx)
            if m_inner is not None:
                cur_pos = _find_matching_delim(code_only, m_inner.end() - 1, "(", ")")
                continue
            m_if = re.match(r"if\s*\(", code_only[idx:])
            if m_if is not None:
                pending_ifs += 1
                cur_pos = _find_matching_delim(code_only, idx + m_if.end() - 1, "(", ")")
                continue
            pdepth = bdepth = cdepth = 0
            quote: str | None = None
            i = idx
            end_idx = n
            while i < n:
                ch = code_only[i]
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
                    if cdepth == 0:
                        end_idx = i
                        break
                    cdepth -= 1
                elif pdepth == 0 and bdepth == 0 and cdepth == 0:
                    if ch == ";":
                        end_idx = i + 1
                        break
                    if ch in ("\n", "\r") and not _arrow_continues_across_newline(code_only, idx, i):
                        end_idx = i
                        break
                i += 1
        while pending_ifs > 0:
            pending_ifs -= 1
            after_then = _skip_ts_ws_and_comments(code_only, end_idx)
            if re.match(r"else(?![\w$])", code_only[after_then:]):
                cur_pos = after_then + 4
                break
        else:
            return end_idx
    return n


def _extract_for_header_binds(hdr: str) -> tuple[str | None, set[str]]:
    m_decl = re.match(r"^\s*(?P<kw>const|let|var)\b(?P<rest>[\s\S]*)$", hdr)
    if m_decl is None:
        return None, set()
    kw = m_decl.group("kw")
    rest = m_decl.group("rest")
    bound: set[str] = set()
    semi_parts = _split_top_level_ts(rest, ";")
    if len(semi_parts) >= 2:
        for decl in _split_top_level_ts(semi_parts[0], ","):
            _collect_pattern_bound_names(decl, bound, allow_type_colon=True)
        return kw, bound
    pdepth = bdepth = cdepth = 0
    quote: str | None = None
    k = 0
    rlen = len(rest)
    while k < rlen:
        ch = rest[k]
        if quote:
            if ch == "\\":
                k += 2
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
        elif (
            pdepth == 0
            and bdepth == 0
            and cdepth == 0
            and k > 0
            and (rest[k - 1].isspace() or rest[k - 1] in "}]")
            and re.match(r"(?:of|in)(?![\w$])", rest[k:])
        ):
            _collect_pattern_bound_names(rest[:k], bound, allow_type_colon=False)
            break
        k += 1
    return kw, bound


def _skip_ts_ws_and_comments(s: str, idx: int) -> int:
    n = len(s)
    while idx < n:
        if s[idx].isspace():
            idx += 1
        elif s.startswith("//", idx):
            nl = s.find("\n", idx + 2)
            idx = n if nl < 0 else nl + 1
        elif s.startswith("/*", idx):
            end_c = s.find("*/", idx + 2)
            idx = n if end_c < 0 else end_c + 2
        else:
            break
    return idx


def _skip_ts_quoted(s: str, idx: int) -> tuple[str | None, int]:
    """Read a static JS/TS string or template literal starting at `idx`, returning `(value_or_None, next_idx)`."""
    n = len(s)
    q = s[idx]
    j = idx + 1
    chars: list[str] = []
    dynamic = False
    if q == "`":
        tpl_bdepth: list[int] = [0]
        while j < n and tpl_bdepth:
            ch = s[j]
            if tpl_bdepth[-1] == 0:
                if ch == "\\":
                    if len(tpl_bdepth) == 1 and j + 1 < n:
                        chars.append(s[j + 1])
                    j += 2
                    continue
                if ch == "`":
                    tpl_bdepth.pop()
                    j += 1
                    if not tpl_bdepth:
                        return (None if dynamic else "".join(chars)), j
                    continue
                if ch == "$" and j + 1 < n and s[j + 1] == "{":
                    dynamic = True
                    tpl_bdepth[-1] = 1
                    j += 2
                    continue
                if len(tpl_bdepth) == 1:
                    chars.append(ch)
                j += 1
            else:
                if ch in ("'", '"'):
                    q2 = ch
                    j += 1
                    while j < n:
                        c2 = s[j]
                        if c2 == "\\":
                            j += 2
                            continue
                        if c2 == q2:
                            j += 1
                            break
                        if c2 in ("\n", "\r"):
                            break
                        j += 1
                    continue
                if ch == "`":
                    tpl_bdepth.append(0)
                    j += 1
                    continue
                if s.startswith("//", j) or s.startswith("/*", j):
                    j = _skip_ts_ws_and_comments(s, j)
                    continue
                if ch == "{":
                    tpl_bdepth[-1] += 1
                elif ch == "}":
                    tpl_bdepth[-1] -= 1
                j += 1
        return None, n
    while j < n:
        ch = s[j]
        if ch == "\\":
            if j + 1 < n:
                chars.append(s[j + 1])
            j += 2
            continue
        if ch == q:
            return "".join(chars), j + 1
        if ch in ("\n", "\r"):
            return None, j
        chars.append(ch)
        j += 1
    return None, n


def _unwrap_ts_prefix_wrappers(s: str, idx: int) -> int:
    n = len(s)
    while idx < n:
        idx = _skip_ts_ws_and_comments(s, idx)
        if idx < n and s[idx] == "(":
            idx += 1
            continue
        if idx < n and s[idx] == "<":
            close_gt = _find_matching_delim(s, idx, "<", ">")
            if close_gt > idx + 1:
                idx = close_gt
                continue
        break
    return idx


def _fetch_method_from_call_tail(txt: str, pos: int, *, at_second_arg: bool = False) -> str:
    n = len(txt)
    if at_second_arg:
        arg2_pos = pos
    else:
        k = pos + 1 if pos < n and txt[pos] in ("'", '"', "`") else pos
        pdepth = 1
        bdepth = cdepth = 0
        arg2_pos = -1
        while k < n and pdepth > 0:
            ch = txt[k]
            if ch in ("'", '"', "`"):
                _, k = _skip_ts_quoted(txt, k)
                continue
            if txt.startswith("//", k) or txt.startswith("/*", k):
                k = _skip_ts_ws_and_comments(txt, k)
                continue
            if ch == "(":
                pdepth += 1
            elif ch == ")":
                pdepth -= 1
            elif ch == "[":
                bdepth += 1
            elif ch == "]":
                bdepth = max(0, bdepth - 1)
            elif ch == "{":
                cdepth += 1
            elif ch == "}":
                cdepth = max(0, cdepth - 1)
            elif ch == "," and pdepth == 1 and bdepth == 0 and cdepth == 0:
                arg2_pos = k + 1
                break
            k += 1
        if arg2_pos < 0:
            return "GET"

    obj_pos = _unwrap_ts_prefix_wrappers(txt, arg2_pos)
    if obj_pos >= n:
        return "GET"
    if txt[obj_pos] != "{":
        if txt[obj_pos] == ")":
            return "GET"
        nullish_m = re.match(r"(?:undefined|null)(?![\w$])", txt[obj_pos:])
        if nullish_m:
            after_null = _skip_ts_ws_and_comments(txt, obj_pos + nullish_m.end())
            while after_null < n and txt[after_null] == ")":
                return "GET"
            if after_null < n and txt[after_null] == ",":
                return "GET"
        return "DYNAMIC"

    props: list[tuple[int, int]] = []
    j = obj_pos + 1
    cdepth = 1
    pdepth = bdepth = 0
    seg_start = j
    while j < n and cdepth > 0:
        ch = txt[j]
        if ch in ("'", '"', "`"):
            _, j = _skip_ts_quoted(txt, j)
            continue
        if txt.startswith("//", j) or txt.startswith("/*", j):
            j = _skip_ts_ws_and_comments(txt, j)
            continue
        if ch == "{":
            cdepth += 1
        elif ch == "}":
            cdepth -= 1
            if cdepth == 0:
                props.append((seg_start, j))
                break
        elif ch == "(":
            pdepth += 1
        elif ch == ")":
            pdepth = max(0, pdepth - 1)
        elif ch == "[":
            bdepth += 1
        elif ch == "]":
            bdepth = max(0, bdepth - 1)
        elif ch == "," and cdepth == 1 and pdepth == 0 and bdepth == 0:
            props.append((seg_start, j))
            seg_start = j + 1
        j += 1

    verb = "GET"
    for ps, pe in props:
        prop = txt[ps:pe]
        p = _skip_ts_ws_and_comments(prop, 0)
        if p >= len(prop):
            continue
        if prop.startswith("...", p):
            verb = "DYNAMIC"
            continue
        key_name: str | None = None
        if prop[p] in ("'", '"', "`"):
            key_name, p = _skip_ts_quoted(prop, p)
        elif prop[p] == "[":
            inner_p = _unwrap_ts_prefix_wrappers(prop, p + 1)
            if inner_p < len(prop) and prop[inner_p] in ("'", '"', "`"):
                key_name, inner_p = _skip_ts_quoted(prop, inner_p)
                close_b = prop.find("]", inner_p)
                p = close_b + 1 if close_b >= 0 else len(prop)
        else:
            km = re.match(r"[A-Za-z_$][\w$]*", prop[p:])
            if km:
                key_name = km.group(0)
                p += km.end()
        if key_name != "method":
            continue
        p = _skip_ts_ws_and_comments(prop, p)
        if p >= len(prop) or prop[p] != ":":
            # ES6 shorthand `{ method }` is dynamic, never static GET.
            verb = "DYNAMIC"
            continue
        val_p = _unwrap_ts_prefix_wrappers(prop, p + 1)
        if val_p < len(prop) and prop[val_p] in ("'", '"', "`"):
            raw_m, _ = _skip_ts_quoted(prop, val_p)
            cand = (
                raw_m.strip().upper()
                if raw_m is not None and not (prop[val_p] == "`" and "${" in raw_m)
                else ""
            )
            verb = cand if cand in _FETCH_OPTION_HTTP_METHODS else "DYNAMIC"
        else:
            verb = "DYNAMIC"
    return verb


_OBJECT_HTTP_CALL_START_RE = re.compile(
    r"""(?:\.(?P<dotverb>get|post|put|patch|del|delete)\b|\b(?P<fnverb>axios|fetch|ofetch|useFetch|useLazyFetch|apiRequest|request|httpClient))\s*(?:<[^;()]{0,220}?>)?\s*\(\s*\{"""
)
_FALLBACK_FETCH_VERBS = frozenset({"AXIOS", "FETCH", "OFETCH", "USEFETCH", "USELAZYFETCH", "APIREQUEST", "REQUEST", "HTTPCLIENT"})


def _extract_object_http_calls_fallback(
    txt: str,
    consts_at: Any,
) -> list[tuple[str, str, int]]:
    """Pure-Python fallback for `.verb({ url, ... })` / `request({ url, method })` SDK calls."""
    found: list[tuple[str, str, int]] = []
    n = len(txt)
    for m in _OBJECT_HTTP_CALL_START_RE.finditer(txt):
        verb_raw = (m.group("dotverb") or m.group("fnverb") or "").upper()
        verb_from_callee: str | None = None
        if verb_raw == "DEL":
            verb_from_callee = "DELETE"
        elif verb_raw in _VALID_HTTP_METHODS:
            verb_from_callee = verb_raw
        elif verb_raw not in _FALLBACK_FETCH_VERBS:
            continue
        i = m.end()
        depth = 1
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
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        if depth != 0:
            continue
        inner = txt[m.end() : i - 1]
        state_fn = getattr(consts_at, "_scope_state_at", None)
        local_consts, local_blocked = (
            state_fn(m.start()) if state_fn is not None else (consts_at(m.start()), frozenset())
        )
        url_val: str | None = None
        explicit_method: str | None = None
        method_dynamic = False
        for prop in _split_top_level_ts(inner, ","):
            prop_s = prop.strip()
            if prop_s.startswith("..."):
                if verb_from_callee is None:
                    explicit_method = "DYNAMIC"
                    method_dynamic = True
                continue
            if ":" not in prop_s:
                if re.fullmatch(r"method", prop_s):
                    explicit_method = "DYNAMIC"
                    method_dynamic = True
                continue
            key_raw, val_raw = prop_s.split(":", 1)
            key = key_raw.strip().strip("'\"")
            val = val_raw.strip()
            if key == "url":
                qm = re.match(r"""^(?P<q>['"`])(?P<u>[^'"`\r\n]*)(?P=q)""", val)
                if qm:
                    cand = qm.group("u")
                    if qm.group("q") == "`":
                        cand = resolve_url_const_head_ext(
                            cand, local_consts, blocked_names=local_blocked
                        )
                    url_val = cand if is_same_origin_url_path(cand) else None
                else:
                    url_val = None
            elif key == "method":
                mm = re.match(r"""^(?P<q>['"`])(?P<m>[A-Za-z]+)(?P=q)$""", val)
                if mm:
                    cand_m = mm.group("m").upper()
                    explicit_method = cand_m if cand_m in _FETCH_OPTION_HTTP_METHODS else "DYNAMIC"
                    method_dynamic = explicit_method == "DYNAMIC"
                else:
                    explicit_method = "DYNAMIC"
                    method_dynamic = True
        if url_val:
            final_verb = (
                explicit_method
                if explicit_method is not None and not method_dynamic
                else (verb_from_callee or explicit_method or "GET")
            )
            found.append((final_verb, url_val, txt.count("\n", 0, m.start()) + 1))
    return found


def _cst_url_template_from_expr_ext(
    raw: bytes,
    node: Any,
    depth: int = 0,
    *,
    html_api_base: str | None = None,
) -> str | None:
    """Turn a static string, template string, mount fallback, or `+` concat into a URL template."""
    if depth > 6 or node is None:
        return None
    cur = _unwrap_cst_expr(node)
    if cur is None:
        return None
    if cur.type == "string":
        val = _unquote_node(raw, cur)
        return None if "${" in val else val
    if cur.type == "template_string":
        return _unquote_node(raw, cur)
    raw_txt = raw[cur.start_byte : cur.end_byte].decode("utf-8", errors="replace").strip()
    if html_api_base is not None and _META_API_BASE_DOM_RE.fullmatch(raw_txt):
        return html_api_base
    if _ENV_MOUNT_RHS_RE.fullmatch(raw_txt):
        return ""
    if cur.type == "identifier":
        return f"${{{raw_txt}}}"
    if (
        cur.type == "member_expression"
        and _MOUNT_EXPR_RE.fullmatch(raw_txt)
        and not _LOCATION_EXPR_RE.search(raw_txt)
    ):
        return f"${{{raw_txt}}}"
    if cur.type == "binary_expression" and len(cur.named_children) >= 2:
        op_node = cur.child_by_field_name("operator") or (
            cur.children[1] if len(cur.children) >= 3 else None
        )
        op_bytes = raw[op_node.start_byte : op_node.end_byte] if op_node is not None else b""
        if op_bytes == b"+":
            left = _cst_url_template_from_expr_ext(
                raw, cur.named_children[0], depth + 1, html_api_base=html_api_base
            )
            right = _cst_url_template_from_expr_ext(
                raw, cur.named_children[1], depth + 1, html_api_base=html_api_base
            )
            if left is not None and right is not None:
                return left + right
        elif op_bytes in (b"||", b"??"):
            rhs_node = _unwrap_cst_expr(cur.named_children[1])
            if (
                rhs_node is not None
                and rhs_node.type in ("string", "template_string")
                and _unquote_node(raw, rhs_node) == ""
                and (_SAFE_STANDALONE_MOUNT_RE.fullmatch(raw_txt) or _extract_mount_expr_root_info(raw_txt)[2])
            ):
                return f"${{{raw_txt}}}"
    return None


def _merge_cst_local_consts_ext(
    outer_consts: dict[str, str],
    raw_local: dict[str, str | None],
    outer_blocked: frozenset[str] = frozenset(),
) -> tuple[dict[str, str], frozenset[str]]:
    if not raw_local:
        return outer_consts, outer_blocked
    merged = {k: v for k, v in outer_consts.items() if k not in raw_local}
    local_invalid = {k for k, v in raw_local.items() if v is None}
    pending = {k: v for k, v in raw_local.items() if v is not None}
    cur_blocked = (outer_blocked - set(pending)) | local_invalid
    if not pending:
        return merged, frozenset(cur_blocked)
    working = {**merged, **pending}
    for _ in range(4):
        for k in list(pending):
            working[k] = resolve_url_const_head_ext(
                working[k],
                {ok: ov for ok, ov in working.items() if ok != k and is_resolvable_url_const_value(ov)},
                strip_unresolved_mount=False,
            )
    unresolved_pending = {k for k in pending if not is_resolvable_url_const_value(working[k])}
    eff_blocked = cur_blocked | unresolved_pending
    for k in list(pending):
        resolved_val = resolve_url_const_head_ext(
            working[k],
            {ok: ov for ok, ov in working.items() if ok != k and is_resolvable_url_const_value(ov)},
            strip_unresolved_mount=True,
            blocked_names=eff_blocked,
        )
        working[k] = _resolve_standalone_mount_const(resolved_val, eff_blocked)
    final_blocked = set(cur_blocked)
    for k in pending:
        if is_resolvable_url_const_value(working[k]):
            merged[k] = working[k]
            final_blocked.discard(k)
        else:
            final_blocked.add(k)
    return merged, frozenset(final_blocked)


def _collect_cst_var_decl_ext(
    raw: bytes,
    decl_node: Any,
    raw_local: dict[str, str | None],
    *,
    html_api_base: str | None = None,
) -> None:
    is_const = decl_node.type == "lexical_declaration" and any(
        tok.type == "const" for tok in decl_node.children
    )
    for decl in decl_node.named_children:
        if decl.type != "variable_declarator":
            continue
        lhs = decl.child_by_field_name("name") or (decl.named_children[0] if decl.named_children else None)
        rhs = decl.child_by_field_name("value")
        val = (
            _cst_url_template_from_expr_ext(raw, rhs, html_api_base=html_api_base)
            if (is_const and rhs is not None)
            else None
        )
        if is_const and lhs is not None and lhs.type == "identifier" and val is not None:
            ident = raw[lhs.start_byte : lhs.end_byte].decode("utf-8", errors="replace")
            raw_local[ident] = val if raw_local.get(ident, val) == val else None
        elif lhs is not None:
            bound: set[str] = set()
            _collect_cst_pattern_idents(raw, lhs, bound)
            for b in bound:
                raw_local[b] = None


def _resolve_relative_api_url(
    url_val: str,
    *,
    mount_prefixes: tuple[str, ...] = (),
    html_api_base: str | None = None,
) -> str:
    if (mount_prefixes or html_api_base) and not is_same_origin_url_path(url_val) and re.match(
        r"^(?:\./)?api(?:/|$)", url_val
    ):
        return "/" + url_val.removeprefix("./")
    return url_val


def _extract_cst_fetch_method_safe(raw: bytes, opts_node: Any) -> str:
    """Extract `method` from a fetch/request options argument, preserving `"DYNAMIC"` over `"GET"`."""
    obj = _unwrap_cst_expr(opts_node)
    if obj is None:
        return "GET"
    if obj.type != "object":
        if obj.type in ("null", "undefined"):
            return "GET"
        if obj.type == "identifier" and raw[obj.start_byte : obj.end_byte] == b"undefined":
            return "GET"
        return "DYNAMIC"
    verb = "GET"
    for ch in obj.named_children:
        if ch.type == "spread_element":
            verb = "DYNAMIC"
            continue
        if ch.type == "shorthand_property_identifier":
            if raw[ch.start_byte : ch.end_byte].decode("utf-8", errors="replace") == "method":
                verb = "DYNAMIC"
            continue
        pair = _cst_static_pair_key(raw, ch)
        if pair is None or pair[0] != "method":
            continue
        val_n = _unwrap_cst_expr(pair[1])
        if (
            val_n is not None
            and val_n.type in ("string", "template_string")
            and not any(c.type == "template_substitution" for c in val_n.children)
        ):
            cm = _unquote_node(raw, val_n).strip().upper()
            verb = cm if cm in _FETCH_OPTION_HTTP_METHODS else "DYNAMIC"
        else:
            verb = "DYNAMIC"
    return verb


def _cst_dynamic_method_lines(source: str, *, is_tsx: bool = True) -> set[int]:
    """Return 1-based line numbers where CST sees a dynamic `method` expression on a fetch/axios call."""
    parser = _get_parser("tsx" if is_tsx else "ts")
    if parser is None:
        return set()
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    dyn_lines: set[int] = set()

    stack: list[tuple[Any, int]] = [(tree.root_node, 0)]
    steps = 0
    while stack and steps < _MAX_CST_NODES:
        node, depth = stack.pop()
        steps += 1
        if node.type == "call_expression" and node.children:
            fn_node = node.children[0]
            while fn_node.type in _CALLEE_WRAPPERS and fn_node.named_children:
                fn_node = fn_node.named_children[-1]
            args_n = next((c for c in node.children if c.type == "arguments"), None)
            if args_n is not None:
                arg_items = [c for c in args_n.children if c.type not in ("(", ")", ",")]
                callee_name = ""
                if fn_node.type == "identifier":
                    callee_name = raw[fn_node.start_byte : fn_node.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                elif fn_node.type == "member_expression" and fn_node.children:
                    prop_n = fn_node.children[-1]
                    callee_name = raw[prop_n.start_byte : prop_n.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                if callee_name in _FETCH_HELPERS or callee_name == "axios":
                    opts = (
                        arg_items[1]
                        if len(arg_items) >= 2
                        else (
                            arg_items[0]
                            if arg_items
                            and _unwrap_cst_expr(arg_items[0]) is not None
                            and _unwrap_cst_expr(arg_items[0]).type == "object"
                            else None
                        )
                    )
                    if opts is not None and _extract_cst_fetch_method_safe(raw, opts) == "DYNAMIC":
                        dyn_lines.add(fn_node.start_point[0] + 1)
        if depth < _MAX_CST_DEPTH:
            for ch in reversed(node.children):
                stack.append((ch, depth + 1))

    return dyn_lines


def _extract_ts_http_calls_cst_mounts(
    source: str,
    *,
    is_tsx: bool = True,
    url_consts: dict[str, str] | None = None,
    mount_prefixes: tuple[str, ...] = (),
    html_api_base: str | None = None,
) -> list[tuple[str, str, int]]:
    """Enhanced CST HTTP/EventSource extractor supporting mount-fallback exprs & companion HTML bases."""
    parser = _get_parser("tsx" if is_tsx else "ts")
    if parser is None:
        return []
    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    found: list[tuple[str, str, int]] = []
    init_consts = dict(url_consts or {})
    init_blocked = frozenset(_collect_cst_imported_idents(raw, tree.root_node) - set(init_consts))

    def apply_block(container: Any, outer_c: dict[str, str], outer_b: frozenset[str]) -> tuple[dict[str, str], frozenset[str]]:
        raw_local: dict[str, str | None] = {}
        for ch in container.named_children:
            decl_node = (
                (ch.child_by_field_name("declaration") or (ch.named_children[0] if ch.named_children else None))
                if ch.type == "export_statement"
                else ch
            )
            if decl_node is None:
                continue
            if decl_node.type in ("lexical_declaration", "variable_declaration"):
                _collect_cst_var_decl_ext(raw, decl_node, raw_local, html_api_base=html_api_base)
            elif decl_node.type in ("function_declaration", "generator_function_declaration", "class_declaration"):
                fn_id = decl_node.child_by_field_name("name")
                if fn_id is not None:
                    b_fn: set[str] = set()
                    _collect_cst_pattern_idents(raw, fn_id, b_fn)
                    for b in b_fn:
                        raw_local[b] = None
        mutated: set[str] = set()
        _collect_mutated_cst_vars(raw, container, mutated)
        for b in mutated:
            raw_local[b] = None
        return _merge_cst_local_consts_ext(outer_c, raw_local, outer_b)

    root_consts, root_blocked = apply_block(tree.root_node, init_consts, init_blocked)
    hoisted: set[str] = set()
    _collect_hoisted_cst_vars(raw, tree.root_node, hoisted)
    if hoisted:
        root_consts = {k: v for k, v in root_consts.items() if k not in hoisted}
        root_blocked = root_blocked | frozenset(hoisted)

    stack: list[tuple[Any, dict[str, str], frozenset[str], int]] = [
        (tree.root_node, root_consts, root_blocked, 0)
    ]
    steps = 0
    while stack and steps < _MAX_CST_NODES:
        node, scope_consts, scope_blocked, depth = stack.pop()
        steps += 1
        ntype = node.type
        if ntype in ("function_declaration", "generator_function_declaration", "function", "function_expression", "arrow_function", "method_definition"):
            bound: set[str] = set()
            params = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
            if params is not None:
                _collect_cst_pattern_idents(raw, params, bound)
            _collect_hoisted_cst_vars(raw, node, bound)
            if bound:
                scope_consts = {k: v for k, v in scope_consts.items() if k not in bound}
                scope_blocked = scope_blocked | frozenset(bound)
        elif ntype in ("catch_clause", "for_in_statement"):
            target_n = node.child_by_field_name("parameter" if ntype == "catch_clause" else "left")
            if target_n is not None:
                f_bound: set[str] = set()
                _collect_cst_pattern_idents(raw, target_n, f_bound)
                if f_bound:
                    scope_consts = {k: v for k, v in scope_consts.items() if k not in f_bound}
                    scope_blocked = scope_blocked | frozenset(f_bound)
        elif ntype == "for_statement":
            init_n = node.child_by_field_name("initializer")
            if init_n is not None and init_n.type in ("lexical_declaration", "variable_declaration"):
                for_local: dict[str, str | None] = {}
                _collect_cst_var_decl_ext(raw, init_n, for_local, html_api_base=html_api_base)
                for_mut: set[str] = set()
                _collect_mutated_cst_vars(raw, node, for_mut)
                for b in for_mut:
                    if b in for_local:
                        for_local[b] = None
                scope_consts, scope_blocked = _merge_cst_local_consts_ext(scope_consts, for_local, scope_blocked)
        elif ntype == "statement_block":
            scope_consts, scope_blocked = apply_block(node, scope_consts, scope_blocked)

        if ntype == "new_expression" and node.children:
            ctor_node = node.child_by_field_name("constructor") or (node.named_children[0] if node.named_children else None)
            while ctor_node is not None and ctor_node.type in _CALLEE_WRAPPERS and ctor_node.named_children:
                ctor_node = ctor_node.named_children[-1]
            ctor_name = ""
            if ctor_node is not None and ctor_node.type in ("identifier", "member_expression"):
                leaf = ctor_node if ctor_node.type == "identifier" else ctor_node.children[-1]
                ctor_name = raw[leaf.start_byte : leaf.end_byte].decode("utf-8", errors="replace")
            if ctor_name == "EventSource":
                args_n = node.child_by_field_name("arguments") or next((c for c in node.children if c.type == "arguments"), None)
                if args_n is not None:
                    arg_items = [c for c in args_n.children if c.type not in ("(", ")", ",")]
                    if arg_items:
                        tpl = _cst_url_template_from_expr_ext(raw, arg_items[0], html_api_base=html_api_base)
                        url_val = resolve_url_const_head_ext(tpl, scope_consts, blocked_names=scope_blocked) if tpl is not None else ""
                        url_val = _resolve_relative_api_url(url_val, mount_prefixes=mount_prefixes, html_api_base=html_api_base)
                        if is_same_origin_url_path(url_val):
                            found.append(("GET", url_val, ctor_node.start_point[0] + 1))

        if ntype == "call_expression" and node.children:
            fn_node = node.children[0]
            while fn_node.type in _CALLEE_WRAPPERS and fn_node.named_children:
                fn_node = fn_node.named_children[-1]
            args_n = next((c for c in node.children if c.type == "arguments"), None)
            if args_n is not None:
                arg_items = [c for c in args_n.children if c.type not in ("(", ")", ",")]
                callee_name = ""
                if fn_node.type == "identifier":
                    callee_name = raw[fn_node.start_byte : fn_node.end_byte].decode("utf-8", errors="replace")
                elif fn_node.type == "member_expression" and fn_node.children:
                    prop_n = fn_node.children[-1]
                    callee_name = raw[prop_n.start_byte : prop_n.end_byte].decode("utf-8", errors="replace")
                if arg_items:
                    tpl = _cst_url_template_from_expr_ext(raw, arg_items[0], html_api_base=html_api_base)
                    url_val = resolve_url_const_head_ext(tpl, scope_consts, blocked_names=scope_blocked) if tpl is not None else ""
                    url_val = _resolve_relative_api_url(url_val, mount_prefixes=mount_prefixes, html_api_base=html_api_base)
                    upper_c = "DELETE" if callee_name.lower() == "del" else callee_name.upper()
                    if is_same_origin_url_path(url_val):
                        if upper_c in _HTTP_VERBS:
                            found.append((upper_c, url_val, fn_node.start_point[0] + 1))
                        elif callee_name in _FETCH_HELPERS:
                            verb = (
                                _extract_cst_fetch_method_safe(raw, arg_items[1])
                                if len(arg_items) >= 2
                                else "GET"
                            )
                            found.append((verb, url_val, fn_node.start_point[0] + 1))
                    elif upper_c in _HTTP_VERBS or callee_name in _FETCH_HELPERS or callee_name == "axios":
                        obj_n = _unwrap_cst_expr(arg_items[0])
                        if obj_n is not None and obj_n.type == "object":
                            o_url: str | None = None
                            o_verb: str | None = None
                            o_dyn = False
                            for ch_o in obj_n.named_children:
                                if ch_o.type == "spread_element":
                                    if upper_c not in _HTTP_VERBS:
                                        o_verb = "DYNAMIC"
                                        o_dyn = True
                                    continue
                                if ch_o.type == "shorthand_property_identifier":
                                    if (
                                        raw[ch_o.start_byte : ch_o.end_byte].decode(
                                            "utf-8", errors="replace"
                                        )
                                        == "method"
                                    ):
                                        o_verb = "DYNAMIC"
                                        o_dyn = True
                                    continue
                                pair = _cst_static_pair_key(raw, ch_o)
                                if pair is None:
                                    continue
                                if pair[0] == "url":
                                    otpl = _cst_url_template_from_expr_ext(raw, pair[1], html_api_base=html_api_base)
                                    ocand = resolve_url_const_head_ext(otpl, scope_consts, blocked_names=scope_blocked) if otpl is not None else ""
                                    ocand = _resolve_relative_api_url(ocand, mount_prefixes=mount_prefixes, html_api_base=html_api_base)
                                    o_url = ocand if is_same_origin_url_path(ocand) else None
                                elif pair[0] == "method":
                                    val_n = _unwrap_cst_expr(pair[1])
                                    if val_n is not None and val_n.type in ("string", "template_string") and not any(c.type == "template_substitution" for c in val_n.children):
                                        cm = _unquote_node(raw, val_n).strip().upper()
                                        o_verb = cm if cm in _FETCH_OPTION_HTTP_METHODS else "DYNAMIC"
                                        o_dyn = o_verb == "DYNAMIC"
                                    else:
                                        o_verb = "DYNAMIC"
                                        o_dyn = True
                            if o_url:
                                fv = o_verb if (o_verb is not None and not o_dyn) else (upper_c if upper_c in _HTTP_VERBS else (o_verb or "GET"))
                                found.append((fv, o_url, fn_node.start_point[0] + 1))
        if depth < _MAX_CST_DEPTH:
            for ch in reversed(node.children):
                stack.append((ch, scope_consts, scope_blocked, depth + 1))

    return found


def _extract_ts_http_calls(
    txt: str,
    *,
    imported_consts: dict[str, str] | None = None,
    mount_prefixes: tuple[str, ...] = (),
    html_api_base: str | None = None,
) -> list[tuple[str, str, int]]:
    """Extract (verb, raw_url, lineno) via Tree-sitter TSX CST (with character-scanner fallback)."""
    seed_consts = (
        {k: v for k, v in imported_consts.items() if is_resolvable_url_const_value(v)}
        if imported_consts
        else None
    )
    cst_calls = extract_ts_http_calls_cst(txt, is_tsx=True, url_consts=seed_consts)
    if cst_calls is not None:
        mount_calls = _extract_ts_http_calls_cst_mounts(
            txt,
            is_tsx=True,
            url_consts=seed_consts,
            mount_prefixes=mount_prefixes,
            html_api_base=html_api_base,
        )
        dyn_lines = _cst_dynamic_method_lines(txt, is_tsx=True)
        dyn_urls_at_line = {(du, dln) for dv, du, dln in mount_calls if dv == "DYNAMIC"}
        static_mount_calls = {(mv, mu, mln) for mv, mu, mln in mount_calls if mv != "DYNAMIC"}
        dyn_lines_with_urls = {dln for _du, dln in dyn_urls_at_line}
        results: list[tuple[str, str, int]] = []
        seen_cst: set[tuple[str, str, int]] = set()
        for verb, raw_u, ln in cst_calls:
            eff_verb = (
                "DYNAMIC"
                if (
                    ((raw_u, ln) in dyn_urls_at_line and (verb, raw_u, ln) not in static_mount_calls)
                    or (verb == "GET" and ln in dyn_lines and ln not in dyn_lines_with_urls)
                )
                else verb
            )
            item = (eff_verb, raw_u, ln)
            if item not in seen_cst:
                seen_cst.add(item)
                results.append(item)
        for item in mount_calls:
            if item not in seen_cst:
                seen_cst.add(item)
                results.append(item)
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
        results.extend(extract_trpc_client_calls(txt, is_tsx=True))
        return results

    _root_consts, consts_at = _build_scoped_url_consts(
        txt, imported_consts=seed_consts, html_api_base=html_api_base
    )
    state_at = getattr(consts_at, "_scope_state_at", None)
    results = []
    n = len(txt)
    for m in _HTTP_CALL_START_RE.finditer(txt):
        local_consts, local_blocked = (
            state_at(m.start()) if state_at is not None else (consts_at(m.start()), frozenset())
        )
        is_es = m.group("es_verb") is not None
        verb = "GET" if is_es else (m.group("verb") or "GET").upper()
        if verb == "DEL":
            verb = "DELETE"
        quote = m.group("quote")
        i = m.end()
        buf: list[str] = []
        seen_heads: set[str] = set()
        while quote == "`":
            hm = _TEMPLATE_HEAD_CONST_RE.match(txt, i)
            if not hm or hm.group("name") in seen_heads or hm.group("name") not in local_consts:
                break
            seen_heads.add(hm.group("name"))
            buf.append(local_consts[hm.group("name")])
            i = hm.end()
        has_rel_api = bool(
            (mount_prefixes or html_api_base)
            and re.match(r"(?:\./)?api(?:/|$)", txt[i:])
        )
        if i >= n or (
            not buf
            and txt[i] != "/"
            and not has_rel_api
            and not (quote == "`" and _match_leading_mount_interp(txt, i) is not None)
        ):
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
        if not is_es and verb in _FETCH_LIKE_VERBS:
            verb = _fetch_method_from_call_tail(txt, i)
        raw_url = "".join(buf)
        if quote == "`":
            raw_url = resolve_url_const_head_ext(raw_url, local_consts, blocked_names=local_blocked)
        raw_url = _resolve_relative_api_url(
            raw_url, mount_prefixes=mount_prefixes, html_api_base=html_api_base
        )
        if is_same_origin_url_path(raw_url):
            lineno = txt.count("\n", 0, m.start()) + 1
            results.append((verb, raw_url, lineno))
    for cm in _CONCAT_HTTP_CALL_RE.finditer(txt):
        local_consts, local_blocked = (
            state_at(cm.start()) if state_at is not None else (consts_at(cm.start()), frozenset())
        )
        is_es_c = cm.group("es_verb") is not None
        cverb = "GET" if is_es_c else (cm.group("verb") or "GET").upper()
        if cverb == "DEL":
            cverb = "DELETE"
        elif not is_es_c and cverb in _FETCH_LIKE_VERBS:
            cverb = _fetch_method_from_call_tail(txt, cm.end() - 1)
        cand_u = resolve_url_const_head_ext(
            f"${{{cm.group('lhs')}}}{cm.group('tail')}",
            local_consts,
            blocked_names=local_blocked,
        )
        if is_same_origin_url_path(cand_u):
            results.append((cverb, cand_u, txt.count("\n", 0, cm.start()) + 1))
    for im in _URL_CALL_IDENT_RE.finditer(txt):
        local_consts = consts_at(im.start())
        ident = im.group("ident")
        if ident in local_consts and is_same_origin_url_path(local_consts[ident]):
            is_es_i = im.group("es_verb") is not None
            iverb = "GET" if is_es_i else (im.group("verb") or "GET").upper()
            if iverb == "DEL":
                iverb = "DELETE"
            elif not is_es_i and iverb in _FETCH_LIKE_VERBS:
                iverb = (
                    _fetch_method_from_call_tail(txt, im.end(), at_second_arg=True)
                    if txt[im.end() - 1] == ","
                    else "GET"
                )
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
    results.extend(_extract_object_http_calls_fallback(txt, consts_at))
    results.extend(extract_trpc_client_calls(txt, is_tsx=True))
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

_TS_POLICY_TOKENS = (  # @secret-ok static policy vocabulary
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


def _normalize_ts_url(
    raw_url: str,
    *,
    mount_prefixes: tuple[str, ...] = (),
) -> str:
    """Normalize a URL literal/template: `${...}` path segments become `{param}`, query strings drop.

    A `${...}` is a path segment unless it ends the URL *and* evidently builds a query string,
    so `${params.id}`, `${encodeURIComponent(id ?? '')}` and `${searchId}` stay path segments.
    Leading mount-prefix interpolations (`${this.apiPrefix || ""}/api/...`) and companion HTML
    mount prefixes (`<base href="/ops/">`, `<meta name="api-base" content="/ops">`) normalize away.
    """
    lead = _extract_leading_mount_prefix(raw_url)
    if lead is not None:
        expr, tail = lead
        is_location, _roots, is_safe_mount = _extract_mount_expr_root_info(expr)
        if not is_location and is_safe_mount:
            raw_url = tail
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
    if mount_prefixes and cleaned:
        for pref in sorted(mount_prefixes, key=len, reverse=True):
            if pref and not re.match(r"^/api(?:/|$)", pref) and cleaned.startswith(f"{pref}/"):
                cleaned = cleaned[len(pref) :] or "/"
                break
    return cleaned or "/"


def _nextjs_route_label(rel_src: str) -> str:
    parts = [
        p
        for p in Path(rel_src).parts[1:-1]
        if not (p.startswith("(") and p.endswith(")"))
    ]
    return "/" + "/".join(parts) if parts else "/"


def _resolve_ts_import(
    spec: str,
    current_file: Path,
    src_root: Path,
    *,
    ws_resolver: WorkspaceResolver | None = None,
    repo_root: Path | None = None,
) -> Path | None:
    bound_root = repo_root or (ws_resolver.repo_root if ws_resolver is not None else src_root)
    if spec.startswith("@/"):
        base = src_root / spec[2:]
    elif spec.startswith("."):
        base = current_file.parent / spec
    else:
        return ws_resolver.resolve_import(spec, current_file) if ws_resolver is not None else None
    candidates = [base]
    if base.suffix in (".js", ".mjs"):
        for alt in (".ts", ".tsx", ".mts"):
            candidates.append(base.with_suffix(alt))
    candidates.extend(
        (
            Path(f"{base}.ts"),
            Path(f"{base}.tsx"),
            Path(f"{base}.js"),
            Path(f"{base}.jsx"),
            Path(f"{base}.mjs"),
            base / "index.ts",
            base / "index.tsx",
            base / "index.js",
            base / "index.jsx",
            base / "index.mjs",
        )
    )
    for candidate in candidates:
        safe_cand = safe_resolve_contained_path(candidate, bound_root)
        if safe_cand is not None:
            try:
                if safe_cand.is_file():
                    return safe_cand
            except OSError:
                continue
    return ws_resolver.resolve_import(spec, current_file) if ws_resolver is not None else None


_PURE_BARREL_DIRECTIVE_RE = re.compile(
    r"""^[ \t]*['"]use\s+(?:client|strict|server)['"]\s*;?[ \t]*$""",
    re.MULTILINE,
)
_PURE_BARREL_IMPORT_RE = re.compile(
    r"""^[ \t]*import\s+(?:type\s+)?(?:[^{;\r\n]+?\s+from\s+)?['"][^'"\r\n]+['"]\s*;?[ \t]*$""",
    re.MULTILINE,
)


def _is_pure_barrel_ts(clean_txt: str, *, is_tsx: bool = True) -> bool:
    """Return True when `clean_txt` contains only directives, imports, and re-exports."""
    if not clean_txt.strip():
        return True
    parser = _get_parser("tsx" if is_tsx else "ts")
    if parser is not None:
        tree = parser.parse(clean_txt.encode("utf-8"))
        if tree.root_node.has_error:
            return False
        for ch in tree.root_node.named_children:
            ctype = ch.type
            if ctype in ("import_statement", "empty_statement", "comment"):
                continue
            if ctype == "expression_statement":
                expr = ch.named_children[0] if ch.named_children else None
                if expr is not None and expr.type == "string":
                    continue
                return False
            if ctype == "export_statement":
                if ch.child_by_field_name("declaration") is not None:
                    return False
                if ch.child_by_field_name("value") is not None:
                    return False
                if any(
                    sc.type not in ("export_clause", "namespace_export", "string", "comment", "*")
                    for sc in ch.named_children
                ):
                    return False
                continue
            return False
        return True
    rem = _PURE_BARREL_DIRECTIVE_RE.sub("", clean_txt)
    rem = _PURE_BARREL_IMPORT_RE.sub("", rem)
    rem = _REEXPORT_STAR_RE.sub("", rem)
    rem = _REEXPORT_NAMED_RE.sub("", rem)
    rem = re.sub(r"^[ \t]*export\s+(?:type\s+)?\{[^}\r\n]*\}\s*;?[ \t]*$", "", rem, flags=re.MULTILINE)
    return not re.sub(r"[\s;]+", "", rem)


def _check_ts_syntax_complete(raw_txt: str, suffix: str) -> bool:
    """Return False when CST parsing (or fallback delimiter balance) finds TS/JS syntax errors."""
    parser = _get_parser("ts" if suffix in (".ts", ".mjs") else "tsx")
    if parser is not None:
        return not parser.parse(raw_txt.encode("utf-8")).root_node.has_error
    # Linear fallback delimiter/string/comment check when Tree-sitter is absent.
    is_jsx = suffix in (".tsx", ".jsx")
    i, n = 0, len(raw_txt)
    stack: list[str] = []
    tpl_brace_depths: list[int] = []
    expr_floors: list[int] = [0]
    prev_sig_pos = -1
    in_tpl = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    closers = {")", "]", "}"}
    while i < n:
        ch = raw_txt[i]
        if in_tpl:
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                in_tpl = False
                prev_sig_pos = i
                i += 1
                continue
            if ch == "$" and i + 1 < n and raw_txt[i + 1] == "{":
                in_tpl = False
                tpl_brace_depths.append(0)
                expr_floors.append(i + 2)
                prev_sig_pos = i + 1
                i += 2
                continue
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = raw_txt[i + 1]
            if nxt == "/":
                nl = raw_txt.find("\n", i + 2)
                i = n if nl < 0 else nl + 1
                continue
            if nxt == "*":
                end_c = raw_txt.find("*/", i + 2)
                if end_c < 0:
                    return False
                i = end_c + 2
                continue
        if (
            ch == "/"
            and not (i > 0 and raw_txt[i - 1] == "<")
            and not (
                i + 1 < n
                and raw_txt[i + 1] == ">"
                and (prev_sig_pos < 0 or raw_txt[prev_sig_pos] not in _REGEX_PREV_CHARS)
            )
            and _can_start_js_regex(raw_txt, prev_sig_pos, expr_floors[-1])
        ):
            rend = _skip_js_regex(raw_txt, i, n)
            if rend is not None:
                prev_sig_pos = rend - 1
                i = rend
                continue
        if ch == "`":
            in_tpl = True
            prev_sig_pos = i
            i += 1
            continue
        if ch in ("'", '"'):
            if is_jsx and not _has_closing_line_quote(raw_txt, i, ch):
                prev_sig_pos = i
                i += 1
                continue
            quote = ch
            i += 1
            closed = False
            while i < n:
                qc = raw_txt[i]
                if qc == "\\":
                    i += 2
                    continue
                if qc == quote:
                    prev_sig_pos = i
                    i += 1
                    closed = True
                    break
                if qc in ("\r", "\n"):
                    return False
                i += 1
            if not closed:
                return False
            continue
        if ch == "{":
            if tpl_brace_depths:
                tpl_brace_depths[-1] += 1
            stack.append("}")
            expr_floors.append(i + 1)
            prev_sig_pos = i
        elif ch == "}" and tpl_brace_depths and tpl_brace_depths[-1] == 0:
            tpl_brace_depths.pop()
            if len(expr_floors) > 1:
                expr_floors.pop()
            in_tpl = True
            prev_sig_pos = i
        elif ch in pairs:
            stack.append(pairs[ch])
            prev_sig_pos = i
        elif ch in closers:
            if not stack or stack.pop() != ch:
                return False
            if ch == "}":
                if tpl_brace_depths:
                    tpl_brace_depths[-1] -= 1
                if len(expr_floors) > 1:
                    expr_floors.pop()
            prev_sig_pos = i
        elif not ch.isspace():
            prev_sig_pos = i
        i += 1
    return not in_tpl and not tpl_brace_depths and not stack


class TypeScriptNextJsAdapter:
    """Extracts Next.js pages, components, hooks, API clients, HTTP calls, and DISP rules."""

    name = "typescript-nextjs"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        from app.adapters.frontend_common import (
            build_a11y_component_resolver,
            build_frontend_url_const_resolver,
            collect_safe_graph_files,
            extract_html_mount_info,
            format_unobserved_a11y_note,
            make_safe_graph_resolver,
        )
        from app.adapters.frontend_common import (
            scan_a11y_markup_findings as scan_common_a11y_markup_findings,
        )

        try:
            if repo_root.is_symlink():
                return DisplayExtractionResult(
                    nodes=[],
                    edges=[],
                    http_calls=[],
                    findings=[],
                    coverage_complete=False,
                    notes=[f"Repository root `{repo_root}` is a symlink; display coverage is incomplete."],
                )
            repo_res = repo_root.resolve(strict=True)
            if not repo_res.is_dir():
                return DisplayExtractionResult(
                    nodes=[],
                    edges=[],
                    http_calls=[],
                    findings=[],
                    coverage_complete=False,
                    notes=[f"Repository root `{repo_root}` is not a directory; display coverage is incomplete."],
                )
            if not os.access(repo_res, os.R_OK | os.X_OK):
                raise PermissionError(f"Repository root is not readable/traversable: {repo_res}")
            with os.scandir(repo_res):
                pass
        except OSError as exc:
            return DisplayExtractionResult(
                nodes=[],
                edges=[],
                http_calls=[],
                findings=[],
                coverage_complete=False,
                notes=[f"Repository root `{repo_root}` is unreadable ({exc}); display coverage is incomplete."],
            )
        fe_dir = (
            repo_res
            if frontend_subdir in ("", ".")
            else safe_resolve_contained_path(Path(frontend_subdir), repo_root)
        )
        try:
            fe_ok = (
                fe_dir is not None
                and fe_dir.is_dir()
                and fe_dir.is_relative_to(repo_res)
                and os.access(fe_dir, os.R_OK | os.X_OK)
            )
            if fe_ok and fe_dir is not None:
                with os.scandir(fe_dir):
                    pass
        except OSError:
            fe_ok = False
        if not fe_ok or fe_dir is None:
            return DisplayExtractionResult(
                nodes=[],
                edges=[],
                http_calls=[],
                findings=[],
                coverage_complete=False,
                notes=[
                    f"Frontend directory `{frontend_subdir}` is missing, unreadable, or outside repository root; display coverage is incomplete."
                ],
            )
        coverage_complete = True
        extra_notes: list[str] = []
        raw_src = fe_dir / "src"
        src_root = fe_dir
        try:
            src_st = raw_src.lstat()
        except FileNotFoundError:
            src_st = None
        except OSError as exc:
            src_st = None
            coverage_complete = False
            extra_notes.append(f"Unreadable source root `{raw_src}` ({exc}); display coverage is incomplete.")
        if src_st is not None:
            if stat.S_ISLNK(src_st.st_mode):
                coverage_complete = False
                extra_notes.append(f"Skipped symlink source root `{raw_src}`; display coverage is incomplete.")
            elif stat.S_ISDIR(src_st.st_mode):
                safe_src = safe_resolve_contained_path(raw_src, repo_res)
                try:
                    if safe_src is not None and safe_src.is_dir():
                        if not os.access(safe_src, os.R_OK | os.X_OK):
                            raise PermissionError(f"Directory is not readable/traversable: {safe_src}")
                        src_root = safe_src
                except OSError as exc:
                    coverage_complete = False
                    extra_notes.append(f"Unreadable source root `{raw_src}` ({exc}); display coverage is incomplete.")

        _next_exts = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".html", ".htm")
        mount_errors: list[str] = []
        const_read_errors: list[str] = []
        html_mount_prefixes, html_api_base = extract_html_mount_info(
            fe_dir, src_root, repo_root=repo_res, errors_out=mount_errors
        )
        url_const_resolver = build_frontend_url_const_resolver(
            src_root,
            _next_exts,
            html_api_base=html_api_base,
            repo_root=repo_res,
            read_errors_out=const_read_errors,
        )
        comp_resolver_for = build_a11y_component_resolver(src_root, _next_exts, repo_root=repo_res)
        if mount_errors:
            coverage_complete = False
            extra_notes.extend(mount_errors)
        ws_resolver = WorkspaceResolver.build(repo_res, extra_roots=(fe_dir, src_root))
        sdk_index = WorkspaceSdkIndex.build(repo_res, ws_resolver)
        has_gen_cfg = has_frontend_generator_config(fe_dir, repo_root=repo_res)
        unobserved_a11y: list[str] = []

        ts_files: list[Path] = []
        barrel_targets: dict[Path, list[Path]] = {}
        cleaned_texts: dict[Path, str] = {}
        raw_texts: dict[Path, str] = {}

        scan_roots = [src_root]
        if src_root != fe_dir:
            for extra_dir in ("pages", "app"):
                raw_extra = fe_dir / extra_dir
                try:
                    extra_st = raw_extra.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    coverage_complete = False
                    extra_notes.append(f"Unreadable directory `{raw_extra}` ({exc}); display coverage is incomplete.")
                    continue
                if stat.S_ISLNK(extra_st.st_mode):
                    coverage_complete = False
                    extra_notes.append(f"Skipped symlink directory `{raw_extra}`; display coverage is incomplete.")
                    continue
                if stat.S_ISDIR(extra_st.st_mode):
                    safe_extra = safe_resolve_contained_path(raw_extra, repo_res)
                    try:
                        if safe_extra is not None and safe_extra.is_dir():
                            if not os.access(safe_extra, os.R_OK | os.X_OK):
                                raise PermissionError(f"Directory is not readable/traversable: {safe_extra}")
                            scan_roots.append(safe_extra)
                    except OSError as exc:
                        coverage_complete = False
                        extra_notes.append(f"Unreadable directory `{raw_extra}` ({exc}); display coverage is incomplete.")

        def _on_next_walk_err(exc: OSError) -> None:
            nonlocal coverage_complete
            coverage_complete = False
            extra_notes.append(
                f"Unreadable frontend directory `{exc.filename or fe_dir}` ({exc}); display coverage is incomplete."
            )

        seen_resolved: set[Path] = set()
        for sroot in scan_roots:
            try:
                if not sroot.is_dir() or not os.access(sroot, os.R_OK | os.X_OK):
                    coverage_complete = False
                    extra_notes.append(f"Unreadable frontend directory `{sroot}`; display coverage is incomplete.")
                    continue
            except OSError as exc:
                coverage_complete = False
                extra_notes.append(f"Unreadable frontend directory `{sroot}` ({exc}); display coverage is incomplete.")
                continue
            walked_paths: list[Path] = []
            for parent, dirs, files in os.walk(sroot, followlinks=False, onerror=_on_next_walk_err):
                parent_p = Path(parent)
                kept_dirs: list[str] = []
                for d in sorted(dirs):
                    dp = parent_p / d
                    fe_d_parts = dp.relative_to(fe_dir).parts if dp.is_relative_to(fe_dir) else dp.parts
                    if any(p in _SKIP_DIR_PARTS for p in fe_d_parts):
                        continue
                    try:
                        dst = dp.lstat()
                    except OSError as exc:
                        coverage_complete = False
                        extra_notes.append(
                            f"Unreadable frontend directory `{dp}` ({exc}); display coverage is incomplete."
                        )
                        continue
                    if stat.S_ISLNK(dst.st_mode):
                        coverage_complete = False
                        extra_notes.append(f"Skipped symlink frontend path `{dp}`; display coverage is incomplete.")
                        continue
                    if stat.S_ISDIR(dst.st_mode):
                        if not os.access(dp, os.R_OK | os.X_OK):
                            coverage_complete = False
                            extra_notes.append(
                                f"Unreadable frontend directory `{dp}`; display coverage is incomplete."
                            )
                            continue
                        kept_dirs.append(d)
                dirs[:] = kept_dirs
                for fname in sorted(files):
                    walked_paths.append(parent_p / fname)

            for fpath in sorted(walked_paths):
                fe_parts = fpath.relative_to(fe_dir).parts if fpath.is_relative_to(fe_dir) else fpath.parts
                if any(p in _SKIP_DIR_PARTS for p in fe_parts[:-1]):
                    continue
                try:
                    st = fpath.lstat()
                except OSError as exc:
                    if fpath.suffix.lower() in _next_exts:
                        coverage_complete = False
                        extra_notes.append(
                            f"Unreadable frontend path `{fpath}` ({exc}); display coverage is incomplete."
                        )
                    continue
                if stat.S_ISLNK(st.st_mode):
                    if fpath.suffix.lower() in _next_exts or not fpath.suffix:
                        coverage_complete = False
                        extra_notes.append(
                            f"Skipped symlink frontend path `{fpath}`; display coverage is incomplete."
                        )
                    continue
                if stat.S_ISDIR(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    if fpath.suffix.lower() in _next_exts:
                        coverage_complete = False
                        extra_notes.append(
                            f"Skipped non-regular frontend path `{fpath}`; display coverage is incomplete."
                        )
                    continue
                if fpath.suffix.lower() not in _next_exts:
                    continue
                resolved = safe_resolve_contained_path(fpath, repo_res)
                if resolved is None:
                    coverage_complete = False
                    extra_notes.append(
                        f"Rejected out-of-repo frontend path `{fpath}`; display coverage is incomplete."
                    )
                    continue
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
                    or fpath.name.endswith(
                        (
                            ".d.ts",
                            ".config.ts",
                            ".config.js",
                            ".config.mjs",
                            ".config.cjs",
                        )
                    )
                    or rel_src.endswith(("/route.ts", "/route.js", "types/api-generated.ts"))
                    or rel_src.startswith("pages/api/")
                ):
                    continue
                try:
                    raw_txt = safe_read_repo_text(resolved, repo_res, encoding="utf-8")
                except (OSError, UnicodeError) as exc:
                    coverage_complete = False
                    extra_notes.append(f"Unreadable frontend file `{rel_src}` ({exc}); display coverage is incomplete.")
                    continue
                if fpath.suffix.lower() not in (".html", ".htm") and not _check_ts_syntax_complete(
                    raw_txt, fpath.suffix.lower()
                ):
                    coverage_complete = False
                    extra_notes.append(
                        f"TypeScript/JavaScript parse error in `{rel_src}`; display coverage is incomplete."
                    )
                if fpath.suffix.lower() in (".html", ".htm"):
                    chars = ["\n" if ch == "\n" else " " for ch in raw_txt]
                    for sm in _NEXT_HTML_SCRIPT_RE.finditer(raw_txt):
                        bs, be = sm.span("body")
                        sc_clean = _strip_ts_comments(sm.group("body"))
                        for ci, cch in enumerate(sc_clean):
                            if bs + ci < be:
                                chars[bs + ci] = cch
                    clean_txt = "".join(chars)
                else:
                    clean_txt = _strip_ts_comments(raw_txt)
                cleaned_texts[resolved] = clean_txt
                raw_texts[resolved] = raw_txt
                if fpath.name in ("index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs") and not rel_src.startswith("pages/"):
                    targets: list[Path] = []
                    for rex in (_REEXPORT_STAR_RE, _REEXPORT_NAMED_RE):
                        for m in rex.finditer(clean_txt):
                            t = _resolve_ts_import(
                                m.group("spec"),
                                resolved,
                                src_root,
                                ws_resolver=ws_resolver,
                                repo_root=repo_res,
                            )
                            if t is not None:
                                targets.append(t)
                    barrel_targets[resolved] = targets
                    if _is_pure_barrel_ts(clean_txt, is_tsx=fpath.suffix.lower() in (".tsx", ".jsx", ".js")):
                        continue
                ts_files.append(resolved)

        reach: ReachabilityIndex | None = None
        local_route_patterns: list[str] = []
        try:
            graph_errors: list[str] = []
            graph_files = collect_safe_graph_files(fe_dir, repo_res, errors_out=graph_errors)
            known_graph = graph_files | {
                p for p in cleaned_texts if p.suffix.lower() in GRAPH_SUFFIXES
            }
            resolve_graph_import = make_safe_graph_resolver(
                fe_dir,
                src_root,
                repo_res,
                known_graph,
                ws_resolver=ws_resolver,
                errors_out=graph_errors,
            )
            if graph_errors:
                coverage_complete = False
                extra_notes.extend(graph_errors)
            modules: dict[Path, _ModuleInfo] = {}
            for gf in sorted(known_graph):
                text = cleaned_texts.get(gf)
                if text is None:
                    try:
                        raw_gf = safe_read_repo_text(gf, repo_res, encoding="utf-8")
                    except (OSError, UnicodeError, ValueError) as exc:
                        coverage_complete = False
                        extra_notes.append(
                            f"Unreadable frontend graph file `{gf}` ({exc}); display coverage is incomplete."
                        )
                        continue
                    text = _strip_ts_comments(raw_gf)
                modules[gf] = parse_module(gf, text)
            roots = {p for p in known_graph if is_nextjs_entry(p, src_root, fe_dir)}
            unreadable_graph = known_graph - modules.keys()
            if unreadable_graph:
                coverage_complete = False
            reach = ReachabilityIndex(
                modules, roots, resolve_graph_import, repo_res, unreadable_graph
            )
            local_route_patterns = nextjs_route_handler_patterns(
                sorted(known_graph), src_root, fe_dir
            )
        except (OSError, ValueError, RecursionError):
            reach = None  # reachability unknown: unbacked calls stay blocking
            coverage_complete = False

        nodes_by_path: dict[Path, AtlasNode] = {}
        for fpath in ts_files:
            rel_src = (
                fpath.relative_to(src_root).as_posix()
                if fpath.is_relative_to(src_root)
                else fpath.relative_to(fe_dir).as_posix()
            )
            rel_repo = fpath.relative_to(repo_res).as_posix()
            parts = Path(rel_src).parts
            head = parts[0] if parts else ""
            stem_low = fpath.stem.lower()
            stem_slug = Path(rel_src).with_suffix("").as_posix().replace("/", ".")
            is_client_stem = (
                stem_low in ("api", "client", "http", "queries", "transport", "sse")
                or fpath.stem.endswith(("Client", "Api", "Service", "Transport", "Stream"))
                or stem_low.endswith(_NEXT_API_CLIENT_SUFFIXES)
                or fpath.name.endswith(".gen.ts")
            )

            if head == "app" and fpath.name in ("page.tsx", "page.jsx", "page.js"):
                route_lbl = _nextjs_route_label(rel_src)
                subkind, label, cluster, role = "page", route_lbl, "pages", "surface"
            elif head == "pages" and fpath.suffix in (".tsx", ".jsx", ".js") and not fpath.name.startswith("_"):
                sub_lbl = "/" + Path(rel_src.removeprefix("pages/")).with_suffix("").as_posix().removesuffix("/index").removesuffix("index")
                subkind, label, cluster, role = "page", sub_lbl or "/", "pages", "surface"
            elif fpath.suffix.lower() in (".html", ".htm"):
                sub_lbl = "/" if stem_low in ("index", "home") else f"/{stem_low}"
                subkind, label, cluster, role = "page", sub_lbl, "pages", "surface"
            elif head in ("hooks", "store", "stores") and "services" not in parts and not is_client_stem:
                subkind, label, cluster, role = "hook", fpath.stem, "hooks", "surface"
            elif head in ("api", "client", "clients", "services", "queries") or "services" in parts or is_client_stem:
                subkind, label, cluster, role = "api_client", fpath.stem, "api_clients", "surface"
            elif head in ("components", "app"):
                subkind, label, cluster, role = "component", fpath.stem, head, "surface"
            elif len(parts) >= 2:
                # Feature folders, lib/, core/, utils/, shared/, constants/ ...: same rules, named by role.
                label = f"{fpath.parent.name}/{fpath.stem}" if fpath.stem in _GENERIC_STEMS else fpath.stem
                is_hook = fpath.stem == "hooks" or bool(_HOOK_STEM_RE.match(fpath.stem))
                subkind = "hook" if is_hook else "component"
                cluster, role = head, "surface"
            elif fpath.suffix.lower() == ".mjs":
                subkind, label, cluster, role = "api_client", fpath.stem, "api_clients", "surface"
            elif fpath.stem == "index":
                subkind = "component" if fpath.suffix.lower() in (".tsx", ".jsx") else "api_client"
                label = fpath.parent.name or "index"
                cluster, role = ("app" if subkind == "component" else "api_clients"), "surface"
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
            if reach is not None:
                nodes_by_path[fpath].summary += " " + reach.node_summary(fpath)

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        def add_edge(src: str, dst: str, kind: str, path: str, note: str, *, declared: bool = False) -> None:
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
                    verification="declared" if declared else "verified",
                    evidence_path=path,
                    evidence_note=note,
                )
            )

        page_paths = {p for p, n in nodes_by_path.items() if n.subkind == "page"}

        for fpath, node in nodes_by_path.items():
            txt = cleaned_texts[fpath]
            rel_repo = node.source_file
            try:
                # 1. Resolve intra-tier imports (including barrel index.ts files)
                imported_Specs = [m.group("spec") for m in _IMPORT_RE.finditer(txt)]
                sdk_calls, uses_typed_sdk = sdk_index.extract_caller_sdk_calls(
                    fpath,
                    txt,
                    is_tsx=fpath.suffix in (".tsx", ".jsx"),
                )
                uses_generated_types = has_generated_contract_provenance(
                    imported_Specs,
                    raw_source=raw_texts.get(fpath),
                    source_file=rel_repo,
                    has_generator_config=has_gen_cfg,
                ) or uses_typed_sdk

                for binding in extract_ts_import_bindings(txt, is_tsx=True):
                    target_path = _resolve_ts_import(
                        binding.spec,
                        fpath,
                        src_root,
                        ws_resolver=ws_resolver,
                        repo_root=repo_res,
                    )
                    if target_path is None:
                        continue
                    expanded = list(barrel_targets.get(target_path, []))
                    if (target_path in nodes_by_path or not expanded) and target_path not in expanded:
                        expanded.insert(0, target_path)
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
                extracted_calls = list(
                    _extract_ts_http_calls(
                        txt,
                        imported_consts=url_const_resolver(fpath, txt),
                        mount_prefixes=html_mount_prefixes,
                        html_api_base=html_api_base,
                    )
                )
                if sdk_calls:
                    seen_calls = set(extracted_calls)
                    for item in sdk_calls:
                        if item not in seen_calls:
                            seen_calls.add(item)
                            extracted_calls.append(item)
                for verb, raw_u, lineno in extracted_calls:
                    norm_u = _normalize_ts_url(raw_u, mount_prefixes=html_mount_prefixes)
                    file_calls += 1
                    if verb not in methods_seen:
                        methods_seen.append(verb)
                    if norm_u not in paths_seen:
                        paths_seen.append(norm_u)
                    caller_sym: str | None = None
                    live: bool | None = None
                    trail: tuple[str, ...] = ()
                    entry_ids: tuple[str, ...] = ()
                    if reach is not None:
                        sym = reach.enclosing_symbol(fpath, lineno)
                        caller_sym = None if sym == MODULE_SYMBOL else sym
                        if reach.has_roots:
                            live = reach.is_live(fpath, sym)
                            trail = reach.trail(fpath, sym) if live else ()
                            if live:
                                entry_ids = tuple(
                                    nodes_by_path[rp].id
                                    for rp in reach.reaching_roots(fpath, sym, stop_paths=page_paths)
                                    if rp in nodes_by_path
                                )
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
                            entry_node_ids=entry_ids,
                        )
                    )
                node.http_methods = methods_seen
                node.http_paths = paths_seen[:25]
                if len(paths_seen) > 25 and "total paths" not in node.summary:
                    node.summary = (
                        f"{node.summary.rstrip('.')} "
                        f"({len(paths_seen)} total paths; {len(paths_seen) - 25} omitted beyond 25-path cap)."
                    )

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

                # 6. DISP-005: WCAG static accessibility markup checks on JSX/TSX/HTML & markup templates
                if fpath.suffix.lower() in (".tsx", ".jsx", ".html", ".htm", ".ts", ".js", ".mjs"):
                    a11y_hits = scan_common_a11y_markup_findings(
                        raw_texts[fpath],
                        node.id,
                        rel_repo,
                        component_resolver=comp_resolver_for(fpath, raw_texts[fpath]),
                        unobserved_out=unobserved_a11y,
                    )
                    if a11y_hits:
                        if node.status == "clean":
                            node.status = "gray_zone"
                        findings.extend(a11y_hits)
            except RecursionError as exc:
                coverage_complete = False
                extra_notes.append(
                    f"Display extraction exceeded recursion limit in `{rel_repo}` ({exc}); display coverage is incomplete."
                )

        if const_read_errors:
            coverage_complete = False
            extra_notes.extend(dict.fromkeys(const_read_errors))

        if reach is not None:
            for source, target in reach.import_edges():
                src_node, dst_node = nodes_by_path.get(source), nodes_by_path.get(target)
                if src_node is not None and dst_node is not None:
                    kind = "uses_hook" if dst_node.subkind == "hook" else "uses_client"
                    add_edge(
                        src_node.id, dst_node.id, kind, src_node.source_file,
                        "Static entry-path dependency, including module evaluation; not proof of runtime invocation.",
                        declared=True,
                    )

        notes = reach.analysis_notes() if reach is not None else [
            "Display reachability could not be analyzed; unbacked calls remain blocking."
        ]
        if any(note.startswith("Unreadable source ") for note in notes):
            coverage_complete = False
        if extra_notes:
            notes = [*notes, *extra_notes]
        unobs_note = format_unobserved_a11y_note(unobserved_a11y)
        if unobs_note:
            notes = [*notes, unobs_note]

        return DisplayExtractionResult(
            nodes=list(nodes_by_path.values()),
            edges=edges,
            http_calls=http_calls,
            findings=findings,
            local_route_patterns=local_route_patterns,
            coverage_complete=coverage_complete,
            notes=notes,
        )
