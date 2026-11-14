"""Tier 3 Accessibility (`DISP-005`) static markup inspector for JSX/TSX, Vue, Svelte, and Rust WASM."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from app.adapters.base import RawCandidateFinding

_IMG_OPEN_RE = re.compile(r"<img\b", re.IGNORECASE)
_CLICKABLE_OPEN_RE = re.compile(r"<(?P<tag>div|span)\b")
_INPUT_OPEN_RE = re.compile(r"<(?P<tag>input|select|textarea)\b")
_BUTTON_OPEN_RE = re.compile(r"<button\b")
_LABEL_TOKEN_RE = re.compile(r"<label\b|</label\s*>")
_CLICK_ATTR_RE = re.compile(r"\b(?:onClick|on:click|@click|onclick)\s*=")
_LABEL_FOR_ATTR_RE = re.compile(r"""\b(?:htmlFor|for)\s*=\s*(?:['"](?P<id>[^'"]+)['"]|\{(?P<expr>[^}]+)\})""")
_ID_ATTR_RE = re.compile(r"""(?<![\w-])id\s*=\s*(?:['"](?P<id>[^'"]+)['"]|\{(?P<expr>[^}]+)\})""")
_HIDDEN_INPUT_RE = re.compile(r"""\btype\s*=\s*['"](?:hidden|submit|reset|button)['"]""", re.IGNORECASE)
_ICON_PKG_SPEC_RE = re.compile(
    r"^(?:lucide-react|lucide-svelte|@lucide/|@heroicons/|react-icons/|@tabler/icons|@radix-ui/react-icons|phosphor-react|@phosphor-icons/|svelte-hero-icons|svelte-lucide)"
)
_COMPONENT_IMPORT_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*import\s+(?!type\b)(?P<clause>[A-Za-z_$][\w$]*(?:\s*,\s*\{[^;{}]*\})?|\{[^;{}]*\})\s+from\s+['"](?P<spec>[^'"]+)['"]"""
)
_OPEN_TAG_SCAN_LIMIT = 8000
_REGEX_PREV_CHARS = frozenset("({[,;=!&|?+~^*%-<>:")
_REGEX_PREV_KEYWORDS = frozenset(
    {"return", "typeof", "void", "delete", "throw", "case", "in", "instanceof", "new", "yield", "await", "of", "else", "do"}
)


def _skip_js_regex(src: str, start: int, limit: int) -> int | None:
    """If `/` at `start` begins a valid single-line `/.../` regex literal, return index past flags."""
    j = start + 1
    in_class = False
    while j < limit and src[j] not in ("\n", "\r"):
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            j += 1
            while j < limit and src[j].isalpha():
                j += 1
            return j
        j += 1
    return None


def _is_property_access(src: str, before_ident: int, floor: int) -> bool:
    p = before_ident
    while p >= floor and src[p].isspace():
        p -= 1
    if p < floor or src[p] != ".":
        return False
    return not (p >= floor + 2 and src[p - 2 : p + 1] == "...")


def _can_start_js_regex(src: str, prev_sig_pos: int, expr_floor: int) -> bool:
    if prev_sig_pos < expr_floor:
        return True
    prev_ch = src[prev_sig_pos]
    if prev_ch in ("+", "-") and prev_sig_pos > expr_floor and src[prev_sig_pos - 1] == prev_ch:
        return False
    if prev_ch == "!":
        q = prev_sig_pos - 1
        while q >= expr_floor and src[q].isspace():
            q -= 1
        if q < expr_floor:
            return True
        qch = src[q]
        if qch in (")", "]", "}", "'", '"', "`"):
            return False
        if qch.isalnum() or qch in ("_", "$"):
            w = q
            while w >= expr_floor and (src[w].isalnum() or src[w] in ("_", "$")):
                w -= 1
            if _is_property_access(src, w, expr_floor):
                return False
            return src[w + 1 : q + 1] in _REGEX_PREV_KEYWORDS
        return True
    if prev_ch in _REGEX_PREV_CHARS:
        return True
    if prev_ch.isalnum() or prev_ch in ("_", "$"):
        k = prev_sig_pos
        while k >= expr_floor and (src[k].isalnum() or src[k] in ("_", "$")):
            k -= 1
        if _is_property_access(src, k, expr_floor):
            return False
        return src[k + 1 : prev_sig_pos + 1] in _REGEX_PREV_KEYWORDS
    return False


def scan_open_tag_end(src: str, pos: int) -> int | None:
    """Index just past the `>` that closes the opening tag whose attributes start at `pos`.

    A `>` inside a `{...}` expression (arrow `=>`, TS generic `as Ref<T>`, comparison `a > b`),
    a quoted attribute value, a template literal, a regex literal, or a comment does not end the
    tag. Returns None for markup that never closes within the scan limit.
    """
    n = min(len(src), pos + _OPEN_TAG_SCAN_LIMIT)
    stack: list[str] = []  # "{" for an expression, "`" for a template literal inside one
    expr_floors: list[int] = []
    prev_sig_pos = -1
    i = pos
    while i < n:
        ch = src[i]
        top = stack[-1] if stack else ""
        if top == "`":
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                stack.pop()
                prev_sig_pos = i
            elif src.startswith("${", i):
                stack.append("{")
                expr_floors.append(i + 2)
                prev_sig_pos = i + 1
                i += 2
                continue
            i += 1
            continue
        if top == "{":
            if src.startswith("//", i):
                nl = src.find("\n", i)
                i = n if nl < 0 else nl
                continue
            if src.startswith("/*", i):
                close = src.find("*/", i + 2)
                i = n if close < 0 else close + 2
                continue
            if ch in ("'", '"'):
                j = i + 1
                while j < n and src[j] not in (ch, "\n"):
                    j += 2 if src[j] == "\\" else 1
                prev_sig_pos = min(j, n - 1)
                i = j + 1
                continue
            if ch == "/" and _can_start_js_regex(src, prev_sig_pos, expr_floors[-1]):
                rx_end = _skip_js_regex(src, i, n)
                if rx_end is not None:
                    prev_sig_pos = rx_end - 1
                    i = rx_end
                    continue
            if ch == "`":
                stack.append("`")
            elif ch == "{":
                stack.append("{")
                expr_floors.append(i + 1)
                prev_sig_pos = i
            elif ch == "}":
                stack.pop()
                expr_floors.pop()
                prev_sig_pos = i
            elif not ch.isspace():
                prev_sig_pos = i
            i += 1
            continue
        if ch in ("'", '"'):
            close = src.find(ch, i + 1, n)
            if close < 0:
                return None
            i = close + 1
            continue
        if ch == "{":
            stack.append("{")
            expr_floors.append(i + 1)
            prev_sig_pos = i
        elif ch == ">":
            return i + 1
        elif ch == "<":
            return None
        i += 1
    return None


def _open_tags(src: str, pattern: re.Pattern[str]) -> list[tuple[re.Match[str], str, int]]:
    """(match, attribute text, end index) for every complete opening tag `pattern` finds."""
    tags: list[tuple[re.Match[str], str, int]] = []
    for m in pattern.finditer(src):
        end = scan_open_tag_end(src, m.end())
        if end is not None:
            tags.append((m, src[m.end() : end - 1], end))
    return tags


def _label_spans_and_targets(src: str) -> tuple[list[tuple[int, int]], set[str]]:
    """Balanced `<label>...</label>` spans (any length, nested-safe) and their `htmlFor` ids."""
    spans: list[tuple[int, int]] = []
    targets: set[str] = set()
    open_starts: list[int] = []
    for m in _LABEL_TOKEN_RE.finditer(src):
        if m.group(0).startswith("</"):
            if open_starts:
                spans.append((open_starts.pop(), m.end()))
            continue
        end = scan_open_tag_end(src, m.end())
        if end is None:
            continue
        attrs = src[m.end() : end - 1]
        fm = _LABEL_FOR_ATTR_RE.search(attrs)
        if fm:
            targets.add((fm.group("id") or fm.group("expr") or "").strip())
        if not attrs.rstrip().endswith("/"):
            open_starts.append(m.start())
    return spans, targets


def _has_svelte_shorthand(attrs: str, name: str) -> bool:
    """Find a top-level `{name}` attribute, not text inside another attribute's value."""
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(attrs):
        ch = attrs[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif depth and attrs.startswith("//", i):
            end = attrs.find("\n", i + 2)
            i = len(attrs) if end < 0 else end
            continue
        elif depth and attrs.startswith("/*", i):
            end = attrs.find("*/", i + 2)
            i = len(attrs) if end < 0 else end + 2
            continue
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "{":
            if depth == 0 and (i == 0 or attrs[i - 1].isspace()):
                match = re.match(r"\{\s*([A-Za-z_$][\w$]*)\s*\}", attrs[i:])
                if match and match.group(1) == name:
                    return True
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        i += 1
    return False


def _scan_brace_end(src: str, pos: int, limit: int | None = None) -> int | None:
    """Index just past the `}` matching `{` at `pos`, respecting JS quotes, templates, and comments."""
    if pos >= len(src) or src[pos] != "{":
        return None
    n = len(src) if limit is None else min(len(src), limit)
    stack = ["{"]
    expr_floors = [pos + 1]
    prev_sig_pos = pos
    i = pos + 1
    while i < n:
        ch = src[i]
        top = stack[-1]
        if top == "`":
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                stack.pop()
                prev_sig_pos = i
            elif src.startswith("${", i):
                stack.append("{")
                expr_floors.append(i + 2)
                prev_sig_pos = i + 1
                i += 2
                continue
            i += 1
            continue
        if src.startswith("//", i):
            nl = src.find("\n", i)
            i = n if nl < 0 else nl
            continue
        if src.startswith("/*", i):
            close = src.find("*/", i + 2)
            i = n if close < 0 else close + 2
            continue
        if ch in ("'", '"'):
            j = i + 1
            while j < n and src[j] not in (ch, "\n"):
                j += 2 if src[j] == "\\" else 1
            prev_sig_pos = min(j, n - 1)
            i = j + 1
            continue
        if ch == "/" and _can_start_js_regex(src, prev_sig_pos, expr_floors[-1]):
            rx_end = _skip_js_regex(src, i, n)
            if rx_end is not None:
                prev_sig_pos = rx_end - 1
                i = rx_end
                continue
        if ch == "`":
            stack.append("`")
        elif ch == "{":
            stack.append("{")
            expr_floors.append(i + 1)
            prev_sig_pos = i
        elif ch == "}":
            stack.pop()
            expr_floors.pop()
            if not stack:
                return i + 1
            prev_sig_pos = i
        elif not ch.isspace():
            prev_sig_pos = i
        i += 1
    return None


def _find_matching_close_tag(
    src: str, start: int, tag_name: str, *, max_span: int = 12000
) -> tuple[int, int] | None:
    """Return `(close_start, close_end)` for matching `</tag_name>`, skipping nested same-name tags."""
    n = min(len(src), start + max_span)
    tag_re = re.compile(rf"<(/?){re.escape(tag_name)}(?=\s|>|/>)")
    depth = 1
    i = start
    while i < n:
        ch = src[i]
        if ch == "{":
            bend = _scan_brace_end(src, i, n)
            i = bend if bend is not None else i + 1
            continue
        if src.startswith("<!--", i):
            cend = src.find("-->", i + 4, n)
            i = cend + 3 if cend >= 0 else n
            continue
        if ch == "<":
            m = tag_re.match(src, i)
            if m:
                if m.group(1) == "/":
                    close_gt = src.find(">", m.end(), n)
                    if close_gt < 0:
                        return None
                    depth -= 1
                    if depth == 0:
                        return m.start(), close_gt + 1
                    i = close_gt + 1
                    continue
                open_end = scan_open_tag_end(src, m.end())
                if open_end is None or open_end > n:
                    return None
                if not src[m.end() : open_end - 1].rstrip().endswith("/"):
                    depth += 1
                i = open_end
                continue
        i += 1
    return None


def js_code_mask(src: str) -> list[bool]:
    """Return per-char mask (`True` outside JS/TS comments, strings, templates, and regexes)."""
    n = len(src)
    mask = [False] * n
    stack: list[str] = []
    expr_floors = [0]
    prev_sig_pos = -1
    i = 0
    while i < n:
        ch = src[i]
        top = stack[-1] if stack else ""
        if top == "`":
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                stack.pop()
                prev_sig_pos = i
            elif src.startswith("${", i):
                stack.append("{")
                expr_floors.append(i + 2)
                prev_sig_pos = i + 1
                i += 2
                continue
            i += 1
            continue
        if src.startswith("//", i):
            nl = src.find("\n", i)
            i = n if nl < 0 else nl
            continue
        if src.startswith("/*", i):
            close = src.find("*/", i + 2)
            i = n if close < 0 else close + 2
            continue
        if ch in ("'", '"'):
            j = i + 1
            while j < n and src[j] not in (ch, "\n"):
                j += 2 if src[j] == "\\" else 1
            prev_sig_pos = min(j, n - 1)
            i = j + 1
            continue
        if ch == "/" and _can_start_js_regex(src, prev_sig_pos, expr_floors[-1]):
            rend = _skip_js_regex(src, i, n)
            if rend is not None:
                prev_sig_pos = rend - 1
                i = rend
                continue
        if ch == "`":
            stack.append("`")
            i += 1
            continue
        mask[i] = True
        if ch == "{":
            stack.append("{")
            expr_floors.append(i + 1)
        elif ch == "}" and stack and stack[-1] == "{":
            stack.pop()
            if len(expr_floors) > 1:
                expr_floors.pop()
        if not ch.isspace():
            prev_sig_pos = i
        i += 1
    return mask


def is_js_module_stmt_in_code(src: str, mask: list[bool], match: re.Match[str]) -> bool:
    """Return True when a module `import`/`export` regex match sits in real JS/TS code."""
    pos = match.start()
    end = match.end()
    while pos < end and (src[pos].isspace() or src[pos] in ";{}"):
        pos += 1
    if pos >= end or not mask[pos]:
        return False
    if "spec" in match.groupdict():
        spec_quote = match.start("spec") - 1
        if spec_quote <= pos:
            return False
        return all(mask[k] or src[k].isspace() for k in range(pos, spec_quote))
    return all(mask[k] or src[k].isspace() for k in range(pos, end))


def parse_component_imports(raw_source: str) -> dict[str, tuple[str, str]]:
    """Map imported local component identifier -> `(module_spec, exported_name)`."""
    script_blocks = [sm.group("body") for sm in _SCRIPT_BLOCK_RE.finditer(raw_source)]
    scan_src = "\n".join(script_blocks) if script_blocks else raw_source
    mask = js_code_mask(scan_src)
    mapping: dict[str, tuple[str, str]] = {}
    for m in _COMPONENT_IMPORT_RE.finditer(scan_src):
        if not is_js_module_stmt_in_code(scan_src, mask, m):
            continue
        clause = m.group("clause").strip()
        spec = m.group("spec").strip()
        if not spec or clause.startswith("type "):
            continue
        brace_idx = clause.find("{")
        if brace_idx >= 0:
            default_part = clause[:brace_idx].rstrip(" ,")
            if default_part and re.fullmatch(r"[A-Za-z_$][\w$]*", default_part):
                mapping[default_part] = (spec, "default")
            end_brace = clause.rfind("}")
            inner = clause[brace_idx + 1 : end_brace] if end_brace > brace_idx else ""
            for raw_item in inner.split(","):
                item = raw_item.strip()
                if not item or item.startswith("type "):
                    continue
                parts = re.split(r"\s+as\s+", item, maxsplit=1)
                orig = parts[0].strip()
                local = parts[1].strip() if len(parts) == 2 else orig
                if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                    mapping[local] = (spec, orig)
        elif "*" not in clause and re.fullmatch(r"[A-Za-z_$][\w$]*", clause):
            mapping[clause] = (spec, "default")
    return mapping


def _eval_attr_value(expr: str, *, preserve_undefined: bool = False) -> str:
    s = expr.strip()
    if preserve_undefined and s == "undefined":
        return "undefined"
    if s in ("", "''", '""', "``", "null", "undefined", "false", "true"):
        return "empty"
    if len(s) >= 2 and s[0] in ("'", '"') and s[-1] == s[0]:
        return "named" if s[1:-1].strip() else "empty"
    return "dynamic"


def _split_top_level_js(src: str, sep: str = ",") -> list[str]:
    """Split JS argument/object/pattern list on `sep` at bracket depth 0 outside strings."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            parts.append(src[start:i])
            start = i + 1
        i += 1
    parts.append(src[start:])
    return parts


def _split_first_top_level_js(src: str, sep: str) -> tuple[str, str | None]:
    """Split on first top-level `sep`, returning `(left, right_or_none)`."""
    depth = 0
    quote: str | None = None
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            return src[:i], src[i + 1 :]
        i += 1
    return src, None


def _extract_prop_attrs(attrs: str) -> tuple[dict[str, str], bool, set[str]]:
    """Parse JSX/Svelte component attrs into `(props, has_opaque_spread, explicit_after_spread)`."""
    props: dict[str, str] = {}
    has_opaque_spread = False
    explicit_after_spread: set[str] = set()

    def mark_opaque_spread() -> None:
        nonlocal has_opaque_spread
        has_opaque_spread = True
        explicit_after_spread.clear()
        for existing_k, existing_v in list(props.items()):
            if existing_v == "empty":
                props[existing_k] = "opaque"

    i = 0
    n = len(attrs)
    while i < n:
        while i < n and (attrs[i].isspace() or attrs[i] == "/"):
            i += 1
        if i >= n:
            break
        if attrs[i] == "{":
            bend = _scan_brace_end(attrs, i)
            if bend is not None:
                inner = attrs[i + 1 : bend - 1].strip()
                if inner.startswith("..."):
                    spread_expr = inner[3:].strip()
                    if spread_expr.startswith("{") and spread_expr.endswith("}"):
                        for entry in _split_top_level_js(spread_expr[1:-1], ","):
                            entry = entry.strip()
                            if not entry:
                                continue
                            if entry.startswith("..."):
                                mark_opaque_spread()
                                continue
                            raw_k, raw_v = _split_first_top_level_js(entry, ":")
                            if raw_v is not None:
                                skey = raw_k.strip().strip("'\"")
                                if re.fullmatch(r"[A-Za-z_$][\w$.-]*", skey):
                                    props[skey] = _eval_attr_value(raw_v, preserve_undefined=True)
                                    if has_opaque_spread:
                                        explicit_after_spread.add(skey)
                            elif re.fullmatch(r"[A-Za-z_$][\w$]*", entry):
                                props[entry] = "dynamic"
                                if has_opaque_spread:
                                    explicit_after_spread.add(entry)
                    else:
                        mark_opaque_spread()
                elif re.fullmatch(r"[A-Za-z_$][\w$]*", inner):
                    props[inner] = "dynamic"
                    if has_opaque_spread:
                        explicit_after_spread.add(inner)
                i = bend
                continue
            i += 1
            continue
        km = re.match(r"([A-Za-z_$][\w$.-]*)", attrs[i:])
        if not km:
            i += 1
            continue
        key = km.group(1)
        i += km.end()
        while i < n and attrs[i].isspace():
            i += 1
        if i >= n or attrs[i] != "=":
            continue
        i += 1
        while i < n and attrs[i].isspace():
            i += 1
        if i >= n:
            break
        if attrs[i] in ("'", '"'):
            q = attrs[i]
            j = i + 1
            while j < n and attrs[j] != q:
                j += 2 if attrs[j] == "\\" else 1
            val = attrs[i + 1 : j]
            props[key] = "named" if val.strip() else "empty"
            if has_opaque_spread:
                explicit_after_spread.add(key)
            i = min(j + 1, n)
        elif attrs[i] == "{":
            bend = _scan_brace_end(attrs, i)
            if bend is None:
                break
            props[key] = _eval_attr_value(
                attrs[i + 1 : bend - 1], preserve_undefined=True
            )
            if has_opaque_spread:
                explicit_after_spread.add(key)
            i = bend
    return props, has_opaque_spread, explicit_after_spread


_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(?P<body>[\s\S]*?)</script>", re.IGNORECASE)
_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>[\s\S]*?</style>", re.IGNORECASE)
_VUE_TPL_RE = re.compile(r"<template\b[^>]*>(?P<body>[\s\S]*)</template>", re.IGNORECASE)
_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
_IDENT_TOKEN_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")


def _parse_default_params(raw_params: str) -> tuple[dict[str, str], dict[str, str]]:
    """Extract `(local_defaults, local_to_source_prop)` respecting destructuring aliases."""
    defaults: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for raw_part in _split_top_level_js(raw_params, ","):
        item = raw_part.strip()
        if not item or item.startswith("..."):
            continue
        lhs_raw, rhs_raw = _split_first_top_level_js(item, "=")
        lhs = lhs_raw.strip()
        src_part, alias_part = _split_first_top_level_js(lhs, ":")
        src_name = src_part.strip()
        local_name = alias_part.strip() if alias_part is not None else src_name
        if not (re.fullmatch(r"[A-Za-z_$][\w$]*", src_name) and re.fullmatch(r"[A-Za-z_$][\w$]*", local_name)):
            continue
        defaults[local_name] = _eval_attr_value(rhs_raw) if rhs_raw is not None else "unknown"
        aliases[local_name] = src_name
    return defaults, aliases


def _scan_paren_end(src: str, pos: int, mask: list[bool]) -> int | None:
    """Index just past `)` matching `(` at `pos`, respecting `mask` (JS strings/comments/regexes)."""
    if pos >= len(src) or src[pos] != "(":
        return None
    depth = 1
    i = pos + 1
    n = len(src)
    while i < n:
        if mask[i]:
            ch = src[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return None


def _slice_arrow_body_end(tail: str, arrow_end: int, mask: list[bool]) -> int:
    """Return slice end index for a block- or expression-bodied arrow right after `=>`."""
    n = len(tail)
    j = arrow_end
    while j < n:
        if tail[j].isspace():
            j += 1
        elif tail.startswith("//", j):
            nl = tail.find("\n", j + 2)
            j = n if nl < 0 else nl + 1
        elif tail.startswith("/*", j):
            close = tail.find("*/", j + 2)
            j = n if close < 0 else close + 2
        else:
            break
    if j >= n:
        return n
    if tail[j] == "{":
        bend = _scan_brace_end(tail, j)
        return bend if bend is not None else n
    if tail[j] == "(":
        pend = _scan_paren_end(tail, j, mask)
        return pend if pend is not None else n
    if tail.startswith("<>", j):
        fend = tail.find("</>", j + 2)
        return fend + 3 if fend >= 0 else n
    if tail[j] == "<":
        tm = re.match(r"<([A-Za-z][\w.]*)", tail[j:])
        if tm:
            open_end = scan_open_tag_end(tail, j + tm.end())
            if open_end is not None:
                if tail[j + tm.end() : open_end - 1].rstrip().endswith("/"):
                    return open_end
                close_span = _find_matching_close_tag(tail, open_end, tm.group(1))
                if close_span is not None:
                    return close_span[1]
    p_d = b_d = c_d = 0
    k = j
    while k < n:
        ch = tail[k]
        if ch == "\n" and p_d == 0 and b_d == 0 and c_d == 0:
            return k
        if mask[k]:
            if ch == "(":
                p_d += 1
            elif ch == ")":
                p_d = max(0, p_d - 1)
            elif ch == "[":
                b_d += 1
            elif ch == "]":
                b_d = max(0, b_d - 1)
            elif ch == "{":
                c_d += 1
            elif ch == "}":
                c_d = max(0, c_d - 1)
            elif ch == ";" and p_d == 0 and b_d == 0 and c_d == 0:
                return k + 1
        k += 1
    return n


def _slice_tsx_decl_body(raw_source: str, decl_start: int) -> str:
    """Slice from `decl_start` to the end of the target function/component declaration."""
    tail = raw_source[decl_start:]
    m_hoc = re.match(
        r"""^(?:export\s+default\s+|(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*(?::[^=;\n]+)?=\s*)"""
        r"""(?:React\.)?(?:memo|forwardRef)\s*(?:<[^;()]{0,160}?>)?\s*\(""",
        tail,
    )
    if m_hoc:
        tail = tail[m_hoc.end() :]
    mask = js_code_mask(tail)
    n = len(tail)
    i = 0
    paren_depth = 0
    angle_depth = 0
    saw_fn_kw = bool(re.match(r"^(?:export\s+(?:default\s+)?)?(?:async\s+)?function\b", tail))
    saw_params_end = False
    in_return_type = False
    last_sig = ""
    while i < n:
        if not mask[i]:
            i += 1
            continue
        ch = tail[i]
        if paren_depth == 0 and angle_depth == 0 and tail.startswith("function", i):
            prev_ok = i == 0 or not (tail[i - 1].isalnum() or tail[i - 1] in "_$")
            nxt_pos = i + 8
            next_ok = nxt_pos >= n or not (tail[nxt_pos].isalnum() or tail[nxt_pos] in "_$")
            if prev_ok and next_ok:
                saw_fn_kw = True
        if ch == "(" and angle_depth == 0:
            paren_depth += 1
            last_sig = "("
        elif ch == ")" and paren_depth > 0:
            paren_depth -= 1
            if paren_depth == 0:
                saw_params_end = True
            last_sig = ")"
        elif paren_depth == 0:
            if angle_depth == 0 and tail.startswith("=>", i):
                return tail[: _slice_arrow_body_end(tail, i + 2, mask)]
            if ch == "<" and (saw_params_end or saw_fn_kw):
                angle_depth += 1
                last_sig = "<"
            elif ch == ">" and angle_depth > 0 and (i == 0 or tail[i - 1] != "="):
                angle_depth -= 1
                last_sig = ">"
            elif ch == ":" and saw_params_end and angle_depth == 0:
                in_return_type = True
                last_sig = ":"
            elif ch == "{" and angle_depth == 0:
                if in_return_type and last_sig in (":", "|", "&"):
                    type_end = _scan_brace_end(tail, i)
                    if type_end is not None:
                        last_sig = "}"
                        i = type_end
                        continue
                if saw_fn_kw and saw_params_end:
                    body_end = _scan_brace_end(tail, i)
                    return tail[:body_end] if body_end is not None else tail
                skip_end = _scan_brace_end(tail, i)
                if skip_end is not None:
                    last_sig = "}"
                    i = skip_end
                    continue
            elif ch == ";" and angle_depth == 0:
                return tail[: i + 1]
            elif not ch.isspace():
                last_sig = ch
        i += 1
    return tail


def _locate_tsx_export_source(raw_source: str, exported_name: str) -> str:
    """Locate the declaration slice for a default or named React/JSX export."""
    mask = js_code_mask(raw_source)

    def _find_named_decl(symbol: str) -> int | None:
        pat = re.compile(
            rf"\b(?:async\s+)?function\s+{re.escape(symbol)}\b|"
            rf"\b(?:const|let|var)\s+{re.escape(symbol)}\s*(?::[^=;\n]+)?="
        )
        for m in pat.finditer(raw_source):
            if mask[m.start()]:
                return m.start()
        return None

    def _resolve_hoc_target(m: re.Match[str]) -> str | None:
        inner_tail = raw_source[m.end() :].lstrip()
        m_ref = re.match(r"^(?P<ref>[A-Za-z_$][\w$]*)\s*(?:,|\))", inner_tail)
        if m_ref:
            ref_pos = _find_named_decl(m_ref.group("ref"))
            if ref_pos is not None:
                return _slice_tsx_decl_body(raw_source, ref_pos)
        return _slice_tsx_decl_body(raw_source, m.end())

    if exported_name == "default":
        for pat in (
            r"\bexport\s+default\s+(?:async\s+)?function\b",
            r"\bexport\s+default\s+(?:async\s+)?\(",
            r"\bexport\s+default\s+(?:async\s+)?[A-Za-z_$][\w$]*\s*=>",
        ):
            for m in re.finditer(pat, raw_source):
                if mask[m.start()]:
                    return _slice_tsx_decl_body(raw_source, m.start())
        for m in re.finditer(
            r"\bexport\s+default\s+(?:React\.)?(?:memo|forwardRef)\s*(?:<[^;()]{0,160}?>)?\s*\(",
            raw_source,
        ):
            if mask[m.start()]:
                resolved = _resolve_hoc_target(m)
                if resolved is not None:
                    return resolved
        for m in re.finditer(
            r"\bexport\s+default\s+(?!(?:async\s+)?function\b|class\b)(?P<ref>[A-Za-z_$][\w$]*)\b(?!\s*=>)",
            raw_source,
        ):
            if mask[m.start()]:
                ref_pos = _find_named_decl(m.group("ref"))
                if ref_pos is not None:
                    return _slice_tsx_decl_body(raw_source, ref_pos)
        for m in re.finditer(
            r"\bexport\s*\{[^}]*\b(?P<ref>[A-Za-z_$][\w$]*)\s+as\s+default\b[^}]*\}",
            raw_source,
        ):
            if mask[m.start()]:
                ref_pos = _find_named_decl(m.group("ref"))
                if ref_pos is not None:
                    return _slice_tsx_decl_body(raw_source, ref_pos)
        return raw_source

    direct_pos = _find_named_decl(exported_name)
    if direct_pos is not None:
        return _slice_tsx_decl_body(raw_source, direct_pos)
    for m in re.finditer(
        rf"\bexport\s*\{{[^}}]*\b(?P<ref>[A-Za-z_$][\w$]*)\s+as\s+{re.escape(exported_name)}\b[^}}]*\}}",
        raw_source,
    ):
        if mask[m.start()]:
            ref_pos = _find_named_decl(m.group("ref"))
            if ref_pos is not None:
                return _slice_tsx_decl_body(raw_source, ref_pos)
    return raw_source


def _extract_jsx_at(src: str, jsx_start: int) -> tuple[str, int] | None:
    """Extract a complete JSX element or fragment starting at `jsx_start`."""
    if jsx_start >= len(src) or src[jsx_start] != "<":
        return None
    if src.startswith("<>", jsx_start):
        depth = 1
        pos = jsx_start + 2
        n = len(src)
        while pos < n:
            nxt_open = src.find("<>", pos)
            nxt_close = src.find("</>", pos)
            if nxt_close < 0:
                return None
            if nxt_open >= 0 and nxt_open < nxt_close:
                depth += 1
                pos = nxt_open + 2
            else:
                depth -= 1
                pos = nxt_close + 3
                if depth == 0:
                    return src[jsx_start:pos], pos
        return None
    tm = re.match(r"<([A-Za-z][\w.]*)", src[jsx_start:])
    if not tm:
        return None
    tname = tm.group(1)
    open_end = scan_open_tag_end(src, jsx_start + tm.end())
    if open_end is None:
        return None
    if src[jsx_start + tm.end() : open_end - 1].rstrip().endswith("/"):
        return src[jsx_start:open_end], open_end
    close_span = _find_matching_close_tag(src, open_end, tname)
    if close_span is None:
        return None
    return src[jsx_start : close_span[1]], close_span[1]


def _extract_jsx_or_conditional_branches(expr_src: str) -> list[str]:
    """Collect JSX roots and short-circuit fallback semantics from a returned JS expression."""
    mask = js_code_mask(expr_src)
    branches: list[str] = []
    n = len(expr_src)
    i = 0
    saw_short_circuit = False
    saw_ternary = False
    while i < n:
        if not mask[i]:
            i += 1
            continue
        ch = expr_src[i]
        if ch == "<":
            found = _extract_jsx_at(expr_src, i)
            if found is not None:
                jsx_slice, end_pos = found
                branches.append(jsx_slice)
                i = end_pos
                continue
        elif expr_src.startswith("&&", i) or expr_src.startswith("||", i):
            saw_short_circuit = True
            i += 2
            continue
        elif ch == "?":
            saw_ternary = True
        elif expr_src.startswith("=>", i):
            i = _slice_arrow_body_end(expr_src, i + 2, mask)
            continue
        i += 1
    if branches and saw_short_circuit and not saw_ternary:
        branches.append("<!--WYTHE_EXPR-->null")
    return branches


def _find_tsx_body_start(target_src: str, mask: str) -> tuple[bool, int] | None:
    """Locate `(is_block_body, body_start_idx)` after a TSX component's signature."""
    n = len(target_src)
    i = 0
    paren_depth = 0
    angle_depth = 0
    saw_fn_kw = bool(re.match(r"^(?:export\s+(?:default\s+)?)?(?:async\s+)?function\b", target_src))
    saw_params_end = False
    in_return_type = False
    last_sig = ""
    while i < n:
        if not mask[i]:
            i += 1
            continue
        ch = target_src[i]
        if paren_depth == 0 and angle_depth == 0 and target_src.startswith("function", i):
            prev_ok = i == 0 or not (target_src[i - 1].isalnum() or target_src[i - 1] in "_$")
            nxt = i + 8
            next_ok = nxt >= n or not (target_src[nxt].isalnum() or target_src[nxt] in "_$")
            if prev_ok and next_ok:
                saw_fn_kw = True
        if ch == "(" and angle_depth == 0:
            paren_depth += 1
            last_sig = "("
        elif ch == ")" and paren_depth > 0:
            paren_depth -= 1
            if paren_depth == 0:
                saw_params_end = True
            last_sig = ")"
        elif paren_depth == 0:
            if angle_depth == 0 and target_src.startswith("=>", i):
                pos = i + 2
                while pos < n and target_src[pos].isspace():
                    pos += 1
                if pos < n and target_src[pos] == "{":
                    return True, pos
                return False, pos
            if ch == "<" and (saw_params_end or saw_fn_kw):
                angle_depth += 1
                last_sig = "<"
            elif ch == ">" and angle_depth > 0 and (i == 0 or target_src[i - 1] != "="):
                angle_depth -= 1
                last_sig = ">"
            elif ch == ":" and saw_params_end and angle_depth == 0:
                in_return_type = True
                last_sig = ":"
            elif ch == "{" and angle_depth == 0:
                if in_return_type and last_sig in (":", "|", "&"):
                    type_end = _scan_brace_end(target_src, i)
                    if type_end is not None:
                        last_sig = "}"
                        i = type_end
                        continue
                if saw_fn_kw and saw_params_end:
                    return True, i
                skip_end = _scan_brace_end(target_src, i)
                if skip_end is not None:
                    last_sig = "}"
                    i = skip_end
                    continue
            elif not ch.isspace():
                last_sig = ch
        i += 1
    return None


def _extract_tsx_return_markup(target_src: str) -> str:
    """Extract single JSX output or `<!--WYTHE_BRANCH-->`-joined conditional returns."""
    mask = js_code_mask(target_src)
    body_info = _find_tsx_body_start(target_src, mask)
    if body_info is None:
        return ""
    is_block, body_start = body_info
    n = len(target_src)

    if not is_block:
        expr_tail = target_src[body_start:].strip()
        if expr_tail.endswith(";"):
            expr_tail = expr_tail[:-1].strip()
        if expr_tail.startswith("(") and expr_tail.endswith(")"):
            expr_tail = expr_tail[1:-1].strip()
        if expr_tail.startswith("<"):
            found = _extract_jsx_at(expr_tail, 0)
            return found[0] if found is not None else ""
        branches = _extract_jsx_or_conditional_branches(expr_tail)
        return "\n<!--WYTHE_BRANCH-->\n".join(branches) if any("<" in b for b in branches) else ""

    body_end = _scan_brace_end(target_src, body_start) or n
    branches: list[str] = []
    i = body_start + 1
    limit = min(body_end - 1, n)
    while i < limit:
        if not mask[i]:
            i += 1
            continue
        if target_src.startswith("=>", i):
            i = _slice_arrow_body_end(target_src, i + 2, mask)
            continue
        if target_src.startswith("function", i):
            prev_ok = i == 0 or not (target_src[i - 1].isalnum() or target_src[i - 1] in "_$")
            nxt = i + 8
            next_ok = nxt >= limit or not (target_src[nxt].isalnum() or target_src[nxt] in "_$")
            if prev_ok and next_ok:
                bpos = nxt
                pdepth = 0
                while bpos < limit:
                    if not mask[bpos]:
                        bpos += 1
                        continue
                    if target_src[bpos] == "(":
                        pdepth += 1
                    elif target_src[bpos] == ")" and pdepth > 0:
                        pdepth -= 1
                    elif target_src[bpos] == "{" and pdepth == 0:
                        bend = _scan_brace_end(target_src, bpos)
                        bpos = bend if bend is not None else limit
                        break
                    bpos += 1
                i = bpos
                continue
        if target_src.startswith("return", i):
            prev_ok = i == 0 or not (target_src[i - 1].isalnum() or target_src[i - 1] in "_$.")
            nxt = i + 6
            next_ok = nxt >= limit or not (target_src[nxt].isalnum() or target_src[nxt] in "_$")
            if prev_ok and next_ok:
                pos = nxt
                while pos < limit and target_src[pos].isspace():
                    pos += 1
                if pos < limit and target_src[pos] == "(":
                    inner_pos = pos + 1
                    while inner_pos < limit and target_src[inner_pos].isspace():
                        inner_pos += 1
                    if inner_pos < limit and target_src[inner_pos] == "<":
                        found = _extract_jsx_at(target_src, inner_pos)
                        if found is not None:
                            branches.append(found[0])
                            i = found[1]
                            continue
                if pos < limit and target_src[pos] == "<":
                    found = _extract_jsx_at(target_src, pos)
                    if found is not None:
                        branches.append(found[0])
                        i = found[1]
                        continue
                depth = 0
                end_pos = pos
                while end_pos < limit:
                    if not mask[end_pos]:
                        end_pos += 1
                        continue
                    ch = target_src[end_pos]
                    if ch in ("(", "[", "{"):
                        depth += 1
                    elif ch in (")", "]", "}"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif ch == ";" and depth == 0:
                        break
                    elif ch == "\n" and depth == 0 and target_src[pos:end_pos].strip():
                        tail_tok = target_src[pos:end_pos].rstrip()
                        if not tail_tok.endswith(("?", ":", "&&", "||", "+", ",")):
                            break
                    end_pos += 1
                raw_expr = target_src[pos:end_pos].strip()
                if "<" in raw_expr:
                    sub_branches = _extract_jsx_or_conditional_branches(raw_expr)
                    if sub_branches:
                        branches.extend(sub_branches)
                    else:
                        branches.append(f"<!--WYTHE_EXPR-->{raw_expr or 'null'}")
                else:
                    branches.append(f"<!--WYTHE_EXPR-->{raw_expr or 'null'}")
                i = end_pos + 1
                continue
        i += 1
    if not any("<" in b and not b.startswith("<!--WYTHE_EXPR-->") for b in branches):
        return ""
    return "\n<!--WYTHE_BRANCH-->\n".join(branches)


def _extract_component_props_and_markup(
    raw_source: str,
    suffix: str,
    exported_name: str = "default",
) -> tuple[dict[str, str], dict[str, str], str]:
    """Return `(prop_defaults, local_to_source, template_markup)` for a local component."""
    prop_defaults: dict[str, str] = {}
    prop_aliases: dict[str, str] = {}
    if suffix == ".svelte":
        for sm in _SCRIPT_BLOCK_RE.finditer(raw_source):
            script_body = sm.group("body")
            for pm in re.finditer(
                r"\bexport\s+let\s+(?P<name>[A-Za-z_$][\w$]*)(?:\s*:\s*[^=;\n]+)?(?:\s*=\s*(?P<def>[^;\n]+))?",
                script_body,
            ):
                dval = pm.group("def")
                pname = pm.group("name")
                prop_defaults[pname] = _eval_attr_value(dval) if dval is not None else "unknown"
                prop_aliases.setdefault(pname, pname)
            for pm in re.finditer(r"\blet\s*\{", script_body):
                bend = _scan_brace_end(script_body, pm.end() - 1)
                if bend is None:
                    continue
                tail = script_body[bend:]
                if re.match(r"^(?:\s*:[^=;\n]+)?\s*=\s*\$props\b", tail):
                    defs, als = _parse_default_params(script_body[pm.end() : bend - 1])
                    prop_defaults.update(defs)
                    prop_aliases.update(als)
        markup = _SCRIPT_BLOCK_RE.sub("", raw_source)
        markup = _STYLE_BLOCK_RE.sub("", markup)
        return prop_defaults, prop_aliases, markup

    if suffix == ".vue":
        for sm in _SCRIPT_BLOCK_RE.finditer(raw_source):
            sb = sm.group("body")
            for pm in re.finditer(r"withDefaults\s*\([\s\S]{0,400}?,\s*\{(?P<inner>[^}]+)\}", sb):
                for item in pm.group("inner").split(","):
                    if ":" in item:
                        k, v = item.split(":", 1)
                        k = k.strip().strip("'\"")
                        if re.fullmatch(r"[A-Za-z_$][\w$]*", k):
                            prop_defaults[k] = _eval_attr_value(v)
                            prop_aliases.setdefault(k, k)
            for pm in re.finditer(r"defineProps\s*<\s*\{(?P<inner>[^}]+)\}\s*>", sb):
                for k in re.findall(r"([A-Za-z_$][\w$]*)\s*\??:", pm.group("inner")):
                    prop_defaults.setdefault(k, "unknown")
                    prop_aliases.setdefault(k, k)
            for pm in re.finditer(r"defineProps\s*\(\s*\[(?P<inner>[^\]]+)\]\s*\)", sb):
                for k in re.findall(r"['\"]([A-Za-z_$][\w$]*)['\"]", pm.group("inner")):
                    prop_defaults.setdefault(k, "unknown")
                    prop_aliases.setdefault(k, k)
        tm = _VUE_TPL_RE.search(raw_source)
        return prop_defaults, prop_aliases, tm.group("body") if tm else ""

    # .tsx / .jsx: locate the target exported component declaration
    target_src = _locate_tsx_export_source(raw_source, exported_name)
    m_open = re.search(r"\(\s*\{", target_src)
    if m_open:
        bend = _scan_brace_end(target_src, m_open.end() - 1)
        if bend is not None:
            defs, als = _parse_default_params(target_src[m_open.end() : bend - 1])
            prop_defaults.update(defs)
            prop_aliases.update(als)
    return prop_defaults, prop_aliases, _extract_tsx_return_markup(target_src)


def _classify_expr_semantics(
    raw_expr: str,
    *,
    prop_values: dict[str, str] | None,
    inner_status: str,
) -> str:
    """Classify a `{...}` expression as `ignore`, `named`, `empty`, or `opaque`."""
    expr = re.sub(r"/\*[\s\S]*?\*/", "", raw_expr).strip()
    if expr.startswith("{") and expr.endswith("}"):
        expr = expr[1:-1].strip()
    if not expr or expr[0] in ("#", ":", "/"):
        return "ignore"
    if expr.startswith("@render"):
        return inner_status if "children" in expr else "named"
    if expr.startswith("@html"):
        expr = expr[5:].strip()
    elif expr.startswith("@"):
        return "ignore"
    if expr in ("''", '""', "``", "null", "undefined", "false", "true"):
        return "empty"
    if prop_values is None:
        return "named"
    if expr in ("children", "props.children"):
        return inner_status
    idents = [tok for tok in _IDENT_TOKEN_RE.findall(expr) if tok != "props"]
    matched_props = [tok for tok in idents if tok in prop_values]
    if matched_props:
        states = [prop_values[tok] for tok in matched_props]
        if any(st in ("named", "dynamic") for st in states):
            return "named"
        if re.search(r"""['"][^'"\s][^'"]*['"]""", expr):
            return "named"
        if any(st == "opaque" for st in states):
            return "opaque"
        return "empty"
    if re.search(r"""['"][^'"\s][^'"]*['"]""", expr):
        return "named"
    # Expressions inside an inspected child component that do not depend on a known prop
    # (e.g. local constants or i18n helper calls like `{t(key)}`) are uncertain, not proven empty.
    if idents or re.search(r"[A-Za-z0-9_$]", expr):
        return "opaque"
    return "empty"


def _classify_markup_segment(
    src: str,
    *,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[[str, str, str], str] | None,
    prop_values: dict[str, str] | None = None,
    inner_status: str = "empty",
) -> tuple[str, list[str], bool]:
    """Classify markup children as `(status, opaque_tags, has_visual_empty_or_icon)`."""
    has_named = False
    has_icon = False
    has_empty_comp = False
    opaque_tags: list[str] = []
    n = len(src)
    i = 0

    def merge_status(st: str, tag_label: str = "") -> None:
        nonlocal has_named, has_icon, has_empty_comp
        if st == "named":
            has_named = True
        elif st == "icon_only":
            has_icon = True
        elif st == "empty":
            has_empty_comp = True
        elif st == "opaque":
            lbl = tag_label or "slot"
            if lbl not in opaque_tags:
                opaque_tags.append(lbl)

    while i < n:
        ch = src[i]
        if src.startswith("<!--", i):
            cend = src.find("-->", i + 4)
            i = cend + 3 if cend >= 0 else n
            continue
        if ch == "{":
            bend = _scan_brace_end(src, i)
            if bend is None:
                i += 1
                continue
            sem = _classify_expr_semantics(
                src[i + 1 : bend - 1],
                prop_values=prop_values,
                inner_status=inner_status,
            )
            if sem == "named":
                has_named = True
            elif sem == "opaque" and prop_values is not None:
                opaque_tags.append("{expr}")
            i = bend
            continue
        if ch == "<":
            if src.startswith("</", i) or src.startswith("<>", i):
                gt = src.find(">", i + 2)
                i = gt + 1 if gt >= 0 else n
                continue
            tm = re.match(r"<([A-Za-z][\w.:-]*)", src[i:])
            if not tm:
                i += 1
                continue
            tag = tm.group(1)
            open_end = scan_open_tag_end(src, i + tm.end())
            if open_end is None:
                i += 1
                continue
            attrs = src[i + tm.end() : open_end - 1]
            self_closing = attrs.rstrip().endswith("/")
            inner_body = ""
            next_i = open_end
            if not self_closing and tag.lower() != "img":
                cspan = _find_matching_close_tag(src, open_end, tag)
                if cspan is not None:
                    inner_body = src[open_end : cspan[0]]
                    next_i = cspan[1]
            tag_low = tag.lower()
            if tag_low in ("svg", "i"):
                has_icon = True
                i = next_i
                continue
            if tag_low == "img":
                if _eval_alt_present(attrs):
                    has_named = True
                else:
                    has_icon = True
                i = next_i
                continue
            if tag_low == "slot":
                if not re.search(r"""\bname\s*=""", attrs):
                    if inner_status == "empty" and inner_body.strip():
                        slot_fallback, _, _ = _classify_markup_segment(
                            inner_body,
                            imported_components=imported_components,
                            component_resolver=component_resolver,
                            prop_values=prop_values,
                            inner_status="empty",
                        )
                        merge_status(slot_fallback, "slot")
                    else:
                        merge_status(inner_status, "slot")
                i = next_i
                continue
            if tag_low in ("script", "style") or re.search(r"""\baria-hidden\s*=\s*['"]true['"]""", attrs):
                i = next_i
                continue
            if tag[0].isupper() or "." in tag:
                child_inner = "empty"
                if inner_body:
                    cst, copaque, _ = _classify_markup_segment(
                        inner_body,
                        imported_components=imported_components,
                        component_resolver=component_resolver,
                        prop_values=prop_values,
                        inner_status=inner_status,
                    )
                    if cst == "named":
                        child_inner = "named"
                    elif copaque:
                        child_inner = "opaque"
                    elif cst == "icon_only":
                        child_inner = "icon_only"
                resolved = _resolve_component_tag(
                    tag,
                    attrs,
                    child_inner,
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                )
                merge_status(resolved, tag)
                i = next_i
                continue
            i = open_end
            continue
        j = i
        while j < n and src[j] not in ("<", "{"):
            j += 1
        if src[i:j].strip():
            has_named = True
        i = j

    if has_named:
        return "named", [], True
    if opaque_tags:
        return "opaque", opaque_tags, False
    if has_icon:
        return "icon_only", [], True
    if has_empty_comp:
        return "empty", [], True
    return "empty", [], False


def _eval_alt_present(attrs: str) -> bool:
    if "{..." in attrs:
        return True
    m = re.search(r"""\balt\s*=\s*(?:['"](?P<lit>[^'"]*)['"]|\{(?P<expr>[^}]+)\})""", attrs)
    if not m:
        return bool(re.search(r"(?:^|\s)\{\s*alt\s*\}(?=\s|$|/)", attrs))
    if m.group("lit") is not None:
        return bool(m.group("lit").strip())
    return _eval_attr_value(m.group("expr") or "") != "empty"


def _resolve_component_tag(
    tag: str,
    attrs: str,
    inner_status: str,
    *,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[[str, str, str], str] | None,
) -> str:
    root_name = tag.split(".", 1)[0]
    imp = imported_components.get(root_name)
    if imp and _ICON_PKG_SPEC_RE.match(imp[0]):
        return "icon_only"
    if component_resolver is not None:
        return component_resolver(tag, attrs, inner_status)
    return "opaque"


def make_local_component_resolver(
    caller_file: Path,
    caller_source: str,
    resolve_import_fn: Callable[[str, Path], Path | None],
    *,
    _caller_imports: dict[str, tuple[str, str]] | None = None,
    _cache: dict[
        tuple[Path, str], tuple[dict[str, str], dict[str, str], str, dict[str, tuple[str, str]], Path]
    ] | None = None,
    _visiting: frozenset[Path] = frozenset(),
    _depth: int = 0,
    _parent_props: dict[str, str] | None = None,
) -> Callable[[str, str, str], str]:
    """Build a depth-bounded, cycle-guarded local component accessibility semantics resolver."""
    imports = _caller_imports if _caller_imports is not None else parse_component_imports(caller_source)
    cache = _cache if _cache is not None else {}

    def resolve_tag(tag_name: str, attrs: str, inner_status: str) -> str:
        root_name = tag_name.split(".", 1)[0]
        imp = imports.get(root_name)
        if imp is not None and _ICON_PKG_SPEC_RE.match(imp[0]):
            return "icon_only"
        same_file = (
            imp is None
            and caller_file.suffix in (".tsx", ".jsx")
            and bool(
                re.search(
                    rf"\b(?:function\s+{re.escape(root_name)}\b|const\s+{re.escape(root_name)}\s*=)",
                    caller_source,
                )
            )
        )
        if _depth >= 3 or (imp is None and not same_file):
            return "opaque"
        if same_file:
            target = caller_file
            exported = tag_name
        else:
            assert imp is not None
            spec, exported = imp
            if "." in tag_name:
                exported = tag_name.split(".", 1)[1]
            target = resolve_import_fn(spec, caller_file)
            if target is None or target in _visiting:
                return "opaque"
        ckey = (target, exported)
        if ckey not in cache:
            try:
                raw_target = caller_source if same_file else target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return "opaque"
            defaults, aliases, markup = _extract_component_props_and_markup(
                raw_target, target.suffix, exported_name=exported
            )
            target_imports = imports if same_file else parse_component_imports(raw_target)
            cache[ckey] = (defaults, aliases, markup, target_imports, target)
        defaults, aliases, markup, target_imports, resolved_path = cache[ckey]
        if not markup.strip():
            return "opaque"

        passed, has_opaque_spread, explicit_after_spread = _extract_prop_attrs(attrs)
        merged_props: dict[str, str] = {}
        for local_name, dstate in defaults.items():
            src_name = aliases.get(local_name, local_name)
            pval = passed.get(src_name)
            if pval is not None and pval != "undefined":
                merged_props[local_name] = pval
            elif has_opaque_spread and src_name not in explicit_after_spread:
                merged_props[local_name] = "opaque"
            elif dstate in ("named", "dynamic"):
                merged_props[local_name] = "named"
            else:
                merged_props[local_name] = "empty"
        for src_name, pstate in passed.items():
            norm_state = "empty" if pstate == "undefined" else pstate
            merged_props.setdefault(src_name, norm_state)

        if _parent_props is not None:
            raw_prop_exprs = _extract_prop_raw_exprs(attrs)
            for local_name, src_name in aliases.items():
                if src_name in raw_prop_exprs and raw_prop_exprs[src_name] in _parent_props:
                    merged_props[local_name] = _parent_props[raw_prop_exprs[src_name]]
            for pname, raw_e in raw_prop_exprs.items():
                if pname not in aliases.values() and raw_e in _parent_props:
                    merged_props[pname] = _parent_props[raw_e]

        children_local = next(
            (ln for ln, sn in aliases.items() if sn == "children"),
            "children",
        )
        effective_children = merged_props.get(children_local, passed.get("children"))
        effective_inner = inner_status
        if effective_inner == "empty":
            if effective_children in ("named", "dynamic"):
                effective_inner = "named"
            elif effective_children == "opaque" or (
                has_opaque_spread and "children" not in explicit_after_spread
            ):
                effective_inner = "opaque"

        nested_resolver = make_local_component_resolver(
            resolved_path,
            "" if not same_file else caller_source,
            resolve_import_fn,
            _caller_imports=target_imports,
            _cache=cache,
            _visiting=_visiting | {resolved_path},
            _depth=_depth + 1,
            _parent_props=merged_props,
        )

        def classify_branch(branch: str) -> str:
            if branch.startswith("<!--WYTHE_EXPR-->"):
                sem = _classify_expr_semantics(
                    branch[len("<!--WYTHE_EXPR-->") :],
                    prop_values=merged_props,
                    inner_status=effective_inner,
                )
                return "empty" if sem == "ignore" else sem
            st, _, _ = _classify_markup_segment(
                branch,
                imported_components=target_imports,
                component_resolver=nested_resolver,
                prop_values=merged_props,
                inner_status=effective_inner,
            )
            return st

        branches = markup.split("\n<!--WYTHE_BRANCH-->\n")
        if len(branches) == 1:
            return classify_branch(branches[0])
        branch_statuses = {classify_branch(b) for b in branches}
        return next(iter(branch_statuses)) if len(branch_statuses) == 1 else "opaque"

    return resolve_tag


def _extract_prop_raw_exprs(attrs: str) -> dict[str, str]:
    """Map prop names on `<Tag prop={ident} {shorthand} />` to bare identifier expressions."""
    exprs: dict[str, str] = {}
    for m in re.finditer(r"\{\s*([A-Za-z_$][\w$]*)\s*\}", attrs):
        before = attrs[: m.start()].rstrip()
        if not before.endswith("="):
            exprs[m.group(1)] = m.group(1)
    for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*=\s*\{\s*([A-Za-z_$][\w$]*)\s*\}", attrs):
        exprs[m.group(1)] = m.group(2)
    return exprs


def scan_a11y_markup_findings(
    raw_source: str,
    node_id: str,
    rel_repo: str,
    *,
    component_resolver: Callable[[str, str, str], str] | None = None,
    unobserved_out: list[str] | None = None,
) -> list[RawCandidateFinding]:
    """Inspect raw UI template/JSX/RSX markup for deterministic WCAG (`DISP-005`) violations."""
    findings: list[RawCandidateFinding] = []
    seen_lines: set[tuple[int, str]] = set()
    imported_components = parse_component_imports(raw_source)

    def emit(lineno: int, kind: str, title: str, detail: str, remediation: str) -> None:
        if (lineno, kind) in seen_lines or len(findings) >= 15:
            return
        seen_lines.add((lineno, kind))
        findings.append(
            RawCandidateFinding(
                rule_code="DISP-005",
                node_id=node_id,
                source_file=rel_repo,
                line=lineno,
                title=title,
                detail=detail,
                remediation=remediation,
            )
        )

    # 1. <img> without alt attribute (unless decorative aria-hidden="true" or role="presentation"/"none")
    for m, attrs, _end in _open_tags(raw_source, _IMG_OPEN_RE):
        if rel_repo.endswith(".svelte") and _has_svelte_shorthand(attrs, "alt"):
            continue
        if re.search(r"\balt\s*=", attrs) or re.search(r"""\baria-hidden\s*=\s*['"]true['"]""", attrs):
            continue
        if re.search(r"""\brole\s*=\s*['"](?:presentation|none)['"]""", attrs):
            continue
        if "{..." in attrs:
            continue
        lineno = raw_source.count("\n", 0, m.start()) + 1
        emit(
            lineno,
            "img_alt",
            "Image element `<img>` missing `alt` text (`WCAG 1.1.1`)",
            f"{rel_repo}:{lineno} renders `<img>` without an `alt` attribute (use `alt=\"\"` if purely decorative).",
            "Provide descriptive `alt` text or `alt=\"\"` with `aria-hidden=\"true\"` for decorative images.",
        )

    # 2. Click handlers on non-interactive <div>/<span> without role + keyboard focusability
    for m, attrs, _end in _open_tags(raw_source, _CLICKABLE_OPEN_RE):
        tag = m.group("tag")
        if not _CLICK_ATTR_RE.search(attrs):
            continue
        if re.search(r"""\baria-hidden\s*=\s*['"]true['"]""", attrs):
            continue
        has_role = bool(re.search(r"\brole\s*=", attrs))
        has_tab = bool(re.search(r"\btab[Ii]ndex\s*=", attrs))
        if has_role and has_tab:
            continue
        lineno = raw_source.count("\n", 0, m.start()) + 1
        emit(
            lineno,
            "div_click",
            f"Non-interactive `<{tag}>` has click handler without keyboard/ARIA semantics (`WCAG 2.1.1`)",
            f"{rel_repo}:{lineno} attaches a click handler to `<{tag}>` without `role` and `tabIndex`.",
            "Replace with a semantic `<button>` element, or add `role=\"button\"`, `tabIndex={0}`, and `onKeyDown`.",
        )

    # 3. Icon-only or empty-label <button> without aria-label / aria-labelledby / title
    for m, attrs, end in _open_tags(raw_source, _BUTTON_OPEN_RE):
        if attrs.rstrip().endswith("/"):
            continue
        if re.search(r"\b(?:aria-label|aria-labelledby|title)\s*=", attrs) or "{..." in attrs:
            continue
        cspan = _find_matching_close_tag(raw_source, end, "button")
        if cspan is None:
            continue
        body = raw_source[end : cspan[0]]
        status, opaque_tags, has_visual = _classify_markup_segment(
            body,
            imported_components=imported_components,
            component_resolver=component_resolver,
        )
        lineno = raw_source.count("\n", 0, m.start()) + 1
        if status == "named":
            continue
        if status == "opaque":
            if unobserved_out is not None:
                unobserved_out.append(
                    f"{rel_repo}:{lineno}: opaque component(s) <{', '.join(opaque_tags)}> inside <button>"
                )
            continue
        if status == "icon_only":
            emit(
                lineno,
                "icon_btn",
                "Icon-only `<button>` missing accessible name (`WCAG 4.1.2`)",
                f"{rel_repo}:{lineno} renders an icon-only `<button>` with no `aria-label`, `aria-labelledby`, or visible text.",
                "Add `aria-label=\"...\"` or visually-hidden `<span className=\"sr-only\">` text inside the button.",
            )
        elif status == "empty" and has_visual:
            emit(
                lineno,
                "icon_btn",
                "Button `<button>` has no accessible text (`WCAG 4.1.2`)",
                f"{rel_repo}:{lineno} renders `<button>` whose resolved child content produces no accessible text and no `aria-label`, `aria-labelledby`, or `title`.",
                "Provide non-empty visible label content or add `aria-label=\"...\"`.",
            )

    # 4. Orphaned form controls (<input>/<select>/<textarea> without label[for], wrapping <label>, or aria-label)
    wrapped_spans, labeled_ids = _label_spans_and_targets(raw_source)
    for m, attrs, end in _open_tags(raw_source, _INPUT_OPEN_RE):
        tag = m.group("tag")
        if _HIDDEN_INPUT_RE.search(attrs) or "{..." in attrs:
            continue
        if re.search(r"\b(?:aria-label|aria-labelledby|title)\s*=", attrs):
            continue
        if any(ws <= m.start() and end <= we for ws, we in wrapped_spans):
            continue
        idm = _ID_ATTR_RE.search(attrs)
        if idm:
            id_val = (idm.group("id") or idm.group("expr") or "").strip()
            if id_val and id_val in labeled_ids:
                continue
        lineno = raw_source.count("\n", 0, m.start()) + 1
        emit(
            lineno,
            "orphan_input",
            f"Form control `<{tag}>` lacks associated `<label>` or `aria-label` (`WCAG 1.3.1`)",
            f"{rel_repo}:{lineno} renders `<{tag}>` without a matching `<label htmlFor=...>` or `aria-label`.",
            "Associate a `<label htmlFor=\"...\">`, wrap in `<label>`, or add `aria-label=\"...\"`.",
        )

    return findings
