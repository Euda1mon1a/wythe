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
    r"^(?:lucide-react|lucide-svelte|lucide-vue-next|@lucide/|@heroicons/|react-icons/|@tabler/icons|@radix-ui/react-icons|phosphor-react|@phosphor-icons/|svelte-hero-icons|svelte-lucide)"
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
    if start > 0 and src[start - 1] == "<" and re.match(r"^/(?:>|[A-Za-z][\w.:-]*\s*>)", src[start:]):
        return None
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


def _scan_paren_end(
    src: str,
    pos: int,
    mask: list[bool] | None = None,
    *,
    skip_jsx: bool = True,
) -> int | None:
    """Index just past the `)` matching `(` at `pos`, respecting quotes, comments, and JSX."""
    if pos >= len(src) or src[pos] != "(":
        return None
    src_mask = mask if mask is not None else js_code_mask(src)
    n = len(src)
    depth = 0
    i = pos
    while i < n:
        if not src_mask[i]:
            i += 1
            continue
        ch = src[i]
        if skip_jsx and ch == "<":
            found = _extract_jsx_at(src, i)
            if found is not None:
                i = found[1]
                continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _unwrap_outer_parens(expr: str) -> str:
    """Repeatedly strip outer `(...)` when the leading `(` closes at the end of `expr`."""
    s = expr.strip()
    while s.startswith("("):
        mask = js_code_mask(s)
        if _scan_paren_end(s, 0, mask) == len(s):
            s = s[1:-1].strip()
        else:
            break
    return s


def _portal_names_from_imports(imported_components: dict[str, tuple[str, str]]) -> frozenset[str]:
    """Return local identifiers bound to `createPortal` (plus default `"createPortal"`)."""
    names = {"createPortal"}
    for local, (_spec, exported) in imported_components.items():
        if exported == "createPortal":
            names.add(local)
    return frozenset(names)


def _is_portal_call_target(callee: str, portal_names: frozenset[str]) -> bool:
    """True when a callee refers to React `createPortal` or an alias/member access to it."""
    return callee in portal_names or callee.rsplit(".", 1)[-1] == "createPortal"


def _split_top_level_ternary(expr: str, mask: list[bool] | None = None) -> tuple[str, str, str] | None:
    """Split a top-level JS `cond ? cons : alt` ternary, respecting nested ternaries and JSX."""
    src_mask = mask if mask is not None else js_code_mask(expr)
    n = len(expr)
    pdepth = bdepth = cdepth = qdepth = 0
    q_pos: int | None = None
    i = 0
    while i < n:
        if not src_mask[i]:
            i += 1
            continue
        if pdepth == 0 and bdepth == 0 and cdepth == 0:
            if expr.startswith("=>", i):
                i = _slice_arrow_body_end(expr, i + 2, src_mask)
                continue
            if expr[i] == "<":
                found = _extract_jsx_at(expr, i)
                if found is not None:
                    i = found[1]
                    continue
        ch = expr[i]
        if ch == "(":
            pdepth += 1
        elif ch == ")" and pdepth > 0:
            pdepth -= 1
        elif ch == "[":
            bdepth += 1
        elif ch == "]" and bdepth > 0:
            bdepth -= 1
        elif ch == "{":
            cdepth += 1
        elif ch == "}" and cdepth > 0:
            cdepth -= 1
        elif pdepth == 0 and bdepth == 0 and cdepth == 0:
            if ch == "?" and not expr.startswith(("?.", "??"), i):
                if qdepth == 0:
                    q_pos = i
                qdepth += 1
            elif ch == ":" and qdepth > 0:
                qdepth -= 1
                if qdepth == 0 and q_pos is not None:
                    return expr[:q_pos], expr[q_pos + 1 : i], expr[i + 1 :]
        i += 1
    return None


def _split_top_level_binary_ops(
    expr: str,
    ops: tuple[str, ...],
    mask: list[bool] | None = None,
) -> list[tuple[str, str | None]]:
    """Split `expr` on any top-level 2-char operator in `ops`, skipping nested scopes and JSX."""
    src_mask = mask if mask is not None else js_code_mask(expr)
    n = len(expr)
    pdepth = bdepth = cdepth = 0
    start = 0
    parts: list[tuple[str, str | None]] = []
    i = 0
    while i < n:
        if not src_mask[i]:
            i += 1
            continue
        if pdepth == 0 and bdepth == 0 and cdepth == 0:
            if expr.startswith("=>", i):
                i = _slice_arrow_body_end(expr, i + 2, src_mask)
                continue
            if expr[i] == "<":
                found = _extract_jsx_at(expr, i)
                if found is not None:
                    i = found[1]
                    continue
        ch = expr[i]
        if ch == "(":
            pdepth += 1
        elif ch == ")" and pdepth > 0:
            pdepth -= 1
        elif ch == "[":
            bdepth += 1
        elif ch == "]" and bdepth > 0:
            bdepth -= 1
        elif ch == "{":
            cdepth += 1
        elif ch == "}" and cdepth > 0:
            cdepth -= 1
        elif pdepth == 0 and bdepth == 0 and cdepth == 0:
            matched_op = next((op for op in ops if expr.startswith(op, i)), None)
            if matched_op is not None:
                parts.append((expr[start:i], matched_op))
                i += len(matched_op)
                start = i
                continue
        i += 1
    parts.append((expr[start:], None))
    return parts


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


_PROP_IDENT_REF_RE = re.compile(r"^(?:props\.)?(?P<ident>[A-Za-z_$][\w$]*)$")
_EMPTY_PROP_STATES = frozenset({"empty", "empty_node", "blank", "null", "undefined"})
_BOOL_PROP_STATES = frozenset({"bool_false", "bool_true"})
_JSX_COMMENT_RE = re.compile(r"\{\s*/\*[\s\S]*?\*/\s*\}")


def _normalize_component_lookup(
    tag: str,
    imported_components: dict[str, tuple[str, str]],
    *,
    allow_vue_case_insensitive: bool = False,
) -> tuple[str, tuple[str, str]] | None:
    """Resolve JSX/Svelte/Vue component tags to imports, scoping case-folding to Vue."""
    root_name = tag.split(".", 1)[0]
    if root_name in imported_components:
        return root_name, imported_components[root_name]
    if allow_vue_case_insensitive:
        if "-" in root_name:
            pascal = "".join(part[:1].upper() + part[1:] for part in root_name.split("-") if part)
            if pascal in imported_components:
                return pascal, imported_components[pascal]
        if "-" in root_name or root_name[:1].isupper():
            collapsed = root_name.replace("-", "").lower()
            for imp_name, val in imported_components.items():
                if imp_name.lower() == collapsed:
                    return imp_name, val
    return None


def _eval_attr_value(expr: str, *, preserve_undefined: bool = False) -> str:
    s = expr.strip()
    if s == "undefined":
        return "undefined" if preserve_undefined else "empty"
    if s == "null":
        return "null" if preserve_undefined else "empty"
    if s in ("", "''", '""', "``"):
        return "empty"
    if s == "false":
        return "bool_false" if preserve_undefined else "empty"
    if s == "true":
        return "bool_true" if preserve_undefined else "empty"
    if re.fullmatch(r"-?\d+(?:\.\d+)?", s):
        if preserve_undefined:
            try:
                if float(s) == 0.0:
                    return "num_zero"
            except ValueError:
                pass
        return "named"
    if len(s) >= 2 and s[0] in ("'", '"') and s[-1] == s[0]:
        inner = s[1:-1]
        if inner.strip():
            return "named"
        return "blank" if (preserve_undefined and inner != "") else "empty"
    if len(s) >= 2 and s[0] == "`" and s[-1] == "`" and "${" not in s:
        inner = s[1:-1]
        if inner.strip():
            return "named"
        return "blank" if (preserve_undefined and inner != "") else "empty"
    if "||" in s or "??" in s:
        ev = _eval_coalesce_expr(s, prop_values={}, inner_status="empty", unknown_fallback="dynamic")
        if not preserve_undefined:
            if ev in ("null", "undefined", "blank", "bool_false", "bool_true"):
                return "empty"
            if ev == "num_zero":
                return "named"
        return ev
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


def _parse_spread_object_literal(
    body: str,
    props: dict[str, str],
    raw_exprs: dict[str, str],
    mark_opaque_spread: Callable[[], None],
    record_explicit: Callable[[str], None],
) -> None:
    """Populate `props` and `raw_exprs` from an inline `{...{ key: val }}` / `v-bind="{...}"` body."""
    for entry in _split_top_level_js(body, ","):
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
                rm = _PROP_IDENT_REF_RE.match(raw_v.strip())
                if rm:
                    raw_exprs[skey] = f"props.{rm.group('ident')}" if raw_v.strip().startswith("props.") else rm.group("ident")
                else:
                    raw_exprs.pop(skey, None)
                record_explicit(skey)
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", entry):
            props[entry] = "dynamic"
            raw_exprs[entry] = entry
            record_explicit(entry)


def _extract_prop_attrs(attrs: str) -> tuple[dict[str, str], bool, set[str], dict[str, str]]:
    """Parse JSX/Svelte/Vue component attrs into `(props, has_opaque_spread, explicit_after_spread, raw_exprs)`."""
    props: dict[str, str] = {}
    raw_exprs: dict[str, str] = {}
    has_opaque_spread = False
    explicit_after_spread: set[str] = set()

    def mark_opaque_spread() -> None:
        nonlocal has_opaque_spread
        has_opaque_spread = True
        explicit_after_spread.clear()
        for existing_k, existing_v in list(props.items()):
            if existing_v in _EMPTY_PROP_STATES or existing_v in _BOOL_PROP_STATES:
                props[existing_k] = "opaque"

    def record_explicit(prop_name: str) -> None:
        if has_opaque_spread:
            explicit_after_spread.add(prop_name)

    def record_ident_ref(prop_name: str, expr: str) -> None:
        rm = _PROP_IDENT_REF_RE.match(expr.strip())
        if rm:
            raw_exprs[prop_name] = (
                f"props.{rm.group('ident')}" if expr.strip().startswith("props.") else rm.group("ident")
            )
        else:
            raw_exprs.pop(prop_name, None)

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
                        _parse_spread_object_literal(
                            spread_expr[1:-1], props, raw_exprs, mark_opaque_spread, record_explicit
                        )
                    else:
                        mark_opaque_spread()
                elif re.fullmatch(r"[A-Za-z_$][\w$]*", inner):
                    props[inner] = "dynamic"
                    raw_exprs[inner] = inner
                    record_explicit(inner)
                i = bend
                continue
            i += 1
            continue
        if attrs.startswith("@", i) or attrs.startswith("v-on:", i):
            dm = re.match(r"(?:@|v-on:)[\w.:$-]+", attrs[i:])
            i += dm.end() if dm else 1
            while i < n and attrs[i].isspace():
                i += 1
            if i < n and attrs[i] == "=":
                i += 1
                while i < n and attrs[i].isspace():
                    i += 1
                if i < n and attrs[i] in ("'", '"'):
                    q = attrs[i]
                    j = i + 1
                    while j < n and attrs[j] != q:
                        j += 2 if attrs[j] == "\\" else 1
                    i = min(j + 1, n)
                elif i < n and attrs[i] == "{":
                    bend = _scan_brace_end(attrs, i)
                    i = bend if bend is not None else i + 1
            continue
        is_vue_bound = False
        if attrs.startswith("v-bind:", i):
            is_vue_bound = True
            i += len("v-bind:")
        elif attrs[i] == ":":
            is_vue_bound = True
            i += 1
        km = re.match(r"([A-Za-z_$][\w$.-]*)", attrs[i:])
        if not km:
            i += 1
            continue
        key = km.group(1)
        i += km.end()
        while i < n and attrs[i].isspace():
            i += 1
        if i >= n or attrs[i] != "=":
            if is_vue_bound:
                base_key = key.split(".", 1)[0]
                props[base_key] = "dynamic"
                raw_exprs[base_key] = base_key
                record_explicit(base_key)
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
            if not is_vue_bound and key == "v-bind":
                trimmed = val.strip()
                if trimmed.startswith("{") and trimmed.endswith("}"):
                    _parse_spread_object_literal(
                        trimmed[1:-1], props, raw_exprs, mark_opaque_spread, record_explicit
                    )
                else:
                    mark_opaque_spread()
            elif is_vue_bound:
                base_key = key.split(".", 1)[0]
                eval_v = _eval_attr_value(val, preserve_undefined=True)
                props[base_key] = eval_v
                record_ident_ref(base_key, val)
                record_explicit(base_key)
                if "-" in base_key:
                    camel = re.sub(r"-([a-zA-Z0-9])", lambda m: m.group(1).upper(), base_key)
                    props[camel] = eval_v
                    record_ident_ref(camel, val)
                    record_explicit(camel)
            else:
                eval_v = "named" if val.strip() else ("blank" if val else "empty")
                props[key] = eval_v
                raw_exprs.pop(key, None)
                record_explicit(key)
                if "-" in key:
                    camel = re.sub(r"-([a-zA-Z0-9])", lambda m: m.group(1).upper(), key)
                    props[camel] = eval_v
                    raw_exprs.pop(camel, None)
                    record_explicit(camel)
            i = min(j + 1, n)
        elif attrs[i] == "{":
            bend = _scan_brace_end(attrs, i)
            if bend is None:
                break
            inner_expr = attrs[i + 1 : bend - 1]
            props[key] = _eval_attr_value(inner_expr, preserve_undefined=True)
            record_ident_ref(key, inner_expr)
            record_explicit(key)
            i = bend
    return props, has_opaque_spread, explicit_after_spread, raw_exprs


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
        defaults[local_name] = (
            _eval_attr_value(rhs_raw, preserve_undefined=True) if rhs_raw is not None else "unknown"
        )
        aliases[local_name] = src_name
    return defaults, aliases


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


_EXPORT_BLOCK_RE = re.compile(
    r"\bexport\s*(?!type\b)\{(?P<body>[^}]*)\}(?:\s*from\s*(?:\"(?P<dq>[^\"]+)\"|'(?P<sq>[^']+)'))?"
)


def _parse_export_specifiers(body: str) -> list[tuple[str, str]]:
    """Parse ESM `{ Orig as Alias, Name }` pairs, ignoring `type` specifiers."""
    pairs: list[tuple[str, str]] = []
    for raw_item in body.split(","):
        item = raw_item.strip()
        if not item or item.startswith("type "):
            continue
        m = re.fullmatch(
            r"(?P<orig>[A-Za-z_$][\w$]*)(?:\s+as\s+(?P<alias>[A-Za-z_$][\w$]*))?",
            item,
        )
        if m:
            orig = m.group("orig")
            pairs.append((orig, m.group("alias") or orig))
    return pairs


def _find_tsx_reexport_target(raw_source: str, exported_name: str) -> tuple[str, str] | None:
    """Return `(specifier, imported_name)` when `exported_name` is re-exported from another module."""
    mask = js_code_mask(raw_source)
    for m in _EXPORT_BLOCK_RE.finditer(raw_source):
        if not mask[m.start()]:
            continue
        spec = m.group("dq") if m.group("dq") is not None else m.group("sq")
        if spec is None:
            continue
        for orig, exp in _parse_export_specifiers(m.group("body")):
            if exp == exported_name:
                return spec, orig
    return None


def _js_brace_spans(raw_source: str, mask: str) -> list[tuple[int, int]]:
    """Return balanced `{open_idx, close_idx_exclusive}` spans for lexical block lookup."""
    spans: list[tuple[int, int]] = []
    stack: list[int] = []
    for idx, ch in enumerate(raw_source):
        if not mask[idx]:
            continue
        if ch == "{":
            stack.append(idx)
        elif ch == "}" and stack:
            spans.append((stack.pop(), idx + 1))
    return spans


def _find_lexical_tsx_decl_pos(
    raw_source: str,
    symbol: str,
    usage_pos: int | None,
    *,
    mask: str | None = None,
    brace_spans: list[tuple[int, int]] | None = None,
) -> tuple[str, int | None]:
    """Resolve same-file `symbol` at `usage_pos` -> `(found|ambiguous|missing, decl_pos)`."""
    src_mask = mask if mask is not None else js_code_mask(raw_source)
    spans = brace_spans if brace_spans is not None else _js_brace_spans(raw_source, src_mask)
    pat = re.compile(
        rf"\b(?:async\s+)?function\s+{re.escape(symbol)}\b|"
        rf"\b(?:const|let|var)\s+{re.escape(symbol)}\s*(?::[^=;\n]+)?="
    )
    decls: list[tuple[int, tuple[int, int]]] = []
    full_span = (0, len(raw_source))
    for m in pat.finditer(raw_source):
        if not src_mask[m.start()]:
            continue
        pos = m.start()
        enclosing = full_span
        best_width = full_span[1] - full_span[0]
        for s_start, s_end in spans:
            if s_start < pos < s_end:
                w = s_end - s_start
                if w < best_width:
                    best_width = w
                    enclosing = (s_start, s_end)
        decls.append((pos, enclosing))
    if not decls:
        return "missing", None
    if usage_pos is None:
        return ("found", decls[0][0]) if len(decls) == 1 else ("ambiguous", None)
    visible = [(pos, sc) for pos, sc in decls if sc[0] <= usage_pos < sc[1]]
    if not visible:
        return "missing", None
    min_width = min(sc[1] - sc[0] for _pos, sc in visible)
    innermost = [pos for pos, sc in visible if (sc[1] - sc[0]) == min_width]
    if len(innermost) != 1:
        return "ambiguous", None
    return "found", innermost[0]


_ALL_TSX_LOCAL_DECL_RE = re.compile(
    r"\b(?:async\s+)?function\s+(?P<fn>[A-Za-z_$][\w$]*)\b"
    r"|\b(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?="
)


def _build_tsx_local_decl_index(
    raw_source: str,
    *,
    mask: list[bool] | str | None = None,
    brace_spans: list[tuple[int, int]] | None = None,
) -> dict[str, list[tuple[int, tuple[int, int]]]]:
    """Index all same-file TSX/JSX value declarations with their innermost brace scope once."""
    src_mask = mask if mask is not None else js_code_mask(raw_source)
    spans = brace_spans if brace_spans is not None else _js_brace_spans(raw_source, src_mask)
    sorted_spans = sorted(spans, key=lambda s: (s[0], -s[1]))
    decls_flat: list[tuple[int, str]] = []
    for m in _ALL_TSX_LOCAL_DECL_RE.finditer(raw_source):
        if not src_mask[m.start()]:
            continue
        sym = m.group("fn") or m.group("var")
        if sym:
            decls_flat.append((m.start(), sym))
    index: dict[str, list[tuple[int, tuple[int, int]]]] = {}
    full_span = (0, len(raw_source))
    scope_stack: list[tuple[int, int]] = [full_span]
    si = 0
    ns = len(sorted_spans)
    for pos, sym in decls_flat:
        while si < ns and sorted_spans[si][0] < pos:
            s_start, s_end = sorted_spans[si]
            si += 1
            if pos < s_end:
                while len(scope_stack) > 1 and scope_stack[-1][1] <= s_start:
                    scope_stack.pop()
                scope_stack.append((s_start, s_end))
        while len(scope_stack) > 1 and scope_stack[-1][1] <= pos:
            scope_stack.pop()
        index.setdefault(sym, []).append((pos, scope_stack[-1]))
    return index


def _lookup_tsx_decl_index(
    index: dict[str, list[tuple[int, tuple[int, int]]]],
    symbol: str,
    usage_pos: int | None,
) -> tuple[str, int | None]:
    """Resolve `symbol` at `usage_pos` against a prebuilt `_build_tsx_local_decl_index` map."""
    decls = index.get(symbol)
    if not decls:
        return "missing", None
    if usage_pos is None:
        return ("found", decls[0][0]) if len(decls) == 1 else ("ambiguous", None)
    visible = [(pos, sc) for pos, sc in decls if sc[0] <= usage_pos < sc[1]]
    if not visible:
        return "missing", None
    min_width = min(sc[1] - sc[0] for _pos, sc in visible)
    innermost = [pos for pos, sc in visible if (sc[1] - sc[0]) == min_width]
    if len(innermost) != 1:
        return "ambiguous", None
    return "found", innermost[0]


def _resolve_tsx_decl_slice_with_pos(
    raw_source: str,
    decl_pos: int,
    *,
    mask: str | None = None,
) -> tuple[str, int]:
    """Follow simple alias/HOC wrappers from `decl_pos`, returning `(decl_slice, resolved_pos)`."""
    src_mask = mask if mask is not None else js_code_mask(raw_source)
    cur = decl_pos
    seen: set[int] = set()
    for _ in range(3):
        if cur in seen:
            break
        seen.add(cur)
        m_alias = re.match(
            r"(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*(?::[^=;\n]+)?=\s*"
            r"(?:(?:React\.)?(?:memo|forwardRef)\s*(?:<[^;()]{0,160}?>)?\s*\(\s*)?"
            r"(?P<ref>[A-Za-z_$][\w$]*)\s*[);,\n]",
            raw_source[cur:],
        )
        if m_alias and m_alias.group("ref") not in ("function", "async", "class", "null", "undefined"):
            ref_pat = re.compile(
                rf"\b(?:async\s+)?function\s+{re.escape(m_alias.group('ref'))}\b|"
                rf"\b(?:const|let|var)\s+{re.escape(m_alias.group('ref'))}\s*(?::[^=;\n]+)?="
            )
            for rm in ref_pat.finditer(raw_source):
                if src_mask[rm.start()]:
                    cur = rm.start()
                    break
            else:
                break
            continue
        break
    return _slice_tsx_decl_body(raw_source, cur), cur


def _locate_tsx_export_source_with_pos(
    raw_source: str,
    exported_name: str,
    *,
    local_scope: bool = False,
    usage_pos: int | None = None,
) -> tuple[str, int]:
    """Locate `(decl_slice, decl_start_pos)` for a default, named, or local TSX component."""
    mask = js_code_mask(raw_source)
    spans = _js_brace_spans(raw_source, mask) if (local_scope or exported_name != "default") else None

    def _find_named_decl(symbol: str, *, exported_only: bool = False) -> int | None:
        if not exported_only:
            status, pos = _find_lexical_tsx_decl_pos(
                raw_source,
                symbol,
                usage_pos if local_scope else 0,
                mask=mask,
                brace_spans=spans,
            )
            if status == "found":
                return pos
            if status == "ambiguous":
                return None
        prefix = r"\bexport\s+" if exported_only else r"\b"
        pat = re.compile(
            rf"{prefix}(?:async\s+)?function\s+{re.escape(symbol)}\b|"
            rf"{prefix}(?:const|let|var)\s+{re.escape(symbol)}\s*(?::[^=;\n]+)?="
        )
        for m in pat.finditer(raw_source):
            if mask[m.start()]:
                return m.start()
        return None

    def _slice_resolved_decl(pos: int) -> tuple[str, int]:
        return _resolve_tsx_decl_slice_with_pos(raw_source, pos, mask=mask)

    def _resolve_hoc_target(m: re.Match[str]) -> tuple[str, int]:
        inner_tail = raw_source[m.end() :].lstrip()
        m_ref = re.match(r"^(?P<ref>[A-Za-z_$][\w$]*)\s*(?:,|\))", inner_tail)
        if m_ref:
            ref_pos = _find_named_decl(m_ref.group("ref"))
            if ref_pos is not None:
                return _slice_resolved_decl(ref_pos)
        return _slice_tsx_decl_body(raw_source, m.end()), m.end()

    if local_scope:
        status, pos = _find_lexical_tsx_decl_pos(
            raw_source, exported_name, usage_pos, mask=mask, brace_spans=spans
        )
        if status == "found" and pos is not None:
            return _slice_resolved_decl(pos)
        return "", 0

    if exported_name == "default":
        for pat in (
            r"\bexport\s+default\s+(?:async\s+)?function\b",
            r"\bexport\s+default\s+(?:async\s+)?\(",
            r"\bexport\s+default\s+(?:async\s+)?[A-Za-z_$][\w$]*\s*=>",
        ):
            for m in re.finditer(pat, raw_source):
                if mask[m.start()]:
                    return _slice_tsx_decl_body(raw_source, m.start()), m.start()
        for m in re.finditer(
            r"\bexport\s+default\s+(?:React\.)?(?:memo|forwardRef)\s*(?:<[^;()]{0,160}?>)?\s*\(",
            raw_source,
        ):
            if mask[m.start()]:
                return _resolve_hoc_target(m)
        for m in re.finditer(
            r"\bexport\s+default\s+(?!(?:async\s+)?function\b|class\b)(?P<ref>[A-Za-z_$][\w$]*)\b(?!\s*=>)",
            raw_source,
        ):
            if mask[m.start()]:
                ref_pos = _find_named_decl(m.group("ref"))
                if ref_pos is not None:
                    return _slice_resolved_decl(ref_pos)
        for m in _EXPORT_BLOCK_RE.finditer(raw_source):
            if not mask[m.start()]:
                continue
            if m.group("dq") is not None or m.group("sq") is not None:
                for _orig, exp in _parse_export_specifiers(m.group("body")):
                    if exp == "default":
                        return "", 0
                continue
            for orig, exp in _parse_export_specifiers(m.group("body")):
                if exp == "default":
                    ref_pos = _find_named_decl(orig)
                    if ref_pos is not None:
                        return _slice_resolved_decl(ref_pos)
        return raw_source, 0

    for m in _EXPORT_BLOCK_RE.finditer(raw_source):
        if not mask[m.start()]:
            continue
        is_reexport = m.group("dq") is not None or m.group("sq") is not None
        for orig, exp in _parse_export_specifiers(m.group("body")):
            if exp == exported_name:
                if is_reexport:
                    return "", 0
                ref_pos = _find_named_decl(orig)
                return _slice_resolved_decl(ref_pos) if ref_pos is not None else ("", 0)

    direct_export_pos = _find_named_decl(exported_name, exported_only=True)
    if direct_export_pos is not None:
        return _slice_resolved_decl(direct_export_pos)

    has_any_export = any(mask[em.start()] for em in re.finditer(r"\bexport\b", raw_source))
    if not has_any_export:
        direct_pos = _find_named_decl(exported_name)
        if direct_pos is not None:
            return _slice_resolved_decl(direct_pos)
        return raw_source, 0
    return "", 0


def _locate_tsx_export_source(
    raw_source: str, exported_name: str, *, local_scope: bool = False
) -> str:
    """Locate the declaration slice for a default, named, or local React/JSX component."""
    decl_src, _pos = _locate_tsx_export_source_with_pos(
        raw_source, exported_name, local_scope=local_scope
    )
    return decl_src


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


def _extract_jsx_or_conditional_branches(
    expr_src: str,
    portal_names: frozenset[str] = frozenset({"createPortal"}),
) -> list[str]:
    """Collect JSX roots, portal semantics, and call uncertainty from a returned JS expression."""
    s = _unwrap_outer_parens(expr_src)
    if not s:
        return ["<!--WYTHE_EXPR-->null"]
    mask = js_code_mask(s)

    ternary = _split_top_level_ternary(s, mask)
    if ternary is not None:
        _cond, cons, alt = ternary
        return _extract_jsx_or_conditional_branches(
            cons, portal_names
        ) + _extract_jsx_or_conditional_branches(alt, portal_names)

    or_parts = _split_top_level_binary_ops(s, ("||", "??"), mask)
    if len(or_parts) > 1:
        out: list[str] = []
        for term, _op in or_parts:
            out.extend(_extract_jsx_or_conditional_branches(term, portal_names))
        return out

    and_parts = _split_top_level_binary_ops(s, ("&&",), mask)
    if len(and_parts) > 1:
        rhs_branches = _extract_jsx_or_conditional_branches(and_parts[-1][0], portal_names)
        return [*rhs_branches, "<!--WYTHE_EXPR-->null"]

    if s.startswith("<"):
        found = _extract_jsx_at(s, 0)
        if found is not None and not s[found[1] :].strip():
            return [found[0]]
        return ["<!--WYTHE_OPAQUE-->"]

    m_call = re.match(r"^(?:await\s+)?(?P<callee>[A-Za-z_$][\w$.]*)\s*(?:<[^()]*>)?\s*\(", s)
    if m_call:
        pend = _scan_paren_end(s, m_call.end() - 1, mask)
        if pend == len(s):
            if _is_portal_call_target(m_call.group("callee"), portal_names):
                return ["<!--WYTHE_EXPR-->null"]
            return ["<!--WYTHE_OPAQUE-->"]

    if "<" in s or any(re.search(rf"\b{re.escape(pname)}\s*\(", s) for pname in portal_names):
        return ["<!--WYTHE_OPAQUE-->"]
    return [f"<!--WYTHE_EXPR-->{s}"]


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


_NON_METHOD_KEYWORDS = frozenset(
    {
        "abstract",
        "as",
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "declare",
        "delete",
        "do",
        "else",
        "enum",
        "export",
        "extends",
        "finally",
        "for",
        "function",
        "get",
        "if",
        "implements",
        "import",
        "in",
        "instanceof",
        "interface",
        "let",
        "new",
        "of",
        "override",
        "private",
        "protected",
        "public",
        "readonly",
        "return",
        "satisfies",
        "set",
        "static",
        "super",
        "switch",
        "throw",
        "try",
        "type",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
    }
)
_METHOD_MODIFIER_WORDS = frozenset(
    {
        "abstract",
        "async",
        "declare",
        "get",
        "override",
        "private",
        "protected",
        "public",
        "readonly",
        "set",
        "static",
    }
)
_DECL_NAME_KEYWORDS = frozenset({"async", "delete", "get", "set", "static", "type"})


def _skip_ws_and_unmasked(src: str, pos: int, mask: list[bool], limit: int) -> int:
    """Advance `pos` past comments, strings, regexes, and whitespace."""
    while pos < limit and (not mask[pos] or src[pos].isspace()):
        pos += 1
    return pos


def _prev_sig_char(
    src: str, pos: int, mask: list[bool], *, skip_modifiers: bool = False
) -> tuple[int, str]:
    """Return `(index, char)` of the previous significant code token before `pos`."""
    j = pos - 1
    while j >= 0:
        if not mask[j] or src[j].isspace():
            j -= 1
            continue
        if skip_modifiers:
            if src[j] == "*":
                j -= 1
                continue
            if src[j].isalnum() or src[j] in "_$":
                ws = j
                while ws > 0 and (src[ws - 1].isalnum() or src[ws - 1] in "_$"):
                    ws -= 1
                if src[ws : j + 1] in _METHOD_MODIFIER_WORDS:
                    j = ws - 1
                    continue
        return j, src[j]
    return -1, ""


def _skip_balanced_type_args(src: str, pos: int, mask: list[bool], limit: int) -> int | None:
    """Advance past `<...>` generic type parameters starting at `pos`."""
    if pos >= limit or src[pos] != "<":
        return None
    depth = 0
    p = pos
    while p < limit:
        if not mask[p]:
            p += 1
            continue
        ch = src[p]
        if ch in (";", "{", "}"):
            return None
        if ch == "<" and not src.startswith("=>", p):
            depth += 1
        elif ch == ">" and (p == 0 or src[p - 1] != "="):
            depth -= 1
            if depth == 0:
                return p + 1
        p += 1
    return None


def _scan_nested_callable_end(
    src: str,
    after_name_pos: int,
    mask: list[bool],
    limit: int,
    *,
    allow_optional_ident: bool = False,
    allow_return_type: bool = True,
) -> int | None:
    """Return end index past `{...}` for a nested `function` or object/class method, else `None`."""
    p = _skip_ws_and_unmasked(src, after_name_pos, mask, limit)
    if allow_optional_ident:
        if p < limit and src[p] == "*":
            p = _skip_ws_and_unmasked(src, p + 1, mask, limit)
        if p < limit and (src[p].isalpha() or src[p] in "_$"):
            while p < limit and (src[p].isalnum() or src[p] in "_$"):
                p += 1
            p = _skip_ws_and_unmasked(src, p, mask, limit)
    if p < limit and src[p] == "<":
        p_next = _skip_balanced_type_args(src, p, mask, limit)
        if p_next is None:
            return None
        p = _skip_ws_and_unmasked(src, p_next, mask, limit)
    if p >= limit or src[p] != "(":
        return None
    p_end = _scan_paren_end(src, p, mask, skip_jsx=True)
    if p_end is None or p_end > limit:
        return None
    p = _skip_ws_and_unmasked(src, p_end, mask, limit)
    if p < limit and src[p] == "{":
        bend = _scan_brace_end(src, p)
        return bend if bend is not None else limit
    if p >= limit or src[p] != ":" or not allow_return_type:
        return None
    p = _skip_ws_and_unmasked(src, p + 1, mask, limit)
    adepth = 0
    tpdepth = 0
    tbdepth = 0
    last_sig = ":"
    while p < limit:
        if not mask[p]:
            p += 1
            continue
        ch = src[p]
        if ch == "{":
            if adepth == 0 and tpdepth == 0 and tbdepth == 0 and last_sig not in (":", "|", "&"):
                bend = _scan_brace_end(src, p)
                return bend if bend is not None else limit
            tend = _scan_brace_end(src, p)
            if tend is None or tend > limit:
                return None
            last_sig = "}"
            p = tend
            continue
        if adepth == 0 and tpdepth == 0 and tbdepth == 0:
            if ch in (";", ",", ")", "]"):
                return None
            if ch == "=" and not src.startswith("=>", p):
                return None
            if src.startswith("=>", p):
                last_sig = ">"
                p += 2
                continue
            if ch == "<" and last_sig == ":" and _extract_jsx_at(src, p) is not None:
                return None
        if ch == "(":
            tpdepth += 1
        elif ch == ")" and tpdepth > 0:
            tpdepth -= 1
        elif ch == "[":
            tbdepth += 1
        elif ch == "]" and tbdepth > 0:
            tbdepth -= 1
        elif ch == "<" and not src.startswith("=>", p):
            adepth += 1
        elif ch == ">" and adepth > 0 and (p == 0 or src[p - 1] != "="):
            adepth -= 1
        if not ch.isspace():
            last_sig = ch
        p += 1
    return None


def _scan_nested_class_end(
    src: str, after_class_pos: int, mask: list[bool], limit: int
) -> int | None:
    """Return end index past `{...}` of a nested `class` declaration/expression, else `None`."""
    p = after_class_pos
    pdepth = 0
    bdepth = 0
    adepth = 0
    while p < limit:
        if not mask[p]:
            p += 1
            continue
        ch = src[p]
        if pdepth == 0 and bdepth == 0 and adepth == 0:
            if ch == ";" or src.startswith("=>", p):
                return None
            if ch == "{":
                bend = _scan_brace_end(src, p)
                return bend if bend is not None else limit
        if ch == "(":
            pdepth += 1
        elif ch == ")" and pdepth > 0:
            pdepth -= 1
        elif ch == "[":
            bdepth += 1
        elif ch == "]" and bdepth > 0:
            bdepth -= 1
        elif ch == "<" and not src.startswith("=>", p):
            adepth += 1
        elif ch == ">" and adepth > 0 and (p == 0 or src[p - 1] != "="):
            adepth -= 1
        p += 1
    return None


def _extract_tsx_return_markup(
    target_src: str,
    *,
    portal_names: frozenset[str] = frozenset({"createPortal"}),
) -> str:
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
        expr_tail = _unwrap_outer_parens(expr_tail)
        if not expr_tail:
            return ""
        if "<" in expr_tail or any(p in expr_tail for p in portal_names):
            branches = _extract_jsx_or_conditional_branches(expr_tail, portal_names)
            return "\n<!--WYTHE_BRANCH-->\n".join(branches)
        return f"<!--WYTHE_EXPR-->{expr_tail}"

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
        ch_cur = target_src[i]
        if ch_cur == "[":
            _, prev_sep = _prev_sig_char(target_src, i, mask, skip_modifiers=True)
            if prev_sep in ("", "{", ",", ";", "}"):
                bdepth = 0
                bp = i
                close_br: int | None = None
                while bp < limit:
                    if not mask[bp]:
                        bp += 1
                        continue
                    if target_src[bp] == "[":
                        bdepth += 1
                    elif target_src[bp] == "]":
                        bdepth -= 1
                        if bdepth == 0:
                            close_br = bp + 1
                            break
                    bp += 1
                if close_br is not None:
                    method_end = _scan_nested_callable_end(
                        target_src, close_br, mask, limit, allow_return_type=True
                    )
                    if method_end is not None:
                        i = method_end
                        continue
        if ch_cur.isalpha() or ch_cur in "_$":
            prev_ok = i == 0 or not (target_src[i - 1].isalnum() or target_src[i - 1] in "_$")
            if prev_ok:
                word_end = i + 1
                while word_end < limit and (
                    target_src[word_end].isalnum() or target_src[word_end] in "_$"
                ):
                    word_end += 1
                word = target_src[i:word_end]
                _, prev_sig = _prev_sig_char(target_src, i, mask, skip_modifiers=False)
                if word == "function" and prev_sig != ".":
                    fn_end = _scan_nested_callable_end(
                        target_src,
                        word_end,
                        mask,
                        limit,
                        allow_optional_ident=True,
                        allow_return_type=True,
                    )
                    i = fn_end if fn_end is not None else word_end
                    continue
                if word == "class" and prev_sig != ".":
                    cls_end = _scan_nested_class_end(target_src, word_end, mask, limit)
                    if cls_end is not None:
                        i = cls_end
                        continue
                    i = word_end
                    continue
                if word != "return" and prev_sig != ".":
                    _, member_sep = _prev_sig_char(target_src, i, mask, skip_modifiers=True)
                    is_candidate = word not in _NON_METHOD_KEYWORDS or (
                        word in _DECL_NAME_KEYWORDS
                        and member_sep in ("", "{", ",", ";", "}", "*")
                    )
                    if is_candidate:
                        method_end = _scan_nested_callable_end(
                            target_src,
                            word_end,
                            mask,
                            limit,
                            allow_return_type=member_sep in ("", "{", ",", ";", "}"),
                        )
                        if method_end is not None:
                            i = method_end
                            continue
                    i = word_end
                    continue
        if target_src.startswith("return", i):
            prev_ok = i == 0 or not (target_src[i - 1].isalnum() or target_src[i - 1] in "_$.")
            nxt = i + 6
            next_ok = nxt >= limit or not (target_src[nxt].isalnum() or target_src[nxt] in "_$")
            if prev_ok and next_ok:
                pos = nxt
                while pos < limit and target_src[pos].isspace():
                    pos += 1
                depth = 0
                end_pos = pos
                while end_pos < limit:
                    if not mask[end_pos]:
                        end_pos += 1
                        continue
                    ch = target_src[end_pos]
                    if ch == "<":
                        found_jsx = _extract_jsx_at(target_src, end_pos)
                        if found_jsx is not None and found_jsx[1] <= limit:
                            end_pos = found_jsx[1]
                            continue
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
                if "<" in raw_expr or any(p in raw_expr for p in portal_names):
                    sub_branches = _extract_jsx_or_conditional_branches(raw_expr, portal_names)
                    if sub_branches:
                        branches.extend(sub_branches)
                    else:
                        branches.append(f"<!--WYTHE_EXPR-->{raw_expr or 'null'}")
                else:
                    branches.append(f"<!--WYTHE_EXPR-->{raw_expr or 'null'}")
                i = end_pos + 1
                continue
        i += 1
    if not branches:
        return ""
    return "\n<!--WYTHE_BRANCH-->\n".join(branches)


def _extract_component_props_and_markup(
    raw_source: str,
    suffix: str,
    exported_name: str = "default",
    *,
    local_scope: bool = False,
    usage_pos: int | None = None,
    _scope_anchor_out: list[int] | None = None,
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
                prop_defaults[pname] = (
                    _eval_attr_value(dval, preserve_undefined=True) if dval is not None else "unknown"
                )
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
            for pm in re.finditer(r"withDefaults\s*\([\s\S]{0,400}?,\s*\{", sb):
                bend = _scan_brace_end(sb, pm.end() - 1)
                if bend is None:
                    continue
                for item in _split_top_level_js(sb[pm.end() : bend - 1], ","):
                    k_raw, v_raw = _split_first_top_level_js(item, ":")
                    if v_raw is not None:
                        k = k_raw.strip().strip("'\"")
                        if re.fullmatch(r"[A-Za-z_$][\w$]*", k):
                            prop_defaults[k] = _eval_attr_value(v_raw, preserve_undefined=True)
                            prop_aliases.setdefault(k, k)
            for pm in re.finditer(r"defineProps\s*\(\s*\{", sb):
                bend = _scan_brace_end(sb, pm.end() - 1)
                if bend is None:
                    continue
                for item in _split_top_level_js(sb[pm.end() : bend - 1], ","):
                    k_raw, v_raw = _split_first_top_level_js(item, ":")
                    if v_raw is None:
                        continue
                    k = k_raw.strip().strip("'\"")
                    if not re.fullmatch(r"[A-Za-z_$][\w$]*", k):
                        continue
                    v_str = v_raw.strip()
                    dstate = "unknown"
                    if v_str.startswith("{") and v_str.endswith("}"):
                        for sub in _split_top_level_js(v_str[1:-1], ","):
                            sk, sv = _split_first_top_level_js(sub, ":")
                            if sv is not None and sk.strip().strip("'\"") == "default":
                                dstate = _eval_attr_value(sv, preserve_undefined=True)
                                break
                    prop_defaults.setdefault(k, dstate)
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

    # .tsx / .jsx: locate the target exported or same-file component declaration
    target_src, decl_pos = _locate_tsx_export_source_with_pos(
        raw_source, exported_name, local_scope=local_scope, usage_pos=usage_pos
    )
    tmask = js_code_mask(target_src)
    body_info = _find_tsx_body_start(target_src, tmask)
    if _scope_anchor_out is not None:
        if body_info is not None:
            anchor = decl_pos + body_info[1] + (1 if body_info[0] else 0)
        else:
            anchor = decl_pos
        _scope_anchor_out.append(min(anchor, max(0, len(raw_source) - 1)))
    sig_src = target_src[: body_info[1]] if body_info is not None else target_src
    m_open = re.search(r"\(\s*\{", sig_src)
    if m_open:
        bend = _scan_brace_end(sig_src, m_open.end() - 1)
        if bend is not None:
            defs, als = _parse_default_params(sig_src[m_open.end() : bend - 1])
            prop_defaults.update(defs)
            prop_aliases.update(als)
    portal_names = _portal_names_from_imports(parse_component_imports(raw_source))
    return prop_defaults, prop_aliases, _extract_tsx_return_markup(
        target_src, portal_names=portal_names
    )


def _split_top_level_coalesce_ops(expr: str) -> list[tuple[str, str | None]]:
    """Split a JS expression on top-level `||` / `??`, yielding `(term, following_op)` pairs."""
    parts: list[tuple[str, str | None]] = []
    depth = 0
    quote: str | None = None
    start = 0
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
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
        elif depth == 0 and (expr.startswith("||", i) or expr.startswith("??", i)):
            op = expr[i : i + 2]
            parts.append((expr[start:i], op))
            i += 2
            start = i
            continue
        i += 1
    parts.append((expr[start:], None))
    return parts


def _eval_coalesce_expr(
    expr: str,
    *,
    prop_values: dict[str, str] | None,
    inner_status: str,
    unknown_fallback: str | None = None,
    depth: int = 0,
    portal_names: frozenset[str] = frozenset({"createPortal"}),
) -> str:
    """Evaluate a JS `||` / `??` expression preserving nullish vs falsy semantics."""
    s = _unwrap_outer_parens(expr)
    if depth > 6:
        return "dynamic" if prop_values is None else "opaque"
    parts = _split_top_level_coalesce_ops(s)
    if len(parts) == 1:
        t = s
        if t == "undefined":
            return "undefined"
        if t == "null":
            return "null"
        if t in ("", "''", '""', "``"):
            return "empty"
        if t == "false":
            return "bool_false"
        if t == "true":
            return "bool_true"
        if re.fullmatch(r"-?\d+(?:\.\d+)?", t):
            try:
                return "num_zero" if float(t) == 0.0 else "named"
            except ValueError:
                return "named"
        if (
            len(t) >= 2
            and t[0] in ("'", '"')
            and t[-1] == t[0]
            and t[0] not in t[1:-1].replace(f"\\{t[0]}", "")
        ):
            inner = t[1:-1]
            return "named" if inner.strip() else ("blank" if inner else "empty")
        if len(t) >= 2 and t[0] == "`" and t[-1] == "`" and "${" not in t and "`" not in t[1:-1].replace("\\`", ""):
            inner = t[1:-1]
            return "named" if inner.strip() else ("blank" if inner else "empty")
        m_portal = re.match(r"^(?:await\s+)?(?P<callee>[A-Za-z_$][\w$.]*)\s*(?:<[^()]*>)?\s*\(", t)
        if (
            m_portal
            and _scan_paren_end(t, m_portal.end() - 1) == len(t)
            and _is_portal_call_target(m_portal.group("callee"), portal_names)
        ):
            return "null"
        mp = re.fullmatch(r"(?:props\.)?(?P<p>[A-Za-z_$][\w$]*)", t)
        if prop_values is not None and mp and mp.group("p") in prop_values:
            return prop_values[mp.group("p")]
        if t in ("children", "props.children"):
            return "undefined" if inner_status == "omitted" else inner_status
        if unknown_fallback is not None:
            return unknown_fallback
        return "dynamic" if prop_values is None else "opaque"

    states = [
        (
            _eval_coalesce_expr(
                term,
                prop_values=prop_values,
                inner_status=inner_status,
                unknown_fallback=unknown_fallback,
                depth=depth + 1,
                portal_names=portal_names,
            ),
            op,
        )
        for term, op in parts
    ]
    acc, prev_op = states[0]
    for nxt_state, nxt_op in states[1:]:
        if prev_op == "??":
            if acc in ("undefined", "null"):
                acc = nxt_state
            elif acc in ("empty", "empty_node", "blank", "named", "icon_only", "num_zero", "bool_false", "bool_true"):
                pass
            elif acc == "dynamic":
                acc = "named" if nxt_state == "named" else "dynamic"
            else:
                acc = "opaque"
        else:
            # Logical `||` treats empty string / false / 0 / null / undefined as falsy.
            if acc in ("undefined", "null", "empty", "bool_false", "num_zero"):
                acc = nxt_state
            elif acc in ("empty_node", "blank", "named", "icon_only", "bool_true"):
                pass
            elif acc == "dynamic":
                acc = "named" if nxt_state == "named" else "dynamic"
            else:
                acc = "opaque"
        prev_op = nxt_op
    return acc


def _classify_expr_semantics(
    raw_expr: str,
    *,
    prop_values: dict[str, str] | None,
    inner_status: str,
    render_booleans_as_text: bool = False,
    portal_names: frozenset[str] = frozenset({"createPortal"}),
) -> str:
    """Classify a `{...}` expression as `ignore`, `named`, `icon_only`, `empty`, or `opaque`."""
    expr = re.sub(r"/\*[\s\S]*?\*/", "", raw_expr).strip()
    if expr.startswith("{") and expr.endswith("}"):
        expr = expr[1:-1].strip()
    if not expr or expr[0] in ("#", ":", "/"):
        return "ignore"
    if expr.startswith("@render"):
        if "children" in expr:
            if inner_status in _BOOL_PROP_STATES:
                return "named" if render_booleans_as_text else "empty"
            if inner_status == "omitted" or inner_status in _EMPTY_PROP_STATES:
                return "empty"
            if inner_status == "num_zero":
                return "named"
            return inner_status
        return "named"
    if expr.startswith("@html"):
        expr = expr[5:].strip()
    elif expr.startswith("@"):
        return "ignore"
    res = _eval_coalesce_expr(
        expr,
        prop_values=prop_values,
        inner_status=inner_status,
        depth=0,
        portal_names=portal_names,
    )
    if res in _BOOL_PROP_STATES:
        return "named" if render_booleans_as_text else "empty"
    if res == "omitted" or res in _EMPTY_PROP_STATES:
        return "empty"
    if res in ("named", "dynamic", "num_zero"):
        return "named"
    if res == "icon_only":
        return "icon_only"
    return "opaque"


def _eval_component_child_inner(
    inner_body: str,
    *,
    self_closing: bool,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[..., str] | None,
    prop_values: dict[str, str] | None,
    inner_status: str,
    render_booleans_as_text: bool,
    allow_vue_kebab: bool,
    source_offset: int,
    portal_names: frozenset[str],
) -> str:
    """Summarize the `children` / default-slot value state passed into a child component."""
    cleaned_inner = _JSX_COMMENT_RE.sub("", _HTML_COMMENT_RE.sub("", inner_body))
    stripped_inner = cleaned_inner.strip()
    if self_closing or cleaned_inner == "" or ("\n" in cleaned_inner and not stripped_inner):
        return "omitted"
    if not stripped_inner:
        return "blank"
    if (
        stripped_inner.startswith("{")
        and _scan_brace_end(stripped_inner, 0) == len(stripped_inner)
        and "<" not in stripped_inner
        and not stripped_inner.startswith(("{#", "{:", "{/", "{@"))
    ):
        expr_s = stripped_inner[1:-1].strip()
        if (
            render_booleans_as_text
            and expr_s.startswith("{")
            and expr_s.endswith("}")
            and _scan_brace_end(expr_s, 0) == len(expr_s)
        ):
            expr_s = expr_s[1:-1].strip()
        if expr_s:
            return _eval_coalesce_expr(
                expr_s,
                prop_values=prop_values,
                inner_status=inner_status,
                portal_names=portal_names,
            )
        return "omitted"
    cst, copaque, _ = _classify_markup_segment(
        inner_body,
        imported_components=imported_components,
        component_resolver=component_resolver,
        prop_values=prop_values,
        inner_status=inner_status,
        render_booleans_as_text=render_booleans_as_text,
        allow_vue_kebab=allow_vue_kebab,
        source_offset=source_offset,
    )
    if cst == "named":
        return "named"
    if copaque:
        return "opaque"
    if cst == "icon_only":
        return "icon_only"
    return "empty_node"


def _extract_dynamic_component_selector(
    tag_low: str,
    attrs: str,
    *,
    allow_vue_kebab: bool,
) -> tuple[bool, str | None, str]:
    """Detect Svelte/Vue dynamic component tags and return `(matched, selector_expr, cleaned_attrs)`."""
    if tag_low == "svelte:component":
        m = re.search(r"(?<![\w$-])this\s*=\s*\{", attrs)
        if m:
            bend = _scan_brace_end(attrs, m.end() - 1)
            if bend is None:
                return True, None, attrs
            return True, attrs[m.end() : bend - 1].strip(), attrs[: m.start()] + attrs[bend:]
        ms = re.search(r"""(?<![\w$-])this\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""", attrs)
        if ms:
            val = (ms.group("dq") if ms.group("dq") is not None else ms.group("sq") or "").strip()
            return True, repr(val), attrs[: ms.start()] + attrs[ms.end() :]
        return True, None, attrs
    if tag_low == "component" and (
        allow_vue_kebab or re.search(r"(?<![\w$-])(?::|v-bind:)is\s*=", attrs)
    ):
        mb = re.search(
            r"""(?<![\w$-])(?::|v-bind:)is\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""",
            attrs,
        )
        if mb:
            expr = (mb.group("dq") if mb.group("dq") is not None else mb.group("sq") or "").strip()
            return True, expr, attrs[: mb.start()] + attrs[mb.end() :]
        ms = re.search(r"""(?<![\w$-])is\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""", attrs)
        if ms:
            val = (ms.group("dq") if ms.group("dq") is not None else ms.group("sq") or "").strip()
            if val.startswith("vue:"):
                val = val[4:].strip()
            return True, repr(val), attrs[: ms.start()] + attrs[ms.end() :]
        return True, None, attrs
    return False, None, attrs


def _resolve_dynamic_component_selector(
    selector_expr: str | None,
    *,
    cleaned_attrs: str,
    inner_body: str,
    child_inner: str,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[..., str] | None,
    prop_values: dict[str, str] | None,
    inner_status: str,
    render_booleans_as_text: bool,
    allow_vue_kebab: bool,
    source_offset: int,
    usage_pos: int,
    portal_names: frozenset[str],
    depth: int = 0,
) -> str:
    """Resolve `<component :is>` / `<svelte:component this={...}>` to component semantics or `"opaque"`."""
    if depth > 4 or selector_expr is None:
        return "opaque"
    s = _unwrap_outer_parens(selector_expr)
    if not s:
        return "opaque"
    if s in ("null", "undefined", "false", "''", '""', "``"):
        return "empty"
    ternary = _split_top_level_ternary(s)
    if ternary is not None:
        _cond, cons, alt = ternary
        st_c = _resolve_dynamic_component_selector(
            cons,
            cleaned_attrs=cleaned_attrs,
            inner_body=inner_body,
            child_inner=child_inner,
            imported_components=imported_components,
            component_resolver=component_resolver,
            prop_values=prop_values,
            inner_status=inner_status,
            render_booleans_as_text=render_booleans_as_text,
            allow_vue_kebab=allow_vue_kebab,
            source_offset=source_offset,
            usage_pos=usage_pos,
            portal_names=portal_names,
            depth=depth + 1,
        )
        st_a = _resolve_dynamic_component_selector(
            alt,
            cleaned_attrs=cleaned_attrs,
            inner_body=inner_body,
            child_inner=child_inner,
            imported_components=imported_components,
            component_resolver=component_resolver,
            prop_values=prop_values,
            inner_status=inner_status,
            render_booleans_as_text=render_booleans_as_text,
            allow_vue_kebab=allow_vue_kebab,
            source_offset=source_offset,
            usage_pos=usage_pos,
            portal_names=portal_names,
            depth=depth + 1,
        )
        return st_c if st_c == st_a else "opaque"

    target: str | None = None
    lit = _unwrap_static_js_string(s)
    if lit is not None:
        target = lit[4:].strip() if lit.startswith("vue:") else lit.strip()
        if not target:
            return "empty"
    elif re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?", s):
        root = s.split(".", 1)[0]
        if prop_values is not None and root in prop_values:
            pval = prop_values[root]
            if pval in _EMPTY_PROP_STATES or pval in ("omitted", "bool_false"):
                return "empty"
            return "opaque"
        if _normalize_component_lookup(
            s, imported_components, allow_vue_case_insensitive=allow_vue_kebab
        ) is None:
            return "opaque"
        target = s
    else:
        return "opaque"

    assert target is not None
    tlow = target.lower()
    if tlow in ("script", "style") or _is_aria_hidden_true(cleaned_attrs):
        return "empty"
    if tlow == "img":
        return _eval_inline_graphic_name(cleaned_attrs, allow_alt=True, prop_values=prop_values)
    if tlow in ("svg", "i"):
        gst, gopaque = _classify_graphic_element(
            tlow,
            cleaned_attrs,
            inner_body,
            imported_components=imported_components,
            component_resolver=component_resolver,
            prop_values=prop_values,
            inner_status=inner_status,
            render_booleans_as_text=render_booleans_as_text,
            allow_vue_kebab=allow_vue_kebab,
            source_offset=source_offset,
        )
        return "opaque" if gopaque else gst
    matched_imp = _normalize_component_lookup(
        target, imported_components, allow_vue_case_insensitive=allow_vue_kebab
    )
    if target[0].isupper() or "." in target or "-" in target or matched_imp is not None:
        return _resolve_component_tag(
            target,
            cleaned_attrs,
            child_inner,
            imported_components=imported_components,
            component_resolver=component_resolver,
            prop_values=prop_values,
            allow_vue_kebab=allow_vue_kebab,
            usage_pos=usage_pos,
        )
    own_name = _eval_element_own_name(cleaned_attrs, allow_alt=False, prop_values=prop_values)
    if own_name in ("named", "opaque"):
        return own_name
    inj = _eval_injected_html_name(
        cleaned_attrs,
        prop_values=prop_values,
        inner_status=inner_status,
        render_booleans_as_text=render_booleans_as_text,
    )
    if inj in ("named", "icon_only", "opaque"):
        return inj
    if child_inner == "named":
        return "named"
    if child_inner == "opaque":
        return "opaque"
    if child_inner == "icon_only":
        return "icon_only"
    return "empty"


def _classify_markup_segment(
    src: str,
    *,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[..., str] | None,
    prop_values: dict[str, str] | None = None,
    inner_status: str = "omitted",
    render_booleans_as_text: bool = False,
    allow_vue_kebab: bool = False,
    source_offset: int = 0,
) -> tuple[str, list[str], bool]:
    """Classify markup children as `(status, opaque_tags, has_visual_empty_or_icon)`."""
    has_named = False
    has_icon = False
    has_empty_comp = False
    opaque_tags: list[str] = []
    portal_names = _portal_names_from_imports(imported_components)
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
                render_booleans_as_text=render_booleans_as_text,
                portal_names=portal_names,
            )
            if sem == "named":
                has_named = True
            elif sem == "icon_only":
                has_icon = True
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
                gst, gopaque = _classify_graphic_element(
                    tag_low,
                    attrs,
                    inner_body,
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                    prop_values=prop_values,
                    inner_status=inner_status,
                    render_booleans_as_text=render_booleans_as_text,
                    allow_vue_kebab=allow_vue_kebab,
                    source_offset=source_offset + open_end,
                )
                if gst == "opaque" and gopaque:
                    for lbl in gopaque:
                        merge_status("opaque", lbl)
                else:
                    merge_status(gst, tag)
                i = next_i
                continue
            if tag_low == "img":
                merge_status(
                    _eval_inline_graphic_name(attrs, allow_alt=True, prop_values=prop_values),
                    tag,
                )
                i = next_i
                continue
            matched_imp = _normalize_component_lookup(
                tag, imported_components, allow_vue_case_insensitive=allow_vue_kebab
            )
            root_imp = matched_imp[1] if matched_imp is not None else None
            if root_imp and _ICON_PKG_SPEC_RE.match(root_imp[0]) and component_resolver is None:
                merge_status(
                    _eval_inline_graphic_name(attrs, allow_alt=False, prop_values=prop_values),
                    tag,
                )
                i = next_i
                continue
            if tag_low == "slot":
                is_named_slot = bool(
                    re.search(r"""(?<![\w$-])(?::|v-bind:)?name\s*=""", attrs)
                )
                if not is_named_slot:
                    if inner_status in ("omitted", "undefined") and inner_body.strip():
                        slot_fallback, _, _ = _classify_markup_segment(
                            inner_body,
                            imported_components=imported_components,
                            component_resolver=component_resolver,
                            prop_values=prop_values,
                            inner_status="omitted",
                            render_booleans_as_text=render_booleans_as_text,
                            allow_vue_kebab=allow_vue_kebab,
                            source_offset=source_offset + open_end,
                        )
                        merge_status(slot_fallback, "slot")
                    else:
                        if inner_status in _BOOL_PROP_STATES:
                            slot_st = "named" if render_booleans_as_text else "empty"
                        elif inner_status == "omitted" or inner_status in _EMPTY_PROP_STATES:
                            slot_st = "empty"
                        elif inner_status in ("dynamic", "num_zero"):
                            slot_st = "named"
                        else:
                            slot_st = inner_status
                        merge_status(slot_st, "slot")
                elif inner_status in ("omitted", "undefined", "blank"):
                    if inner_body.strip():
                        slot_fallback, _, _ = _classify_markup_segment(
                            inner_body,
                            imported_components=imported_components,
                            component_resolver=component_resolver,
                            prop_values=prop_values,
                            inner_status="omitted",
                            render_booleans_as_text=render_booleans_as_text,
                            allow_vue_kebab=allow_vue_kebab,
                            source_offset=source_offset + open_end,
                        )
                        merge_status(slot_fallback, "slot")
                else:
                    # Caller supplied child content that may target or override this named slot.
                    merge_status("opaque", "slot")
                i = next_i
                continue
            if tag_low in ("script", "style"):
                i = next_i
                continue
            if _is_aria_hidden_true(attrs):
                if root_imp and _ICON_PKG_SPEC_RE.match(root_imp[0]):
                    resolved = _resolve_component_tag(
                        tag,
                        attrs,
                        "omitted",
                        imported_components=imported_components,
                        component_resolver=component_resolver,
                        prop_values=prop_values,
                        allow_vue_kebab=allow_vue_kebab,
                        usage_pos=source_offset + i,
                    )
                    merge_status("empty" if resolved == "named" else resolved, tag)
                i = next_i
                continue
            is_dyn_comp, dyn_sel, dyn_attrs = _extract_dynamic_component_selector(
                tag_low,
                attrs,
                allow_vue_kebab=allow_vue_kebab,
            )
            if is_dyn_comp:
                child_inner = _eval_component_child_inner(
                    inner_body,
                    self_closing=self_closing,
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                    prop_values=prop_values,
                    inner_status=inner_status,
                    render_booleans_as_text=render_booleans_as_text,
                    allow_vue_kebab=allow_vue_kebab,
                    source_offset=source_offset + open_end,
                    portal_names=portal_names,
                )
                dyn_status = _resolve_dynamic_component_selector(
                    dyn_sel,
                    cleaned_attrs=dyn_attrs,
                    inner_body=inner_body,
                    child_inner=child_inner,
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                    prop_values=prop_values,
                    inner_status=inner_status,
                    render_booleans_as_text=render_booleans_as_text,
                    allow_vue_kebab=allow_vue_kebab,
                    source_offset=source_offset + open_end,
                    usage_pos=source_offset + i,
                    portal_names=portal_names,
                )
                merge_status(dyn_status, tag)
                i = next_i
                continue
            if tag[0].isupper() or "." in tag or "-" in tag or matched_imp is not None:
                child_inner = _eval_component_child_inner(
                    inner_body,
                    self_closing=self_closing,
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                    prop_values=prop_values,
                    inner_status=inner_status,
                    render_booleans_as_text=render_booleans_as_text,
                    allow_vue_kebab=allow_vue_kebab,
                    source_offset=source_offset + open_end,
                    portal_names=portal_names,
                )
                resolved = _resolve_component_tag(
                    tag,
                    attrs,
                    child_inner,
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                    prop_values=prop_values,
                    allow_vue_kebab=allow_vue_kebab,
                    usage_pos=source_offset + i,
                )
                merge_status(resolved, tag)
                i = next_i
                continue
            own_name = _eval_element_own_name(attrs, allow_alt=False, prop_values=prop_values)
            if own_name == "named":
                has_named = True
                i = next_i
                continue
            if own_name == "opaque":
                merge_status("opaque", tag)
            inj = _eval_injected_html_name(
                attrs,
                prop_values=prop_values,
                inner_status=inner_status,
                render_booleans_as_text=render_booleans_as_text,
            )
            if inj == "named":
                has_named = True
                i = next_i
                continue
            if inj == "icon_only":
                has_icon = True
                i = next_i
                continue
            if inj == "opaque":
                merge_status("opaque", tag)
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


def _is_aria_hidden_true(attrs: str) -> bool:
    """True when element attributes statically set `aria-hidden="true"` / `{true}` / bare boolean."""
    return bool(
        re.search(r"""(?<![\w$-])aria-hidden\s*=\s*(?:['"]true['"]|\{\s*true\s*\})""", attrs)
        or re.search(
            r"""(?<![\w$-])(?::|v-bind:)aria-hidden\s*=\s*(?:"\s*(?:true|'true')\s*"|'\s*(?:true|"true")\s*')""",
            attrs,
        )
        or re.search(r"""(?<![\w$-])aria-hidden(?!\s*=)(?=\s|$|/)""", attrs)
    )


def _has_presentational_role(attrs: str) -> bool:
    """True when `role` is statically `presentation` or `none`, stripping implicit/ARIA naming."""
    return bool(
        re.search(
            r"""(?<![\w$-])role\s*=\s*(?:['"](?:presentation|none)['"]|\{\s*['"](?:presentation|none)['"]\s*\})""",
            attrs,
        )
    )


def _eval_element_own_name(
    attrs: str,
    *,
    allow_alt: bool,
    prop_values: dict[str, str] | None,
) -> str | None:
    """Evaluate ARIA/`title`/`alt` accessible name attributes on an element as `named`, `opaque`, or `None`."""
    if _is_aria_hidden_true(attrs) or _has_presentational_role(attrs):
        return None
    attr_names = ("aria-label", "aria-labelledby", "title") + (("alt",) if allow_alt else ())
    saw_opaque = False
    for attr_name in attr_names:
        mb = re.search(
            rf"""(?<![\w$-])(?::|v-bind:){re.escape(attr_name)}\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""",
            attrs,
        )
        if mb:
            bexpr = mb.group("dq") if mb.group("dq") is not None else (mb.group("sq") or "")
            sem = _classify_expr_semantics(
                bexpr,
                prop_values=prop_values,
                inner_status="empty",
            )
            if sem in ("named", "dynamic"):
                return "named"
            if sem == "opaque":
                saw_opaque = True
            continue
        m = re.search(
            rf"""(?<![\w$:-]){re.escape(attr_name)}\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|\{{(?P<expr>[^}}]+)\}})""",
            attrs,
        )
        if m:
            lit = m.group("dq") if m.group("dq") is not None else m.group("sq")
            if lit is not None:
                if lit.strip():
                    return "named"
                continue
            sem = _classify_expr_semantics(
                m.group("expr") or "",
                prop_values=prop_values,
                inner_status="empty",
            )
            if sem in ("named", "dynamic"):
                return "named"
            if sem == "opaque":
                saw_opaque = True
    if allow_alt and _has_svelte_shorthand(attrs, "alt"):
        if prop_values is None or prop_values.get("alt") in ("named", "dynamic"):
            return "named"
        if prop_values.get("alt") == "opaque":
            saw_opaque = True
    if "{..." in attrs or re.search(r"(?<![\w$:-])v-bind\s*=", attrs):
        return "named" if prop_values is None else "opaque"
    return "opaque" if saw_opaque else None


def _unwrap_static_js_string(expr: str) -> str | None:
    """Return unquoted string content if `expr` is a static single/double/template literal."""
    s = expr.strip()
    if (
        len(s) >= 2
        and s[0] in ("'", '"')
        and s[-1] == s[0]
        and s[0] not in s[1:-1].replace(f"\\{s[0]}", "")
    ):
        return s[1:-1]
    if (
        len(s) >= 2
        and s[0] == "`"
        and s[-1] == "`"
        and "${" not in s
        and "`" not in s[1:-1].replace("\\`", "")
    ):
        return s[1:-1]
    return None


def _classify_static_html_fragment(html: str) -> str:
    """Classify a statically known HTML string fragment (`named`/`icon_only`/`empty`/`opaque`)."""
    st, copaque, _ = _classify_markup_segment(
        html,
        imported_components={},
        component_resolver=None,
        prop_values=None,
        inner_status="omitted",
    )
    if st == "named":
        return "named"
    if copaque:
        return "opaque"
    if st == "icon_only":
        return "icon_only"
    return "empty"


_HTML_INJECTION_ATTR_RE = re.compile(
    r"""(?<![\w$-])(?P<kind>v-html|(?:v-bind)?:innerHTML|(?:v-bind)?:inner-html|innerHTML)\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')"""
)
_TEXT_INJECTION_ATTR_RE = re.compile(
    r"""(?<![\w$-])(?P<kind>v-text|(?:v-bind)?:textContent|(?:v-bind)?:text-content|(?:v-bind)?:innerText|(?:v-bind)?:inner-text)\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')"""
)


def _eval_injected_html_name(
    attrs: str,
    *,
    prop_values: dict[str, str] | None,
    inner_status: str,
    render_booleans_as_text: bool = False,
) -> str | None:
    """Classify `dangerouslySetInnerHTML`, `v-html`/`innerHTML`, or `v-text`/text bindings."""
    if _is_aria_hidden_true(attrs) or _has_presentational_role(attrs):
        return None
    md = re.search(r"(?<![\w$-])dangerouslySetInnerHTML\s*=\s*\{", attrs)
    if md:
        bend = _scan_brace_end(attrs, md.end() - 1)
        if bend is None:
            return "opaque"
        outer = attrs[md.end() : bend - 1].strip()
        if not (outer.startswith("{") and _scan_brace_end(outer, 0) == len(outer)):
            return "opaque"
        val_expr: str | None = None
        for entry in _split_top_level_js(outer[1:-1], ","):
            item = entry.strip()
            if not item:
                continue
            if item.startswith("..."):
                val_expr = None
                continue
            raw_k, raw_v = _split_first_top_level_js(item, ":")
            if raw_v is not None and raw_k.strip().strip("'\"") == "__html":
                val_expr = raw_v.strip()
            elif raw_v is None and item == "__html":
                val_expr = "__html"
        if val_expr is None:
            return "opaque"
        lit = _unwrap_static_js_string(val_expr)
        if lit is not None:
            return _classify_static_html_fragment(lit)
        sem = _classify_expr_semantics(
            val_expr, prop_values=prop_values, inner_status=inner_status
        )
        return sem if sem in ("named", "empty", "icon_only") else "opaque"

    mv = _HTML_INJECTION_ATTR_RE.search(attrs)
    if mv:
        kind = mv.group("kind")
        raw_val = mv.group("dq") if mv.group("dq") is not None else (mv.group("sq") or "")
        if kind == "innerHTML":
            return _classify_static_html_fragment(raw_val)
        lit = _unwrap_static_js_string(raw_val)
        if lit is not None:
            return _classify_static_html_fragment(lit)
        sem = _classify_expr_semantics(
            raw_val,
            prop_values=prop_values,
            inner_status=inner_status,
            render_booleans_as_text=render_booleans_as_text or kind.startswith(("v-", ":")),
        )
        return sem if sem in ("named", "empty", "icon_only") else "opaque"

    mt = _TEXT_INJECTION_ATTR_RE.search(attrs)
    if mt:
        raw_val = mt.group("dq") if mt.group("dq") is not None else (mt.group("sq") or "")
        lit = _unwrap_static_js_string(raw_val)
        if lit is not None:
            return "named" if lit.strip() else "empty"
        sem = _classify_expr_semantics(
            raw_val,
            prop_values=prop_values,
            inner_status=inner_status,
            render_booleans_as_text=True,
        )
        return sem if sem in ("named", "empty") else "opaque"
    return None


_SVG_NAME_CHILD_RE = re.compile(
    r"(?is)<(?P<ctag>title|text)(?P<cattrs>[^>]*)>(?P<cbody>[\s\S]*?)</(?P=ctag)\s*>"
)


def _classify_graphic_element(
    tag_low: str,
    attrs: str,
    inner_body: str,
    *,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[..., str] | None,
    prop_values: dict[str, str] | None,
    inner_status: str,
    render_booleans_as_text: bool = False,
    allow_vue_kebab: bool = False,
    source_offset: int = 0,
) -> tuple[str, list[str]]:
    """Classify inline `<i>`/`<svg>` checking ARIA/title attrs first, then naming children."""
    own_name = _eval_element_own_name(attrs, allow_alt=False, prop_values=prop_values)
    if own_name == "named":
        return "named", []
    if inner_body and not _is_aria_hidden_true(attrs):
        if tag_low == "i":
            cst, copaque, _ = _classify_markup_segment(
                inner_body,
                imported_components=imported_components,
                component_resolver=component_resolver,
                prop_values=prop_values,
                inner_status=inner_status,
                render_booleans_as_text=render_booleans_as_text,
                allow_vue_kebab=allow_vue_kebab,
                source_offset=source_offset,
            )
            if cst == "named":
                return "named", []
            if copaque:
                return "opaque", copaque
        elif tag_low == "svg" and not _has_presentational_role(attrs):
            child_opaque: list[str] = []
            for cm in _SVG_NAME_CHILD_RE.finditer(inner_body):
                cattrs = cm.group("cattrs") or ""
                if _is_aria_hidden_true(cattrs) or _has_presentational_role(cattrs):
                    continue
                cst, copaque, _ = _classify_markup_segment(
                    cm.group("cbody") or "",
                    imported_components=imported_components,
                    component_resolver=component_resolver,
                    prop_values=prop_values,
                    inner_status=inner_status,
                    render_booleans_as_text=render_booleans_as_text,
                    allow_vue_kebab=allow_vue_kebab,
                    source_offset=source_offset + cm.start("cbody"),
                )
                if cst == "named":
                    return "named", []
                child_opaque.extend(copaque)
            if child_opaque:
                return "opaque", child_opaque
    return (own_name or "icon_only"), []


def _eval_inline_graphic_name(
    attrs: str,
    *,
    allow_alt: bool,
    prop_values: dict[str, str] | None,
) -> str:
    """Classify accessible name of inline `<img>`/`<svg>`/`<i>` or icon component."""
    return _eval_element_own_name(attrs, allow_alt=allow_alt, prop_values=prop_values) or "icon_only"


def _resolve_component_tag(
    tag: str,
    attrs: str,
    inner_status: str,
    *,
    imported_components: dict[str, tuple[str, str]],
    component_resolver: Callable[..., str] | None,
    prop_values: dict[str, str] | None = None,
    allow_vue_kebab: bool = False,
    usage_pos: int | None = None,
) -> str:
    if component_resolver is not None:
        if getattr(component_resolver, "_wythe_accepts_usage_pos", False):
            return component_resolver(tag, attrs, inner_status, usage_pos=usage_pos)
        return component_resolver(tag, attrs, inner_status)
    matched = _normalize_component_lookup(
        tag, imported_components, allow_vue_case_insensitive=allow_vue_kebab
    )
    imp = matched[1] if matched is not None else None
    if imp and _ICON_PKG_SPEC_RE.match(imp[0]):
        return _eval_inline_graphic_name(attrs, allow_alt=False, prop_values=prop_values)
    return "opaque"


def make_local_component_resolver(
    caller_file: Path,
    caller_source: str,
    resolve_import_fn: Callable[[str, Path], Path | None],
    *,
    _caller_imports: dict[str, tuple[str, str]] | None = None,
    _cache: dict[
        tuple[Path, str],
        tuple[dict[str, str], dict[str, str], str, dict[str, tuple[str, str]], Path, str, int],
    ] | None = None,
    _lexical_cache: dict[Path, dict[str, list[tuple[int, tuple[int, int]]]]] | None = None,
    _visiting: frozenset[tuple[Path, str]] = frozenset(),
    _depth: int = 0,
    _parent_props: dict[str, str] | None = None,
    _parent_has_spread: bool = False,
    _fallback_scope_pos: int | None = None,
) -> Callable[..., str]:
    """Build a depth-bounded, cycle-guarded local component accessibility semantics resolver."""
    imports = _caller_imports if _caller_imports is not None else parse_component_imports(caller_source)
    cache = _cache if _cache is not None else {}
    lexical_cache = _lexical_cache if _lexical_cache is not None else {}
    vue_kebab_caller = caller_file.suffix == ".vue"

    def resolve_tag(
        tag_name: str,
        attrs: str,
        inner_status: str,
        *,
        usage_pos: int | None = None,
    ) -> str:
        matched = _normalize_component_lookup(
            tag_name, imports, allow_vue_case_insensitive=vue_kebab_caller
        )
        imp = matched[1] if matched is not None else None
        raw_root = tag_name.split(".", 1)[0]
        effective_usage_pos = usage_pos if usage_pos is not None else _fallback_scope_pos
        scope_status = "missing"
        local_decl_pos: int | None = None
        if caller_file.suffix in (".tsx", ".jsx"):
            caller_index = lexical_cache.get(caller_file)
            if caller_index is None:
                caller_index = _build_tsx_local_decl_index(caller_source)
                lexical_cache[caller_file] = caller_index
            scope_status, local_decl_pos = _lookup_tsx_decl_index(
                caller_index, raw_root, effective_usage_pos
            )
            if scope_status == "ambiguous":
                return "opaque"
            if scope_status == "found" and "." in tag_name:
                return "opaque"
        same_file = scope_status == "found" and local_decl_pos is not None
        if not same_file and imp is not None and _ICON_PKG_SPEC_RE.match(imp[0]):
            return _eval_inline_graphic_name(attrs, allow_alt=False, prop_values=_parent_props)
        if _depth >= 3 or (imp is None and not same_file):
            return "opaque"
        if same_file:
            target = caller_file
            exported = raw_root
            initial_ckey = (target, f"__local__:{local_decl_pos}:{exported}")
        else:
            assert imp is not None
            spec, exported = imp
            if "." in tag_name:
                exported = tag_name.split(".", 1)[1]
            target = resolve_import_fn(spec, caller_file)
            if target is None:
                return "opaque"
            initial_ckey = (target, exported)
        if initial_ckey in _visiting:
            return "opaque"
        if initial_ckey not in cache:
            seen_reexports: set[tuple[Path, str]] = set()
            final_target = target
            final_exported = exported
            if same_file:
                raw_target = caller_source
            else:
                raw_target = ""
                for _ in range(3):
                    if (final_target, final_exported) in _visiting or (
                        final_target,
                        final_exported,
                    ) in seen_reexports:
                        return "opaque"
                    seen_reexports.add((final_target, final_exported))
                    try:
                        raw_target = final_target.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        return "opaque"
                    if final_target.suffix not in (".tsx", ".jsx", ".ts", ".js"):
                        break
                    reexport = _find_tsx_reexport_target(raw_target, final_exported)
                    if reexport is None:
                        break
                    re_spec, re_name = reexport
                    nxt_target = resolve_import_fn(re_spec, final_target)
                    if nxt_target is None:
                        return "opaque"
                    final_target = nxt_target
                    final_exported = re_name
            final_ckey = (
                final_target,
                f"__local__:{local_decl_pos}:{final_exported}" if same_file else final_exported,
            )
            if final_ckey in _visiting:
                return "opaque"
            if final_ckey not in cache:
                anchor_box: list[int] = []
                defaults, aliases, markup = _extract_component_props_and_markup(
                    raw_target,
                    final_target.suffix,
                    exported_name=final_exported,
                    local_scope=same_file,
                    usage_pos=effective_usage_pos if same_file else None,
                    _scope_anchor_out=anchor_box,
                )
                target_imports = imports if same_file else parse_component_imports(raw_target)
                scope_anchor = anchor_box[0] if anchor_box else 0
                cache[final_ckey] = (
                    defaults,
                    aliases,
                    markup,
                    target_imports,
                    final_target,
                    raw_target,
                    scope_anchor,
                )
            cache[initial_ckey] = cache[final_ckey]
        else:
            final_ckey = initial_ckey
        (
            defaults,
            aliases,
            markup,
            target_imports,
            resolved_path,
            resolved_source,
            scope_anchor,
        ) = cache[initial_ckey]
        if not markup.strip():
            return "opaque"

        passed, has_opaque_spread, explicit_after_spread, raw_prop_exprs = _extract_prop_attrs(attrs)
        if _parent_props is not None:
            for pname, raw_ref in raw_prop_exprs.items():
                if raw_ref.startswith("props."):
                    ident = raw_ref[len("props.") :]
                    resolved_val = _parent_props.get(
                        ident, "opaque" if _parent_has_spread else "undefined"
                    )
                elif raw_ref in _parent_props:
                    resolved_val = _parent_props[raw_ref]
                else:
                    continue
                if has_opaque_spread and pname not in explicit_after_spread and resolved_val in (
                    "empty",
                    "empty_node",
                    "blank",
                    "null",
                    "num_zero",
                    "bool_false",
                    "bool_true",
                ):
                    passed[pname] = "opaque"
                else:
                    passed[pname] = resolved_val

        if inner_status != "omitted":
            passed["children"] = inner_status
            explicit_after_spread.add("children")
            raw_prop_exprs.pop("children", None)

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
            elif dstate == "num_zero" or dstate in _EMPTY_PROP_STATES or dstate in _BOOL_PROP_STATES:
                merged_props[local_name] = dstate
            else:
                # Preserve omitted/`undefined` state when no default is declared so multi-hop
                # prop forwarding lets nested components apply their own default values.
                merged_props[local_name] = "undefined"
        for src_name, pstate in passed.items():
            norm_state = (
                "opaque"
                if (
                    has_opaque_spread
                    and src_name not in explicit_after_spread
                    and (pstate == "num_zero" or pstate in _EMPTY_PROP_STATES or pstate in _BOOL_PROP_STATES)
                )
                else pstate
            )
            merged_props.setdefault(src_name, norm_state)

        children_local = next(
            (ln for ln, sn in aliases.items() if sn == "children"),
            "children",
        )
        if children_local not in merged_props:
            merged_props[children_local] = (
                "opaque"
                if (has_opaque_spread and "children" not in explicit_after_spread)
                else "undefined"
            )
        resolved_children = merged_props[children_local]
        if inner_status == "omitted" and resolved_children == "undefined":
            effective_inner = "omitted"
        else:
            effective_inner = resolved_children

        nested_resolver = make_local_component_resolver(
            resolved_path,
            resolved_source,
            resolve_import_fn,
            _caller_imports=target_imports,
            _cache=cache,
            _lexical_cache=lexical_cache,
            _visiting=_visiting | {initial_ckey, final_ckey},
            _depth=_depth + 1,
            _parent_props=merged_props,
            _parent_has_spread=has_opaque_spread,
            _fallback_scope_pos=scope_anchor,
        )
        child_bool_as_text = resolved_path.suffix in (".svelte", ".vue")
        child_vue_kebab = resolved_path.suffix == ".vue"

        def classify_branch(branch: str) -> str:
            if branch == "<!--WYTHE_OPAQUE-->":
                return "opaque"
            if branch.startswith("<!--WYTHE_EXPR-->"):
                sem = _classify_expr_semantics(
                    branch[len("<!--WYTHE_EXPR-->") :],
                    prop_values=merged_props,
                    inner_status=effective_inner,
                    render_booleans_as_text=child_bool_as_text,
                    portal_names=_portal_names_from_imports(target_imports),
                )
                return "empty" if sem == "ignore" else sem
            st, _, _ = _classify_markup_segment(
                branch,
                imported_components=target_imports,
                component_resolver=nested_resolver,
                prop_values=merged_props,
                inner_status=effective_inner,
                render_booleans_as_text=child_bool_as_text,
                allow_vue_kebab=child_vue_kebab,
                source_offset=scope_anchor,
            )
            return st

        branches = markup.split("\n<!--WYTHE_BRANCH-->\n")
        if len(branches) == 1:
            return classify_branch(branches[0])
        branch_statuses = {classify_branch(b) for b in branches}
        return next(iter(branch_statuses)) if len(branch_statuses) == 1 else "opaque"

    resolve_tag._wythe_accepts_usage_pos = True
    return resolve_tag


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
        lineno = raw_source.count("\n", 0, m.start()) + 1
        btn_inj = _eval_injected_html_name(
            attrs,
            prop_values=None,
            inner_status="omitted",
            render_booleans_as_text=rel_repo.endswith((".svelte", ".vue")),
        )
        if btn_inj == "named":
            continue
        if btn_inj == "opaque":
            if unobserved_out is not None:
                unobserved_out.append(f"{rel_repo}:{lineno}: opaque injected HTML inside <button>")
            continue
        cspan = _find_matching_close_tag(raw_source, end, "button")
        if cspan is None:
            continue
        body = raw_source[end : cspan[0]]
        status, opaque_tags, has_visual = _classify_markup_segment(
            body,
            imported_components=imported_components,
            component_resolver=component_resolver,
            render_booleans_as_text=rel_repo.endswith((".svelte", ".vue")),
            allow_vue_kebab=rel_repo.endswith(".vue"),
            source_offset=end,
        )
        if status == "empty" and btn_inj == "icon_only":
            status = "icon_only"
            has_visual = True
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
