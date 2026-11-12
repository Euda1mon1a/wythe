"""Tier 3 Accessibility (`DISP-005`) static markup inspector for JSX/TSX, Vue, Svelte, and Rust WASM."""

from __future__ import annotations

import re

from app.adapters.base import RawCandidateFinding

_IMG_OPEN_RE = re.compile(r"<img\b", re.IGNORECASE)
_CLICKABLE_OPEN_RE = re.compile(r"<(?P<tag>div|span)\b")
_INPUT_OPEN_RE = re.compile(r"<(?P<tag>input|select|textarea)\b")
_BUTTON_OPEN_RE = re.compile(r"<button\b")
_LABEL_TOKEN_RE = re.compile(r"<label\b|</label\s*>")
_CLICK_ATTR_RE = re.compile(r"\b(?:onClick|on:click|@click|onclick)\s*=")
# Children of an icon-only button: self-closing components, or inline <svg>/<i> glyphs.
_ICON_ONLY_CHILDREN_RE = re.compile(
    r"\s*(?:<[A-Z][A-Za-z0-9_.]*\b[^>]*/\s*>\s*|<(?:svg|i)\b[\s\S]{0,400}?/\s*>\s*|<(?:svg|i)\b[\s\S]{0,400}?</(?:svg|i)>\s*)+"
    r"</button>",
)
_LABEL_FOR_ATTR_RE = re.compile(r"""\b(?:htmlFor|for)\s*=\s*(?:['"](?P<id>[^'"]+)['"]|\{(?P<expr>[^}]+)\})""")
_ID_ATTR_RE = re.compile(r"""(?<![\w-])id\s*=\s*(?:['"](?P<id>[^'"]+)['"]|\{(?P<expr>[^}]+)\})""")
_HIDDEN_INPUT_RE = re.compile(r"""\btype\s*=\s*['"](?:hidden|submit|reset|button)['"]""", re.IGNORECASE)
_OPEN_TAG_SCAN_LIMIT = 8000


def scan_open_tag_end(src: str, pos: int) -> int | None:
    """Index just past the `>` that closes the opening tag whose attributes start at `pos`.

    A `>` inside a `{...}` expression (arrow `=>`, TS generic `as Ref<T>`, comparison `a > b`),
    a quoted attribute value, a template literal, or a comment does not end the tag. Returns
    None for markup that never closes within the scan limit.
    """
    n = min(len(src), pos + _OPEN_TAG_SCAN_LIMIT)
    stack: list[str] = []  # "{" for an expression, "`" for a template literal inside one
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
            elif src.startswith("${", i):
                stack.append("{")
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
                i = j + 1
                continue
            if ch == "`" or ch == "{":
                stack.append(ch)
            elif ch == "}":
                stack.pop()
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


def scan_a11y_markup_findings(
    raw_source: str,
    node_id: str,
    rel_repo: str,
) -> list[RawCandidateFinding]:
    """Inspect raw UI template/JSX/RSX markup for deterministic WCAG (`DISP-005`) violations."""
    findings: list[RawCandidateFinding] = []
    seen_lines: set[tuple[int, str]] = set()

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

    # 3. Icon-only <button> without aria-label / aria-labelledby / title
    for m, attrs, end in _open_tags(raw_source, _BUTTON_OPEN_RE):
        if not _ICON_ONLY_CHILDREN_RE.match(raw_source, end):
            continue
        if re.search(r"\b(?:aria-label|aria-labelledby|title)\s*=", attrs) or "{..." in attrs:
            continue
        lineno = raw_source.count("\n", 0, m.start()) + 1
        emit(
            lineno,
            "icon_btn",
            "Icon-only `<button>` missing accessible name (`WCAG 4.1.2`)",
            f"{rel_repo}:{lineno} renders an icon-only `<button>` with no `aria-label`, `aria-labelledby`, or visible text.",
            "Add `aria-label=\"...\"` or visually-hidden `<span className=\"sr-only\">` text inside the button.",
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
