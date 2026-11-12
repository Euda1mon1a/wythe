"""Tier 3 Accessibility (`DISP-005`) static markup inspector for JSX/TSX, Vue, Svelte, and Rust WASM."""

from __future__ import annotations

import re

from app.adapters.base import RawCandidateFinding

# Match opening tags (<img ...>, <div ...>, <span ...>, <input ...>) without stopping early on JSX `=>` arrows
_IMG_TAG_RE = re.compile(r"<img\b(?P<attrs>(?:=>|[^>\"']|\"[^\"]*\"|'[^']*')*)>", re.IGNORECASE)
_NON_INTERACTIVE_CLICK_RE = re.compile(
    r"<(?P<tag>div|span)\b(?P<attrs>(?:=>|[^>\"']|\"[^\"]*\"|'[^']*'){0,500}?"
    r"\b(?:onClick|on:click|@click|onclick)\s*=[\s\S]{0,240}?)>",
)
_INPUT_TAG_RE = re.compile(
    r"<(?P<tag>input|select|textarea)\b(?P<attrs>(?:=>|[^>\"']|\"[^\"]*\"|'[^']*')*)>",
)
_EMPTY_BUTTON_RE = re.compile(
    r"<button\b(?P<attrs>(?:=>|[^>\"']|\"[^\"]*\"|'[^']*')*)>\s*"
    r"(?:<[A-Z][A-Za-z0-9_.]*\b[^>]*/\s*>\s*|<(?:svg|i)\b[\s\S]{0,400}?/\s*>\s*|<(?:svg|i)\b[\s\S]{0,400}?</(?:svg|i)>\s*)+"
    r"</button>",
)
_LABEL_FOR_RE = re.compile(r"""<label\b[^>]*?\b(?:htmlFor|for)\s*=\s*(?:['"](?P<id>[^'"]+)['"]|\{(?P<expr>[^}]+)\})""")
_WRAPPING_LABEL_RE = re.compile(r"<label\b(?:(?!</label>)[\s\S]){0,1500}?</label>")
_ID_ATTR_RE = re.compile(r"""\bid\s*=\s*(?:['"](?P<id>[^'"]+)['"]|\{(?P<expr>[^}]+)\})""")
_HIDDEN_INPUT_RE = re.compile(r"""\btype\s*=\s*['"](?:hidden|submit|reset|button)['"]""", re.IGNORECASE)


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
    for m in _IMG_TAG_RE.finditer(raw_source):
        attrs = m.group("attrs")
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
    for m in _NON_INTERACTIVE_CLICK_RE.finditer(raw_source):
        tag = m.group("tag")
        attrs = m.group("attrs")
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
    for m in _EMPTY_BUTTON_RE.finditer(raw_source):
        attrs = m.group("attrs")
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
    labeled_ids = {
        (lm.group("id") or lm.group("expr") or "").strip()
        for lm in _LABEL_FOR_RE.finditer(raw_source)
    }
    wrapped_spans = [wm.span() for wm in _WRAPPING_LABEL_RE.finditer(raw_source)]
    for m in _INPUT_TAG_RE.finditer(raw_source):
        tag = m.group("tag")
        attrs = m.group("attrs")
        if _HIDDEN_INPUT_RE.search(attrs) or "{..." in attrs:
            continue
        if re.search(r"\b(?:aria-label|aria-labelledby|title)\s*=", attrs):
            continue
        if any(ws <= m.start() and m.end() <= we for ws, we in wrapped_spans):
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
