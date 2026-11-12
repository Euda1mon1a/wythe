"""Shared frontend display extraction utilities for React SPA, Vue/Nuxt, and SvelteKit."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.a11y_inspect import scan_a11y_markup_findings
from app.adapters.base import FrontendHttpCall, RawCandidateFinding
from app.adapters.typescript_nextjs import (
    _CLOCK_UTIL_FILES,
    _IMPORT_RE,
    _RAW_NEW_DATE_RE,
    _TS_POLICY_CONST_RE,
    _UI_SAFE_TOKENS,
    _UTC_SLICE_RE,
    _extract_ts_http_calls,
    _normalize_ts_url,
    _strip_ts_comments,
)
from app.core.policy_context import get_active_policy_tokens
from app.schemas.atlas import AtlasNode

_SFC_SCRIPT_RE = re.compile(r"<script\b[^>]*>(?P<body>[\s\S]*?)</script>", re.IGNORECASE)
_VUE_SFC_FETCH_RE = re.compile(
    r"""\b(?:\$fetch|useFetch|useLazyFetch)\s*(?:<[^;()]{0,180}?>)?\s*\(\s*(?P<quote>['"`])(?P<url>/[^'"`\n]+)(?P=quote)(?P<tail>[\s\S]{0,160})"""
)
_METHOD_OPT_RE = re.compile(r"""method\s*:\s*['"](?P<m>GET|POST|PUT|PATCH|DELETE)['"]""", re.IGNORECASE)
_API_ENDPOINT_LIT_RE = re.compile(r"""(?P<q>['"`])(?P<url>/api/[A-Za-z0-9_./{}$?=&-]+)(?P=q)""")
_SCHEMA_BIND_MARKERS = ("api-generated", "openapi", ".schema", "generated/", "/types", "./types")


def extract_script_preserving_lines(raw_source: str, suffix: str) -> str:
    """For .vue / .svelte files, replace non-script regions with newlines to preserve line numbers."""
    if suffix not in (".vue", ".svelte"):
        return _strip_ts_comments(raw_source)

    chars = ["\n" if ch == "\n" else " " for ch in raw_source]
    for m in _SFC_SCRIPT_RE.finditer(raw_source):
        start, end = m.span("body")
        cleaned = _strip_ts_comments(m.group("body"))
        for idx, ch in enumerate(cleaned):
            if start + idx < end:
                chars[start + idx] = ch
    return "".join(chars)


def resolve_frontend_import(
    spec: str,
    current_file: Path,
    src_root: Path,
    extensions: tuple[str, ...],
) -> Path | None:
    if spec.startswith(("@/", "~/")):
        base = src_root / spec[2:]
    elif spec.startswith("$lib/"):
        lib_dir = src_root / "lib" if (src_root / "lib").is_dir() else src_root
        base = lib_dir / spec[len("$lib/") :]
    elif spec.startswith("."):
        base = (current_file.parent / spec).resolve()
    else:
        return None

    candidates = [base]
    for ext in extensions:
        candidates.append(Path(f"{base}{ext}"))
    for ext in extensions:
        candidates.append(base / f"index{ext}")
    for cand in candidates:
        if cand.is_file():
            return cand.resolve()
    return None


def scan_display_module_semantics(
    node: AtlasNode,
    cleaned_txt: str,
    rel_repo: str,
    raw_source: str | None = None,
) -> tuple[list[str], list[FrontendHttpCall], list[RawCandidateFinding]]:
    """Extract imports, HTTP calls, and DISP-001..005 findings for a single display node."""
    imported_specs = [m.group("spec") for m in _IMPORT_RE.finditer(cleaned_txt)]
    uses_schema_types = any(
        any(marker in spec for marker in _SCHEMA_BIND_MARKERS) for spec in imported_specs
    )

    raw_calls = list(_extract_ts_http_calls(cleaned_txt))
    for vm in _VUE_SFC_FETCH_RE.finditer(cleaned_txt):
        raw_tail = vm.group("tail")
        pdepth = 1
        j = 0
        while j < len(raw_tail) and pdepth > 0:
            if raw_tail[j] == "(":
                pdepth += 1
            elif raw_tail[j] == ")":
                pdepth -= 1
            j += 1
        mm = _METHOD_OPT_RE.search(raw_tail[:j])
        verb = mm.group("m").upper() if mm else "GET"
        lineno = cleaned_txt.count("\n", 0, vm.start()) + 1
        raw_calls.append((verb, vm.group("url"), lineno))

    if not raw_calls and node.subkind in ("api_client", "hook"):
        for em in _API_ENDPOINT_LIT_RE.finditer(cleaned_txt):
            lineno = cleaned_txt.count("\n", 0, em.start()) + 1
            raw_calls.append(("GET", em.group("url"), lineno))

    http_calls: list[FrontendHttpCall] = []
    methods_seen: list[str] = []
    paths_seen: list[str] = []
    seen_call_keys: set[tuple[str, str, int]] = set()
    for verb, raw_u, lineno in raw_calls:
        if (verb, raw_u, lineno) in seen_call_keys:
            continue
        seen_call_keys.add((verb, raw_u, lineno))
        norm_u = _normalize_ts_url(raw_u)
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
        if any(tok in cname for tok in active_tokens) and not any(
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
            if args_str == "" or ("," not in args_str and "Date." not in args_str):
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

    if raw_source and rel_repo.endswith((".tsx", ".jsx", ".vue", ".svelte")):
        a11y_hits = scan_a11y_markup_findings(raw_source, node.id, rel_repo)
        if a11y_hits:
            if node.status == "clean":
                node.status = "gray_zone"
            findings.extend(a11y_hits)

    return imported_specs, http_calls, findings
