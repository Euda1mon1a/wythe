"""Shared frontend display extraction utilities for React SPA, Vue/Nuxt, and SvelteKit."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from app.adapters.a11y_inspect import (
    is_js_module_stmt_in_code,
    js_code_mask,
    make_local_component_resolver,
    scan_a11y_markup_findings,
)
from app.adapters.base import FrontendHttpCall, RawCandidateFinding
from app.adapters.typescript_nextjs import (
    _CLOCK_UTIL_FILES,
    _IMPORT_RE,
    _RAW_NEW_DATE_RE,
    _TS_POLICY_CONST_RE,
    _UI_SAFE_TOKENS,
    _UTC_SLICE_RE,
    _build_scoped_url_consts,
    _extract_ts_http_calls,
    _is_raw_clock_read,
    _normalize_ts_url,
    _strip_ts_comments,
    has_generated_contract_provenance,
)
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasNode

_SFC_SCRIPT_RE = re.compile(r"<script\b[^>]*>(?P<body>[\s\S]*?)</script>", re.IGNORECASE)
_VUE_SFC_FETCH_RE = re.compile(
    r"""\b(?:\$fetch|useFetch|useLazyFetch)\s*(?:<[^;()]{0,180}?>)?\s*\(\s*(?P<quote>['"`])(?P<url>/[^'"`\n]+)(?P=quote)(?P<tail>[\s\S]{0,160})"""
)
_METHOD_OPT_RE = re.compile(r"""method\s*:\s*['"](?P<m>GET|POST|PUT|PATCH|DELETE)['"]""", re.IGNORECASE)


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
) -> Path | None:
    if spec.startswith(("@/", "~/")):
        base = src_root / spec[2:]
    elif spec.startswith(("$lib/", "#lib/")):
        lib_dir = src_root / "lib" if (src_root / "lib").is_dir() else src_root
        base = lib_dir / spec[5:]
    elif spec.startswith("."):
        base = (current_file.parent / spec).resolve()
    else:
        return None

    candidates = [base]
    if base.suffix in (".js", ".mjs"):
        for alt in (".ts", ".tsx", ".mts", ".svelte", ".vue"):
            candidates.append(base.with_suffix(alt))
    for ext in extensions:
        candidates.append(Path(f"{base}{ext}"))
    for ext in extensions:
        candidates.append(base / f"index{ext}")
    for cand in candidates:
        if cand.is_file():
            return cand.resolve()
    return None


def build_frontend_url_const_resolver(
    src_root: Path,
    extensions: tuple[str, ...],
    *,
    cleaned_cache: dict[Path, str] | None = None,
) -> Callable[[Path, str], dict[str, str]]:
    """Return `imported_consts_for(file_path, cleaned_txt)` resolving static same-origin URL exports."""
    export_cache: dict[Path, dict[str, str]] = {}
    text_cache: dict[Path, str] = dict(cleaned_cache) if cleaned_cache is not None else {}
    parsed_cache: dict[Path, tuple[str, list[tuple[Path, list[tuple[str, str]]]], list[Path], list[tuple[Path | None, list[tuple[str, str]]]], list[str], list[tuple[str, str]]]] = {}
    scoped_const_cache: dict[tuple[Path, tuple[tuple[str, str], ...]], dict[str, str]] = {}

    def _read_cleaned(fpath: Path) -> str:
        if fpath not in text_cache:
            try:
                raw = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
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
            target = resolve_frontend_import(im.group("spec"), fpath, src_root, extensions)
            if target is not None:
                named_imports.append((target, _parse_specifier_pairs(im.group("clause"))))
        reexport_all: list[Path] = []
        for rm in _REEXPORT_ALL_RE.finditer(cleaned):
            if not is_js_module_stmt_in_code(cleaned, mask, rm):
                continue
            target = resolve_frontend_import(rm.group("spec"), fpath, src_root, extensions)
            if target is not None:
                reexport_all.append(target)
        reexport_from: list[tuple[Path | None, list[tuple[str, str]]]] = []
        for rm in _REEXPORT_FROM_RE.finditer(cleaned):
            if not is_js_module_stmt_in_code(cleaned, mask, rm):
                continue
            target = resolve_frontend_import(rm.group("spec"), fpath, src_root, extensions)
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
                local_consts, _ = _build_scoped_url_consts(cleaned, imported_consts=imported)
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
        resolved_path = fpath.resolve()
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
) -> Callable[[Path, str], Callable[[str, str, str], str]]:
    """Build a per-scan factory returning depth-bounded component text-semantics resolvers."""
    shared_cache: dict[
        tuple[Path, str],
        tuple[dict[str, str], dict[str, str], str, dict[str, tuple[str, str]], Path, str, int],
    ] = {}
    shared_lexical_cache: dict[Path, dict[str, list[tuple[int, tuple[int, int]]]]] = {}

    def _resolve_imp(spec: str, current_file: Path) -> Path | None:
        return resolve_frontend_import(spec, current_file, src_root, extensions)

    def resolver_for(caller_file: Path, caller_raw_source: str) -> Callable[[str, str, str], str]:
        return make_local_component_resolver(
            caller_file.resolve(),
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
) -> tuple[list[str], list[FrontendHttpCall], list[RawCandidateFinding]]:
    """Extract imports, HTTP calls, and DISP-001..005 findings for a single display node."""
    imported_specs = [m.group("spec") for m in _IMPORT_RE.finditer(cleaned_txt)]
    uses_schema_types = has_generated_contract_provenance(
        imported_specs,
        raw_source=raw_source,
        source_file=rel_repo,
        has_generator_config=has_generator_config,
    ) or uses_typed_sdk

    raw_calls = list(_extract_ts_http_calls(cleaned_txt, imported_consts=imported_url_consts))
    if sdk_calls:
        seen_calls = set(raw_calls)
        for item in sdk_calls:
            if item not in seen_calls:
                seen_calls.add(item)
                raw_calls.append(item)
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

    if raw_source and rel_repo.endswith((".tsx", ".jsx", ".vue", ".svelte")):
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
