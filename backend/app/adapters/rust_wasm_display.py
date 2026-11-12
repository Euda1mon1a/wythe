"""Tier 3 Adapter: Rust WASM / Native UI (`Leptos`, `Dioxus`, `Yew`, & Tauri WASM)."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.a11y_inspect import scan_a11y_markup_findings
from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    RawCandidateFinding,
)
from app.adapters.rust_inspect import (
    _RUST_POLICY_RE,
    _TAURI_READ_PREFIXES,
    _USE_CRATE_RE,
    strip_rust_comments,
)
from app.core.policy_context import get_active_policy_tokens
from app.schemas.atlas import AtlasEdge, AtlasNode

_SKIP_DIRS = ("target", "node_modules", ".git", "tests", "benches")
_LEPTOS_ROUTE_RE = re.compile(r"""<Route\b[^>]*?\bpath=(?:path!\(\s*)?"(?P<path>/[^"]*)" """)
_ATTR_UI_ROUTE_RE = re.compile(r"""#\[\s*(?:route|at)\(\s*"(?P<path>/[^"]*)" """)
_GLOO_HTTP_RE = re.compile(
    r"""\b(?:Request::|\.|\bclient\.|\bhttp::)?(?P<verb>get|post|put|patch|delete)\s*(?:::<[^>]+>)?\s*\(\s*(?:&?format!\(\s*)?"(?P<url>/[^"]*)" """.strip()
)
_RUST_CONST_ENDPOINT_RE = re.compile(
    r"""\b(?:const|static(?:\s+ref)?)\s+(?P<name>[A-Z][A-Z0-9_]*)\s*:[^=]+=\s*"(?P<url>/[^"]*)" """.strip()
)
_RUST_CONST_HTTP_CALL_RE = re.compile(
    r"""\b(?P<verb>get|post|put|patch|delete)\s*(?:::<[^>]+>)?\s*\(\s*(?P<arg>[^,\n)]{1,140})"""
)
_WASM_INVOKE_RE = re.compile(r"""\binvoke\s*\(\s*"(?P<cmd>[a-z_][a-z0-9_]*)" """)
_WASM_CLOCK_RE = re.compile(r"""\b(?:js_sys::Date::new_0|Local::now|Utc::now)\s*\(\s*\)""")
_SHARED_CONTRACT_MARKERS = ("shared::", "common::", "types::", "contracts::", "domain::", "_domain::", "openapi")


def _normalize_rust_format_url(raw_url: str) -> str:
    norm = re.sub(r"\{[^}]*\}", "{param}", raw_url.split("?", 1)[0])
    cleaned = re.sub(r"/+", "/", norm).rstrip("/")
    return cleaned or "/"


class RustWasmDisplayAdapter:
    """Extracts Leptos/Dioxus/Yew components, WASM HTTP/Tauri calls, and DISP-001..003 rules."""

    name = "rust-wasm"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        fe_dir = repo_root if frontend_subdir in ("", ".") else repo_root / frontend_subdir
        src_dir = fe_dir / "src" if (fe_dir / "src").is_dir() else fe_dir
        if not src_dir.is_dir():
            return DisplayExtractionResult(nodes=[], edges=[], http_calls=[], findings=[])

        cleaned_by_file: dict[Path, str] = {}
        raw_by_file: dict[Path, str] = {}
        nodes_by_file: dict[Path, AtlasNode] = {}
        stem_to_files: dict[str, list[Path]] = {}

        for rs_file in sorted(src_dir.rglob("*.rs")):
            if any(p in _SKIP_DIRS for p in rs_file.parts) or rs_file.name in ("build.rs", "mod.rs"):
                continue
            try:
                raw = rs_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            cleaned = strip_rust_comments(raw)
            cleaned_by_file[rs_file] = cleaned
            raw_by_file[rs_file] = raw

            rel_repo = rs_file.relative_to(repo_root).as_posix()
            rel_src = rs_file.relative_to(src_dir).as_posix()
            parts = Path(rel_src).parts
            route_m = _LEPTOS_ROUTE_RE.search(cleaned) or _ATTR_UI_ROUTE_RE.search(cleaned)
            if route_m or any(p in ("pages", "routes", "views") for p in parts) or rs_file.name in ("app.rs", "main.rs", "router.rs"):
                subkind, cluster = "page", "pages"
                lbl = route_m.group("path") if route_m else ("/" if rs_file.stem in ("app", "main", "home", "router") else f"/{rs_file.stem}")
            elif any(p in ("api", "client", "clients", "services") for p in parts) or rs_file.stem in ("api", "client", "http"):
                subkind, cluster, lbl = "api_client", "api_clients", rs_file.stem
            elif any(p in ("hooks", "signals", "stores", "contexts") for p in parts) or rs_file.stem.startswith("use_"):
                subkind, cluster, lbl = "hook", "signals", rs_file.stem
            else:
                subkind, cluster, lbl = "component", "components", rs_file.stem

            slug = Path(rel_src).with_suffix("").as_posix().replace("/", ".")
            nodes_by_file[rs_file] = AtlasNode(
                id=f"d:{subkind}:{slug}",
                tier="display",
                subkind=subkind,  # type: ignore[arg-type]
                label=lbl,
                source_file=rel_repo,
                line=1,
                status="clean",
                role="surface",
                cluster=cluster,
                summary=f"Rust WASM {subkind.replace('_', ' ')} `{lbl}` ({rel_repo}).",
            )
            stem_to_files.setdefault(rs_file.stem, []).append(rs_file)

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        for rs_file, node in nodes_by_file.items():
            txt = cleaned_by_file[rs_file]
            rel_repo = node.source_file
            uses_shared_contract = any(m in txt for m in _SHARED_CONTRACT_MARKERS)

            for um in _USE_CRATE_RE.finditer(txt):
                for tok in (t for t in re.split(r"[:{},\s*]+", um.group("path")) if t):
                    for dst_f in stem_to_files.get(tok, []):
                        if dst_f != rs_file:
                            dst = nodes_by_file[dst_f]
                            kind = "uses_hook" if dst.subkind == "hook" else "uses_client"
                            if (node.id, dst.id, kind) not in seen_edges:
                                seen_edges.add((node.id, dst.id, kind))
                                edges.append(
                                    AtlasEdge(
                                        id=f"e:{node.id}->{dst.id}:{kind}",
                                        source_id=node.id,
                                        target_id=dst.id,
                                        kind=kind,  # type: ignore[arg-type]
                                        verification="verified",
                                        evidence_path=rel_repo,
                                        evidence_note=f"Imports `{dst.label}`.",
                                    )
                                )

            methods_seen: list[str] = []
            paths_seen: list[str] = []
            mod_calls = 0
            const_urls = {
                cm.group("name"): cm.group("url")
                for cm in _RUST_CONST_ENDPOINT_RE.finditer(txt)
            }
            for hm in _GLOO_HTTP_RE.finditer(txt):
                verb = hm.group("verb").upper()
                raw_u = hm.group("url")
                norm_u = _normalize_rust_format_url(raw_u)
                lineno = txt.count("\n", 0, hm.start()) + 1
                mod_calls += 1
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
            if const_urls:
                for chm in _RUST_CONST_HTTP_CALL_RE.finditer(txt):
                    arg_expr = chm.group("arg")
                    matched_const = next((cname for cname in const_urls if cname in arg_expr), None)
                    if not matched_const:
                        continue
                    verb = chm.group("verb").upper()
                    base_u = const_urls[matched_const].rstrip("/")
                    fmt_m = re.search(r'format!\(\s*"(?P<fmt>[^"]+)"', arg_expr)
                    if fmt_m:
                        fmt_s = fmt_m.group("fmt")
                        # Replace first `{}` with base_u and subsequent `{}` with `{param}`
                        parts_fmt = fmt_s.split("{}")
                        raw_u = base_u + "{param}".join(parts_fmt[1:]) if len(parts_fmt) > 1 else base_u
                    else:
                        raw_u = base_u or "/"
                    norm_u = _normalize_rust_format_url(raw_u)
                    lineno = txt.count("\n", 0, chm.start()) + 1
                    mod_calls += 1
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

            for im in _WASM_INVOKE_RE.finditer(txt):
                cmd = im.group("cmd")
                verb = "GET" if cmd.startswith(_TAURI_READ_PREFIXES) else "POST"
                tpath = f"/tauri/{cmd}"
                lineno = txt.count("\n", 0, im.start()) + 1
                mod_calls += 1
                if verb not in methods_seen:
                    methods_seen.append(verb)
                if tpath not in paths_seen:
                    paths_seen.append(tpath)
                http_calls.append(
                    FrontendHttpCall(
                        caller_node_id=node.id,
                        http_method=verb,
                        raw_path=tpath,
                        normalized_path=tpath,
                        source_file=rel_repo,
                        line=lineno,
                    )
                )

            node.http_methods = methods_seen
            node.http_paths = paths_seen[:25]

            if node.subkind == "api_client" and mod_calls > 0 and not uses_shared_contract:
                node.status = "gray_zone"
                findings.append(
                    RawCandidateFinding(
                        rule_code="DISP-003",
                        node_id=node.id,
                        source_file=rel_repo,
                        line=1,
                        title=f"Rust WASM API client `{node.label}` omits shared contract types",
                        detail=f"{rel_repo} issues {mod_calls} call(s) without importing a shared schema/types crate.",
                        remediation="Bind responses to a shared `common`/`types` workspace crate or generated OpenAPI structs.",
                    )
                )

            active_tokens = get_active_policy_tokens()
            for pm in _RUST_POLICY_RE.finditer(txt):
                cname = pm.group("name")
                if any(tok in cname for tok in active_tokens):
                    lineno = txt.count("\n", 0, pm.start()) + 1
                    node.status = "policy_in_code"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="DISP-001",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Client-side Rust WASM policy constant `{cname}`",
                            detail=f"{rel_repo}:{lineno} embeds domain policy `{cname}` in WASM UI code.",
                            remediation="Read policy values from backend responses backed by database truth.",
                        )
                    )

            if rs_file.name not in ("clock.rs", "time.rs"):
                for cm in _WASM_CLOCK_RE.finditer(txt):
                    lineno = txt.count("\n", 0, cm.start()) + 1
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="DISP-002",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Raw browser/WASM clock call `{cm.group(0).strip()}`",
                            detail=f"{rel_repo}:{lineno} reads ambient browser/WASM clock directly.",
                            remediation="Format server-supplied UTC instants via a centralized time utility.",
                        )
                    )

            raw_rs = raw_by_file[rs_file]
            if any(m in raw_rs for m in ("html!", "view!", "rsx!")):
                a11y_hits = scan_a11y_markup_findings(raw_rs, node.id, rel_repo)
                if a11y_hits:
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.extend(a11y_hits)

        return DisplayExtractionResult(
            nodes=list(nodes_by_file.values()),
            edges=edges,
            http_calls=http_calls,
            findings=findings,
        )
