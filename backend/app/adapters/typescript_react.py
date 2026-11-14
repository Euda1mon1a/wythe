"""Tier 3 Adapter: React SPA / Vite / React Router / TanStack Router / Remix (`typescript-react`)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    RawCandidateFinding,
)
from app.adapters.frontend_common import (
    build_a11y_component_resolver,
    build_frontend_url_const_resolver,
    extract_script_preserving_lines,
    format_unobserved_a11y_note,
    resolve_frontend_import,
    scan_display_module_semantics,
)
from app.adapters.ts_reachability import (
    MODULE_SYMBOL,
    ReachabilityIndex,
    build_react_spa_reachability,
)
from app.adapters.ts_sdk import WorkspaceSdkIndex
from app.adapters.ts_workspace import WorkspaceResolver
from app.adapters.typescript_nextjs import (
    _REEXPORT_NAMED_RE,
    _REEXPORT_STAR_RE,
    has_frontend_generator_config,
)
from app.schemas.atlas import AtlasEdge, AtlasNode

_EXTS = (".ts", ".tsx", ".js", ".jsx")


class TypeScriptReactSpaAdapter:
    """Extracts React SPA routes/pages, hooks, API clients, components, and DISP rules."""

    name = "typescript-react"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        fe_dir = repo_root.resolve() if frontend_subdir in ("", ".") else (repo_root / frontend_subdir).resolve()
        src_root = (fe_dir / "src").resolve() if (fe_dir / "src").is_dir() else fe_dir
        if not src_root.is_dir():
            return DisplayExtractionResult(nodes=[], edges=[], http_calls=[], findings=[])

        cleaned: dict[Path, str] = {}
        raw_sources: dict[Path, str] = {}
        barrel_targets: dict[Path, list[Path]] = {}
        nodes_by_path: dict[Path, AtlasNode] = {}

        for fpath in sorted(src_root.rglob("*")):
            if not fpath.is_file() or fpath.suffix not in _EXTS:
                continue
            if any(p in fpath.parts for p in ("node_modules", "dist", "build", "out", "__tests__", "src-tauri")):
                continue
            rel_src = fpath.relative_to(src_root).as_posix()
            if (
                fpath.name.endswith((".d.ts", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".config.ts", ".config.js"))
                or rel_src.endswith("api-generated.ts")
                or fpath.name == "types.gen.ts"
                or ("/core/" in f"/{rel_src}" and fpath.name.endswith(".gen.ts"))
                or rel_src.startswith("client/client/")
                or rel_src in ("main.tsx", "index.tsx", "vite-env.d.ts", "lib/api.ts")
            ):
                continue
            try:
                raw = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue

            resolved = fpath.resolve()
            clean_txt = extract_script_preserving_lines(raw, fpath.suffix)
            parts = Path(rel_src).parts
            eff_parts = parts[1:] if len(parts) > 1 and parts[0] in ("lib", "app") else parts
            head = eff_parts[0] if eff_parts else ""
            if fpath.name in ("index.ts", "index.tsx", "index.js") and head not in ("pages", "routes", "views"):
                targets: list[Path] = []
                for rex in (_REEXPORT_STAR_RE, _REEXPORT_NAMED_RE):
                    for m in rex.finditer(clean_txt):
                        t = resolve_frontend_import(m.group("spec"), resolved, src_root, _EXTS)
                        if t is not None:
                            targets.append(t)
                barrel_targets[resolved] = targets
                continue

            stem_low = fpath.stem.lower()
            if head in ("pages", "routes", "views") or fpath.stem == "App":
                lbl = "/" if fpath.stem in ("App", "Home", "index") else f"/{stem_low}"
                subkind, cluster = "page", "pages"
            elif head in ("hooks", "stores", "store") or fpath.stem.startswith("use") or stem_low in ("store", "state"):
                lbl, subkind, cluster = fpath.stem, "hook", "hooks"
            elif (
                head in ("api", "client", "services", "clients", "queries")
                or stem_low in ("api", "client", "http", "queries")
                or fpath.stem.endswith(("Client", "Api", "Service"))
                or fpath.name.endswith(".gen.ts")
            ):
                lbl, subkind, cluster = fpath.stem, "api_client", "api_clients"
            elif head in ("components", "features") or fpath.suffix in (".tsx", ".jsx"):
                lbl, subkind, cluster = fpath.stem, "component", head or "components"
            else:
                continue

            cleaned[resolved] = clean_txt
            raw_sources[resolved] = raw
            rel_repo = resolved.relative_to(repo_root.resolve()).as_posix()
            slug = Path(rel_src).with_suffix("").as_posix().replace("/", ".")
            nodes_by_path[resolved] = AtlasNode(
                id=f"d:{subkind}:{slug}",
                tier="display",
                subkind=subkind,  # type: ignore[arg-type]
                label=lbl,
                source_file=rel_repo,
                line=1,
                status="clean",
                role="surface",
                cluster=cluster,
                summary=f"React {subkind.replace('_', ' ')} `{lbl}` ({rel_repo}).",
            )

        reach: ReachabilityIndex | None = None
        try:
            reach = build_react_spa_reachability(
                fe_dir,
                src_root,
                repo_root.resolve(),
                lambda raw_text: extract_script_preserving_lines(raw_text, ".tsx"),
                pre_cleaned=cleaned,
            )
        except (OSError, ValueError, RecursionError):
            reach = None

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        url_const_resolver = build_frontend_url_const_resolver(src_root, _EXTS, cleaned_cache=cleaned)
        comp_resolver_for = build_a11y_component_resolver(src_root, _EXTS)
        has_gen_cfg = has_frontend_generator_config(fe_dir)
        ws_resolver = WorkspaceResolver.build(repo_root.resolve(), (fe_dir,))
        sdk_index = WorkspaceSdkIndex.build(repo_root, ws_resolver)
        page_paths = {p for p, n in nodes_by_path.items() if n.subkind == "page"}
        unobserved_a11y: list[str] = []

        for fpath, node in nodes_by_path.items():
            sdk_calls, uses_typed_sdk = sdk_index.extract_caller_sdk_calls(
                fpath,
                cleaned[fpath],
                is_tsx=fpath.suffix in (".tsx", ".jsx"),
            )
            specs, calls, mod_findings = scan_display_module_semantics(
                node,
                cleaned[fpath],
                node.source_file,
                raw_source=raw_sources[fpath],
                imported_url_consts=url_const_resolver(fpath, cleaned[fpath]),
                component_resolver=comp_resolver_for(fpath, raw_sources[fpath]),
                unobserved_a11y_out=unobserved_a11y,
                has_generator_config=has_gen_cfg,
                sdk_calls=sdk_calls,
                uses_typed_sdk=uses_typed_sdk,
            )
            if reach is not None:
                annotated_calls: list[FrontendHttpCall] = []
                for c in calls:
                    sym = reach.enclosing_symbol(fpath, c.line)
                    caller_sym = None if sym == MODULE_SYMBOL else sym
                    live: bool | None = None
                    trail: tuple[str, ...] = ()
                    entry_ids: tuple[str, ...] = ()
                    if reach.has_roots:
                        live = reach.is_live(fpath, sym)
                        trail = reach.trail(fpath, sym) if live else ()
                        if live:
                            entry_ids = tuple(
                                nodes_by_path[rp].id
                                for rp in reach.reaching_roots(fpath, sym, stop_paths=page_paths)
                                if rp in nodes_by_path
                            )
                    annotated_calls.append(
                        replace(
                            c,
                            caller_symbol=caller_sym,
                            reachable=live,
                            reach_trail=trail,
                            entry_node_ids=entry_ids,
                        )
                    )
                http_calls.extend(annotated_calls)
            else:
                http_calls.extend(calls)
            findings.extend(mod_findings)
            for spec in specs:
                dst_path = resolve_frontend_import(spec, fpath, src_root, _EXTS)
                if dst_path is None:
                    dst_path = ws_resolver.resolve_import(spec, fpath, exts=_EXTS)
                if dst_path is None:
                    continue
                for exp in barrel_targets.get(dst_path, [dst_path]):
                    if exp in nodes_by_path and exp != fpath:
                        dst = nodes_by_path[exp]
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
                                    evidence_path=node.source_file,
                                    evidence_note=f"Imports `{dst.label}`.",
                                )
                            )

        notes: list[str] = []
        unobs_note = format_unobserved_a11y_note(unobserved_a11y)
        if unobs_note:
            notes.append(unobs_note)

        return DisplayExtractionResult(
            nodes=list(nodes_by_path.values()),
            edges=edges,
            http_calls=http_calls,
            findings=findings,
            notes=notes,
        )
