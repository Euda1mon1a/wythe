"""Tier 3 Adapter: React SPA / Vite / React Router / TanStack Router / Remix (`typescript-react`)."""

from __future__ import annotations

from pathlib import Path

from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    RawCandidateFinding,
)
from app.adapters.frontend_common import (
    extract_script_preserving_lines,
    resolve_frontend_import,
    scan_display_module_semantics,
)
from app.adapters.typescript_nextjs import _REEXPORT_NAMED_RE, _REEXPORT_STAR_RE
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
                or rel_src in ("main.tsx", "index.tsx", "vite-env.d.ts", "lib/api.ts")
            ):
                continue
            try:
                raw = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue

            resolved = fpath.resolve()
            clean_txt = extract_script_preserving_lines(raw, fpath.suffix)
            if fpath.name in ("index.ts", "index.tsx", "index.js"):
                targets: list[Path] = []
                for rex in (_REEXPORT_STAR_RE, _REEXPORT_NAMED_RE):
                    for m in rex.finditer(clean_txt):
                        t = resolve_frontend_import(m.group("spec"), resolved, src_root, _EXTS)
                        if t is not None:
                            targets.append(t)
                barrel_targets[resolved] = targets
                continue

            parts = Path(rel_src).parts
            eff_parts = parts[1:] if len(parts) > 1 and parts[0] in ("lib", "app") else parts
            head = eff_parts[0] if eff_parts else ""
            stem_low = fpath.stem.lower()
            if head in ("pages", "routes", "views") or fpath.stem == "App":
                lbl = "/" if fpath.stem in ("App", "Home", "index") else f"/{stem_low}"
                subkind, cluster = "page", "pages"
            elif head in ("hooks", "stores", "store") or fpath.stem.startswith("use") or stem_low in ("store", "state"):
                lbl, subkind, cluster = fpath.stem, "hook", "hooks"
            elif (
                head in ("api", "services", "clients", "queries")
                or stem_low in ("api", "client", "http", "queries")
                or fpath.stem.endswith(("Client", "Api", "Service"))
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

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        for fpath, node in nodes_by_path.items():
            specs, calls, mod_findings = scan_display_module_semantics(
                node, cleaned[fpath], node.source_file, raw_source=raw_sources[fpath]
            )
            http_calls.extend(calls)
            findings.extend(mod_findings)
            for spec in specs:
                dst_path = resolve_frontend_import(spec, fpath, src_root, _EXTS)
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

        return DisplayExtractionResult(
            nodes=list(nodes_by_path.values()),
            edges=edges,
            http_calls=http_calls,
            findings=findings,
        )
