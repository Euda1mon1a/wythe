"""Tier 3 Adapter: Vue 3 & Nuxt 3 Single-File Components (`vue-sfc`)."""

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
from app.schemas.atlas import AtlasEdge, AtlasNode

_EXTS = (".vue", ".ts", ".js")


class VueSfcDisplayAdapter:
    """Extracts Vue 3 / Nuxt 3 `.vue` pages, components, composables, API clients, and DISP rules."""

    name = "vue-sfc"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        fe_dir = repo_root.resolve() if frontend_subdir in ("", ".") else (repo_root / frontend_subdir).resolve()
        src_root = (fe_dir / "src").resolve() if (fe_dir / "src").is_dir() else fe_dir
        if not src_root.is_dir():
            return DisplayExtractionResult(nodes=[], edges=[], http_calls=[], findings=[])

        cleaned: dict[Path, str] = {}
        raw_sources: dict[Path, str] = {}
        nodes_by_path: dict[Path, AtlasNode] = {}

        for fpath in sorted(src_root.rglob("*")):
            if not fpath.is_file() or fpath.suffix not in _EXTS:
                continue
            if any(p in fpath.parts for p in ("node_modules", ".nuxt", ".output", "dist", "server")):
                continue
            rel_src = fpath.relative_to(src_root).as_posix()
            if (
                fpath.name.endswith((".d.ts", ".test.ts", ".spec.ts", ".config.ts"))
                or rel_src.endswith("api-generated.ts")
                or rel_src in ("main.ts", "lib/api.ts")
            ):
                continue
            try:
                raw = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue

            parts = Path(rel_src).parts
            head = parts[0] if parts else ""
            if head in ("pages", "views") or fpath.name == "App.vue":
                sub_lbl = "/" + rel_src.removeprefix("pages/").removeprefix("views/").removesuffix(".vue").removesuffix("/index").removesuffix("index")
                lbl = "/" if fpath.name == "App.vue" else (sub_lbl or "/")
                subkind, cluster = "page", "pages"
            elif head in ("composables", "stores") or fpath.stem.startswith("use"):
                lbl, subkind, cluster = fpath.stem, "hook", "composables"
            elif head in ("api", "services", "clients") or fpath.stem in ("api", "client", "http"):
                lbl, subkind, cluster = fpath.stem, "api_client", "api_clients"
            elif fpath.suffix == ".vue" or head == "components":
                lbl, subkind, cluster = fpath.stem, "component", "components"
            else:
                continue

            resolved = fpath.resolve()
            cleaned[resolved] = extract_script_preserving_lines(raw, fpath.suffix)
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
                summary=f"Vue/Nuxt {subkind.replace('_', ' ')} `{lbl}` ({rel_repo}).",
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
                if dst_path and dst_path in nodes_by_path and dst_path != fpath:
                    dst = nodes_by_path[dst_path]
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
