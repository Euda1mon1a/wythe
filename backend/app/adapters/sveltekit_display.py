"""Tier 3 Adapter: Svelte 5 & SvelteKit (`sveltekit`)."""

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

_EXTS = (".svelte", ".ts", ".js")


def _sveltekit_route_label(rel_src: str) -> str:
    parts = [
        p
        for p in Path(rel_src).parts[1:-1]
        if not (p.startswith("(") and p.endswith(")"))
    ]
    return "/" + "/".join(parts) if parts else "/"


class SvelteKitDisplayAdapter:
    """Extracts SvelteKit `+page.svelte` / `+page.ts` routes, `$lib` stores/clients, and DISP rules."""

    name = "sveltekit"

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
            if any(p in fpath.parts for p in ("node_modules", ".svelte-kit", "build", "dist", "server")):
                continue
            rel_src = fpath.relative_to(src_root).as_posix()
            if (
                fpath.name.endswith((".d.ts", ".test.ts", ".spec.ts", "+server.ts", "+page.server.ts", "+layout.server.ts", "+layout.svelte"))
                or rel_src.endswith("api-generated.ts")
            ):
                continue
            try:
                raw = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue

            parts = Path(rel_src).parts
            head = parts[0] if parts else ""
            if head == "routes" and fpath.name in ("+page.svelte", "+page.ts"):
                lbl = _sveltekit_route_label(rel_src)
                subkind, cluster = "page", "pages"
            elif "stores" in parts or fpath.stem.startswith("use"):
                lbl, subkind, cluster = fpath.stem, "hook", "stores"
            elif "api" in parts or "clients" in parts or fpath.stem in ("api", "client", "http"):
                lbl, subkind, cluster = fpath.stem, "api_client", "api_clients"
            elif fpath.suffix == ".svelte" or "components" in parts:
                lbl, subkind, cluster = fpath.stem, "component", "components"
            else:
                continue

            resolved = fpath.resolve()
            cleaned[resolved] = extract_script_preserving_lines(raw, fpath.suffix)
            raw_sources[resolved] = raw
            rel_repo = resolved.relative_to(repo_root.resolve()).as_posix()
            slug = Path(rel_src).as_posix().replace("/", ".").replace("+", "plus_")
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
                summary=f"SvelteKit {subkind.replace('_', ' ')} `{lbl}` ({rel_repo}).",
            )

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        # Link `+page.svelte` automatically to sibling `+page.ts` and `+page.server.ts` load/actions
        for fpath, node in nodes_by_path.items():
            if fpath.name == "+page.svelte":
                sib = (fpath.parent / "+page.ts").resolve()
                if sib in nodes_by_path:
                    dst = nodes_by_path[sib]
                    seen_edges.add((node.id, dst.id, "uses_client"))
                    edges.append(
                        AtlasEdge(
                            id=f"e:{node.id}->{dst.id}:uses_client",
                            source_id=node.id,
                            target_id=dst.id,
                            kind="uses_client",
                            verification="verified",
                            evidence_path=node.source_file,
                            evidence_note="SvelteKit sibling `+page.ts` load function.",
                        )
                    )
                sib_srv = fpath.parent / "+page.server.ts"
                if sib_srv.is_file():
                    srv_txt = sib_srv.read_text(encoding="utf-8", errors="replace")
                    norm_lbl = node.label if node.label.startswith("/") else f"/{node.label}"
                    for verb, marker in (("GET", "load"), ("POST", "actions")):
                        if f"const {marker}" in srv_txt or f"function {marker}" in srv_txt:
                            http_calls.append(
                                FrontendHttpCall(
                                    caller_node_id=node.id,
                                    http_method=verb,
                                    raw_path=norm_lbl,
                                    normalized_path=norm_lbl,
                                    source_file=node.source_file,
                                    line=1,
                                )
                            )
                            if verb not in node.http_methods:
                                node.http_methods.append(verb)
                            if norm_lbl not in node.http_paths:
                                node.http_paths.append(norm_lbl)

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
