"""Tier 2 Adapter: Python + Django / DRF / Django Ninja Manipulation Graph & Boundary Rules."""

from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.django_urls import (
    UrlModuleAst,
    ViewModuleMeta,
    django_route_regex,
    expand_url_modules,
    extract_pkg_reexports,
    extract_view_module_meta,
    norm_django_path,
    parse_url_module,
    resolve_dotted_symbol,
    resolve_view_target_and_methods,
)
from app.adapters.python_ast_inspect import parse_python_module
from app.schemas.atlas import AtlasEdge, AtlasNode

_DJANGO_READ_ATTRS = frozenset(
    {"filter", "get", "all", "exclude", "values", "values_list", "count", "exists", "first", "last", "select_related", "prefetch_related"}
)
_DJANGO_WRITE_ATTRS = frozenset(
    {"create", "bulk_create", "update", "bulk_update", "update_or_create", "get_or_create", "delete"}
)
_CLOCK_ALLOW_MODULES = ("clock.py", "program_time.py", "sql_clock.py", "timezone.py")
_SKIP_DIRS = frozenset(
    {".venv", "venv", "__pycache__", "migrations", "tests", "node_modules", "frontend", "static", "dist"}
)
_SKIP_FILES = frozenset({"models.py", "settings.py", "asgi.py", "wsgi.py", "apps.py", "admin.py"})


def _extract_django_orm_ops(source: str) -> tuple[set[str], set[str]]:
    """Extract (model_reads, model_writes) from Django `Model.objects.*` and `Model(...)` + `.save()`."""
    reads: set[str] = set()
    writes: set[str] = set()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return reads, writes

    instantiated: set[str] = set()
    has_save_or_delete = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr in ("save", "delete"):
                    has_save_or_delete = True
                val = node.func.value
                if (
                    isinstance(val, ast.Attribute)
                    and val.attr == "objects"
                    and isinstance(val.value, ast.Name)
                ):
                    model_cls = val.value.id
                    if attr in _DJANGO_WRITE_ATTRS:
                        writes.add(model_cls)
                    elif attr in _DJANGO_READ_ATTRS:
                        reads.add(model_cls)
            elif isinstance(node.func, ast.Name) and node.func.id[:1].isupper():
                instantiated.add(node.func.id)

    if has_save_or_delete:
        writes |= instantiated
    return reads, writes


class PythonDjangoAdapter:
    """Extracts Django urls.py/DRF/Ninja routes, Django ORM read/write links, and MANIP findings."""

    name = "python-django"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        base_dir = (repo_root / backend_subdir).resolve() if backend_subdir not in ("", ".") else repo_root
        if not base_dir.is_dir():
            return ManipulatorExtractionResult(
                nodes=[],
                edges=[],
                routes=[],
                findings=[],
                notes=[
                    f"Backend directory '{backend_subdir}' was not found; Django backend coverage is absent."
                ],
                coverage_complete=False,
            )

        mod_files: dict[str, tuple[Path, str]] = {}
        nodes_by_mod: dict[str, AtlasNode] = {}
        parsed_by_mod: dict[str, tuple[Path, str, object]] = {}
        view_metas: dict[str, ViewModuleMeta] = {}
        url_modules: dict[str, UrlModuleAst] = {}
        pkg_reexports: dict[tuple[str, str], tuple[str, str | None]] = {}

        for pf in sorted(base_dir.rglob("*.py")):
            if pf.is_symlink():
                continue
            rel_base_path = pf.relative_to(base_dir)
            rel_parts = rel_base_path.parts
            if _SKIP_DIRS.intersection(rel_parts):
                continue
            if pf.name in _SKIP_FILES:
                continue

            rel_repo = pf.relative_to(repo_root).as_posix()
            raw_mod = ".".join(rel_base_path.with_suffix("").parts)
            is_init = pf.name == "__init__.py"
            mod_name = raw_mod.removesuffix(".__init__") if is_init else raw_mod
            if not mod_name or mod_name == "__init__":
                continue

            mod_files[mod_name] = (pf, rel_repo)
            try:
                src = pf.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue

            in_url_pkg = "urls" in rel_base_path.parts[:-1]
            is_url_file = pf.name == "urls.py" or in_url_pkg
            if is_url_file:
                parsed_url = parse_url_module(pf, rel_repo, mod_name)
                if parsed_url is not None:
                    url_modules[mod_name] = parsed_url
                try:
                    tree = ast.parse(src)
                except (SyntaxError, ValueError):
                    tree = None
                if tree is not None:
                    view_metas[mod_name] = extract_view_module_meta(tree, mod_name, is_init=is_init)
                    if is_init:
                        pkg_reexports.update(extract_pkg_reexports(tree, mod_name))
                continue

            if is_init:
                try:
                    tree = ast.parse(src)
                except (SyntaxError, ValueError):
                    continue
                pkg_reexports.update(extract_pkg_reexports(tree, mod_name))
                continue

            pm = parse_python_module(src, rel_repo, mod_name)
            if pm is None:
                continue
            try:
                tree = ast.parse(src)
            except (SyntaxError, ValueError):
                tree = None
            if tree is not None:
                view_metas[mod_name] = extract_view_module_meta(tree, mod_name, is_init=False)

            is_view = pf.name in ("views.py", "viewsets.py", "api.py", "routers.py") or "views" in rel_parts
            is_cli = "management" in rel_parts or pf.name == "manage.py"
            subkind = "route" if is_view else "cli" if is_cli else "service"
            nid = f"m:{subkind}:{mod_name}"
            nodes_by_mod[mod_name] = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind=subkind,  # type: ignore[arg-type]
                label=mod_name,
                source_file=rel_repo,
                line=1,
                status="clean",
                role="mechanism",
                cluster=mod_name.split(".", 1)[0],
                summary=pm.summary,
            )
            parsed_by_mod[mod_name] = (pf, src, pm)

        expansion = expand_url_modules(url_modules, mod_files, pkg_reexports)
        for promoted_mod in expansion.promoted_modules:
            nodes_by_mod.pop(promoted_mod, None)
            parsed_by_mod.pop(promoted_mod, None)

        symbol_to_mod: dict[str, str] = {}
        for mod_name, (_, _, pm) in parsed_by_mod.items():
            for sym in pm.top_level_defs:  # type: ignore[attr-defined]
                symbol_to_mod.setdefault(sym, mod_name)
        for mod_name, (_, _, pm) in parsed_by_mod.items():
            for sym in pm.defined:  # type: ignore[attr-defined]
                symbol_to_mod.setdefault(sym, mod_name)

        url_imports = {m: u.imports for m, u in url_modules.items()}
        all_imports = {**{m: meta.imports for m, meta in view_metas.items()}, **url_imports}
        known_mods = set(view_metas) | set(url_imports) | {m for m, _ in pkg_reexports}
        routes: list[RouteDescriptor] = []

        def _ensure_route_node(mod_name: str) -> AtlasNode | None:
            if mod_name in nodes_by_mod:
                return nodes_by_mod[mod_name]
            if mod_name not in url_modules or mod_name not in mod_files:
                return None
            pf_u, rel_u = mod_files[mod_name]
            try:
                src_u = pf_u.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                return None
            pm_u = parse_python_module(src_u, rel_u, mod_name)
            if pm_u is None:
                return None
            node_u = AtlasNode(
                id=f"m:route:{mod_name}",
                tier="manipulate",
                subkind="route",
                label=mod_name,
                source_file=rel_u,
                line=1,
                status="clean",
                role="mechanism",
                cluster=mod_name.split(".", 1)[0],
                summary=pm_u.summary,
            )
            nodes_by_mod[mod_name] = node_u
            parsed_by_mod[mod_name] = (pf_u, src_u, pm_u)
            return node_u

        for r in expansion.routes:
            target_mod, vref, verbs = resolve_view_target_and_methods(
                r.target_expr, r.origin_mod, url_imports, view_metas, pkg_reexports, symbol_to_mod
            )
            if not target_mod:
                continue
            vnode = _ensure_route_node(target_mod)
            if vnode is None:
                continue
            vnode.subkind = "route"
            for verb in verbs:
                if verb not in vnode.http_methods:
                    vnode.http_methods.append(verb)
                if r.full_path not in vnode.http_paths:
                    vnode.http_paths.append(r.full_path)
                routes.append(
                    RouteDescriptor(
                        node_id=vnode.id,
                        http_method=verb,
                        full_path=r.full_path,
                        path_regex=django_route_regex(r.full_path),
                        source_file=vnode.source_file,
                        line=r.lineno,
                        called_symbols=frozenset({vref}) if vref else frozenset(),
                        imported_modules=frozenset(),
                    )
                )

        for drf in expansion.drf_regs:
            vs_expr = drf.viewset_expr
            vs_dotted = ""
            if isinstance(vs_expr, ast.Name):
                vs_dotted = vs_expr.id
            elif isinstance(vs_expr, ast.Attribute):
                parts: list[str] = []
                cur: ast.AST = vs_expr
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                    vs_dotted = ".".join(reversed(parts))
            vs_short = vs_dotted.rsplit(".", 1)[-1]
            target_mod, vs_sym, is_ext = (
                resolve_dotted_symbol(drf.origin_mod, vs_dotted, all_imports, known_mods, pkg_reexports)
                if vs_dotted
                else (None, None, False)
            )
            if is_ext:
                continue
            if not target_mod or target_mod not in nodes_by_mod:
                target_mod = symbol_to_mod.get(vs_short)
            if not target_mod or target_mod not in nodes_by_mod:
                continue
            vnode = nodes_by_mod[target_mod]
            vnode.subkind = "route"
            vs_label = (vs_sym or vs_short).rsplit(".", 1)[-1]
            for verb, fp in (
                ("GET", drf.collection_path),
                ("POST", drf.collection_path),
                ("GET", drf.item_path),
                ("PATCH", drf.item_path),
                ("DELETE", drf.item_path),
            ):
                if verb not in vnode.http_methods:
                    vnode.http_methods.append(verb)
                if fp not in vnode.http_paths:
                    vnode.http_paths.append(fp)
                routes.append(
                    RouteDescriptor(
                        node_id=vnode.id,
                        http_method=verb,
                        full_path=fp,
                        path_regex=django_route_regex(fp),
                        source_file=vnode.source_file,
                        line=drf.lineno,
                        called_symbols=frozenset({vs_label}) if vs_label else frozenset(),
                        imported_modules=frozenset(),
                    )
                )

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        findings: list[RawCandidateFinding] = []
        table_readers: dict[str, set[str]] = {}
        table_writers: dict[str, set[str]] = {}

        def add_edge(src: str, dst: str, kind: str, ev_path: str, note: str) -> None:
            if (src, dst, kind) not in seen_edges:
                seen_edges.add((src, dst, kind))
                edges.append(
                    AtlasEdge(
                        id=f"e:{src}->{dst}:{kind}",
                        source_id=src,
                        target_id=dst,
                        kind=kind,  # type: ignore[arg-type]
                        verification="verified",
                        evidence_path=ev_path,
                        evidence_note=note,
                    )
                )

        for mod_name, (_pf, src, pm) in parsed_by_mod.items():
            node = nodes_by_mod[mod_name]
            # Django Ninja decorator routes
            for rh in pm.route_handlers:  # type: ignore[attr-defined]
                full_p = norm_django_path(pm.router_prefix, rh.subpath)  # type: ignore[attr-defined]
                routes.append(
                    RouteDescriptor(
                        node_id=node.id,
                        http_method=rh.http_method,
                        full_path=full_p,
                        path_regex=django_route_regex(full_p),
                        source_file=node.source_file,
                        line=rh.lineno,
                        called_symbols=rh.called_symbols,
                        imported_modules=pm.imported_modules,  # type: ignore[attr-defined]
                    )
                )

            dj_reads, dj_writes = _extract_django_orm_ops(src)
            all_reads = set(pm.reads) | set(pm.sql_reads) | dj_reads  # type: ignore[attr-defined]
            all_writes = set(pm.writes) | set(pm.sql_writes) | dj_writes  # type: ignore[attr-defined]

            for sym in sorted(all_reads):
                tid = truth.table_symbol_map.get(sym) or truth.table_symbol_map.get(sym.lower())
                if tid:
                    table_readers.setdefault(tid, set()).add(node.id)
                    add_edge(node.id, tid, "reads_truth", node.source_file, f"Reads `{sym}`.")
            for sym in sorted(all_writes):
                tid = truth.table_symbol_map.get(sym) or truth.table_symbol_map.get(sym.lower())
                if tid:
                    table_writers.setdefault(tid, set()).add(node.id)
                    add_edge(node.id, tid, "writes_truth", node.source_file, f"Writes `{sym}`.")
                    if node.subkind == "route":
                        node.status = "gray_zone"
                        findings.append(
                            RawCandidateFinding(
                                rule_code="TRUTH-003",
                                node_id=node.id,
                                source_file=node.source_file,
                                line=1,
                                title=f"Django view `{node.label}` mutates `{tid.removeprefix('t:')}` directly",
                                detail=f"`{node.source_file}` writes ORM state directly in view code.",
                                remediation="Move write transactions into a dedicated domain service.",
                            )
                        )

            for imp_mod in pm.imported_modules:  # type: ignore[attr-defined]
                if imp_mod in nodes_by_mod and imp_mod != mod_name:
                    add_edge(node.id, nodes_by_mod[imp_mod].id, "calls_helper", node.source_file, f"Calls `{imp_mod}`.")

            for cname, lineno, sample in pm.policy_literals:  # type: ignore[attr-defined]
                node.status = "policy_in_code"
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-001",
                        node_id=node.id,
                        source_file=node.source_file,
                        line=lineno,
                        title=f"Hardcoded policy constant `{cname}` ({sample})",
                        detail=f"`{node.source_file}:{lineno}` embeds domain policy `{cname}` in Python.",
                        remediation="Persist mutable thresholds in database truth.",
                    )
                )
            if PurePosixPath(node.source_file).name not in _CLOCK_ALLOW_MODULES:
                for clk, lineno in pm.raw_clock_calls:  # type: ignore[attr-defined]
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-002",
                            node_id=node.id,
                            source_file=node.source_file,
                            line=lineno,
                            title=f"Direct host clock call `{clk}`",
                            detail=f"`{node.source_file}:{lineno}` calls `{clk}` directly.",
                            remediation="Use centralized `django.utils.timezone` / program clock helpers.",
                        )
                    )

        for tnode in truth.nodes:
            if tnode.subkind != "table":
                continue
            tnode.read_by_count = len(table_readers.get(tnode.id, set()))
            tnode.written_by_count = len(table_writers.get(tnode.id, set()))
            if tnode.read_by_count == 0 and tnode.role == "input":
                tnode.status = "orphaned"
                findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-001",
                        node_id=tnode.id,
                        source_file=tnode.source_file,
                        line=tnode.line,
                        title=f"Persisted input table `{tnode.label}` has 0 verified readers",
                        detail=f"`{tnode.label}` has zero Django readers.",
                        remediation="Wire active consumers or retire unused model.",
                    )
                )

        inbound: dict[str, int] = {}
        for e in edges:
            if e.kind == "calls_helper":
                inbound[e.target_id] = inbound.get(e.target_id, 0) + 1
        for node in nodes_by_mod.values():
            if node.subkind == "service" and inbound.get(node.id, 0) == 0:
                if node.status == "clean":
                    node.status = "unwired"
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-003",
                        node_id=node.id,
                        source_file=node.source_file,
                        line=1,
                        title=f"Manipulator `{node.label}` has no inbound callers",
                        detail=f"`{node.source_file}` has no callers from views, commands, or peer services.",
                        remediation="Wire into an active execution path or retire dormant code.",
                    )
                )

        return ManipulatorExtractionResult(
            nodes=list(nodes_by_mod.values()),
            edges=edges,
            routes=routes,
            findings=findings,
            notes=expansion.notes,
            coverage_complete=expansion.coverage_complete,
        )
