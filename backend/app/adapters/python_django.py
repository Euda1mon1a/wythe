"""Tier 2 Adapter: Python + Django / DRF / Django Ninja Manipulation Graph & Boundary Rules."""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.python_ast_inspect import parse_python_module
from app.schemas.atlas import AtlasEdge, AtlasNode

_DJANGO_PARAM_RE = re.compile(r"<(?:[a-zA-Z_]\w*:)?(?P<p>[a-zA-Z_]\w*)>")
_DJANGO_REGEX_NAMED_RE = re.compile(r"\(\?P<(?P<p>[a-zA-Z_]\w*)>[^)]+\)")
_DJANGO_READ_ATTRS = frozenset(
    {"filter", "get", "all", "exclude", "values", "values_list", "count", "exists", "first", "last", "select_related", "prefetch_related"}
)
_DJANGO_WRITE_ATTRS = frozenset(
    {"create", "bulk_create", "update", "bulk_update", "update_or_create", "get_or_create", "delete"}
)
_CLOCK_ALLOW_MODULES = ("clock.py", "program_time.py", "sql_clock.py", "timezone.py")


def _norm_django_path(*parts: str) -> str:
    cleaned_parts: list[str] = []
    for p in parts:
        s = re.sub(r"^\^|\$$", "", p.strip()).strip("/")
        if s:
            cleaned_parts.append(s)
    joined = "/" + "/".join(cleaned_parts) if cleaned_parts else "/"
    converted = _DJANGO_REGEX_NAMED_RE.sub(r"{\g<p>}", joined)
    converted = _DJANGO_PARAM_RE.sub(r"{\g<p>}", converted)
    return converted or "/"


def _route_regex(full_path: str) -> str:
    norm = full_path.rstrip("/") or "/"
    escaped = re.sub(r"\{[^/{}]+\}", r"[^/?#]+", norm)
    return rf"^(?:/api/v\d+)?{escaped}/?$"


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


def _extract_urls_file(
    py_file: Path,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, int]], list[tuple[str, str, int]]]:
    """Return (includes[(prefix, target_mod)], paths[(subpath, view_ref, line)], drf_regs[(prefix, viewset, line)])."""
    includes: list[tuple[str, str]] = []
    url_paths: list[tuple[str, str, int]] = []
    drf_regs: list[tuple[str, str, int]] = []
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return includes, url_paths, drf_regs

    for sub in ast.walk(tree):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        fn_name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        if fn_name in ("path", "re_path") and len(sub.args) >= 2 and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
            raw_route = sub.args[0].value
            target = sub.args[1]
            if isinstance(target, ast.Call):
                tfn = target.func
                tfn_name = tfn.id if isinstance(tfn, ast.Name) else tfn.attr if isinstance(tfn, ast.Attribute) else ""
                if tfn_name == "include" and target.args and isinstance(target.args[0], ast.Constant) and isinstance(target.args[0].value, str):
                    includes.append((raw_route, target.args[0].value))
                    continue
                if isinstance(tfn, ast.Attribute) and tfn.attr == "as_view":
                    vref = tfn.value.id if isinstance(tfn.value, ast.Name) else tfn.value.attr if isinstance(tfn.value, ast.Attribute) else ""
                    url_paths.append((raw_route, vref, sub.lineno))
                    continue
            vref = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
            url_paths.append((raw_route, vref, sub.lineno))
        elif fn_name == "register" and len(sub.args) >= 2 and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
            vs_arg = sub.args[1]
            vs_name = vs_arg.id if isinstance(vs_arg, ast.Name) else vs_arg.attr if isinstance(vs_arg, ast.Attribute) else ""
            drf_regs.append((sub.args[0].value, vs_name, sub.lineno))
    return includes, url_paths, drf_regs


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
            return ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])

        py_files: list[Path] = []
        for pf in sorted(base_dir.rglob("*.py")):
            if any(
                p in pf.parts
                for p in (".venv", "venv", "__pycache__", "migrations", "tests", "node_modules", "frontend", "static", "dist")
            ):
                continue
            if pf.name in ("__init__.py", "models.py", "settings.py", "asgi.py", "wsgi.py", "apps.py", "admin.py"):
                continue
            py_files.append(pf)

        nodes_by_mod: dict[str, AtlasNode] = {}
        parsed_by_mod: dict[str, tuple[Path, str, object]] = {}
        url_data: dict[str, tuple[list[tuple[str, str]], list[tuple[str, str, int]], list[tuple[str, str, int]]]] = {}

        for pf in py_files:
            rel_base = pf.relative_to(base_dir).as_posix()
            rel_repo = pf.relative_to(repo_root).as_posix()
            mod_name = ".".join(Path(rel_base).with_suffix("").parts)
            try:
                src = pf.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if pf.name == "urls.py":
                url_data[mod_name] = _extract_urls_file(pf)
                continue
            pm = parse_python_module(src, rel_repo, mod_name)
            if pm is None:
                continue
            is_view = pf.name in ("views.py", "viewsets.py", "api.py", "routers.py") or "views" in pf.parts
            is_cli = "management" in pf.parts or pf.name == "manage.py"
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

        # Resolve urls.py prefixes across included app urlconfs
        mod_prefixes: dict[str, str] = {}
        for umod, (incs, _, _) in url_data.items():
            base_pref = mod_prefixes.get(umod, "")
            for sub_pref, target_umod in incs:
                mod_prefixes[target_umod] = _norm_django_path(base_pref, sub_pref)

        symbol_to_mod: dict[str, str] = {}
        for mod_name, (_, _, pm) in parsed_by_mod.items():
            for sym in pm.defined:  # type: ignore[attr-defined]
                symbol_to_mod.setdefault(sym, mod_name)

        routes: list[RouteDescriptor] = []
        for umod, (_, upaths, drf_regs) in url_data.items():
            pref = mod_prefixes.get(umod, "")
            app_pkg = umod.rsplit(".", 1)[0] if "." in umod else ""
            fallback_view_mod = f"{app_pkg}.views" if f"{app_pkg}.views" in nodes_by_mod else next(iter(nodes_by_mod), "")
            for subpath, vref, lineno in upaths:
                target_mod = symbol_to_mod.get(vref, fallback_view_mod)
                if target_mod not in nodes_by_mod:
                    continue
                vnode = nodes_by_mod[target_mod]
                vnode.subkind = "route"
                full_p = _norm_django_path(pref, subpath)
                for verb in ("GET", "POST"):
                    if verb not in vnode.http_methods:
                        vnode.http_methods.append(verb)
                    if full_p not in vnode.http_paths:
                        vnode.http_paths.append(full_p)
                    routes.append(
                        RouteDescriptor(
                            node_id=vnode.id,
                            http_method=verb,
                            full_path=full_p,
                            path_regex=_route_regex(full_p),
                            source_file=vnode.source_file,
                            line=lineno,
                            called_symbols=frozenset({vref}),
                            imported_modules=frozenset(),
                        )
                    )
            for reg_pref, vs_name, lineno in drf_regs:
                target_mod = symbol_to_mod.get(vs_name, fallback_view_mod)
                if target_mod not in nodes_by_mod:
                    continue
                vnode = nodes_by_mod[target_mod]
                coll_p = _norm_django_path(pref, reg_pref)
                item_p = _norm_django_path(coll_p, "{id}")
                for verb, fp in (("GET", coll_p), ("POST", coll_p), ("GET", item_p), ("PATCH", item_p), ("DELETE", item_p)):
                    if verb not in vnode.http_methods:
                        vnode.http_methods.append(verb)
                    if fp not in vnode.http_paths:
                        vnode.http_paths.append(fp)
                    routes.append(
                        RouteDescriptor(
                            node_id=vnode.id,
                            http_method=verb,
                            full_path=fp,
                            path_regex=_route_regex(fp),
                            source_file=vnode.source_file,
                            line=lineno,
                            called_symbols=frozenset({vs_name}),
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
                full_p = _norm_django_path(pm.router_prefix, rh.subpath)  # type: ignore[attr-defined]
                routes.append(
                    RouteDescriptor(
                        node_id=node.id,
                        http_method=rh.http_method,
                        full_path=full_p,
                        path_regex=_route_regex(full_p),
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
        )
