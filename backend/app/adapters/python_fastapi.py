"""Tier 2 Adapter: Python + FastAPI + SQLAlchemy Manipulation Graph & Boundary Rules."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.python_ast_inspect import ParsedPythonModule, parse_python_module
from app.schemas.atlas import AtlasEdge, AtlasNode

_CLOCK_ALLOW_MODULES = ("clock.py", "program_time.py", "sql_clock.py")
_INFRA_SKIP_PARTS = ("models", "schemas", "__pycache__", "tests")
# Not mechanisms of their own, but their imports still count as callers of the modules they use.
_CALLER_ONLY_PARTS = ("models", "schemas")
_CALLER_ONLY_FILES = ("core/config.py", "db/base.py", "db/session.py")


def _join_http_path(*parts: str) -> str:
    cleaned: list[str] = []
    for part in parts:
        p = part.strip()
        if not p or p == "/":
            continue
        cleaned.append(p.strip("/"))
    return "/" + "/".join(cleaned) if cleaned else "/"


_VERSION_HEAD_RE = re.compile(r"^/api/v\d+(?=/)")


def _compile_route_regex(full_path: str) -> str:
    """Route matcher where the API version head is optional, as clients usually prepend it.

    A route mounted under an explicit `/api/vN` keeps that exact version optional, so both
    `/api/v1/items` and a base-URL-relative `/items` match it.
    """
    norm = full_path.rstrip("/") or "/"
    version = r"/api/v\d+"
    head = _VERSION_HEAD_RE.match(norm)
    if head:
        version = re.escape(head.group(0))
        norm = norm[head.end():]
    escaped = re.sub(r"\{[^/{}]+\}", r"[^/?#]+", norm)
    return rf"^(?:{version})?{escaped}/?$"


def _resolve_router_mounts(modules: list[tuple[str, ParsedPythonModule]]) -> dict[str, list[str]]:
    """Mount prefixes per module stem, composing nested `router.include_router(sub)` chains.

    An include made by an aggregator (`app` or a module with no route handlers of its own)
    mounts the child at the include prefix, as before. An include made into a route module's
    own router mounts the child under every prefix that module is itself mounted at, plus that
    module's `APIRouter(prefix=...)` and the include prefix.
    """
    mounts: dict[str, list[str]] = {}
    nested_edges: list[tuple[str, str, str]] = []
    for stem, pm in modules:
        nested = set(pm.nested_router_includes) if pm.route_handlers else set()
        for child, prefix in pm.router_includes:
            if (child, prefix) in nested:
                nested_edges.append((stem, child, _join_http_path(pm.router_prefix, prefix)))
            else:
                bucket = mounts.setdefault(child, [])
                if prefix not in bucket:
                    bucket.append(prefix)
    for _ in range(8):  # bounded: include chains are shallow and cycles must not loop
        changed = False
        for parent, child, via in nested_edges:
            for parent_mount in list(mounts.get(parent) or [""]):
                joined = _join_http_path(parent_mount, via)
                full = "" if joined == "/" else joined
                bucket = mounts.setdefault(child, [])
                if full not in bucket:
                    bucket.append(full)
                    changed = True
        if not changed:
            break
    return mounts


def _sql_table_id(truth: TruthExtractionResult, sym: str) -> str | None:
    """Table node for a table name taken from SQL text (`public.` is the default schema)."""
    bare = sym.split(".", 1)[1] if sym.startswith("public.") else sym
    return truth.table_symbol_map.get(sym) or truth.table_symbol_map.get(bare)


def _ast_table_id(
    truth: TruthExtractionResult, pm: ParsedPythonModule, sym: str, model_modules: frozenset[str]
) -> str | None:
    """Table node for a Python identifier or module-qualified model/table reference."""
    if not truth.class_modules:
        return _sql_table_id(truth, sym.rpartition(".")[2] if "." in sym else sym)
    if "." in sym:
        mod_part, _, attr = sym.rpartition(".")
        cand_mods: set[str] = set()
        if mod_part in pm.imported_modules:
            cand_mods.add(mod_part)
        for src in pm.imported_names.get(mod_part, ()):
            cand_mods.add(f"{src}.{mod_part}")
        if not cand_mods:
            return None
        defining_attr = truth.class_modules.get(attr)
        if defining_attr:
            if any(d == c or d.startswith(f"{c}.") for c in cand_mods for d in defining_attr):
                return truth.table_symbol_map.get(attr)
            return None
        if any(m == c or m.startswith(f"{c}.") or c.startswith(f"{m}.") for c in cand_mods for m in model_modules):
            return _sql_table_id(truth, attr)
        return None
    defining = truth.class_modules.get(sym)
    if not defining:
        # A table object imported by name from a models module (e.g. an association `Table`).
        sources = pm.imported_names.get(sym)
        if sources and any(m == s or m.startswith(f"{s}.") for s in sources for m in model_modules):
            return _sql_table_id(truth, sym)
        return None
    if pm.module_name not in defining:
        sources = pm.imported_names.get(sym)
        if sources:
            if not any(m == s or m.startswith(f"{s}.") for s in sources for m in defining):
                return None
        elif sym in pm.defined:
            return None
    return truth.table_symbol_map.get(sym)


def _classify_manipulator(rel_inside_app: str) -> tuple[str, str]:
    parts = Path(rel_inside_app).parts
    head = parts[0] if parts else ""
    if head == "api" or "routes" in parts:
        return "route", "api"
    if head in ("scheduling", "solvers", "constraints", "resilience"):
        return "solver", head
    if head in ("cli", "tasks") or rel_inside_app.endswith(("cli.py", "seed.py")):
        return "cli", head or "ops"
    return "service", head or "services"


def _parse_caller_only_parts(app_dir: Path, repo_root: Path) -> list[ParsedPythonModule]:
    """Parse `models/` and `schemas/` modules (never `tests/`): not mechanisms, but callers."""
    out: list[ParsedPythonModule] = []
    for py_file in sorted(app_dir.rglob("*.py")):
        dirs = set(py_file.relative_to(app_dir).parts)  # same test as the main loop's skip
        if not dirs & set(_CALLER_ONLY_PARTS) or dirs & (set(_INFRA_SKIP_PARTS) - set(_CALLER_ONLY_PARTS)):
            continue
        parts = py_file.relative_to(app_dir).with_suffix("").parts
        mod_name = ".".join(("app", *(parts[:-1] if parts[-1] == "__init__" else parts)))
        try:
            text = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        parsed = parse_python_module(text, py_file.relative_to(repo_root).as_posix(), mod_name)
        if parsed is not None:
            out.append(parsed)
    return out


class _ImportResolver:
    """Maps an imported name to manipulator nodes.

    Follows package `__init__` re-exports (relative, absolute, `*`, and PEP 562 lazy tables), and credits
    the modules a package initializer itself uses to whoever uses that package's own code.
    """

    def __init__(
        self,
        mod_to_node: dict[str, str],
        parsed_by_mod: dict[str, ParsedPythonModule],
        packages: dict[str, ParsedPythonModule],
        top_level_definers: dict[str, list[str]],
    ) -> None:
        # Python imports a package before a same-named module file, which the package shadows.
        self.mod_to_node = {mod: nid for mod, nid in mod_to_node.items() if mod not in packages}
        self.parsed_by_mod = parsed_by_mod
        self.top_level_definers = top_level_definers
        self.node_module = {nid: mod for mod, nid in self.mod_to_node.items()}
        self.exports: dict[str, dict[str, str]] = {pkg: {} for pkg in packages}
        self.stars: dict[str, list[str]] = {}
        self.own_uses: dict[str, list[tuple[str, frozenset[str]]]] = {}
        for pkg, ppm in packages.items():
            for name, target, users in ppm.package_exports:
                if name == "*":
                    self.stars.setdefault(pkg, []).append(target.removesuffix(".*"))
                    continue
                self.exports[pkg][name] = target
                if users:
                    self.own_uses.setdefault(pkg, []).append((target, users))

    def _export(self, pkg: str, sym: str, seen: frozenset[str] = frozenset()) -> str | None:
        if pkg in seen:
            return None
        if sym in self.exports.get(pkg, {}):
            return self.exports[pkg][sym]
        next_seen = seen | {pkg}
        for star_mod in self.stars.get(pkg, ()):
            star_pm = self.parsed_by_mod.get(star_mod)
            if star_pm is not None and sym in star_pm.defined:
                return f"{star_mod}.{sym}"
            if star_mod in self.exports:
                nested = self._export(star_mod, sym, next_seen)
                if nested is not None:
                    return nested
        return None

    def node_for(self, qualified: str, depth: int = 0) -> str | None:
        """Node hosting `pkg.mod` or `pkg.mod.Name`, looking through package re-exports."""
        nid = self.mod_to_node.get(qualified)
        if nid or depth > 8 or "." not in qualified:
            return nid
        parent, _, sym = qualified.rpartition(".")
        if parent in self.mod_to_node:
            return self.mod_to_node[parent]
        target = self._export(parent, sym) if parent in self.exports else None
        return self.node_for(target, depth + 1) if target and target != qualified else None

    def resolve_class(
        self,
        qualified: str,
        raw_class_attrs: dict[tuple[str, str], set[str]],
        depth: int = 0,
    ) -> tuple[str, str] | None:
        """Resolve `pkg.mod.ClassName` through module and package re-exports to `(node_id, class_name)`."""
        if depth > 8 or "." not in qualified:
            return None
        parent, _, sym = qualified.rpartition(".")
        nid = self.mod_to_node.get(parent)
        if nid is not None and (nid, sym) in raw_class_attrs:
            return (nid, sym)
        pm_parent = self.parsed_by_mod.get(parent)
        if pm_parent is not None:
            reexp = pm_parent.import_targets.get(sym)
            if reexp and reexp != qualified:
                return self.resolve_class(reexp, raw_class_attrs, depth + 1)
            star_hits = {
                sh
                for m in pm_parent.imported_modules
                if m.endswith(".*")
                for sh in (self.resolve_class(f"{m[:-2]}.{sym}", raw_class_attrs, depth + 1),)
                if sh is not None
            }
            if len(star_hits) == 1:
                return next(iter(star_hits))
        if parent in self.exports:
            target = self._export(parent, sym)
            if target and target != qualified:
                return self.resolve_class(target, raw_class_attrs, depth + 1)
        return None

    def targets(self, imp: str, pm: ParsedPythonModule) -> list[tuple[str, str]]:
        """(node id, evidence) pairs that the import entry `imp` of module `pm` reaches."""
        target_nid = self.mod_to_node.get(imp)
        if target_nid is None and "." in imp:
            parent_mod, _, imported_sym = imp.rpartition(".")
            cand_nid = self.mod_to_node.get(parent_mod)
            if cand_nid and imported_sym in pm.called | pm.reads:
                target_nid = cand_nid
        if target_nid:
            return [(target_nid, f"Imports and invokes `{imp}`.")]
        pkg, _, sym = (imp, "", "") if imp in self.exports else imp.rpartition(".")
        if pkg not in self.exports:
            return []
        if sym and self._export(pkg, sym):
            nid = self.node_for(imp)
            return [(nid, f"Imports `{imp}`, re-exported by package `{pkg}`.")] if nid else []
        if not sym and any(m.startswith(f"{pkg}.") for m in pm.imported_modules):
            return []  # the `from pkg import ...` entry itself; its names resolve one by one
        hits: list[tuple[str, str]] = []
        if sym and sym in pm.called | pm.reads:
            # A name the initializer builds at runtime: accept a unique definer inside the package.
            inside = [d for d in self.top_level_definers.get(sym, ()) if self.node_module.get(d, "").startswith(f"{pkg}.")]
            if len(inside) == 1:
                hits.append((inside[0], f"Uses `{imp}`, defined once inside package `{pkg}`."))
        # Code defined in the initializer: credit what that definition (or import-time code) uses;
        # a bare `import pkg` could reach any of it.
        for dep, users in self.own_uses.get(pkg, ()):
            dep_nid = self.node_for(dep)
            if dep_nid and (not sym or sym in users or "*" in users):
                hits.append((dep_nid, f"Uses `{imp}`; the `{pkg}` initializer builds it on `{dep}`."))
        return hits


class PythonFastApiAdapter:
    """Extracts FastAPI routes, Python services/solvers, ORM/SQL links, and MANIP findings."""

    name = "python-fastapi"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        app_dir = repo_root / backend_subdir / "app"
        if not app_dir.is_dir():
            return ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])

        packages: dict[str, ParsedPythonModule] = {}
        caller_only: list[ParsedPythonModule] = []
        parsed_modules: dict[str, ParsedPythonModule] = {}
        all_parsed: list[tuple[str, ParsedPythonModule]] = []

        for py_file in sorted(app_dir.rglob("*.py")):
            rel_app = py_file.relative_to(app_dir).as_posix()
            if any(part in _INFRA_SKIP_PARTS for part in Path(rel_app).parts):
                continue
            rel_repo = py_file.relative_to(repo_root).as_posix()
            mod_parts = list(Path(rel_app).with_suffix("").parts)
            if mod_parts and mod_parts[-1] == "__init__":
                mod_parts = mod_parts[:-1]
            mod_name = ".".join(["app", *mod_parts]) if mod_parts else "app"
            try:
                text = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            parsed = parse_python_module(text, rel_repo, mod_name)
            if parsed is None:
                continue
            all_parsed.append((Path(rel_app).stem, parsed))
            if Path(rel_app).name == "__init__.py" and not parsed.route_handlers:
                packages[mod_name] = parsed
                continue
            if rel_app in _CALLER_ONLY_FILES:
                caller_only.append(parsed)
                continue
            parsed_modules[rel_app] = parsed
        caller_only.extend(_parse_caller_only_parts(app_dir, repo_root))

        router_mounts = _resolve_router_mounts(all_parsed)

        nodes_by_rel: dict[str, AtlasNode] = {}
        mod_name_to_node_id: dict[str, str] = {}
        symbol_to_defining_nodes: dict[str, list[str]] = {}
        raw_class_attrs: dict[tuple[str, str], set[str]] = {}
        raw_class_methods: dict[tuple[str, str], dict[str, str]] = {}
        raw_class_bases: dict[tuple[str, str], tuple[str, ...]] = {}
        star_sources_by_key: dict[tuple[str, str], tuple[str, ...]] = {}
        classes_by_name: dict[str, list[tuple[str, str]]] = {}

        for rel_app, pm in parsed_modules.items():
            subkind, cluster = _classify_manipulator(rel_app)
            stem_slug = rel_app.removesuffix(".py").replace("/", ".")
            node_id = f"m:{subkind}:{stem_slug}"
            mod_name_to_node_id[pm.module_name] = node_id
            for sym in pm.top_level_defs:
                if len(sym) > 3 and not sym.startswith("_"):
                    symbol_to_defining_nodes.setdefault(sym, []).append(node_id)
            star_mods = tuple(sorted(m[:-2] for m in pm.imported_modules if m.endswith(".*")))
            for cname, cattrs in pm.class_attrs.items():
                key = (node_id, cname)
                raw_class_attrs[key] = set(cattrs)
                raw_class_methods[key] = {
                    m: node_id for m in cattrs if len(m) > 3 and not m.startswith("_") and m in pm.method_defs
                }
                raw_class_bases[key] = pm.class_bases.get(cname, ())
                if star_mods:
                    star_sources_by_key[key] = star_mods
                classes_by_name.setdefault(cname, []).append(key)

            nodes_by_rel[rel_app] = AtlasNode(
                id=node_id,
                tier="manipulate",
                subkind=subkind,  # type: ignore[arg-type]
                label=Path(rel_app).stem if subkind == "route" else rel_app.removesuffix(".py"),
                source_file=pm.rel_path,
                line=1,
                status="clean",
                role="mechanism",
                cluster=cluster,
                summary=pm.summary,
            )

        import_resolver = _ImportResolver(
            mod_name_to_node_id,
            {pm.module_name: pm for pm in parsed_modules.values()},
            packages,
            symbol_to_defining_nodes,
        )

        for _ in range(4):
            for key, bases in raw_class_bases.items():
                for bname in bases:
                    if "." in bname:
                        hit = import_resolver.resolve_class(bname, raw_class_attrs)
                        if hit is None and not bname.startswith("app."):
                            hit = import_resolver.resolve_class(f"app.{bname}", raw_class_attrs)
                        bkeys = [hit] if hit is not None else []
                    else:
                        star_hits = {
                            sh
                            for smod in star_sources_by_key.get(key, ())
                            for sh in (
                                import_resolver.resolve_class(f"{smod}.{bname}", raw_class_attrs)
                                or (
                                    import_resolver.resolve_class(f"app.{smod}.{bname}", raw_class_attrs)
                                    if not smod.startswith("app.")
                                    else None
                                ),
                            )
                            if sh is not None
                        }
                        bkeys = list(star_hits) if len(star_hits) == 1 else classes_by_name.get(bname, ())
                    if len(bkeys) == 1:
                        raw_class_attrs[key].update(raw_class_attrs[bkeys[0]])
                        for mname, def_nid in raw_class_methods[bkeys[0]].items():
                            raw_class_methods[key].setdefault(mname, def_nid)

        method_to_class_profiles: dict[str, list[tuple[str, str, frozenset[str]]]] = {}
        for rel_app, pm in parsed_modules.items():
            nid = nodes_by_rel[rel_app].id
            for cname in pm.class_attrs:
                full_attrs = frozenset(raw_class_attrs[(nid, cname)])
                for mname, def_nid in raw_class_methods[(nid, cname)].items():
                    method_to_class_profiles.setdefault(mname, []).append((def_nid, nid, full_attrs))
        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        routes: list[RouteDescriptor] = []
        findings: list[RawCandidateFinding] = []
        table_readers: dict[str, set[str]] = {}
        table_writers: dict[str, set[str]] = {}
        precise = bool(truth.class_modules)
        model_modules = frozenset(truth.model_modules) | frozenset().union(*truth.class_modules.values())

        def add_edge(src: str, dst: str, kind: str, path: str, note: str) -> None:
            key = (src, dst, kind)
            if src == dst or key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(
                AtlasEdge(
                    id=f"e:{src}->{dst}:{kind}",
                    source_id=src,
                    target_id=dst,
                    kind=kind,  # type: ignore[arg-type]
                    verification="verified",
                    evidence_path=path,
                    evidence_note=note,
                )
            )

        for rel_app, pm in parsed_modules.items():
            node = nodes_by_rel[rel_app]
            nid = node.id

            # 1. Manipulate -> Truth (ORM + SQL reads & writes)
            matched_reads: set[str] = set()
            write_line: dict[str, int] = {}
            for sym in pm.sql_reads:
                tid = _sql_table_id(truth, sym)
                if tid:
                    matched_reads.add(tid)
            for sym in pm.reads:
                tid = _ast_table_id(truth, pm, sym, model_modules)
                if tid:
                    matched_reads.add(tid)
            ast_writes = (
                pm.persisted | (pm.constructed if pm.has_session_writes else frozenset())
                if precise
                else pm.writes
            )
            for sym, resolver in (
                *((s, _sql_table_id) for s in pm.sql_writes),
                *((s, None) for s in ast_writes),
            ):
                tid = resolver(truth, sym) if resolver else _ast_table_id(truth, pm, sym, model_modules)
                if tid:
                    line = pm.write_lines.get(sym, 1)
                    write_line[tid] = min(write_line.get(tid, line), line)
            matched_writes = set(write_line)

            for tid in sorted(matched_reads):
                table_readers.setdefault(tid, set()).add(nid)
                add_edge(nid, tid, "reads_truth", pm.rel_path, f"AST verified read of `{tid.removeprefix('t:')}`.")
            for tid in sorted(matched_writes):
                table_writers.setdefault(tid, set()).add(nid)
                add_edge(nid, tid, "writes_truth", pm.rel_path, f"AST verified write to `{tid.removeprefix('t:')}`.")
                if node.subkind == "route":
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-003",
                            node_id=nid,
                            source_file=pm.rel_path,
                            line=write_line[tid],
                            title=f"HTTP route `{node.label}` writes `{tid.removeprefix('t:')}` directly",
                            detail=f"{pm.rel_path} mutates `{tid.removeprefix('t:')}` inside the route layer rather than delegating to a transactional service door.",
                            remediation="Move persistence mutations into an audited domain service or SQL write-lane function.",
                        )
                    )

            for fn_call in pm.sql_calls | pm.called:
                fn_id = truth.function_symbol_map.get(fn_call.lower())
                if fn_id:
                    add_edge(nid, fn_id, "guards_truth", pm.rel_path, f"Calls PostgreSQL function `{fn_call}`.")

            # 2. Manipulate -> Manipulate (module imports + called symbols)
            for imp in pm.imported_modules:
                for target_nid, note in import_resolver.targets(imp, pm):
                    add_edge(nid, target_nid, "calls_helper", pm.rel_path, note)

            for called_sym in pm.symbol_calls:
                defs = symbol_to_defining_nodes.get(called_sym, [])
                if len(defs) == 1:
                    add_edge(nid, defs[0], "calls_helper", pm.rel_path, f"Calls `{called_sym}()` across manipulation tier.")
            for called_sym, req_attrs in pm.param_method_calls:
                matches = [
                    (def_nid, own_nid)
                    for def_nid, own_nid, cattrs in method_to_class_profiles.get(called_sym, ())
                    if req_attrs <= cattrs
                ]
                definers = {def_nid for def_nid, _ in matches}
                owners = {own_nid for _, own_nid in matches}
                targets = (*(definers if len(definers) == 1 else ()), *(owners if len(owners) == 1 else ()))
                for target_cand in dict.fromkeys(targets):
                    add_edge(
                        nid,
                        target_cand,
                        "calls_helper",
                        pm.rel_path,
                        f"Calls `{called_sym}()` across manipulation tier.",
                    )

            # 3. Route descriptors
            if pm.route_handlers:
                stem = Path(rel_app).stem
                mounts = router_mounts.get(stem) or [""]
                methods_seen: list[str] = []
                paths_seen: list[str] = []
                for mount_prefix in mounts:
                    for h in pm.route_handlers:
                        full_p = _join_http_path(mount_prefix, pm.router_prefix, h.subpath)
                        if h.http_method not in methods_seen:
                            methods_seen.append(h.http_method)
                        if full_p not in paths_seen:
                            paths_seen.append(full_p)
                        routes.append(
                            RouteDescriptor(
                                node_id=nid,
                                http_method=h.http_method,
                                full_path=full_p,
                                path_regex=_compile_route_regex(full_p),
                                source_file=pm.rel_path,
                                line=h.lineno,
                                called_symbols=h.called_symbols,
                                imported_modules=pm.imported_modules,
                            )
                        )
                node.http_methods = methods_seen
                node.http_paths = paths_seen[:25]

            # 4. MANIP-001 & MANIP-002 checks
            if not rel_app.startswith("adapters/"):
                for const_name, lineno, sample in pm.policy_literals:
                    node.status = "policy_in_code"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-001",
                            node_id=nid,
                            source_file=pm.rel_path,
                            line=lineno,
                            title=f"Hardcoded policy constant `{const_name}` ({sample})",
                            detail=f"{pm.rel_path}:{lineno} defines mutable domain policy `{const_name}` in Python code.",
                            remediation="Move policy threshold/vocabulary into PostgreSQL catalog truth and read via snapshot.",
                        )
                    )
            if PurePosixPath(pm.rel_path).name not in _CLOCK_ALLOW_MODULES:
                for clock_expr, lineno in pm.raw_clock_calls:
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-002",
                            node_id=nid,
                            source_file=pm.rel_path,
                            line=lineno,
                            title=f"Direct host clock call `{clock_expr}`",
                            detail=f"{pm.rel_path}:{lineno} calls `{clock_expr}` directly instead of shared DB/program time.",
                            remediation="Read current date/instant from the shared clock authority module.",
                        )
                    )

        # 5. Database-side readers (SQL function bodies, foreign keys) also consume a table.
        # A foreign key only consumes its target when the referencing table is itself in use
        # (touched by code or read by a SQL function); a chain of unused tables stays unused.
        in_use = set(table_readers) | set(table_writers)
        in_use |= {
            tid
            for tid, readers in truth.db_readers.items()
            if any(r.startswith("fn:") for r in readers)
        }
        for tid, db_readers in sorted(truth.db_readers.items()):
            for reader_id, (evidence, kind, note) in sorted(db_readers.items()):
                if reader_id.startswith("t:") and reader_id not in in_use:
                    continue
                table_readers.setdefault(tid, set()).add(reader_id)
                add_edge(reader_id, tid, kind, evidence, note)

        # 6. Update truth read/write counts & TRUTH-001 (orphaned input tables)
        for tnode in truth.nodes:
            if tnode.subkind != "table":
                continue
            rcount = len(table_readers.get(tnode.id, set()))
            wcount = len(table_writers.get(tnode.id, set()))
            tnode.read_by_count = rcount
            tnode.written_by_count = wcount
            if rcount == 0 and tnode.role == "input":
                tnode.status = "orphaned"
                findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-001",
                        node_id=tnode.id,
                        source_file=tnode.source_file,
                        line=tnode.line,
                        title=f"Persisted input table `{tnode.label}` has 0 verified readers",
                        detail=f"`{tnode.label}` is defined as input truth, but no backend module reads it.",
                        remediation="Wire active consumers to read this table or mark/retire unused schema.",
                    )
                )

        # 7. MANIP-003 (inert service/solver mechanisms with zero inbound callers)
        inbound_callers: dict[str, int] = {}
        for edge in edges:
            if edge.kind == "calls_helper":
                inbound_callers[edge.target_id] = inbound_callers.get(edge.target_id, 0) + 1
        for cpm in caller_only:
            for imp in cpm.imported_modules:
                for target_nid, _ in import_resolver.targets(imp, cpm):
                    inbound_callers[target_nid] = inbound_callers.get(target_nid, 0) + 1
        for rel_app, node in nodes_by_rel.items():
            if (
                node.subkind in ("service", "solver")
                and not rel_app.endswith("main.py")
                and inbound_callers.get(node.id, 0) == 0
                and not rel_app.startswith("adapters/")
            ):
                if node.status == "clean":
                    node.status = "unwired"
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-003",
                        node_id=node.id,
                        source_file=node.source_file,
                        line=node.line,
                        title=f"Manipulator `{node.label}` has no inbound callers",
                        detail=f"`{node.source_file}` is not invoked by any route, CLI, task, or peer service.",
                        remediation="Wire the mechanism into an active execution door or quarantine dormant code.",
                    )
                )

        return ManipulatorExtractionResult(
            nodes=list(nodes_by_rel.values()),
            edges=edges,
            routes=routes,
            findings=findings,
        )
