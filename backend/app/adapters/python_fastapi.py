"""Tier 2 Adapter: Python + FastAPI + SQLAlchemy Manipulation Graph & Boundary Rules."""

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
from app.adapters.python_ast_inspect import ParsedPythonModule, _excluded_ids, parse_python_module
from app.adapters.python_layout import discover_python_app
from app.adapters.python_policy_consumption import (
    analyze_module_policy_table_read,
    classify_table_policy_columns,
    merge_policy_consumptions,
    summarize_edge_policy_consumption,
)
from app.schemas.atlas import AtlasEdge, AtlasNode, PolicyFieldConsumption

_CLOCK_ALLOW_MODULES = ("clock.py", "program_time.py", "sql_clock.py")
_INFRA_SKIP_PARTS = ("__pycache__", "tests", "test", "alembic")
# Declaration-only files are callers, not mechanisms; mixed repository modules are retained.
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
    if head == "api" or "routes" in parts or "routers" in parts:
        return "route", "api"
    if head in ("scheduling", "solvers", "constraints", "resilience"):
        return "solver", head
    if head in ("cli", "tasks") or rel_inside_app.endswith(("cli.py", "seed.py")):
        return "cli", head or "ops"
    return "service", head or "services"


def _is_passive_imported_symbol(
    imported_sym: str,
    pm: ParsedPythonModule,
    pm_parent: ParsedPythonModule | None,
) -> bool:
    """Return True when `imported_sym` is a constant or exception class in a callable service module."""
    if pm_parent is None or not pm_parent.defined:
        return False
    if pm_parent.route_handlers or pm_parent.router_includes:
        parent_stem = Path(pm_parent.rel_path).stem
        if any(child == parent_stem for child, _ in pm.router_includes):
            return False
    has_attr_call = any(c.startswith(f"{imported_sym}.") for c in pm.called)
    if imported_sym not in pm.called and not has_attr_call:
        stripped = imported_sym.lstrip("_")
        if stripped and stripped.isupper():
            return True
        if (
            pm_parent is not None
            and imported_sym not in pm_parent.defined
            and imported_sym not in pm_parent.import_targets
            and not any(m.endswith(".*") for m in pm_parent.imported_modules)
        ):
            return True
    if pm_parent is not None and imported_sym in pm_parent.class_bases and not has_attr_call:
        bases = pm_parent.class_bases.get(imported_sym, ())
        pub_methods = pm_parent.class_attrs.get(imported_sym, frozenset()) & pm_parent.method_defs
        if not pub_methods and (
            imported_sym.endswith(("Error", "Exception", "Refusal", "Warning"))
            or any(b.endswith(("Error", "Exception", "BaseException", "Warning")) for b in bases)
        ):
            return True
    return False


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
        if target_nid is not None and any(m.startswith(f"{imp}.") for m in pm.imported_modules):
            mod_leaf = imp.rpartition(".")[2] or imp
            if (
                mod_leaf not in pm.called
                and not any(c.startswith((f"{mod_leaf}.", f"{imp}.")) for c in pm.called)
            ):
                target_nid = None
        if target_nid is None and "." in imp:
            parent_mod, _, imported_sym = imp.rpartition(".")
            cand_nid = self.mod_to_node.get(parent_mod)
            if cand_nid and imported_sym in pm.called | pm.reads:
                pm_parent = self.parsed_by_mod.get(parent_mod)
                if not _is_passive_imported_symbol(imported_sym, pm, pm_parent):
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


def _collect_runtime_import_sites(
    source: str,
    module_name: str,
    rel_repo: str,
    package_name: str,
) -> list[tuple[str, str, int]]:
    """Return `(target_module, importer_rel_path, lineno)` for runtime imports and PEP 562 exports."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    skip = _excluded_ids(tree)
    own_pkg = module_name if rel_repo.endswith("__init__.py") else module_name.rpartition(".")[0]
    out: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.ImportFrom):
            src_mod = node.module or ""
            if node.level:
                base_pkg = own_pkg
                for _ in range(node.level - 1):
                    base_pkg = base_pkg.rpartition(".")[0]
                src_mod = ".".join(p for p in (base_pkg, src_mod) if p)
            cand_srcs = [src_mod]
            if node.level == 0 and src_mod and not src_mod.startswith(f"{package_name}."):
                cand_srcs.append(f"{package_name}.{src_mod}")
            for cand_src in cand_srcs:
                if cand_src:
                    out.append((cand_src, rel_repo, node.lineno))
                for alias in node.names:
                    if alias.name != "*":
                        ln = getattr(alias, "lineno", None) or node.lineno
                        qual = f"{cand_src}.{alias.name}" if cand_src else alias.name
                        out.append((qual, rel_repo, ln))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                ln = getattr(alias, "lineno", None) or node.lineno
                cand_imps = [alias.name]
                if not alias.name.startswith(f"{package_name}."):
                    cand_imps.append(f"{package_name}.{alias.name}")
                for cand_imp in cand_imps:
                    parts = cand_imp.split(".")
                    for k in range(2, len(parts) + 1):
                        out.append((".".join(parts[:k]), rel_repo, ln))

    if rel_repo.endswith("__init__.py") and any(
        isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name == "__getattr__"
        for s in tree.body
    ):
        for stmt in tree.body:
            val_node = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
            if not isinstance(val_node, ast.Dict):
                continue
            for val in val_node.values:
                mod_str: str | None = None
                if (
                    isinstance(val, ast.Tuple)
                    and len(val.elts) == 2
                    and all(isinstance(e, ast.Constant) for e in val.elts)
                    and isinstance(val.elts[0].value, str)
                ):
                    mod_str = val.elts[0].value
                elif isinstance(val, ast.Constant) and isinstance(val.value, str):
                    mod_str = val.value
                if mod_str:
                    ln = getattr(val, "lineno", None) or stmt.lineno
                    out.append((mod_str, rel_repo, ln))
                    if not mod_str.startswith(f"{package_name}."):
                        out.append((f"{package_name}.{mod_str}", rel_repo, ln))
    return out


class PythonFastApiAdapter:
    """Extracts FastAPI routes, Python services/solvers, ORM/SQL links, and MANIP findings."""

    name = "python-fastapi"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        app_dir, notes = discover_python_app(repo_root / backend_subdir)
        if app_dir is None:
            return ManipulatorExtractionResult(
                nodes=[],
                edges=[],
                routes=[],
                findings=[],
                notes=notes,
                coverage_complete=False,
            )
        package_name = app_dir.name

        packages: dict[str, ParsedPythonModule] = {}
        caller_only: list[ParsedPythonModule] = []
        parsed_modules: dict[str, ParsedPythonModule] = {}
        source_by_rel: dict[str, str] = {}
        all_parsed: list[tuple[str, ParsedPythonModule]] = []
        scanned_sources: list[tuple[str, str, str]] = []

        for py_file in sorted(app_dir.rglob("*.py")):
            rel_app = py_file.relative_to(app_dir).as_posix()
            rel_parts = Path(rel_app).parts
            if (
                py_file.is_symlink()
                or any(part in _INFRA_SKIP_PARTS for part in rel_parts)
                or ("migrations" in rel_parts[:-1] and ("versions" in rel_parts or rel_parts[-1] == "env.py"))
            ):
                continue
            rel_repo = py_file.relative_to(repo_root).as_posix()
            mod_parts = list(Path(rel_app).with_suffix("").parts)
            if mod_parts and mod_parts[-1] == "__init__":
                mod_parts = mod_parts[:-1]
            mod_name = ".".join([package_name, *mod_parts]) if mod_parts else package_name
            try:
                text = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            parsed = parse_python_module(text, rel_repo, mod_name)
            if parsed is None:
                continue
            scanned_sources.append((rel_repo, mod_name, text))
            all_parsed.append((Path(rel_app).stem, parsed))
            if any(p in _CALLER_ONLY_PARTS for p in Path(rel_app).parts) and not (
                parsed.has_session_reads or parsed.has_session_writes or parsed.sql_reads or parsed.sql_writes
                or parsed.route_handlers
            ):
                caller_only.append(parsed)
                if Path(rel_app).name == "__init__.py":
                    packages[mod_name] = parsed
                continue
            if Path(rel_app).name == "__init__.py" and not parsed.route_handlers:
                packages[mod_name] = parsed
                continue
            if rel_app in _CALLER_ONLY_FILES:
                caller_only.append(parsed)
                continue
            parsed_modules[rel_app] = parsed
            source_by_rel[rel_app] = text

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
                        if hit is None and not bname.startswith(f"{package_name}."):
                            hit = import_resolver.resolve_class(f"{package_name}.{bname}", raw_class_attrs)
                        bkeys = [hit] if hit is not None else []
                    else:
                        star_hits = {
                            sh
                            for smod in star_sources_by_key.get(key, ())
                            for sh in (
                                import_resolver.resolve_class(f"{smod}.{bname}", raw_class_attrs)
                                or (
                                    import_resolver.resolve_class(f"{package_name}.{smod}.{bname}", raw_class_attrs)
                                    if not smod.startswith(f"{package_name}.")
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
        edge_idx_by_key: dict[tuple[str, str, str], int] = {}
        routes: list[RouteDescriptor] = []
        findings: list[RawCandidateFinding] = []
        table_readers: dict[str, set[str]] = {}
        table_writers: dict[str, set[str]] = {}
        tnode_by_id: dict[str, AtlasNode] = {}
        model_syms_by_tid: dict[str, set[str]] = {}
        edge_consumptions_by_tid: dict[str, list[PolicyFieldConsumption]] = {}
        for sym_k, mapped_tid in truth.table_symbol_map.items():
            model_syms_by_tid.setdefault(mapped_tid, set()).add(sym_k)
        for tnode in truth.nodes:
            if tnode.subkind == "table":
                tnode_by_id[tnode.id] = tnode
                tnode.policy_columns = classify_table_policy_columns(
                    tnode.label, tnode.columns
                )
        precise = bool(truth.class_modules)
        model_modules = frozenset(truth.model_modules) | frozenset().union(*truth.class_modules.values())
        parsed_by_nid: dict[str, ParsedPythonModule] = {
            nodes_by_rel[rel_a].id: pm_a for rel_a, pm_a in parsed_modules.items()
        }
        all_other_modules: list[ParsedPythonModule] = [
            *parsed_modules.values(),
            *caller_only,
            *packages.values(),
        ]
        global_ref_counts: dict[str, int] = {}
        own_ref_tokens: dict[int, set[str]] = {}
        for m_item in all_other_modules:
            toks = set(m_item.called) | set(m_item.reads)
            for imp_m in m_item.imported_modules:
                if "." in imp_m:
                    toks.add(imp_m.rpartition(".")[2])
            own_ref_tokens[id(m_item)] = toks
            for tok in toks:
                global_ref_counts[tok] = global_ref_counts.get(tok, 0) + 1

        def add_edge(
            src: str,
            dst: str,
            kind: str,
            path: str,
            note: str,
            *,
            verification: str = "verified",
            symbol_links: list[str] | None = None,
            policy_field_consumption: PolicyFieldConsumption | None = None,
        ) -> None:
            key = (src, dst, kind)
            if src == dst:
                return
            links = list(dict.fromkeys(symbol_links or ()))
            if key in edge_idx_by_key:
                existing = edges[edge_idx_by_key[key]]
                if links:
                    merged = list(dict.fromkeys([*existing.symbol_links, *links]))
                    existing.symbol_links = merged
                if policy_field_consumption is not None:
                    existing.policy_field_consumption = (
                        merge_policy_consumptions(
                            [existing.policy_field_consumption, policy_field_consumption]
                        )
                        if existing.policy_field_consumption is not None
                        else policy_field_consumption
                    )
                if existing.verification != "verified" and verification == "verified":
                    existing.verification = "verified"  # type: ignore[assignment]
                    existing.evidence_note = note
                return
            edge_idx_by_key[key] = len(edges)
            edges.append(
                AtlasEdge(
                    id=f"e:{src}->{dst}:{kind}",
                    source_id=src,
                    target_id=dst,
                    kind=kind,  # type: ignore[arg-type]
                    verification=verification,  # type: ignore[arg-type]
                    evidence_path=path,
                    evidence_note=note,
                    symbol_links=links,
                    policy_field_consumption=policy_field_consumption,
                )
            )

        for rel_app, pm in parsed_modules.items():
            node = nodes_by_rel[rel_app]
            nid = node.id

            # 0. Route descriptors (computed first so route HTTP keys are available for symbol_links)
            handler_route_keys: dict[str, list[str]] = {}
            if pm.route_handlers:
                stem = Path(rel_app).stem
                mounts = router_mounts.get(stem) or [""]
                methods_seen: list[str] = []
                paths_seen: list[str] = []
                for mount_prefix in mounts:
                    for h in pm.route_handlers:
                        full_p = _join_http_path(mount_prefix, pm.router_prefix, h.subpath)
                        rk = f"{h.http_method} {full_p}"
                        rkeys = handler_route_keys.setdefault(h.func_name, [])
                        if rk not in rkeys:
                            rkeys.append(rk)
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

            def _expand_scopes(
                raw_scopes: set[str],
                _rkeys: dict[str, list[str]] = handler_route_keys,
            ) -> list[str]:
                out: list[str] = []
                for sc in sorted(raw_scopes):
                    out.append(sc)
                    out.extend(_rkeys.get(sc, ()))
                return out

            pm_own_toks = own_ref_tokens.get(id(pm), set())
            ext_refs = {
                fn
                for fn in pm.top_level_defs
                if global_ref_counts.get(fn, 0) > (1 if fn in pm_own_toks else 0)
            }

            seed_live_scopes: set[str] = (
                {"*"}
                | set(pm.decorated_funcs)
                | set(pm.class_attrs)
                | set(pm.method_defs)
                | {
                    fn
                    for fn in pm.top_level_defs
                    if fn in ext_refs
                    or fn in pm.func_calls.get("*", ())
                    or any(
                        fn in pm.func_calls.get(m, ())
                        for m in (set(pm.class_attrs) | set(pm.method_defs) | set(pm.decorated_funcs))
                    )
                }
            )
            live_scopes = set(seed_live_scopes) | {
                cal
                for sc in seed_live_scopes
                for cal in pm.func_calls.get(sc, ())
                if cal in pm.top_level_defs
            }
            top_funcs = pm.top_level_defs - set(pm.class_attrs)
            has_selective_liveness = bool(
                node.subkind in ("service", "solver")
                and (top_funcs & live_scopes)
                and (top_funcs - live_scopes)
            )

            # 1. Manipulate -> Truth (ORM + SQL reads & writes)
            matched_reads: set[str] = set()
            verified_read_scopes: dict[str, set[str]] = {}
            declared_read_scopes: dict[str, set[str]] = {}
            write_line: dict[str, int] = {}
            write_scopes_by_tid: dict[str, set[str]] = {}
            for sym, is_sql in (
                *((s, True) for s in pm.sql_reads),
                *((s, False) for s in pm.reads),
            ):
                tid = _sql_table_id(truth, sym) if is_sql else _ast_table_id(truth, pm, sym, model_modules)
                if not tid:
                    continue
                r_scopes = {sc for sc, rsyms in pm.func_reads.items() if sym in rsyms} or {"*"}
                if has_selective_liveness and r_scopes.isdisjoint(live_scopes):
                    declared_read_scopes.setdefault(tid, set()).update(r_scopes)
                else:
                    matched_reads.add(tid)
                    active_r = (r_scopes & live_scopes) if has_selective_liveness else r_scopes
                    verified_read_scopes.setdefault(tid, set()).update(active_r or {"*"})

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
                    w_scopes = {sc for sc, wsyms in pm.func_writes.items() if sym in wsyms} or {"*"}
                    write_scopes_by_tid.setdefault(tid, set()).update(w_scopes)
            matched_writes = set(write_line)

            edge_consumptions_for_node: list[PolicyFieldConsumption] = []
            subst_consts_in_mod: dict[str, list[str]] = {}
            fb_consts_in_mod: dict[str, list[str]] = {}

            for tid in sorted(matched_reads):
                table_readers.setdefault(tid, set()).add(nid)
                slinks = [f"{sc}->*" for sc in _expand_scopes(verified_read_scopes.get(tid, {"*"}))]
                t_label = tid.removeprefix("t:")
                ev_note = f"AST verified read of `{t_label}`."
                edge_pfc: PolicyFieldConsumption | None = None
                tnode_ref = tnode_by_id.get(tid)
                if tnode_ref is not None and tnode_ref.policy_columns:
                    ast_syms = {
                        s for s in pm.reads if _ast_table_id(truth, pm, s, model_modules) == tid
                    }
                    sql_syms = {s for s in pm.sql_reads if _sql_table_id(truth, s) == tid}
                    scope_analyses = analyze_module_policy_table_read(
                        source_by_rel.get(rel_app, ""),
                        table_label=tnode_ref.label,
                        table_columns=tnode_ref.columns,
                        policy_columns=tnode_ref.policy_columns,
                        active_scopes=sorted(verified_read_scopes.get(tid, {"*"})),
                        write_scopes=write_scopes_by_tid.get(tid, set()),
                        func_calls=pm.func_calls,
                        model_symbols=ast_syms | (model_syms_by_tid.get(tid, set()) & set(pm.reads)),
                        sql_table_names=sql_syms,
                        declared_policy_consts=[c for c, _, _ in pm.policy_literals],
                    )
                    summarized = summarize_edge_policy_consumption(
                        tnode_ref.label, tnode_ref.policy_columns, scope_analyses
                    )
                    if summarized is not None:
                        edge_pfc, ev_note = summarized
                        edge_consumptions_for_node.append(edge_pfc)
                        edge_consumptions_by_tid.setdefault(tid, []).append(edge_pfc)
                    for sa in scope_analyses:
                        if sa.state == "bypassed":
                            for sc_const in sa.substituted_constants:
                                subst_consts_in_mod.setdefault(sc_const, []).append(
                                    tnode_ref.label
                                )
                        for fb_const in sa.fallback_constants:
                            fb_consts_in_mod.setdefault(fb_const, []).append(tnode_ref.label)
                        if sa.state == "bypassed" and not rel_app.startswith("adapters/"):
                            node.status = "policy_in_code"
                            uncons_str = ", ".join(f"`{c}`" for c in sa.unconsumed_policy_columns)
                            cons_str = (
                                ", ".join(f"`{c}`" for c in sa.consumed_columns)
                                if sa.consumed_columns
                                else "none"
                            )
                            subst_str = (
                                " and substitutes "
                                + ", ".join(f"`{k}`" for k in sa.substituted_constants)
                                if sa.substituted_constants
                                else ""
                            )
                            dead_str = (
                                " Policy column access occurs only in dead/unreachable flow."
                                if sa.had_dead_policy_access
                                else ""
                            )
                            sc_label = (
                                f"`{sa.scope_name}()`" if sa.scope_name != "*" else "module scope"
                            )
                            findings.append(
                                RawCandidateFinding(
                                    rule_code="MANIP-001",
                                    node_id=nid,
                                    target_node_id=tid,
                                    source_file=pm.rel_path,
                                    line=sa.lineno,
                                    title=(
                                        f"Policy read of `{tnode_ref.label}` in {sc_label} "
                                        f"bypasses policy column(s) {uncons_str}{subst_str}"
                                    ),
                                    detail=(
                                        f"{pm.rel_path}:{sa.lineno} queries `{tnode_ref.label}` "
                                        f"in {sc_label} (consumed columns: {cons_str}; "
                                        f"unconsumed policy columns: {uncons_str})"
                                        f"{subst_str}.{dead_str}"
                                    ),
                                    remediation=(
                                        f"Project and flow `{tnode_ref.label}` policy column(s) "
                                        f"{uncons_str} into live returned/controlling values "
                                        "instead of hardcoded constants."
                                    ),
                                )
                            )
                add_edge(
                    nid,
                    tid,
                    "reads_truth",
                    pm.rel_path,
                    ev_note,
                    symbol_links=slinks,
                    policy_field_consumption=edge_pfc,
                )
            if edge_consumptions_for_node:
                node.policy_field_consumption = merge_policy_consumptions(
                    edge_consumptions_for_node
                )
            for tid in sorted(set(declared_read_scopes) - matched_reads):
                u_funcs = sorted(declared_read_scopes[tid])
                slinks = [f"{sc}->*" for sc in _expand_scopes(set(u_funcs))]
                add_edge(
                    nid,
                    tid,
                    "reads_truth",
                    pm.rel_path,
                    f"Uncalled function `{u_funcs[0]}()` declares read of `{tid.removeprefix('t:')}` (0 callers).",
                    verification="declared",
                    symbol_links=slinks,
                )
            for tid in sorted(matched_writes):
                table_writers.setdefault(tid, set()).add(nid)
                slinks = [f"{sc}->*" for sc in _expand_scopes(write_scopes_by_tid.get(tid, {"*"}))]
                add_edge(
                    nid,
                    tid,
                    "writes_truth",
                    pm.rel_path,
                    f"AST verified write to `{tid.removeprefix('t:')}`.",
                    symbol_links=slinks,
                )
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
                    g_scopes = {sc for sc, csyms in pm.func_calls.items() if fn_call in csyms} or {"*"}
                    slinks = [f"{sc}->*" for sc in _expand_scopes(g_scopes)]
                    add_edge(
                        nid,
                        fn_id,
                        "guards_truth",
                        pm.rel_path,
                        f"Calls PostgreSQL function `{fn_call}`.",
                        symbol_links=slinks,
                    )

            def _helper_links(
                target_cand: str,
                explicit_sym: str | None = None,
                _pm: ParsedPythonModule = pm,
                _expand: object = _expand_scopes,
            ) -> list[str]:
                t_pm = parsed_by_nid.get(target_cand)
                if t_pm is None:
                    return []
                t_defs = (t_pm.defined | set(t_pm.class_attrs)) - {
                    s for s in t_pm.defined if _is_passive_imported_symbol(s, _pm, t_pm)
                }
                pairs: list[str] = []
                for sc, c_syms in sorted(_pm.func_calls.items()):
                    matched_callees = set(c_syms & t_defs)
                    if explicit_sym and explicit_sym in c_syms:
                        matched_callees.add(explicit_sym)
                    if not matched_callees:
                        continue
                    for caller_k in _expand({sc}):  # type: ignore[operator]
                        for cal in sorted(matched_callees):
                            pairs.append(f"{caller_k}->{cal}")
                return pairs

            # 2. Manipulate -> Manipulate (module imports + called symbols)
            for imp in pm.imported_modules:
                for target_nid, note in import_resolver.targets(imp, pm):
                    add_edge(
                        nid,
                        target_nid,
                        "calls_helper",
                        pm.rel_path,
                        note,
                        symbol_links=_helper_links(target_nid),
                    )

            for called_sym in pm.symbol_calls:
                defs = symbol_to_defining_nodes.get(called_sym, [])
                if len(defs) == 1:
                    add_edge(
                        nid,
                        defs[0],
                        "calls_helper",
                        pm.rel_path,
                        f"Calls `{called_sym}()` across manipulation tier.",
                        symbol_links=_helper_links(defs[0], called_sym),
                    )
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
                        symbol_links=_helper_links(target_cand, called_sym),
                    )

            # 4. MANIP-001 & MANIP-002 checks
            if not rel_app.startswith("adapters/"):
                for const_name, lineno, sample in pm.policy_literals:
                    node.status = "policy_in_code"
                    subst_tbls = list(dict.fromkeys(subst_consts_in_mod.get(const_name, ())))
                    fb_tbls = list(dict.fromkeys(fb_consts_in_mod.get(const_name, ())))
                    usage_suffix = ""
                    if subst_tbls:
                        tbl_list = ", ".join(f"`{t}`" for t in subst_tbls)
                        usage_suffix = (
                            f" Overrides database policy column(s) on {tbl_list} in reader output."
                        )
                    elif fb_tbls:
                        tbl_list = ", ".join(f"`{t}`" for t in fb_tbls)
                        usage_suffix = (
                            f" Used as null/falsy fallback alongside {tbl_list} policy read."
                        )
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-001",
                            node_id=nid,
                            source_file=pm.rel_path,
                            line=lineno,
                            title=f"Hardcoded policy constant `{const_name}` ({sample})",
                            detail=(
                                f"{pm.rel_path}:{lineno} defines mutable domain policy "
                                f"`{const_name}` in Python code.{usage_suffix}"
                            ),
                            remediation=(
                                "Move policy threshold/vocabulary into PostgreSQL catalog truth "
                                "and read via snapshot."
                            ),
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
            if tid_pfcs := edge_consumptions_by_tid.get(tnode.id):
                merged_tpfc = merge_policy_consumptions(tid_pfcs)
                tnode.policy_field_consumption = merged_tpfc
                if merged_tpfc is not None:
                    pfc_tag = (
                        f"policy_field_consumption={merged_tpfc.state} "
                        f"(consumed={merged_tpfc.consumed_columns}, "
                        f"unconsumed_policy={merged_tpfc.unconsumed_policy_columns})"
                    )
                    tnode.verification_note = (
                        f"{tnode.verification_note} | {pfc_tag}"
                        if tnode.verification_note
                        else pfc_tag
                    )
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
        unwired_rels = [
            rel_app
            for rel_app, node in nodes_by_rel.items()
            if node.subkind in ("service", "solver")
            and not rel_app.endswith("main.py")
            and inbound_callers.get(node.id, 0) == 0
            and not rel_app.startswith("adapters/")
        ]
        mod_to_test_files: dict[str, list[str]] = {}
        if unwired_rels:
            pkg_rx = re.compile(rf"\b{re.escape(package_name)}(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
            seen_tpaths: set[Path] = set()
            for tdir in (repo_root / backend_subdir / "tests", repo_root / "tests"):
                if not tdir.is_dir():
                    continue
                for tf in sorted(tdir.rglob("*.py")):
                    if tf.is_symlink() or tf in seen_tpaths:
                        continue
                    seen_tpaths.add(tf)
                    try:
                        t_txt = tf.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    if package_name not in t_txt:
                        continue
                    t_rel = tf.relative_to(repo_root).as_posix()
                    for m_tok in set(pkg_rx.findall(t_txt)):
                        parts_t = m_tok.split(".")
                        for k in range(2, len(parts_t) + 1):
                            prefix_m = ".".join(parts_t[:k])
                            mod_to_test_files.setdefault(prefix_m, []).append(t_rel)

        passive_importers_by_mod: dict[str, list[tuple[str, int]]] = {}
        if unwired_rels:
            for s_rel_repo, s_mod_name, s_text in scanned_sources:
                for tgt_mod, imp_rel, imp_line in _collect_runtime_import_sites(
                    s_text, s_mod_name, s_rel_repo, package_name
                ):
                    passive_importers_by_mod.setdefault(tgt_mod, []).append((imp_rel, imp_line))

        for rel_app in unwired_rels:
            node = nodes_by_rel[rel_app]
            pm_u = parsed_modules.get(rel_app)
            if node.status == "clean":
                node.status = "unwired"
            dotted_rel = rel_app.removesuffix(".py").replace("/", ".")
            mod_full = pm_u.module_name if pm_u else f"{package_name}.{dotted_rel}"
            test_hits = mod_to_test_files.get(mod_full, [])
            title_suffix = (
                f" (referenced in {len(test_hits)} test file(s): `{test_hits[0]}`)"
                if test_hits
                else ""
            )
            test_note = (
                f" Referenced in {len(test_hits)} test file(s) (e.g. `{test_hits[0]}`) with 0 non-test callers."
                if test_hits
                else ""
            )
            passive_sites = sorted(
                {(imp_rel, ln) for imp_rel, ln in passive_importers_by_mod.get(mod_full, ()) if imp_rel != node.source_file},
                key=lambda item: (0 if item[0].endswith("__init__.py") else 1, item[0], item[1]),
            )
            reexport_note = ""
            remediation_text = "Check dynamic and external callers before wiring, refactoring, or removing the module."
            if passive_sites:
                ptr_list = ", ".join(f"`{p}:{ln}`" for p, ln in passive_sites[:4])
                more_ptrs = f" (+{len(passive_sites) - 4} more)" if len(passive_sites) > 4 else ""
                has_pkg_init = any(p.endswith("__init__.py") for p, _ in passive_sites)
                reexport_prefix = "Passively re-exported by" if has_pkg_init else "Passively imported by"
                target_noun = "the package" if has_pkg_init else "those module(s)"
                reexport_note = (
                    f"{reexport_prefix} {ptr_list}{more_ptrs}; deleting `{node.source_file}` "
                    f"without removing that re-export/import will raise `ImportError`/`ModuleNotFoundError` "
                    f"when importing {target_noun}."
                )
                node.verification_note = (
                    f"{node.verification_note} | {reexport_note}"
                    if node.verification_note
                    else reexport_note
                )
                remediation_text = (
                    f"Remove or update the passive re-export/import in {ptr_list}{more_ptrs} before "
                    f"deleting or moving `{node.source_file}` (otherwise importing {target_noun} raises "
                    "`ImportError`/`ModuleNotFoundError`), and check dynamic or external callers."
                )
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-003",
                    node_id=node.id,
                    source_file=node.source_file,
                    line=node.line,
                    title=f"Manipulator `{node.label}` has no discovered inbound callers{title_suffix}",
                    detail=(
                        f"No static route, CLI, task, or peer service reference to `{node.source_file}` "
                        f"was resolved.{test_note}"
                        f"{' ' + reexport_note if reexport_note else ''} "
                        "Dynamic registration and external entry points may be unobserved; "
                        "this is not proof that the module is unused or safe to delete."
                    ),
                    remediation=remediation_text,
                )
            )

        return ManipulatorExtractionResult(
            nodes=list(nodes_by_rel.values()),
            edges=edges,
            routes=routes,
            findings=findings,
        )
