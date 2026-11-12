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
                continue
            if rel_app in ("core/config.py", "db/base.py", "db/session.py"):
                continue
            parsed_modules[rel_app] = parsed

        router_mounts = _resolve_router_mounts(all_parsed)

        nodes_by_rel: dict[str, AtlasNode] = {}
        mod_name_to_node_id: dict[str, str] = {}
        symbol_to_defining_nodes: dict[str, list[str]] = {}

        for rel_app, pm in parsed_modules.items():
            subkind, cluster = _classify_manipulator(rel_app)
            stem_slug = rel_app.removesuffix(".py").replace("/", ".")
            node_id = f"m:{subkind}:{stem_slug}"
            mod_name_to_node_id[pm.module_name] = node_id
            for sym in pm.defined:
                if len(sym) > 3 and not sym.startswith("_"):
                    symbol_to_defining_nodes.setdefault(sym, []).append(node_id)

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

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        routes: list[RouteDescriptor] = []
        findings: list[RawCandidateFinding] = []
        table_readers: dict[str, set[str]] = {}
        table_writers: dict[str, set[str]] = {}

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
            matched_writes: set[str] = set()
            for sym in pm.reads | pm.sql_reads:
                bare = sym.split(".", 1)[1] if sym.startswith("public.") else sym
                tid = truth.table_symbol_map.get(sym) or truth.table_symbol_map.get(bare)
                if tid:
                    matched_reads.add(tid)
            for sym in pm.writes | pm.sql_writes:
                bare = sym.split(".", 1)[1] if sym.startswith("public.") else sym
                tid = truth.table_symbol_map.get(sym) or truth.table_symbol_map.get(bare)
                if tid:
                    matched_writes.add(tid)

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
                            line=1,
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
                target_nid = mod_name_to_node_id.get(imp)
                if target_nid is None and "." in imp:
                    parent_mod, _, imported_sym = imp.rpartition(".")
                    cand_nid = mod_name_to_node_id.get(parent_mod)
                    if cand_nid and imported_sym in pm.called | pm.reads:
                        target_nid = cand_nid
                if target_nid:
                    add_edge(nid, target_nid, "calls_helper", pm.rel_path, f"Imports and invokes `{imp}`.")

            for called_sym in pm.symbol_calls:
                defs = symbol_to_defining_nodes.get(called_sym, [])
                if len(defs) == 1:
                    add_edge(nid, defs[0], "calls_helper", pm.rel_path, f"Calls `{called_sym}()` across manipulation tier.")

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

        # 5. Update truth read/write counts & TRUTH-001 (orphaned input tables)
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

        # 6. MANIP-003 (inert service/solver mechanisms with zero inbound callers)
        inbound_callers: dict[str, int] = {}
        for edge in edges:
            if edge.kind == "calls_helper":
                inbound_callers[edge.target_id] = inbound_callers.get(edge.target_id, 0) + 1
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
