"""Tier 2 Adapter: TypeScript / Node Backend Manipulation (`route.ts`, Express, Hono, NestJS)."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.treesitter_engine import (
    blank_comments_cst,
    extract_ts_backend_routes_cst,
    extract_ts_imports_cst,
)
from app.core.policy_context import get_active_policy_tokens
from app.schemas.atlas import AtlasEdge, AtlasNode

_COMMENT_STRIP_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")
_IMPORT_SPEC_RE = re.compile(r"""(?:import|export)\s+[\s\S]*?from\s+['"](?P<spec>[^'"]+)['"]""")
_NEXT_HANDLER_EXPORT_RE = re.compile(
    r"""export\s+(?:async\s+)?(?:function|const)\s+(?P<verb>GET|POST|PUT|PATCH|DELETE)\b"""
)
_EXPRESS_MOUNT_RE = re.compile(
    r"""\b(?:app|server|api)\.(?:use|route)\(\s*['"](?P<prefix>/[^'"]*)['"]\s*,\s*(?P<target>[A-Za-z_]\w*)"""
)
_EXPRESS_ROUTE_RE = re.compile(
    r"""\b(?P<recv>[A-Za-z_]\w*)\.(?P<verb>get|post|put|patch|delete)\(\s*['"](?P<path>/[^'"]*)['"]"""
)
_NEST_CTRL_RE = re.compile(r"""@Controller\(\s*(?:['"](?P<prefix>[^'"]*)['"])?\s*\)""")
_NEST_VERB_RE = re.compile(
    r"""@(?P<verb>Get|Post|Put|Patch|Delete)\(\s*(?:['"](?P<subpath>[^'"]*)['"])?\s*\)"""
)
_PRISMA_OP_RE = re.compile(
    r"""(?:\bthis\.)?\b(?:prisma|tx)\.(?P<model>[A-Za-z_]\w*)\.(?P<op>findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow|count|aggregate|groupBy|create|createMany|update|updateMany|upsert|delete|deleteMany)\b"""
)
_DRIZZLE_READ_RE = re.compile(r"""\.from\(\s*(?P<sym>[A-Za-z_]\w*)\s*\)|\bquery\.(?P<qsym>[A-Za-z_]\w*)\.find""")
_DRIZZLE_WRITE_RE = re.compile(r"""\b(?:db|tx)\.(?:insert|update|delete)\(\s*(?P<sym>[A-Za-z_]\w*)\s*\)""")
_RAW_SQL_READ_RE = re.compile(r"""\b(?:SELECT|FROM|JOIN)\s+["`]?([A-Za-z_]\w*)["`]?""", re.IGNORECASE)
_RAW_SQL_WRITE_RE = re.compile(
    r"""\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+["`]?([A-Za-z_]\w*)["`]?""", re.IGNORECASE
)
_TS_POLICY_RE = re.compile(
    r"""^[ \t]*(?:export\s+)?const\s+(?P<name>[A-Z][A-Z0-9_]{3,})\s*(?::[^=]+)?=\s*(?P<val>[0-9]+(?:\.[0-9]+)?)\b""",
    re.MULTILINE,
)
_TS_CLOCK_RE = re.compile(r"""\b(?:new\s+Date\s*\(\s*\)|Date\.now\s*\(\s*\))""")
_POLICY_WORDS = ("CAPACITY", "WORKLOAD", "SHIFT_CAP", "DUTY_HOUR", "WORK_HOUR", "HOUR_LIMIT", "HOURS_LIMIT", "CALL_CAP", "SUPERVISION", "PENALTY", "WEEKLY_MAX")
_CLOCK_ALLOW = ("clock.ts", "time.ts", "date-utils.ts", "programTime.ts")


def _strip_preserve_lines(source: str) -> str:
    cst_cleaned = blank_comments_cst(source, "ts")
    if cst_cleaned is not None:
        return cst_cleaned
    return _COMMENT_STRIP_RE.sub(lambda m: "\n" * m.group(0).count("\n"), source)


def _norm_colon_params(path: str) -> str:
    cleaned = "/" + "/".join(p for p in path.strip().split("/") if p)
    cleaned = re.sub(r":([A-Za-z_]\w*)", r"{\1}", cleaned)
    cleaned = re.sub(r"\[\.\.\.([A-Za-z_]\w*)\]", r"{\1}", cleaned)
    cleaned = re.sub(r"\[([A-Za-z_]\w*)\]", r"{\1}", cleaned)
    return cleaned or "/"


def _route_regex(full_path: str) -> str:
    norm = full_path.rstrip("/") or "/"
    escaped = "" if norm == "/" else re.sub(r"\{[^/{}]+\}", r"[^/?#]+", norm)
    return rf"^(?:/api(?:/v\d+)?)?{escaped}/?$" if escaped else r"^(?:/api(?:/v\d+)?)?/?$"


def _sveltekit_server_route_path(rel_base: str) -> str:
    idx = rel_base.find("routes/")
    sub = rel_base[idx + len("routes/") :] if idx >= 0 else rel_base
    segs = [
        p
        for p in Path(sub).parts[:-1]
        if not (p.startswith("(") and p.endswith(")"))
    ]
    return _norm_colon_params("/" + "/".join(segs))


def _is_backend_ts_candidate(rel_base: str, fullstack_root: bool) -> bool:
    parts = Path(rel_base).parts
    if any(p in parts for p in ("node_modules", ".next", ".svelte-kit", "dist", "build", "tests", "test", "__tests__", "types")):
        return False
    if rel_base.endswith((".d.ts", ".test.ts", ".spec.ts", ".e2e-spec.ts", ".config.ts", ".module.ts")):
        return False
    if not fullstack_root:
        return rel_base.endswith(".ts")
    if rel_base.endswith(("/+server.ts", "/+page.server.ts", "/+layout.server.ts")):
        return True
    # In a shared root (e.g. Next.js + Prisma/Drizzle), select server/API/service tiers only
    if "api" in parts and (rel_base.endswith("/route.ts") or "pages/api/" in rel_base):
        return True
    return any(
        seg in parts
        for seg in ("server", "services", "repositories", "controllers", "routes", "actions")
    ) and rel_base.endswith(".ts")


class TypeScriptNodeAdapter:
    """Extracts Next.js route.ts, Express/Hono, and NestJS routes + Prisma/Drizzle/SQL links."""

    name = "typescript-node"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        fullstack_root = backend_subdir in ("", ".")
        base_dir = repo_root if fullstack_root else (repo_root / backend_subdir)
        if not base_dir.is_dir():
            return ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])

        files: list[Path] = [
            f
            for f in sorted(base_dir.rglob("*.ts"))
            if _is_backend_ts_candidate(f.relative_to(base_dir).as_posix(), fullstack_root)
        ]

        mount_map: dict[str, str] = {}
        cleaned_texts: dict[Path, str] = {}
        for f in files:
            try:
                txt = _strip_preserve_lines(f.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                continue
            cleaned_texts[f] = txt
            for mm in _EXPRESS_MOUNT_RE.finditer(txt):
                mount_map[mm.group("target").lower()] = mm.group("prefix")

        nodes_by_path: dict[Path, AtlasNode] = {}
        for f in cleaned_texts:
            rel_repo = f.relative_to(repo_root).as_posix()
            rel_b = f.relative_to(base_dir).as_posix()
            is_route = (
                rel_b.endswith(("/route.ts", "/+server.ts", "/+page.server.ts", ".controller.ts"))
                or "routes" in Path(rel_b).parts
                or "controllers" in Path(rel_b).parts
                or "pages/api" in rel_b
                or f.stem in ("server", "app", "index")
            )
            subkind = "route" if is_route else "service"
            stem_id = rel_b.removesuffix(".ts").replace("/", ".")
            nid = f"m:{subkind}:{stem_id}"
            nodes_by_path[f] = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind=subkind,  # type: ignore[arg-type]
                label=Path(rel_b).with_suffix("").as_posix(),
                source_file=rel_repo,
                line=1,
                status="clean",
                role="mechanism",
                cluster="api" if subkind == "route" else "services",
                summary=f"TypeScript backend {subkind} `{rel_repo}`.",
            )

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        routes: list[RouteDescriptor] = []
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

        for f, txt in cleaned_texts.items():
            node = nodes_by_path[f]
            rel_repo = node.source_file
            rel_b = f.relative_to(base_dir).as_posix()

            # 1. Cross-module runtime imports -> calls_helper (type-only imports excluded under CST)
            cst_imps = extract_ts_imports_cst(txt, is_tsx=False)
            runtime_specs = (
                cst_imps[0]
                if cst_imps is not None
                else [imp.group("spec") for imp in _IMPORT_SPEC_RE.finditer(txt)]
            )
            for spec in runtime_specs:
                cand: Path | None = None
                if spec.startswith("."):
                    cand = (f.parent / spec).resolve()
                elif spec.startswith("@/"):
                    src_dir = base_dir / "src" if (base_dir / "src").is_dir() else base_dir
                    cand = (src_dir / spec[2:]).resolve()
                elif spec.startswith("$lib/"):
                    src_dir = base_dir / "src" if (base_dir / "src").is_dir() else base_dir
                    lib_dir = src_dir / "lib" if (src_dir / "lib").is_dir() else src_dir
                    cand = (lib_dir / spec[len("$lib/") :]).resolve()
                if cand is not None:
                    for probe in (cand, Path(f"{cand}.ts"), cand / "index.ts"):
                        if probe in nodes_by_path and probe != f:
                            add_edge(node.id, nodes_by_path[probe].id, "calls_helper", rel_repo, f"Imports `{nodes_by_path[probe].label}`.")

            # 2. Synthesize HTTP routes
            file_methods: list[str] = []
            file_paths: list[str] = []
            if rel_b.endswith("/+server.ts"):
                full_p = _sveltekit_server_route_path(rel_b)
                for hm in _NEXT_HANDLER_EXPORT_RE.finditer(txt):
                    verb = hm.group("verb")
                    lineno = txt.count("\n", 0, hm.start()) + 1
                    file_methods.append(verb)
                    if full_p not in file_paths:
                        file_paths.append(full_p)
                    routes.append(
                        RouteDescriptor(
                            node_id=node.id,
                            http_method=verb,
                            full_path=full_p,
                            path_regex=_route_regex(full_p),
                            source_file=rel_repo,
                            line=lineno,
                            called_symbols=frozenset(),
                            imported_modules=frozenset(),
                        )
                    )
            elif rel_b.endswith("/+page.server.ts"):
                full_p = _sveltekit_server_route_path(rel_b)
                for verb, marker in (("GET", "load"), ("POST", "actions")):
                    if f"const {marker}" in txt or f"function {marker}" in txt:
                        file_methods.append(verb)
                        if full_p not in file_paths:
                            file_paths.append(full_p)
                        routes.append(
                            RouteDescriptor(
                                node_id=node.id,
                                http_method=verb,
                                full_path=full_p,
                                path_regex=_route_regex(full_p),
                                source_file=rel_repo,
                                line=1,
                                called_symbols=frozenset(),
                                imported_modules=frozenset(),
                            )
                        )
            elif rel_b.endswith("/route.ts") and "/api/" in f"/{rel_b}":
                idx = rel_b.find("api/")
                raw_p = "/" + rel_b[idx:].removesuffix("/route.ts")
                full_p = _norm_colon_params(raw_p)
                for hm in _NEXT_HANDLER_EXPORT_RE.finditer(txt):
                    verb = hm.group("verb")
                    lineno = txt.count("\n", 0, hm.start()) + 1
                    file_methods.append(verb)
                    if full_p not in file_paths:
                        file_paths.append(full_p)
                    routes.append(
                        RouteDescriptor(
                            node_id=node.id,
                            http_method=verb,
                            full_path=full_p,
                            path_regex=_route_regex(full_p),
                            source_file=rel_repo,
                            line=lineno,
                            called_symbols=frozenset(),
                            imported_modules=frozenset(),
                        )
                    )

            mount_prefix = ""
            for mkey, mpref in mount_map.items():
                if f.stem.lower() in mkey or mkey.startswith(f.stem.lower()):
                    mount_prefix = mpref
                    break

            cst_routes = extract_ts_backend_routes_cst(txt, mount_prefix=mount_prefix)
            raw_express_routes = (
                cst_routes
                if cst_routes is not None
                else [
                    (
                        em.group("verb").upper(),
                        f"{mount_prefix}/{em.group('path')}",
                        txt.count("\n", 0, em.start()) + 1,
                    )
                    for em in _EXPRESS_ROUTE_RE.finditer(txt)
                ]
            )
            for verb, raw_ep, lineno in raw_express_routes:
                full_p = _norm_colon_params(raw_ep)
                node.subkind = "route"
                file_methods.append(verb)
                if full_p not in file_paths:
                    file_paths.append(full_p)
                routes.append(
                    RouteDescriptor(
                        node_id=node.id,
                        http_method=verb,
                        full_path=full_p,
                        path_regex=_route_regex(full_p),
                        source_file=rel_repo,
                        line=lineno,
                        called_symbols=frozenset(),
                        imported_modules=frozenset(),
                    )
                )

            ctrl_m = _NEST_CTRL_RE.search(txt)
            if ctrl_m:
                ctrl_pref = ctrl_m.group("prefix") or ""
                node.subkind = "route"
                for nm in _NEST_VERB_RE.finditer(txt):
                    verb = nm.group("verb").upper()
                    sub_p = nm.group("subpath") or ""
                    full_p = _norm_colon_params(f"/{ctrl_pref}/{sub_p}")
                    lineno = txt.count("\n", 0, nm.start()) + 1
                    file_methods.append(verb)
                    if full_p not in file_paths:
                        file_paths.append(full_p)
                    routes.append(
                        RouteDescriptor(
                            node_id=node.id,
                            http_method=verb,
                            full_path=full_p,
                            path_regex=_route_regex(full_p),
                            source_file=rel_repo,
                            line=lineno,
                            called_symbols=frozenset(),
                            imported_modules=frozenset(),
                        )
                    )
            node.http_methods = sorted(set(file_methods))
            node.http_paths = file_paths[:20]

            # 3. Extract Prisma, Drizzle, and SQL table reads vs writes
            reads_tids: set[str] = set()
            writes_tids: set[str] = set()
            for pm in _PRISMA_OP_RE.finditer(txt):
                tid = truth.table_symbol_map.get(pm.group("model")) or truth.table_symbol_map.get(f"prisma.{pm.group('model')}")
                if tid:
                    if pm.group("op").startswith(("find", "count", "aggregate", "group")):
                        reads_tids.add(tid)
                    else:
                        writes_tids.add(tid)
            for dm in _DRIZZLE_READ_RE.finditer(txt):
                sym = dm.group("sym") or dm.group("qsym") or ""
                if sym in truth.table_symbol_map:
                    reads_tids.add(truth.table_symbol_map[sym])
            for dw in _DRIZZLE_WRITE_RE.finditer(txt):
                sym = dw.group("sym")
                if sym in truth.table_symbol_map:
                    writes_tids.add(truth.table_symbol_map[sym])
            for sw in _RAW_SQL_WRITE_RE.finditer(txt):
                tk = sw.group(1).lower()
                if tk in truth.table_symbol_map:
                    writes_tids.add(truth.table_symbol_map[tk])
            for sr in _RAW_SQL_READ_RE.finditer(txt):
                tk = sr.group(1).lower()
                if tk in truth.table_symbol_map and truth.table_symbol_map[tk] not in writes_tids:
                    reads_tids.add(truth.table_symbol_map[tk])

            for tid in sorted(reads_tids):
                table_readers.setdefault(tid, set()).add(node.id)
                add_edge(node.id, tid, "reads_truth", rel_repo, f"Reads `{tid}`.")
            for tid in sorted(writes_tids):
                table_writers.setdefault(tid, set()).add(node.id)
                add_edge(node.id, tid, "writes_truth", rel_repo, f"Writes `{tid}`.")
                if node.subkind == "route":
                    node.status = "gray_zone"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-003",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=1,
                            title=f"Route handler `{node.label}` mutates `{tid.removeprefix('t:')}` directly",
                            detail=f"`{rel_repo}` performs direct database mutations inside an HTTP route handler.",
                            remediation="Delegate mutations to an explicit transactional service or SQL write-lane function.",
                        )
                    )

            # 4. MANIP-001 & MANIP-002
            active_tokens = get_active_policy_tokens()
            for cm in _TS_POLICY_RE.finditer(txt):
                cname = cm.group("name")
                if any(w in cname for w in active_tokens):
                    lineno = txt.count("\n", 0, cm.start()) + 1
                    node.status = "policy_in_code"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-001",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Hardcoded policy constant `{cname}` ({cm.group('val')})",
                            detail=f"`{rel_repo}:{lineno}` hardcodes domain policy `{cname}` in TypeScript.",
                            remediation="Store mutable policy thresholds in database truth tables.",
                        )
                    )
            if not rel_repo.endswith(_CLOCK_ALLOW):
                for clkm in _TS_CLOCK_RE.finditer(txt):
                    lineno = txt.count("\n", 0, clkm.start()) + 1
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-002",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Direct host clock call `{clkm.group(0)}`",
                            detail=f"`{rel_repo}:{lineno}` reads host time directly instead of a shared clock helper.",
                            remediation="Inject or import time from a centralized clock module.",
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
                        detail=f"`{tnode.label}` has no backend readers.",
                        remediation="Wire consumers to read this table or retire unused schema.",
                    )
                )

        inbound: dict[str, int] = {}
        for e in edges:
            if e.kind == "calls_helper":
                inbound[e.target_id] = inbound.get(e.target_id, 0) + 1
        for node in nodes_by_path.values():
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
                        detail=f"`{node.source_file}` is not imported by any route or peer service.",
                        remediation="Connect the service to a route handler or remove dormant code.",
                    )
                )

        return ManipulatorExtractionResult(
            nodes=list(nodes_by_path.values()),
            edges=edges,
            routes=routes,
            findings=findings,
        )
