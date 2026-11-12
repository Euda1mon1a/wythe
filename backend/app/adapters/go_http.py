"""Tier 2 Adapter: Go HTTP Routers (`net/http`, `chi`, `gin`, `echo`) + `sqlc` / `pgx` / `GORM`."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.treesitter_engine import blank_comments_cst, extract_go_routes_cst
from app.core.policy_context import get_active_policy_tokens
from app.schemas.atlas import AtlasEdge, AtlasNode

_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")
_GO_MOD_RE = re.compile(r"^\s*module\s+(?P<mod>\S+)", re.MULTILINE)
_GO_IMPORT_RE = re.compile(r'"(?P<imp>[^"\n]+)"')
_GROUP_PREFIX_RE = re.compile(
    r"""(?:(?P<var>[A-Za-z_]\w*)\s*:=\s*)?(?P<parent>[A-Za-z_]\w*)\.(?:Route|Group)\(\s*"(?P<prefix>/[^"]*)" """.strip()
)
_STD_MUX_RE = re.compile(
    r"""\b(?:HandleFunc|Handle)\(\s*"(?P<verb>GET|POST|PUT|PATCH|DELETE)\s+(?P<path>/[^"]*)" """.strip()
)
_ROUTER_VERB_RE = re.compile(
    r"""\b(?P<recv>[A-Za-z_]\w*)\.(?P<verb>Get|Post|Put|Patch|Delete|GET|POST|PUT|PATCH|DELETE)\(\s*"(?P<path>/[^"]*)" """.strip()
)
_METHOD_CALL_RE = re.compile(r"\b(?P<pkg>[A-Za-z_]\w*)\.(?P<fn>[A-Z][A-Za-z0-9_]*)\s*\(")
_RAW_SQL_WRITE_RE = re.compile(
    r"""\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+["`]?([A-Za-z_]\w*)["`]?""", re.IGNORECASE
)
_RAW_SQL_READ_RE = re.compile(r"""\b(?:FROM|JOIN)\s+["`]?([A-Za-z_]\w*)["`]?""", re.IGNORECASE)
_GO_POLICY_CONST_RE = re.compile(
    r"""^[ \t]*(?:const|var)\s+(?P<name>[A-Za-z][A-Za-z0-9_]*)\s*(?:[A-Za-z0-9_]+\s*)?=\s*(?P<val>[0-9]+(?:\.[0-9]+)?)\b""",
    re.MULTILINE,
)
_GO_CLOCK_RE = re.compile(r"\btime\.Now\s*\(\s*\)")
_POLICY_WORDS = ("capacity", "workload", "shiftcap", "dutyhour", "workhour", "hourlimit", "hourslimit", "callcap", "supervision", "penalty", "weeklymax")


def _strip_comments(source: str) -> str:
    cst_cleaned = blank_comments_cst(source, "go")
    if cst_cleaned is not None:
        return cst_cleaned
    return _COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), source)


def _norm_go_path(*parts: str) -> str:
    joined = "/" + "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    joined = re.sub(r":([A-Za-z_]\w*)", r"{\1}", joined)
    return joined or "/"


def _route_regex(full_path: str) -> str:
    norm = full_path.rstrip("/") or "/"
    escaped = re.sub(r"\{[^/{}]+\}", r"[^/?#]+", norm)
    return rf"^(?:/api/v\d+)?{escaped}/?$"


class GoHttpAdapter:
    """Extracts Go HTTP routes, package call graphs, sqlc/SQL table links, and MANIP rules."""

    name = "go-http"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        base_dir = (repo_root / backend_subdir).resolve() if backend_subdir not in ("", ".") else repo_root
        if not base_dir.is_dir():
            return ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])

        go_mod_name = ""
        for gm_cand in (base_dir / "go.mod", repo_root / "go.mod"):
            if gm_cand.is_file():
                mm = _GO_MOD_RE.search(gm_cand.read_text(encoding="utf-8", errors="replace"))
                if mm:
                    go_mod_name = mm.group("mod")
                    break

        pkg_files: dict[str, list[tuple[Path, str]]] = {}
        for gf in sorted(base_dir.rglob("*.go")):
            if gf.name.endswith("_test.go") or any(p in gf.parts for p in ("vendor", "node_modules", ".git")):
                continue
            try:
                txt = _strip_comments(gf.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                continue
            rel_pkg = gf.parent.relative_to(base_dir).as_posix()
            pkg_files.setdefault(rel_pkg, []).append((gf, txt))

        nodes_by_pkg: dict[str, AtlasNode] = {}
        for rel_pkg, flist in pkg_files.items():
            first_file = flist[0][0].relative_to(repo_root).as_posix()
            lower_pkg = rel_pkg.lower()
            is_route = any(k in lower_pkg for k in ("handler", "http", "api", "router", "server", "cmd"))
            is_cli = "cmd/" in lower_pkg and not any("Handle" in t or ".Get(" in t or ".GET(" in t for _, t in flist)
            subkind = "cli" if is_cli else "route" if is_route else "service"
            pkg_id_slug = "root" if rel_pkg == "." else rel_pkg.replace("/", ".")
            nid = f"m:{subkind}:{pkg_id_slug}"
            nodes_by_pkg[rel_pkg] = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind=subkind,  # type: ignore[arg-type]
                label="main" if rel_pkg == "." else rel_pkg,
                source_file=first_file,
                line=1,
                status="clean",
                role="mechanism",
                cluster=rel_pkg.split("/", 1)[0] if "/" in rel_pkg else "core",
                summary=f"Go package `{rel_pkg}` ({len(flist)} file(s)).",
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

        # Build global router mount table in case routes are registered in cmd/server/main.go
        handler_pkg_routes: dict[str, list[RouteDescriptor]] = {}
        for rel_pkg, flist in pkg_files.items():
            node = nodes_by_pkg[rel_pkg]
            for gf, txt in flist:
                rel_repo = gf.relative_to(repo_root).as_posix()
                # Imports -> calls_helper between internal Go packages
                imported_internal: dict[str, str] = {}
                for im in _GO_IMPORT_RE.finditer(txt):
                    imp = im.group("imp")
                    target_rel = ""
                    if go_mod_name and imp.startswith(go_mod_name + "/"):
                        sub = imp[len(go_mod_name) + 1 :]
                        if sub in nodes_by_pkg:
                            target_rel = sub
                        elif backend_subdir not in ("", ".") and sub.startswith(backend_subdir + "/"):
                            cand = sub[len(backend_subdir) + 1 :]
                            if cand in nodes_by_pkg:
                                target_rel = cand
                    if target_rel and target_rel != rel_pkg:
                        alias = target_rel.rsplit("/", 1)[-1]
                        imported_internal[alias] = target_rel
                        add_edge(node.id, nodes_by_pkg[target_rel].id, "calls_helper", rel_repo, f"Imports `{target_rel}`.")

                cst_go_routes = extract_go_routes_cst(txt, _norm_go_path)
                if cst_go_routes is not None:
                    for verb, full_p, lineno in cst_go_routes:
                        node.subkind = "route"
                        if verb not in node.http_methods:
                            node.http_methods.append(verb)
                        if full_p not in node.http_paths:
                            node.http_paths.append(full_p)
                        rdesc = RouteDescriptor(
                            node_id=node.id,
                            http_method=verb,
                            full_path=full_p,
                            path_regex=_route_regex(full_p),
                            source_file=rel_repo,
                            line=lineno,
                            called_symbols=frozenset(),
                            imported_modules=frozenset(),
                        )
                        routes.append(rdesc)
                        handler_pkg_routes.setdefault(rel_pkg, []).append(rdesc)
                else:
                    group_vars: dict[str, str] = {}
                    default_prefix = ""
                    for gm in _GROUP_PREFIX_RE.finditer(txt):
                        parent_pref = group_vars.get(gm.group("parent"), "")
                        pref = _norm_go_path(parent_pref, gm.group("prefix"))
                        if gm.group("var"):
                            group_vars[gm.group("var")] = pref
                        else:
                            default_prefix = pref

                    for sm in _STD_MUX_RE.finditer(txt):
                        verb = sm.group("verb").upper()
                        full_p = _norm_go_path(sm.group("path"))
                        lineno = txt.count("\n", 0, sm.start()) + 1
                        node.subkind = "route"
                        if verb not in node.http_methods:
                            node.http_methods.append(verb)
                        if full_p not in node.http_paths:
                            node.http_paths.append(full_p)
                        rdesc = RouteDescriptor(
                            node_id=node.id,
                            http_method=verb,
                            full_path=full_p,
                            path_regex=_route_regex(full_p),
                            source_file=rel_repo,
                            line=lineno,
                            called_symbols=frozenset(),
                            imported_modules=frozenset(),
                        )
                        routes.append(rdesc)
                        handler_pkg_routes.setdefault(rel_pkg, []).append(rdesc)

                    for rm in _ROUTER_VERB_RE.finditer(txt):
                        recv = rm.group("recv")
                        verb = rm.group("verb").upper()
                        pref = group_vars.get(recv, default_prefix)
                        full_p = _norm_go_path(pref, rm.group("path"))
                        lineno = txt.count("\n", 0, rm.start()) + 1
                        node.subkind = "route"
                        if verb not in node.http_methods:
                            node.http_methods.append(verb)
                        if full_p not in node.http_paths:
                            node.http_paths.append(full_p)
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

                # sqlc query method calls + raw SQL reads/writes
                reads_tids: set[str] = set()
                writes_tids: set[str] = set()
                for mc in _METHOD_CALL_RE.finditer(txt):
                    fn_name = mc.group("fn")
                    if f"sqlc:write:{fn_name}" in truth.table_symbol_map:
                        writes_tids.add(truth.table_symbol_map[f"sqlc:write:{fn_name}"])
                    elif f"sqlc:read:{fn_name}" in truth.table_symbol_map:
                        reads_tids.add(truth.table_symbol_map[f"sqlc:read:{fn_name}"])
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
                    if node.subkind == "route" and len(pkg_files) > 1 and any(n.subkind == "service" for n in nodes_by_pkg.values()):
                        node.status = "gray_zone"
                        findings.append(
                            RawCandidateFinding(
                                rule_code="TRUTH-003",
                                node_id=node.id,
                                source_file=rel_repo,
                                line=1,
                                title=f"Go HTTP handler `{node.label}` mutates `{tid.removeprefix('t:')}` directly",
                                detail=f"`{rel_repo}` executes write queries directly inside the HTTP handler package.",
                                remediation="Route mutations through a dedicated service/store write boundary.",
                            )
                        )

                go_policy_words = tuple(
                    t.replace("_", "").lower() for t in get_active_policy_tokens()
                )
                for cm in _GO_POLICY_CONST_RE.finditer(txt):
                    cname = cm.group("name")
                    normalized = cname.replace("_", "").lower()
                    if any(w in normalized for w in go_policy_words):
                        lineno = txt.count("\n", 0, cm.start()) + 1
                        node.status = "policy_in_code"
                        findings.append(
                            RawCandidateFinding(
                                rule_code="MANIP-001",
                                node_id=node.id,
                                source_file=rel_repo,
                                line=lineno,
                                title=f"Hardcoded policy constant `{cname}` ({cm.group('val')})",
                                detail=f"`{rel_repo}:{lineno}` embeds domain threshold `{cname}` in Go code.",
                                remediation="Move mutable policy constants into database truth tables.",
                            )
                        )
                if "clock" not in rel_repo.lower():
                    for clkm in _GO_CLOCK_RE.finditer(txt):
                        lineno = txt.count("\n", 0, clkm.start()) + 1
                        if node.status == "clean":
                            node.status = "gray_zone"
                        findings.append(
                            RawCandidateFinding(
                                rule_code="MANIP-002",
                                node_id=node.id,
                                source_file=rel_repo,
                                line=lineno,
                                title="Direct host `time.Now()` call",
                                detail=f"`{rel_repo}:{lineno}` calls `time.Now()` directly instead of injected clock.",
                                remediation="Read time from an injected Clock interface or database clock.",
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
                        detail=f"`{tnode.label}` has no Go readers.",
                        remediation="Wire active sqlc/SQL consumers or retire unused schema.",
                    )
                )

        inbound: dict[str, int] = {}
        for e in edges:
            if e.kind == "calls_helper":
                inbound[e.target_id] = inbound.get(e.target_id, 0) + 1
        for node in nodes_by_pkg.values():
            if node.subkind == "service" and inbound.get(node.id, 0) == 0:
                if node.status == "clean":
                    node.status = "unwired"
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-003",
                        node_id=node.id,
                        source_file=node.source_file,
                        line=1,
                        title=f"Go package `{node.label}` has no inbound callers",
                        detail=f"`{node.source_file}` is not imported by any handler, cmd, or peer package.",
                        remediation="Wire package into active handlers or remove unused package.",
                    )
                )

        return ManipulatorExtractionResult(
            nodes=list(nodes_by_pkg.values()),
            edges=edges,
            routes=routes,
            findings=findings,
        )
