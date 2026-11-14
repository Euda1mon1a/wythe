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
)
from app.adapters.ts_kysely import extract_kysely_table_ops
from app.adapters.ts_trpc import collect_trpc_lineage, derive_next_trpc_mount_prefix
from app.adapters.ts_workspace import (
    WorkspaceResolver,
    executable_ts_text,
    extract_ts_dynamic_imports,
    extract_ts_import_bindings,
    resolve_reexport_targets,
    resolve_string_expr,
    verified_dynamic_import,
    verified_import_bindings,
)
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasEdge, AtlasNode

_COMMENT_STRIP_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")
_NEXT_HANDLER_EXPORT_RE = re.compile(
    r"""export\s+(?:async\s+)?(?:function|const)\s+(?P<verb>GET|POST|PUT|PATCH|DELETE)\b"""
)
_EXPRESS_MOUNT_RE = re.compile(
    r"""\b(?:app|server|api)\.(?:use|route)\(\s*['"](?P<prefix>/[^'"]*)['"]\s*,\s*(?P<target>[A-Za-z_]\w*)"""
)
_EXPRESS_ROUTE_RE = re.compile(
    r"""\b(?P<recv>[A-Za-z_]\w*)\.(?P<verb>get|post|put|patch|delete)\(\s*['"](?P<path>/[^'"]*)['"]"""
)
_NEST_CTRL_RE = re.compile(r"""@Controller\(\s*(?P<arg>[^)]*?)\s*\)""")
_NEST_VERB_RE = re.compile(
    r"""@(?P<verb>Get|Post|Put|Patch|Delete)\(\s*(?:['"](?P<subpath>[^'"]*)['"])?\s*\)"""
)
_PRISMA_OP_RE = re.compile(
    r"""(?:\bthis\.)?\b(?:prisma(?:\.client)?|tx|db)\.(?P<model>[A-Za-z_]\w*)\.(?P<op>findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow|count|aggregate|groupBy|create|createMany|update|updateMany|upsert|delete|deleteMany)\b"""
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
_CLASS_EXTENDS_RE = re.compile(r"""\bclass\s+[A-Za-z_$][\w$]*\s+extends\s+(?P<base>[A-Za-z_$][\w$]*)""")
_POLICY_WORDS = ("CAPACITY", "WORKLOAD", "SHIFT_CAP", "DUTY_HOUR", "WORK_HOUR", "HOUR_LIMIT", "HOURS_LIMIT", "CALL_CAP", "SUPERVISION", "PENALTY", "WEEKLY_MAX")
_CLOCK_ALLOW = ("clock.ts", "time.ts", "date-utils.ts", "programTime.ts")
_WS_SKIP_PARTS = frozenset(
    {
        "node_modules", ".next", ".svelte-kit", "dist", "build", "out", "tests", "test",
        "__tests__", "__mocks__", "mocks", "fixtures", "e2e", "playwright", "stories",
        "components", "views", "hooks", "styles", "embeds", "coss-ui", "ui", "emails", "types",
    }
)
_WS_SKIP_PKGS = frozenset(
    {"prisma", "types", "i18n", "dayjs", "config", "tsconfig", "ui", "coss-ui", "emails", "embeds", "sms", "testing", "app-store", "app-store-cli"}
)
_SERVER_TSX_MARKER_RE = re.compile(
    r"""\b(?:initTRPC|createTRPCRouter|createNextApiHandler|fetchRequestHandler|publicProcedure|authedProcedure)\b|(?:\brouter\s*\(\s*\{)"""
)


def _is_server_tsx_candidate(fpath: Path, raw_text: str, rel_repo: str) -> bool:
    if fpath.suffix != ".tsx":
        return fpath.suffix in (".ts", ".mts")
    head = raw_text[:200].lstrip()
    if head.startswith(('"use client"', "'use client'")):
        return False
    parts = set(Path(rel_repo).parts)
    if parts & {"server", "router", "routers", "trpc", "api", "routes"}:
        return True
    return bool(_SERVER_TSX_MARKER_RE.search(raw_text))


def _is_external_ws_module_allowed(fpath: Path, repo_root: Path) -> bool:
    try:
        rel = fpath.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return False
    parts = Path(rel).parts
    if any(p in _WS_SKIP_PARTS for p in parts[:-1]):
        return False
    if len(parts) >= 2 and parts[0] == "packages" and parts[1] in _WS_SKIP_PKGS:
        return False
    name = fpath.name
    if any(tag in name for tag in (".test.", ".spec.", ".stories.", ".e2e-spec.", ".config.")) or name.endswith(".d.ts"):
        return False
    return fpath.suffix in (".ts", ".mts", ".tsx")


def _discover_workspace_backend_files(
    repo_root: Path,
    base_dir: Path,
    initial_files: list[Path],
    resolver: WorkspaceResolver,
) -> list[Path]:
    """Collect multi-root API handlers (`pages/api`, `app/api`) + imported workspace server modules."""
    from collections import deque

    root_res = repo_root.resolve()
    base_res = base_dir.resolve()
    discovered: list[Path] = []
    seen: set[Path] = set()
    ext_queue: deque[tuple[Path, int]] = deque()
    seed_seen: set[Path] = set()

    for f in initial_files:
        rf = f.resolve()
        if rf not in seen:
            seen.add(rf)
            discovered.append(rf)
            ext_queue.append((rf, 0))
            seed_seen.add(rf)

    # Discover manifest-backed web app API handler dirs and server tRPC root routers
    app_roots: list[Path] = [root_res]
    for pat in ("apps/*", "packages/*"):
        for d in sorted(root_res.glob(pat)):
            if d.is_dir() and "node_modules" not in d.parts and (d / "package.json").is_file():
                app_roots.append(d.resolve())
    for extra in ("web", "frontend"):
        d = root_res / extra
        if d.is_dir() and (d / "package.json").is_file():
            app_roots.append(d.resolve())

    for aroot in app_roots:
        for api_sub in ("pages/api", "src/pages/api", "app/api", "src/app/api"):
            api_dir = aroot / api_sub
            if not api_dir.is_dir():
                continue
            for f in sorted(api_dir.rglob("*.ts")):
                rf = f.resolve()
                if rf not in seed_seen and _is_external_ws_module_allowed(rf, root_res):
                    seed_seen.add(rf)
                    ext_queue.append((rf, 0))
                    if rf not in seen:
                        seen.add(rf)
                        discovered.append(rf)
        # Seed root tRPC router manifests (`routers/_app.{ts,tsx}`) for canonical appRouter paths
        for app_pat in ("server/routers/_app.ts", "server/routers/_app.tsx", "src/server/routers/_app.ts", "src/server/routers/_app.tsx", "routers/_app.ts", "routers/_app.tsx"):
            cand = aroot / app_pat
            if cand.is_file():
                rf = cand.resolve()
                if rf not in seed_seen:
                    seed_seen.add(rf)
                    ext_queue.append((rf, 0))
                    if rf not in seen:
                        seen.add(rf)
                        discovered.append(rf)

    ext_added = 0
    _reexp_spec_rx = re.compile(r"""from\s+['"](?P<spec>[^'"]+)['"]""")
    while ext_queue and ext_added < 650:
        cur, depth = ext_queue.popleft()
        if depth >= 6:
            continue
        try:
            raw_txt = cur.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        is_tsx = cur.suffix == ".tsx"
        clean_txt = _strip_preserve_lines(raw_txt, is_tsx=is_tsx)
        specs: list[str] = [imp.spec for imp in extract_ts_import_bindings(clean_txt, is_tsx=is_tsx)]
        exec_txt, _ = executable_ts_text(clean_txt, is_tsx=is_tsx)
        for site in extract_ts_dynamic_imports(exec_txt, is_tsx=is_tsx):
            if site.spec:
                specs.append(site.spec)
        if cur.name in ("index.ts", "index.tsx", "_router.ts", "_router.tsx", "_app.ts", "_app.tsx"):
            for rm in _reexp_spec_rx.finditer(clean_txt):
                specs.append(rm.group("spec"))

        for sp in specs:
            if not sp:
                continue
            tgt = resolver.resolve_import(sp, cur)
            if tgt is None:
                continue
            rtgt = tgt.resolve()
            if rtgt in seen:
                continue
            if rtgt.is_relative_to(base_res) and rtgt.suffix != ".tsx":
                continue
            if not _is_external_ws_module_allowed(rtgt, root_res):
                continue
            if rtgt.suffix == ".tsx":
                try:
                    t_raw = rtgt.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeError):
                    continue
                if not _is_server_tsx_candidate(rtgt, t_raw, rtgt.relative_to(root_res).as_posix()):
                    continue
            seen.add(rtgt)
            discovered.append(rtgt)
            ext_added += 1
            ext_queue.append((rtgt, depth + 1))

    return discovered


def _strip_preserve_lines(source: str, *, is_tsx: bool = False) -> str:
    cst_cleaned = blank_comments_cst(source, "tsx" if is_tsx else "ts")
    if cst_cleaned is not None:
        return cst_cleaned
    return _COMMENT_STRIP_RE.sub(lambda m: "\n" * m.group(0).count("\n"), source)


def _norm_colon_params(path: str) -> str:
    segs = [
        p
        for p in path.strip().split("/")
        if p and not (p.startswith("(") and p.endswith(")"))
    ]
    cleaned = "/" + "/".join(segs)
    cleaned = re.sub(r":([A-Za-z_]\w*)", r"{\1}", cleaned)
    cleaned = re.sub(r"\[\[\.\.\.([A-Za-z_]\w*)\]\]", r"{\1?*}", cleaned)
    cleaned = re.sub(r"\[\.\.\.([A-Za-z_]\w*)\]", r"{\1+}", cleaned)
    cleaned = re.sub(r"\[([A-Za-z_]\w*)\]", r"{\1}", cleaned)
    return cleaned or "/"


def _route_regex(full_path: str) -> str:
    norm = re.sub(r"^/api(?:/v\d+)?(?=/|$)", "", full_path.rstrip("/")) or "/"
    if norm == "/":
        return r"^(?:/api(?:/v\d+)?)?/?$"
    escaped = re.sub(r"/\{[A-Za-z_]\w*\?\*\}", r"(?:/[^?#]+)?", norm)
    escaped = re.sub(r"/\{[A-Za-z_]\w*\+\}", r"/[^?#]+", escaped)
    escaped = re.sub(r"\{[^/{}]+\}", r"[^/?#]+", escaped)
    return rf"^(?:/api(?:/v\d+)?)?{escaped}/?$"


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
        for seg in (
            "server",
            "services",
            "repositories",
            "controllers",
            "routes",
            "actions",
            "queries",
            "repos",
            "processors",
            "queues",
            "workers",
            "tasks",
            "jobs",
            "db",
            "models",
            "prisma",
            "drizzle",
        )
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
            return ManipulatorExtractionResult(
                nodes=[],
                edges=[],
                routes=[],
                findings=[],
                notes=[
                    f"Backend directory '{backend_subdir}' was not found; Node backend coverage is absent."
                ],
                coverage_complete=False,
            )

        resolver = WorkspaceResolver.build(repo_root, extra_roots=(base_dir,))
        initial_files: list[Path] = [
            f
            for f in sorted(base_dir.rglob("*.ts"))
            if _is_backend_ts_candidate(f.relative_to(base_dir).as_posix(), fullstack_root)
        ]
        files = _discover_workspace_backend_files(repo_root, base_dir, initial_files, resolver)
        sql_tools_truth_files = {
            (repo_root / tn.source_file).resolve()
            for tn in truth.nodes
            if tn.source_file and tn.summary.startswith("@immich/sql-tools ")
        }
        if sql_tools_truth_files:
            files = [f for f in files if f.resolve() not in sql_tools_truth_files]

        mount_map: dict[str, str] = {}
        cleaned_texts: dict[Path, str] = {}
        for f in files:
            try:
                txt = _strip_preserve_lines(
                    f.read_text(encoding="utf-8", errors="replace"),
                    is_tsx=(f.suffix == ".tsx"),
                )
            except (OSError, UnicodeError):
                continue
            cleaned_texts[f] = txt
            for mm in _EXPRESS_MOUNT_RE.finditer(txt):
                mount_map[mm.group("target").lower()] = mm.group("prefix")

        root_res = repo_root.resolve()
        base_res = base_dir.resolve()
        nodes_by_path: dict[Path, AtlasNode] = {}
        for f in cleaned_texts:
            rf = f.resolve()
            rel_repo = rf.relative_to(root_res).as_posix()
            rel_b = rf.relative_to(base_res).as_posix() if rf.is_relative_to(base_res) else rel_repo
            is_route = (
                rel_b.endswith(("/route.ts", "/+server.ts", "/+page.server.ts", ".controller.ts"))
                or derive_next_trpc_mount_prefix(rf, root_res) is not None
                or "routes" in Path(rel_b).parts
                or "controllers" in Path(rel_b).parts
                or "pages/api" in rel_repo
                or f.stem in ("server", "app", "index")
            )
            subkind = "route" if is_route else "service"
            stem_id = rel_b.removesuffix(".tsx").removesuffix(".ts").replace("/", ".")
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
        edge_map: dict[tuple[str, str, str], AtlasEdge] = {}
        routes: list[RouteDescriptor] = []
        findings: list[RawCandidateFinding] = []
        manip_notes: list[str] = []
        seen_notes: set[str] = set()
        table_readers: dict[str, set[str]] = {}
        table_writers: dict[str, set[str]] = {}

        def add_note(msg: str) -> None:
            if msg not in seen_notes:
                seen_notes.add(msg)
                manip_notes.append(msg)

        def add_edge(
            src: str,
            dst: str,
            kind: str,
            ev_path: str,
            note: str,
            verification: str = "verified",
        ) -> None:
            key = (src, dst, kind)
            existing = edge_map.get(key)
            if existing is None:
                edge = AtlasEdge(
                    id=f"e:{src}->{dst}:{kind}",
                    source_id=src,
                    target_id=dst,
                    kind=kind,  # type: ignore[arg-type]
                    verification=verification,  # type: ignore[arg-type]
                    evidence_path=ev_path,
                    evidence_note=note,
                )
                edge_map[key] = edge
                edges.append(edge)
            elif verification == "verified" and existing.verification != "verified":
                existing.verification = "verified"
                existing.evidence_note = note

        def _extract_truth_ops_in_text(text: str, fpath: Path) -> tuple[set[str], set[str]]:
            r_tids: set[str] = set()
            w_tids: set[str] = set()
            for pm in _PRISMA_OP_RE.finditer(text):
                tid = truth.table_symbol_map.get(pm.group("model")) or truth.table_symbol_map.get(
                    f"prisma.{pm.group('model')}"
                )
                if tid:
                    if pm.group("op").startswith(("find", "count", "aggregate", "group")):
                        r_tids.add(tid)
                    else:
                        w_tids.add(tid)
            for dm in _DRIZZLE_READ_RE.finditer(text):
                sym = dm.group("sym") or dm.group("qsym") or ""
                if sym in truth.table_symbol_map:
                    r_tids.add(truth.table_symbol_map[sym])
            for dw in _DRIZZLE_WRITE_RE.finditer(text):
                sym = dw.group("sym")
                if sym in truth.table_symbol_map:
                    w_tids.add(truth.table_symbol_map[sym])
            for sw in _RAW_SQL_WRITE_RE.finditer(text):
                tk = sw.group(1).lower()
                if tk in truth.table_symbol_map:
                    w_tids.add(truth.table_symbol_map[tk])
            for sr in _RAW_SQL_READ_RE.finditer(text):
                tk = sr.group(1).lower()
                if tk in truth.table_symbol_map and truth.table_symbol_map[tk] not in w_tids:
                    r_tids.add(truth.table_symbol_map[tk])
            rel_p = fpath.resolve().relative_to(root_res).as_posix()
            k_r, k_w, k_n = extract_kysely_table_ops(text, rel_p, truth, fpath, resolver)
            r_tids.update(k_r)
            w_tids.update(k_w)
            for kn in k_n:
                add_note(kn)
            return r_tids, w_tids

        trpc_proc_nodes, trpc_router_files = collect_trpc_lineage(
            repo_root=root_res,
            cleaned_texts=cleaned_texts,
            resolver=resolver,
            nodes_by_path=nodes_by_path,
            routes=routes,
            add_edge=add_edge,
            add_note=add_note,
            extract_truth_ops=_extract_truth_ops_in_text,
            table_readers=table_readers,
            table_writers=table_writers,
        )

        file_meta: dict[Path, tuple[list, str, dict[str, set[str]], dict[str, Path]]] = {}
        di_prop_targets: dict[Path, dict[str, Path]] = {}
        for mf, mtxt in cleaned_texts.items():
            mrf = mf.resolve()
            is_m_tsx = mf.suffix == ".tsx"
            m_imps = extract_ts_import_bindings(mtxt, is_tsx=is_m_tsx)
            m_exec, m_di = executable_ts_text(mtxt, is_tsx=is_m_tsx)
            sym_targets: dict[str, Path] = {}
            prop_tgts: dict[str, Path] = {}
            for m_imp in m_imps:
                mtgt = resolver.resolve_import(m_imp.spec, mf)
                if mtgt is None:
                    continue
                for loc_n in m_imp.local_names:
                    resolved_tgt = mtgt
                    if mtgt not in nodes_by_path:
                        re_tgts = [r for r in resolve_reexport_targets(mtgt, loc_n, resolver) if r in nodes_by_path]
                        if re_tgts:
                            resolved_tgt = re_tgts[0]
                    sym_targets[loc_n] = resolved_tgt
                    for prop in m_di.get(loc_n, ()):
                        prop_tgts[prop] = resolved_tgt
            file_meta[mrf] = (m_imps, m_exec, m_di, sym_targets)
            di_prop_targets[mrf] = prop_tgts

        for f, txt in cleaned_texts.items():
            if f.resolve() in trpc_router_files:
                continue
            node = nodes_by_path[f]
            rel_repo = node.source_file
            rf = f.resolve()
            rel_b = rf.relative_to(base_res).as_posix() if rf.is_relative_to(base_res) else rel_repo
            is_tsx = f.suffix == ".tsx"

            # 1. Cross-module runtime imports + dynamic imports -> verified vs declared calls_helper
            imp_bindings, exec_txt, di_map, sym_targets = file_meta[rf]
            for imp in imp_bindings:
                target = resolver.resolve_import(imp.spec, f)
                if target is None or target == f:
                    continue
                imp_verified, used_syms = verified_import_bindings(exec_txt, di_map, imp)
                verif = "verified" if imp_verified else "declared"
                if target in nodes_by_path:
                    verb_txt = "Calls/uses" if imp_verified else "Imports (uninvoked)"
                    add_edge(
                        node.id,
                        nodes_by_path[target].id,
                        "calls_helper",
                        rel_repo,
                        f"{verb_txt} `{nodes_by_path[target].label}`.",
                        verification=verif,
                    )
                # Follow re-export barrels to concrete target modules so calls through barrels link cleanly
                sym_list: list[str | None] = sorted(used_syms) if used_syms else [None]
                for sym in sym_list:
                    for re_tgt in resolve_reexport_targets(target, sym, resolver):
                        if re_tgt not in nodes_by_path or re_tgt == f:
                            continue
                        if target in nodes_by_path:
                            re_src = nodes_by_path[target].id
                            re_ev = nodes_by_path[target].source_file
                            re_note = (
                                f"Re-exports invoked symbol `{sym}` from `{nodes_by_path[re_tgt].label}`."
                                if sym and imp_verified
                                else f"Re-exports `{nodes_by_path[re_tgt].label}`."
                            )
                        else:
                            re_src = node.id
                            re_ev = rel_repo
                            re_note = f"Imports `{nodes_by_path[re_tgt].label}` via `{target.name}`."
                        add_edge(re_src, nodes_by_path[re_tgt].id, "calls_helper", re_ev, re_note, verification=verif)

            # Follow 1-2 hops of `extends BaseClass` inherited NestJS DI properties (`this.<prop>`)
            visited_bases: set[Path] = {rf}
            frontier: list[tuple[dict[str, Path], str, int]] = [
                (sym_targets, em.group("base"), 1) for em in _CLASS_EXTENDS_RE.finditer(exec_txt)
            ]
            while frontier:
                cur_syms, bname, hop = frontier.pop(0)
                btgt = cur_syms.get(bname)
                if btgt is None or btgt in visited_bases:
                    continue
                visited_bases.add(btgt)
                for prop, dep_tgt in sorted(di_prop_targets.get(btgt, {}).items()):
                    if dep_tgt in nodes_by_path and dep_tgt != rf and re.search(rf"\bthis\.{re.escape(prop)}\b", exec_txt):
                        add_edge(
                            node.id,
                            nodes_by_path[dep_tgt].id,
                            "calls_helper",
                            rel_repo,
                            f"Calls inherited DI dependency `this.{prop}` (`{nodes_by_path[dep_tgt].label}`).",
                            verification="verified",
                        )
                if hop < 2 and btgt in file_meta:
                    _, b_exec, _, b_syms = file_meta[btgt]
                    for em2 in _CLASS_EXTENDS_RE.finditer(b_exec):
                        frontier.append((b_syms, em2.group("base"), hop + 1))

            # 1. Cross-module runtime imports + dynamic imports -> verified vs declared calls_helper
            for bare_re in resolve_reexport_targets(f, None, resolver):
                if bare_re in nodes_by_path and bare_re != f:
                    add_edge(
                        node.id,
                        nodes_by_path[bare_re].id,
                        "calls_helper",
                        rel_repo,
                        f"Re-exports `{nodes_by_path[bare_re].label}`.",
                        verification="declared",
                    )

            for d_site in extract_ts_dynamic_imports(exec_txt, is_tsx=is_tsx):
                if d_site.spec is None:
                    add_note(f"Unresolved dynamic import `{d_site.raw_expr}` in {rel_repo}:{d_site.line}.")
                    continue
                d_tgt = resolver.resolve_import(d_site.spec, f)
                if d_tgt is None or d_tgt == f:
                    continue
                d_verif_flag, d_used = verified_dynamic_import(exec_txt, d_site)
                d_verif = "verified" if d_verif_flag else "declared"
                if d_tgt in nodes_by_path:
                    d_verb = "Dynamically calls" if d_verif_flag else "Dynamically imports (uninvoked)"
                    add_edge(
                        node.id,
                        nodes_by_path[d_tgt].id,
                        "calls_helper",
                        rel_repo,
                        f"{d_verb} `{nodes_by_path[d_tgt].label}`.",
                        verification=d_verif,
                    )
                for sym in sorted(d_used) if d_used else [None]:
                    for re_tgt in resolve_reexport_targets(d_tgt, sym, resolver):
                        if re_tgt not in nodes_by_path or re_tgt == f:
                            continue
                        re_src = nodes_by_path[d_tgt].id if d_tgt in nodes_by_path else node.id
                        re_ev = nodes_by_path[d_tgt].source_file if d_tgt in nodes_by_path else rel_repo
                        add_edge(re_src, nodes_by_path[re_tgt].id, "calls_helper", re_ev, f"Re-exports `{sym or nodes_by_path[re_tgt].label}`.", verification=d_verif)

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

            ctrl_matches = list(_NEST_CTRL_RE.finditer(txt))
            for c_idx, ctrl_m in enumerate(ctrl_matches):
                raw_ctrl_arg = (ctrl_m.group("arg") or "").strip()
                if not raw_ctrl_arg:
                    ctrl_pref = ""
                else:
                    if raw_ctrl_arg.startswith("{"):
                        pm = re.search(r"\bpath\s*:\s*([^,\n}]+)", raw_ctrl_arg)
                        raw_ctrl_arg = pm.group(1).strip() if pm else ""
                    resolved_pref = resolve_string_expr(raw_ctrl_arg, f, resolver) if raw_ctrl_arg else ""
                    if resolved_pref is None:
                        ctrl_lineno = txt.count("\n", 0, ctrl_m.start()) + 1
                        add_note(f"Unresolved @Controller prefix expression `{raw_ctrl_arg}` in {rel_repo}:{ctrl_lineno}.")
                        ctrl_pref = None
                    else:
                        ctrl_pref = resolved_pref
                if ctrl_pref is not None:
                    node.subkind = "route"
                    ctrl_end = ctrl_matches[c_idx + 1].start() if c_idx + 1 < len(ctrl_matches) else len(txt)
                    ctrl_body = txt[ctrl_m.start() : ctrl_end]
                    for nm in _NEST_VERB_RE.finditer(ctrl_body):
                        verb = nm.group("verb").upper()
                        sub_p = nm.group("subpath") or ""
                        full_p = _norm_colon_params(f"/{ctrl_pref}/{sub_p}")
                        lineno = txt.count("\n", 0, ctrl_m.start() + nm.start()) + 1
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

            # 3. Extract Prisma, Drizzle, Kysely, and SQL table reads vs writes
            reads_tids, writes_tids = _extract_truth_ops_in_text(txt, f)

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
                if name_has_policy_token(cname, active_tokens):
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

        in_use = set(table_readers) | set(table_writers)
        in_use |= {
            tid
            for tid, rdrs in truth.db_readers.items()
            if any(r.startswith("fn:") for r in rdrs)
        }
        for tid, db_rdrs in sorted(truth.db_readers.items()):
            for reader_id, (evidence, kind, note) in sorted(db_rdrs.items()):
                if reader_id.startswith("t:") and reader_id not in in_use:
                    continue
                table_readers.setdefault(tid, set()).add(reader_id)
                add_edge(reader_id, tid, kind, evidence, note)

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
            if e.kind == "calls_helper" and e.verification == "verified":
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
            nodes=[*nodes_by_path.values(), *trpc_proc_nodes],
            edges=edges,
            routes=routes,
            findings=findings,
            notes=manip_notes,
        )
