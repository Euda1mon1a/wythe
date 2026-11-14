"""Typed tRPC server router, Next.js handler mount, and client call extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.treesitter_engine import _get_parser, has_treesitter
from app.adapters.ts_workspace import (
    WorkspaceResolver,
    extract_ts_dynamic_imports,
    extract_ts_import_bindings,
)

_TRPC_CALL_CLIENT_RE = re.compile(
    r"""(?<![.\w$])(?P<root>[A-Za-z_$][\w$]*)\s*\.\s*(?P<chain>(?:[A-Za-z_$][\w$]*\s*\.\s*)+)(?P<op>useQuery|useSuspenseQuery|useInfiniteQuery|useSuspenseInfiniteQuery|query|useMutation|mutate|mutateAsync)\s*\("""
)
_TRPC_LOCAL_CREATE_RE = re.compile(
    r"""\b(?:const|let|export\s+const)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:createTRPCNext|createTRPCReact|createTRPCProxyClient|createTRPCClient)\b"""
)
_TRPC_SERVER_CREATE_RE = re.compile(
    r"""(?:(?:export\s+)?(?:const|let)\s+(?P<cname>[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*|export\s+(?P<default>default)\s+)(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?P<fn>createTRPCRouter|router)\s*\(\s*\{"""
)
_MERGE_ROUTERS_RE = re.compile(
    r"""(?:export\s+(?:const|let)\s+(?P<cname>[A-Za-z_$][\w$]*)\s*=\s*)?(?:[A-Za-z_$][\w$]*\s*\.\s*)?mergeRouters\s*\((?P<args>[^)]+)\)"""
)
_NEXT_TRPC_HANDLER_RE = re.compile(
    r"""\bcreateNextApiHandler\s*(?:<[^>]+>)?\s*\(\s*(?P<ident>[A-Za-z_$][\w$]*)\s*[,)]"""
)
_FETCH_TRPC_HANDLER_RE = re.compile(
    r"""\b(?:createNextApiHandler|fetchRequestHandler)\s*(?:<[^>]+>)?\s*\(\s*\{(?P<body>[\s\S]{0,600}?)(?:\brouter\s*:\s*(?P<ident>[A-Za-z_$][\w$]*)|(?<![.\w$:])(?P<short>router)\s*(?=[,}]))"""
)
_END_PROC_METHOD_RE = re.compile(r"""\.\s*(?P<op>query|mutation)\s*\(""")
_MUTATION_CLIENT_OPS = frozenset({"useMutation", "mutate", "mutateAsync"})
_TRPC_SKIP_CHAIN_SEGS = frozenset({"useUtils", "useContext", "Provider"})
_CLIENT_SPEC_HINT_RE = re.compile(r"""trpc|@/utils/api|~/utils/api""", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedTrpcProcedure:
    name: str
    http_method: str  # "GET" | "POST"
    line: int
    start_line: int
    end_line: int
    body_text: str


@dataclass
class ParsedTrpcRouter:
    file_path: Path
    export_names: set[str] = field(default_factory=set)
    procedures: dict[str, ParsedTrpcProcedure] = field(default_factory=dict)
    child_routers: dict[str, str] = field(default_factory=dict)  # prop_key -> local_ident
    merged_routers: list[str] = field(default_factory=list)  # local_idents


@dataclass(frozen=True)
class ParsedTrpcMount:
    handler_file: Path
    mount_prefix: str
    router_ident: str
    router_file: Path
    router_export: str
    line: int


def _skip_string(txt: str, idx: int) -> int:
    q = txt[idx]
    j = idx + 1
    n = len(txt)
    while j < n:
        ch = txt[j]
        if ch == "\\":
            j += 2
            continue
        if ch == q and q != "`":
            return j + 1
        if ch == "`" and q == "`":
            return j + 1
        j += 1
    return n


def _extract_brace_span(txt: str, open_idx: int) -> tuple[int, int]:
    n = len(txt)
    depth = 1
    i = open_idx + 1
    while i < n and depth > 0:
        ch = txt[i]
        if ch in ("'", '"', "`"):
            i = _skip_string(txt, i)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return open_idx + 1, max(open_idx + 1, i - 1)


def _split_top_level_entries(body: str) -> list[tuple[int, int, str]]:
    """Split an object literal body `{ ... }` into top-level `(rel_start, rel_end, entry_text)`."""
    entries: list[tuple[int, int, str]] = []
    n = len(body)
    i = 0
    start = 0
    pdepth = bdepth = cdepth = 0
    while i < n:
        ch = body[i]
        if ch in ("'", '"', "`"):
            i = _skip_string(body, i)
            continue
        if ch == "(":
            pdepth += 1
        elif ch == ")":
            pdepth = max(0, pdepth - 1)
        elif ch == "[":
            bdepth += 1
        elif ch == "]":
            bdepth = max(0, bdepth - 1)
        elif ch == "{":
            cdepth += 1
        elif ch == "}":
            cdepth = max(0, cdepth - 1)
        elif ch == "," and pdepth == 0 and bdepth == 0 and cdepth == 0:
            entries.append((start, i, body[start:i]))
            start = i + 1
        i += 1
    if start < n:
        entries.append((start, n, body[start:n]))
    return entries


def extract_trpc_client_calls(txt: str, *, is_tsx: bool = True) -> list[tuple[str, str, int]]:
    """Return `(http_method, "/api/trpc/<path>", lineno)` for typed tRPC client invocations."""
    client_idents: set[str] = set()
    for imp in extract_ts_import_bindings(txt, is_tsx=is_tsx):
        for imp_name, loc_name in zip(imp.imported_names, imp.local_names):
            if (
                "trpc" in imp_name.lower() or "trpc" in loc_name.lower() or _CLIENT_SPEC_HINT_RE.search(imp.spec)
            ) and (loc_name in ("trpc", "api", "trpcClient") or "trpc" in loc_name.lower()):
                client_idents.add(loc_name)
    for lm in _TRPC_LOCAL_CREATE_RE.finditer(txt):
        client_idents.add(lm.group("name"))
    if not client_idents:
        return []

    out: list[tuple[str, str, int]] = []
    for m in _TRPC_CALL_CLIENT_RE.finditer(txt):
        if m.group("root") not in client_idents:
            continue
        segs = [s.strip() for s in m.group("chain").split(".") if s.strip()]
        if not segs or any(s in _TRPC_SKIP_CHAIN_SEGS for s in segs):
            continue
        op = m.group("op")
        verb = "POST" if op in _MUTATION_CLIENT_OPS else "GET"
        proc_path = ".".join(segs)
        lineno = txt.count("\n", 0, m.start()) + 1
        out.append((verb, f"/api/trpc/{proc_path}", lineno))
    return out


def parse_trpc_routers(file_path: Path, txt: str) -> list[ParsedTrpcRouter]:
    """Extract `router({...})` / `createTRPCRouter({...})` / `mergeRouters(...)` from TS/TSX text."""
    is_tsx = file_path.suffix == ".tsx"
    routers: list[ParsedTrpcRouter] = []

    if has_treesitter():
        parser = _get_parser("tsx" if is_tsx else "ts")
        if parser is not None:
            raw = txt.encode("utf-8")
            tree = parser.parse(raw)

            def _node_txt(n: Any) -> str:
                return raw[n.start_byte : n.end_byte].decode("utf-8", errors="replace")

            def _enclosing_export_name(call_n: Any) -> str:
                cur = call_n.parent
                while cur is not None:
                    if cur.type == "variable_declarator":
                        nm = cur.child_by_field_name("name")
                        if nm is not None:
                            return _node_txt(nm).strip()
                    elif cur.type == "export_statement":
                        if any(c.type == "default" for c in cur.children):
                            return "default"
                    elif cur.type in ("program", "statement_block"):
                        break
                    cur = cur.parent
                return "default"

            def _walk(node: Any) -> None:
                if node.type == "call_expression":
                    fn = node.child_by_field_name("function")
                    fn_name = ""
                    if fn is not None:
                        if fn.type == "identifier":
                            fn_name = _node_txt(fn)
                        elif fn.type == "member_expression":
                            prop = fn.child_by_field_name("property")
                            fn_name = _node_txt(prop) if prop is not None else ""
                    args = node.child_by_field_name("arguments")
                    arg_nodes = [c for c in args.named_children if c.type != "comment"] if args else []
                    if fn_name in ("router", "createTRPCRouter") and len(arg_nodes) == 1 and arg_nodes[0].type == "object":
                        exp_name = _enclosing_export_name(node)
                        rtr = ParsedTrpcRouter(file_path=file_path, export_names={exp_name})
                        for prop_n in arg_nodes[0].named_children:
                            if prop_n.type == "shorthand_property_identifier":
                                nm = _node_txt(prop_n).strip()
                                if nm:
                                    rtr.child_routers[nm] = nm
                            elif prop_n.type == "spread_element":
                                for ch in prop_n.named_children:
                                    if ch.type == "identifier":
                                        rtr.merged_routers.append(_node_txt(ch))
                            elif prop_n.type == "pair":
                                kn = prop_n.child_by_field_name("key")
                                vn = prop_n.child_by_field_name("value")
                                if kn is None or vn is None:
                                    continue
                                k = _node_txt(kn).strip().strip("'\"")
                                while vn is not None and vn.type in ("as_expression", "satisfies_expression", "parenthesized_expression") and vn.named_children:
                                    vn = vn.named_children[0]
                                if vn is None:
                                    continue
                                if vn.type == "identifier":
                                    rtr.child_routers[k] = _node_txt(vn).strip()
                                elif vn.type == "call_expression":
                                    vfn = vn.child_by_field_name("function")
                                    if vfn is not None and vfn.type == "member_expression":
                                        mprop = vfn.child_by_field_name("property")
                                        op_name = _node_txt(mprop) if mprop is not None else ""
                                        if op_name in ("query", "mutation"):
                                            vtxt = _node_txt(vn)
                                            rtr.procedures[k] = ParsedTrpcProcedure(
                                                name=k,
                                                http_method="GET" if op_name == "query" else "POST",
                                                line=vn.start_point[0] + 1,
                                                start_line=vn.start_point[0] + 1,
                                                end_line=vn.end_point[0] + 1,
                                                body_text=vtxt,
                                            )
                        if rtr.procedures or rtr.child_routers or rtr.merged_routers:
                            routers.append(rtr)
                        return
                    if fn_name == "mergeRouters" and arg_nodes:
                        exp_name = _enclosing_export_name(node)
                        merged = [
                            _node_txt(a).strip()
                            for a in arg_nodes
                            if a.type == "identifier"
                        ]
                        if merged:
                            routers.append(
                                ParsedTrpcRouter(
                                    file_path=file_path,
                                    export_names={exp_name},
                                    merged_routers=merged,
                                )
                            )
                for ch in node.children:
                    _walk(ch)

            _walk(tree.root_node)
            return routers

    # Brace-scanner fallback when Tree-sitter is disabled
    for m in _TRPC_SERVER_CREATE_RE.finditer(txt):
        exp_name = m.group("cname") or "default"
        open_idx = m.end() - 1
        b_start, b_end = _extract_brace_span(txt, open_idx)
        body = txt[b_start:b_end]
        rtr = ParsedTrpcRouter(file_path=file_path, export_names={exp_name})
        for rel_s, rel_e, raw_entry in _split_top_level_entries(body):
            entry = raw_entry.strip()
            if not entry:
                continue
            if entry.startswith("..."):
                ident = entry[3:].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", ident):
                    rtr.merged_routers.append(ident)
                continue
            if re.fullmatch(r"[A-Za-z_$][\w$]*", entry):
                rtr.child_routers[entry] = entry
                continue
            colon_idx = -1
            pdepth = bdepth = cdepth = 0
            k_i = 0
            while k_i < len(entry):
                c = entry[k_i]
                if c in ("'", '"', "`"):
                    k_i = _skip_string(entry, k_i)
                    continue
                if c == "(":
                    pdepth += 1
                elif c == ")":
                    pdepth = max(0, pdepth - 1)
                elif c == "[":
                    bdepth += 1
                elif c == "]":
                    bdepth = max(0, bdepth - 1)
                elif c == "{":
                    cdepth += 1
                elif c == "}":
                    cdepth = max(0, cdepth - 1)
                elif c == ":" and pdepth == 0 and bdepth == 0 and cdepth == 0:
                    colon_idx = k_i
                    break
                k_i += 1
            if colon_idx <= 0:
                continue
            key_s = entry[:colon_idx].strip().strip("'\"")
            val_s = entry[colon_idx + 1 :].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", val_s):
                rtr.child_routers[key_s] = val_s
                continue
            last_op: re.Match[str] | None = None
            for om in _END_PROC_METHOD_RE.finditer(val_s):
                last_op = om
            if last_op is not None:
                abs_start = b_start + rel_s
                abs_end = b_start + rel_e
                sline = txt.count("\n", 0, abs_start) + 1
                eline = txt.count("\n", 0, abs_end) + 1
                rtr.procedures[key_s] = ParsedTrpcProcedure(
                    name=key_s,
                    http_method="GET" if last_op.group("op") == "query" else "POST",
                    line=sline,
                    start_line=sline,
                    end_line=eline,
                    body_text=val_s,
                )
        if rtr.procedures or rtr.child_routers or rtr.merged_routers:
            routers.append(rtr)

    for mm in _MERGE_ROUTERS_RE.finditer(txt):
        exp_name = mm.group("cname") or "default"
        args = [a.strip() for a in mm.group("args").split(",") if re.fullmatch(r"[A-Za-z_$][\w$]*", a.strip())]
        if args:
            routers.append(ParsedTrpcRouter(file_path=file_path, export_names={exp_name}, merged_routers=args))
    return routers


def derive_next_trpc_mount_prefix(handler_file: Path, repo_root: Path) -> str | None:
    """Derive `/api/trpc/...` mount prefix from `pages/api/**/[trpc].ts` or `app/api/**/[trpc]/route.ts`."""
    rel = handler_file.relative_to(repo_root).as_posix()
    for marker in ("/pages/", "/src/pages/"):
        lead = marker.lstrip("/")
        if (marker in rel or rel.startswith(lead)) and (
            handler_file.stem in ("[trpc]", "[[...trpc]]") or "/trpc/" in f"/{rel}"
        ):
            sub = rel.split(marker, 1)[1] if marker in rel else rel[len(lead) :]
            if not sub.startswith("api/"):
                continue
            parts = list(Path(sub).with_suffix("").parts)
            if parts and parts[-1] in ("[trpc]", "[[...trpc]]", "index"):
                parts.pop()
            return "/" + "/".join(parts)
    for marker in ("/app/", "/src/app/"):
        lead = marker.lstrip("/")
        if (marker in rel or rel.startswith(lead)) and handler_file.name == "route.ts" and "trpc" in rel:
            sub = rel.split(marker, 1)[1] if marker in rel else rel[len(lead) :]
            if not sub.startswith("api/"):
                continue
            parts = list(Path(sub).parts[:-1])
            if parts and parts[-1] in ("[trpc]", "[[...trpc]]"):
                parts.pop()
            return "/" + "/".join(parts)
    return None


def extract_trpc_mounts_in_file(
    handler_file: Path,
    txt: str,
    repo_root: Path,
    resolver: WorkspaceResolver,
) -> list[ParsedTrpcMount]:
    """Detect `createNextApiHandler(r)` / `fetchRequestHandler({ router: r })` in API handlers."""
    prefix = derive_next_trpc_mount_prefix(handler_file, repo_root)
    if prefix is None:
        return []
    imp_map: dict[str, tuple[Path, str]] = {}
    for imp in extract_ts_import_bindings(txt, is_tsx=handler_file.suffix == ".tsx"):
        tgt = resolver.resolve_import(imp.spec, handler_file)
        if tgt is None:
            continue
        for src_n, loc_n in zip(imp.imported_names, imp.local_names):
            imp_map[loc_n] = (tgt, src_n)

    mounts: list[ParsedTrpcMount] = []
    for rx in (_NEXT_TRPC_HANDLER_RE, _FETCH_TRPC_HANDLER_RE):
        for m in rx.finditer(txt):
            ident = m.groupdict().get("ident") or m.groupdict().get("short")
            if not ident:
                continue
            lineno = txt.count("\n", 0, m.start()) + 1
            rfile, rexport = imp_map.get(ident, (handler_file, ident))
            mounts.append(
                ParsedTrpcMount(
                    handler_file=handler_file,
                    mount_prefix=prefix,
                    router_ident=ident,
                    router_file=rfile,
                    router_export=rexport,
                    line=lineno,
                )
            )
    return mounts


def extract_procedure_dynamic_sites(proc: ParsedTrpcProcedure, router_file: Path):
    """Extract dynamic `import(...)` call sites inside a single tRPC procedure body."""
    return extract_ts_dynamic_imports(proc.body_text, is_tsx=router_file.suffix == ".tsx")


def _trpc_route_regex(full_path: str) -> str:
    norm = re.sub(r"^/api(?:/v\d+)?(?=/|$)", "", full_path.rstrip("/")) or "/"
    return rf"^(?:/api(?:/v\d+)?)?{re.escape(norm)}/?$"


def collect_trpc_lineage(
    *,
    repo_root: Path,
    cleaned_texts: dict[Path, str],
    resolver: WorkspaceResolver,
    nodes_by_path: dict[Path, Any],
    routes: list[Any],
    add_edge: Any,
    add_note: Any,
    extract_truth_ops: Any,
    table_readers: dict[str, set[str]],
    table_writers: dict[str, set[str]],
) -> tuple[list[Any], set[Path]]:
    """Assemble typed tRPC procedure nodes, dynamic/static handler edges, and `RouteDescriptor`s.

    Returns `(procedure_nodes, router_file_paths)`.
    """
    from app.adapters.base import RouteDescriptor
    from app.adapters.ts_workspace import (
        executable_ts_text,
        resolve_reexport_targets,
        verified_dynamic_import,
    )
    from app.schemas.atlas import AtlasNode

    routers_by_key: dict[tuple[Path, str], ParsedTrpcRouter] = {}
    fallback_router_by_file: dict[Path, ParsedTrpcRouter] = {}
    mounts: list[ParsedTrpcMount] = []
    root_router_keys: list[tuple[Path, str]] = []

    for fpath, txt in cleaned_texts.items():
        if "router(" in txt or "createTRPCRouter" in txt or "mergeRouters" in txt:
            for rtr in parse_trpc_routers(fpath, txt):
                rf = fpath.resolve()
                fallback_router_by_file.setdefault(rf, rtr)
                for ename in rtr.export_names:
                    routers_by_key[(rf, ename)] = rtr
                    if fpath.stem in ("_app", "appRouter") or ename == "appRouter":
                        root_router_keys.append((rf, ename))
        mounts.extend(extract_trpc_mounts_in_file(fpath, txt, repo_root, resolver))

    if not mounts:
        return [], set()

    imp_lookup_cache: dict[Path, dict[str, tuple[Path, str]]] = {}
    file_imp_bindings_cache: dict[Path, list[Any]] = {}

    def _file_imp_bindings(fpath: Path):
        if fpath not in file_imp_bindings_cache:
            txt = cleaned_texts.get(fpath, "")
            file_imp_bindings_cache[fpath] = extract_ts_import_bindings(txt, is_tsx=fpath.suffix == ".tsx")
        return file_imp_bindings_cache[fpath]

    def _file_imp_map(fpath: Path) -> dict[str, tuple[Path, str]]:
        if fpath in imp_lookup_cache:
            return imp_lookup_cache[fpath]
        mp: dict[str, tuple[Path, str]] = {}
        for imp in _file_imp_bindings(fpath):
            tgt = resolver.resolve_import(imp.spec, fpath)
            if tgt is None:
                continue
            for src_n, loc_n in zip(imp.imported_names, imp.local_names):
                mp[loc_n] = (tgt, src_n)
        imp_lookup_cache[fpath] = mp
        return mp

    def _lookup_router(fpath: Path, export_name: str) -> ParsedTrpcRouter | None:
        rf = fpath.resolve()
        if (rf, export_name) in routers_by_key:
            return routers_by_key[(rf, export_name)]
        # Check barrel re-exports
        for re_tgt in resolve_reexport_targets(rf, export_name, resolver):
            r_ref = re_tgt.resolve()
            if (r_ref, export_name) in routers_by_key:
                return routers_by_key[(r_ref, export_name)]
            if r_ref in fallback_router_by_file:
                return fallback_router_by_file[r_ref]
        return fallback_router_by_file.get(rf)

    def _iter_router_procs(
        rtr: ParsedTrpcRouter,
        prefix: str = "",
        seen: frozenset[tuple[Path, str]] = frozenset(),
    ):
        rkey = (rtr.file_path.resolve(), next(iter(rtr.export_names), "*"))
        if rkey in seen:
            return
        seen = seen | {rkey}
        for pname, proc in rtr.procedures.items():
            full_sub = f"{prefix}.{pname}" if prefix else pname
            yield rtr, proc, full_sub
        mp = _file_imp_map(rtr.file_path)
        for child_key, local_ident in rtr.child_routers.items():
            tgt_f, tgt_exp = mp.get(local_ident, (rtr.file_path, local_ident))
            child_rtr = _lookup_router(tgt_f, tgt_exp)
            if child_rtr is not None:
                child_pref = f"{prefix}.{child_key}" if prefix else child_key
                yield from _iter_router_procs(child_rtr, child_pref, seen)
        for m_ident in rtr.merged_routers:
            tgt_f, tgt_exp = mp.get(m_ident, (rtr.file_path, m_ident))
            m_rtr = _lookup_router(tgt_f, tgt_exp)
            if m_rtr is not None:
                yield from _iter_router_procs(m_rtr, prefix, seen)

    # Compute canonical `appRouter` dot paths (`viewer.slots.reserveSlot`)
    canonical_paths: dict[tuple[Path, str], list[str]] = {}
    for rf, ename in root_router_keys:
        root_rtr = _lookup_router(rf, ename)
        if root_rtr is None:
            continue
        for sub_rtr, proc, cpath in _iter_router_procs(root_rtr):
            canonical_paths.setdefault((sub_rtr.file_path.resolve(), proc.name), [])
            if cpath not in canonical_paths[(sub_rtr.file_path.resolve(), proc.name)]:
                canonical_paths[(sub_rtr.file_path.resolve(), proc.name)].append(cpath)

    proc_nodes: dict[tuple[Path, str], AtlasNode] = {}
    router_files: set[Path] = set()
    mounted_router_files: dict[Path, list[tuple[ParsedTrpcMount, ParsedTrpcRouter]]] = {}

    for mnt in mounts:
        rtr = _lookup_router(mnt.router_file, mnt.router_export)
        if rtr is None:
            continue
        hnode = nodes_by_path.get(mnt.handler_file)
        if hnode is not None:
            hnode.subkind = "route"
        for sub_rtr, proc, rel_sub in _iter_router_procs(rtr):
            rf = sub_rtr.file_path.resolve()
            router_files.add(rf)
            mounted_router_files.setdefault(rf, [])
            rnode_orig = nodes_by_path.get(rf)
            if rnode_orig is not None:
                rnode_orig.subkind = "route"
                rnode_orig.cluster = "api"
            rtr_rel = sub_rtr.file_path.relative_to(repo_root).as_posix()
            c_list = canonical_paths.get((rf, proc.name), [])
            p_key = (rf, proc.name)
            pnode = proc_nodes.get(p_key)
            if pnode is None:
                slug = rtr_rel.removesuffix(".tsx").removesuffix(".ts").replace("/", ".")
                label = c_list[0] if c_list else rel_sub
                pnode = AtlasNode(
                    id=f"m:route:{slug}:{proc.name}",
                    tier="manipulate",
                    subkind="route",
                    label=label,
                    source_file=rtr_rel,
                    line=proc.line,
                    status="clean",
                    role="mechanism",
                    cluster="api",
                    summary=f"Typed tRPC {proc.http_method} procedure `{label}` ({rtr_rel}:{proc.line}).",
                    http_methods=[proc.http_method],
                )
                proc_nodes[p_key] = pnode

                # Scoped truth & helper/dynamic-import edges inside THIS procedure body only
                proc_reads, proc_writes = extract_truth_ops(proc.body_text, sub_rtr.file_path)
                for tid in sorted(proc_reads):
                    table_readers.setdefault(tid, set()).add(pnode.id)
                    add_edge(pnode.id, tid, "reads_truth", rtr_rel, f"Procedure `{proc.name}` reads `{tid}`.")
                for tid in sorted(proc_writes):
                    table_writers.setdefault(tid, set()).add(pnode.id)
                    add_edge(pnode.id, tid, "writes_truth", rtr_rel, f"Procedure `{proc.name}` writes `{tid}`.")

                is_tsx = sub_rtr.file_path.suffix == ".tsx"
                proc_exec, _ = executable_ts_text(proc.body_text, is_tsx=is_tsx)
                for site in extract_ts_dynamic_imports(proc_exec, is_tsx=is_tsx):
                    if site.spec is None:
                        abs_line = proc.start_line + max(0, site.line - 1)
                        add_note(f"Unresolved dynamic import `{site.raw_expr}` in {rtr_rel}:{abs_line}.")
                        continue
                    tgt = resolver.resolve_import(site.spec, sub_rtr.file_path)
                    if tgt is None or tgt == sub_rtr.file_path:
                        continue
                    invoked, used_syms = verified_dynamic_import(proc_exec, site)
                    verif = "verified" if invoked else "declared"
                    tnode = nodes_by_path.get(tgt)
                    if tnode is not None:
                        vtxt = "Dynamically invokes" if invoked else "Dynamically imports (uninvoked)"
                        add_edge(pnode.id, tnode.id, "calls_helper", rtr_rel, f"{vtxt} `{tnode.label}` from `{proc.name}`.", verification=verif)
                    for sym in sorted(used_syms) if used_syms else [None]:
                        for re_tgt in resolve_reexport_targets(tgt, sym, resolver):
                            re_node = nodes_by_path.get(re_tgt)
                            if re_node is not None and re_tgt != sub_rtr.file_path:
                                add_edge(pnode.id, re_node.id, "calls_helper", tgt.relative_to(repo_root).as_posix(), f"Re-exports invoked handler `{sym or re_node.label}`.", verification=verif)

                # Static runtime imports referenced inside procedure body
                for imp in _file_imp_bindings(sub_rtr.file_path):
                    tgt = resolver.resolve_import(imp.spec, sub_rtr.file_path)
                    if tgt is None or tgt == sub_rtr.file_path:
                        continue
                    for src_n, loc_n in zip(imp.imported_names, imp.local_names):
                        if re.search(rf"(?<![.\w$]){re.escape(loc_n)}\b", proc_exec):
                            if tgt in nodes_by_path:
                                add_edge(pnode.id, nodes_by_path[tgt].id, "calls_helper", rtr_rel, f"Procedure `{proc.name}` invokes `{loc_n}`.")
                            for re_tgt in resolve_reexport_targets(tgt, src_n, resolver):
                                if re_tgt in nodes_by_path and re_tgt != sub_rtr.file_path:
                                    add_edge(pnode.id, nodes_by_path[re_tgt].id, "calls_helper", tgt.relative_to(repo_root).as_posix(), f"Re-exports `{src_n}`.")

            if hnode is not None:
                add_edge(hnode.id, pnode.id, "calls_helper", hnode.source_file, f"Mounts tRPC procedure `{pnode.label}`.")

            # Register normalized endpoint path variants (single root + split-endpoint + canonical appRouter path)
            ep_cands: list[str] = [f"{mnt.mount_prefix}/{rel_sub}"]
            if mnt.mount_prefix != "/api/trpc":
                ep_cands.append(f"{mnt.mount_prefix}.{rel_sub}")
            for cp in c_list:
                ep_cands.append(f"/api/trpc/{cp}")
            for ep in dict.fromkeys(ep_cands):
                if ep not in pnode.http_paths:
                    pnode.http_paths.append(ep)
                routes.append(
                    RouteDescriptor(
                        node_id=pnode.id,
                        http_method=proc.http_method,
                        full_path=ep,
                        path_regex=_trpc_route_regex(ep),
                        source_file=rtr_rel,
                        line=proc.line,
                        called_symbols=frozenset(),
                        imported_modules=frozenset(),
                    )
                )

    return list(proc_nodes.values()), router_files
