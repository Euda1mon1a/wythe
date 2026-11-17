"""`Model::GetOrCreate<T>()` service-locator singleton dependency graph and `SAT-INT-003`.

Extracts C++ `Model::GetOrCreate<T>()`, `model->GetOrCreate<T>()`, and `model->Get<T>()`
instantiations across `Trail`, `IntegerTrail`, `SatSolver`, `TimeLimit`, `ImpliedBounds`,
and cut generators into Zoom-2 `StratumMicroNode` / `StratumMicroEdge` subgraphs and
`AtlasEdge` dependencies with `symbol_links`, flagging cyclic constructor dependencies.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

from app.adapters.base import RawCandidateFinding
from app.schemas.atlas import AtlasEdge, StratumMicroEdge, StratumMicroNode
from wythe_plugin_solver_internals.proto_descriptor import (
    MAX_SOLVER_FILE_BYTES,
    iter_safe_repo_files,
    read_safe_artifact_text,
    strip_c_comments_and_strings,
)
from wythe_plugin_solver_internals.stage_matrix import CppUsrIndex, UsrSymbolEntry

_CPP_SUFFIXES: frozenset[str] = frozenset({".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"})

# Matches `model->GetOrCreate<T>()`, `model_->Get<T>()`, `Model::GetOrCreate<T>()`, etc.
_SERVICE_LOCATOR_RE = re.compile(
    r"(?:\b(?:[A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*|\b(?:[A-Za-z0-9_]+::)*Model::)"
    r"(GetOrCreate|Get|Mutable)\s*<\s*(::)?\s*([A-Za-z_][A-Za-z0-9_:\s]*?)\s*>\s*\("
)
_NAMESPACE_OPEN_RE = re.compile(
    r"(?:^|[\s;])(?:inline\s+)?namespace(?:\s+([A-Za-z_][A-Za-z0-9_:]*))?\s*$"
)
_CLASS_OPEN_RE = re.compile(
    r"\b(?:class|struct)\s+(?:ABSL_[A-Z0-9_]+\s+|alignas\([^)]*\)\s+)*([A-Za-z_][A-Za-z0-9_:]*)\b([^()]*)$"
)
_CLASS_FWD_RE = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_:]*)\s*$"
)
_OOL_METHOD_OPEN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*~?[A-Za-z_][A-Za-z0-9_]*)+)\s*\("
)
_GENERIC_TEMPLATE_PARAMS: frozenset[str] = frozenset({"T", "U", "Class", "Singleton", "Service", "Type"})
_CONTROL_KEYWORDS: frozenset[str] = frozenset(
    {"if", "for", "while", "switch", "return", "sizeof", "catch", "DCHECK", "CHECK", "ABSL_CHECK"}
)


@dataclass(frozen=True)
class SingletonNodeDecl:
    type_name: str
    qualified_name: str
    source_file: str
    line: int
    usr: str | None = None


@dataclass(frozen=True)
class SingletonDependencyEdge:
    caller_symbol: str
    caller_type: str | None
    target_type: str
    accessor: str  # "GetOrCreate" | "Get" | "Mutable"
    is_constructor_dep: bool
    source_file: str
    line: int
    symbol_links: tuple[str, ...]
    is_ambiguous: bool = False


@dataclass(frozen=True)
class SingletonCycle:
    chain: tuple[str, ...]
    edges: tuple[SingletonDependencyEdge, ...]


@dataclass(frozen=True)
class SingletonGraphReport:
    singletons: dict[str, SingletonNodeDecl]
    dependencies: tuple[SingletonDependencyEdge, ...]
    cycles: tuple[SingletonCycle, ...]
    atlas_edges: tuple[AtlasEdge, ...]
    findings: tuple[RawCandidateFinding, ...]


def _short_cpp_type(raw_type: str) -> str:
    base = raw_type.split("[", 1)[0].strip().lstrip(":")
    return base.rsplit("::", 1)[-1]


def _normalize_qual(raw_qual: str) -> str:
    return "::".join(p.strip() for p in raw_qual.strip().lstrip(":").split("::") if p.strip())


def _bounded_atlas_id(raw_id: str, *, max_len: int = 180) -> str:
    safe = raw_id.replace("<", "_").replace(">", "_")
    if len(safe) <= max_len:
        return safe
    digest = hashlib.sha1(safe.encode("utf-8")).hexdigest()[:10]
    return f"{safe[: max_len - 11]}:{digest}"


def _qualified_name_from_usr_entry(entry: UsrSymbolEntry) -> str:
    nm = entry.name.strip()
    if "::" in nm:
        return _normalize_qual(nm.split("(", 1)[0])
    usr_segs = re.findall(r"@(?:N|S|C|U)@([A-Za-z_][A-Za-z0-9_]*)", entry.usr)
    if usr_segs:
        return "::".join(usr_segs)
    colon_m = re.search(r"([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)", entry.usr)
    if colon_m:
        return _normalize_qual(colon_m.group(1))
    return _normalize_qual(nm)


def _resolve_type_usr(
    qualified_name: str,
    usr_index: CppUsrIndex,
) -> tuple[str | None, str | None, int | None]:
    type_kinds = {"class", "struct", "type", "cxx-class", "record"}
    exact_hits: list[UsrSymbolEntry] = []
    for entry in usr_index.symbols_by_usr.values():
        entry_qual = _qualified_name_from_usr_entry(entry)
        if entry_qual == qualified_name and entry.kind in type_kinds:
            exact_hits.append(entry)
    if len(exact_hits) == 1:
        hit = exact_hits[0]
        return hit.usr, hit.file or None, hit.line
    if len(exact_hits) > 1:
        return None, None, None

    for entry in usr_index.symbols_by_usr.values():
        if _qualified_name_from_usr_entry(entry) == qualified_name:
            exact_hits.append(entry)
    if len(exact_hits) == 1:
        hit = exact_hits[0]
        return hit.usr, hit.file or None, hit.line

    if "::" not in qualified_name:
        short_hits = [
            e
            for e in usr_index.symbols_by_usr.values()
            if _short_cpp_type(e.name) == qualified_name and e.kind in type_kinds
        ]
        if len(short_hits) == 1 and "::" not in _qualified_name_from_usr_entry(short_hits[0]):
            hit = short_hits[0]
            return hit.usr, hit.file or None, hit.line
    return None, None, None


def _find_constructor_cycles(
    deps: tuple[SingletonDependencyEdge, ...],
) -> tuple[SingletonCycle, ...]:
    """Run linear-time Tarjan SCC over proven (non-ambiguous) constructor `GetOrCreate<T>()` edges."""
    adj: dict[str, list[SingletonDependencyEdge]] = {}
    nodes: set[str] = set()
    for d in deps:
        if (
            not d.is_constructor_dep
            or d.accessor != "GetOrCreate"
            or not d.caller_type
            or d.is_ambiguous
        ):
            continue
        nodes.add(d.caller_type)
        nodes.add(d.target_type)
        adj.setdefault(d.caller_type, []).append(d)

    index_counter = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []

    def _strongconnect(v: str) -> None:
        nonlocal index_counter
        indices[v] = index_counter
        lowlink[v] = index_counter
        index_counter += 1
        stack.append(v)
        on_stack.add(v)

        for edge in adj.get(v, ()):
            w = edge.target_type
            if w not in indices:
                _strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(sorted(comp))

    for node in sorted(nodes):
        if node not in indices:
            _strongconnect(node)

    cycles: list[SingletonCycle] = []
    for comp in sorted(sccs, key=lambda c: c[0]):
        comp_set = set(comp)
        if len(comp) == 1:
            only = comp[0]
            self_edges = [e for e in adj.get(only, ()) if e.target_type == only]
            if self_edges:
                cycles.append(SingletonCycle(chain=(only, only), edges=(self_edges[0],)))
            continue

        start = comp[0]
        # Deterministic shortest directed cycle from `start` back to `start` inside `comp_set`
        q: deque[tuple[str, tuple[str, ...], tuple[SingletonDependencyEdge, ...]]] = deque()
        for first_e in sorted(adj.get(start, ()), key=lambda e: (e.target_type, e.source_file, e.line)):
            if first_e.target_type in comp_set:
                q.append((first_e.target_type, (start, first_e.target_type), (first_e,)))

        visited: set[str] = set()
        found_cycle: SingletonCycle | None = None
        while q:
            cur, path_nodes, path_edges = q.popleft()
            if cur == start:
                found_cycle = SingletonCycle(chain=path_nodes, edges=path_edges)
                break
            if cur in visited:
                continue
            visited.add(cur)
            for nxt_e in sorted(adj.get(cur, ()), key=lambda e: (e.target_type, e.source_file, e.line)):
                if nxt_e.target_type in comp_set:
                    q.append((nxt_e.target_type, (*path_nodes, nxt_e.target_type), (*path_edges, nxt_e)))

        if found_cycle is not None:
            cycles.append(found_cycle)

    return tuple(cycles)


@dataclass
class _CppScopeFrame:
    kind: Literal["root", "namespace", "class", "function", "block"]
    ns_parts: tuple[str, ...] = ()
    class_parts: tuple[str, ...] = ()
    fn_symbol: str | None = None
    fn_owner_type: str | None = None
    fn_is_ctor: bool = False
    fn_is_ambiguous: bool = False
    type_aliases: dict[str, str] = field(default_factory=dict)
    ns_aliases: dict[str, str] = field(default_factory=dict)
    using_namespaces: list[str] = field(default_factory=list)

    def child(
        self,
        kind: Literal["namespace", "class", "function", "block"],
        *,
        ns_parts: tuple[str, ...] | None = None,
        class_parts: tuple[str, ...] | None = None,
        fn_symbol: str | None = None,
        fn_owner_type: str | None = None,
        fn_is_ctor: bool = False,
        fn_is_ambiguous: bool = False,
    ) -> _CppScopeFrame:
        return _CppScopeFrame(
            kind=kind,
            ns_parts=self.ns_parts if ns_parts is None else ns_parts,
            class_parts=self.class_parts if class_parts is None else class_parts,
            fn_symbol=self.fn_symbol if fn_symbol is None and kind == "block" else fn_symbol,
            fn_owner_type=self.fn_owner_type if fn_owner_type is None and kind == "block" else fn_owner_type,
            fn_is_ctor=self.fn_is_ctor if kind == "block" else fn_is_ctor,
            fn_is_ambiguous=self.fn_is_ambiguous if kind == "block" else fn_is_ambiguous,
            type_aliases=dict(self.type_aliases),
            ns_aliases=dict(self.ns_aliases),
            using_namespaces=list(self.using_namespaces),
        )


def _blank_preprocessor_lines(cleaned: str) -> str:
    out_lines: list[str] = []
    in_pp_cont = False
    for ln in cleaned.splitlines():
        s = ln.lstrip()
        if in_pp_cont or s.startswith("#"):
            in_pp_cont = ln.rstrip().endswith("\\")
            out_lines.append("")
        else:
            out_lines.append(ln)
    return "\n".join(out_lines)


def _split_cpp_chunks(src: str) -> tuple[list[tuple[int, int, str, str]], list[int]]:
    """Split C++ source on top-level `{`, `}`, and `;` (preserving ctor member-init `{...}`)."""
    line_starts = [0]
    for i, ch in enumerate(src):
        if ch == "\n":
            line_starts.append(i + 1)

    chunks: list[tuple[int, int, str, str]] = []
    paren_depth = 0
    in_ctor_init_list = False
    init_brace_depth = 0
    prev_non_ws = ""
    chunk_start = 0
    n = len(src)

    for idx, ch in enumerate(src):
        if ch == "(":
            paren_depth += 1
            prev_non_ws = ch
            continue
        if ch == ")":
            paren_depth = max(0, paren_depth - 1)
            if paren_depth == 0 and init_brace_depth == 0 and not in_ctor_init_list:
                m_init = re.match(
                    r"^\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?:(?!=|:)",
                    src[idx + 1 : min(n, idx + 80)],
                )
                if m_init is not None:
                    in_ctor_init_list = True
            prev_non_ws = ch
            continue

        if paren_depth == 0:
            if init_brace_depth > 0:
                if ch == "{":
                    init_brace_depth += 1
                elif ch == "}":
                    init_brace_depth -= 1
                if not ch.isspace():
                    prev_non_ws = ch
                continue

            if in_ctor_init_list:
                if ch == "{":
                    if prev_non_ws and (prev_non_ws.isalnum() or prev_non_ws in ("_", ">")):
                        init_brace_depth = 1
                        prev_non_ws = ch
                        continue
                    in_ctor_init_list = False
                elif ch == ";":
                    in_ctor_init_list = False

            if ch in ("{", "}", ";"):
                chunks.append((chunk_start, idx, src[chunk_start:idx], ch))
                chunk_start = idx + 1
                prev_non_ws = ch
                continue

        if not ch.isspace():
            prev_non_ws = ch

    if chunk_start < n:
        chunks.append((chunk_start, n, src[chunk_start:], ""))
    return chunks, line_starts


def _resolve_cpp_type_in_scope(
    raw_type: str,
    *,
    leading_global: bool,
    frame: _CppScopeFrame,
    known_types: set[str],
) -> tuple[str, bool]:
    clean_t = _normalize_qual(raw_type)
    if not clean_t:
        return "", False
    if leading_global or raw_type.strip().startswith("::"):
        return clean_t, False

    if "::" in clean_t:
        segs = [s for s in clean_t.split("::") if s]
        head = segs[0]
        if head in frame.ns_aliases:
            segs = [*frame.ns_aliases[head].split("::"), *segs[1:]]
        elif head in frame.type_aliases and frame.type_aliases[head] != "__AMBIGUOUS__":
            segs = [*frame.type_aliases[head].split("::"), *segs[1:]]
        rel_qual = "::".join(segs)
        cands: list[str] = []
        for k in range(len(frame.ns_parts), -1, -1):
            cand = "::".join((*frame.ns_parts[:k], rel_qual)) if k > 0 else rel_qual
            if cand in known_types and cand not in cands:
                cands.append(cand)
        for u_ns in frame.using_namespaces:
            cand_u = f"{u_ns}::{rel_qual}"
            if cand_u in known_types and cand_u not in cands:
                cands.append(cand_u)
        if len(cands) == 1:
            return cands[0], False
        if len(cands) > 1:
            return rel_qual, True
        return rel_qual, False

    ident = clean_t
    if ident in frame.type_aliases:
        mapped = frame.type_aliases[ident]
        if mapped == "__AMBIGUOUS__":
            return ident, True
        return mapped, False

    if frame.class_parts:
        cur_cls_qual = "::".join((*frame.ns_parts, *frame.class_parts))
        nested_cand = f"{cur_cls_qual}::{ident}"
        if nested_cand in known_types:
            return nested_cand, False
        if ident == frame.class_parts[-1]:
            return cur_cls_qual, False

    if frame.using_namespaces:
        cand_set: list[str] = []
        for k in range(len(frame.ns_parts), -1, -1):
            cand = "::".join((*frame.ns_parts[:k], ident)) if k > 0 else ident
            if cand in known_types and cand not in cand_set:
                cand_set.append(cand)
        for u_ns in frame.using_namespaces:
            cand_u = f"{u_ns}::{ident}"
            if cand_u in known_types and cand_u not in cand_set:
                cand_set.append(cand_u)
        if len(cand_set) > 1:
            return ident, True
        if len(cand_set) == 1:
            return cand_set[0], False
        if len(frame.using_namespaces) >= 2 or frame.ns_parts:
            return ident, True
        return f"{frame.using_namespaces[0]}::{ident}", False

    for k in range(len(frame.ns_parts), -1, -1):
        cand = "::".join((*frame.ns_parts[:k], ident)) if k > 0 else ident
        if cand in known_types:
            return cand, False
    return "::".join((*frame.ns_parts, ident)) if frame.ns_parts else ident, False


def _strip_leading_access_specifiers(header_text: str) -> str:
    return re.sub(r"^\s*(?:(?:public|private|protected)\s*:\s*)+", "", header_text)

def _resolve_cpp_namespace_in_scope(
    raw_ns: str,
    *,
    leading_global: bool,
    frame: _CppScopeFrame,
    known_types: set[str],
) -> str:
    clean_ns = _normalize_qual(raw_ns)
    if not clean_ns:
        return ""
    if leading_global or raw_ns.strip().startswith("::"):
        return clean_ns
    segs = [s for s in clean_ns.split("::") if s]
    if segs[0] in frame.ns_aliases:
        segs = [*frame.ns_aliases[segs[0]].split("::"), *segs[1:]]
    rel_ns = "::".join(segs)
    known_ns_prefixes = {
        "::".join(t.split("::")[:k])
        for t in known_types
        if "::" in t
        for k in range(1, len(t.split("::")))
    }
    for k in range(len(frame.ns_parts), -1, -1):
        cand = "::".join((*frame.ns_parts[:k], rel_ns)) if k > 0 else rel_ns
        if cand in known_ns_prefixes:
            return cand
    return rel_ns


def _apply_cpp_directive(
    stmt_body: str,
    top: _CppScopeFrame,
    known_types: set[str],
    decl_by_qual: dict[str, SingletonNodeDecl] | None,
    rel_posix: str,
    ln_no: int,
) -> None:
    s = _strip_leading_access_specifiers(stmt_body).strip()
    if not s:
        return
    m_uns = re.match(r"^using\s+namespace\s+(::)?\s*([A-Za-z_][A-Za-z0-9_:]*)\s*$", s)
    if m_uns:
        ns_q = _resolve_cpp_namespace_in_scope(
            m_uns.group(2), leading_global=bool(m_uns.group(1)), frame=top, known_types=known_types
        )
        if ns_q and ns_q not in top.using_namespaces:
            top.using_namespaces.append(ns_q)
        return
    m_nsa = re.match(r"^namespace\s+([A-Za-z_]\w*)\s*=\s*(::)?\s*([A-Za-z_][A-Za-z0-9_:]*)\s*$", s)
    if m_nsa:
        ns_q = _resolve_cpp_namespace_in_scope(
            m_nsa.group(3), leading_global=bool(m_nsa.group(2)), frame=top, known_types=known_types
        )
        if ns_q:
            top.ns_aliases[m_nsa.group(1)] = ns_q
        return
    m_ta = re.match(
        r"^using\s+([A-Za-z_]\w*)\s*=\s*(?:typename\s+|class\s+|struct\s+)?(::)?\s*([A-Za-z_][A-Za-z0-9_:]*)\s*$",
        s,
    )
    if m_ta:
        alias_nm = m_ta.group(1)
        tgt_q, amb = _resolve_cpp_type_in_scope(
            m_ta.group(3), leading_global=bool(m_ta.group(2)), frame=top, known_types=known_types
        )
        top.type_aliases[alias_nm] = "__AMBIGUOUS__" if amb else tgt_q
        return
    m_ud = re.match(r"^using\s+(::)?\s*([A-Za-z_][A-Za-z0-9_:]+::([A-Za-z_]\w*))\s*$", s)
    if m_ud:
        short_u = m_ud.group(3)
        tgt_q, amb = _resolve_cpp_type_in_scope(
            m_ud.group(2), leading_global=bool(m_ud.group(1)), frame=top, known_types=known_types
        )
        prev = top.type_aliases.get(short_u)
        if amb or (prev is not None and prev != tgt_q):
            top.type_aliases[short_u] = "__AMBIGUOUS__"
        else:
            top.type_aliases[short_u] = tgt_q
        return
    m_td = re.match(
        r"^typedef\s+(?:typename\s+|class\s+|struct\s+)?(::)?\s*([A-Za-z_][A-Za-z0-9_:]*)\s+([A-Za-z_]\w*)\s*$",
        s,
    )
    if m_td:
        alias_nm = m_td.group(3)
        tgt_q, amb = _resolve_cpp_type_in_scope(
            m_td.group(2), leading_global=bool(m_td.group(1)), frame=top, known_types=known_types
        )
        top.type_aliases[alias_nm] = "__AMBIGUOUS__" if amb else tgt_q
        return
    if top.kind in ("root", "namespace", "class"):
        m_fwd = _CLASS_FWD_RE.match(s)
        if m_fwd:
            c_segs = tuple(p for p in m_fwd.group(1).split("::") if p)
            if c_segs and c_segs[-1] != "Model":
                qual_fwd = "::".join((*top.ns_parts, *top.class_parts, *c_segs))
                known_types.add(qual_fwd)
                if decl_by_qual is not None:
                    decl_by_qual.setdefault(
                        qual_fwd,
                        SingletonNodeDecl(
                            type_name=c_segs[-1],
                            qualified_name=qual_fwd,
                            source_file=rel_posix,
                            line=ln_no,
                        ),
                    )


def _walk_cpp_chunks(
    chunks: list[tuple[int, int, str, str]],
    line_starts: list[int],
    rel_posix: str,
    *,
    known_types: set[str],
    decl_by_qual: dict[str, SingletonNodeDecl],
    usr_index: CppUsrIndex,
    collect_deps: bool,
    deps_out: list[SingletonDependencyEdge],
) -> None:
    anon_stem = re.sub(r"[^A-Za-z0-9_]+", "_", PurePosixPath(rel_posix).stem) or "tu"
    stack: list[_CppScopeFrame] = [_CppScopeFrame(kind="root")]

    def _line_at(pos: int) -> int:
        return bisect_right(line_starts, pos)

    def _scan_calls(seg_text: str, seg_start: int, frame: _CppScopeFrame) -> None:
        if not collect_deps or "Get" not in seg_text and "Mutable" not in seg_text:
            return
        for m_loc in _SERVICE_LOCATOR_RE.finditer(seg_text):
            accessor = m_loc.group(1)
            lead_glob = bool(m_loc.group(2))
            raw_tgt = re.sub(r"\s+", "", m_loc.group(3))
            tgt_short = _short_cpp_type(raw_tgt)
            if not tgt_short or tgt_short in _GENERIC_TEMPLATE_PARAMS or tgt_short == "Model":
                continue
            call_ln = _line_at(seg_start + m_loc.start())
            if frame.fn_symbol is not None:
                caller_sym = frame.fn_symbol
                caller_cls = frame.fn_owner_type
                is_ctor = frame.fn_is_ctor
                amb_caller = frame.fn_is_ambiguous
            elif frame.class_parts:
                caller_cls = "::".join((*frame.ns_parts, *frame.class_parts))
                caller_sym = caller_cls
                is_ctor = False
                amb_caller = False
            else:
                caller_cls = None
                caller_sym = PurePosixPath(rel_posix).stem
                is_ctor = False
                amb_caller = False

            if caller_cls and _short_cpp_type(caller_cls) == "Model":
                continue

            tgt_qual, amb_tgt = _resolve_cpp_type_in_scope(
                raw_tgt,
                leading_global=lead_glob,
                frame=frame,
                known_types=known_types,
            )
            is_amb = amb_caller or amb_tgt
            usr_str, u_file, u_line = (
                (None, None, None) if is_amb else _resolve_type_usr(tgt_qual, usr_index)
            )
            if tgt_qual not in decl_by_qual:
                decl_by_qual[tgt_qual] = SingletonNodeDecl(
                    type_name=tgt_short,
                    qualified_name=tgt_qual,
                    source_file=u_file or rel_posix,
                    line=u_line or call_ln,
                    usr=usr_str,
                )
            elif usr_str and decl_by_qual[tgt_qual].usr is None:
                prev_d = decl_by_qual[tgt_qual]
                decl_by_qual[tgt_qual] = SingletonNodeDecl(
                    type_name=prev_d.type_name,
                    qualified_name=prev_d.qualified_name,
                    source_file=prev_d.source_file,
                    line=prev_d.line,
                    usr=usr_str,
                )

            links: list[str] = [
                f"{caller_sym}->Model::{accessor}<{tgt_qual}>",
                f"{rel_posix}:{call_ln}",
            ]
            if usr_str:
                links.append(usr_str)

            deps_out.append(
                SingletonDependencyEdge(
                    caller_symbol=caller_sym,
                    caller_type=caller_cls,
                    target_type=tgt_qual,
                    accessor=accessor,
                    is_constructor_dep=is_ctor,
                    source_file=rel_posix,
                    line=call_ln,
                    symbol_links=tuple(dict.fromkeys(links)),
                    is_ambiguous=is_amb,
                )
            )

    for c_start, _c_end, c_text, delim in chunks:
        top = stack[-1]
        clean_head = _strip_leading_access_specifiers(c_text)
        head_ln = _line_at(c_start + (len(c_text) - len(c_text.lstrip())))

        if delim == ";":
            if top.kind in ("function", "block"):
                _scan_calls(c_text, c_start, top)
            _apply_cpp_directive(
                clean_head, top, known_types, decl_by_qual if not collect_deps else None, rel_posix, head_ln
            )
            continue

        if delim == "}":
            if top.kind in ("function", "block"):
                _scan_calls(c_text, c_start, top)
            if len(stack) > 1:
                stack.pop()
            continue

        if delim != "{":
            if top.kind in ("function", "block"):
                _scan_calls(c_text, c_start, top)
            continue

        # delim == "{"
        if top.kind in ("function", "block"):
            blk_frame = top.child("block")
            stack.append(blk_frame)
            _scan_calls(c_text, c_start, blk_frame)
            continue

        s_head = clean_head.strip()
        m_ns = _NAMESPACE_OPEN_RE.search(s_head)
        if m_ns and "(" not in s_head:
            raw_ns = m_ns.group(1)
            ns_segs = tuple(p for p in raw_ns.split("::") if p) if raw_ns else (f"anon_{anon_stem}",)
            stack.append(top.child("namespace", ns_parts=(*top.ns_parts, *ns_segs)))
            continue

        m_cls = _CLASS_OPEN_RE.search(s_head)
        if m_cls and not re.search(r"\benum\s+(?:class|struct)\b", s_head) and not s_head.startswith(("friend ", "using ", "typedef ")):
            c_segs = tuple(p for p in m_cls.group(1).split("::") if p)
            if c_segs:
                qual_cls = "::".join((*top.ns_parts, *top.class_parts, *c_segs))
                known_types.add(qual_cls)
                u_str, u_f, u_l = _resolve_type_usr(qual_cls, usr_index)
                decl_by_qual.setdefault(
                    qual_cls,
                    SingletonNodeDecl(
                        type_name=c_segs[-1],
                        qualified_name=qual_cls,
                        source_file=rel_posix or (u_f or ""),
                        line=head_ln or (u_l or 1),
                        usr=u_str,
                    ),
                )
                stack.append(top.child("class", class_parts=(*top.class_parts, *c_segs)))
                continue

        # Out-of-line method / constructor definition `Qual::Cls::Meth(...)`
        ool_matches = list(_OOL_METHOD_OPEN_RE.finditer(s_head))
        fn_frame: _CppScopeFrame | None = None
        if ool_matches and not s_head.startswith(("return ", "auto ", "const auto")):
            # First `Qual::Cls::Meth(` in header (before member-initializer `:`)
            colon_init = s_head.find(")")
            cand_m = ool_matches[0]
            if colon_init == -1 or cand_m.start() < colon_init:
                q_parts = [p.strip() for p in cand_m.group(1).split("::") if p.strip()]
                if len(q_parts) >= 2 and q_parts[-1] not in _CONTROL_KEYWORDS and q_parts[-2] not in _CONTROL_KEYWORDS:
                    meth_nm = q_parts[-1]
                    owner_raw = "::".join(q_parts[:-1])
                    owner_short = q_parts[-2]
                    is_ctor = meth_nm == owner_short
                    owner_qual, amb_o = _resolve_cpp_type_in_scope(
                        owner_raw,
                        leading_global=cand_m.group(1).lstrip().startswith("::"),
                        frame=top,
                        known_types=known_types,
                    )
                    if is_ctor and not amb_o and owner_short != "Model":
                        known_types.add(owner_qual)
                        u_str, _, _ = _resolve_type_usr(owner_qual, usr_index)
                        decl_by_qual.setdefault(
                            owner_qual,
                            SingletonNodeDecl(
                                type_name=owner_short,
                                qualified_name=owner_qual,
                                source_file=rel_posix,
                                line=head_ln,
                                usr=u_str,
                            ),
                        )
                    fn_frame = top.child(
                        "function",
                        fn_symbol=f"{owner_qual}::{meth_nm}",
                        fn_owner_type=owner_qual,
                        fn_is_ctor=is_ctor,
                        fn_is_ambiguous=amb_o,
                    )

        if fn_frame is None and top.kind == "class" and top.class_parts:
            cur_short = top.class_parts[-1]
            cur_qual = "::".join((*top.ns_parts, *top.class_parts))
            head_before_paren = s_head.split("(", 1)[0]
            if "(" in s_head and re.search(
                rf"(?:^|\b(?:explicit|inline|constexpr)\s+){re.escape(cur_short)}\s*$",
                head_before_paren,
            ):
                fn_frame = top.child(
                    "function",
                    fn_symbol=f"{cur_qual}::{cur_short}",
                    fn_owner_type=cur_qual,
                    fn_is_ctor=True,
                )
            else:
                m_in_meth = re.search(r"([~A-Za-z_][A-Za-z0-9_]*)\s*$", head_before_paren)
                if "(" in s_head and m_in_meth and m_in_meth.group(1) not in _CONTROL_KEYWORDS:
                    m_nm = m_in_meth.group(1)
                    fn_frame = top.child(
                        "function",
                        fn_symbol=f"{cur_qual}::{m_nm}",
                        fn_owner_type=cur_qual,
                        fn_is_ctor=False,
                    )

        if fn_frame is None:
            head_before_paren = s_head.split("(", 1)[0]
            m_free = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", head_before_paren)
            if "(" in s_head and m_free and m_free.group(1) not in _CONTROL_KEYWORDS:
                f_nm = m_free.group(1)
                f_qual = "::".join((*top.ns_parts, f_nm)) if top.ns_parts else f_nm
                fn_frame = top.child("function", fn_symbol=f_qual, fn_owner_type=None, fn_is_ctor=False)

        if fn_frame is not None:
            stack.append(fn_frame)
            _scan_calls(c_text, c_start, fn_frame)
        else:
            stack.append(top.child("block"))


def extract_singleton_dependency_graph(
    repo_root: Path,
    *,
    usr_index: CppUsrIndex | None = None,
    node_id_by_file: dict[str, str] | None = None,
    max_bytes: int = MAX_SOLVER_FILE_BYTES,
) -> SingletonGraphReport:
    """Extract `Model::GetOrCreate<T>()` / `Get<T>()` singleton dependencies and constructor cycles."""
    idx = usr_index or CppUsrIndex()
    nid_map = node_id_by_file or {}
    known_types: set[str] = set()
    decl_by_qual: dict[str, SingletonNodeDecl] = {}
    deps: list[SingletonDependencyEdge] = []

    type_usr_kinds = {"class", "struct", "type", "cxx-class", "record"}
    usr_qual_counts: Counter[str] = Counter()
    for u_ent in idx.symbols_by_usr.values():
        if u_ent.kind in type_usr_kinds:
            usr_qual_counts[_qualified_name_from_usr_entry(u_ent)] += 1

    for u_ent in sorted(idx.symbols_by_usr.values(), key=lambda u: u.usr):
        if u_ent.kind not in type_usr_kinds:
            continue
        u_qual = _qualified_name_from_usr_entry(u_ent)
        if not u_qual or _short_cpp_type(u_qual) == "Model":
            continue
        vertex_key = f"{u_qual}[{u_ent.usr}]" if usr_qual_counts[u_qual] > 1 else u_qual
        known_types.add(u_qual)
        decl_by_qual.setdefault(
            vertex_key,
            SingletonNodeDecl(
                type_name=_short_cpp_type(u_ent.name),
                qualified_name=u_qual,
                source_file=u_ent.file,
                line=u_ent.line,
                usr=u_ent.usr,
            ),
        )

    parsed_units: list[tuple[str, list[tuple[int, int, str, str]], list[int], bool]] = []
    for rel_posix, abs_p in iter_safe_repo_files(repo_root, suffixes=_CPP_SUFFIXES):
        _, raw_txt = read_safe_artifact_text(abs_p, repo_root=repo_root, max_bytes=max_bytes)
        cleaned = _blank_preprocessor_lines(
            strip_c_comments_and_strings(raw_txt, blank_strings=True)
        )
        has_locator = (
            "GetOrCreate" in cleaned or "Model" in cleaned or "Propagator" in cleaned
        )
        if not has_locator and "class " not in cleaned and "struct " not in cleaned:
            continue
        chunks, line_starts = _split_cpp_chunks(cleaned)
        parsed_units.append((rel_posix, chunks, line_starts, has_locator))
        # Pass 1: discover all namespace-qualified C++ class/struct declarations across the repo
        _walk_cpp_chunks(
            chunks,
            line_starts,
            rel_posix,
            known_types=known_types,
            decl_by_qual=decl_by_qual,
            usr_index=idx,
            collect_deps=False,
            deps_out=deps,
        )

    # Pass 2: extract qualified `GetOrCreate<T>()` / `Get<T>()` edges with full type catalog
    for rel_posix, chunks, line_starts, has_locator in parsed_units:
        if not has_locator:
            continue
        _walk_cpp_chunks(
            chunks,
            line_starts,
            rel_posix,
            known_types=known_types,
            decl_by_qual=decl_by_qual,
            usr_index=idx,
            collect_deps=True,
            deps_out=deps,
        )

    referenced_types = {d.target_type for d in deps} | {
        d.caller_type for d in deps if d.caller_type
    }
    # Preserve distinct USR-indexed C++ class symbols when explicitly supplied alongside singletons
    if deps and idx.symbols_by_usr:
        for k, d in decl_by_qual.items():
            if d.usr and k in decl_by_qual:
                referenced_types.add(k)

    active_singletons = {
        k: decl_by_qual[k]
        for k in sorted(referenced_types)
        if k in decl_by_qual
    }

    deps_tuple = tuple(deps)
    cycles = _find_constructor_cycles(deps_tuple)

    atlas_edges: list[AtlasEdge] = []
    seen_eids: set[str] = set()
    for dep in deps_tuple:
        src_key = dep.caller_type or dep.caller_symbol
        src_nid = nid_map.get(dep.source_file, _bounded_atlas_id(f"m:singleton:{src_key}"))
        tgt_decl = active_singletons.get(dep.target_type)
        tgt_nid = (
            nid_map.get(tgt_decl.source_file, _bounded_atlas_id(f"m:singleton:{dep.target_type}"))
            if tgt_decl
            else _bounded_atlas_id(f"m:singleton:{dep.target_type}")
        )
        eid = _bounded_atlas_id(
            f"e:singleton:{src_key}->{dep.target_type}:{dep.accessor}:{dep.line}"
        )
        if eid in seen_eids:
            continue
        seen_eids.add(eid)
        atlas_edges.append(
            AtlasEdge(
                id=eid,
                source_id=src_nid,
                target_id=tgt_nid,
                kind="calls_helper",
                verification="unverified" if dep.is_ambiguous else "verified",
                evidence_path=f"{dep.source_file}:{dep.line}",
                evidence_note=(
                    f"`{dep.caller_symbol}` resolves `{dep.target_type}` via "
                    f"`Model::{dep.accessor}<{dep.target_type}>()`"
                    + (" (constructor injection)" if dep.is_constructor_dep else "")
                    + (
                        " [unverified: ambiguous unqualified C++ lookup across namespaces]"
                        if dep.is_ambiguous
                        else ""
                    )
                ),
                symbol_links=list(dep.symbol_links),
            )
        )

    findings: list[RawCandidateFinding] = []
    for cyc in cycles:
        anchor_edge = cyc.edges[0]
        chain_str = " -> ".join(cyc.chain)
        hops_str = ", ".join(
            f"`{e.caller_type}` -> `GetOrCreate<{e.target_type}>()` (`{e.source_file}:{e.line}`)"
            for e in cyc.edges
        )
        findings.append(
            RawCandidateFinding(
                rule_code="SAT-INT-003",
                node_id=nid_map.get(anchor_edge.source_file),
                source_file=anchor_edge.source_file,
                line=anchor_edge.line,
                title=f"Hidden cyclic `Model::GetOrCreate<T>()` constructor dependency: `{chain_str}`",
                detail=(
                    f"C++ `Model*` service-locator constructors form a recursive `GetOrCreate<T>()` "
                    f"instantiation cycle `{chain_str}` across {hops_str}. Calling `GetOrCreate` on "
                    "any member of this cycle triggers re-entrant singleton construction before "
                    "member initialization completes."
                ),
                remediation=(
                    f"Break the constructor cycle `{chain_str}` by deferring `model->Get<T>()` / "
                    "`GetOrCreate<T>()` lookup to a post-construction `Init()` or lazy propagator hook, "
                    "or extract shared state into a leaf singleton."
                ),
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )

    return SingletonGraphReport(
        singletons=active_singletons,
        dependencies=deps_tuple,
        cycles=cycles,
        atlas_edges=tuple(atlas_edges),
        findings=tuple(findings),
    )


def build_singleton_zoom2_subgraph(
    parent_node_id: str,
    graph: SingletonGraphReport,
    *,
    usr_index: CppUsrIndex | None = None,
) -> tuple[list[StratumMicroNode], list[StratumMicroEdge]]:
    """Project `SingletonGraphReport` into Zoom-2 `StratumMicroNode` & `StratumMicroEdge` items."""
    micro_nodes: list[StratumMicroNode] = []
    micro_edges: list[StratumMicroEdge] = []
    cyclic_pairs = {
        (e.caller_type, e.target_type)
        for cyc in graph.cycles
        for e in cyc.edges
        if e.caller_type
    }
    short_counts = Counter(decl.type_name for decl in graph.singletons.values())
    node_id_by_key: dict[str, str] = {}

    for t_key, decl in sorted(graph.singletons.items()):
        in_cycle = any(t_key in cyc.chain for cyc in graph.cycles)
        display_lbl = decl.type_name if short_counts[decl.type_name] == 1 else decl.qualified_name
        s_nid = _bounded_atlas_id(f"z2:{parent_node_id}:singleton:{t_key}", max_len=160)
        node_id_by_key[t_key] = s_nid
        micro_nodes.append(
            StratumMicroNode(
                id=s_nid,
                label=display_lbl,
                kind="cpp_singleton",
                zoom=2,
                source_file=decl.source_file,
                line=decl.line,
                verification="broken" if in_cycle else "verified",
                summary=(
                    f"`Model` singleton `{decl.qualified_name}`"
                    + (f" (USR `{decl.usr}`)" if decl.usr else "")
                ),
            )
        )

    caller_fn_seen: set[str] = set()
    for dep in graph.dependencies:
        if dep.caller_type and dep.caller_type in node_id_by_key:
            src_id = node_id_by_key[dep.caller_type]
        else:
            fn_id = _bounded_atlas_id(f"z2:{parent_node_id}:fn:{dep.caller_symbol}", max_len=160)
            if fn_id not in caller_fn_seen:
                caller_fn_seen.add(fn_id)
                micro_nodes.append(
                    StratumMicroNode(
                        id=fn_id,
                        label=dep.caller_symbol,
                        kind="cpp_solver_fn",
                        zoom=2,
                        source_file=dep.source_file,
                        line=dep.line,
                        verification="unverified" if dep.is_ambiguous else "verified",
                        summary=f"Solver C++ consumer `{dep.caller_symbol}`",
                    )
                )
            src_id = fn_id

        tgt_id = node_id_by_key.get(
            dep.target_type,
            _bounded_atlas_id(f"z2:{parent_node_id}:singleton:{dep.target_type}", max_len=160),
        )
        is_cyc_edge = (dep.caller_type, dep.target_type) in cyclic_pairs and dep.is_constructor_dep
        ekind = "singleton_get_or_create" if dep.accessor == "GetOrCreate" else "singleton_get"
        edge_verif: Literal["broken", "unverified", "verified"] = (
            "broken" if is_cyc_edge else ("unverified" if dep.is_ambiguous else "verified")
        )
        micro_edges.append(
            StratumMicroEdge(
                id=_bounded_atlas_id(f"e:{src_id}->{tgt_id}:{dep.accessor}:{dep.line}"),
                source_id=src_id,
                target_id=tgt_id,
                label=f"{dep.accessor}<{dep.target_type}>()",
                kind=ekind,
                verification=edge_verif,
                evidence_note=(
                    f"{dep.source_file}:{dep.line} (`{dep.caller_symbol}` -> "
                    f"`Model::{dep.accessor}<{dep.target_type}>()`)"
                ),
            )
        )

    if usr_index is not None:
        key_by_usr = {d.usr: k for k, d in graph.singletons.items() if d.usr}
        for entry in sorted(usr_index.symbols_by_usr.values(), key=lambda u: u.usr):
            if not entry.callees:
                continue
            entry_qual = _qualified_name_from_usr_entry(entry)
            owner_key = key_by_usr.get(entry.usr)
            if owner_key is None:
                if entry_qual in graph.singletons:
                    owner_key = entry_qual
                elif "::" in entry_qual and entry_qual.rsplit("::", 1)[0] in graph.singletons:
                    owner_key = entry_qual.rsplit("::", 1)[0]
            if not owner_key or owner_key not in node_id_by_key:
                continue
            src_id = node_id_by_key[owner_key]
            for c_idx, callee in enumerate(entry.callees, start=1):
                callee_entry = usr_index.symbols_by_usr.get(callee)
                lbl = callee_entry.name if callee_entry else callee
                safe_slug = re.sub(r"[^A-Za-z0-9_.:-]+", "_", lbl).strip("_")[:80] or f"sym_{c_idx}"
                b_id = _bounded_atlas_id(f"z2:{parent_node_id}:ir:{safe_slug}", max_len=160)
                micro_nodes.append(
                    StratumMicroNode(
                        id=b_id,
                        label=lbl,
                        kind="cpp_ir_symbol",
                        zoom=2,
                        source_file=callee_entry.file if callee_entry else entry.file,
                        line=callee_entry.line if callee_entry else entry.line,
                        verification="verified",
                        summary=f"C++ USR symbol `{lbl}`",
                    )
                )
                micro_edges.append(
                    StratumMicroEdge(
                        id=_bounded_atlas_id(f"e:{src_id}->ir:{safe_slug}"),
                        source_id=src_id,
                        target_id=b_id,
                        label="calls_ir",
                        kind="calls_ir",
                        verification="verified",
                        evidence_note=f"USR reference `{entry.usr}` -> `{callee}`",
                    )
                )

    return micro_nodes, micro_edges
